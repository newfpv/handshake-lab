from __future__ import annotations

import hashlib
import ctypes
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKER_VERSION = "1.3.1"
CONFIG_PATH = ROOT / "lan-worker.json"
RUNTIME = ROOT / "data" / "lan-worker"
RUNTIME.mkdir(parents=True, exist_ok=True)
INSTANCE_HANDLE = None


def acquire_single_instance(worker_name: str) -> None:
    global INSTANCE_HANDLE
    if os.name != "nt":
        return
    safe_name = re.sub(r"[^0-9A-Za-z_.-]", "-", worker_name)[:80]
    handle = ctypes.windll.kernel32.CreateMutexW(None, False, f"Local\\NewFPV-Handshake-Lab-{safe_name}")
    if not handle:
        raise RuntimeError("Unable to create the worker instance lock")
    if ctypes.windll.kernel32.GetLastError() == 183:
        ctypes.windll.kernel32.CloseHandle(handle)
        raise RuntimeError(f"Worker {safe_name} is already running on this computer")
    INSTANCE_HANDLE = handle


def load_config() -> dict:
    defaults = {"coordinator_url": "http://192.168.1.10:8787", "token": "", "worker_name": socket.gethostname(),
                "hashcat_path": "", "wordlist_roots": [str(ROOT / "wordlists"), str(ROOT / "rules")],
                "poll_seconds": 3, "force_opencl": False}
    if CONFIG_PATH.is_file():
        raw = CONFIG_PATH.read_text(encoding="utf-8-sig")
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError:
            repaired = []
            inside = False
            index = 0
            while index < len(raw):
                character = raw[index]
                if character == '"' and (index == 0 or raw[index - 1] != "\\"):
                    inside = not inside
                if inside and character == "\\":
                    following = raw[index + 1] if index + 1 < len(raw) else ""
                    if following in {"\\", '"'}:
                        repaired.extend((character, following)); index += 2; continue
                    else:
                        repaired.append("\\")
                repaired.append(character)
                index += 1
            loaded = json.loads("".join(repaired))
            CONFIG_PATH.write_text(json.dumps(loaded, ensure_ascii=False, indent=2), encoding="utf-8")
            print("Repaired single backslashes in lan-worker.json")
        defaults.update(loaded)
    return defaults


def set_suspended(process: subprocess.Popen, suspended: bool) -> bool:
    if process.poll() is not None:
        return False
    if os.name != "nt":
        import signal
        os.kill(process.pid, signal.SIGSTOP if suspended else signal.SIGCONT)
        return True
    handle = ctypes.windll.kernel32.OpenProcess(0x0800, False, process.pid)
    if not handle:
        return False
    try:
        operation = ctypes.windll.ntdll.NtSuspendProcess if suspended else ctypes.windll.ntdll.NtResumeProcess
        return operation(handle) == 0
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def apply_affinity(process: subprocess.Popen, profile: str) -> None:
    if os.name != "nt" or profile == "off": return
    logical = max(1, os.cpu_count() or 1); count = {"low": max(1, logical // 4), "balanced": max(1, logical // 2), "high": logical}.get(profile, 1)
    handle = ctypes.windll.kernel32.OpenProcess(0x0200 | 0x0400, False, process.pid)
    if handle:
        try: ctypes.windll.kernel32.SetProcessAffinityMask(handle, ctypes.c_size_t((1 << count) - 1))
        finally: ctypes.windll.kernel32.CloseHandle(handle)


def api(config: dict, path: str, payload: dict) -> dict:
    request = urllib.request.Request(config["coordinator_url"].rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {config['token']}"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def hashcat_path(config: dict) -> Path:
    configured = Path(str(config.get("hashcat_path") or ""))
    if configured.is_file():
        return configured
    for path in (ROOT / "tools").glob("**/hashcat.exe"):
        return path
    raise RuntimeError("hashcat.exe not found; run bootstrap.ps1 or set hashcat_path in lan-worker.json")


def backend_capabilities(config: dict) -> dict:
    path = hashcat_path(config)
    try:
        process = subprocess.run([str(path), "-I"], cwd=str(path.parent), capture_output=True, text=True, timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        output = process.stdout + process.stderr
    except (OSError, subprocess.TimeoutExpired):
        output = ""
    names = re.findall(r"Name\.{3,}:\s*(.+)", output)
    return {"cpu_available": bool(re.search(r"Type\.{3,}: CPU", output, re.IGNORECASE)),
            "device_names": list(dict.fromkeys(name.strip() for name in names))[:8]}


def nvidia_telemetry() -> dict:
    executable = shutil.which("nvidia-smi")
    if not executable:
        return {}
    fields = ["name", "temperature.gpu", "utilization.gpu", "memory.used", "memory.total",
              "power.draw", "power.limit", "clocks.gr", "fan.speed"]
    try:
        process = subprocess.run(
            [executable, f"--query-gpu={','.join(fields)}", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=4,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        values = [value.strip() for value in process.stdout.splitlines()[0].split(",")]
        if len(values) != len(fields):
            return {}
        def number(value: str):
            try: return float(value)
            except ValueError: return None
        return {"device_name": values[0], "temperature": number(values[1]), "utilization": number(values[2]),
                "memory_used": number(values[3]), "memory_total": number(values[4]), "power_draw": number(values[5]),
                "power_limit": number(values[6]), "clock_graphics": number(values[7]), "fan_speed": number(values[8])}
    except (OSError, subprocess.SubprocessError, IndexError):
        return {}


def portable_fingerprint(path: Path) -> str:
    stat = path.stat(); size = 2 * 1024 * 1024
    offsets = sorted({0, max(0, stat.st_size // 2 - size // 2), max(0, stat.st_size - size)})
    digest = hashlib.sha256(); digest.update(f"newfpv-source-v1\0{stat.st_size}\0".encode("ascii"))
    with path.open("rb") as handle:
        for offset in offsets:
            handle.seek(offset); digest.update(str(offset).encode("ascii") + b"\0" + handle.read(size))
    return digest.hexdigest()


def find_source(config: dict, expected: dict) -> Path:
    candidates: list[Path] = []
    for root in config.get("wordlist_roots") or []:
        folder = Path(os.path.expandvars(str(root)))
        if folder.is_dir():
            candidates.extend(path for path in folder.rglob(expected["filename"]) if path.is_file())
    for path in candidates:
        if path.stat().st_size == int(expected.get("bytes") or -1) and portable_fingerprint(path) == expected["fingerprint"]:
            return path
    raise RuntimeError(f"Source not found on worker: {expected['filename']} ({expected.get('bytes', 0)} bytes)")


def flatten_numbers(value) -> list[float]:
    if isinstance(value, (int, float)): return [float(value)]
    if isinstance(value, dict): return sum((flatten_numbers(item) for item in value.values()), [])
    if isinstance(value, list): return sum((flatten_numbers(item) for item in value), [])
    return []


def run_job(config: dict, job: dict) -> None:
    job_id = int(job["id"]); folder = RUNTIME / str(job_id); folder.mkdir(parents=True, exist_ok=True)
    hash_file = folder / "input.22000"; hash_file.write_text(job["hash_text"], encoding="utf-8")
    outfile = folder / "found.txt"; outfile.unlink(missing_ok=True)
    log_file = folder / "hashcat.log"
    command = [str(hashcat_path(config)), "-m", "22000", str(hash_file), "--potfile-path", str(ROOT / "data" / "lan-worker.potfile"),
        "--session", f"lan-{job['session']}", "--outfile", str(outfile), "--outfile-format", "1,2", "--separator", "|",
        "--status", "--status-json", "--status-timer", "2", "--workload-profile", "4",
        "--hwmon-temp-abort", str(job.get("temperature_abort", 90))]
    if config.get("force_opencl", False): command.append("--backend-ignore-cuda")
    cpu_profile = str(job.get("cpu_profile") or "off")
    if cpu_profile != "off": command += ["--opencl-device-types", "1,2"]
    mode = job["mode"]; cfg = job.get("config") or {}; sources = job.get("sources") or {}
    if mode == "known": command = [str(hashcat_path(config)), "-m", "22000", str(hash_file), "--potfile-path", str(ROOT / "data" / "lan-worker.potfile"), "--show", "--outfile", str(outfile), "--outfile-format", "1,2", "--separator", "|"]
    elif mode in {"common", "pattern"}:
        candidate = folder / "generated.dict"; candidate.write_text(job.get("candidate_text") or "", encoding="utf-8"); command += ["-a", "0", str(candidate)]
    elif mode == "dictionary": command += ["-a", "0", str(find_source(config, sources["wordlist_id"]))]
    elif mode == "rules": command += ["-a", "0", str(find_source(config, sources["wordlist_id"])), "-r", str(find_source(config, sources["rule_id"]))]
    elif mode == "hybrid": command += ["-a", "6", str(find_source(config, sources["wordlist_id"])), str(cfg.get("mask") or "?d?d?d?d")]
    elif mode == "mask":
        command += ["-a", "3", str(cfg.get("mask") or "?d?d?d?d?d?d?d?d")]
        if cfg.get("increment"): command.append("--increment")
    if cfg.get("optimized"): command.append("--optimized-kernel-enable")
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(command, cwd=str(hashcat_path(config).parent), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1, creationflags=flags)
    apply_affinity(process, cpu_profile)
    runtime = {"last": {"name": config["worker_name"], "telemetry": {"capabilities": config.get("_capabilities") or {}}},
               "paused": False, "workload": max(1, min(int(job.get("workload", 3)), 4)), "throttle_suspended": False}
    controller_stop = threading.Event()

    def throttle_loop() -> None:
        duty_cycles = {1: 0.35, 2: 0.60, 3: 0.85, 4: 1.0}
        period = 0.40
        while process.poll() is None and not controller_stop.is_set():
            if runtime["paused"]:
                runtime["throttle_suspended"] = False
                controller_stop.wait(0.08)
                continue
            duty = duty_cycles.get(int(runtime["workload"]), 1.0)
            if runtime["throttle_suspended"]:
                set_suspended(process, False); runtime["throttle_suspended"] = False
            if duty >= 1.0:
                controller_stop.wait(0.08); continue
            if controller_stop.wait(period * duty): break
            if not runtime["paused"] and process.poll() is None:
                runtime["throttle_suspended"] = set_suspended(process, True)
            if controller_stop.wait(period * (1.0 - duty)): break
        if runtime["throttle_suspended"] and not runtime["paused"] and process.poll() is None:
            set_suspended(process, False); runtime["throttle_suspended"] = False

    def control_loop() -> None:
        while not controller_stop.wait(0.5):
            try:
                reply = api(config, f"/api/lan/jobs/{job_id}/progress", dict(runtime["last"]))
                action = reply.get("command")
                runtime["workload"] = max(1, min(int(reply.get("workload", runtime["workload"])), 4))
                if action == "cancel":
                    if runtime["paused"]: set_suspended(process, False); runtime["paused"] = False
                    process.terminate()
                elif action == "pause" and not runtime["paused"]:
                    runtime["paused"] = set_suspended(process, True)
                elif action in {"resume", ""} and runtime["paused"]:
                    set_suspended(process, False); runtime["paused"] = False
            except (OSError, urllib.error.URLError):
                pass

    controller = threading.Thread(target=control_loop, name=f"job-{job_id}-control", daemon=True)
    throttle = threading.Thread(target=throttle_loop, name=f"job-{job_id}-live-profile", daemon=True)
    controller.start(); throttle.start()
    with log_file.open("a", encoding="utf-8") as log:
        for line in iter(process.stdout.readline, ""):
            log.write(line); log.flush()
            if line.lstrip().startswith("{"):
                try:
                    status = json.loads(line); progress = flatten_numbers(status.get("progress")); devices = status.get("devices") or []
                    speeds = [float(device.get("speed") or 0) for device in devices]
                    done, total = (progress + [0, 0])[:2]; speed = sum(speeds)
                    device = next((item for item in devices if str(item.get("device_type", "")).upper() == "GPU"), devices[0] if devices else {})
                    telemetry = nvidia_telemetry()
                    telemetry.update({key: value for key, value in {
                        "device_name": device.get("device_name"), "temperature": device.get("temp"),
                        "utilization": device.get("util"), "fan_speed": device.get("fanspeed"),
                        "clock_graphics": device.get("corespeed"), "memory_clock": device.get("memoryspeed")
                    }.items() if value not in (None, -1)})
                    telemetry["capabilities"] = config.get("_capabilities") or {}
                    runtime["last"] = {"name": config["worker_name"], "progress": done / total * 100 if total else 0,
                        "speed_hps": speed, "speed": f"{speed:,.0f} H/s", "recovered": int(status.get("recovered_hashes") or 0),
                        "candidates_done": int(done), "candidates_total": int(total), "eta": str(status.get("estimated_stop") or ""),
                        "telemetry": telemetry}
                except (ValueError, KeyError, urllib.error.URLError):
                    pass
    code = process.wait()
    controller_stop.set(); controller.join(timeout=3); throttle.join(timeout=3)
    api(config, f"/api/lan/jobs/{job_id}/complete", {"name": config["worker_name"], "exit_code": code,
        "outfile": outfile.read_text(encoding="utf-8", errors="replace") if outfile.is_file() else "",
        "log": log_file.read_text(encoding="utf-8", errors="replace")[-200000:]})


def main() -> None:
    config = load_config()
    acquire_single_instance(str(config.get("worker_name") or socket.gethostname()))
    if not config.get("token"):
        raise RuntimeError("Paste the coordinator LAN token into lan-worker.json")
    capabilities = backend_capabilities(config)
    capabilities["worker_version"] = WORKER_VERSION
    config["_capabilities"] = capabilities
    api(config, "/api/lan/register", {"name": config["worker_name"], "gpu_name": ", ".join(capabilities["device_names"]) or "Hashcat worker",
                                      "capabilities": capabilities})
    print(f"Connected to {config['coordinator_url']} as {config['worker_name']}")
    while True:
        try:
            idle_telemetry = nvidia_telemetry()
            idle_telemetry["capabilities"] = capabilities
            response = api(config, "/api/lan/claim", {"name": config["worker_name"], "telemetry": idle_telemetry})
            if response.get("job"):
                try:
                    run_job(config, response["job"])
                except Exception as error:
                    api(config, f"/api/lan/jobs/{response['job']['id']}/complete", {
                        "name": config["worker_name"], "exit_code": 2, "outfile": "", "log": f"Worker preparation failed: {error}"})
            else: time.sleep(max(1, int(config.get("poll_seconds", 3))))
        except urllib.error.HTTPError as error:
            print(f"Coordinator error {error.code}: {error.read().decode('utf-8', errors='replace')}"); time.sleep(10)
        except Exception as error:
            print(f"Worker error: {error}"); time.sleep(10)


if __name__ == "__main__":
    main()
