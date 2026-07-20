from __future__ import annotations

import csv
import ctypes
import atexit
import base64
import binascii
import html
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DB_PATH = DATA / "newfpv_audit.db"
CONFIG_PATH = ROOT / "config.json"
RESULTS_CSV = DATA / "recovered.csv"
POTFILE = DATA / "hashcat.potfile"
RESULT_LOCK = threading.Lock()
CONFIG_LOCK = threading.Lock()
TELEMETRY_LOCK = threading.Lock()
NETWORK_CACHE_LOCK = threading.Lock()
NETWORK_CACHE: dict[str, tuple[int, int, list[dict]]] = {}
SOURCE_IDENTITY_LOCK = threading.Lock()
SOURCE_IDENTITY_CACHE: dict[str, tuple[int, int, str]] = {}
BACKEND_INFO_LOCK = threading.Lock()
BACKEND_INFO_CACHE: dict[str, object] = {"key": "", "value": {}}
CPU_SAMPLE_LOCK = threading.Lock()
CPU_SAMPLE_PREVIOUS: tuple[int, int] | None = None
CASCADE_DEDUP_LOCK = threading.Lock()
WORDLIST_FILTER_LOCK = threading.Lock()
WORDLIST_ANALYSIS_LOCK = threading.Lock()
WORDLIST_ANALYSIS_ACTIVE: set[int] = set()
NOTIFICATION_LOCK = threading.Lock()
NOTIFICATION_LAST_SENT: dict[str, float] = {}
LOGIN_ATTEMPT_LOCK = threading.Lock()
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
BENCHMARK_LOCK = threading.Lock()
BENCHMARK_STATE: dict[str, object] = {"status": "idle", "speed": "", "speed_hps": 0.0, "output": "", "error": ""}
BENCHMARK_PATH = DATA / "benchmark.json"
TELEGRAM_INTAKE_STOP = threading.Event()
TELEGRAM_OFFSET_PATH = DATA / "telegram-update-offset.txt"
SELF_SIGNED_HTTPS_URL = ""
ALLOWED_CAPTURES = {".22000", ".hc22000", ".pcap", ".pcapng", ".cap"}
ALLOWED_WORDLISTS = {".txt", ".dic", ".dict", ".lst", ".wordlist"}
ALLOWED_RULES = {".rule"}
CAPTURE_SORT_MODES = {"current", "likely_fastest", "factory_first", "simple_first", "alphabetical", "fewest_networks", "newest", "oldest"}
FACTORY_SSID_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:tp[-_ ]?link|zte|huawei|keenetic|xiaomi|redmi|netgear|d[-_ ]?link|"
    r"dir[-_ ]?\d|asus|tenda|mercusys|mikrotik|linksys|zyxel|mgts|rostelecom|beeline|"
    r"sagemcom|sercomm|nokia|fiberhome|router)",
    re.IGNORECASE,
)
COMMON_PASSWORDS = (
    "12345678", "password", "123456789", "qwerty123", "qwertyui", "1234567890",
    "password1", "password123", "adminadmin", "admin1234", "administrator",
    "iloveyou", "welcome1", "welcome123", "letmein1", "internet", "internet1",
    "wifi12345", "wifi123456", "wireless", "homewifi", "home1234", "default1",
    "00000000", "11111111", "22222222", "33333333", "44444444", "55555555",
    "66666666", "77777777", "88888888", "99999999", "11223344", "12341234",
    "87654321", "12121212", "12344321", "10203040", "987654321", "qwerty12",
    "qwerty1234", "asdfghjk", "zxcvbnm1", "1q2w3e4r", "1q2w3e4r5t",
    "abc12345", "abcd1234", "changeme", "guest1234", "router123", "router1234",
    "xiaomi123", "tplink123", "tplink1234", "netgear1", "linksys1", "mikrotik",
)
COMMON_CANDIDATE_VERSION = 1
PATTERN_BUILDER_VERSION = 1
BACKUP_FORMAT = "newfpv-handshake-lab-memory-v1"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_config() -> dict:
    return {
        "host": "127.0.0.1",
        "port": 8787,
        "hashcat_path": "",
        "hcxpcapngtool_path": "",
        "max_workers": 1,
        "workload_profile": 3,
        "cpu_profile": "off",
        "temperature_abort": 90,
        "force_opencl": False,
        "restore_interrupted_jobs": True,
        "queue_paused": False,
        "theme_accent": "cyan",
        "lan_enabled": False,
        "lan_token": "",
        "lan_job_timeout": 180,
        "notifications_windows": True,
        "notifications_telegram": False,
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "telegram_file_intake": False,
        "notify_password_found": True,
        "notify_overheat": True,
        "notify_worker_error": True,
        "notify_queue_complete": True,
        "remote_access_enabled": False,
        "remote_username": "newfpv",
        "remote_password_hash": "",
        "remote_https_url": "",
        "self_signed_https_enabled": False,
        "https_port": 8788,
        "workspace_root": str(ROOT),
    }


def load_config() -> dict:
    config = default_config()
    if CONFIG_PATH.exists():
        try:
            config.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
    return config


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def relocated_workspace_path(value: str, old_root: str) -> str:
    if not value or not old_root:
        return value
    normalized_value = os.path.normcase(os.path.normpath(value))
    normalized_old = os.path.normcase(os.path.normpath(old_root)).rstrip("\\/")
    if normalized_value != normalized_old and not normalized_value.startswith(normalized_old + os.sep):
        return value
    relative = value[len(old_root.rstrip("\\/")):].lstrip("\\/")
    return str(ROOT / Path(relative))


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def stop_job_clock(connection: sqlite3.Connection, job_id: int, stopped_at: str | None = None) -> None:
    """Persist active execution time for one job without counting pauses or queue time."""
    row = connection.execute(
        "SELECT elapsed_seconds,active_started_at FROM jobs WHERE id=?",
        (job_id,),
    ).fetchone()
    if not row or not row["active_started_at"]:
        return
    stopped = stopped_at or now()
    try:
        started_value = datetime.fromisoformat(str(row["active_started_at"]))
        stopped_value = datetime.fromisoformat(stopped)
        seconds = max(0.0, (stopped_value - started_value).total_seconds())
    except (TypeError, ValueError):
        seconds = 0.0
    connection.execute(
        "UPDATE jobs SET elapsed_seconds=?,active_started_at=NULL WHERE id=?",
        (float(row["elapsed_seconds"] or 0) + seconds, job_id),
    )


def start_job_clock(connection: sqlite3.Connection, job_id: int, started_at: str | None = None) -> None:
    """Start or resume the active clock while preserving time already spent on this job."""
    started = started_at or now()
    connection.execute(
        "UPDATE jobs SET started_at=COALESCE(started_at,?),active_started_at=? WHERE id=?",
        (started, started, job_id),
    )


def stop_job_clocks(connection: sqlite3.Connection, statuses: tuple[str, ...]) -> None:
    placeholders = ",".join("?" for _ in statuses)
    for row in connection.execute(
        f"SELECT id FROM jobs WHERE status IN ({placeholders}) AND active_started_at IS NOT NULL",
        statuses,
    ).fetchall():
        stop_job_clock(connection, int(row["id"]))


def builtin_presets() -> list[tuple[str, str, dict]]:
    numeric = "?d?d?d?d?d?d?d?d"
    return [
        ("Quick triage", "Known results and the first ordered dictionary across every selected capture.", {
            "order": "strategy_first", "workload": 3,
            "stages": [{"kind": "known"}, {"kind": "first_wordlists", "limit": 1}],
        }),
        ("Top two sources", "Known results followed by only the first two ordered dictionaries.", {
            "order": "strategy_first", "workload": 3,
            "stages": [{"kind": "known"}, {"kind": "first_wordlists", "limit": 2}],
        }),
        ("Overnight balanced", "All captures by stage: known results, every dictionary, rules, then an 8-digit mask.", {
            "order": "strategy_first", "workload": 3,
            "stages": [{"kind": "known"}, {"kind": "all_wordlists", "mode": "dictionary"},
                       {"kind": "all_rules"}, {"kind": "mask", "mask": numeric}],
        }),
        ("Dictionary sweep", "Dictionary 1 across every remaining capture, then dictionary 2, and so on.", {
            "order": "strategy_first", "workload": 3,
            "stages": [{"kind": "known"}, {"kind": "all_wordlists", "mode": "dictionary"}],
        }),
        ("Capture marathon", "One capture through all dictionaries before moving to the next capture.", {
            "order": "capture_first", "workload": 3,
            "stages": [{"kind": "known"}, {"kind": "all_wordlists", "mode": "dictionary"}],
        }),
        ("8-digit PIN first", "Tests 00000000–99999999 first, then sweeps the ordered dictionaries.", {
            "order": "strategy_first", "workload": 4,
            "stages": [{"kind": "known"}, {"kind": "mask", "mask": numeric},
                       {"kind": "all_wordlists", "mode": "dictionary"}],
        }),
        ("Maximum overnight", "Maximum GPU workload: known results, PIN space, dictionaries, then every dictionary/rule pair.", {
            "order": "strategy_first", "workload": 4,
            "stages": [{"kind": "known"}, {"kind": "mask", "mask": numeric},
                       {"kind": "all_wordlists", "mode": "dictionary"}, {"kind": "all_rules"}],
        }),
        ("Numeric 1–8 digits", "Incremental numeric mask from short PINs through eight digits, then stop.", {
            "order": "strategy_first", "workload": 4,
            "stages": [{"kind": "known"}, {"kind": "mask", "mask": numeric, "increment": True}],
        }),
        ("Rules sweep", "Known results, then every ordered dictionary combined with every connected rule file.", {
            "order": "strategy_first", "workload": 3,
            "stages": [{"kind": "known"}, {"kind": "all_rules"}],
        }),
        ("Quiet overnight", "Every ordered dictionary at a lower workload so the desktop remains more responsive.", {
            "order": "strategy_first", "workload": 2,
            "stages": [{"kind": "known"}, {"kind": "all_wordlists", "mode": "dictionary"}],
        }),
        ("Deep capture marathon", "Finish every dictionary, rule pair and numeric mask on one capture before moving on.", {
            "order": "capture_first", "workload": 4,
            "stages": [{"kind": "known"}, {"kind": "all_wordlists", "mode": "dictionary"},
                       {"kind": "all_rules"}, {"kind": "mask", "mask": numeric}],
        }),
    ]


def init_storage() -> None:
    for folder in (DATA, DATA / "runtime", ROOT / "captures", ROOT / "hashes", ROOT / "wordlists", ROOT / "rules", ROOT / "masks", ROOT / "logs", ROOT / "sessions", ROOT / "tools"):
        folder.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        atomic_json(CONFIG_PATH, default_config())
    configured = load_config()
    old_workspace = str(configured.get("workspace_root") or ROOT)
    relocated = os.path.normcase(os.path.normpath(old_workspace)) != os.path.normcase(os.path.normpath(str(ROOT)))
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY, filename TEXT NOT NULL, stored_path TEXT NOT NULL,
                hash_path TEXT, kind TEXT NOT NULL, networks INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL UNIQUE,
                imported_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wordlists (
                id INTEGER PRIMARY KEY, filename TEXT NOT NULL, stored_path TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'wordlist', bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL UNIQUE, imported_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS strategies (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, mode TEXT NOT NULL,
                config_json TEXT NOT NULL DEFAULT '{}', position INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1, builtin INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY, capture_id INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
                strategy_id INTEGER NOT NULL REFERENCES strategies(id) ON DELETE CASCADE,
                status TEXT NOT NULL, progress REAL NOT NULL DEFAULT 0, speed TEXT NOT NULL DEFAULT '',
                eta TEXT NOT NULL DEFAULT '', session_name TEXT NOT NULL, command_json TEXT NOT NULL DEFAULT '[]',
                log_path TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
                started_at TEXT, finished_at TEXT
            );
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, essid TEXT NOT NULL,
                bssid TEXT NOT NULL DEFAULT '', password TEXT NOT NULL, capture_id INTEGER,
                strategy TEXT NOT NULL, found_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, level TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS presets (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                config_json TEXT NOT NULL, builtin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY, job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
                temperature REAL, utilization REAL, memory_used REAL, memory_total REAL,
                power_draw REAL, power_limit REAL, clock_graphics REAL, fan_speed REAL,
                speed_hps REAL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS network_attempts (
                id INTEGER PRIMARY KEY, essid TEXT NOT NULL, bssid TEXT NOT NULL,
                method_key TEXT NOT NULL, mode TEXT NOT NULL, method_label TEXT NOT NULL,
                source_label TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT 'exhausted',
                job_id INTEGER, completed_at TEXT NOT NULL,
                UNIQUE(essid,bssid,method_key)
            );
            CREATE TABLE IF NOT EXISTS lan_workers (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, gpu_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'offline', current_job_id INTEGER,
                address TEXT NOT NULL DEFAULT '', telemetry_json TEXT NOT NULL DEFAULT '{}',
                last_seen TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )
        ensure_column(connection, "captures", "diagnostic_path", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "wordlists", "position", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "wordlists", "analysis_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column(connection, "strategies", "hidden", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "jobs", "speed_hps", "REAL NOT NULL DEFAULT 0")
        ensure_column(connection, "jobs", "recovered", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "jobs", "candidates_done", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "jobs", "candidates_total", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "jobs", "preset_name", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "jobs", "workload", "INTEGER NOT NULL DEFAULT 3")
        ensure_column(connection, "jobs", "position", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "jobs", "capture_ids_json", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column(connection, "jobs", "attempt_key", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "jobs", "attempt_label", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "jobs", "worker_name", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "jobs", "remote_command", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "jobs", "cpu_profile", "TEXT NOT NULL DEFAULT 'off'")
        ensure_column(connection, "jobs", "elapsed_seconds", "REAL NOT NULL DEFAULT 0")
        ensure_column(connection, "jobs", "active_started_at", "TEXT")
        ensure_column(connection, "lan_workers", "paused", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "lan_workers", "workload", "INTEGER NOT NULL DEFAULT 3")
        ensure_column(connection, "lan_workers", "cpu_profile", "TEXT NOT NULL DEFAULT 'off'")
        ensure_column(connection, "results", "job_id", "INTEGER")
        # Backfill old installations once. New jobs use an active clock that excludes
        # queue waiting and pauses; legacy rows can only provide their wall interval.
        connection.execute(
            """UPDATE jobs SET elapsed_seconds=MAX(0,(julianday(COALESCE(finished_at,?))-julianday(started_at))*86400)
               WHERE elapsed_seconds=0 AND started_at IS NOT NULL""",
            (now(),),
        )
        stop_job_clocks(connection, ("running", "paused", "lan_preparing", "lan_running", "lan_paused"))
        if relocated:
            for table, columns in {
                "captures": ("stored_path", "hash_path", "diagnostic_path"),
                "wordlists": ("stored_path",),
                "jobs": ("log_path",),
            }.items():
                rows = connection.execute(f"SELECT id,{','.join(columns)} FROM {table}").fetchall()
                for row in rows:
                    previous = [str(row[column] or "") for column in columns]
                    updated = [relocated_workspace_path(value, old_workspace) for value in previous]
                    if updated != previous:
                        assignments = ",".join(f"{column}=?" for column in columns)
                        connection.execute(f"UPDATE {table} SET {assignments} WHERE id=?", (*updated, row["id"]))
            connection.execute(
                "UPDATE jobs SET status='queued',error='Workspace moved; restarting without the old checkpoint' WHERE status IN ('running','paused')"
            )
        connection.execute("UPDATE wordlists SET position=id WHERE position=0")
        connection.execute("UPDATE jobs SET position=id WHERE position=0")
        if connection.execute("SELECT COUNT(*) FROM strategies").fetchone()[0] == 0:
            defaults = [
                ("Known results", "known", {}, 0, 1),
                ("Common passwords", "common", {}, 1, 1),
                ("Pattern Builder", "pattern", {}, 2, 1),
                ("Dictionary", "dictionary", {"wordlist_id": None}, 3, 1),
                ("Dictionary + rules", "rules", {"wordlist_id": None, "rule_id": None}, 4, 1),
                ("Hybrid", "hybrid", {"wordlist_id": None, "mask": "?d?d?d?d"}, 5, 1),
                ("Mask", "mask", {"mask": "?d?d?d?d?d?d?d?d", "increment": False}, 6, 1),
            ]
            connection.executemany(
                "INSERT INTO strategies(name,mode,config_json,position,builtin) VALUES(?,?,?,?,?)",
                [(name, mode, json.dumps(cfg), pos, builtin) for name, mode, cfg, pos, builtin in defaults],
            )
            connection.execute("UPDATE strategies SET enabled=0 WHERE mode='common'")
            connection.execute("UPDATE strategies SET enabled=0 WHERE mode='pattern'")
        elif not connection.execute("SELECT 1 FROM strategies WHERE mode='common' LIMIT 1").fetchone():
            connection.execute("UPDATE strategies SET position=position+1 WHERE position>=1")
            connection.execute(
                "INSERT INTO strategies(name,mode,config_json,position,enabled,builtin) "
                "VALUES('Common passwords','common','{}',1,0,1)"
            )
        if not connection.execute("SELECT 1 FROM strategies WHERE mode='pattern' LIMIT 1").fetchone():
            connection.execute("UPDATE strategies SET position=position+1 WHERE position>=2")
            connection.execute("INSERT INTO strategies(name,mode,config_json,position,enabled,builtin) VALUES('Pattern Builder','pattern','{}',2,0,1)")
        initialize_attempt_memory(connection)
        for name, description, preset_config in builtin_presets():
            existing = connection.execute("SELECT id FROM presets WHERE name=? AND builtin=1", (name,)).fetchone()
            if existing:
                connection.execute("UPDATE presets SET description=?,config_json=?,updated_at=? WHERE id=?",
                                   (description, json.dumps(preset_config), now(), existing[0]))
            else:
                connection.execute("INSERT INTO presets(name,description,config_json,builtin,created_at,updated_at) VALUES(?,?,?,1,?,?)",
                                   (name, description, json.dumps(preset_config), now(), now()))
        if load_config().get("restore_interrupted_jobs", True):
            connection.execute("UPDATE jobs SET status='queued',worker_name='',remote_command='',error='Recovered after app restart' WHERE status IN ('running','paused')")
        else:
            connection.execute("UPDATE jobs SET status='blocked', error='Interrupted by app restart; retry manually' WHERE status IN ('running','paused')")
    if relocated:
        for restore_file in (ROOT / "sessions").glob("*.restore"):
            restore_file.unlink(missing_ok=True)
        configured["workspace_root"] = str(ROOT)
        configured["hashcat_path"] = relocated_workspace_path(str(configured.get("hashcat_path") or ""), old_workspace)
        configured["hcxpcapngtool_path"] = relocated_workspace_path(str(configured.get("hcxpcapngtool_path") or ""), old_workspace)
        atomic_json(CONFIG_PATH, configured)
    POTFILE.touch(exist_ok=True)
    if not RESULTS_CSV.exists():
        with RESULTS_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
            csv.writer(handle).writerow(["ESSID", "BSSID", "Password", "Strategy", "Found at"])
            handle.flush()
            os.fsync(handle.fileno())


def row_dict(row: sqlite3.Row) -> dict:
    result = dict(row)
    if "config_json" in result:
        result["config"] = json.loads(result.pop("config_json") or "{}")
    if "command_json" in result:
        result["command"] = json.loads(result.pop("command_json") or "[]")
    if "capture_ids_json" in result:
        result["capture_ids"] = json.loads(result.pop("capture_ids_json") or "[]")
    if "telemetry_json" in result:
        try:
            result["telemetry"] = json.loads(result.pop("telemetry_json") or "{}")
        except json.JSONDecodeError:
            result["telemetry"] = {}
    if "analysis_json" in result:
        try:
            result["analysis"] = json.loads(result.pop("analysis_json") or "{}")
        except json.JSONDecodeError:
            result["analysis"] = {}
    return result


def latest_lan_log_telemetry(path: Path, sampled_at: str | None = None) -> dict:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, path.stat().st_size - 1024 * 1024))
            text = handle.read().decode("utf-8", errors="replace")
        for line in reversed(text.splitlines()):
            start = line.find('{ "session"')
            if start < 0:
                continue
            try:
                status = json.loads(line[start:])
            except json.JSONDecodeError:
                continue
            devices = status.get("devices") or []
            device = next((item for item in devices if str(item.get("device_type", "")).upper() == "GPU"), devices[0] if devices else {})
            if not device:
                continue
            return {
                "device_name": device.get("device_name"), "temperature": device.get("temp"),
                "utilization": device.get("util"), "fan_speed": device.get("fanspeed"),
                "clock_graphics": device.get("corespeed"), "memory_clock": device.get("memoryspeed"),
                "speed_hps": float(device.get("speed") or 0), "sampled_at": sampled_at,
                "source": "last_job",
            }
    except OSError:
        return {}
    return {}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def linked_source_fingerprint(path: Path) -> str:
    stat = path.stat()
    identity = f"linked\0{path.resolve()}\0{stat.st_size}\0{stat.st_mtime_ns}"
    return hashlib.sha256(identity.encode("utf-8", errors="surrogatepass")).hexdigest()


def analyze_wordlist_file(path: Path, progress_callback=None) -> dict:
    """Stream a dictionary and count WPA-ready candidates without retaining its contents in RAM."""
    total_bytes = path.stat().st_size
    started = time.monotonic()
    counters = {
        "lines": 0, "valid": 0, "unique_valid": 0, "duplicates": 0,
        "short": 0, "too_long": 0, "empty": 0, "nul_bytes": 0,
        "bytes_read": 0, "bytes_total": total_bytes,
    }
    runtime = DATA / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(prefix="wordlist-seen-", suffix=".sqlite", dir=runtime, delete=False)
    seen_path = Path(handle.name)
    handle.close()
    seen = sqlite3.connect(seen_path, timeout=60)
    try:
        seen.execute("PRAGMA journal_mode=OFF")
        seen.execute("PRAGMA synchronous=OFF")
        seen.execute("PRAGMA temp_store=MEMORY")
        seen.execute("CREATE TABLE seen (digest BLOB PRIMARY KEY) WITHOUT ROWID")
        last_report = 0.0
        with path.open("rb") as source:
            for raw in source:
                counters["bytes_read"] += len(raw)
                candidate = raw.rstrip(b"\r\n")
                counters["lines"] += 1
                if not candidate:
                    counters["empty"] += 1
                digest = hashlib.blake2b(candidate, digest_size=16).digest()
                unique = True
                try:
                    seen.execute("INSERT INTO seen(digest) VALUES(?)", (digest,))
                except sqlite3.IntegrityError:
                    counters["duplicates"] += 1
                    unique = False
                length = len(candidate)
                if length < 8:
                    counters["short"] += 1
                elif length > 63:
                    counters["too_long"] += 1
                elif b"\0" in candidate:
                    counters["nul_bytes"] += 1
                else:
                    counters["valid"] += 1
                    if unique:
                        counters["unique_valid"] += 1
                current = time.monotonic()
                if progress_callback and current - last_report >= 0.75:
                    progress_callback({**counters, "status": "processing", "elapsed_seconds": round(current - started, 1)})
                    last_report = current
        seen.commit()
    finally:
        seen.close()
        seen_path.unlink(missing_ok=True)
    duration = max(0.001, time.monotonic() - started)
    return {
        **counters,
        "status": "complete",
        "elapsed_seconds": round(duration, 2),
        "lines_per_second": round(counters["lines"] / duration, 1),
        "analyzed_at": now(),
    }


def save_wordlist_analysis(item_id: int, analysis: dict) -> None:
    with db() as connection:
        connection.execute(
            "UPDATE wordlists SET analysis_json=? WHERE id=?",
            (json.dumps(analysis, ensure_ascii=False), item_id),
        )


def analyze_wordlist_task(item_id: int) -> None:
    try:
        with db() as connection:
            row = connection.execute("SELECT * FROM wordlists WHERE id=?", (item_id,)).fetchone()
        if not row:
            return
        item = dict(row)
        path = Path(item["stored_path"])
        if item["kind"] != "wordlist":
            raise ValueError("Rule files are not password dictionaries")
        if not path.is_file():
            raise FileNotFoundError(f"Source file is missing: {path}")
        initial = {
            "status": "processing", "lines": 0, "bytes_read": 0,
            "bytes_total": path.stat().st_size, "started_at": now(),
        }
        save_wordlist_analysis(item_id, initial)
        last_persisted = 0.0

        def progress(snapshot: dict) -> None:
            nonlocal last_persisted
            current = time.monotonic()
            if current - last_persisted >= 1.5:
                save_wordlist_analysis(item_id, {**initial, **snapshot})
                last_persisted = current

        result = analyze_wordlist_file(path, progress)
        result["source_sha256"] = item["sha256"]
        save_wordlist_analysis(item_id, result)
        add_event("success", f"Analyzed {item['filename']}: {result['unique_valid']:,} unique WPA-ready candidates")
    except Exception as exc:
        try:
            save_wordlist_analysis(item_id, {"status": "failed", "error": str(exc)[:500], "finished_at": now()})
        except Exception:
            pass
        add_event("error", f"Wordlist analysis failed: {exc}")
    finally:
        with WORDLIST_ANALYSIS_LOCK:
            WORDLIST_ANALYSIS_ACTIVE.discard(item_id)


def scan_local_sources() -> tuple[list[dict], list[str]]:
    candidates: list[tuple[Path, str]] = []
    for folder, kind, suffixes in (
        (ROOT / "wordlists", "wordlist", ALLOWED_WORDLISTS),
        (ROOT / "rules", "rule", ALLOWED_RULES),
    ):
        for path in folder.rglob("*"):
            if path.is_file() and path.suffix.lower() in suffixes:
                candidates.append((path.resolve(), kind))
    hashcat = executable("hashcat_path", ("hashcat",))
    if hashcat:
        hashcat_root = Path(hashcat).resolve().parent
        example_dictionary = hashcat_root / "example.dict"
        if example_dictionary.is_file():
            candidates.append((example_dictionary.resolve(), "wordlist"))
        bundled = hashcat_root / "rules"
        recommended = {
            "best66.rule", "d3ad0ne.rule", "dive.rule", "leetspeak.rule",
            "rockyou-30000.rule", "T0XlC.rule",
        }
        if bundled.is_dir():
            for path in bundled.glob("*.rule"):
                if path.name in recommended:
                    candidates.append((path.resolve(), "rule"))
    candidates.sort(key=lambda item: (item[0].stat().st_size, item[0].name.lower()))
    imported: list[dict] = []
    errors: list[str] = []
    with db() as connection:
        for path, kind in candidates:
            try:
                stat = path.stat()
                existing = connection.execute("SELECT id FROM wordlists WHERE stored_path=?", (str(path),)).fetchone()
                if existing:
                    connection.execute("UPDATE wordlists SET filename=?,bytes=?,analysis_json='{}' WHERE id=?", (path.name, stat.st_size, existing[0]))
                    continue
                position = connection.execute("SELECT COALESCE(MAX(position),0)+1 FROM wordlists WHERE kind=?", (kind,)).fetchone()[0]
                cursor = connection.execute(
                    "INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,?)",
                    (path.name, str(path), kind, stat.st_size, linked_source_fingerprint(path), now(), position),
                )
                imported.append({"id": cursor.lastrowid, "filename": path.name, "bytes": stat.st_size, "kind": kind})
            except (OSError, sqlite3.Error) as error:
                errors.append(f"{path.name}: {error}")
    return imported, errors


def cascade_deduplicate(rows: list[dict]) -> dict:
    seen: set[bytes] = set()
    staged: list[tuple[dict, Path, Path]] = []
    files: list[dict] = []
    total_input = 0
    total_written = 0
    total_removed = 0
    try:
        for row in rows:
            source = Path(row["stored_path"])
            if row["kind"] == "rule" or source.suffix.lower() == ".rule":
                continue
            if source.suffix.lower() not in ALLOWED_WORDLISTS:
                continue
            if not source.is_file():
                raise FileNotFoundError(f"Dictionary not found: {source}")

            destination = source if source.name.lower().startswith("unique_") else source.with_name(f"unique_{source.name}")
            if destination != source and destination.exists():
                destination = source.with_name(f"unique_{uuid.uuid4().hex[:8]}_{source.name}")
            temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
            input_lines = 0
            written_lines = 0
            with source.open("rb") as reader, temporary.open("wb") as writer:
                for raw_line in reader:
                    input_lines += 1
                    candidate = raw_line.rstrip(b"\r\n")
                    if not candidate or candidate in seen:
                        continue
                    seen.add(candidate)
                    writer.write(candidate)
                    writer.write(b"\n")
                    written_lines += 1
                writer.flush()
                os.fsync(writer.fileno())
            removed_lines = input_lines - written_lines
            staged.append((row, temporary, destination))
            files.append({
                "source": source.name,
                "output": destination.name,
                "input_lines": input_lines,
                "written_lines": written_lines,
                "removed_lines": removed_lines,
            })
            total_input += input_lines
            total_written += written_lines
            total_removed += removed_lines

        for row, temporary, destination in staged:
            os.replace(temporary, destination)
            stat = destination.stat()
            with db() as connection:
                connection.execute(
                    "UPDATE wordlists SET filename=?,stored_path=?,bytes=?,sha256=?,imported_at=?,analysis_json='{}' WHERE id=?",
                    (destination.name, str(destination.resolve()), stat.st_size,
                     linked_source_fingerprint(destination), now(), row["id"]),
                )
        return {
            "processed_files": len(files),
            "input_lines": total_input,
            "written_lines": total_written,
            "removed_lines": total_removed,
            "files": files,
        }
    except BaseException:
        for _, temporary, _ in staged:
            temporary.unlink(missing_ok=True)
        raise


def unique_path(folder: Path, original: str) -> Path:
    clean = secure_filename(original) or "upload.bin"
    return folder / f"{uuid.uuid4().hex[:10]}_{clean}"


def decode_essid(value: str) -> str:
    try:
        decoded = bytes.fromhex(value).decode("utf-8", errors="replace")
        return decoded or "<hidden>"
    except ValueError:
        return "<invalid>"


def parse_22000(path: Path) -> list[dict]:
    networks = []
    seen = set()
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            line = raw.strip()
            parts = line.split("*")
            if len(parts) < 6 or parts[0] != "WPA" or parts[1] not in {"01", "02"}:
                continue
            fingerprint = hashlib.sha256(line.encode()).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            networks.append({"fingerprint": fingerprint, "hash": line, "essid": decode_essid(parts[5]), "bssid": parts[3].upper()})
    return networks


def cached_networks(path: Path) -> list[dict]:
    try:
        stat = path.stat()
    except OSError:
        return []
    key = str(path.resolve())
    with NETWORK_CACHE_LOCK:
        cached = NETWORK_CACHE.get(key)
        if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
            return cached[2]
    networks = parse_22000(path)
    with NETWORK_CACHE_LOCK:
        NETWORK_CACHE[key] = (stat.st_mtime_ns, stat.st_size, networks)
    return networks


def normalize_bssid(value: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", str(value or "")).upper()[:12]


def network_identity(network: dict) -> tuple[str, str]:
    return str(network.get("essid") or ""), normalize_bssid(network.get("bssid") or "")


def portable_source_identity(path: Path) -> str:
    stat = path.stat()
    cache_key = str(path.resolve())
    with SOURCE_IDENTITY_LOCK:
        cached = SOURCE_IDENTITY_CACHE.get(cache_key)
        if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
            return cached[2]
    sample_size = 2 * 1024 * 1024
    offsets = sorted({0, max(0, stat.st_size // 2 - sample_size // 2), max(0, stat.st_size - sample_size)})
    digest = hashlib.sha256()
    digest.update(f"newfpv-source-v1\0{stat.st_size}\0".encode("ascii"))
    with path.open("rb") as handle:
        for offset in offsets:
            handle.seek(offset)
            chunk = handle.read(sample_size)
            digest.update(str(offset).encode("ascii") + b"\0" + chunk)
    value = digest.hexdigest()
    with SOURCE_IDENTITY_LOCK:
        SOURCE_IDENTITY_CACHE[cache_key] = (stat.st_mtime_ns, stat.st_size, value)
    return value


def strategy_attempt_descriptor(connection: sqlite3.Connection, stage: dict) -> tuple[str, str, str] | None:
    stage = dict(stage)
    mode = str(stage.get("mode") or "")
    if mode == "known":
        return None
    raw_config = stage.get("config_json")
    config = stage.get("config") if isinstance(stage.get("config"), dict) else json.loads(raw_config or "{}")
    payload: dict = {"version": 1, "mode": mode}
    source_labels: list[str] = []

    def add_source(field: str, source_id: int | None) -> None:
        row = connection.execute("SELECT id,filename,stored_path,sha256 FROM wordlists WHERE id=?", (source_id,)).fetchone() if source_id else None
        if not row:
            payload[field] = f"missing:{source_id or 0}"
            source_labels.append(f"missing source #{source_id or 0}")
            return
        path = Path(row["stored_path"])
        try:
            identity = portable_source_identity(path)
        except OSError:
            identity = str(row["sha256"] or f"missing:{row['id']}")
        payload[field] = identity
        source_labels.append(row["filename"])

    if mode == "common":
        payload["generator"] = COMMON_CANDIDATE_VERSION
        label = f"Common passwords v{COMMON_CANDIDATE_VERSION}"
    elif mode == "pattern":
        rows = connection.execute("SELECT essid,bssid,password FROM results ORDER BY essid,bssid,password").fetchall()
        corpus = "\n".join(f"{row['essid']}\0{normalize_bssid(row['bssid'])}\0{row['password']}" for row in rows)
        payload["generator"] = PATTERN_BUILDER_VERSION
        payload["corpus"] = hashlib.sha256(corpus.encode("utf-8", errors="replace")).hexdigest()
        label = f"Pattern Builder v{PATTERN_BUILDER_VERSION}"
    elif mode == "dictionary":
        add_source("wordlist", config.get("wordlist_id"))
        label = f"Dictionary · {source_labels[0]}"
    elif mode == "rules":
        add_source("wordlist", config.get("wordlist_id"))
        add_source("rule", config.get("rule_id"))
        label = f"Rules · {' + '.join(source_labels)}"
    elif mode == "hybrid":
        add_source("wordlist", config.get("wordlist_id"))
        payload["mask"] = str(config.get("mask") or "?d?d?d?d")
        label = f"Hybrid · {source_labels[0]} + {payload['mask']}"
    elif mode == "mask":
        payload["mask"] = str(config.get("mask") or "?d?d?d?d?d?d?d?d")
        payload["increment"] = bool(config.get("increment"))
        label = f"Mask · {payload['mask']}{' · increment' if payload['increment'] else ''}"
    else:
        payload["config"] = config
        label = str(stage.get("name") or mode.title())
    method_key = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return method_key, label, " + ".join(source_labels)


def capture_sort_metadata(capture: dict) -> dict:
    networks = cached_networks(Path(capture.get("hash_path") or ""))
    essids = [
        str(item.get("essid") or "").strip() for item in networks
        if str(item.get("essid") or "").strip() not in {"", "<hidden>", "<invalid>"}
    ]
    primary = essids[0] if essids else Path(str(capture.get("filename") or "capture")).stem
    factory = any(FACTORY_SSID_PATTERN.search(essid) for essid in essids)
    normalized = re.sub(r"[^0-9A-Za-z]", "", primary)
    looks_random = bool(re.search(r"[A-Fa-f0-9]{8,}$", normalized)) or (
        len(normalized) >= 14 and bool(re.search(r"[A-Za-z]", normalized)) and bool(re.search(r"\d", normalized))
    )
    simple_score = (
        0 if re.fullmatch(r"[A-Za-z][A-Za-z _-]{2,15}", primary) else 1,
        1 if looks_random else 0,
        len(primary),
    )
    return {
        "primary_essid": primary,
        "factory_ssid": factory,
        "simple_score": simple_score,
        "network_count": len(networks) or int(capture.get("networks") or 0),
    }


def filter_short_wordlist(source: Path) -> dict:
    destination = source if source.name.lower().startswith("wpa_") else source.with_name(f"wpa_{source.name}")
    if destination != source and destination.exists():
        destination = source.with_name(f"wpa_{uuid.uuid4().hex[:8]}_{source.name}")
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    input_lines = kept_lines = removed_lines = 0
    try:
        with source.open("rb") as reader, temporary.open("wb") as writer:
            for raw in reader:
                input_lines += 1
                candidate = raw.rstrip(b"\r\n")
                if len(candidate) < 8:
                    removed_lines += 1
                    continue
                writer.write(candidate + b"\n")
                kept_lines += 1
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {"path": destination, "input_lines": input_lines, "kept_lines": kept_lines,
            "removed_lines": removed_lines, "bytes": destination.stat().st_size}


def sort_captures(captures: list[dict], mode: str) -> list[dict]:
    if mode not in CAPTURE_SORT_MODES or mode == "current":
        return captures
    decorated = [(capture, capture_sort_metadata(capture), index) for index, capture in enumerate(captures)]
    if mode == "likely_fastest":
        key = lambda item: (
            not item[1]["factory_ssid"], *item[1]["simple_score"], item[1]["network_count"],
            item[1]["primary_essid"].casefold(), item[2],
        )
        return [item[0] for item in sorted(decorated, key=key)]
    if mode == "factory_first":
        key = lambda item: (not item[1]["factory_ssid"], item[1]["primary_essid"].casefold(), item[2])
        return [item[0] for item in sorted(decorated, key=key)]
    if mode == "simple_first":
        key = lambda item: (*item[1]["simple_score"], item[1]["primary_essid"].casefold(), item[2])
        return [item[0] for item in sorted(decorated, key=key)]
    if mode == "alphabetical":
        return [item[0] for item in sorted(decorated, key=lambda item: (item[1]["primary_essid"].casefold(), item[2]))]
    if mode == "fewest_networks":
        return [item[0] for item in sorted(decorated, key=lambda item: (item[1]["network_count"], item[1]["primary_essid"].casefold(), item[2]))]
    reverse = mode == "newest"
    return [item[0] for item in sorted(
        decorated, key=lambda item: (str(item[0].get("imported_at") or ""), -item[2]), reverse=reverse
    )]


def common_candidate_wordlist(hash_path: Path, job_id: int) -> Path:
    candidates: list[str] = []
    seen: set[bytes] = set()

    def add(value: str) -> None:
        value = str(value or "").strip()
        if not value or any(character in value for character in "\r\n\0"):
            return
        encoded = value.encode("utf-8", errors="ignore")
        if len(encoded) < 8 or len(encoded) > 63 or encoded in seen:
            return
        seen.add(encoded)
        candidates.append(value)

    for password in COMMON_PASSWORDS:
        add(password)

    for network in cached_networks(hash_path):
        essid = str(network.get("essid") or "").strip()
        if essid and essid not in {"<hidden>", "<invalid>"}:
            compact = re.sub(r"[^0-9A-Za-z]+", "", essid)
            tokens = [token for token in re.split(r"[^0-9A-Za-z]+", essid) if token]
            bases = [essid, compact, *tokens]
            for base in bases:
                if not base:
                    continue
                variants = (base, base.lower(), base.upper(), base.capitalize())
                for variant in variants:
                    add(variant)
                for suffix in ("1234", "12345", "123456", "12345678", "2024", "2025", "2026", "2027", "@123", "!123"):
                    add(base + suffix)
                    add(base.lower() + suffix)
                    add(base.capitalize() + suffix)
        bssid = re.sub(r"[^0-9A-Fa-f]", "", str(network.get("bssid") or ""))
        if len(bssid) == 12:
            add(bssid)
            add(bssid.lower())
            add(bssid[-8:])
            add(bssid[-8:].lower())

    destination = DATA / "runtime" / f"job-{job_id}-common.dict"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for candidate in candidates:
            handle.write(candidate + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
    return destination


def pattern_candidate_wordlist(hash_path: Path, job_id: int) -> Path:
    """Build a compact, ranked candidate list from locally recovered password structure."""
    candidates: list[str] = []
    seen: set[bytes] = set()

    def add(value: str) -> None:
        value = str(value or "").strip()
        if not value or any(character in value for character in "\r\n\0"):
            return
        encoded = value.encode("utf-8", errors="ignore")
        valid = 8 <= len(encoded) <= 63 or (len(value) == 64 and bool(re.fullmatch(r"[0-9a-fA-F]{64}", value)))
        if not valid or encoded in seen or len(candidates) >= 250_000:
            return
        seen.add(encoded)
        candidates.append(value)

    with db() as connection:
        recovered = [dict(row) for row in connection.execute(
            "SELECT essid,bssid,password FROM results ORDER BY id DESC"
        )]
    networks = cached_networks(hash_path)
    target_stems: list[str] = []
    for network in networks:
        essid = str(network.get("essid") or "")
        compact = re.sub(r"[^0-9A-Za-z]+", "", essid)
        if compact:
            target_stems.extend((compact, compact.lower(), compact.upper(), compact.capitalize()))

    suffixes = ["1234", "12345", "123456", "12345678", "2024", "2025", "2026", "2027", "!", "@123"]
    learned_stems: list[str] = []
    learned_suffixes: list[str] = []
    for item in recovered:
        password = str(item.get("password") or "")
        add(password)
        for variant in (password.lower(), password.upper(), password.capitalize(), password.swapcase()):
            add(variant)
        match = re.fullmatch(r"(.+?)(\d{2,10}|[!@#$%^&*]+)$", password)
        if match:
            stem, suffix = match.groups()
            learned_stems.extend((stem, stem.lower(), stem.capitalize()))
            learned_suffixes.append(suffix)
        for year in re.findall(r"(?:19|20)\d{2}", password):
            learned_suffixes.append(year)
    learned_stems = list(dict.fromkeys(learned_stems))[:500]
    learned_suffixes = list(dict.fromkeys(learned_suffixes + suffixes))[:250]
    for stem in list(dict.fromkeys(target_stems + learned_stems))[:1000]:
        add(stem)
        for suffix in learned_suffixes:
            add(stem + suffix)
    for target in target_stems[:100]:
        for source in learned_stems[:250]:
            digits = re.findall(r"\d+", source)
            for value in digits:
                add(target + value)

    destination = DATA / "runtime" / f"job-{job_id}-pattern.dict"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(candidates))
        if candidates:
            handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
    return destination


def normalize_22000(source: Path, destination: Path) -> list[dict]:
    networks = parse_22000(source)
    write_22000_networks(destination, networks)
    return networks


def write_22000_networks(destination: Path, networks: list[dict]) -> None:
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for network in networks:
            handle.write(network["hash"] + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)


def executable(config_key: str, names: tuple[str, ...]) -> str | None:
    configured = str(load_config().get(config_key, "")).strip()
    if configured and Path(configured).is_file():
        return configured
    for candidate in names:
        found = shutil.which(candidate)
        if found:
            return found
    local_names = names + tuple(name + ".exe" for name in names if not name.endswith(".exe"))
    for name in local_names:
        matches = list((ROOT / "tools").glob(f"**/{name}"))
        if matches:
            return str(matches[0])
    return None


def hashcat_backend_info() -> dict:
    path_value = executable("hashcat_path", ("hashcat",))
    if not path_value:
        return {"cpu_available": False, "cpu_name": "CPU backend unavailable"}
    path = Path(path_value)
    try:
        cache_key = f"{path.resolve()}:{path.stat().st_mtime_ns}"
    except OSError:
        return {"cpu_available": False, "cpu_name": "CPU backend unavailable"}
    with BACKEND_INFO_LOCK:
        if BACKEND_INFO_CACHE.get("key") == cache_key:
            return dict(BACKEND_INFO_CACHE.get("value") or {})
    try:
        process = subprocess.run([str(path), "-I"], cwd=str(path.parent), capture_output=True, text=True,
                                 timeout=20, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        output = "\n".join((process.stdout, process.stderr))
    except (OSError, subprocess.TimeoutExpired):
        output = ""
    blocks = re.split(r"(?=Backend Device ID #\d+)", output)
    cpu_names = []
    for block in blocks:
        if re.search(r"Type\.{3,}: CPU", block, re.IGNORECASE):
            match = re.search(r"Name\.{3,}:\s*(.+)", block)
            cpu_names.append(match.group(1).strip() if match else "OpenCL CPU")
    value = {"cpu_available": bool(cpu_names), "cpu_name": ", ".join(dict.fromkeys(cpu_names)) or "CPU OpenCL runtime not detected"}
    with BACKEND_INFO_LOCK:
        BACKEND_INFO_CACHE.update({"key": cache_key, "value": value})
    return value


def system_cpu_sample() -> dict:
    if os.name != "nt":
        return {"load": None, "logical_cpus": os.cpu_count() or 1}
    idle = ctypes.c_ulonglong(); kernel = ctypes.c_ulonglong(); user = ctypes.c_ulonglong()
    if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        return {"load": None, "logical_cpus": os.cpu_count() or 1}
    idle_value, total_value = idle.value, kernel.value + user.value
    global CPU_SAMPLE_PREVIOUS
    with CPU_SAMPLE_LOCK:
        previous = CPU_SAMPLE_PREVIOUS
        CPU_SAMPLE_PREVIOUS = (idle_value, total_value)
    load = None
    if previous and total_value > previous[1]:
        load = max(0.0, min(100.0, 100.0 * (1 - (idle_value - previous[0]) / (total_value - previous[1]))))
    return {"load": load, "logical_cpus": os.cpu_count() or 1}


def set_process_suspended(process: subprocess.Popen, suspended: bool) -> bool:
    if process.poll() is not None:
        return False
    if os.name != "nt":
        try:
            import signal
            os.kill(process.pid, signal.SIGSTOP if suspended else signal.SIGCONT)
            return True
        except OSError:
            return False
    access = 0x0800
    handle = ctypes.windll.kernel32.OpenProcess(access, False, process.pid)
    if not handle:
        return False
    try:
        operation = ctypes.windll.ntdll.NtSuspendProcess if suspended else ctypes.windll.ntdll.NtResumeProcess
        return operation(handle) == 0
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def apply_cpu_affinity(process: subprocess.Popen, profile: str) -> None:
    if os.name != "nt" or profile == "off":
        return
    logical = max(1, os.cpu_count() or 1)
    count = {"low": max(1, logical // 4), "balanced": max(1, logical // 2), "high": logical}.get(profile, 1)
    mask = (1 << count) - 1
    handle = ctypes.windll.kernel32.OpenProcess(0x0200 | 0x0400, False, process.pid)
    if handle:
        try:
            ctypes.windll.kernel32.SetProcessAffinityMask(handle, ctypes.c_size_t(mask))
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)


def summarize_conversion_output(output: str) -> str:
    normalized = " ".join(output.split())
    lowered = normalized.lower()
    if "no hashes written" in lowered:
        if "missing eapol" in lowered or "missing frames" in lowered:
            return "No usable WPA handshake or PMKID was found. Required EAPOL frames are missing; recapture this network and try again."
        return "No usable WPA handshake or PMKID was found in this capture. Recapture the network and try again."
    if "missing eapol" in lowered or "missing frames" in lowered:
        return "The capture is incomplete because required EAPOL frames are missing. Recapture the network and try again."
    if not normalized:
        return "The converter did not produce a usable WPA/PMKID hash. Open diagnostics for technical details."
    return "The converter did not produce a usable WPA/PMKID hash. Open diagnostics for technical details."


def capture_quality_assessment(capture: dict, networks: list[dict]) -> dict:
    diagnostics = ""
    path = Path(str(capture.get("diagnostic_path") or ""))
    if path.is_file():
        try:
            diagnostics = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            pass
    pmkid = sum(1 for item in networks if str(item.get("hash") or "").startswith("WPA*01*"))
    eapol = sum(1 for item in networks if str(item.get("hash") or "").startswith("WPA*02*"))
    reasons: list[str] = []
    recommendations: list[str] = []
    if not networks:
        return {
            "score": 0, "label": "Unusable", "pmkid": 0, "eapol": 0,
            "reasons": ["No usable PMKID or EAPOL record was extracted."],
            "recommendations": ["Recapture longer while an authorized client reconnects; keep beacon and association frames."],
        }
    score = 92 if eapol else 84
    reasons.append(f"{len(networks)} usable WPA record{'s' if len(networks) != 1 else ''} extracted ({eapol} EAPOL, {pmkid} PMKID).")
    penalties = (
        ("packet read error", 18, "The packet file contains a read error.", "Keep the original capture and recapture if verification is unstable."),
        ("missing eapol m3", 10, "EAPOL M3 frames are missing.", "Capture a complete client reconnect to improve the message pair."),
        ("missing frames", 6, "Some contextual Wi-Fi frames are missing.", "Avoid capture filters and retain beacon/association traffic."),
        ("duration was a way too short", 8, "Capture duration was very short.", "Capture for longer around a fresh authorized connection."),
        ("limited dump file format", 3, "Legacy PCAP stores limited metadata.", "Prefer PCAPNG for future captures."),
    )
    for needle, penalty, reason, recommendation in penalties:
        if needle in diagnostics:
            score -= penalty
            reasons.append(reason)
            recommendations.append(recommendation)
    score = max(35, min(100, score + min(5, max(0, len(networks) - 1))))
    label = "Excellent" if score >= 90 else "Good" if score >= 75 else "Usable" if score >= 55 else "Partial"
    if not recommendations:
        recommendations.append("Ready for local password verification; preserve the original capture as evidence.")
    return {"score": score, "label": label, "pmkid": pmkid, "eapol": eapol,
            "reasons": reasons, "recommendations": recommendations}


def write_conversion_diagnostics(destination: Path, output: str) -> Path:
    path = ROOT / "logs" / f"{destination.stem}.conversion.log"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(output.strip() or "hcxpcapngtool returned no diagnostic output.")
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return path


def convert_capture(source: Path, destination: Path) -> tuple[list[dict], str, str]:
    converter = executable("hcxpcapngtool_path", ("hcxpcapngtool",))
    if not converter:
        return [], "Install hcxtools or set hcxpcapngtool_path in Settings.", ""
    process = subprocess.run([converter, "-o", str(destination), str(source)], capture_output=True, text=True, timeout=300)
    networks = parse_22000(destination) if destination.exists() else []
    output = "\n".join(part for part in (process.stdout, process.stderr) if part).strip()
    diagnostic_path = str(write_conversion_diagnostics(destination, output))
    if process.returncode not in (0, 1) or not networks:
        return [], summarize_conversion_output(output), diagnostic_path
    return networks, "Ready for the recovery pipeline.", diagnostic_path


def add_event(level: str, message: str) -> None:
    with db() as connection:
        connection.execute("INSERT INTO events(level,message,created_at) VALUES(?,?,?)", (level, message[:1000], now()))


def send_windows_notification(title: str, message: str) -> None:
    if os.name != "nt":
        return
    import base64
    app_id = "NewFPV.HandshakeLab"
    logo_path = (ROOT / "static" / "handshake-lab-logo.svg").resolve()
    logo_uri = logo_path.as_uri()
    xml = (
        "<toast duration='short'><visual><binding template='ToastGeneric'>"
        f"<text>{html.escape(title)}</text><text>{html.escape(message)}</text>"
        f"<image placement='appLogoOverride' src='{html.escape(logo_uri, quote=True)}'/>"
        "</binding></visual></toast>"
    )
    xml_encoded = base64.b64encode(xml.encode("utf-8")).decode("ascii")
    logo_encoded = base64.b64encode(str(logo_path).encode("utf-8")).decode("ascii")
    script = (
        f"$appId='{app_id}';$appKey='HKCU:\\Software\\Classes\\AppUserModelId\\'+$appId;"
        f"$icon=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{logo_encoded}'));"
        "New-Item -Path $appKey -Force|Out-Null;"
        "New-ItemProperty -Path $appKey -Name DisplayName -Value 'Handshake Lab' -PropertyType String -Force|Out-Null;"
        "New-ItemProperty -Path $appKey -Name IconUri -Value $icon -PropertyType String -Force|Out-Null;"
        "New-ItemProperty -Path $appKey -Name IconBackgroundColor -Value '#07090a' -PropertyType String -Force|Out-Null;"
        "New-ItemProperty -Path $appKey -Name ShowInSettings -Value 1 -PropertyType DWord -Force|Out-Null;"
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]>$null;"
        "[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]>$null;"
        f"$payload=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{xml_encoded}'));"
        "$document=New-Object Windows.Data.Xml.Dom.XmlDocument;$document.LoadXml($payload);"
        "$toast=[Windows.UI.Notifications.ToastNotification]::new($document);$null=$toast.add_Activated({});"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast);"
        "Start-Sleep -Milliseconds 2000"
    )
    encoded = script.encode("utf-16le")
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.b64encode(encoded).decode("ascii")],
        capture_output=True, timeout=12, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if completed.returncode:
        raise OSError(completed.stderr.decode("utf-8", errors="replace")[:300] or "Windows toast command failed")


def telegram_api(token: str, method: str, fields: dict | None = None, timeout: int = 25) -> dict:
    payload = urllib.parse.urlencode(fields or {}).encode("utf-8")
    request_value = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}", data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
    )
    with urllib.request.urlopen(request_value, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not payload.get("ok"):
        raise OSError(str(payload.get("description") or f"Telegram {method} failed"))
    return payload


def telegram_send_message(token: str, chat_id: str, text: str, reply_markup: dict | None = None,
                          message_id: int | None = None) -> dict:
    fields: dict[str, object] = {"chat_id": chat_id, "text": text[:4096]}
    if reply_markup:
        fields["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    method = "sendMessage"
    if message_id:
        method = "editMessageText"
        fields["message_id"] = message_id
    try:
        return telegram_api(token, method, fields, 12)
    except OSError as error:
        if message_id and "message is not modified" in str(error).lower():
            return {"ok": True, "result": {}}
        raise


def send_telegram_notification(token: str, chat_id: str, title: str, message: str) -> None:
    telegram_send_message(token, chat_id, f"{title}\n{message}")


def telegram_https_url(config: dict | None = None) -> str:
    current = config or load_config()
    if not current.get("remote_access_enabled"):
        return ""
    value = str(current.get("remote_https_url") or "").strip().rstrip("/")
    if not value and current.get("self_signed_https_enabled"):
        value = SELF_SIGNED_HTTPS_URL
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return ""
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return ""
    return value


def generate_self_signed_certificate() -> tuple[Path, Path, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    tls_dir = DATA / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    certificate_path = tls_dir / "handshake-lab-self-signed.crt"
    key_path = tls_dir / "handshake-lab-self-signed.key"
    hostnames = {"localhost", socket.gethostname()}
    addresses = {"127.0.0.1"}
    try:
        addresses.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    public_ip = ""
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=6) as response:
            public_ip = str(json.loads(response.read().decode("utf-8")).get("ip") or "")
        ipaddress.ip_address(public_ip)
        addresses.add(public_ip)
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        public_ip = ""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Handshake Lab Local"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Handshake Lab self-signed"),
    ])
    alternate_names: list[x509.GeneralName] = [x509.DNSName(name) for name in sorted(hostnames) if name]
    for address in sorted(addresses):
        try:
            alternate_names.append(x509.IPAddress(ipaddress.ip_address(address)))
        except ValueError:
            continue
    timestamp = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(timestamp - timedelta(minutes=5))
        .not_valid_after(timestamp + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(alternate_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    temporary_key = key_path.with_suffix(".key.tmp")
    temporary_certificate = certificate_path.with_suffix(".crt.tmp")
    temporary_key.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    ))
    temporary_certificate.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    os.replace(temporary_key, key_path)
    os.replace(temporary_certificate, certificate_path)
    return certificate_path, key_path, public_ip


def start_self_signed_https(config: dict) -> None:
    global SELF_SIGNED_HTTPS_URL
    if not (config.get("remote_access_enabled") and config.get("self_signed_https_enabled")):
        SELF_SIGNED_HTTPS_URL = ""
        return
    try:
        certificate_path, key_path, public_ip = generate_self_signed_certificate()
        from werkzeug.serving import make_server
        port = max(1, min(int(config.get("https_port", 8788)), 65535))
        server = make_server(
            str(config.get("host") or "0.0.0.0"), port, app, threaded=True,
            ssl_context=(str(certificate_path), str(key_path)),
        )
        display_host = public_ip or "127.0.0.1"
        SELF_SIGNED_HTTPS_URL = f"https://{display_host}:{port}"
        threading.Thread(target=server.serve_forever, name="self-signed-https", daemon=True).start()
        add_event("info", f"Self-signed HTTPS listener started on port {port}")
    except Exception as error:
        SELF_SIGNED_HTTPS_URL = ""
        add_event("error", f"Self-signed HTTPS failed: {str(error)[:240]}")


def telegram_keyboard(config: dict | None = None) -> dict:
    current = config or load_config()
    paused = bool(current.get("queue_paused"))
    workload = max(1, min(int(current.get("workload_profile", 3)), 4))
    profiles = [
        {"text": ("✓ " if item == workload else "") + f"W{item}", "callback_data": f"hl:w{item}"}
        for item in range(1, 5)
    ]
    rows = [
        [{"text": "📊 Status", "callback_data": "hl:status"},
         {"text": "📋 Queue", "callback_data": "hl:queue"}],
        [{"text": "▶️ Resume all" if paused else "⏸ Pause all", "callback_data": "hl:toggle"},
         {"text": "🔑 Results", "callback_data": "hl:results"}],
        profiles,
        [{"text": "📎 Upload PCAP", "callback_data": "hl:upload"},
         {"text": "❔ Help", "callback_data": "hl:help"}],
    ]
    web_url = telegram_https_url(current)
    if web_url:
        rows.append([{"text": "🌐 Open Handshake Lab", "web_app": {"url": web_url}}])
    elif current.get("remote_access_enabled"):
        rows.append([{"text": "🌐 Web UI setup", "callback_data": "hl:web"}])
    return {"inline_keyboard": rows}


def telegram_status_text() -> str:
    config = load_config()
    with db() as connection:
        counts = {row["status"]: int(row["amount"]) for row in connection.execute(
            "SELECT status,COUNT(*) AS amount FROM jobs GROUP BY status"
        )}
        captures = int(connection.execute("SELECT COUNT(*) FROM captures").fetchone()[0])
        recovered = int(connection.execute("SELECT COUNT(*) FROM results").fetchone()[0])
        current = connection.execute(
            """SELECT j.id,j.status,j.progress,c.filename,s.name AS strategy_name
               FROM jobs j JOIN captures c ON c.id=j.capture_id JOIN strategies s ON s.id=j.strategy_id
               WHERE j.status IN ('running','paused','lan_running','lan_paused') ORDER BY j.id LIMIT 1"""
        ).fetchone()
    telemetry = dict(getattr(runner, "current_telemetry", {}) or {})
    paused = bool(config.get("queue_paused"))
    workload = max(1, min(int(config.get("workload_profile", 3)), 4))
    waiting = sum(counts.get(state, 0) for state in ("queued", "running", "paused", "lan_preparing", "lan_running", "lan_paused"))
    lines = [
        "HANDSHAKE LAB",
        f"Engine: {'PAUSED' if paused else ('RUNNING' if current else 'IDLE')} · W{workload}",
        f"Captures: {captures} · Queue: {waiting} · Recovered: {recovered}",
    ]
    if current:
        lines.append(f"Job #{current['id']} · {current['strategy_name']} · {float(current['progress'] or 0):.2f}%")
        lines.append(str(current["filename"]))
    speed = float(telemetry.get("speed_hps") or 0)
    temperature = telemetry.get("temperature")
    utilization = telemetry.get("utilization")
    if speed or temperature is not None or utilization is not None:
        gpu = []
        if speed:
            gpu.append(human_rate(speed))
        if temperature is not None:
            gpu.append(f"{float(temperature):.0f}°C")
        if utilization is not None:
            gpu.append(f"{float(utilization):.0f}% GPU")
        lines.append("GPU: " + " · ".join(gpu))
    return "\n".join(lines)


def telegram_queue_text() -> str:
    active_states = ("running", "paused", "lan_preparing", "lan_running", "lan_paused", "queued")
    with db() as connection:
        total = int(connection.execute(
            f"SELECT COUNT(*) FROM jobs WHERE status IN ({','.join('?' * len(active_states))})", active_states
        ).fetchone()[0])
        rows = connection.execute(
            f"""SELECT j.id,j.status,j.progress,j.eta,c.filename,s.name AS strategy_name
                FROM jobs j JOIN captures c ON c.id=j.capture_id JOIN strategies s ON s.id=j.strategy_id
                WHERE j.status IN ({','.join('?' * len(active_states))})
                ORDER BY CASE WHEN j.status='queued' THEN 1 ELSE 0 END,j.position,j.id LIMIT 8""",
            active_states,
        ).fetchall()
    lines = [f"QUEUE · {total} active/waiting"]
    if not rows:
        lines.append("Nothing is waiting. Build a pipeline in the web UI.")
    for row in rows:
        state = str(row["status"]).replace("lan_", "REMOTE ").upper()
        lines.append(f"#{row['id']} · {state} · {float(row['progress'] or 0):.1f}%")
        lines.append(f"{row['strategy_name']} · {row['filename']}")
    if total > len(rows):
        lines.append(f"…and {total - len(rows)} more")
    return "\n".join(lines)


def telegram_results_text() -> str:
    with db() as connection:
        total = int(connection.execute("SELECT COUNT(*) FROM results").fetchone()[0])
        rows = connection.execute(
            "SELECT essid,password,found_at FROM results ORDER BY id DESC LIMIT 8"
        ).fetchall()
    lines = [f"RECOVERED · {total}"]
    if not rows:
        lines.append("No recovered passwords yet.")
    for row in rows:
        lines.append(f"🔑 {row['essid']}  →  {row['password']}")
    return "\n".join(lines)


def telegram_help_text(file_intake: bool) -> str:
    state = "enabled" if file_intake else "disabled in Settings"
    return (
        "HANDSHAKE LAB BOT\n"
        "Use the buttons below to inspect and control the local recovery queue. W1–W4 changes the live GPU profile.\n\n"
        "UPLOADS\n"
        f"File intake is {state}. Send a file as a Telegram document (not as media). Supported captures: "
        ".pcap, .pcapng, .cap, .22000 and .hc22000. Dictionaries and .rule files are also accepted. "
        "Telegram Bot API downloads are limited to 20 MB. Captures are converted, validated and added to Captures; nothing starts automatically.\n\n"
        "Commands: /start /status /queue /results /help"
    )


def telegram_render(token: str, chat_id: str, view: str = "status", message_id: int | None = None) -> None:
    config = load_config()
    texts = {
        "status": telegram_status_text,
        "queue": telegram_queue_text,
        "results": telegram_results_text,
        "help": lambda: telegram_help_text(bool(config.get("telegram_file_intake"))),
        "upload": lambda: telegram_help_text(bool(config.get("telegram_file_intake"))),
        "web": lambda: (
            "WEB APP\nRemote Web is enabled, but Telegram requires a trusted HTTPS URL. "
            "Set HTTPS public URL in Settings after configuring a domain, VPN HTTPS share or reverse proxy. "
            "Handshake Lab will not present insecure HTTP as HTTPS."
        ),
    }
    text = texts.get(view, telegram_status_text)()
    telegram_send_message(token, chat_id, text, telegram_keyboard(config), message_id)


def telegram_sync_bot_ui(token: str, chat_id: str, config: dict) -> None:
    commands = [
        {"command": "start", "description": "Open the Handshake Lab panel"},
        {"command": "status", "description": "Show GPU and queue status"},
        {"command": "queue", "description": "Show active and waiting jobs"},
        {"command": "results", "description": "Show latest recovered passwords"},
        {"command": "help", "description": "Uploads, controls and safety"},
    ]
    telegram_api(token, "setMyCommands", {"commands": json.dumps(commands)}, 12)
    web_url = telegram_https_url(config)
    menu_button: dict = {"type": "default"}
    if web_url:
        menu_button = {"type": "web_app", "text": "Open Handshake Lab", "web_app": {"url": web_url}}
    telegram_api(token, "setChatMenuButton", {
        "chat_id": chat_id, "menu_button": json.dumps(menu_button, ensure_ascii=False),
    }, 12)


def import_telegram_document(filename: str, content: bytes) -> tuple[int, dict]:
    suffix = Path(filename).suffix.lower()
    endpoint = "/api/captures" if suffix in ALLOWED_CAPTURES else "/api/wordlists"
    handler = upload_captures if suffix in ALLOWED_CAPTURES else upload_wordlists
    with app.test_request_context(endpoint, method="POST", data={"files": (io.BytesIO(content), filename)}):
        result = handler()
    response, status = result if isinstance(result, tuple) else (result, 200)
    return int(status), response.get_json()


def telegram_file_intake_loop() -> None:
    offset = 0
    synced_identity = ""
    try:
        if TELEGRAM_OFFSET_PATH.is_file():
            offset = int(TELEGRAM_OFFSET_PATH.read_text(encoding="ascii").strip() or 0)
    except (OSError, ValueError):
        offset = 0
    while not TELEGRAM_INTAKE_STOP.is_set():
        config = load_config()
        token = str(config.get("telegram_bot_token") or "").strip()
        allowed_chat = str(config.get("telegram_chat_id") or "").strip()
        if not (config.get("notifications_telegram") and token and allowed_chat):
            TELEGRAM_INTAKE_STOP.wait(3)
            continue
        try:
            identity = hashlib.sha256(f"{token}\0{allowed_chat}\0{telegram_https_url(config)}".encode("utf-8")).hexdigest()
            if identity != synced_identity:
                telegram_sync_bot_ui(token, allowed_chat, config)
                synced_identity = identity
            updates = telegram_api(
                token, "getUpdates",
                {"offset": offset, "timeout": 15, "allowed_updates": json.dumps(["message", "callback_query"])}, 22,
            )
            for update in updates.get("result") or []:
                offset = max(offset, int(update.get("update_id", 0)) + 1)
                callback = update.get("callback_query") or {}
                if callback:
                    callback_message = callback.get("message") or {}
                    chat_id = str((callback_message.get("chat") or {}).get("id") or "")
                    if chat_id != allowed_chat:
                        continue
                    callback_id = str(callback.get("id") or "")
                    if callback_id:
                        telegram_api(token, "answerCallbackQuery", {"callback_query_id": callback_id}, 8)
                    action = str(callback.get("data") or "").removeprefix("hl:")
                    if action == "toggle":
                        set_global_queue_paused(not bool(load_config().get("queue_paused")))
                        action = "status"
                    elif re.fullmatch(r"w[1-4]", action):
                        set_global_workload(int(action[1]))
                        action = "status"
                    telegram_render(token, allowed_chat, action, int(callback_message.get("message_id") or 0) or None)
                    continue
                message = update.get("message") or {}
                chat_id = str((message.get("chat") or {}).get("id") or "")
                document = message.get("document") or {}
                if chat_id != allowed_chat:
                    continue
                text = str(message.get("text") or "").strip().split("@", 1)[0].lower()
                if text.startswith("/") and not document:
                    view = {
                        "/start": "status", "/menu": "status", "/status": "status",
                        "/queue": "queue", "/results": "results", "/help": "help",
                    }.get(text, "help")
                    telegram_render(token, allowed_chat, view)
                    continue
                if not document:
                    telegram_render(token, allowed_chat, "help")
                    continue
                if not config.get("telegram_file_intake"):
                    telegram_send_message(
                        token, allowed_chat,
                        "FILE INTAKE IS OFF\nEnable Telegram file intake in Settings and press Save changes before uploading.",
                        telegram_keyboard(config),
                    )
                    continue
                filename = secure_filename(str(document.get("file_name") or "telegram-upload"))
                suffix = Path(filename).suffix.lower()
                if suffix not in ALLOWED_CAPTURES | ALLOWED_WORDLISTS | ALLOWED_RULES:
                    telegram_send_message(token, allowed_chat, "FILE REJECTED\nUse .pcap, .pcapng, .cap, .22000, .hc22000, a dictionary or a Hashcat .rule file.", telegram_keyboard(config))
                    continue
                size = int(document.get("file_size") or 0)
                if size <= 0 or size > 20 * 1024 * 1024:
                    telegram_send_message(token, allowed_chat, "FILE REJECTED\nTelegram intake accepts documents up to 20 MB.", telegram_keyboard(config))
                    continue
                file_info = telegram_api(token, "getFile", {"file_id": document.get("file_id")}, 12).get("result") or {}
                file_path = str(file_info.get("file_path") or "")
                if not file_path:
                    raise OSError("Telegram did not return a download path")
                with urllib.request.urlopen(f"https://api.telegram.org/file/bot{token}/{urllib.parse.quote(file_path)}", timeout=45) as response:
                    content = response.read(20 * 1024 * 1024 + 1)
                if len(content) > 20 * 1024 * 1024:
                    raise OSError("Telegram document exceeded 20 MB")
                status, result = import_telegram_document(filename, content)
                imported = result.get("imported") or []
                errors = result.get("errors") or []
                detail = f"Imported {len(imported)} item(s)."
                if imported and suffix in ALLOWED_CAPTURES:
                    item = imported[0]
                    detail += f" {int(item.get('networks') or 0)} network(s), state: {item.get('status') or 'unknown'}."
                if errors:
                    detail += " " + "; ".join(str(item) for item in errors[:3])
                telegram_send_message(token, allowed_chat, f"UPLOAD COMPLETE\n{filename}\n{detail}", telegram_keyboard(config))
                add_event("success" if status < 400 else "error", f"Telegram intake: {filename}: {detail}")
            temporary = TELEGRAM_OFFSET_PATH.with_suffix(".tmp")
            temporary.write_text(str(offset), encoding="ascii")
            os.replace(temporary, TELEGRAM_OFFSET_PATH)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            add_event("error", f"Telegram intake: {error}")
            TELEGRAM_INTAKE_STOP.wait(5)


def notify_user(kind: str, title: str, message: str, cooldown_key: str = "", cooldown_seconds: int = 0) -> None:
    if globals().get("app") is not None and app.config.get("TESTING"):
        return
    config = load_config()
    switches = {
        "password": "notify_password_found", "overheat": "notify_overheat",
        "worker": "notify_worker_error", "queue": "notify_queue_complete", "test": "",
    }
    switch = switches.get(kind, "")
    if switch and not config.get(switch, True):
        return
    key = cooldown_key or f"{kind}:{title}:{message}"
    if cooldown_seconds:
        with NOTIFICATION_LOCK:
            previous = NOTIFICATION_LAST_SENT.get(key, 0)
            if time.time() - previous < cooldown_seconds:
                return
            NOTIFICATION_LAST_SENT[key] = time.time()

    def worker() -> None:
        if config.get("notifications_windows", True):
            try:
                send_windows_notification(title, message)
            except Exception as exc:
                add_event("error", f"Windows notification failed: {str(exc)[:240]}")
        if config.get("notifications_telegram", False):
            token = str(config.get("telegram_bot_token") or "").strip()
            chat_id = str(config.get("telegram_chat_id") or "").strip()
            if token and chat_id:
                try:
                    send_telegram_notification(token, chat_id, title, message)
                except Exception as exc:
                    add_event("error", f"Telegram notification failed: {str(exc)[:240]}")

    threading.Thread(target=worker, name=f"notification-{kind}", daemon=True).start()


def append_result(essid: str, bssid: str, password: str, capture_id: int | None, strategy: str,
                  job_id: int | None = None) -> bool:
    fingerprint = hashlib.sha256(f"{essid}\0{bssid}\0{password}".encode("utf-8", errors="replace")).hexdigest()
    timestamp = now()
    try:
        with db() as connection:
            connection.execute(
                "INSERT INTO results(fingerprint,essid,bssid,password,capture_id,strategy,found_at,job_id) VALUES(?,?,?,?,?,?,?,?)",
                (fingerprint, essid, bssid, password, capture_id, strategy, timestamp, job_id),
            )
    except sqlite3.IntegrityError:
        return False
    with RESULT_LOCK:
        with RESULTS_CSV.open("a", encoding="utf-8-sig", newline="") as handle:
            csv.writer(handle).writerow([essid, bssid, password, strategy, timestamp])
            handle.flush()
            os.fsync(handle.fileno())
    notify_user("password", f"Password recovered · {essid}", f"Password: {password}", f"password:{fingerprint}")
    return True


def rebuild_results_csv() -> None:
    with db() as connection:
        rows = connection.execute(
            "SELECT essid,bssid,password,strategy,found_at FROM results ORDER BY id"
        ).fetchall()
    temporary = RESULTS_CSV.with_suffix(".csv.tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ESSID", "BSSID", "Password", "Strategy", "Found at"])
        writer.writerows(tuple(row) for row in rows)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, RESULTS_CSV)


def import_outfile(path: Path, capture_id: int, strategy: str, hash_path: Path,
                   capture_lookup: dict[str, int] | None = None,
                   job_id: int | None = None) -> tuple[int, set[tuple[str, str]]]:
    if not path.exists():
        return 0, set()
    lookup = {item["hash"]: item for item in parse_22000(hash_path)}
    network_lookup = {(item["essid"], item["bssid"].replace(":", "").upper()): item for item in lookup.values()}
    imported = 0
    recovered_networks: set[tuple[str, str]] = set()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            raw = line.rstrip("\r\n")
            if "|" not in raw:
                continue
            hash_value, password = raw.split("|", 1)
            network = lookup.get(hash_value)
            if not network:
                legacy = hash_value.split(":", 3)
                if len(legacy) == 4:
                    network = network_lookup.get((legacy[3], legacy[1].replace(":", "").upper()))
            if network:
                network_capture_id = (capture_lookup or {}).get(hash_value, capture_id)
                if capture_lookup and hash_value not in capture_lookup:
                    network_capture_id = capture_lookup.get(network["hash"], capture_id)
                recovered_networks.add((network["essid"], network["bssid"]))
                if append_result(network["essid"], network["bssid"], password, network_capture_id, strategy, job_id):
                    imported += 1
    return imported, recovered_networks


def job_capture_ids(job: dict) -> list[int]:
    raw = job.get("capture_ids_json", job.get("capture_ids", []))
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except json.JSONDecodeError:
            raw = []
    ids = [int(value) for value in raw or []]
    return list(dict.fromkeys(ids or [int(job["capture_id"])]))


def source_networks_for_job(job: dict) -> tuple[list[dict], dict[str, int]]:
    capture_ids = job_capture_ids(job)
    placeholders = ",".join("?" * len(capture_ids))
    with db() as connection:
        rows = connection.execute(
            f"SELECT id,hash_path FROM captures WHERE id IN ({placeholders})", capture_ids
        ).fetchall()
    by_id = {row["id"]: row["hash_path"] for row in rows}
    networks: list[dict] = []
    capture_lookup: dict[str, int] = {}
    seen_networks: set[tuple[str, str]] = set()
    for capture_id in capture_ids:
        path_value = by_id.get(capture_id)
        if not path_value or not Path(path_value).is_file():
            continue
        for network in parse_22000(Path(path_value)):
            key = (network["essid"], network["bssid"])
            if key in seen_networks:
                continue
            seen_networks.add(key)
            networks.append(network)
            capture_lookup[network["hash"]] = capture_id
    return networks, capture_lookup


def descriptor_for_job(connection: sqlite3.Connection, job: dict) -> tuple[str, str, str] | None:
    if str(job.get("mode") or "") == "known":
        return None
    if job.get("attempt_key"):
        return str(job["attempt_key"]), str(job.get("attempt_label") or job.get("strategy_name") or "Method"), ""
    stage = job
    if not stage.get("mode") or "config_json" not in stage:
        row = connection.execute(
            "SELECT name,mode,config_json FROM strategies WHERE id=?", (job.get("strategy_id"),)
        ).fetchone()
        if not row:
            return None
        stage = dict(row)
    return strategy_attempt_descriptor(connection, stage)


def insert_network_attempts(connection: sqlite3.Connection, job: dict, networks: list[dict],
                            recovered_networks: set[tuple[str, str]] | None = None) -> int:
    descriptor = descriptor_for_job(connection, job)
    if not descriptor:
        return 0
    method_key, method_label, source_label = descriptor
    recovered = {(essid, normalize_bssid(bssid)) for essid, bssid in (recovered_networks or set())}
    inserted = 0
    for network in networks:
        essid, bssid = network_identity(network)
        if not essid or not bssid:
            continue
        outcome = "recovered" if (essid, bssid) in recovered else "exhausted"
        inserted += connection.execute(
            """INSERT OR IGNORE INTO network_attempts
               (essid,bssid,method_key,mode,method_label,source_label,outcome,job_id,completed_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (essid, bssid, method_key, str(job.get("mode") or ""), method_label, source_label,
             outcome, job.get("id"), now()),
        ).rowcount
    return inserted


def initialize_attempt_memory(connection: sqlite3.Connection) -> None:
    jobs = [dict(row) for row in connection.execute(
        """SELECT j.*,s.name AS strategy_name,s.mode,s.config_json
           FROM jobs j JOIN strategies s ON s.id=j.strategy_id"""
    )]
    for job in jobs:
        descriptor = descriptor_for_job(connection, job)
        if descriptor and not job.get("attempt_key"):
            connection.execute(
                "UPDATE jobs SET attempt_key=?,attempt_label=? WHERE id=?",
                (descriptor[0], descriptor[1], job["id"]),
            )
            job["attempt_key"], job["attempt_label"] = descriptor[0], descriptor[1]
    recovered = {(row["essid"], normalize_bssid(row["bssid"])) for row in connection.execute(
        "SELECT DISTINCT essid,bssid FROM results"
    )}
    for job in jobs:
        if job.get("mode") == "known" or job.get("status") != "complete" or not job.get("started_at"):
            continue
        if str(job.get("error") or "").lower().startswith("skipped:"):
            continue
        capture_ids = job_capture_ids(job)
        placeholders = ",".join("?" * len(capture_ids))
        rows = connection.execute(
            f"SELECT id,hash_path FROM captures WHERE id IN ({placeholders})", capture_ids
        ).fetchall()
        networks: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for row in rows:
            path = Path(row["hash_path"] or "")
            if not path.is_file():
                continue
            for network in cached_networks(path):
                identity = network_identity(network)
                if identity not in seen:
                    seen.add(identity)
                    networks.append(network)
        recovered_for_job = {identity for identity in seen if identity in recovered}
        insert_network_attempts(connection, job, networks, recovered_for_job)


def prepare_job_hashes(job: dict) -> tuple[Path | None, dict[str, int], int]:
    networks, capture_lookup = source_networks_for_job(job)
    if job.get("mode") != "known":
        with db() as connection:
            recovered = {(row["essid"], normalize_bssid(row["bssid"])) for row in connection.execute(
                "SELECT DISTINCT essid,bssid FROM results"
            )}
            descriptor = descriptor_for_job(connection, job)
            attempted = set()
            if descriptor:
                attempted = {(row["essid"], normalize_bssid(row["bssid"])) for row in connection.execute(
                    "SELECT essid,bssid FROM network_attempts WHERE method_key=?", (descriptor[0],)
                )}
        networks = [network for network in networks if network_identity(network) not in recovered | attempted]
    if not networks:
        return None, capture_lookup, 0
    target = DATA / "runtime" / f"job-{job['id']}.22000"
    temporary = target.with_suffix(".22000.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for network in networks:
            handle.write(network["hash"] + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)
    return target, capture_lookup, len(networks)


def skip_fully_recovered_jobs() -> int:
    with db() as connection:
        recovered = {(row["essid"], normalize_bssid(row["bssid"])) for row in connection.execute(
            "SELECT DISTINCT essid,bssid FROM results"
        )}
        queued = [dict(row) for row in connection.execute(
            """SELECT j.*,s.name AS strategy_name,s.mode,s.config_json
               FROM jobs j JOIN strategies s ON s.id=j.strategy_id WHERE j.status='queued'"""
        )]
        attempted_by_job: dict[int, set[tuple[str, str]]] = {}
        for job in queued:
            descriptor = descriptor_for_job(connection, job)
            if descriptor:
                attempted_by_job[job["id"]] = {
                    (row["essid"], normalize_bssid(row["bssid"])) for row in connection.execute(
                        "SELECT essid,bssid FROM network_attempts WHERE method_key=?", (descriptor[0],)
                    )
                }
    skipped: list[int] = []
    for job in queued:
        if job["mode"] == "known":
            continue
        networks, _ = source_networks_for_job(job)
        satisfied = recovered | attempted_by_job.get(job["id"], set())
        if networks and all(network_identity(network) in satisfied for network in networks):
            skipped.append(int(job["id"]))
    if skipped:
        with db() as connection:
            connection.executemany(
                "UPDATE jobs SET status='complete',progress=100,error='Skipped: recovered or method already tested',finished_at=? WHERE id=? AND status='queued'",
                [(now(), job_id) for job_id in skipped],
            )
    return len(skipped)


def reconcile_job_outfiles() -> int:
    with db() as connection:
        jobs = [dict(row) for row in connection.execute(
            """SELECT j.*,s.name AS strategy_name,s.mode,c.hash_path
               FROM jobs j JOIN strategies s ON s.id=j.strategy_id JOIN captures c ON c.id=j.capture_id"""
        )]
    imported_total = 0
    for job in jobs:
        outfile = DATA / f"job-{job['id']}-found.txt"
        if not outfile.is_file() or outfile.stat().st_size == 0:
            continue
        networks, capture_lookup = source_networks_for_job(job)
        if not networks:
            continue
        target = DATA / "runtime" / f"reconcile-{job['id']}.22000"
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            for network in networks:
                handle.write(network["hash"] + "\n")
        imported, _ = import_outfile(
            outfile, job["capture_id"], job["strategy_name"], target, capture_lookup, int(job["id"])
        )
        imported_total += imported
    if imported_total:
        skip_fully_recovered_jobs()
        add_event("success", f"Recovered {imported_total} saved result(s) from Hashcat output files")
    return imported_total


def hashcat_failure_message(log_path: Path, code: int) -> str:
    try:
        output = log_path.read_text(encoding="utf-8", errors="replace")[-12000:]
    except OSError:
        output = ""
    option = re.search(r"unknown option\s+--\s*([^\s]+)", output, re.IGNORECASE)
    if option:
        return f"Hashcat rejected option --{option.group(1)}"
    for line in reversed(output.splitlines()):
        clean = line.strip()
        if clean and not clean.startswith("{"):
            return f"Hashcat: {clean[:240]}"
    signed = code - (1 << 32) if code >= (1 << 31) else code
    return f"Hashcat exited with code {signed}"


def recent_process_logs(limit: int = 40) -> list[tuple[Path, str]]:
    paths = sorted((ROOT / "logs").glob("job-*.log"), key=lambda item: item.stat().st_mtime, reverse=True)[:limit]
    output: list[tuple[Path, str]] = []
    for path in paths:
        try:
            with path.open("rb") as handle:
                handle.seek(max(0, path.stat().st_size - 64000))
                output.append((path, handle.read().decode("utf-8", errors="replace")))
        except OSError:
            continue
    return output


def error_doctor_report() -> dict:
    issues: list[dict] = []

    def issue(identifier: str, severity: str, title: str, detail: str, action: str = "", fix_label: str = "") -> None:
        issues.append({
            "id": identifier, "severity": severity, "title": title, "detail": detail,
            "action": action, "fix_label": fix_label, "fixable": bool(action),
        })

    hashcat = executable("hashcat_path", ("hashcat",))
    converter = executable("hcxpcapngtool_path", ("hcxpcapngtool",))
    if not hashcat:
        issue("hashcat_missing", "critical", "Hashcat is missing", "The recovery engine cannot start.", "repair_paths", "Locate bundled tools")
    if not converter:
        issue("converter_missing", "warning", "Capture converter is missing", "PCAP and PCAPNG imports cannot be converted; direct 22000 imports still work.", "repair_paths", "Locate bundled tools")

    with db() as connection:
        sources = [dict(row) for row in connection.execute("SELECT id,filename,stored_path FROM wordlists")]
        captures = [dict(row) for row in connection.execute(
            "SELECT id,filename,stored_path,hash_path,status,diagnostic_path FROM captures"
        )]
        failed_jobs = [dict(row) for row in connection.execute(
            "SELECT id,error,log_path,worker_name FROM jobs WHERE status IN ('failed','blocked') ORDER BY id DESC LIMIT 100"
        )]
        worker_rows = [dict(row) for row in connection.execute("SELECT name,status,last_seen FROM lan_workers")]
    missing_sources = [item for item in sources if not Path(item["stored_path"]).is_file()]
    if missing_sources:
        issue("missing_sources", "critical", f"{len(missing_sources)} candidate source file(s) are missing",
              ", ".join(item["filename"] for item in missing_sources[:6]), "relink_sources", "Relink local files")
    missing_captures = [item for item in captures if not Path(item["stored_path"]).is_file() or (item["status"] == "ready" and not Path(item["hash_path"] or "").is_file())]
    if missing_captures:
        issue("missing_captures", "critical", f"{len(missing_captures)} capture file(s) are missing",
              "Restore these files from backup or import them again: " + ", ".join(item["filename"] for item in missing_captures[:6]))
    corrupt = []
    for item in captures:
        diagnostic = Path(item.get("diagnostic_path") or "")
        if diagnostic.is_file():
            try:
                if "packet read error" in diagnostic.read_text(encoding="utf-8", errors="replace").lower():
                    corrupt.append(item)
            except OSError:
                pass
    if corrupt:
        issue("capture_corruption", "warning", f"{len(corrupt)} capture(s) contain packet read errors",
              "The original files are preserved. Recheck them, but recapture if no usable WPA hash is produced: " + ", ".join(item["filename"] for item in corrupt[:6]))

    logs = recent_process_logs()
    local_text = "\n".join(text for path, text in logs if not path.name.endswith("-lan.log"))
    active_worker_names: set[str] = set()
    for worker in worker_rows:
        try:
            last_seen = datetime.fromisoformat(str(worker.get("last_seen") or "")).timestamp()
        except (TypeError, ValueError):
            continue
        if worker.get("status") != "offline" and time.time() - last_seen < 15:
            active_worker_names.add(worker["name"])
    remote_text = "\n".join(text for path, text in logs if path.name.endswith("-lan.log")) if active_worker_names else ""
    job_errors = "\n".join(str(job.get("error") or "") for job in failed_jobs if not job.get("worker_name"))
    cuda_pattern = r"failed to initialize nvidia rtc|cuda sdk toolkit not installed"
    vram_pattern = r"not enough allocatable device memory|insufficient memory|out of memory"
    opencl_pattern = r"no devices found|opencl.*(?:missing|failed|not found)|clgetplatformids"
    if re.search(cuda_pattern, local_text, re.IGNORECASE):
        issue("cuda_rtc", "warning", "CUDA RTC initialization failed", "Hashcat fell back to OpenCL. The fallback is reliable but may be slower.", "enable_opencl_fallback", "Use stable OpenCL fallback")
    if re.search(cuda_pattern, remote_text, re.IGNORECASE):
        issue("remote_cuda_rtc", "warning", "A LAN worker reported a CUDA RTC problem", "Update the portable worker, install a matching NVIDIA CUDA runtime, or enable force_opencl in lan-worker.json.")
    if re.search(vram_pattern, local_text + "\n" + job_errors, re.IGNORECASE):
        issue("vram_pressure", "critical", "A job ran out of allocatable VRAM", "Close GPU-heavy applications and use one Hashcat process at W1 before retrying.", "optimize_vram", "Apply safe VRAM profile")
    if re.search(vram_pattern, remote_text, re.IGNORECASE):
        issue("remote_vram", "critical", "A LAN worker ran out of allocatable VRAM", "On that PC close GPU applications, set W1, keep one worker process, then retry.")
    if re.search(opencl_pattern, local_text + "\n" + job_errors, re.IGNORECASE):
        issue("opencl_runtime", "warning", "OpenCL runtime problem detected", "Reinstall the GPU driver with OpenCL support. CPU mode also needs an OpenCL CPU runtime.")

    backend = hashcat_backend_info() if hashcat else {"cpu_available": False, "cpu_name": "Unavailable"}
    if load_config().get("cpu_profile") != "off" and not backend.get("cpu_available"):
        issue("cpu_backend", "warning", "CPU profile is enabled but no OpenCL CPU backend exists", backend.get("cpu_name") or "Disable CPU mode or install a compatible OpenCL runtime.")
    if not issues:
        issues.append({"id": "healthy", "severity": "ok", "title": "No known problems found", "detail": "Tools, registered files and recent process logs look healthy.", "action": "", "fix_label": "", "fixable": False})
    return {"checked_at": now(), "issues": issues, "fixable": sum(1 for item in issues if item["fixable"])}


def relink_missing_sources() -> int:
    roots = (ROOT / "wordlists", ROOT / "rules")
    available: dict[str, list[Path]] = {}
    for root in roots:
        if root.is_dir():
            for path in root.rglob("*"):
                if path.is_file():
                    available.setdefault(path.name.lower(), []).append(path.resolve())
    repaired = 0
    with db() as connection:
        for row in connection.execute("SELECT id,filename,stored_path FROM wordlists").fetchall():
            if Path(row["stored_path"]).is_file():
                continue
            matches = available.get(str(row["filename"]).lower()) or []
            if len(matches) == 1:
                path = matches[0]
                connection.execute(
                    "UPDATE wordlists SET stored_path=?,bytes=?,sha256=?,analysis_json='{}' WHERE id=?",
                    (str(path), path.stat().st_size, linked_source_fingerprint(path), row["id"]),
                )
                repaired += 1
    return repaired


def apply_doctor_fix(action: str) -> dict:
    result: dict = {"action": action, "changes": []}
    if action in {"repair_paths", "all"}:
        hashcat = executable("hashcat_path", ("hashcat",))
        converter = executable("hcxpcapngtool_path", ("hcxpcapngtool",))
        with CONFIG_LOCK:
            config = load_config()
            if hashcat:
                config["hashcat_path"] = hashcat
            if converter:
                config["hcxpcapngtool_path"] = converter
            atomic_json(CONFIG_PATH, config)
        result["changes"].append("Bundled tool paths refreshed")
    if action in {"relink_sources", "all"}:
        repaired = relink_missing_sources()
        result["changes"].append(f"Relinked {repaired} missing source file(s)")
    if action in {"enable_opencl_fallback", "all"}:
        if action != "all" or any(item["id"] == "cuda_rtc" for item in error_doctor_report()["issues"]):
            with CONFIG_LOCK:
                config = load_config(); config["force_opencl"] = True; atomic_json(CONFIG_PATH, config)
            result["changes"].append("Enabled OpenCL fallback for new local jobs")
    if action in {"optimize_vram", "all"}:
        if action != "all" or any(item["id"] == "vram_pressure" for item in error_doctor_report()["issues"]):
            with CONFIG_LOCK:
                config = load_config(); config["max_workers"] = 1; config["workload_profile"] = 1; atomic_json(CONFIG_PATH, config)
            with db() as connection:
                connection.execute("UPDATE jobs SET workload=1 WHERE status='queued'")
                retried = connection.execute(
                    "UPDATE jobs SET status='queued',error='',finished_at=NULL,progress=0,speed='',speed_hps=0 WHERE status IN ('failed','blocked') AND lower(error) LIKE '%memory%'"
                ).rowcount
            result["changes"].append(f"Applied W1 / one-worker VRAM profile and retried {retried} memory failure(s)")
    if not result["changes"]:
        raise ValueError("This diagnosis needs a manual fix; open its details")
    add_event("success", "Error Doctor: " + "; ".join(result["changes"]))
    result["report"] = error_doctor_report()
    return result


class Runner:
    def __init__(self) -> None:
        self.processes: dict[int, subprocess.Popen] = {}
        self.lock = threading.Lock()
        self.manual_paused: set[int] = set()
        self.throttle_stops: dict[int, threading.Event] = {}
        self.live_workload = max(1, min(int(load_config().get("workload_profile", 3)), 4))
        self.stop_event = threading.Event()
        self.shutting_down = threading.Event()
        self.current_telemetry: dict = {}
        self.last_telemetry_write = 0.0
        self.last_lan_recovery = 0.0
        self.queue_was_active = False
        self.restart_requests: dict[int, int] = {}
        self.thread = threading.Thread(target=self.loop, name="hashcat-queue", daemon=True)
        self.telemetry_thread = threading.Thread(target=self.telemetry_loop, name="gpu-telemetry", daemon=True)

    def start(self) -> None:
        self.thread.start()
        self.telemetry_thread.start()

    def nvidia_sample(self) -> dict:
        executable_path = shutil.which("nvidia-smi") or r"C:\Windows\System32\nvidia-smi.exe"
        if not Path(executable_path).is_file():
            return {}
        fields = ["temperature.gpu", "utilization.gpu", "memory.used", "memory.total",
                  "power.draw", "power.limit", "clocks.current.graphics", "fan.speed"]
        try:
            result = subprocess.run(
                [executable_path, f"--query-gpu={','.join(fields)}", "--format=csv,noheader,nounits", "--id=0"],
                capture_output=True, text=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            values = next(csv.reader([result.stdout.strip()]))
            numbers = []
            for value in values:
                try:
                    numbers.append(float(value.strip()))
                except ValueError:
                    numbers.append(None)
            if len(numbers) != len(fields):
                return {}
            return dict(zip(("temperature", "utilization", "memory_used", "memory_total",
                             "power_draw", "power_limit", "clock_graphics", "fan_speed"), numbers))
        except (OSError, subprocess.SubprocessError, StopIteration):
            return {}

    def telemetry_loop(self) -> None:
        while not self.stop_event.wait(2):
            sample = self.nvidia_sample()
            with self.lock:
                active_ids = list(self.processes)
            job_id = active_ids[0] if active_ids else None
            speed_hps = 0.0
            if job_id:
                with db() as connection:
                    row = connection.execute("SELECT speed_hps FROM jobs WHERE id=?", (job_id,)).fetchone()
                speed_hps = float(row[0] or 0) if row else 0.0
            sample.update({"job_id": job_id, "speed_hps": speed_hps, "sampled_at": now()})
            self.current_telemetry = sample
            temperature = sample.get("temperature")
            limit = max(70, min(int(load_config().get("temperature_abort", 90)), 100))
            if temperature is not None and float(temperature) >= limit - 2:
                notify_user("overheat", "GPU temperature warning", f"GPU reached {float(temperature):.0f}°C; abort limit is {limit}°C.", "local-gpu-temperature", 600)
            if job_id and time.time() - self.last_telemetry_write >= 5:
                self.persist_telemetry(job_id, sample)
                self.last_telemetry_write = time.time()

    def persist_telemetry(self, job_id: int, sample: dict) -> None:
        keys = ("temperature", "utilization", "memory_used", "memory_total", "power_draw",
                "power_limit", "clock_graphics", "fan_speed")
        values = [sample.get(key) for key in keys]
        with db() as connection:
            connection.execute(
                """INSERT INTO telemetry(job_id,temperature,utilization,memory_used,memory_total,
                   power_draw,power_limit,clock_graphics,fan_speed,speed_hps,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (job_id, *values, sample.get("speed_hps", 0), sample.get("sampled_at", now())),
            )
        path = ROOT / "logs" / f"job-{job_id}-telemetry.csv"
        new_file = not path.exists()
        with TELEMETRY_LOCK:
            with path.open("a", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                if new_file:
                    writer.writerow(["Time", "Temperature C", "GPU %", "VRAM MiB", "VRAM total MiB",
                                     "Power W", "Power limit W", "Graphics MHz", "Fan %", "Speed H/s"])
                writer.writerow([sample.get("sampled_at", now()), *values, sample.get("speed_hps", 0)])
                handle.flush()
                os.fsync(handle.fileno())

    def loop(self) -> None:
        while not self.stop_event.wait(1):
            try:
                config = load_config()
                if time.time() - self.last_lan_recovery > 15:
                    self.last_lan_recovery = time.time()
                    cutoff = time.time() - max(60, int(config.get("lan_job_timeout", 180)))
                    with db() as connection:
                        for worker in connection.execute("SELECT name,last_seen,current_job_id,telemetry_json FROM lan_workers WHERE status IN ('running','idle')").fetchall():
                            heartbeat = worker["last_seen"]
                            if worker["current_job_id"]:
                                try:
                                    heartbeat = (json.loads(worker["telemetry_json"] or "{}") or {}).get("sampled_at") or heartbeat
                                except json.JSONDecodeError:
                                    pass
                            try:
                                stale = datetime.fromisoformat(heartbeat).timestamp() < cutoff
                            except (ValueError, TypeError):
                                stale = True
                            if stale:
                                connection.execute("UPDATE lan_workers SET status='offline',current_job_id=NULL WHERE name=?", (worker["name"],))
                                if worker["current_job_id"]:
                                    stop_job_clock(connection, int(worker["current_job_id"]))
                                    connection.execute("UPDATE jobs SET status='queued',worker_name='',remote_command='',error='LAN worker heartbeat timed out; safely requeued' WHERE id=? AND status IN ('lan_preparing','lan_running','lan_paused')", (worker["current_job_id"],))
                                notify_user("worker", "Worker disconnected", f"{worker['name']} is offline; its active job was safely returned to the queue.", f"worker:{worker['name']}", 300)
                with db() as connection:
                    pending_count = connection.execute(
                        "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running','paused','lan_preparing','lan_running','lan_paused')"
                    ).fetchone()[0]
                if pending_count:
                    self.queue_was_active = True
                elif self.queue_was_active:
                    self.queue_was_active = False
                    notify_user("queue", "Queue complete", "Handshake Lab finished every waiting job.", "queue-complete", 30)
                if config.get("queue_paused", False) or config.get("local_queue_paused", False):
                    continue
                limit = max(1, min(int(config.get("max_workers", 1)), 2))
                with self.lock:
                    active = len(self.processes)
                if active >= limit:
                    continue
                with db() as connection:
                    job = connection.execute(
                        """SELECT j.*, c.hash_path, c.filename AS capture_name,
                                  s.name AS strategy_name, s.mode, s.config_json
                           FROM jobs j JOIN captures c ON c.id=j.capture_id
                           JOIN strategies s ON s.id=j.strategy_id
                           WHERE j.status='queued' ORDER BY j.position,j.id LIMIT 1"""
                    ).fetchone()
                if job:
                    threading.Thread(target=self.run_job, args=(dict(job),), daemon=True).start()
            except Exception as exc:
                add_event("error", f"Queue error: {exc}")

    def resolve_file(self, table: str, item_id: int | None) -> str | None:
        if not item_id or table not in {"wordlists"}:
            return None
        with db() as connection:
            row = connection.execute(f"SELECT stored_path FROM {table} WHERE id=?", (item_id,)).fetchone()
        return row[0] if row else None

    def build_command(self, job: dict, outfile: Path) -> list[str]:
        hashcat = executable("hashcat_path", ("hashcat",))
        if not hashcat:
            raise RuntimeError("Hashcat is not installed. Open Settings and install or select hashcat.exe.")
        restore_path = ROOT / "sessions" / f"{job['session_name']}.restore"
        if restore_path.exists() and restore_path.stat().st_size:
            self.patch_restore_workload(restore_path, 4)
            return [hashcat, "--session", job["session_name"], "--restore", "--restore-file-path", str(restore_path)]
        cfg = json.loads(job["config_json"] or "{}")
        temp_abort = max(70, min(int(load_config().get("temperature_abort", 90)), 100))
        command = [hashcat, "-m", "22000", str(job["hash_path"]), "--potfile-path", str(POTFILE),
                   "--session", job["session_name"], "--restore-file-path", str(restore_path),
                   "--outfile", str(outfile), "--outfile-format", "1,2", "--separator", "|",
                   "--status", "--status-json", "--status-timer", "2",
                   "--workload-profile", "4", "--hwmon-temp-abort", str(temp_abort)]
        if load_config().get("force_opencl", False):
            command.append("--backend-ignore-cuda")
        cpu_profile = str(job.get("cpu_profile") or load_config().get("cpu_profile", "off"))
        if cpu_profile != "off" and hashcat_backend_info().get("cpu_available"):
            command += ["--opencl-device-types", "1,2"]
        mode = job["mode"]
        if mode == "known":
            return [hashcat, "-m", "22000", str(job["hash_path"]), "--potfile-path", str(POTFILE),
                    "--show", "--outfile", str(outfile), "--outfile-format", "1,2", "--separator", "|"]
        if mode == "common":
            common_wordlist = common_candidate_wordlist(Path(job["hash_path"]), int(job["id"]))
            command += ["-a", "0", str(common_wordlist)]
            return command
        if mode == "pattern":
            pattern_wordlist = pattern_candidate_wordlist(Path(job["hash_path"]), int(job["id"]))
            if pattern_wordlist.stat().st_size == 0:
                raise RuntimeError("Pattern Builder needs at least one locally recovered password")
            command += ["-a", "0", str(pattern_wordlist)]
            return command
        wordlist = self.resolve_file("wordlists", cfg.get("wordlist_id"))
        if mode in {"dictionary", "rules", "hybrid"} and not wordlist:
            raise RuntimeError("This strategy needs a wordlist")
        if mode == "dictionary":
            command += ["-a", "0", wordlist]
        elif mode == "rules":
            rule = self.resolve_file("wordlists", cfg.get("rule_id"))
            if not rule:
                raise RuntimeError("This strategy needs a rule file")
            command += ["-a", "0", wordlist, "-r", rule]
        elif mode == "hybrid":
            command += ["-a", "6", wordlist, str(cfg.get("mask") or "?d?d?d?d")]
        elif mode == "mask":
            command += ["-a", "3", str(cfg.get("mask") or "?d?d?d?d?d?d?d?d")]
            if cfg.get("increment"):
                command.append("--increment")
        else:
            raise RuntimeError(f"Unsupported strategy: {mode}")
        if cfg.get("optimized"):
            command.append("--optimized-kernel-enable")
        return command

    def run_job(self, job: dict) -> None:
        job_id = int(job["id"])
        throttle_stop: threading.Event | None = None
        with self.lock:
            if job_id in self.processes:
                return
        log_path = ROOT / "logs" / f"job-{job_id}.log"
        outfile = DATA / f"job-{job_id}-found.txt"
        try:
            runtime_hash, capture_lookup, network_count = prepare_job_hashes(job)
            if not runtime_hash:
                with db() as connection:
                    connection.execute(
                        "UPDATE jobs SET status='complete',progress=100,error='Skipped: recovered or method already tested',finished_at=? WHERE id=? AND status='queued'",
                        (now(), job_id),
                    )
                add_event("success", f"{job['capture_name']} / {job['strategy_name']}: skipped, already recovered or tested")
                return
            job["hash_path"] = str(runtime_hash)
            with self.lock:
                if not self.processes:
                    self.live_workload = max(1, min(int(job.get("workload") or 3), 4))
            command = self.build_command(job, outfile)
            if load_config().get("queue_paused", False):
                return
            with db() as connection:
                started = now()
                changed = connection.execute(
                    "UPDATE jobs SET status='running',started_at=COALESCE(started_at,?),active_started_at=?,log_path=?,command_json=?,error='' WHERE id=? AND status='queued'",
                    (started, started, str(log_path), json.dumps(command), job_id),
                ).rowcount
            if not changed:
                return
            outfile.unlink(missing_ok=True)
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            process = subprocess.Popen(command, cwd=str(Path(command[0]).parent), stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                       encoding="utf-8", errors="replace", bufsize=1, creationflags=creation_flags)
            apply_cpu_affinity(process, str(job.get("cpu_profile") or "off"))
            with self.lock:
                self.processes[job_id] = process
                throttle_stop = threading.Event()
                self.throttle_stops[job_id] = throttle_stop
            throttle = threading.Thread(
                target=self.throttle_process, args=(job_id, process, throttle_stop),
                name=f"job-{job_id}-live-profile", daemon=True,
            )
            throttle.start()
            with log_path.open("a", encoding="utf-8", newline="\n") as log:
                for line in iter(process.stdout.readline, ""):
                    log.write(line)
                    log.flush()
                    if '{ "session"' in line:
                        os.fsync(log.fileno())
                    self.consume_status(job_id, line)
            code = process.wait()
            imported, recovered_networks = import_outfile(
                outfile, job["capture_id"], job["strategy_name"], Path(job["hash_path"]), capture_lookup, job_id
            )
            with self.lock:
                requested_workload = self.restart_requests.pop(job_id, None)
            if requested_workload is not None:
                restore_path = ROOT / "sessions" / f"{job['session_name']}.restore"
                if code in (0, 1) and not restore_path.is_file():
                    attempts_recorded = 0
                    with db() as connection:
                        stop_job_clock(connection, job_id)
                        if job.get("mode") != "known":
                            attempts_recorded = insert_network_attempts(
                                connection, job, parse_22000(Path(job["hash_path"])), recovered_networks
                            )
                        connection.execute(
                            "UPDATE jobs SET status='complete',progress=100,error='',finished_at=? WHERE id=?",
                            (now(), job_id),
                        )
                    skipped = skip_fully_recovered_jobs() if recovered_networks or attempts_recorded else 0
                    add_event("success", f"Job {job_id} completed before the W{requested_workload} checkpoint; {attempts_recorded} network attempt(s) remembered, {skipped} skipped")
                elif self.patch_restore_workload(restore_path, requested_workload):
                    with db() as connection:
                        stop_job_clock(connection, job_id)
                        connection.execute(
                            "UPDATE jobs SET status='queued',workload=?,error=?,finished_at=NULL WHERE id=?",
                            (requested_workload, f"Checkpoint restored with W{requested_workload}", job_id),
                        )
                    add_event("info", f"Job {job_id}: workload changed to W{requested_workload}; resuming from checkpoint")
                else:
                    with db() as connection:
                        stop_job_clock(connection, job_id)
                        connection.execute(
                            "UPDATE jobs SET status='blocked',workload=?,error=?,finished_at=? WHERE id=?",
                            (requested_workload, "Workload change checkpoint was not created; retry the job", now(), job_id),
                        )
                    add_event("error", f"Job {job_id}: workload checkpoint could not be updated")
                skipped = skip_fully_recovered_jobs() if recovered_networks else 0
                return
            attempts_recorded = 0
            with db() as connection:
                current = connection.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
                if current not in {"cancelled"}:
                    stop_job_clock(connection, job_id)
                    if self.shutting_down.is_set():
                        status, error = "queued", "Checkpointed during background service shutdown"
                    else:
                        status = "complete" if code in (0, 1) else "failed"
                        error = "" if status == "complete" else hashcat_failure_message(log_path, code)
                        if status == "complete" and job.get("mode") != "known":
                            attempts_recorded = insert_network_attempts(
                                connection, job, parse_22000(Path(job["hash_path"])), recovered_networks
                            )
                    connection.execute("UPDATE jobs SET status=?,progress=CASE WHEN ?='complete' THEN 100 ELSE progress END,error=?,finished_at=? WHERE id=?",
                                       (status, status, error, now(), job_id))
            skipped = skip_fully_recovered_jobs() if recovered_networks or attempts_recorded else 0
            add_event("success", f"{job['capture_name']} / {job['strategy_name']}: {imported} recovered, {attempts_recorded} network attempt(s) remembered, {skipped} skipped")
        except Exception as exc:
            with db() as connection:
                stop_job_clock(connection, job_id)
                connection.execute("UPDATE jobs SET status='blocked',error=?,finished_at=? WHERE id=?", (str(exc), now(), job_id))
            add_event("error", f"Job {job_id}: {exc}")
        finally:
            with self.lock:
                throttle_stop = self.throttle_stops.pop(job_id, None)
                if throttle_stop:
                    throttle_stop.set()
                self.processes.pop(job_id, None)
                self.manual_paused.discard(job_id)
                self.restart_requests.pop(job_id, None)

    def throttle_process(self, job_id: int, process: subprocess.Popen, stop: threading.Event) -> None:
        """Apply live GPU duty-cycle profiles without restarting Hashcat."""
        duty_cycles = {1: 0.35, 2: 0.60, 3: 0.85, 4: 1.0}
        period = 0.40
        throttle_suspended = False
        while process.poll() is None and not stop.is_set():
            with self.lock:
                manually_paused = job_id in self.manual_paused
                workload = self.live_workload
            if manually_paused:
                throttle_suspended = False
                stop.wait(0.08)
                continue
            duty = duty_cycles.get(workload, 1.0)
            if throttle_suspended:
                set_process_suspended(process, False)
                throttle_suspended = False
            if duty >= 1.0:
                stop.wait(0.08)
                continue
            if stop.wait(period * duty):
                break
            with self.lock:
                manually_paused = job_id in self.manual_paused
            if not manually_paused and process.poll() is None:
                throttle_suspended = set_process_suspended(process, True)
            if stop.wait(period * (1.0 - duty)):
                break
        with self.lock:
            manually_paused = job_id in self.manual_paused
        if throttle_suspended and not manually_paused and process.poll() is None:
            set_process_suspended(process, False)

    def set_live_workload(self, workload: int) -> list[int]:
        with self.lock:
            self.live_workload = max(1, min(int(workload), 4))
            return sorted(self.processes)

    def consume_status(self, job_id: int, line: str) -> None:
        line = line.strip()
        json_start = line.find("{")
        if json_start < 0:
            return
        try:
            payload = json.loads(line[json_start:])
            if "progress" not in payload:
                return
            progress_pair = payload.get("progress", [0, 0])
            progress = (progress_pair[0] / progress_pair[1] * 100) if progress_pair[1] else 0
            devices = payload.get("devices", [])
            if devices:
                speed_total = sum(float(device.get("speed") or 0) for device in devices if isinstance(device, dict))
            else:
                speeds = payload.get("speed", [])
                # Older Hashcat JSON reports each device as [hashes_per_second, exec_ms].
                speed_total = sum(
                    float(device[0]) if isinstance(device, (list, tuple)) and device else first_number(device)
                    for device in speeds
                ) if isinstance(speeds, (list, tuple)) else first_number(speeds)
            speed = human_rate(speed_total)
            estimated_stop = payload.get("estimated_stop", "")
            if isinstance(estimated_stop, (int, float)) and estimated_stop > 0:
                eta = datetime.fromtimestamp(estimated_stop).astimezone().isoformat(timespec="seconds")
            else:
                eta = str(estimated_stop or "")
            recovered = first_number(payload.get("recovered_hashes", payload.get("recovered", 0)))
            with db() as connection:
                connection.execute("""UPDATE jobs SET progress=?,speed=?,speed_hps=?,eta=?,recovered=?,
                                   candidates_done=?,candidates_total=? WHERE id=?""",
                                   (round(progress, 2), speed, speed_total, eta, int(recovered),
                                    int(progress_pair[0] or 0), int(progress_pair[1] or 0), job_id))
        except (ValueError, TypeError, KeyError, sqlite3.Error):
            pass

    def control(self, job_id: int, action: str) -> bool:
        with self.lock:
            process = self.processes.get(job_id)
        if not process or action not in {"pause", "resume", "cancel"}:
            return False
        if action == "pause":
            with self.lock:
                self.manual_paused.add(job_id)
            changed = set_process_suspended(process, True)
        elif action == "resume":
            with self.lock:
                self.manual_paused.discard(job_id)
            changed = set_process_suspended(process, False)
        else:
            try:
                with self.lock:
                    was_paused = job_id in self.manual_paused
                    self.manual_paused.discard(job_id)
                if was_paused:
                    set_process_suspended(process, False)
                process.terminate()
                changed = True
            except OSError:
                changed = False
        if not changed:
            if action == "pause":
                with self.lock:
                    self.manual_paused.discard(job_id)
            return False
        status = {"pause": "paused", "resume": "running", "cancel": "cancelled"}[action]
        with db() as connection:
            if action == "resume":
                start_job_clock(connection, job_id)
            else:
                stop_job_clock(connection, job_id)
            connection.execute("UPDATE jobs SET status=?,finished_at=CASE WHEN ?='cancelled' THEN ? ELSE finished_at END WHERE id=?",
                               (status, status, now(), job_id))
        return True

    def patch_restore_workload(self, restore_path: Path, workload: int) -> bool:
        if not restore_path.is_file():
            return False
        try:
            payload = restore_path.read_bytes()
            updated, replacements = re.subn(
                rb"(--workload-profile\n)[1-4](\n)",
                rb"\g<1>" + str(workload).encode("ascii") + rb"\g<2>",
                payload,
                count=1,
            )
            if replacements != 1 or len(updated) != len(payload):
                return False
            temporary = restore_path.with_suffix(".restore.tmp")
            with temporary.open("wb") as handle:
                handle.write(updated)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, restore_path)
            return True
        except OSError:
            return False

    def request_workload(self, workload: int) -> list[int]:
        with self.lock:
            active = list(self.processes.items())
        with db() as connection:
            eligible = {row[0] for row in connection.execute(
                """SELECT j.id FROM jobs j JOIN strategies s ON s.id=j.strategy_id
                   WHERE j.status IN ('running','paused') AND s.mode!='known'"""
            )}
        active = [(job_id, process) for job_id, process in active if job_id in eligible]
        with self.lock:
            for job_id, _ in active:
                self.restart_requests[job_id] = workload
        requested: list[int] = []
        for job_id, process in active:
            try:
                if process.stdin and process.poll() is None:
                    process.stdin.write("c")
                    process.stdin.flush()
                    requested.append(job_id)
            except (OSError, ValueError):
                with self.lock:
                    self.restart_requests.pop(job_id, None)
        return requested

    def pause_all(self) -> list[int]:
        paused: set[int] = set()
        for _ in range(4):
            with self.lock:
                active_ids = list(self.processes)
            for job_id in active_ids:
                with db() as connection:
                    row = connection.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
                if row and row[0] == "running" and self.control(job_id, "pause"):
                    paused.add(job_id)
            if active_ids:
                break
            time.sleep(0.15)
        return sorted(paused)

    def resume_all(self) -> list[int]:
        with self.lock:
            active_ids = list(self.processes)
        resumed: list[int] = []
        for job_id in active_ids:
            with db() as connection:
                row = connection.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row and row[0] == "paused" and self.control(job_id, "resume"):
                resumed.append(job_id)
        return resumed

    def graceful_shutdown(self) -> None:
        self.shutting_down.set()
        self.stop_event.set()
        with self.lock:
            processes = list(self.processes.items())
        for job_id, process in processes:
            try:
                with db() as connection:
                    row = connection.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
                if row and row[0] == "paused":
                    set_process_suspended(process, False)
                if process.stdin:
                    process.stdin.write("c")
                    process.stdin.flush()
                with db() as connection:
                    connection.execute("UPDATE jobs SET error='Checkpoint requested; waiting to stop' WHERE id=?", (job_id,))
            except (OSError, ValueError):
                pass
        deadline = time.time() + 18
        while time.time() < deadline and any(process.poll() is None for _, process in processes):
            time.sleep(0.5)
        for job_id, process in processes:
            if process.poll() is None:
                try:
                    if process.stdin:
                        process.stdin.write("q")
                        process.stdin.flush()
                except (OSError, ValueError):
                    pass
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.terminate()
            with db() as connection:
                stop_job_clock(connection, job_id)
                connection.execute("UPDATE jobs SET status='queued',error='Saved for resume after shutdown' WHERE id=? AND status IN ('running','paused')", (job_id,))


def numeric_values(value) -> list[float]:
    if isinstance(value, (int, float)):
        return [float(value)]
    if isinstance(value, dict):
        output = []
        for nested in value.values():
            output.extend(numeric_values(nested))
        return output
    if isinstance(value, (list, tuple)):
        output = []
        for nested in value:
            output.extend(numeric_values(nested))
        return output
    return []


def first_number(value) -> float:
    values = numeric_values(value)
    return values[0] if values else 0


def human_rate(value: float) -> str:
    units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s"]
    amount = float(value)
    for unit in units:
        if abs(amount) < 1000:
            return f"{amount:.1f} {unit}"
        amount /= 1000
    return f"{amount:.1f} PH/s"


def create_dynamic_strategy(connection: sqlite3.Connection, name: str, mode: str, config: dict, position: int) -> int:
    cursor = connection.execute(
        "INSERT INTO strategies(name,mode,config_json,position,enabled,builtin,hidden) VALUES(?,?,?,?,1,0,1)",
        (name[:100], mode, json.dumps(config), position),
    )
    return int(cursor.lastrowid)


def expand_preset_stages(connection: sqlite3.Connection, preset_config: dict) -> list[dict]:
    wordlists = [dict(row) for row in connection.execute(
        "SELECT * FROM wordlists WHERE kind='wordlist' ORDER BY position,id"
    )]
    rules = [dict(row) for row in connection.execute(
        "SELECT * FROM wordlists WHERE kind='rule' ORDER BY position,id"
    )]
    stages = []
    position = 0
    for definition in preset_config.get("stages", []):
        kind = definition.get("kind")
        expanded = []
        if kind == "known":
            expanded = [("Known results", "known", {})]
        elif kind == "common":
            expanded = [("Common passwords", "common", {})]
        elif kind == "pattern":
            expanded = [("Pattern Builder", "pattern", {})]
        elif kind == "mask":
            mask = str(definition.get("mask") or "?d?d?d?d?d?d?d?d")[:256]
            expanded = [(f"Mask {mask}", "mask", {
                "mask": mask, "increment": bool(definition.get("increment")),
                "optimized": bool(definition.get("optimized")),
            })]
        elif kind in {"all_wordlists", "first_wordlists"}:
            mode = definition.get("mode", "dictionary")
            selected_wordlists = wordlists
            if kind == "first_wordlists":
                selected_wordlists = wordlists[:max(1, min(int(definition.get("limit", 1)), 20))]
            for source in selected_wordlists:
                cfg = {"wordlist_id": source["id"], "optimized": bool(definition.get("optimized"))}
                if mode == "hybrid":
                    cfg["mask"] = str(definition.get("mask") or "?d?d?d?d")[:256]
                expanded.append((f"{source['filename']} · {mode}", mode, cfg))
        elif kind == "all_rules":
            for source in wordlists:
                for rule in rules:
                    expanded.append((f"{source['filename']} + {rule['filename']}", "rules", {
                        "wordlist_id": source["id"], "rule_id": rule["id"],
                        "optimized": bool(definition.get("optimized")),
                    }))
        elif kind == "strategy":
            mode = str(definition.get("mode", "dictionary"))
            if mode in {"known", "common", "pattern", "dictionary", "rules", "hybrid", "mask"}:
                expanded = [(str(definition.get("name") or mode.title()), mode, definition.get("config") or {})]
        for name, mode, config in expanded:
            strategy_id = create_dynamic_strategy(connection, name, mode, config, position)
            stages.append({"id": strategy_id, "name": name, "mode": mode, "config": config})
            position += 1
    return stages


def enqueue_matrix(connection: sqlite3.Connection, captures: list[dict], stages: list[dict], order: str,
                   workload: int, preset_name: str = "", prepend: bool = False) -> int:
    recovered_keys = {(row["essid"], normalize_bssid(row["bssid"])) for row in connection.execute(
        "SELECT DISTINCT essid,bssid FROM results"
    )}
    unique_captures: list[dict] = []
    seen_signatures: set[tuple[tuple[str, str], ...]] = set()
    for capture in captures:
        path = Path(capture.get("hash_path") or "")
        capture_networks = cached_networks(path) if path.is_file() else []
        network_keys = {network_identity(item) for item in capture_networks}
        if network_keys and network_keys.issubset(recovered_keys):
            continue
        signature = tuple(sorted(network_keys))
        if signature and signature in seen_signatures:
            continue
        if signature:
            seen_signatures.add(signature)
        unique_captures.append(capture)
    captures = unique_captures
    if order == "strategy_first":
        groups = [([capture], stage) for stage in stages for capture in captures]
    else:
        groups = [([capture], stage) for capture in captures for stage in stages]
    next_prepend_position = 0
    if prepend and groups:
        connection.execute("UPDATE jobs SET position=position+? WHERE status='queued'", (len(groups),))
    created = 0
    for capture_group, stage in groups:
        if not capture_group:
            continue
        capture = capture_group[0]
        capture_ids = [item["id"] for item in capture_group]
        descriptor = strategy_attempt_descriptor(connection, stage)
        attempt_key, attempt_label = (descriptor[0], descriptor[1]) if descriptor else ("", "")
        if descriptor:
            capture_networks = cached_networks(Path(capture.get("hash_path") or ""))
            network_keys = {network_identity(item) for item in capture_networks}
            attempted = {(row["essid"], normalize_bssid(row["bssid"])) for row in connection.execute(
                "SELECT essid,bssid FROM network_attempts WHERE method_key=?", (attempt_key,)
            )}
            if network_keys and network_keys.issubset(recovered_keys | attempted):
                continue
            duplicate_pending = connection.execute(
                """SELECT 1 FROM jobs WHERE capture_id=? AND attempt_key=?
                   AND status IN ('queued','running','paused','lan_preparing','lan_running','lan_paused') LIMIT 1""",
                (capture["id"], attempt_key),
            ).fetchone()
            if duplicate_pending:
                continue
        session = f"newfpv-{capture['id']}-{stage['id']}-{uuid.uuid4().hex[:8]}"
        if prepend:
            next_prepend_position += 1
            position = next_prepend_position
        else:
            position = connection.execute("SELECT COALESCE(MAX(position),0)+1 FROM jobs").fetchone()[0]
        connection.execute(
            """INSERT INTO jobs(capture_id,strategy_id,status,session_name,created_at,preset_name,workload,cpu_profile,position,
                                 capture_ids_json,attempt_key,attempt_label)
               VALUES(?,?,'queued',?,?,?,?,?,?,?,?,?)""",
            (capture["id"], stage["id"], session, now(), preset_name[:100], workload,
             str(load_config().get("cpu_profile", "off")), position, json.dumps(capture_ids), attempt_key, attempt_label),
        )
        created += 1
    return created


app = Flask(__name__)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


def session_secret() -> bytes:
    path = DATA / "session-secret.bin"
    try:
        value = path.read_bytes()
        if len(value) >= 32:
            return value
    except OSError:
        pass
    value = secrets.token_bytes(48)
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(value)
    os.replace(temporary, path)
    return value


app.secret_key = session_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(days=7))


def browser_config() -> dict:
    config = load_config()
    config["remote_password_configured"] = bool(config.get("remote_password_hash"))
    config.pop("remote_password_hash", None)
    return config


def private_client(address: str | None) -> bool:
    try:
        client = ipaddress.ip_address(str(address or "").split("%")[0])
        return client.is_loopback or client.is_private or client.is_link_local
    except ValueError:
        return False


def remote_password_valid(username: str, password: str) -> bool:
    config = load_config()
    expected_user = str(config.get("remote_username") or "newfpv")
    password_hash = str(config.get("remote_password_hash") or "")
    return bool(password_hash and secrets.compare_digest(username, expected_user) and check_password_hash(password_hash, password))


def remote_credentials_valid() -> bool:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return False
    try:
        username, password = base64.b64decode(header[6:], validate=True).decode("utf-8").split(":", 1)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return False
    return remote_password_valid(username, password)


def effective_client_address() -> str:
    forwarded = ""
    if private_client(request.remote_addr):
        forwarded = str(request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
    return forwarded or str(request.remote_addr or "")


def remote_session_valid() -> bool:
    config = load_config()
    password_hash = str(config.get("remote_password_hash") or "")
    expected = hashlib.sha256(password_hash.encode("utf-8")).hexdigest() if password_hash else ""
    return bool(session.get("remote_authenticated") and expected and secrets.compare_digest(str(session.get("remote_auth_version") or ""), expected))


@app.before_request
def protect_public_web_access():
    effective_client = effective_client_address()
    if private_client(effective_client) or request.path.startswith("/api/lan/") or request.path in {"/health", "/login"} or request.path.startswith("/static/"):
        return None
    config = load_config()
    authenticated = remote_session_valid() or remote_credentials_valid()
    if not config.get("remote_access_enabled") or not authenticated:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Remote session expired", "login": "/login"}), 401
        destination = request.full_path if request.query_string else request.path
        return redirect(url_for("remote_login", next=destination))
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("Origin")
        if origin and urllib.parse.urlsplit(origin).netloc != request.host:
            return jsonify({"error": "Cross-origin remote write blocked"}), 403
    return None


@app.route("/login", methods=["GET", "POST"])
def remote_login():
    config = load_config()
    if not config.get("remote_access_enabled") and not private_client(effective_client_address()):
        return render_template("login.html", error="Remote access is disabled.", username="", next_path="/"), 403
    destination = str(request.values.get("next") or "/")
    if not destination.startswith("/") or destination.startswith("//"):
        destination = "/"
    error = ""
    username = str(request.form.get("username") or "")
    if request.method == "POST":
        client = effective_client_address()
        timestamp = time.time()
        with LOGIN_ATTEMPT_LOCK:
            recent = [value for value in LOGIN_ATTEMPTS.get(client, []) if timestamp - value < 300]
            LOGIN_ATTEMPTS[client] = recent
        if len(recent) >= 10:
            error = "Too many attempts. Wait five minutes and try again."
        elif remote_password_valid(username, str(request.form.get("password") or "")):
            password_hash = str(config.get("remote_password_hash") or "")
            session.clear()
            session.permanent = True
            session["remote_authenticated"] = True
            session["remote_auth_version"] = hashlib.sha256(password_hash.encode("utf-8")).hexdigest()
            with LOGIN_ATTEMPT_LOCK:
                LOGIN_ATTEMPTS.pop(client, None)
            return redirect(destination)
        else:
            with LOGIN_ATTEMPT_LOCK:
                LOGIN_ATTEMPTS.setdefault(client, []).append(timestamp)
            error = "Incorrect username or password."
            time.sleep(0.35)
    return render_template("login.html", error=error, username=username, next_path=destination)


@app.get("/logout")
def remote_logout():
    session.clear()
    return redirect(url_for("remote_login"))


def benchmark_task(previous_queue_pause: bool) -> None:
    try:
        hashcat = executable("hashcat_path", ("hashcat",))
        if not hashcat:
            raise OSError("Hashcat is not installed")
        command = [hashcat, "-b", "-m", "22000", "-w", "4"]
        completed = subprocess.run(
            command, cwd=str(Path(hashcat).parent), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=180,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        matches = re.findall(r"Speed\.#[^:]*:\s*([0-9.]+)\s*([kMGT]?H/s)", output, re.IGNORECASE)
        if completed.returncode or not matches:
            raise OSError(hashcat_failure_message_from_text(output, completed.returncode))
        value, unit = matches[-1]
        multipliers = {"h/s": 1, "kh/s": 1_000, "mh/s": 1_000_000, "gh/s": 1_000_000_000, "th/s": 1_000_000_000_000}
        speed_hps = float(value) * multipliers[unit.lower()]
        with BENCHMARK_LOCK:
            BENCHMARK_STATE.update({"status": "complete", "speed": f"{value} {unit}", "speed_hps": speed_hps,
                                    "output": output[-12000:], "error": "", "finished_at": now()})
            atomic_json(BENCHMARK_PATH, BENCHMARK_STATE)
        add_event("success", f"WPA 22000 benchmark completed at {value} {unit}")
    except (OSError, subprocess.SubprocessError) as error:
        with BENCHMARK_LOCK:
            BENCHMARK_STATE.update({"status": "failed", "error": str(error), "finished_at": now()})
            atomic_json(BENCHMARK_PATH, BENCHMARK_STATE)
        add_event("error", f"Benchmark failed: {error}")
    finally:
        with CONFIG_LOCK:
            config = load_config()
            config["queue_paused"] = previous_queue_pause
            atomic_json(CONFIG_PATH, config)


def hashcat_failure_message_from_text(output: str, code: int) -> str:
    useful = [line.strip() for line in output.splitlines() if line.strip()]
    return (useful[-1] if useful else f"Hashcat exited with code {code}")[:500]
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024 * 1024
init_storage()
scan_local_sources()
reconcile_job_outfiles()
runner = Runner()


@app.get("/")
def index():
    return render_template("index.html", remote_session=remote_session_valid())


@app.get("/favicon.ico")
def favicon():
    return send_file(ROOT / "static" / "favicon.svg", mimetype="image/svg+xml")


@app.get("/api/state")
def state():
    with db() as connection:
        captures = [row_dict(row) for row in connection.execute("SELECT * FROM captures ORDER BY id DESC")]
        wordlists = [row_dict(row) for row in connection.execute("SELECT * FROM wordlists ORDER BY kind,position,id")]
        strategies = [row_dict(row) for row in connection.execute("SELECT * FROM strategies WHERE hidden=0 ORDER BY position,id")]
        presets = [row_dict(row) for row in connection.execute("SELECT * FROM presets ORDER BY builtin DESC,id")]
        jobs = [row_dict(row) for row in connection.execute(
            """SELECT j.*,c.filename AS capture_name,s.name AS strategy_name FROM jobs j
               JOIN captures c ON c.id=j.capture_id JOIN strategies s ON s.id=j.strategy_id
               ORDER BY CASE WHEN j.status IN ('running','paused','lan_preparing','lan_running','lan_paused') THEN 0 WHEN j.status='queued' THEN 1 ELSE 2 END,
                        CASE WHEN j.status IN ('running','paused','lan_preparing','lan_running','lan_paused','queued') THEN j.position ELSE -j.id END,j.id
               LIMIT 200""")]
        results = [row_dict(row) for row in connection.execute("SELECT * FROM results ORDER BY id DESC LIMIT 500")]
        attempts = [row_dict(row) for row in connection.execute(
            "SELECT * FROM network_attempts ORDER BY completed_at DESC,id DESC"
        )]
        events = [row_dict(row) for row in connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT 30")]
        lan_workers = [row_dict(row) for row in connection.execute("SELECT * FROM lan_workers ORDER BY name")]
        for worker in lan_workers:
            worker_telemetry = worker.get("telemetry") or {}
            if worker_telemetry.get("temperature") is None:
                previous = connection.execute(
                    "SELECT log_path,finished_at,id FROM jobs WHERE worker_name=? AND log_path LIKE '%-lan.log' ORDER BY COALESCE(finished_at,started_at,created_at) DESC,id DESC LIMIT 1",
                    (worker["name"],),
                ).fetchone()
                if previous:
                    fallback = latest_lan_log_telemetry(Path(previous["log_path"]), previous["finished_at"] or worker.get("last_seen"))
                    fallback["job_id"] = previous["id"]
                    fallback["capabilities"] = worker_telemetry.get("capabilities") or {}
                    if fallback.get("temperature") is not None:
                        worker["telemetry"] = fallback
        active = connection.execute("SELECT id FROM jobs WHERE status IN ('running','paused') ORDER BY id LIMIT 1").fetchone()
        telemetry_job = active[0] if active else (jobs[0]["id"] if jobs else None)
        telemetry = []
        if telemetry_job:
            telemetry = [row_dict(row) for row in reversed(connection.execute(
                "SELECT * FROM telemetry WHERE job_id=? ORDER BY id DESC LIMIT 180", (telemetry_job,)
            ).fetchall())]
    recovered_by_network: dict[tuple[str, str], list[dict]] = {}
    for result in results:
        key = (result["essid"], result["bssid"].replace(":", "").upper())
        recovered_by_network.setdefault(key, []).append({
            "essid": result["essid"], "bssid": result["bssid"], "password": result["password"],
        })
    attempts_by_network: dict[tuple[str, str], list[dict]] = {}
    for attempt in attempts:
        attempts_by_network.setdefault((attempt["essid"], normalize_bssid(attempt["bssid"])), []).append(attempt)
    for capture in captures:
        networks = cached_networks(Path(capture.get("hash_path") or ""))
        capture["quality"] = capture_quality_assessment(capture, networks)
        priority = capture_sort_metadata(capture)
        capture["primary_essid"] = priority["primary_essid"]
        capture["factory_ssid"] = priority["factory_ssid"]
        keys = {(item["essid"], item["bssid"].replace(":", "").upper()) for item in networks}
        recovered_keys = keys.intersection(recovered_by_network)
        capture["recovered_networks"] = len(recovered_keys)
        capture["unresolved_networks"] = max(0, len(keys) - len(recovered_keys))
        capture["fully_recovered"] = bool(keys) and not capture["unresolved_networks"]
        capture["recovered_passwords"] = [item for key in recovered_keys for item in recovered_by_network[key]]
        method_groups: dict[str, dict] = {}
        for key in keys:
            for attempt in attempts_by_network.get(key, []):
                group = method_groups.setdefault(attempt["method_key"], {
                    "method_key": attempt["method_key"], "mode": attempt["mode"],
                    "label": attempt["method_label"], "source": attempt["source_label"],
                    "completed_at": attempt["completed_at"], "networks": 0,
                    "recovered": 0, "exhausted": 0,
                })
                group["networks"] += 1
                group[attempt["outcome"] if attempt["outcome"] in {"recovered", "exhausted"} else "exhausted"] += 1
                if attempt["completed_at"] > group["completed_at"]:
                    group["completed_at"] = attempt["completed_at"]
        capture["attempted_methods"] = sorted(method_groups.values(), key=lambda item: item["completed_at"], reverse=True)
        capture["tested_method_count"] = len(method_groups)
    capture_names = {item["id"]: item["filename"] for item in captures}
    passwords_by_capture: dict[int, list[dict]] = {}
    for result in results:
        password_item = {"essid": result["essid"], "bssid": result["bssid"], "password": result["password"]}
        if result.get("capture_id"):
            passwords_by_capture.setdefault(int(result["capture_id"]), []).append(password_item)
    for job in jobs:
        capture_ids = job.get("capture_ids") or [job["capture_id"]]
        job["capture_ids"] = capture_ids
        job["capture_count"] = len(capture_ids)
        if len(capture_ids) > 1:
            first_name = capture_names.get(capture_ids[0], job["capture_name"])
            job["capture_name"] = f"{len(capture_ids)} captures · {first_name} + more"
        job_passwords: list[dict] = []
        for capture_id in capture_ids:
            job_passwords.extend(passwords_by_capture.get(int(capture_id), []))
        deduplicated = {(item["essid"], item["bssid"], item["password"]): item for item in job_passwords}
        job["passwords"] = list(deduplicated.values())
    hashcat = executable("hashcat_path", ("hashcat",))
    converter = executable("hcxpcapngtool_path", ("hcxpcapngtool",))
    backend = hashcat_backend_info()
    return jsonify({"captures": captures, "wordlists": wordlists, "strategies": strategies, "presets": presets, "jobs": jobs,
                    "results": results, "events": events, "config": browser_config(),
                    "lan_workers": lan_workers,
                    "telemetry": telemetry, "gpu": runner.current_telemetry, "cpu": system_cpu_sample(),
                    "tools": {"hashcat": hashcat, "hcxpcapngtool": converter, **backend}})


@app.get("/api/doctor")
def run_error_doctor():
    return jsonify(error_doctor_report())


@app.post("/api/doctor/fix")
def fix_error_doctor_issue():
    action = str((request.get_json(silent=True) or {}).get("action") or "all")
    if action not in {"all", "repair_paths", "relink_sources", "enable_opencl_fallback", "optimize_vram"}:
        return jsonify({"error": "Unsupported Doctor action"}), 400
    try:
        return jsonify({"ok": True, **apply_doctor_fix(action)})
    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.get("/api/benchmark")
def benchmark_status():
    with BENCHMARK_LOCK:
        if BENCHMARK_STATE.get("status") == "idle" and BENCHMARK_PATH.is_file():
            try:
                BENCHMARK_STATE.update(json.loads(BENCHMARK_PATH.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                pass
        return jsonify(dict(BENCHMARK_STATE))


@app.post("/api/benchmark")
def start_benchmark():
    with BENCHMARK_LOCK:
        if BENCHMARK_STATE.get("status") == "running":
            return jsonify({"error": "A benchmark is already running"}), 409
    with runner.lock:
        active = sorted(runner.processes)
    if active:
        return jsonify({"error": f"Benchmark needs exclusive GPU access. Finish or cancel active Job #{active[0]} first."}), 409
    with CONFIG_LOCK:
        config = load_config()
        previous_queue_pause = bool(config.get("queue_paused", False))
        config["queue_paused"] = True
        atomic_json(CONFIG_PATH, config)
    with runner.lock:
        active = sorted(runner.processes)
    if active:
        with CONFIG_LOCK:
            config = load_config(); config["queue_paused"] = previous_queue_pause; atomic_json(CONFIG_PATH, config)
        return jsonify({"error": f"Benchmark needs exclusive GPU access. Finish or cancel active Job #{active[0]} first."}), 409
    with BENCHMARK_LOCK:
        BENCHMARK_STATE.update({"status": "running", "speed": "", "speed_hps": 0.0, "output": "", "error": "", "started_at": now()})
    threading.Thread(target=benchmark_task, args=(previous_queue_pause,), name="wpa-benchmark", daemon=True).start()
    return jsonify({"ok": True, "status": "running"}), 202


@app.post("/api/captures")
def upload_captures():
    files = request.files.getlist("files")
    imported = []
    errors = []
    with db() as connection:
        known_networks: set[tuple[str, str]] = set()
        for row in connection.execute("SELECT hash_path FROM captures WHERE status='ready'"):
            path = Path(row["hash_path"] or "")
            if path.is_file():
                known_networks.update(network_identity(network) for network in cached_networks(path))
    for upload in files:
        suffix = Path(upload.filename or "").suffix.lower()
        if suffix not in ALLOWED_CAPTURES:
            errors.append(f"{upload.filename}: unsupported format")
            continue
        stored = unique_path(ROOT / "captures", upload.filename)
        upload.save(stored)
        digest = sha256_file(stored)
        with db() as connection:
            existing = connection.execute("SELECT id FROM captures WHERE sha256=?", (digest,)).fetchone()
        if existing:
            stored.unlink(missing_ok=True)
            errors.append(f"{upload.filename}: already imported")
            continue
        hash_path = unique_path(ROOT / "hashes", Path(upload.filename).stem + ".22000")
        if suffix in {".22000", ".hc22000"}:
            networks = normalize_22000(stored, hash_path)
            note = "" if networks else "No valid WPA*01/WPA*02 records"
            diagnostic_path = ""
        else:
            networks, note, diagnostic_path = convert_capture(stored, hash_path)
        skipped_networks = 0
        if networks:
            unique_networks: list[dict] = []
            seen_in_upload: set[tuple[str, str]] = set()
            for network in networks:
                identity = network_identity(network)
                if identity in known_networks or identity in seen_in_upload:
                    skipped_networks += 1
                    continue
                seen_in_upload.add(identity)
                unique_networks.append(network)
            networks = unique_networks
            if not networks:
                stored.unlink(missing_ok=True)
                hash_path.unlink(missing_ok=True)
                if diagnostic_path:
                    Path(diagnostic_path).unlink(missing_ok=True)
                errors.append(f"{upload.filename}: no new networks ({skipped_networks} already imported or duplicated)")
                continue
            write_22000_networks(hash_path, networks)
            known_networks.update(seen_in_upload)
            if skipped_networks:
                note = f"Ready for the recovery pipeline. Skipped {skipped_networks} previously imported or duplicate network record(s)."
        status = "ready" if networks else ("needs_converter" if "Install hcxtools" in note else "unusable")
        with db() as connection:
            cursor = connection.execute(
                "INSERT INTO captures(filename,stored_path,hash_path,kind,networks,status,note,sha256,imported_at,diagnostic_path) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (secure_filename(upload.filename), str(stored), str(hash_path), suffix.lstrip("."), len(networks), status, note, digest, now(), diagnostic_path),
            )
            imported.append({"id": cursor.lastrowid, "filename": upload.filename, "networks": len(networks),
                             "skipped_networks": skipped_networks, "status": status})
    return jsonify({"imported": imported, "errors": errors}), (200 if imported else 400)


@app.post("/api/wordlists")
def upload_wordlists():
    files = request.files.getlist("files")
    imported, errors = [], []
    for upload in files:
        suffix = Path(upload.filename or "").suffix.lower()
        kind = "rule" if suffix in ALLOWED_RULES else "wordlist"
        if suffix not in ALLOWED_WORDLISTS | ALLOWED_RULES:
            errors.append(f"{upload.filename}: unsupported format")
            continue
        folder = ROOT / ("rules" if kind == "rule" else "wordlists")
        stored = unique_path(folder, upload.filename)
        upload.save(stored)
        digest = sha256_file(stored)
        with db() as connection:
            existing = connection.execute("SELECT id FROM wordlists WHERE sha256=?", (digest,)).fetchone()
            if existing:
                stored.unlink(missing_ok=True)
                errors.append(f"{upload.filename}: already imported")
                continue
            position = connection.execute("SELECT COALESCE(MAX(position),0)+1 FROM wordlists WHERE kind=?", (kind,)).fetchone()[0]
            cursor = connection.execute("INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,?)",
                                        (secure_filename(upload.filename), str(stored), kind, stored.stat().st_size, digest, now(), position))
            imported.append({"id": cursor.lastrowid, "filename": upload.filename, "kind": kind})
    return jsonify({"imported": imported, "errors": errors}), (200 if imported else 400)


@app.post("/api/wordlists/scan")
def scan_wordlist_folders():
    imported, errors = scan_local_sources()
    add_event("success", f"Linked {len(imported)} local candidate source(s)")
    return jsonify({"imported": imported, "errors": errors})


@app.post("/api/wordlists/cascade-deduplicate")
def cascade_deduplicate_wordlists():
    payload = request.get_json(force=True)
    requested_paths = payload.get("paths")
    if not isinstance(requested_paths, list) or not requested_paths:
        return jsonify({"error": "Provide the current ordered source path list"}), 400
    if not CASCADE_DEDUP_LOCK.acquire(blocking=False):
        return jsonify({"error": "Cascade deduplication is already running"}), 409
    try:
        with db() as connection:
            registered = [dict(row) for row in connection.execute("SELECT * FROM wordlists")]
        by_path = {os.path.normcase(os.path.abspath(row["stored_path"])): row for row in registered}
        ordered: list[dict] = []
        used: set[int] = set()
        for raw_path in requested_paths:
            if not isinstance(raw_path, str):
                return jsonify({"error": "Every source path must be a string"}), 400
            row = by_path.get(os.path.normcase(os.path.abspath(raw_path)))
            if not row:
                return jsonify({"error": f"Source is not registered: {raw_path}"}), 400
            if row["id"] not in used:
                ordered.append(row)
                used.add(row["id"])
        dictionaries = [row for row in ordered if row["kind"] != "rule" and Path(row["stored_path"]).suffix.lower() != ".rule"]
        if not dictionaries:
            return jsonify({"error": "No dictionary files were supplied"}), 400
        try:
            result = cascade_deduplicate(ordered)
        except MemoryError:
            return jsonify({"error": "Not enough RAM to retain the global deduplication index"}), 507
        except (OSError, sqlite3.Error) as error:
            return jsonify({"error": f"Cascade deduplication failed: {error}"}), 500
        add_event("success", f"Cascade deduplication removed {result['removed_lines']} duplicate candidate(s) from {result['processed_files']} file(s)")
        return jsonify(result)
    finally:
        CASCADE_DEDUP_LOCK.release()


@app.post("/api/queue")
def create_queue():
    payload = request.get_json(force=True)
    capture_ids = [int(value) for value in payload.get("capture_ids", [])]
    strategy_ids = [int(value) for value in payload.get("strategy_ids", [])]
    if not capture_ids or not strategy_ids:
        return jsonify({"error": "Select at least one capture and strategy"}), 400
    order = str(payload.get("order", "capture_first"))
    workload = max(1, min(int(payload.get("workload", load_config().get("workload_profile", 3))), 4))
    if order not in {"capture_first", "strategy_first"}:
        return jsonify({"error": "Unsupported queue order"}), 400
    with db() as connection:
        capture_rows = {row["id"]: dict(row) for row in connection.execute(
            f"SELECT * FROM captures WHERE status='ready' AND id IN ({','.join('?' * len(capture_ids))})", capture_ids
        )}
        captures = [capture_rows[item_id] for item_id in capture_ids if item_id in capture_rows]
        captures = sort_captures(captures, str(payload.get("capture_sort", "current")))
        strategies = [dict(row) for row in connection.execute(
            f"SELECT * FROM strategies WHERE enabled=1 AND id IN ({','.join('?' * len(strategy_ids))}) ORDER BY position", strategy_ids
        )]
        created = enqueue_matrix(connection, captures, strategies, order, workload, prepend=bool(payload.get("prepend")))
    if not created:
        return jsonify({"error": "All selected networks are already recovered, tested with these methods, or already queued"}), 400
    return jsonify({"created": created, "order": order})


@app.post("/api/queue/pause-all")
def pause_all_jobs():
    return jsonify(set_global_queue_paused(True))


def set_global_queue_paused(paused: bool) -> dict:
    with CONFIG_LOCK:
        current = load_config()
        current["queue_paused"] = paused
        atomic_json(CONFIG_PATH, current)
    jobs = runner.pause_all() if paused else runner.resume_all()
    with db() as connection:
        if paused:
            stop_job_clocks(connection, ("lan_running",))
            connection.execute("UPDATE jobs SET status='lan_paused',remote_command='pause' WHERE status='lan_running'")
        else:
            connection.execute("UPDATE jobs SET status='lan_running',remote_command='resume' WHERE status='lan_paused'")
    add_event("info", f"GPU queue {'paused' if paused else 'resumed'}")
    return {"ok": True, "queue_paused": paused, "paused_jobs" if paused else "resumed_jobs": jobs}


@app.post("/api/queue/resume-all")
def resume_all_jobs():
    return jsonify(set_global_queue_paused(False))


@app.post("/api/queue/local/<action>")
def control_local_queue(action: str):
    if action not in {"pause", "resume"}:
        return jsonify({"error": "Unsupported local queue action"}), 400
    paused = action == "pause"
    with CONFIG_LOCK:
        current = load_config()
        current["local_queue_paused"] = paused
        atomic_json(CONFIG_PATH, current)
    jobs = runner.pause_all() if paused else runner.resume_all()
    add_event("info", f"Coordinator GPU lane {'paused' if paused else 'resumed'}")
    return jsonify({"ok": True, "local_queue_paused": paused, "jobs": jobs})


@app.put("/api/queue/workload")
def update_queue_workload():
    payload = request.get_json(force=True)
    workload = max(1, min(int(payload.get("workload", 3)), 4))
    return jsonify(set_global_workload(workload))


def set_global_workload(workload: int) -> dict:
    workload = max(1, min(int(workload), 4))
    with CONFIG_LOCK:
        current = load_config()
        current["workload_profile"] = workload
        atomic_json(CONFIG_PATH, current)
    with db() as connection:
        changed = connection.execute(
            "UPDATE jobs SET workload=? WHERE status IN ('queued','running','paused')",
            (workload,),
        ).rowcount
    live_jobs = runner.set_live_workload(workload)
    add_event("info", f"Live GPU profile changed instantly to W{workload} for {len(live_jobs)} active job(s)")
    return {"ok": True, "workload": workload, "updated_jobs": changed, "live_jobs": live_jobs,
            "restarting_jobs": []}


@app.put("/api/queue/cpu-profile")
def update_cpu_profile():
    profile = str((request.get_json(force=True) or {}).get("profile") or "off")
    if profile not in {"off", "low", "balanced", "high"}:
        return jsonify({"error": "Unsupported CPU profile"}), 400
    backend = hashcat_backend_info()
    with CONFIG_LOCK:
        current = load_config(); current["cpu_profile"] = profile; atomic_json(CONFIG_PATH, current)
    with db() as connection:
        changed = connection.execute("UPDATE jobs SET cpu_profile=? WHERE status='queued'", (profile,)).rowcount
        active = connection.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('running','paused','lan_running','lan_paused')").fetchone()[0]
    add_event("info", f"CPU profile changed to {profile}; applies to {changed} waiting job(s)")
    return jsonify({"ok": True, "profile": profile, "updated_jobs": changed, "active_jobs_unchanged": active,
                    "local_cpu_available": bool(backend.get("cpu_available")), "local_cpu_name": backend.get("cpu_name")})


@app.post("/api/wordlists/<int:item_id>/analyze")
def analyze_wordlist(item_id: int):
    with db() as connection:
        row = connection.execute("SELECT id,kind,stored_path FROM wordlists WHERE id=?", (item_id,)).fetchone()
    if not row:
        return jsonify({"error": "Source not found"}), 404
    if row["kind"] != "wordlist":
        return jsonify({"error": "Rule files are not password dictionaries"}), 400
    if not Path(row["stored_path"]).is_file():
        return jsonify({"error": f"Dictionary not found: {row['stored_path']}"}), 404
    with WORDLIST_ANALYSIS_LOCK:
        if item_id in WORDLIST_ANALYSIS_ACTIVE:
            return jsonify({"ok": True, "status": "processing"}), 202
        WORDLIST_ANALYSIS_ACTIVE.add(item_id)
    threading.Thread(target=analyze_wordlist_task, args=(item_id,), name=f"wordlist-analysis-{item_id}", daemon=True).start()
    return jsonify({"ok": True, "status": "processing"}), 202


@app.post("/api/wordlists/analyze-all")
def analyze_all_wordlists():
    with db() as connection:
        item_ids = [row[0] for row in connection.execute(
            "SELECT id FROM wordlists WHERE kind='wordlist' ORDER BY position,id"
        )]
    started = []
    with WORDLIST_ANALYSIS_LOCK:
        for item_id in item_ids:
            if item_id not in WORDLIST_ANALYSIS_ACTIVE:
                WORDLIST_ANALYSIS_ACTIVE.add(item_id)
                started.append(item_id)
    for item_id in started:
        threading.Thread(target=analyze_wordlist_task, args=(item_id,), name=f"wordlist-analysis-{item_id}", daemon=True).start()
    return jsonify({"ok": True, "started": started, "processing": len(WORDLIST_ANALYSIS_ACTIVE)}), 202


@app.post("/api/wordlists/<int:item_id>/filter-short")
def filter_short_candidates(item_id: int):
    if not WORDLIST_FILTER_LOCK.acquire(blocking=False):
        return jsonify({"error": "Another dictionary filter is already running"}), 409
    try:
        with db() as connection:
            row = connection.execute("SELECT * FROM wordlists WHERE id=?", (item_id,)).fetchone()
            if not row:
                return jsonify({"error": "Source not found"}), 404
            source = dict(row)
            if source["kind"] != "wordlist":
                return jsonify({"error": "Hashcat rule files cannot be filtered as dictionaries"}), 400
            active = connection.execute(
                """SELECT j.id,s.config_json FROM jobs j JOIN strategies s ON s.id=j.strategy_id
                   WHERE j.status IN ('running','paused','lan_preparing','lan_running','lan_paused')"""
            ).fetchall()
            for job in active:
                config = json.loads(job["config_json"] or "{}")
                if int(config.get("wordlist_id") or 0) == item_id:
                    return jsonify({"error": f"Job #{job['id']} is using this dictionary. Finish or cancel it first."}), 409
        path = Path(source["stored_path"])
        if not path.is_file():
            return jsonify({"error": f"Dictionary not found: {path}"}), 404
        result = filter_short_wordlist(path)
        destination = result.pop("path")
        with db() as connection:
            connection.execute(
                "UPDATE wordlists SET filename=?,stored_path=?,bytes=?,sha256=?,imported_at=?,analysis_json='{}' WHERE id=?",
                (destination.name, str(destination), result["bytes"], linked_source_fingerprint(destination), now(), item_id),
            )
            queued = connection.execute(
                """SELECT j.id,s.name,s.mode,s.config_json FROM jobs j JOIN strategies s ON s.id=j.strategy_id
                   WHERE j.status='queued'"""
            ).fetchall()
            for job in queued:
                descriptor = strategy_attempt_descriptor(connection, dict(job))
                if descriptor:
                    connection.execute("UPDATE jobs SET attempt_key=?,attempt_label=? WHERE id=?",
                                       (descriptor[0], descriptor[1], job["id"]))
        add_event("success", f"WPA-filtered {source['filename']}: removed {result['removed_lines']} candidate(s) shorter than 8 bytes")
        return jsonify({"ok": True, "filename": destination.name, **result})
    except OSError as error:
        return jsonify({"error": str(error)}), 500
    finally:
        WORDLIST_FILTER_LOCK.release()


@app.patch("/api/wordlists/<int:item_id>")
def update_wordlist(item_id: int):
    payload = request.get_json(force=True)
    with db() as connection:
        current = connection.execute("SELECT * FROM wordlists WHERE id=?", (item_id,)).fetchone()
        if not current:
            return jsonify({"error": "Source not found"}), 404
        position = max(0, int(payload.get("position", current["position"])))
        connection.execute("UPDATE wordlists SET position=? WHERE id=?", (position, item_id))
    return jsonify({"ok": True})


@app.post("/api/presets")
def create_preset():
    payload = request.get_json(force=True)
    name = str(payload.get("name") or "Custom overnight plan").strip()[:100]
    config = payload.get("config") or {}
    if config.get("order") not in {"capture_first", "strategy_first"}:
        return jsonify({"error": "Choose capture_first or strategy_first"}), 400
    if not isinstance(config.get("stages"), list) or not config["stages"]:
        return jsonify({"error": "A preset needs at least one stage"}), 400
    config["workload"] = max(1, min(int(config.get("workload", 3)), 4))
    with db() as connection:
        cursor = connection.execute(
            "INSERT INTO presets(name,description,config_json,builtin,created_at,updated_at) VALUES(?,?,?,0,?,?)",
            (name, str(payload.get("description") or "Custom recovery plan")[:300], json.dumps(config), now(), now()),
        )
    return jsonify({"id": cursor.lastrowid})


@app.delete("/api/presets/<int:preset_id>")
def delete_preset(preset_id: int):
    with db() as connection:
        changed = connection.execute("DELETE FROM presets WHERE id=? AND builtin=0", (preset_id,)).rowcount
    return jsonify({"ok": bool(changed)})


@app.post("/api/presets/<int:preset_id>/queue")
def queue_preset(preset_id: int):
    payload = request.get_json(force=True)
    capture_ids = [int(value) for value in payload.get("capture_ids", [])]
    if not capture_ids:
        return jsonify({"error": "Select at least one ready capture"}), 400
    with db() as connection:
        preset = connection.execute("SELECT * FROM presets WHERE id=?", (preset_id,)).fetchone()
        if not preset:
            return jsonify({"error": "Preset not found"}), 404
        config = json.loads(preset["config_json"])
        capture_rows = {row["id"]: dict(row) for row in connection.execute(
            f"SELECT * FROM captures WHERE status='ready' AND id IN ({','.join('?' * len(capture_ids))})", capture_ids
        )}
        captures = [capture_rows[item_id] for item_id in capture_ids if item_id in capture_rows]
        captures = sort_captures(captures, str(payload.get("capture_sort", "current")))
        stages = expand_preset_stages(connection, config)
        if not stages:
            return jsonify({"error": "This preset produced no stages. Add wordlists or rules first."}), 400
        workload = max(1, min(int(config.get("workload", 3)), 4))
        created = enqueue_matrix(connection, captures, stages, config.get("order", "strategy_first"), workload, preset["name"])
    if not created:
        return jsonify({"error": "All selected networks are already recovered, tested with these methods, or already queued"}), 400
    add_event("success", f"Queued preset {preset['name']}: {created} jobs")
    return jsonify({"created": created, "preset": preset["name"]})


@app.put("/api/strategies/order")
def reorder_strategies():
    payload = request.get_json(force=True)
    strategy_ids = [int(value) for value in payload.get("strategy_ids", [])]
    if len(strategy_ids) != len(set(strategy_ids)):
        return jsonify({"error": "Strategy order contains duplicates"}), 400
    with db() as connection:
        visible_ids = [row[0] for row in connection.execute("SELECT id FROM strategies WHERE hidden=0 ORDER BY position,id")]
        if set(strategy_ids) != set(visible_ids):
            return jsonify({"error": "Strategy order is incomplete"}), 400
        connection.executemany("UPDATE strategies SET position=? WHERE id=?", [(position, strategy_id) for position, strategy_id in enumerate(strategy_ids)])
    return jsonify({"ok": True, "strategy_ids": strategy_ids})


@app.patch("/api/strategies/<int:strategy_id>")
def update_strategy(strategy_id: int):
    payload = request.get_json(force=True)
    allowed_modes = {"known", "common", "pattern", "dictionary", "rules", "hybrid", "mask"}
    with db() as connection:
        current = connection.execute("SELECT * FROM strategies WHERE id=?", (strategy_id,)).fetchone()
        if not current:
            return jsonify({"error": "Strategy not found"}), 404
        name = str(payload.get("name", current["name"]))[:80]
        mode = str(payload.get("mode", current["mode"]))
        if mode not in allowed_modes:
            return jsonify({"error": "Unsupported mode"}), 400
        config = payload.get("config", json.loads(current["config_json"]))
        enabled = 1 if payload.get("enabled", current["enabled"]) else 0
        position = int(payload.get("position", current["position"]))
        connection.execute("UPDATE strategies SET name=?,mode=?,config_json=?,enabled=?,position=? WHERE id=?",
                           (name, mode, json.dumps(config), enabled, position, strategy_id))
    return jsonify({"ok": True})


@app.post("/api/strategies")
def create_strategy():
    payload = request.get_json(force=True)
    mode = str(payload.get("mode", "dictionary"))
    if mode not in {"known", "common", "pattern", "dictionary", "rules", "hybrid", "mask"}:
        return jsonify({"error": "Unsupported mode"}), 400
    with db() as connection:
        position = connection.execute("SELECT COALESCE(MAX(position),-1)+1 FROM strategies").fetchone()[0]
        cursor = connection.execute("INSERT INTO strategies(name,mode,config_json,position,enabled,builtin) VALUES(?,?,?,?,1,0)",
                                    (str(payload.get("name", "New strategy"))[:80], mode, json.dumps(payload.get("config", {})), position))
    return jsonify({"id": cursor.lastrowid})


@app.post("/api/jobs/<int:job_id>/<action>")
def control_job(job_id: int, action: str):
    if action not in {"pause", "resume", "cancel", "retry"}:
        return jsonify({"error": "Unsupported action"}), 400
    if action == "retry":
        with db() as connection:
            next_position = connection.execute("SELECT COALESCE(MAX(position),0)+1 FROM jobs").fetchone()[0]
            changed = connection.execute("""UPDATE jobs SET status='queued',progress=0,speed='',speed_hps=0,recovered=0,
                candidates_done=0,candidates_total=0,eta='',error='',started_at=NULL,finished_at=NULL,
                elapsed_seconds=0,active_started_at=NULL,worker_name='',remote_command='',position=? WHERE id=? AND status IN ('failed','blocked','cancelled')""",
                (next_position, job_id)).rowcount
        if not changed:
            return jsonify({"error": "This job is no longer in a retryable state"}), 409
        return jsonify({"ok": True, "job_id": job_id})
    with db() as connection:
        remote = connection.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
        if remote and remote["status"] in {"lan_preparing", "lan_running", "lan_paused"}:
            command = action
            target = "lan_paused" if action == "pause" else "lan_running" if action == "resume" else remote["status"]
            if action in {"pause", "cancel"}:
                stop_job_clock(connection, job_id)
            connection.execute("UPDATE jobs SET remote_command=?,status=? WHERE id=?", (command, target, job_id))
            return jsonify({"ok": True})
    return jsonify({"ok": runner.control(job_id, action)})


@app.put("/api/jobs/order")
def reorder_jobs():
    payload = request.get_json(force=True)
    job_ids = [int(value) for value in payload.get("job_ids", [])]
    if len(job_ids) != len(set(job_ids)):
        return jsonify({"error": "Queue order contains duplicates"}), 400
    with db() as connection:
        queued_ids = [row[0] for row in connection.execute("SELECT id FROM jobs WHERE status='queued' ORDER BY position,id")]
        if set(job_ids) != set(queued_ids):
            return jsonify({"error": "The queue changed while it was being reordered. Refresh and try again."}), 409
        connection.executemany("UPDATE jobs SET position=? WHERE id=?", [(position + 1, job_id) for position, job_id in enumerate(job_ids)])
    return jsonify({"ok": True, "job_ids": job_ids})


@app.put("/api/jobs/sort")
def sort_waiting_jobs():
    payload = request.get_json(force=True)
    mode = str(payload.get("mode", "current"))
    if mode not in CAPTURE_SORT_MODES or mode == "current":
        return jsonify({"error": "Choose a queue sorting mode"}), 400
    with db() as connection:
        rows = [dict(row) for row in connection.execute(
            """SELECT j.id,j.position,c.filename,c.hash_path,c.networks,c.imported_at
               FROM jobs j JOIN captures c ON c.id=j.capture_id
               WHERE j.status='queued' ORDER BY j.position,j.id"""
        )]
        ordered = sort_captures(rows, mode)
        connection.executemany(
            "UPDATE jobs SET position=? WHERE id=?",
            [(position + 1, int(row["id"])) for position, row in enumerate(ordered)],
        )
    add_event("info", f"Sorted {len(ordered)} waiting jobs: {mode}")
    return jsonify({"ok": True, "mode": mode, "updated": len(ordered)})


@app.get("/api/jobs/<int:job_id>/log")
def job_log(job_id: int):
    with db() as connection:
        row = connection.execute("SELECT id,log_path,command_json,error FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    path = Path(row["log_path"]) if row["log_path"] else None
    output = path.read_text(encoding="utf-8", errors="replace") if path and path.is_file() else "No process output was recorded."
    command = json.loads(row["command_json"] or "[]")
    return jsonify({"id": job_id, "error": row["error"], "command": command, "output": output})


def delete_job_files(job_id: int, log_path: str, session_name: str) -> None:
    candidates = [
        Path(log_path) if log_path else None,
        ROOT / "logs" / f"job-{job_id}-telemetry.csv",
        DATA / f"job-{job_id}-found.txt",
        DATA / "runtime" / f"job-{job_id}.22000",
        DATA / "runtime" / f"reconcile-{job_id}.22000",
        ROOT / "sessions" / f"{session_name}.restore",
    ]
    for path in candidates:
        if path:
            path.unlink(missing_ok=True)


@app.delete("/api/jobs/finished")
def delete_finished_jobs():
    with db() as connection:
        rows = connection.execute("SELECT id,log_path,session_name FROM jobs WHERE status IN ('complete','failed','blocked','cancelled')").fetchall()
        connection.execute("DELETE FROM jobs WHERE status IN ('complete','failed','blocked','cancelled')")
    for row in rows:
        delete_job_files(row["id"], row["log_path"], row["session_name"])
    return jsonify({"ok": True, "deleted": len(rows)})


@app.delete("/api/jobs/<int:job_id>")
def delete_job(job_id: int):
    with db() as connection:
        row = connection.execute("SELECT id,status,log_path,session_name FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return jsonify({"error": "Job not found"}), 404
        if row["status"] in {"running", "paused"}:
            return jsonify({"error": "Cancel the active job before deleting it"}), 409
        connection.execute("DELETE FROM jobs WHERE id=?", (job_id,))
    delete_job_files(row["id"], row["log_path"], row["session_name"])
    return jsonify({"ok": True})


@app.delete("/api/captures/<int:capture_id>")
def delete_capture(capture_id: int):
    with db() as connection:
        row = connection.execute("SELECT stored_path,hash_path,diagnostic_path FROM captures WHERE id=?", (capture_id,)).fetchone()
        if not row:
            return jsonify({"error": "Not found"}), 404
        running = connection.execute("SELECT 1 FROM jobs WHERE capture_id=? AND status IN ('running','paused')", (capture_id,)).fetchone()
        if running:
            return jsonify({"error": "Capture has an active job"}), 409
        connection.execute("DELETE FROM captures WHERE id=?", (capture_id,))
    for path in row:
        if path:
            Path(path).unlink(missing_ok=True)
    return jsonify({"ok": True})


@app.post("/api/captures/<int:capture_id>/reprocess")
def reprocess_capture(capture_id: int):
    with db() as connection:
        row = connection.execute("SELECT * FROM captures WHERE id=?", (capture_id,)).fetchone()
        other_hashes = [item[0] for item in connection.execute(
            "SELECT hash_path FROM captures WHERE id<>? AND status='ready'", (capture_id,)
        )]
    if not row:
        return jsonify({"error": "Not found"}), 404
    source, destination = Path(row["stored_path"]), Path(row["hash_path"])
    current_identities = {network_identity(network) for network in cached_networks(destination)} if destination.is_file() else set()
    other_identities: set[tuple[str, str]] = set()
    for path_value in other_hashes:
        path = Path(path_value or "")
        if path.is_file():
            other_identities.update(network_identity(network) for network in cached_networks(path))
    if row["kind"] in {"22000", "hc22000"}:
        networks = normalize_22000(source, destination)
        note = "" if networks else "No valid WPA*01/WPA*02 records"
        diagnostic_path = ""
    else:
        networks, note, diagnostic_path = convert_capture(source, destination)
    if networks:
        filtered: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for network in networks:
            identity = network_identity(network)
            if identity in seen or (identity in other_identities and identity not in current_identities):
                continue
            seen.add(identity)
            filtered.append(network)
        networks = filtered
        write_22000_networks(destination, networks)
    status = "ready" if networks else ("needs_converter" if "Install hcxtools" in note else "unusable")
    with db() as connection:
        connection.execute("UPDATE captures SET networks=?,status=?,note=?,diagnostic_path=? WHERE id=?", (len(networks), status, note, diagnostic_path, capture_id))
    return jsonify({"status": status, "networks": len(networks), "note": note})


@app.get("/api/captures/<int:capture_id>/diagnostics")
def capture_diagnostics(capture_id: int):
    with db() as connection:
        row = connection.execute("SELECT filename,diagnostic_path,note FROM captures WHERE id=?", (capture_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    path = Path(row["diagnostic_path"]) if row["diagnostic_path"] else None
    diagnostics = path.read_text(encoding="utf-8", errors="replace") if path and path.is_file() else row["note"]
    return jsonify({"filename": row["filename"], "diagnostics": diagnostics or "No converter diagnostics are available."})


@app.post("/api/captures/<int:capture_id>/verify")
def verify_capture_password(capture_id: int):
    password = str((request.get_json(force=True) or {}).get("password", ""))
    encoded = password.encode("utf-8")
    is_raw_psk = len(password) == 64 and all(character in "0123456789abcdefABCDEF" for character in password)
    if "\n" in password or "\r" in password or not (is_raw_psk or 8 <= len(encoded) <= 63):
        return jsonify({"error": "WPA password must be 8–63 UTF-8 bytes or exactly 64 hexadecimal characters"}), 400
    with runner.lock:
        if runner.processes:
            return jsonify({"error": "Finish or cancel the active GPU job before verifying a password"}), 409
    with db() as connection:
        capture = connection.execute("SELECT * FROM captures WHERE id=? AND status='ready'", (capture_id,)).fetchone()
    if not capture:
        return jsonify({"error": "Ready capture not found"}), 404
    hashcat = executable("hashcat_path", ("hashcat",))
    if not hashcat:
        return jsonify({"error": "Hashcat is not configured"}), 409
    token = uuid.uuid4().hex
    candidate_path = DATA / "runtime" / f"verify-{token}.txt"
    outfile = DATA / "runtime" / f"verify-{token}-found.txt"
    candidate_path.write_text(password + "\n", encoding="utf-8", newline="\n")
    command = [
        hashcat, "-m", "22000", capture["hash_path"], "-a", "0", str(candidate_path),
        "--potfile-disable", "--outfile", str(outfile), "--outfile-format", "1,2", "--separator", "|",
        "--workload-profile", "2", "--hwmon-temp-abort", str(load_config().get("temperature_abort", 90)),
    ]
    try:
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.run(
            command, cwd=str(Path(hashcat).parent), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120, creationflags=creation_flags,
        )
        capture_lookup = {network["hash"]: capture_id for network in parse_22000(Path(capture["hash_path"]))}
        _, recovered_networks = import_outfile(
            outfile, capture_id, "Manual verification", Path(capture["hash_path"]), capture_lookup
        )
        if process.returncode not in (0, 1) and not recovered_networks:
            output = "\n".join(part for part in (process.stdout, process.stderr) if part).strip()
            return jsonify({"error": f"Hashcat verification failed ({process.returncode}): {output[-800:]}"}), 500
        skipped = skip_fully_recovered_jobs() if recovered_networks else 0
        matches = [{"essid": essid, "bssid": bssid, "password": password} for essid, bssid in sorted(recovered_networks)]
        add_event("success" if matches else "info", f"Manual password verification for {capture['filename']}: {'valid' if matches else 'no match'}")
        return jsonify({"valid": bool(matches), "matches": matches, "skipped_jobs": skipped})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Password verification timed out after 120 seconds"}), 504
    finally:
        candidate_path.unlink(missing_ok=True)
        outfile.unlink(missing_ok=True)


@app.get("/api/results/export")
def export_results():
    with db() as connection:
        rows = connection.execute(
            "SELECT essid,bssid,password,found_at FROM results ORDER BY id"
        ).fetchall()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["datetime", "task", "algorithm", "status", "password", "note"])
    for row in rows:
        compact_bssid = re.sub(r"[^0-9a-fA-F]", "", row["bssid"] or "")[:12].lower()
        if len(compact_bssid) == 12:
            display_bssid = ":".join(compact_bssid[index:index + 2] for index in range(0, 12, 2))
        else:
            display_bssid = str(row["bssid"] or "").strip().lower()
        try:
            found_at = datetime.fromisoformat(row["found_at"].replace("Z", "+00:00"))
            timestamp = found_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (TypeError, ValueError):
            timestamp = str(row["found_at"] or "")
        task = f'{row["essid"]}<br><span class="small">{display_bssid}</span>'
        writer.writerow([timestamp, task, "WPA(2)", "FOUND", row["password"], ""])
    payload = io.BytesIO(("\ufeff" + output.getvalue()).encode("utf-8"))
    return send_file(
        payload,
        as_attachment=True,
        download_name="recovered.csv",
        mimetype="text/csv; charset=utf-8",
    )


@app.get("/api/backup/export")
def export_memory_backup():
    with db() as connection:
        results = [dict(row) for row in connection.execute(
            "SELECT essid,bssid,password,strategy,found_at FROM results ORDER BY id"
        )]
        attempts = [dict(row) for row in connection.execute(
            """SELECT essid,bssid,method_key,mode,method_label,source_label,outcome,completed_at
               FROM network_attempts ORDER BY id"""
        )]
        sources = [dict(row) for row in connection.execute(
            "SELECT filename,kind,bytes,sha256,position FROM wordlists ORDER BY kind,position,id"
        )]
    payload = {
        "format": BACKUP_FORMAT,
        "exported_at": now(),
        "config": load_config(),
        "results": results,
        "network_attempts": attempts,
        "source_manifest": sources,
    }
    data = io.BytesIO((json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return send_file(
        data, as_attachment=True,
        download_name=f"NewFPV-Handshake-Lab-memory-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json",
        mimetype="application/json",
    )


@app.post("/api/backup/restore")
def restore_memory_backup():
    with runner.lock:
        if runner.processes:
            return jsonify({"error": "Pause or finish the active GPU job before restoring a backup"}), 409
    upload = request.files.get("file")
    if not upload:
        return jsonify({"error": "Select a Handshake Lab backup JSON file"}), 400
    raw = upload.stream.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        return jsonify({"error": "Backup file is larger than 32 MB"}), 413
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "Backup JSON is invalid"}), 400
    if not isinstance(payload, dict) or payload.get("format") != BACKUP_FORMAT:
        return jsonify({"error": "This is not a supported Handshake Lab memory backup"}), 400
    imported_results = 0
    imported_attempts = 0
    with db() as connection:
        for item in payload.get("results", []):
            if not isinstance(item, dict):
                continue
            essid, bssid, password = str(item.get("essid") or ""), normalize_bssid(item.get("bssid") or ""), str(item.get("password") or "")
            if not essid or not bssid or not password:
                continue
            fingerprint = hashlib.sha256(f"{essid}\0{bssid}\0{password}".encode("utf-8", errors="replace")).hexdigest()
            imported_results += connection.execute(
                """INSERT OR IGNORE INTO results
                   (fingerprint,essid,bssid,password,capture_id,strategy,found_at,job_id)
                   VALUES(?,?,?,?,NULL,?,?,NULL)""",
                (fingerprint, essid, bssid, password, str(item.get("strategy") or "Backup restore")[:100],
                 str(item.get("found_at") or now())),
            ).rowcount
        for item in payload.get("network_attempts", []):
            if not isinstance(item, dict):
                continue
            method_key = str(item.get("method_key") or "")
            essid, bssid = str(item.get("essid") or ""), normalize_bssid(item.get("bssid") or "")
            mode = str(item.get("mode") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", method_key) or not essid or not bssid or mode == "known":
                continue
            outcome = str(item.get("outcome") or "exhausted")
            if outcome not in {"exhausted", "recovered"}:
                outcome = "exhausted"
            imported_attempts += connection.execute(
                """INSERT OR IGNORE INTO network_attempts
                   (essid,bssid,method_key,mode,method_label,source_label,outcome,job_id,completed_at)
                   VALUES(?,?,?,?,?,?,?,NULL,?)""",
                (essid, bssid, method_key, mode, str(item.get("method_label") or mode.title())[:300],
                 str(item.get("source_label") or "")[:500], outcome, str(item.get("completed_at") or now())),
            ).rowcount
    backup_config = payload.get("config") if isinstance(payload.get("config"), dict) else {}
    with CONFIG_LOCK:
        current = load_config()
        for key in ("max_workers", "workload_profile", "cpu_profile", "temperature_abort", "restore_interrupted_jobs", "theme_accent"):
            if key in backup_config:
                current[key] = backup_config[key]
        current["max_workers"] = max(1, min(int(current.get("max_workers", 1)), 2))
        current["workload_profile"] = max(1, min(int(current.get("workload_profile", 3)), 4))
        current["cpu_profile"] = current.get("cpu_profile") if current.get("cpu_profile") in {"off", "low", "balanced", "high"} else "off"
        current["temperature_abort"] = max(70, min(int(current.get("temperature_abort", 90)), 100))
        current["queue_paused"] = False
        atomic_json(CONFIG_PATH, current)
    rebuild_results_csv()
    add_event("success", f"Memory backup restored: {imported_results} result(s), {imported_attempts} network attempt(s)")
    skip_fully_recovered_jobs()
    return jsonify({"ok": True, "results": imported_results, "attempts": imported_attempts, "config": current})


@app.put("/api/config")
def save_config():
    payload = request.get_json(force=True)
    with CONFIG_LOCK:
        current = load_config()
        for key in default_config():
            if key != "remote_password_hash" and key in payload:
                current[key] = payload[key]
        current["port"] = max(1, min(int(current["port"]), 65535))
        current["max_workers"] = max(1, min(int(current["max_workers"]), 2))
        current["workload_profile"] = max(1, min(int(current.get("workload_profile", 3)), 4))
        current["cpu_profile"] = current.get("cpu_profile") if current.get("cpu_profile") in {"off", "low", "balanced", "high"} else "off"
        current["temperature_abort"] = max(70, min(int(current.get("temperature_abort", 90)), 100))
        current["queue_paused"] = bool(current.get("queue_paused", False))
        current["lan_enabled"] = bool(current.get("lan_enabled", False))
        current["lan_job_timeout"] = max(60, min(int(current.get("lan_job_timeout", 180)), 1800))
        current["telegram_file_intake"] = bool(current.get("telegram_file_intake", False))
        current["remote_access_enabled"] = bool(current.get("remote_access_enabled", False))
        current["self_signed_https_enabled"] = bool(current.get("self_signed_https_enabled", False))
        current["https_port"] = max(1, min(int(current.get("https_port", 8788)), 65535))
        if current["self_signed_https_enabled"] and current["https_port"] == current["port"]:
            return jsonify({"error": "Self-signed HTTPS must use a different port from the HTTP listener"}), 400
        current["remote_username"] = re.sub(r"[^0-9A-Za-z_.-]", "", str(current.get("remote_username") or "newfpv"))[:64] or "newfpv"
        current["remote_https_url"] = str(current.get("remote_https_url") or "").strip().rstrip("/")
        if current["remote_https_url"]:
            parsed_https = urllib.parse.urlsplit(current["remote_https_url"])
            if parsed_https.scheme != "https" or not parsed_https.hostname or parsed_https.username or parsed_https.password:
                return jsonify({"error": "Telegram Web App URL must be a valid HTTPS address without embedded credentials"}), 400
        remote_password = str(payload.get("remote_password") or "")
        if remote_password:
            if len(remote_password) < 12:
                return jsonify({"error": "Remote password must contain at least 12 characters"}), 400
            current["remote_password_hash"] = generate_password_hash(remote_password)
        if current["remote_access_enabled"] and not current.get("remote_password_hash"):
            return jsonify({"error": "Set a remote password before enabling public access"}), 400
        if current["remote_access_enabled"]:
            current["host"] = "0.0.0.0"
        if current["lan_enabled"] and not str(current.get("lan_token") or "").strip():
            current["lan_token"] = secrets.token_urlsafe(32)
        atomic_json(CONFIG_PATH, current)
    if current.get("self_signed_https_enabled") and not SELF_SIGNED_HTTPS_URL:
        start_self_signed_https(current)
    return jsonify({"ok": True, "config": browser_config()})


@app.post("/api/notifications/test")
def test_notification():
    channel = str((request.get_json(silent=True) or {}).get("channel") or "windows")
    config = load_config()
    sent: list[str] = []
    try:
        if channel in {"windows", "all"} and config.get("notifications_windows", True):
            if os.name != "nt":
                if channel == "windows":
                    return jsonify({"error": "Windows notifications are available only on Windows"}), 400
            else:
                send_windows_notification("TEST ONLY · Handshake Lab", "Notification check completed. No password was recovered.")
                sent.append("windows")
        if channel in {"telegram", "all"} and config.get("notifications_telegram", False):
            token = str(config.get("telegram_bot_token") or "").strip()
            chat_id = str(config.get("telegram_chat_id") or "").strip()
            if not token or not chat_id:
                return jsonify({"error": "Enter both Telegram bot token and chat ID first"}), 400
            telegram_render(token, chat_id, "status")
            sent.append("telegram")
        if channel not in {"windows", "telegram", "all"}:
            return jsonify({"error": "Unsupported notification channel"}), 400
        if not sent:
            return jsonify({"error": "Enable at least one configured notification channel first"}), 400
    except (OSError, urllib.error.URLError, subprocess.SubprocessError) as error:
        return jsonify({"error": str(error)}), 502
    return jsonify({"ok": True, "channel": channel, "sent": sent})


@app.get("/api/remote/status")
def remote_access_status():
    config = load_config()
    public_ip = ""
    error = ""
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=6) as response:
            public_ip = str(json.loads(response.read().decode("utf-8")).get("ip") or "")
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as failure:
        error = str(failure)
    port = int(config.get("port", 8787))
    return jsonify({
        "enabled": bool(config.get("remote_access_enabled")),
        "password_configured": bool(config.get("remote_password_hash")),
        "listening_publicly": str(config.get("host")) in {"0.0.0.0", "::"},
        "public_ip": public_ip,
        "url": str(config.get("remote_https_url") or "") or (f"http://{public_ip}:{port}" if public_ip else ""),
        "https_url": telegram_https_url(config),
        "self_signed_https_enabled": bool(config.get("self_signed_https_enabled")),
        "self_signed_https_url": SELF_SIGNED_HTTPS_URL,
        "https_port": int(config.get("https_port", 8788)),
        "error": error,
        "requires_router_forward": True,
        "tls_recommended": True,
    })


def lan_authorized() -> bool:
    config = load_config()
    expected = str(config.get("lan_token") or "")
    supplied = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    return bool(config.get("lan_enabled") and expected and secrets.compare_digest(expected, supplied))


def lan_source(connection: sqlite3.Connection, source_id: int | None) -> dict | None:
    row = connection.execute("SELECT filename,stored_path,bytes,kind FROM wordlists WHERE id=?", (source_id,)).fetchone() if source_id else None
    if not row:
        return None
    path = Path(row["stored_path"])
    if not path.is_file():
        return None
    return {"filename": row["filename"], "bytes": row["bytes"], "kind": row["kind"],
            "fingerprint": portable_source_identity(path)}


@app.post("/api/lan/register")
def lan_register():
    if not lan_authorized():
        return jsonify({"error": "LAN worker authentication failed"}), 401
    payload = request.get_json(force=True)
    name = re.sub(r"[^0-9A-Za-z_.-]", "-", str(payload.get("name") or "worker"))[:80]
    timestamp = now()
    with db() as connection:
        previous = connection.execute("SELECT current_job_id FROM lan_workers WHERE name=?", (name,)).fetchone()
        if previous and previous["current_job_id"]:
            connection.execute(
                """UPDATE jobs SET status='queued',worker_name='',remote_command='',
                   error='LAN worker restarted; safely requeued' WHERE id=?
                   AND status IN ('lan_preparing','lan_running','lan_paused')""",
                (previous["current_job_id"],),
            )
        connection.execute(
            """INSERT INTO lan_workers(name,gpu_name,status,current_job_id,address,telemetry_json,last_seen,created_at)
               VALUES(?,?,'idle',NULL,?,?,?,?) ON CONFLICT(name) DO UPDATE SET
               gpu_name=excluded.gpu_name,status='idle',current_job_id=NULL,address=excluded.address,
               telemetry_json=excluded.telemetry_json,last_seen=excluded.last_seen""",
            (name, str(payload.get("gpu_name") or "")[:120], request.remote_addr or "",
             json.dumps({"capabilities": payload.get("capabilities") or {}}), timestamp, timestamp),
        )
    return jsonify({"ok": True, "worker": name, "temperature_abort": load_config().get("temperature_abort", 90)})


@app.post("/api/lan/claim")
def lan_claim():
    if not lan_authorized():
        return jsonify({"error": "LAN worker authentication failed"}), 401
    payload = request.get_json(force=True)
    name = re.sub(r"[^0-9A-Za-z_.-]", "-", str(payload.get("name") or "worker"))[:80]
    telemetry = payload.get("telemetry") or {}
    if telemetry:
        telemetry["sampled_at"] = now()
    with db() as connection:
        if telemetry:
            connection.execute(
                """UPDATE lan_workers SET status=CASE WHEN status='offline' THEN 'idle' ELSE status END,
                   telemetry_json=?,last_seen=? WHERE name=?""",
                (json.dumps(telemetry), now(), name),
            )
        else:
            connection.execute(
                "UPDATE lan_workers SET status=CASE WHEN status='offline' THEN 'idle' ELSE status END,last_seen=? WHERE name=?",
                (now(), name),
            )
    if load_config().get("queue_paused"):
        return jsonify({"job": None, "paused": True})
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        worker = connection.execute(
            "SELECT paused,workload,cpu_profile,current_job_id FROM lan_workers WHERE name=?",
            (name,),
        ).fetchone()
        if not worker:
            return jsonify({"error": "Worker must register before claiming jobs"}), 409
        if worker["paused"]:
            return jsonify({"job": None, "paused": True, "scope": "worker"})
        if worker["current_job_id"]:
            active = connection.execute(
                "SELECT id FROM jobs WHERE id=? AND worker_name=? AND status IN ('lan_preparing','lan_running','lan_paused')",
                (worker["current_job_id"], name),
            ).fetchone()
            if active:
                return jsonify({"job": None, "busy": True, "current_job_id": active["id"]})
            connection.execute("UPDATE lan_workers SET current_job_id=NULL,status='idle' WHERE name=?", (name,))
        row = connection.execute(
            """SELECT j.*,c.hash_path,c.filename AS capture_name,s.name AS strategy_name,s.mode,s.config_json
               FROM jobs j JOIN captures c ON c.id=j.capture_id JOIN strategies s ON s.id=j.strategy_id
               WHERE j.status='queued' ORDER BY j.position,j.id LIMIT 1"""
        ).fetchone()
        if not row:
            connection.execute("UPDATE lan_workers SET status='idle',current_job_id=NULL,last_seen=? WHERE name=?", (now(), name))
            return jsonify({"job": None})
        job = dict(row)
        started = now()
        changed = connection.execute(
            "UPDATE jobs SET status='lan_preparing',worker_name=?,started_at=COALESCE(started_at,?),active_started_at=NULL,error='' WHERE id=? AND status='queued'",
            (name, started, job["id"]),
        ).rowcount
        if not changed:
            return jsonify({"job": None})
        connection.execute(
            "UPDATE lan_workers SET status='running',current_job_id=?,last_seen=? WHERE name=?",
            (job["id"], now(), name),
        )
    try:
        runtime_hash, capture_lookup, _ = prepare_job_hashes(job)
        if not runtime_hash:
            with db() as connection:
                stop_job_clock(connection, int(job["id"]))
                connection.execute("UPDATE jobs SET status='complete',progress=100,error='Skipped: recovered or method already tested',finished_at=? WHERE id=?", (now(), job["id"]))
            return jsonify({"job": None})
        cfg = json.loads(job.get("config_json") or "{}")
        with db() as connection:
            sources = {key: lan_source(connection, cfg.get(key)) for key in ("wordlist_id", "rule_id") if cfg.get(key)}
            if any(source is None for source in sources.values()):
                raise RuntimeError("A source referenced by this job is missing on the coordinator")
            connection.execute("UPDATE jobs SET status='lan_running',log_path=?,command_json=? WHERE id=?",
                               (str(ROOT / "logs" / f"job-{job['id']}-lan.log"), json.dumps(["LAN worker", name]), job["id"]))
            connection.execute("UPDATE lan_workers SET status='running',current_job_id=?,last_seen=? WHERE name=?", (job["id"], now(), name))
        candidate_text = ""
        if job["mode"] == "common":
            candidate_text = common_candidate_wordlist(runtime_hash, int(job["id"])).read_text(encoding="utf-8")
        elif job["mode"] == "pattern":
            candidate_text = pattern_candidate_wordlist(runtime_hash, int(job["id"])).read_text(encoding="utf-8")
        return jsonify({"job": {"id": job["id"], "mode": job["mode"], "strategy": job["strategy_name"],
            "session": job["session_name"], "workload": int(worker["workload"] or 3), "config": cfg,
            "cpu_profile": str(worker["cpu_profile"] or "off"),
            "hash_text": runtime_hash.read_text(encoding="utf-8"), "candidate_text": candidate_text,
            "sources": sources, "temperature_abort": load_config().get("temperature_abort", 90)}})
    except Exception as exc:
        with db() as connection:
            stop_job_clock(connection, int(job["id"]))
            connection.execute("UPDATE jobs SET status='blocked',error=?,finished_at=? WHERE id=?", (str(exc), now(), job["id"]))
            connection.execute("UPDATE lan_workers SET status='idle',current_job_id=NULL WHERE name=? AND current_job_id=?", (name, job["id"]))
        return jsonify({"error": str(exc)}), 409


@app.post("/api/lan/jobs/<int:job_id>/progress")
def lan_progress(job_id: int):
    if not lan_authorized():
        return jsonify({"error": "LAN worker authentication failed"}), 401
    payload = request.get_json(force=True)
    name = str(payload.get("name") or "")[:80]
    telemetry = payload.get("telemetry") or {}
    telemetry["speed_hps"] = float(payload.get("speed_hps") or 0)
    telemetry["sampled_at"] = now()
    telemetry["job_id"] = job_id
    with db() as connection:
        row = connection.execute("SELECT remote_command,status,active_started_at FROM jobs WHERE id=? AND worker_name=?", (job_id, name)).fetchone()
        if not row:
            return jsonify({"command": "cancel"}), 404
        if row["status"] not in {"lan_preparing", "lan_running", "lan_paused"}:
            return jsonify({"command": "cancel", "reason": "job is no longer active"})
        if row["status"] != "lan_paused" and not row["active_started_at"]:
            start_job_clock(connection, job_id)
        connection.execute("""UPDATE jobs SET progress=?,speed=?,speed_hps=?,eta=?,recovered=?,candidates_done=?,candidates_total=? WHERE id=?""",
            (float(payload.get("progress") or 0), str(payload.get("speed") or "")[:80], float(payload.get("speed_hps") or 0),
             str(payload.get("eta") or "")[:100], int(payload.get("recovered") or 0), int(payload.get("candidates_done") or 0),
             int(payload.get("candidates_total") or 0), job_id))
        worker = connection.execute("SELECT paused,workload FROM lan_workers WHERE name=?", (name,)).fetchone()
        connection.execute("UPDATE lan_workers SET status='running',current_job_id=?,telemetry_json=?,last_seen=? WHERE name=?",
                           (job_id, json.dumps(telemetry), now(), name))
    command = row["remote_command"] or ("pause" if load_config().get("queue_paused") else "")
    if worker and worker["paused"]:
        command = "pause"
    return jsonify({"command": command, "workload": int(worker["workload"] or 3) if worker else 3})


@app.post("/api/lan/jobs/<int:job_id>/complete")
def lan_complete(job_id: int):
    if not lan_authorized():
        return jsonify({"error": "LAN worker authentication failed"}), 401
    payload = request.get_json(force=True)
    name = str(payload.get("name") or "")[:80]
    with db() as connection:
        row = connection.execute("""SELECT j.*,c.hash_path,s.name AS strategy_name,s.mode,s.config_json
            FROM jobs j JOIN captures c ON c.id=j.capture_id JOIN strategies s ON s.id=j.strategy_id
            WHERE j.id=? AND j.worker_name=?""", (job_id, name)).fetchone()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    job = dict(row)
    if job["status"] not in {"lan_preparing", "lan_running", "lan_paused"}:
        return jsonify({"ok": True, "ignored": True, "reason": "Job is no longer active"})
    runtime_hash, capture_lookup, _ = prepare_job_hashes(job)
    outfile = DATA / f"job-{job_id}-lan-found.txt"
    outfile.write_text(str(payload.get("outfile") or ""), encoding="utf-8")
    log_path = ROOT / "logs" / f"job-{job_id}-lan.log"
    log_path.write_text(str(payload.get("log") or "")[-200000:], encoding="utf-8")
    imported, recovered = import_outfile(outfile, job["capture_id"], job["strategy_name"], runtime_hash, capture_lookup, job_id)
    code = int(payload.get("exit_code", 1))
    with db() as connection:
        control = connection.execute("SELECT remote_command FROM jobs WHERE id=?", (job_id,)).fetchone()
        status = "cancelled" if control and control[0] == "cancel" else "complete" if code in (0, 1) else "failed"
        stop_job_clock(connection, job_id)
        if status == "complete" and job["mode"] != "known":
            insert_network_attempts(connection, job, parse_22000(runtime_hash), recovered)
        connection.execute("UPDATE jobs SET status=?,progress=CASE WHEN ?='complete' THEN 100 ELSE progress END,recovered=?,error=?,finished_at=?,remote_command='' WHERE id=?",
                           (status, status, len(recovered), "" if status == "complete" else f"Remote Hashcat exited with code {code}", now(), job_id))
        connection.execute("UPDATE lan_workers SET status='idle',current_job_id=NULL,last_seen=? WHERE name=? AND current_job_id=?", (now(), name, job_id))
    skip_fully_recovered_jobs()
    return jsonify({"ok": True, "imported": imported})


@app.patch("/api/lan/workers/<worker_name>")
def configure_lan_worker(worker_name: str):
    name = re.sub(r"[^0-9A-Za-z_.-]", "-", worker_name)[:80]
    payload = request.get_json(force=True) or {}
    with db() as connection:
        worker = connection.execute("SELECT * FROM lan_workers WHERE name=?", (name,)).fetchone()
        if not worker:
            return jsonify({"error": "LAN worker not found"}), 404
        updates: list[str] = []
        values: list[object] = []
        if "paused" in payload:
            paused = 1 if payload.get("paused") else 0
            updates.append("paused=?"); values.append(paused)
            if worker["current_job_id"]:
                if paused:
                    stop_job_clock(connection, int(worker["current_job_id"]))
                connection.execute(
                    "UPDATE jobs SET status=?,remote_command=? WHERE id=? AND worker_name=? AND status IN ('lan_running','lan_paused')",
                    ("lan_paused" if paused else "lan_running", "pause" if paused else "resume", worker["current_job_id"], name),
                )
        if "workload" in payload:
            workload = max(1, min(int(payload.get("workload") or 3), 4))
            updates.append("workload=?"); values.append(workload)
        if "cpu_profile" in payload:
            profile = str(payload.get("cpu_profile") or "off")
            if profile not in {"off", "low", "balanced", "high"}:
                return jsonify({"error": "Unsupported CPU profile"}), 400
            updates.append("cpu_profile=?"); values.append(profile)
        if updates:
            connection.execute(f"UPDATE lan_workers SET {','.join(updates)} WHERE name=?", (*values, name))
        updated = row_dict(connection.execute("SELECT * FROM lan_workers WHERE name=?", (name,)).fetchone())
    add_event("info", f"LAN worker {name} settings updated")
    return jsonify({"ok": True, "worker": updated,
                    "gpu_profile_live": bool(worker["current_job_id"] and "workload" in payload),
                    "cpu_profile_applies_next_job": bool(worker["current_job_id"] and "cpu_profile" in payload)})


@app.post("/api/system/shutdown")
def shutdown_background_server():
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        return jsonify({"error": "Shutdown is only available from this computer"}), 403

    def worker():
        (DATA / "service.stop").write_text(now(), encoding="ascii")
        runner.graceful_shutdown()
        (DATA / "server.pid").unlink(missing_ok=True)
        time.sleep(0.5)
        os._exit(0)

    threading.Thread(target=worker, name="graceful-shutdown", daemon=True).start()
    return jsonify({"ok": True, "message": "Checkpointing active work and stopping in the background"}), 202


@app.get("/health")
def health():
    return jsonify({"ok": True, "time": now()})


def main() -> None:
    (DATA / "server.pid").write_text(str(os.getpid()), encoding="ascii")
    atexit.register(lambda: (DATA / "server.pid").unlink(missing_ok=True))
    runner.start()
    config = load_config()
    start_self_signed_https(config)
    telegram_thread = threading.Thread(target=telegram_file_intake_loop, name="telegram-file-intake", daemon=True)
    telegram_thread.start()
    atexit.register(TELEGRAM_INTAKE_STOP.set)
    try:
        from waitress import serve
        serve(app, host=config["host"], port=int(config["port"]), threads=8)
    except ImportError:
        app.run(host=config["host"], port=int(config["port"]), threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
