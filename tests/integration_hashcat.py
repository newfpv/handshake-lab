import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HASHCAT = ROOT / "tools" / "hashcat-official" / "hashcat-7.1.2" / "hashcat.exe"
EXAMPLE_HASH = "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"


def main():
    if not HASHCAT.exists():
        raise SystemExit("Hashcat is not installed")
    with tempfile.TemporaryDirectory() as folder:
        temp = Path(folder)
        hash_file = temp / "example.22000"
        words = temp / "words.txt"
        output = temp / "found.txt"
        hash_file.write_text(EXAMPLE_HASH + "\n", encoding="utf-8")
        words.write_text("not-the-key\nhashcat!\n", encoding="utf-8")
        command = [
            str(HASHCAT), "-m", "22000", str(hash_file),
            "--potfile-disable", "--outfile", str(output),
            "--outfile-format", "1,2", "--separator", "|",
            "-a", "0", str(words),
        ]
        process = subprocess.run(command, cwd=HASHCAT.parent, capture_output=True, text=True, timeout=90)
        if process.returncode not in (0, 1):
            raise SystemExit(process.stdout + process.stderr)
        recovered = output.read_text(encoding="utf-8", errors="replace")
        if not recovered.rstrip().endswith("|hashcat!"):
            raise SystemExit(f"Unexpected output: {recovered!r}")

        status_command = [
            str(HASHCAT), "-m", "22000", str(hash_file), "-a", "3", "?d?d?d?d?d?d?d?d",
            "--potfile-disable", "--restore-disable", "--runtime", "4",
            "--status", "--status-json", "--status-timer", "1", "--workload-profile", "4",
            "--optimized-kernel-enable",
        ]
        probe = subprocess.run(status_command, cwd=HASHCAT.parent, capture_output=True, text=True, timeout=120)
        samples = []
        for line in probe.stdout.splitlines():
            marker = line.find("{")
            if marker >= 0:
                payload = json.loads(line[marker:])
                if "session" in payload:
                    samples.append(payload)
        if not samples or not samples[-1].get("devices"):
            raise SystemExit(f"Hashcat status JSON was not emitted:\n{probe.stdout}\n{probe.stderr}")
        rate = sum(float(device.get("speed") or 0) for device in samples[-1]["devices"])
        if rate <= 0:
            raise SystemExit(f"Invalid measured rate: {rate}")
        print(f"Hashcat integration: OK (mode 22000, status JSON, RTX rate {rate:,.0f} H/s)")


if __name__ == "__main__":
    main()
