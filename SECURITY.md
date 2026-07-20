# Security

NewFPV Handshake Lab is intended only for networks you own or have explicit written authorization to audit.

The default web server listens on `127.0.0.1`. Keep it that way unless you intentionally configure a trusted private-LAN worker. Never expose port `8787` to the public internet. Treat `config.json`, `lan-worker.json`, backups, captures, recovered CSV files and potfiles as sensitive.

Do not publish captures, passwords, LAN tokens or process logs in a public issue. For a security defect, open a private GitHub security advisory in this repository and include the affected version, reproduction steps and a redacted log.
