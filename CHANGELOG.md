# Changelog

All notable changes to NewFPV Handshake Lab are documented here.

## 1.2.3 — 2026-07-20

- Kept Save changes visible as a floating Settings action on desktop and above the mobile navigation dock.
- Fixed notification and Remote Web checkbox labels running into their descriptions.

## 1.2.2 — 2026-07-20

- Prevented the three-second dashboard refresh from overwriting unsaved Settings fields and checkboxes.
- Added an explicit highlighted Save changes state while configuration edits are pending.
- Kept invalid Remote Web and Telegram drafts visible so validation errors can be corrected without re-entering the form.

## 1.2.1 — 2026-07-20

- Added a registered native Windows notification identity with a compact Handshake Lab logo.
- Replaced the temporary tray balloon fallback with branded Windows Runtime toasts.
- Expanded the README for live profiles, benchmarking, notifications, Telegram intake and authenticated remote access.

## 1.2.0 — 2026-07-20

- Replaced checkpoint-based W1–W4 changes with immediate live GPU duty-cycle profiles that preserve the exact running process and position.
- Added an exclusive WPA 22000 benchmark with persisted on-screen results for meaningful same-system speed comparisons.
- Added a one-click test for every enabled notification channel.
- Added allowlisted Telegram document intake for captures, dictionaries and rule files up to 20 MB.
- Added opt-in authenticated public-IP web access, public-address detection and cross-origin write protection.
- Updated the built-in Wiki with remote-access, benchmark and Telegram intake guidance.

## 1.1.0 — 2026-07-20

- Added a streaming Wordlist Analyzer with exact duplicate counting, WPA length validation, progress and GPU-time estimates.
- Added one-click Error Doctor detection and safe repairs for tool paths, missing sources, CUDA fallback and VRAM failures.
- Added local Windows toast notifications and opt-in Telegram notifications for results, heat, worker errors and queue completion.
- Hidden every offline LAN runtime card, telemetry panel and status marker after its heartbeat expires.
- Forced the Overview GPU rate onto one line and removed year-long stale asset caching.
- Fixed workload changes requested near job completion incorrectly leaving a completed job Blocked.
- Added an OpenCL fallback switch for coordinator and portable LAN workers.

## 1.0.0 — 2026-07-20

- Added a persistent local Hashcat queue with checkpoints, pause, resume, retry, drag ordering and ETA.
- Added capture quality diagnostics, manual password verification and duplicate-import protection.
- Added reusable recovery pipelines, Pattern Builder, candidate-source ordering and cascading deduplication.
- Added per-network method memory so unchanged failed stages are not repeated.
- Added local and authenticated LAN workers with independent GPU/CPU profiles, pause controls and idle telemetry.
- Added NVIDIA load, temperature, VRAM, power, clock, fan and speed telemetry with a dual-axis history chart.
- Added automatic Python, Hashcat and hcxtools bootstrap with post-install cleanup.
- Added crash-safe SQLite/result writes, backups, restore support and OHC/PWMenu-compatible CSV exports.
- Added a responsive NewFPV interface and a comprehensive built-in Help & Wiki.
- Added a background service supervisor so unexpected web-service exits recover automatically.
