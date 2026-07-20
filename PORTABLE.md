# Portable Windows package

## First launch

1. Extract the archive to a writable local folder.
2. Double-click `start.bat`.
3. Keep the internet connection available during the first launch.
4. The bootstrap checks Python, Python packages, Hashcat, and the optional capture converter.
5. Missing Python is installed locally under `tools/python` without administrator rights.
6. Missing Python packages are installed from `requirements.txt`.
7. Missing Hashcat 7.1.2 is downloaded from `hashcat.net`, verified by SHA-256, and extracted locally.
8. After every required executable passes validation, downloaded installers, archives, partial downloads, legacy extraction folders, and converter build sources are removed automatically.
9. The local web interface opens after its health check succeeds.

Later launches perform a fast integrity check, reuse everything already installed, clean any recognized installation residue, and do not download it again. Cleanup is intentionally restricted to the application's own `tools` directory; personal Downloads and external source folders are never touched.

## GPU requirement

The target computer still needs a compatible GPU driver. The bootstrap does not silently install or replace display drivers. For NVIDIA, install a current official driver before starting a GPU job.

## Moving an existing workspace

Run `stop.bat` before copying an active workspace. This gives Hashcat time to checkpoint and closes SQLite cleanly.

The application detects that its root folder changed and rewrites workspace-local database paths. Restore files from a different absolute path are discarded safely, so an interrupted active job may restart from the beginning after moving to another drive. Recovered results remain intact.

The workspace package intentionally excludes multi-gigabyte dictionaries. Copy the `wordlists` folder separately beside the extracted application, then press **Sources → Scan local folder**.

## Creating packages

Clean portable application:

```powershell
.\build-portable.ps1
```

Application plus captures, hashes, queue database, results, and sessions:

```powershell
.\stop.bat
.\build-portable.ps1 -IncludeWorkspace
```

The resulting ZIP is written to `dist`.
