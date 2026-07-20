$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Runtime = Get-Content -LiteralPath (Join-Path $Root "data\runtime.json") -Raw | ConvertFrom-Json

& $Runtime.python -m py_compile (Join-Path $Root "app.py") (Join-Path $Root "lan-worker.py")
if ($LASTEXITCODE -ne 0) { throw "Python syntax check failed." }
& $Runtime.python -m unittest discover -s (Join-Path $Root "tests") -p "test_*.py"
if ($LASTEXITCODE -ne 0) { throw "Test suite failed." }
& (Join-Path $Root "build-portable.ps1")

$Archive = Join-Path $Root "dist\NewFPV-Handshake-Lab-portable.zip"
$Hash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
$Checksum = "$Hash  NewFPV-Handshake-Lab-portable.zip`n"
[IO.File]::WriteAllText((Join-Path $Root "dist\NewFPV-Handshake-Lab-portable.zip.sha256"), $Checksum, [Text.UTF8Encoding]::new($false))
Write-Host "Release package and SHA-256 checksum are ready in dist." -ForegroundColor Green
