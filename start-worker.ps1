$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
& "$Root\bootstrap.ps1"
if ($LASTEXITCODE -ne 0) { throw "Portable dependency bootstrap failed." }
if (-not (Test-Path "$Root\lan-worker.json")) {
    Copy-Item "$Root\lan-worker.example.json" "$Root\lan-worker.json"
    Write-Host "Edit lan-worker.json, then run start-worker.bat again." -ForegroundColor Yellow
    Start-Process notepad.exe -ArgumentList "$Root\lan-worker.json"
    exit 1
}
$Runtime = Get-Content "$Root\data\runtime.json" -Raw | ConvertFrom-Json
if (-not (Test-Path -LiteralPath $Runtime.python)) { & "$Root\bootstrap.ps1"; $Runtime = Get-Content "$Root\data\runtime.json" -Raw | ConvertFrom-Json }
& $Runtime.python "$Root\lan-worker.py"
