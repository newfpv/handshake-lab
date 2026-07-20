$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $Root

& (Join-Path $Root "bootstrap.ps1")
if ($LASTEXITCODE -ne 0) { throw "Portable dependency bootstrap failed." }
$Runtime = Get-Content -LiteralPath (Join-Path $Root "data\runtime.json") -Raw | ConvertFrom-Json
$Python = $Runtime.python
if (-not $Python -or -not (Test-Path -LiteralPath $Python)) { throw "The bootstrapped Python runtime was not found." }

$Config = Get-Content -LiteralPath (Join-Path $Root "config.json") -Raw | ConvertFrom-Json
$DisplayHost = if ($Config.host -eq "0.0.0.0") { "127.0.0.1" } else { $Config.host }
Write-Host ""
Write-Host "  NEWFPV // HANDSHAKE LAB" -ForegroundColor Cyan
Write-Host "  http://${DisplayHost}:$($Config.port)" -ForegroundColor White
Write-Host "  Press Ctrl+C to stop the console." -ForegroundColor DarkGray
Write-Host ""

& $Python (Join-Path $Root "app.py")
