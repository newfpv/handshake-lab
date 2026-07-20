$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$config = Get-Content -LiteralPath (Join-Path $root "config.json") -Raw | ConvertFrom-Json
$browserHost = if ($config.host -and $config.host -notin @("0.0.0.0", "::")) { $config.host } else { "127.0.0.1" }
$url = "http://${browserHost}:$($config.port)"

try {
    Invoke-RestMethod -Uri "$url/api/system/shutdown" -Method Post -TimeoutSec 5 | Out-Null
    Write-Host "Checkpoint requested. Handshake Lab will stop safely in the background."
}
catch {
    Write-Host "Handshake Lab is not running."
}
