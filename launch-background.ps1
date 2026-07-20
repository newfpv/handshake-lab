$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $root

$config = Get-Content -LiteralPath (Join-Path $root "config.json") -Raw | ConvertFrom-Json
$browserHost = if ($config.host -and $config.host -notin @("0.0.0.0", "::")) { $config.host } else { "127.0.0.1" }
$url = "http://${browserHost}:$($config.port)"

function Test-HandshakeLab {
    try {
        $response = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 2
        return $response.ok -eq $true
    }
    catch {
        return $false
    }
}

if (-not (Test-HandshakeLab)) {
    & (Join-Path $root "bootstrap.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Portable dependency bootstrap failed." }
    $runtime = Get-Content -LiteralPath (Join-Path $root "data\runtime.json") -Raw | ConvertFrom-Json
    $python = $runtime.python
    if (-not $python -or -not (Test-Path -LiteralPath $python)) { throw "The bootstrapped Python runtime was not found." }
    $stopPath = Join-Path $root "data\service.stop"
    Remove-Item -LiteralPath $stopPath -Force -ErrorAction SilentlyContinue
    $supervisorPath = Join-Path $root "data\supervisor.pid"
    $supervisorAlive = $false
    if (Test-Path -LiteralPath $supervisorPath) {
        try { $supervisorAlive = [bool](Get-Process -Id ([int](Get-Content -LiteralPath $supervisorPath -Raw)) -ErrorAction Stop) } catch { $supervisorAlive = $false }
    }
    if (-not $supervisorAlive) {
        Remove-Item -LiteralPath $supervisorPath -Force -ErrorAction SilentlyContinue
        $hostScript = Join-Path $root "service-host.ps1"
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$hostScript`"", "-Python", "`"$python`"") -WorkingDirectory $root -WindowStyle Hidden -PassThru
    }

    $ready = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        Start-Sleep -Milliseconds 500
        if (Test-HandshakeLab) { $ready = $true; break }
        if ($process -and $process.HasExited) { break }
    }
    if (-not $ready) { throw "Handshake Lab did not start. Run start.ps1 once to inspect the error." }
}

Start-Process $url
