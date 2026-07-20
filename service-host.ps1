param([Parameter(Mandatory = $true)][string]$Python)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Data = Join-Path $Root "data"
$Logs = Join-Path $Root "logs"
$StopPath = Join-Path $Data "service.stop"
$SupervisorPid = Join-Path $Data "supervisor.pid"
$OutputLog = Join-Path $Logs "server-output.log"
$ErrorLog = Join-Path $Logs "server-error.log"
$LifecycleLog = Join-Path $Logs "service-host.log"

New-Item -ItemType Directory -Force -Path $Data, $Logs | Out-Null
[IO.File]::WriteAllText($SupervisorPid, [string]$PID, [Text.Encoding]::ASCII)

function Rotate-Log([string]$Path) {
    if ((Test-Path -LiteralPath $Path) -and (Get-Item -LiteralPath $Path).Length -gt 5MB) {
        $Previous = "$Path.previous"
        Remove-Item -LiteralPath $Previous -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $Path -Destination $Previous -Force
    }
}

try {
    while (-not (Test-Path -LiteralPath $StopPath)) {
        Rotate-Log $OutputLog
        Rotate-Log $ErrorLog
        Add-Content -LiteralPath $LifecycleLog -Value "$(Get-Date -Format o) starting app.py"
        & $Python -u (Join-Path $Root "app.py") 1>> $OutputLog 2>> $ErrorLog
        $ExitCode = $LASTEXITCODE
        if (Test-Path -LiteralPath $StopPath) { break }
        Add-Content -LiteralPath $LifecycleLog -Value "$(Get-Date -Format o) app.py exited unexpectedly with code $ExitCode; restarting in 2 seconds"
        Start-Sleep -Seconds 2
    }
}
finally {
    Remove-Item -LiteralPath $SupervisorPid -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StopPath -Force -ErrorAction SilentlyContinue
}
