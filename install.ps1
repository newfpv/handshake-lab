$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repository = "newfpv/handshake-lab"
$Asset = "NewFPV-Handshake-Lab-portable.zip"
$InstallDir = Join-Path $env:LOCALAPPDATA "NewFPV\HandshakeLab"
$Archive = Join-Path ([IO.Path]::GetTempPath()) ("newfpv-handshake-lab-" + [Guid]::NewGuid().ToString("N") + ".zip")
$Extract = [IO.Path]::ChangeExtension($Archive, $null)
$Download = "https://github.com/$Repository/releases/latest/download/$Asset"

try {
    Write-Host "Downloading NewFPV Handshake Lab..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $Download -OutFile $Archive -UseBasicParsing
    Expand-Archive -LiteralPath $Archive -DestinationPath $Extract -Force
    $Source = Get-ChildItem -LiteralPath $Extract -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "start.bat") } | Select-Object -First 1
    if (-not $Source) { throw "The release archive does not contain start.bat." }

    $StopScript = Join-Path $InstallDir "stop-background.ps1"
    if (Test-Path -LiteralPath $StopScript) {
        Write-Host "Checkpointing the existing installation..." -ForegroundColor Cyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $StopScript
        $ServerPid = Join-Path $InstallDir "data\server.pid"
        $Deadline = (Get-Date).AddMinutes(2)
        while ((Test-Path -LiteralPath $ServerPid) -and (Get-Date) -lt $Deadline) { Start-Sleep -Milliseconds 500 }
        if (Test-Path -LiteralPath $ServerPid) { throw "The existing service did not stop safely within two minutes. Run stop.bat and retry." }
    }

    $Saved = @{}
    foreach ($Name in @("config.json", "lan-worker.json")) {
        $Path = Join-Path $InstallDir $Name
        if (Test-Path -LiteralPath $Path) { $Saved[$Name] = [IO.File]::ReadAllBytes($Path) }
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Path (Join-Path $Source.FullName "*") -Destination $InstallDir -Recurse -Force
    foreach ($Name in $Saved.Keys) { [IO.File]::WriteAllBytes((Join-Path $InstallDir $Name), $Saved[$Name]) }

    Write-Host "Installed to $InstallDir" -ForegroundColor Green
    Start-Process -FilePath (Join-Path $InstallDir "start.bat") -WorkingDirectory $InstallDir
}
finally {
    Remove-Item -LiteralPath $Archive -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Extract -Recurse -Force -ErrorAction SilentlyContinue
}
