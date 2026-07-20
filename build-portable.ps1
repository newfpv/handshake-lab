param(
    [switch]$IncludeWorkspace
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dist = Join-Path $Root "dist"
$Name = if ($IncludeWorkspace) { "NewFPV-Handshake-Lab-workspace" } else { "NewFPV-Handshake-Lab-portable" }
$Stage = Join-Path $Dist $Name
$Archive = Join-Path $Dist "$Name.zip"

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
$ResolvedDist = [IO.Path]::GetFullPath($Dist).TrimEnd('\') + '\'
$ResolvedStage = [IO.Path]::GetFullPath($Stage)
if (-not $ResolvedStage.StartsWith($ResolvedDist, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsafe staging path: $ResolvedStage"
}

if ($IncludeWorkspace) {
    $Config = Get-Content -LiteralPath (Join-Path $Root "config.json") -Raw | ConvertFrom-Json
    $HostName = if ($Config.host -and $Config.host -notin @("0.0.0.0", "::")) { $Config.host } else { "127.0.0.1" }
    try {
        $Health = Invoke-RestMethod -Uri "http://${HostName}:$($Config.port)/health" -TimeoutSec 2
        if ($Health.ok) { throw "Run stop.bat before building a workspace snapshot so SQLite and Hashcat checkpoints are consistent." }
    }
    catch {
        if ($_.Exception.Message -like "Run stop.bat*") { throw }
    }
}

if (Test-Path -LiteralPath $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force }
if (Test-Path -LiteralPath $Archive) { Remove-Item -LiteralPath $Archive -Force }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

$Files = @(
    "app.py", "bootstrap.ps1", "launch-background.ps1", "service-host.ps1", "start.ps1", "start.bat",
    "stop-background.ps1", "stop.bat", "install-tools.ps1", "requirements.txt",
    "README.md", "PORTABLE.md", "LICENSE", "VERSION", "CHANGELOG.md", "SECURITY.md", "config.example.json",
    "build-portable.ps1", "install.ps1", "lan-worker.py",
    "lan-worker.example.json", "start-worker.ps1", "start-worker.bat"
)
foreach ($File in $Files) {
    Copy-Item -LiteralPath (Join-Path $Root $File) -Destination (Join-Path $Stage $File)
}
foreach ($Folder in @("static", "templates", "masks", "docs")) {
    Copy-Item -LiteralPath (Join-Path $Root $Folder) -Destination (Join-Path $Stage $Folder) -Recurse
}
foreach ($Folder in @("captures", "hashes", "wordlists", "rules", "logs", "sessions", "data", "tools")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $Stage $Folder) | Out-Null
}

$BootstrapTools = Join-Path $Stage "tools\bootstrap"
New-Item -ItemType Directory -Force -Path $BootstrapTools | Out-Null
foreach ($File in @("7zr.exe", "7zip-license.txt")) {
    $Source = Join-Path $Root "tools\bootstrap\$File"
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Missing portable bootstrap asset: $Source"
    }
    Copy-Item -LiteralPath $Source -Destination (Join-Path $BootstrapTools $File)
}

$HcxSource = Join-Path $Root "tools\hcxtools"
if (-not (Test-Path -LiteralPath (Join-Path $HcxSource "hcxpcapngtool.exe"))) {
    $HcxSource = Join-Path $Root "tools\hcxtools-source\hcxtools-7.1.2"
}
$HcxTarget = Join-Path $Stage "tools\hcxtools"
if (Test-Path -LiteralPath (Join-Path $HcxSource "hcxpcapngtool.exe")) {
    New-Item -ItemType Directory -Force -Path $HcxTarget | Out-Null
    foreach ($File in @("hcxpcapngtool.exe", "libcrypto-3-x64.dll", "zlib1.dll", "license.txt")) {
        Copy-Item -LiteralPath (Join-Path $HcxSource $File) -Destination (Join-Path $HcxTarget $File)
    }
}

if ($IncludeWorkspace) {
    foreach ($Folder in @("captures", "hashes", "data", "sessions", "rules")) {
        $Source = Join-Path $Root $Folder
        $Target = Join-Path $Stage $Folder
        if (Test-Path -LiteralPath $Source) { Copy-Item -Path (Join-Path $Source "*") -Destination $Target -Recurse -Force }
    }
    Remove-Item -LiteralPath (Join-Path $Stage "data\runtime.json") -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $Stage "data\server.pid") -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath (Join-Path $Root "config.json") -Destination (Join-Path $Stage "config.json") -Force
}
else {
    $Config = [ordered]@{
        host = "127.0.0.1"; port = 8787; hashcat_path = ""; hcxpcapngtool_path = ""
        max_workers = 1; workload_profile = 3; cpu_profile = "off"; temperature_abort = 90
        restore_interrupted_jobs = $true; queue_paused = $false; theme_accent = "cyan"
        lan_enabled = $false; lan_token = ""; lan_job_timeout = 180
    }
    $Json = $Config | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $Stage "config.json"), $Json, [Text.UTF8Encoding]::new($false))
}

Compress-Archive -LiteralPath $Stage -DestinationPath $Archive -CompressionLevel Optimal
Remove-Item -LiteralPath $Stage -Recurse -Force
$Size = [math]::Round((Get-Item -LiteralPath $Archive).Length / 1MB, 1)
Write-Host "Portable archive ready: $Archive ($Size MB)" -ForegroundColor Green
if ($IncludeWorkspace) {
    Write-Host "Large wordlists are intentionally separate. Copy the wordlists folder next to the extracted app." -ForegroundColor Yellow
}
