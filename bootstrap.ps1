$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Tools = Join-Path $Root "tools"
$Cache = Join-Path $Tools "cache"
$Data = Join-Path $Root "data"
$RuntimePath = Join-Path $Data "runtime.json"
$ConfigPath = Join-Path $Root "config.json"
$Requirements = Join-Path $Root "requirements.txt"
$PythonVersion = "3.12.10"
$PythonHome = Join-Path $Tools "python"
$PythonInstaller = Join-Path $Cache "python-$PythonVersion-amd64.exe"
$PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
$HashcatVersion = "7.1.2"
$HashcatSha256 = "80DB0316387794CE9D14ED376DA75B8A7742972485B45DB790F5F8260307FF98"
$HashcatUrl = "https://hashcat.net/files/hashcat-$HashcatVersion.7z"
$HashcatArchive = Join-Path $Cache "hashcat-$HashcatVersion.7z"
$HashcatRoot = Join-Path $Tools "hashcat-official"
$HashcatExe = Join-Path $HashcatRoot "hashcat-$HashcatVersion\hashcat.exe"
$SevenZipSha256 = "56B8CC9F4971CEF253644FAFE54063ED7FDCA551D4DEE0F8C6BAA81B855ACD72"
$SevenZipUrl = "https://www.7-zip.org/a/7zr.exe"
$BundledSevenZip = Join-Path $Tools "bootstrap\7zr.exe"
$CachedSevenZip = Join-Path $Cache "7zr.exe"

New-Item -ItemType Directory -Force -Path $Tools, $Data | Out-Null

function Write-Step([string]$Message) {
    Write-Host "  -> $Message" -ForegroundColor Cyan
}

function Write-JsonAtomic([string]$Path, $Value) {
    $Temporary = "$Path.tmp"
    $Json = $Value | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($Temporary, $Json, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $Temporary -Destination $Path -Force
}

function Get-Download([string]$Url, [string]$Destination) {
    $DestinationFolder = Split-Path -Parent $Destination
    if ($DestinationFolder) { New-Item -ItemType Directory -Force -Path $DestinationFolder | Out-Null }
    $Partial = "$Destination.partial"
    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        try {
            Remove-Item -LiteralPath $Partial -Force -ErrorAction SilentlyContinue
            Invoke-WebRequest -Uri $Url -OutFile $Partial -UseBasicParsing -TimeoutSec 900
            Move-Item -LiteralPath $Partial -Destination $Destination -Force
            return
        }
        catch {
            Remove-Item -LiteralPath $Partial -Force -ErrorAction SilentlyContinue
            if ($Attempt -eq 3) { throw }
            Start-Sleep -Seconds (2 * $Attempt)
        }
    }
}

function Test-Python([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        & $Path -c "import sys, pip; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" 2>$null
        return $LASTEXITCODE -eq 0
    }
    catch { return $false }
}

function Find-Python {
    $Local = Join-Path $PythonHome "python.exe"
    if (Test-Python $Local) { return $Local }
    $Command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($Command -and (Test-Python $Command.Source)) { return $Command.Source }
    return $null
}

function Install-PortablePython {
    Write-Step "Downloading Python $PythonVersion from python.org"
    if (-not (Test-Path -LiteralPath $PythonInstaller)) {
        Get-Download $PythonUrl $PythonInstaller
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $PythonInstaller
    if ($Signature.Status -ne "Valid" -or $Signature.SignerCertificate.Subject -notmatch "Python Software Foundation") {
        Remove-Item -LiteralPath $PythonInstaller -Force -ErrorAction SilentlyContinue
        throw "The downloaded Python installer did not have a valid Python Software Foundation signature."
    }
    New-Item -ItemType Directory -Force -Path $PythonHome | Out-Null
    $Arguments = @(
        "/quiet", "InstallAllUsers=0", "TargetDir=`"$PythonHome`"", "Include_pip=1",
        "Include_launcher=0", "InstallLauncherAllUsers=0", "PrependPath=0",
        "AppendPath=0", "Include_test=0", "Include_doc=0", "Shortcuts=0"
    )
    $Process = Start-Process -FilePath $PythonInstaller -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    $Installed = Join-Path $PythonHome "python.exe"
    if ($Process.ExitCode -ne 0 -or -not (Test-Python $Installed)) {
        throw "Portable Python installation failed with exit code $($Process.ExitCode)."
    }
    return $Installed
}

function Ensure-PythonPackages([string]$Python) {
    $Ready = $false
    try {
        & $Python -c "import flask, waitress" 2>$null
        $Ready = $LASTEXITCODE -eq 0
    }
    catch { $Ready = $false }
    if ($Ready) { return }
    Write-Step "Installing local Python dependencies"
    $PreviousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $InstallOutput = & $Python -m pip install --disable-pip-version-check --no-cache-dir --prefer-binary --no-warn-script-location -r $Requirements 2>&1
    $InstallCode = $LASTEXITCODE
    $ErrorActionPreference = $PreviousPreference
    $InstallOutput | ForEach-Object { Write-Host $_ }
    if ($InstallCode -ne 0) { throw "Python dependency installation failed." }
    try {
        & $Python -c "import flask, waitress" 2>$null
        if ($LASTEXITCODE -ne 0) { throw "Import failed" }
    }
    catch { throw "Installed Python dependencies could not be imported." }
}

function Get-SevenZip {
    $Candidate = if (Test-Path -LiteralPath $BundledSevenZip -PathType Leaf) {
        $BundledSevenZip
    }
    else {
        if (-not (Test-Path -LiteralPath $CachedSevenZip -PathType Leaf)) {
            Write-Step "Downloading the official 7-Zip bootstrap extractor"
            Get-Download $SevenZipUrl $CachedSevenZip
        }
        $CachedSevenZip
    }
    $ActualHash = (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash
    if ($ActualHash -ne $SevenZipSha256) {
        if ($Candidate -eq $CachedSevenZip) {
            Remove-Item -LiteralPath $CachedSevenZip -Force -ErrorAction SilentlyContinue
        }
        throw "7-Zip bootstrap verification failed. Expected SHA-256 $SevenZipSha256, received $ActualHash."
    }
    return $Candidate
}

function Test-Hashcat([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $Folder = Split-Path -Parent $Path
    return (Test-Path -LiteralPath (Join-Path $Folder "modules")) -and (Test-Path -LiteralPath (Join-Path $Folder "OpenCL"))
}

function Ensure-Hashcat {
    if (Test-Hashcat $HashcatExe) { return $HashcatExe }
    $LegacyArchive = Join-Path $Tools "hashcat-$HashcatVersion.7z"
    if (-not (Test-Path -LiteralPath $HashcatArchive) -and (Test-Path -LiteralPath $LegacyArchive)) {
        New-Item -ItemType Directory -Force -Path $Cache | Out-Null
        Copy-Item -LiteralPath $LegacyArchive -Destination $HashcatArchive
    }
    if (-not (Test-Path -LiteralPath $HashcatArchive)) {
        Write-Step "Downloading official Hashcat $HashcatVersion"
        Get-Download $HashcatUrl $HashcatArchive
    }
    $ActualHash = (Get-FileHash -LiteralPath $HashcatArchive -Algorithm SHA256).Hash
    if ($ActualHash -ne $HashcatSha256) {
        Remove-Item -LiteralPath $HashcatArchive -Force -ErrorAction SilentlyContinue
        throw "Hashcat archive verification failed. Expected SHA-256 $HashcatSha256, received $ActualHash."
    }
    Write-Step "Extracting Hashcat $HashcatVersion"
    New-Item -ItemType Directory -Force -Path $HashcatRoot | Out-Null
    $HashcatFolder = Join-Path $HashcatRoot "hashcat-$HashcatVersion"
    $ResolvedRoot = [IO.Path]::GetFullPath($HashcatRoot).TrimEnd('\') + '\'
    $ResolvedFolder = [IO.Path]::GetFullPath($HashcatFolder)
    if (-not $ResolvedFolder.StartsWith($ResolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe Hashcat extraction path: $ResolvedFolder"
    }
    if (Test-Path -LiteralPath $HashcatFolder) {
        Remove-Item -LiteralPath $HashcatFolder -Recurse -Force
    }
    $SevenZip = Get-SevenZip
    $PreviousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $ExtractOutput = & $SevenZip x $HashcatArchive "-o$HashcatRoot" -y 2>&1
    $ExtractCode = $LASTEXITCODE
    $ErrorActionPreference = $PreviousPreference
    $ExtractOutput | ForEach-Object { Write-Host $_ }
    if ($ExtractCode -ne 0 -or -not (Test-Hashcat $HashcatExe)) {
        throw "Hashcat extraction failed."
    }
    return $HashcatExe
}

function Find-HcxTool {
    $Candidates = @(
        (Join-Path $Tools "hcxtools\hcxpcapngtool.exe"),
        (Join-Path $Tools "hcxtools-source\hcxtools-7.1.2\hcxpcapngtool.exe")
    )
    foreach ($Candidate in $Candidates) {
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) { return $Candidate }
    }
    return ""
}

function Normalize-HcxTool {
    $PreferredFolder = Join-Path $Tools "hcxtools"
    $Preferred = Join-Path $PreferredFolder "hcxpcapngtool.exe"
    if (Test-Path -LiteralPath $Preferred -PathType Leaf) { return $Preferred }
    $LegacyFolder = Join-Path $Tools "hcxtools-source\hcxtools-7.1.2"
    $Legacy = Join-Path $LegacyFolder "hcxpcapngtool.exe"
    if (-not (Test-Path -LiteralPath $Legacy -PathType Leaf)) { return (Find-HcxTool) }
    Write-Step "Consolidating the capture converter runtime"
    New-Item -ItemType Directory -Force -Path $PreferredFolder | Out-Null
    foreach ($Name in @("hcxpcapngtool.exe", "libcrypto-3-x64.dll", "zlib1.dll", "license.txt")) {
        $Source = Join-Path $LegacyFolder $Name
        if (Test-Path -LiteralPath $Source -PathType Leaf) {
            Copy-Item -LiteralPath $Source -Destination (Join-Path $PreferredFolder $Name) -Force
        }
    }
    if (-not (Test-Path -LiteralPath $Preferred -PathType Leaf)) {
        throw "The capture converter runtime could not be consolidated."
    }
    return $Preferred
}

function Remove-InstallResidue([string]$HcxTool) {
    $ResolvedTools = [IO.Path]::GetFullPath($Tools).TrimEnd('\') + '\'
    $script:CleanupRemoved = 0
    function Remove-WorkspaceItem([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        $Resolved = [IO.Path]::GetFullPath($Path)
        if (-not $Resolved.StartsWith($ResolvedTools, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean a path outside the tools directory: $Resolved"
        }
        Remove-Item -LiteralPath $Resolved -Recurse -Force
        $script:CleanupRemoved++
    }

    if (Test-Python $Python) {
        Remove-WorkspaceItem $Cache
    }
    if (Test-Hashcat $Hashcat) {
        Remove-WorkspaceItem (Join-Path $Tools "hashcat-$HashcatVersion.7z")
        Remove-WorkspaceItem (Join-Path $Tools "hashcat-$HashcatVersion")
    }
    $PreferredHcx = Join-Path $Tools "hcxtools\hcxpcapngtool.exe"
    if ($HcxTool -and (Test-Path -LiteralPath $PreferredHcx -PathType Leaf)) {
        foreach ($Path in @(
            (Join-Path $Tools "hcxtools-7.1.2.zip"),
            (Join-Path $Tools "hcxtools-source"),
            (Join-Path $Tools "build-hcx.sh"),
            (Join-Path $Tools "hcxtools-win-compat.h")
        )) { Remove-WorkspaceItem $Path }
    }
    if (Test-Path -LiteralPath $BundledSevenZip -PathType Leaf) {
        Remove-WorkspaceItem (Join-Path $Tools "_py7zr")
    }
    return $script:CleanupRemoved
}

Write-Host ""
Write-Host "  NEWFPV // PORTABLE BOOTSTRAP" -ForegroundColor White
$Python = Find-Python
if (-not $Python) { $Python = Install-PortablePython }
Ensure-PythonPackages $Python
$Hashcat = Ensure-Hashcat
$HcxTool = Normalize-HcxTool
$Pythonw = Join-Path (Split-Path -Parent $Python) "pythonw.exe"
if (-not (Test-Path -LiteralPath $Pythonw)) { $Pythonw = $Python }

if (Test-Path -LiteralPath $ConfigPath) {
    $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
}
else {
    $Config = [pscustomobject]@{
        host = "127.0.0.1"; port = 8787; hashcat_path = ""; hcxpcapngtool_path = ""
        max_workers = 1; workload_profile = 3; temperature_abort = 90
        restore_interrupted_jobs = $true; queue_paused = $false; theme_accent = "cyan"
        workspace_root = $Root
    }
}
if (-not ($Config.PSObject.Properties.Name -contains "workspace_root")) {
    $Config | Add-Member -NotePropertyName workspace_root -NotePropertyValue $Root
}
$Config.hashcat_path = $Hashcat
$Config.hcxpcapngtool_path = $HcxTool
Write-JsonAtomic $ConfigPath $Config

$Runtime = [pscustomobject]@{
    python = $Python
    pythonw = $Pythonw
    hashcat = $Hashcat
    hcxpcapngtool = $HcxTool
    bootstrapped_at = [DateTime]::UtcNow.ToString("o")
}
Write-JsonAtomic $RuntimePath $Runtime
$RemovedResidue = Remove-InstallResidue $HcxTool
Write-Host "  OK Python: $Python" -ForegroundColor Green
Write-Host "  OK Hashcat: $Hashcat" -ForegroundColor Green
if ($HcxTool) {
    Write-Host "  OK Converter: $HcxTool" -ForegroundColor Green
}
else {
    Write-Host "  Optional converter is not bundled. Direct .22000 files still work." -ForegroundColor Yellow
}
if ($RemovedResidue -gt 0) {
    Write-Host "  OK Cleanup: removed $RemovedResidue installer/archive/build item(s)" -ForegroundColor Green
}
