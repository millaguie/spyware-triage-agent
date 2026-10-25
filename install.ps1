# Install everything a phone check needs, on Windows (PowerShell 5.1 or 7):
#   - winget packages: Python 3.12, Git (Git Bash runs ./sta and ./agent.sh), adb, age
#   - mvt and pymobiledevice3 (with pipx)
#   - androidqf (fixed version, checked against the SHA-256 written below)
#   - a small virtualenv for the sta scripts (requirements.txt)
#
# Usage: .\install.ps1              install or upgrade
#        .\install.ps1 -Check       only report what is missing
#        .\install.ps1 -NoSystem    skip winget
#
# If PowerShell refuses to run scripts:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
param([switch]$Check, [switch]$NoSystem)
$ErrorActionPreference = "Stop"
$Dir = $PSScriptRoot
$Bin = Join-Path $HOME ".local\bin"

if ($Check) { & "$Dir\sta.ps1" doctor; exit $LASTEXITCODE }

function Say($text) { Write-Host "`n==> $text" }

# Programs winget just installed are not on this window's PATH yet.
function Update-Path {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path", "User") + ";$Bin"
}

function Install-System {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warning "winget is missing. Install by hand: Python 3.12, Git, Android platform-tools (adb), age."
        return
    }
    Say "Installing winget packages"
    foreach ($id in "Python.Python.3.12", "Git.Git", "Google.PlatformTools", "FiloSottile.age") {
        winget install --exact --id $id --silent --accept-package-agreements --accept-source-agreements
        # 0 = installed; -1978335189 = already installed, no newer version.
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) {
            Write-Warning "winget could not install $id (exit $LASTEXITCODE)."
        }
    }
    Update-Path
}

function Find-Python {
    # The py launcher comes with python.org Python; "python" may be the Microsoft Store stub.
    if (Get-Command py -ErrorAction SilentlyContinue) { return "py", "-3.12" }
    if (Get-Command python -ErrorAction SilentlyContinue) { return "python", $null }
    throw "Python 3.12 is missing. Install it (winget install Python.Python.3.12), then run this again."
}

function Invoke-Python {
    if ($script:PyVersion) { & $script:PyExe $script:PyVersion @args } else { & $script:PyExe @args }
}

function Install-PipxTool($name, $spec) {
    if (-not $spec) { $spec = $name }
    Say "Installing $name"
    Invoke-Python -m pipx install --force $spec
    if ($LASTEXITCODE -ne 0) { Write-Warning "$name did not install." }
}

# Same version as install.sh and docker/Dockerfile. The SHA-256 is written
# here, not read from the release, so a changed file on GitHub cannot get installed.
$AndroidqfVersion = "1.8.3"
$AndroidqfAsset = "androidqf_windows_amd64_${AndroidqfVersion}_unsigned.exe"
$AndroidqfSha256 = "2a5aa89b8aa2145d1246372ef3310ffd1e6d8a457c59b0a232c3de79892d4650"

function Install-Androidqf {
    if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
        Write-Warning "androidqf has no Windows build for $env:PROCESSOR_ARCHITECTURE. Android checks will not work."
        return
    }
    Say "Installing androidqf $AndroidqfVersion"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $AndroidqfAsset
    $url = "https://github.com/mvt-project/androidqf/releases/download/v$AndroidqfVersion/$AndroidqfAsset"
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    $sum = (Get-FileHash -Algorithm SHA256 $tmp).Hash.ToLower()
    if ($sum -ne $AndroidqfSha256) {
        Remove-Item $tmp
        throw "androidqf checksum does not match. Not installing."
    }
    New-Item -ItemType Directory -Force $Bin | Out-Null
    Move-Item -Force $tmp (Join-Path $Bin "androidqf.exe")
    Write-Host "androidqf $AndroidqfVersion installed in $Bin\androidqf.exe"
}

# EC-DIGIT-CSIRC's sysdiagnose analysis framework. Same commit as install.sh.
# Optional: without it the check reads only shutdown.log from a sysdiagnose.
$SafCommit = "2962575f0e114093f3d7da3cad20f8bc99f94cb6"

function Install-Venv {
    Say "Creating $Dir\.venv for the sta scripts"
    Invoke-Python -m venv "$Dir\.venv"
    if ($LASTEXITCODE -ne 0) { throw "Python could not create $Dir\.venv." }
    $venvPy = "$Dir\.venv\Scripts\python.exe"
    & $venvPy -m pip install --quiet --upgrade pip
    # Pinned versions from requirements.txt (apkid brings yara, pywinpty the
    # terminal androidqf's menus need), then the sta package itself, editable.
    & $venvPy -m pip install --quiet -r "$Dir\requirements.txt"
    if ($LASTEXITCODE -ne 0) { throw "pip could not install requirements.txt." }
    & $venvPy -m pip install --quiet --no-deps -e "$Dir"
    if ($LASTEXITCODE -ne 0) { throw "pip could not install the sta package." }
}

if (-not $NoSystem) { Install-System }
$PyExe, $PyVersion = Find-Python
Say "Installing pipx"
Invoke-Python -m pip install --user --quiet --upgrade pipx
if ($LASTEXITCODE -ne 0) { throw "pip could not install pipx." }
Invoke-Python -m pipx ensurepath | Out-Null
Update-Path
Install-PipxTool "mvt"
Install-PipxTool "pymobiledevice3"
Install-Androidqf
if (Get-Command git -ErrorAction SilentlyContinue) {
    Install-PipxTool "saf" "git+https://github.com/EC-DIGIT-CSIRC/sysdiagnose@$SafCommit"
} else {
    Write-Warning "git is missing: saf not installed. The check still reads shutdown.log."
}
Install-Venv
# ./sta and ./start read the mode the last installation set up.
New-Item -ItemType Directory -Force "$Dir\.sta" | Out-Null
Set-Content -NoNewline -Encoding ascii "$Dir\.sta\runtime" "local"

Say "Checking"
& "$Dir\sta.ps1" doctor
Write-Host ""
Write-Host "Done. Open a new terminal so the PATH changes apply."
Write-Host "Android: a Pixel needs the Google USB driver: https://developer.android.com/studio/run/win-usb"
Write-Host "iPhone: install Apple Devices from the Microsoft Store (it brings the USB driver and service)."
Write-Host "Start a check with: .\start.ps1  (or ./start in Git Bash)"
