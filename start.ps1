# One command for a phone check, from PowerShell: setup on the first run, then the agent.
$Dir = $PSScriptRoot
$python = "$Dir\.venv\Scripts\python.exe"
$pre = @()
if (-not (Test-Path $python)) {
    # First run: no virtualenv yet. ./start runs install.ps1, which creates it.
    if (Get-Command py -ErrorAction SilentlyContinue) { $python = "py"; $pre = @("-3") }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { $python = "python" }
    else { Write-Error "Python 3.12 is missing. Install it (winget install Python.Python.3.12), then run .\start.ps1 again."; exit 2 }
}
& $python @pre -c "import sys; sys.exit(sys.version_info < (3, 11))"
if ($LASTEXITCODE -ne 0) {
    Write-Error "./start needs Python 3.11 or newer. Install it (winget install Python.Python.3.12), then run .\start.ps1 again."
    exit 2
}
$env:PYTHONPATH = "$Dir\src"
$env:PYTHONUTF8 = "1"
& $python @pre -m sta.setup @args
exit $LASTEXITCODE
