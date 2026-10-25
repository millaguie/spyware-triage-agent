# Run the sta CLI from PowerShell on Windows, with the project's .venv.
# Git Bash uses ./sta. There is no container mode on Windows.
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "$PSScriptRoot\.venv is missing. Run .\install.ps1 first."
    exit 2
}
# Without it, Python prints with the console code page and fails on « » and other scripts.
$env:PYTHONUTF8 = "1"
& $python -m sta @args
exit $LASTEXITCODE
