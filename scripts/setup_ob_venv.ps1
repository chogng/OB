param(
  [string]$VenvDir = "ob"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPath = Join-Path $repoRoot $VenvDir
$requirements = Join-Path $repoRoot "python\\requirements.txt"

if (-not (Test-Path -LiteralPath $requirements)) {
  throw "requirements.txt not found: $requirements"
}

Write-Host "RepoRoot: $repoRoot"
Write-Host "VenvDir:  $venvPath"

if (-not (Test-Path -LiteralPath $venvPath)) {
  Write-Host "Creating venv..."
  python -m venv $venvPath
} else {
  Write-Host "Venv already exists."
}

$pythonExe = Join-Path $venvPath "Scripts\\python.exe"
if (-not (Test-Path -LiteralPath $pythonExe)) {
  throw "python.exe not found in venv: $pythonExe"
}

Write-Host "Upgrading pip..."
& $pythonExe -m pip install --upgrade pip

Write-Host "Installing dependencies..."
& $pythonExe -m pip install -r $requirements

Write-Host "Done."
Write-Host "Activate: & '$venvPath\\Scripts\\Activate.ps1'"

