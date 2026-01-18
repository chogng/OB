param(
  [string]$PythonExe = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workerPy = Join-Path $repoRoot "src-tauri\\src\\utils\\run_origin_job.py"

if (-not (Test-Path -LiteralPath $workerPy)) {
  throw "Python worker not found: $workerPy"
}

if (-not $PythonExe) {
  $venvPy = Join-Path $repoRoot "ob\\Scripts\\python.exe"
  if (Test-Path -LiteralPath $venvPy) {
    $PythonExe = $venvPy
  } else {
    $PythonExe = "python"
  }
}

$root = Join-Path $repoRoot "target-codex\\smoke_plot_json"
$extractDir = Join-Path $root "pkg"
$workDir = Join-Path $extractDir ".ob"

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

# 1) With plot.json (validates header-name column mapping)
$csvPath = Join-Path $extractDir "result.csv"
$csv = @"
x1,y1,x2,y2
0,1,0,2
1,2,1,3
2,3,2,4
"@
Set-Content -LiteralPath $csvPath -Value $csv -Encoding UTF8

$plotJsonPath = Join-Path $extractDir "plot.json"
$plotJson = @"
{
  "version": 1,
  "csv": "result.csv",
  "graphs": [
    {
      "name": "AllCurves",
      "series": [
        { "x": "x1", "y": "y1", "label": "curve1", "type": 202 },
        { "x": "x2", "y": "y2", "label": "curve2", "type": 202 }
      ]
    }
  ]
}
"@
Set-Content -LiteralPath $plotJsonPath -Value $plotJson -Encoding UTF8

$oldPlotMode = $env:ORIGINBRIDGE_PLOT_MODE
try {
  $env:ORIGINBRIDGE_PLOT_MODE = "single"
  & $PythonExe $workerPy --work-dir $workDir --extract-dir $extractDir --dry-run
  if ($LASTEXITCODE -ne 0) { throw "Dry-run failed (plot.json + single)" }

  # 2) Without plot.json (validates fallback pairing + multi mode)
  Remove-Item -Force -ErrorAction SilentlyContinue $plotJsonPath
  $env:ORIGINBRIDGE_PLOT_MODE = "multi"
  & $PythonExe $workerPy --work-dir $workDir --extract-dir $extractDir --dry-run
  if ($LASTEXITCODE -ne 0) { throw "Dry-run failed (fallback + multi)" }

  Write-Host "Smoke test OK."
  Write-Host "WorkDir:  $workDir"
  Write-Host "Log:      $(Join-Path $workDir 'originbridge.log')"
} finally {
  $env:ORIGINBRIDGE_PLOT_MODE = $oldPlotMode
}

