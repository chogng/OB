param(
  [string]$ZipDir = "C:\Users\lanxi\Desktop\test_origin",
  [string]$OutDir = "",
  [int]$Count = 5,
  [string]$OriginExe = "C:\Program Files\OriginLab\Origin2024\Origin64.exe",
  [string]$PythonExe = "",
  [string]$WorkerPy = ""
)

$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$p) {
  if (-not $p) { throw "Path is empty" }
  if (Test-Path -LiteralPath $p) { return }
  New-Item -ItemType Directory -Force -Path $p | Out-Null
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $WorkerPy) {
  $WorkerPy = Join-Path $repoRoot "src-tauri\\src\\utils\\run_origin_job.py"
}
if (-not (Test-Path -LiteralPath $WorkerPy)) {
  throw "Python worker not found: $WorkerPy"
}

if (-not $PythonExe) {
  $venvPy = Join-Path $repoRoot "ob\\Scripts\\python.exe"
  if (Test-Path -LiteralPath $venvPy) { $PythonExe = $venvPy }
  else { $PythonExe = "python" }
}

if (-not $OutDir) {
  $OutDir = Join-Path $ZipDir "stress_out_py\\single_window_reuse_ui"
}

if (-not (Test-Path -LiteralPath $ZipDir)) {
  throw "ZipDir not found: $ZipDir"
}
if (-not (Test-Path -LiteralPath $OriginExe)) {
  throw "OriginExe not found: $OriginExe"
}

Ensure-Dir $OutDir

$zips = Get-ChildItem -LiteralPath $ZipDir -Filter "stress_*.zip" -File -ErrorAction Stop |
  Sort-Object Name |
  Select-Object -First $Count

if (-not $zips -or $zips.Count -lt 1) {
  throw "No stress_*.zip found under: $ZipDir"
}

# Ensure an Origin UI window exists for ApplicationSI attach.
try {
  Start-Process -FilePath $OriginExe | Out-Null
} catch {
  # ignore; attach may still start an instance
}
try {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  while ($sw.ElapsedMilliseconds -lt 60000) {
    $ui = @(Get-Process -Name Origin64 -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 })
    if ($ui.Count -gt 0) { break }
    Start-Sleep -Milliseconds 500
  }
} catch {
  # ignore
}

$oldUiAutomation = $env:ORIGINBRIDGE_UI_AUTOMATION
$oldMultiInst = $env:ORIGINBRIDGE_MULTI_INSTANCE_UI
$oldPlotMode = $env:ORIGINBRIDGE_PLOT_MODE

$env:ORIGINBRIDGE_UI_AUTOMATION = "1"
$env:ORIGINBRIDGE_MULTI_INSTANCE_UI = "0"
$env:ORIGINBRIDGE_PLOT_MODE = "single"

$startedAt = (Get-Date).ToString("o")

$results = @()
$ok = 0
$fail = 0

for ($i = 0; $i -lt $zips.Count; $i++) {
  $zip = $zips[$i]
  $idx = $i + 1
  $jobDir = Join-Path $OutDir ("job_{0:D2}" -f $idx)
  $workDir = Join-Path $jobDir ".ob"
  Ensure-Dir $workDir

  # Clean job folder (but keep the directory itself).
  try {
    Get-ChildItem -LiteralPath $workDir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  } catch {}
  Ensure-Dir $workDir

  $originPackageZip = Join-Path $workDir "origin_package.zip"

  $swJob = [System.Diagnostics.Stopwatch]::StartNew()
  $exitCode = 1
  $procId = $null
  try {
    Copy-Item -LiteralPath $zip.FullName -Destination $originPackageZip -Force
    Expand-Archive -LiteralPath $originPackageZip -DestinationPath $workDir -Force

    $argList = @(
      ('"' + $WorkerPy + '"'),
      "--work-dir", ('"' + $workDir + '"'),
      "--extract-dir", ('"' + $workDir + '"'),
      "--origin-exe", ('"' + $OriginExe + '"')
    ) -join " "
    $p = Start-Process -FilePath $PythonExe -ArgumentList $argList -PassThru -Wait -NoNewWindow
    $procId = $p.Id
    $exitCode = $p.ExitCode
  } catch {
    $exitCode = 1
  } finally {
    $swJob.Stop()
  }

  if ($exitCode -eq 0) { $ok++ } else { $fail++ }

  $results += [pscustomobject]@{
    index       = $idx
    zipPath     = $zip.FullName
    jobDir      = $jobDir
    workDir     = $workDir
    pid         = $procId
    hasExited   = $true
    exitCode    = $exitCode
    durationSec = [Math]::Round($swJob.Elapsed.TotalSeconds, 3)
  }

  Write-Host ("[{0}/{1}] {2} exit={3} sec={4}" -f $idx, $zips.Count, $zip.Name, $exitCode, $results[-1].durationSec)
}

$summary = [pscustomobject]@{
  mode          = "python_single_window_reuse_ui"
  startedAt     = $startedAt
  originExe     = $OriginExe
  zipDir        = $ZipDir
  count         = $zips.Count
  env           = @{
    ORIGINBRIDGE_UI_AUTOMATION     = $env:ORIGINBRIDGE_UI_AUTOMATION
    ORIGINBRIDGE_MULTI_INSTANCE_UI = $env:ORIGINBRIDGE_MULTI_INSTANCE_UI
    ORIGINBRIDGE_PLOT_MODE         = $env:ORIGINBRIDGE_PLOT_MODE
  }
  finishedCount = $results.Count
  okCount       = $ok
  failCount     = $fail
  timeoutCount  = 0
  results       = $results
}

$summaryPath = Join-Path $OutDir "stress_summary.json"
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "Summary: $summaryPath"
Write-Host "ok=$ok fail=$fail"

# Restore env
$env:ORIGINBRIDGE_UI_AUTOMATION = $oldUiAutomation
$env:ORIGINBRIDGE_MULTI_INSTANCE_UI = $oldMultiInst
$env:ORIGINBRIDGE_PLOT_MODE = $oldPlotMode
