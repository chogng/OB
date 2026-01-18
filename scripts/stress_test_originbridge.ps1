param(
  [int]$Count = 20,
  [string]$ZipDir = "C:\\Users\\lanxi\\Desktop\\test_origin",
  [string]$OutDir = "",
  [string]$OriginExe = "",
  [int]$TimeoutMinutes = 60
)

$ErrorActionPreference = "Stop"

function Normalize-WinPath([string]$p) {
  if ($null -eq $p) { return "" }
  $s = $p.Trim()
  if (-not $s) { return "" }
  if ($s -like "\\\\?\\UNC\\*") { return "\\\\" + $s.Substring(8) }
  if ($s -like "\\\\?\\*") { return $s.Substring(4) }
  return $s
}

function Get-OriginExeFromConfig {
  try {
    $cfg = Join-Path $env:APPDATA "Appointer\\OriginBridge\\config.json"
    if (-not (Test-Path -LiteralPath $cfg)) { return "" }
    $raw = Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop
    $json = $raw | ConvertFrom-Json -ErrorAction Stop
    return [string]$json.originExe
  } catch {
    return ""
  }
}

function Extract-WorkerScript([string]$repoRoot, [string]$outPath) {
  $originRs = Join-Path $repoRoot "src-tauri\\src\\utils\\origin.rs"
  if (-not (Test-Path -LiteralPath $originRs)) { throw "origin.rs not found: $originRs" }

  $raw = Get-Content -LiteralPath $originRs -Raw -ErrorAction Stop
  $m = [regex]::Match($raw, '(?s)fn\s+build_run_script\(\)\s+->\s+&''static\s+str\s*\{\s*r#"(.*?)"#\s*\}')
  if (-not $m.Success) {
    throw "Failed to extract build_run_script() body from: $originRs"
  }

  $body = $m.Groups[1].Value
  $dir = Split-Path -Parent $outPath
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  Set-Content -LiteralPath $outPath -Value $body -Encoding UTF8
}

function Ensure-StressZips([string]$zipDir, [int]$count) {
  if (-not (Test-Path -LiteralPath $zipDir)) { throw "ZIP dir not found: $zipDir" }

  $existing = @(Get-ChildItem -LiteralPath $zipDir -File -Filter "*.zip" -ErrorAction SilentlyContinue)
  if (-not $existing -or $existing.Count -eq 0) { throw "No .zip files found under: $zipDir" }

  $src = $existing[0].FullName
  $out = @()
  for ($i = 1; $i -le $count; $i++) {
    $name = "stress_{0:D2}.zip" -f $i
    $dest = Join-Path $zipDir $name
    if (-not (Test-Path -LiteralPath $dest)) {
      Copy-Item -LiteralPath $src -Destination $dest -Force
    }
    $out += $dest
  }
  return $out
}

function Start-WorkerJobs(
  [string]$modeName,
  [string[]]$zipPaths,
  [string]$workerScript,
  [string]$originExe,
  [string]$modeOutDir,
  [hashtable]$envVars
) {
  Write-Host ""
  Write-Host "=== $modeName ==="
  Write-Host "OutDir: $modeOutDir"

  if (Test-Path -LiteralPath $modeOutDir) {
    Remove-Item -Recurse -Force -LiteralPath $modeOutDir
  }
  New-Item -ItemType Directory -Force -Path $modeOutDir | Out-Null

  $savedEnv = @{}
  foreach ($k in $envVars.Keys) {
    $existed = (Test-Path "Env:$k")
    $prev = $null
    if ($existed) {
      try { $prev = (Get-Item "Env:$k" -ErrorAction Stop).Value } catch { $prev = $null }
    }
    $savedEnv[$k] = [pscustomobject]@{ existed = $existed; value = $prev }
    Set-Item -Path "Env:$k" -Value ([string]$envVars[$k])
  }

  $procs = @()
  $startedAt = Get-Date
  try {
    for ($i = 0; $i -lt $zipPaths.Count; $i++) {
      $zipPath = $zipPaths[$i]
      $jobName = "job_{0:D2}" -f ($i + 1)
      $jobDir = Join-Path $modeOutDir $jobName
      $workDir = Join-Path $jobDir ".ob"
      New-Item -ItemType Directory -Force -Path $workDir | Out-Null

      $cmd = "& '$workerScript' -WorkDir '$workDir' -LocalZip '$zipPath' -OriginExe '$originExe'"

      $p = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $cmd) `
        -WindowStyle Hidden `
        -PassThru

      $procs += [pscustomobject]@{
        Index    = ($i + 1)
        ZipPath  = $zipPath
        JobDir   = $jobDir
        WorkDir  = $workDir
        Proc     = $p
        StartUtc = (Get-Date).ToUniversalTime()
      }
    }

    # Snapshot how many Origin processes are alive shortly after launch.
    Start-Sleep -Seconds 5
    $originProcName = [IO.Path]::GetFileNameWithoutExtension($originExe)
    $originCount = @(Get-Process -Name $originProcName -ErrorAction SilentlyContinue).Count
    Write-Host "Origin process count after 5s: $originCount"

    $timeoutMs = [int]([TimeSpan]::FromMinutes($TimeoutMinutes).TotalMilliseconds)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($timeoutMs)
    foreach ($item in $procs) {
      $remaining = [int]([Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds))
      if ($remaining -le 0) { break }
      try { [void]$item.Proc.WaitForExit($remaining) } catch {}
      if ($item.Proc.HasExited) {
        $item | Add-Member -NotePropertyName ExitCode -NotePropertyValue ($item.Proc.ExitCode) -Force
        $item | Add-Member -NotePropertyName EndUtc -NotePropertyValue (Get-Date).ToUniversalTime() -Force
        $item | Add-Member -NotePropertyName DurationSec -NotePropertyValue ([Math]::Round((New-TimeSpan -Start $item.StartUtc -End $item.EndUtc).TotalSeconds, 3)) -Force
      } else {
        $item | Add-Member -NotePropertyName ExitCode -NotePropertyValue $null -Force
        $item | Add-Member -NotePropertyName EndUtc -NotePropertyValue $null -Force
        $item | Add-Member -NotePropertyName DurationSec -NotePropertyValue $null -Force
      }
    }

    $finished = @($procs | Where-Object { $_.Proc.HasExited })
    $pending = @($procs | Where-Object { -not $_.Proc.HasExited })
    if ($pending.Count -gt 0) {
      Write-Host "Timeout: $($pending.Count) worker(s) still running after $TimeoutMinutes min."
    }

    $ok = @($finished | Where-Object { $_.ExitCode -eq 0 })
    $fail = @($finished | Where-Object { $_.ExitCode -ne 0 })
    Write-Host "Workers finished: $($finished.Count)/$($procs.Count)  OK: $($ok.Count)  FAIL: $($fail.Count)"

    if ($fail.Count -gt 0) {
      Write-Host ""
      Write-Host "Sample failures (first 5):"
      foreach ($f in ($fail | Select-Object -First 5)) {
        $errPath = Join-Path $f.WorkDir "error.txt"
        $msg = ""
        if (Test-Path -LiteralPath $errPath) {
          $msg = (Get-Content -LiteralPath $errPath -Raw -ErrorAction SilentlyContinue).Trim()
        }
        if (-not $msg) { $msg = "(no error.txt content)" }
        Write-Host ("[{0:D2}] exit={1} zip={2}`n{3}`n" -f $f.Index, $f.ExitCode, (Split-Path -Leaf $f.ZipPath), $msg)
      }
    }

    $summaryPath = Join-Path $modeOutDir "stress_summary.json"
    $summary = [pscustomobject]@{
      mode          = $modeName
      startedAt     = $startedAt.ToString("o")
      originExe     = $originExe
      zipDir        = $ZipDir
      count         = $zipPaths.Count
      env           = $envVars
      finishedCount = $finished.Count
      okCount       = $ok.Count
      failCount     = $fail.Count
      timeoutCount  = $pending.Count
      results       = $procs | ForEach-Object {
        [pscustomobject]@{
          index       = $_.Index
          zipPath     = $_.ZipPath
          jobDir      = $_.JobDir
          workDir     = $_.WorkDir
          pid         = $_.Proc.Id
          hasExited   = $_.Proc.HasExited
          exitCode    = $_.ExitCode
          durationSec = $_.DurationSec
        }
      }
    }
    $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-Host "Wrote: $summaryPath"
  } finally {
    # Restore env
    foreach ($k in $envVars.Keys) {
      if ($savedEnv.ContainsKey($k)) {
        if ($savedEnv[$k].existed) {
          Set-Item -Path "Env:$k" -Value ([string]$savedEnv[$k].value)
        } else {
          Remove-Item "Env:$k" -ErrorAction SilentlyContinue
        }
      } else {
        Remove-Item "Env:$k" -ErrorAction SilentlyContinue
      }
    }
  }
}

# --- Main ---

if (-not $OutDir) {
  $OutDir = Join-Path $ZipDir "stress_out"
}

$OriginExe = Normalize-WinPath $OriginExe
if (-not $OriginExe) {
  $OriginExe = Normalize-WinPath (Get-OriginExeFromConfig)
}
if (-not $OriginExe) { throw "OriginExe not provided and not found in config." }
if (-not (Test-Path -LiteralPath $OriginExe)) { throw "OriginExe not found: $OriginExe" }

$zipPaths = Ensure-StressZips $ZipDir $Count

$runnerDir = Join-Path $OutDir "runner"
$workerScript = Join-Path $runnerDir "run_origin_job.ps1"
$repoRoot = Split-Path -Parent $PSScriptRoot
Extract-WorkerScript -repoRoot $repoRoot -outPath $workerScript

Write-Host "OriginExe: $OriginExe"
Write-Host "ZIPs: $($zipPaths.Count) under $ZipDir"
Write-Host "WorkerScript: $workerScript"

# Single-window (reuse UI) mode
Start-WorkerJobs `
  -modeName "single_window_reuse_ui" `
  -zipPaths $zipPaths `
  -workerScript $workerScript `
  -originExe $OriginExe `
  -modeOutDir (Join-Path $OutDir "single_window_reuse_ui") `
  -envVars @{
    ORIGINBRIDGE_UI_AUTOMATION = "1"
    ORIGINBRIDGE_MULTI_INSTANCE_UI = "0"
    ORIGINBRIDGE_NO_ERROR_NOTEPAD = "1"
  }

# Multi-instance mode (parallel workers + parallel Origin instances)
Start-WorkerJobs `
  -modeName "multi_instance_parallel" `
  -zipPaths $zipPaths `
  -workerScript $workerScript `
  -originExe $OriginExe `
  -modeOutDir (Join-Path $OutDir "multi_instance_parallel") `
  -envVars @{
    ORIGINBRIDGE_UI_AUTOMATION = "0"
    ORIGINBRIDGE_MULTI_INSTANCE_UI = "1"
    ORIGINBRIDGE_PARALLEL_MULTI_INSTANCE = "1"
    ORIGINBRIDGE_NO_ERROR_NOTEPAD = "1"
  }
