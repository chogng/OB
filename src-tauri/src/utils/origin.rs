use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

fn ensure_dir(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("Work directory path is empty".to_string());
    }

    if path.exists() {
        if !path.is_dir() {
            return Err(format!(
                "Work path exists but is not a directory: {}",
                path.display()
            ));
        }
        return Ok(());
    }

    std::fs::create_dir_all(path)
        .map_err(|e| format!("Failed to create work directory {}: {e}", path.display()))?;
    Ok(())
}

fn work_root_dir_for_zip(zip_path: &Path) -> Result<PathBuf, String> {
    let parent = zip_path
        .parent()
        .ok_or_else(|| format!("ZIP has no parent directory: {}", zip_path.display()))?;
    ensure_dir(parent)?;
    Ok(parent.to_path_buf())
}

fn sanitize_path_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }

    let out = out.trim_matches('_');
    let out = if out.is_empty() { "origin_job" } else { out };
    out.chars().take(80).collect()
}

fn strip_windows_extended_path_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("\\\\?\\UNC\\") {
        return format!("\\\\{rest}");
    }
    if let Some(rest) = path.strip_prefix("\\\\?\\") {
        return rest.to_string();
    }
    path.to_string()
}

fn display_path_for_user(path: &Path) -> String {
    strip_windows_extended_path_prefix(&path.to_string_lossy())
}

#[cfg(target_os = "windows")]
fn powershell_exe_path() -> PathBuf {
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));

    if cfg!(target_pointer_width = "32") {
        let sysnative = system_root.join(r"sysnative\WindowsPowerShell\v1.0\powershell.exe");
        if sysnative.exists() {
            return sysnative;
        }
    }

    let system32 = system_root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    if system32.exists() {
        return system32;
    }

    PathBuf::from("powershell.exe")
}

/// Extract ZIP to the work directory and launch Origin UI.
/// Returns the extracted directory path.
#[cfg(target_os = "windows")]
pub fn extract_zip_and_launch_origin(
    zip_path: &std::path::Path,
    origin_exe: &std::path::Path,
    save_path: Option<String>,
) -> Result<serde_json::Value, String> {
    use std::fs;

    let raw_zip = zip_path;
    if raw_zip.as_os_str().is_empty() {
        return Err("ZIP path is empty".to_string());
    }
    // Common browser "still downloading" suffix; avoid extracting partial ZIPs.
    if raw_zip
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("crdownload"))
    {
        return Err("ZIP looks like an in-progress browser download (.crdownload). Please wait until the download completes and select the final .zip file.".to_string());
    }
    if !raw_zip.exists() {
        return Err(format!("ZIP not found: {}", raw_zip.display()));
    }
    if !raw_zip.is_file() {
        return Err(format!("ZIP path is not a file: {}", raw_zip.display()));
    }
    if let Ok(meta) = fs::metadata(raw_zip) {
        if meta.len() == 0 {
            return Err(format!("ZIP is empty (0 bytes): {}", raw_zip.display()));
        }
    }

    let zip_full = raw_zip
        .canonicalize()
        .unwrap_or_else(|_| raw_zip.to_path_buf());

    let work_root = if let Some(sp) = save_path.as_ref().filter(|s| !s.trim().is_empty()) {
        let p = std::path::PathBuf::from(sp.trim());
        ensure_dir(&p)?;
        p
    } else {
        match work_root_dir_for_zip(&zip_full) {
            Ok(p) => p,
            Err(_) => {
                let fallback = std::env::temp_dir().join("OriginBridge");
                ensure_dir(&fallback)?;
                fallback
            }
        }
    };

    // Create extract directory:
    // If save_path is provided: [Save Path]\[Date]\[Zip Filename]
    // Otherwise: work_root/Extract/{zip_name}
    let name_hint = zip_full
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("origin_package");
    let name_hint = sanitize_path_component(name_hint);

    let base_extract_dir = if save_path.is_some() {
        let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();
        work_root.join(date_str).join(name_hint.clone())
    } else {
        work_root.join("Extract").join(name_hint.clone())
    };

    let mut extract_dir = base_extract_dir.clone();

    // Overwrite any previous extracted folder for this ZIP name.
    if base_extract_dir.exists() {
        if base_extract_dir.is_dir() {
            if let Err(_e) = fs::remove_dir_all(&base_extract_dir) {
                // When a previous run is still open in Origin, files under `.ob` can be locked and
                // prevent deletion. Fall back to a unique extraction directory instead of failing.
                let ts = std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                if save_path.is_some() {
                     let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();
                     extract_dir = work_root.join(date_str).join(format!("{name_hint}_{ts}"));
                } else {
                     extract_dir = work_root.join("Extract").join(format!("{name_hint}_{ts}"));
                }
            }

        } else {
            return Err(format!(
                "Extract dir path exists but is not a directory: {}",
                base_extract_dir.display()
            ));
        }
    }

    // Ensure the chosen extraction dir does not already exist (unlikely, but possible).
    if extract_dir.exists() {
        if !extract_dir.is_dir() {
            return Err(format!(
                "Extract dir path exists but is not a directory: {}",
                extract_dir.display()
            ));
        }
        // If it's a directory, try to remove; if that fails, pick another unique name.
        if let Err(_e) = fs::remove_dir_all(&extract_dir) {
            let ts = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
             if save_path.is_some() {
                 let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();
                 extract_dir = work_root.join(date_str).join(format!("{name_hint}_{ts}"));
            } else {
                 extract_dir = work_root.join("Extract").join(format!("{name_hint}_{ts}"));
            }
        }
    }

    // Create extraction directory
    fs::create_dir_all(&extract_dir).map_err(|e| {
        format!(
            "Failed to create extract dir {}: {e}",
            extract_dir.display()
        )
    })?;

    // Expand the ZIP archive
    let mut zip = zip::ZipArchive::new(
        std::fs::File::open(&zip_full).map_err(|e| format!("Failed to open ZIP: {e}"))?,
    )
    .map_err(|e| format!("Failed to read ZIP: {e}"))?;

    zip.extract(&extract_dir)
        .map_err(|e| format!("Failed to extract ZIP: {e}"))?;

    // Worker directory: keep logs + output artifacts under the extracted folder so everything is in one place.
    // Use a dedicated subfolder so the extracted package content stays clean.
    let worker_root = extract_dir.join(".ob");
    if worker_root.exists() {
        if worker_root.is_dir() {
            fs::remove_dir_all(&worker_root).map_err(|e| {
                format!(
                    "Failed to remove existing worker dir {}: {e}",
                    worker_root.display()
                )
            })?;
        } else {
            return Err(format!(
                "Worker dir path exists but is not a directory: {}",
                worker_root.display()
            ));
        }
    }
    fs::create_dir_all(&worker_root)
        .map_err(|e| format!("Failed to create worker dir {}: {e}", worker_root.display()))?;

    // Find .ogs files in the extracted content
    let ogs_paths = find_ogs_files(&extract_dir);

    let script_body = build_run_script();

    // Worker script executed by PowerShell.
    let worker_script_path = worker_root.join("run_origin_job.ps1");
    fs::write(&worker_script_path, script_body)
        .map_err(|e| format!("Failed to write worker script: {e}"))?;

    // Write a pointer file so users can find logs easily.
    let worker_log_path = worker_root.join("originbridge.log");
    let worker_error_path = worker_root.join("error.txt");
    let trace_hint_path = worker_root.join("log_location.txt");
    let trace_hint = format!(
        "ExtractDir: {}\nWorkDir: {}\nLog: {}\nError: {}\nWorkerScript: {}\n",
        display_path_for_user(&extract_dir),
        display_path_for_user(&worker_root),
        display_path_for_user(&worker_log_path),
        display_path_for_user(&worker_error_path),
        display_path_for_user(&worker_script_path),
    );
    let _ = fs::write(&trace_hint_path, trace_hint);

    let write_worker_error = |message: &str| {
        let body = format!(
            "OriginBridge failed.\n\n{message}\n\nWorkDir: {}\nLog: {}\n",
            display_path_for_user(&worker_root),
            display_path_for_user(&worker_log_path)
        );
        let _ = fs::write(&worker_error_path, body);
    };

    if origin_exe.as_os_str().is_empty() {
        let msg = "Origin executable path is empty.".to_string();
        write_worker_error(&msg);
        return Err(format!(
            "{msg}\nError file: {}",
            display_path_for_user(&worker_error_path)
        ));
    }
    if !origin_exe.exists() {
        let msg = format!("Origin executable not found: {}", origin_exe.display());
        write_worker_error(&msg);
        return Err(format!(
            "{msg}\nError file: {}",
            display_path_for_user(&worker_error_path)
        ));
    }
    if !origin_exe.is_file() {
        let msg = format!(
            "Origin executable path is not a file: {}",
            origin_exe.display()
        );
        write_worker_error(&msg);
        return Err(format!(
            "{msg}\nError file: {}",
            display_path_for_user(&worker_error_path)
        ));
    }

    let work_dir_arg = display_path_for_user(&worker_root);

    let extract_dir_arg = display_path_for_user(&extract_dir);

    let script_path_arg = display_path_for_user(&worker_script_path);

    let mut args = vec![
        "-NoProfile".to_string(),
        "-ExecutionPolicy".to_string(),
        "Bypass".to_string(),
        "-File".to_string(),
        script_path_arg,
        "-WorkDir".to_string(),
        work_dir_arg.clone(),
        "-ExtractDir".to_string(),
        extract_dir_arg,
    ];

    args.push("-OriginExe".to_string());
    args.push(display_path_for_user(origin_exe));

    // Run the worker in background (hidden window).
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new(powershell_exe_path());
        c.creation_flags(0x08000000); // CREATE_NO_WINDOW
        c
    };

    // Default to reusing a single Origin UI instance for automation to avoid the
    // expensive Origin COM shutdown path (EndSession/Exit/Release) on every job.
    // Users can opt out by setting ORIGINBRIDGE_UI_AUTOMATION=0/false in the app env.
    if std::env::var_os("ORIGINBRIDGE_UI_AUTOMATION").is_none() {
        cmd.env("ORIGINBRIDGE_UI_AUTOMATION", "1");
    }

    let mut final_args = vec!["-WindowStyle".to_string(), "Hidden".to_string()];
    final_args.extend(args);

    cmd.args(final_args);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!(
                "Failed to spawn PowerShell worker: {e}\nError file: {}",
                display_path_for_user(&worker_error_path)
            );
            write_worker_error(&msg);
            return Err(msg);
        }
    };

    // Best-effort: if the worker fails immediately, surface the error to the UI instead of
    // returning "started" while nothing actually runs.
    let fast_start = std::env::var("ORIGINBRIDGE_FAST_START")
        .ok()
        .map(|v| !v.trim().is_empty() && ["1", "true", "yes", "y", "on"].contains(&v.trim().to_ascii_lowercase().as_str()))
        .unwrap_or(false);
    let wait_ms = if fast_start { 0 } else { 1200 };
    if wait_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(wait_ms));
    }
    if let Ok(Some(status)) = child.try_wait() {
        if !status.success() {
            let worker_err = fs::read_to_string(&worker_error_path).unwrap_or_default();
            let detail = if worker_err.trim().is_empty() {
                format!(
                    "PowerShell worker exited early ({status}).\nLog: {}\nError: {}",
                    display_path_for_user(&worker_log_path),
                    display_path_for_user(&worker_error_path)
                )
            } else {
                worker_err
            };
            let msg = format!(
                "PowerShell worker failed.\n\n{detail}\n\nLog: {}\nError file: {}",
                display_path_for_user(&worker_log_path),
                display_path_for_user(&worker_error_path)
            );
            write_worker_error(&msg);
            return Err(msg);
        }
    }

    Ok(serde_json::json!({
        "extractDir": display_path_for_user(&extract_dir),
        "workDir": display_path_for_user(&worker_root),
        "logPath": display_path_for_user(&worker_log_path),
        "errorPath": display_path_for_user(&worker_error_path),
        "ogsPaths": ogs_paths
            .iter()
            .map(|p| display_path_for_user(p))
            .collect::<Vec<_>>(),
    }))
}

fn find_ogs_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if out.len() >= 200 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            if out.len() >= 200 {
                return;
            }
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }

            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if ext.eq_ignore_ascii_case("ogs") {
                out.push(path);
            }
        }
    }

    let mut ogs_files = Vec::new();
    walk(dir, &mut ogs_files);

    ogs_files
}

fn build_run_script() -> &'static str {
    r#"param(
  [Parameter(Mandatory=$true)][string]$WorkDir,
  [string]$LocalZip = "",
  [string]$ExtractDir = "",
  [string]$OriginExe = ""
)

function Normalize-WinPath([string]$p) {
  if ($null -eq $p) { return '' }
  $s = $p.Trim()
  if (-not $s) { return '' }
  if ($s -like '\\?\UNC\*') { return '\\' + $s.Substring(8) }
  if ($s -like '\\?\*') { return $s.Substring(4) }
  return $s
}

$WorkDir = Normalize-WinPath $WorkDir
$LocalZip = Normalize-WinPath $LocalZip
$ExtractDir = Normalize-WinPath $ExtractDir
$OriginExe = Normalize-WinPath $OriginExe

$ErrorActionPreference = 'Stop'

$script:LogPath = $null

function Write-OriginBridgeLog([string]$message) {
  try {
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "[$ts] $message"
    try { Write-Host $line } catch {}
    if ($script:LogPath) {
      try { Add-Content -Path $script:LogPath -Value $line -Encoding UTF8 } catch {}
    }
  } catch {
    try { Write-Host $message } catch {}
  }
}

function Write-OriginBridgeError([string]$message) {
  try {
    if (-not (Test-Path -LiteralPath $WorkDir)) {
      New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    }
    $path = Join-Path $WorkDir 'error.txt'
    $logInfo = ''
    if ($script:LogPath) { $logInfo = "Log: $script:LogPath`r`n" }
    $body = "OriginBridge failed.`r`n`r`n$message`r`n`r`nWorkDir: $WorkDir`r`n$logInfo"
    Set-Content -Path $path -Value $body -Encoding UTF8
    Start-Process -FilePath 'notepad.exe' -ArgumentList @($path) | Out-Null
  } catch {
    # ignore
  }
}

function Release-ComObject($obj) {
  try {
    if ($null -ne $obj) {
      [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($obj)
    }
  } catch {
    # ignore
  }
  if (Test-EnvTruthy $env:ORIGINBRIDGE_AGGRESSIVE_COM_GC) {
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
  }
}

function Wait-FileUnlocked([string]$path, [int]$timeoutMs = 10000) {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
    try {
      if (-not (Test-Path -LiteralPath $path)) {
        Start-Sleep -Milliseconds 200
        continue
      }
      $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
      $fs.Close()
      return $true
    } catch {
      Start-Sleep -Milliseconds 200
    }
  }
  return $false
}

function Test-EnvTruthy([string]$value) {
  if ($null -eq $value) { return $false }
  $v = $value.Trim().ToLowerInvariant()
  return @('1','true','yes','y','on') -contains $v
}

function Start-OriginBridgeCleanup([string]$workDir, [string]$projectPath, [string]$traceDir) {
  if (-not (Test-EnvTruthy $env:ORIGINBRIDGE_ENABLE_CLEANUP)) {
    Write-OriginBridgeLog "Cleanup disabled by default. Set ORIGINBRIDGE_ENABLE_CLEANUP=1 to enable."
    return
  }
  if ((Test-EnvTruthy $env:ORIGINBRIDGE_KEEP_WORK) -or (Test-EnvTruthy $env:ORIGINBRIDGE_KEEP_TEMP) -or (Test-EnvTruthy $env:ORIGINBRIDGE_KEEP_ARTIFACTS)) {
    Write-OriginBridgeLog "Cleanup disabled via ORIGINBRIDGE_KEEP_WORK/ORIGINBRIDGE_KEEP_TEMP."
    return
  }

  $parentPid = $PID
  $cleanupCmd = @'
& {
param(
  [int]$ParentPid,
  [string]$WorkDir,
  [string]$ProjectPath,
  [string]$TraceDir = ''
)
$ErrorActionPreference = 'SilentlyContinue'

try { Wait-Process -Id $ParentPid -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Milliseconds 500

function Wait-Unlocked([string]$path) {
  while ($true) {
    try {
      if (-not $path) { return $true }
      if (-not (Test-Path -LiteralPath $path)) { return $true }
      $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
      $fs.Close()
      return $true
    } catch {
      Start-Sleep -Seconds 5
    }
  }
}

# Clean trace folder early (project may still be open in Origin).
if ($TraceDir) {
  try { Remove-Item -Recurse -Force -LiteralPath $TraceDir } catch {}
}

# Best-effort: purge stale legacy open folder (older versions).
try {
  $legacyOpenDir = Join-Path $env:TEMP 'appointer-originbridge-open'
  if (Test-Path -LiteralPath $legacyOpenDir) {
    Get-ChildItem -LiteralPath $legacyOpenDir -File -Filter *.opju -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
      ForEach-Object { try { Remove-Item -Force -LiteralPath $_.FullName } catch {} }
    try {
      if ((Get-ChildItem -LiteralPath $legacyOpenDir -Force -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
        Remove-Item -Recurse -Force -LiteralPath $legacyOpenDir -ErrorAction SilentlyContinue
      }
    } catch {}
  }
} catch {}

# Wait for Origin to release the project file, then remove the whole WorkDir.
if ($ProjectPath) { [void](Wait-Unlocked $ProjectPath) }
if ($WorkDir) {
  try { Remove-Item -Recurse -Force -LiteralPath $WorkDir } catch {}
}

# If the work root becomes empty, remove it too.
try {
  if ($WorkDir) {
    $workRoot = Split-Path -Parent $WorkDir
    if ($workRoot -and (Test-Path -LiteralPath $workRoot)) {
      if ((Get-ChildItem -LiteralPath $workRoot -Force -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
        Remove-Item -Recurse -Force -LiteralPath $workRoot -ErrorAction SilentlyContinue
      }
    }
  }
} catch {}
}
'@

  try {
    $workDirSafe = [string]$workDir
    $projectPathSafe = [string]$projectPath
    $traceDirSafe = [string]$traceDir
    if ($null -eq $workDirSafe) { $workDirSafe = '' }
    if ($null -eq $projectPathSafe) { $projectPathSafe = '' }
    if ($null -eq $traceDirSafe) { $traceDirSafe = '' }
    if (-not $workDirSafe) {
      Write-OriginBridgeLog "Cleanup skipped: WorkDir is empty."
      return
    }
    if (-not $projectPathSafe) {
      Write-OriginBridgeLog "Cleanup skipped: ProjectPath is empty."
      return
    }

    $args = @(
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-Command', $cleanupCmd,
      [string]$parentPid,
      $workDirSafe,
      $projectPathSafe
    )
    if ($traceDirSafe) { $args += $traceDirSafe }

    Start-Process -WindowStyle Hidden -FilePath 'powershell.exe' -ArgumentList $args | Out-Null
    Write-OriginBridgeLog "Scheduled cleanup for WorkDir (will run after Origin closes project)."
  } catch {
    Write-OriginBridgeLog "Failed to schedule cleanup. $($_.Exception.Message)"
  }
}

function Get-OgsPreferredSection([string]$ogsPath) {
  $first = ''
  try {
    foreach ($line in Get-Content -LiteralPath $ogsPath -ErrorAction Stop) {
      if ($line -match '^\s*\[([^\]]+)\]\s*$') {
        $name = $Matches[1].Trim()
        if (-not $first) { $first = $name }
        if ($name -ieq 'main') { return $name }
      }
    }
  } catch {
    # ignore
  }
  return $first
}

function Escape-LabTalkPath([string]$s) {
  if ($null -eq $s) { return '' }
  # LabTalk/Origin script strings are safest with doubled backslashes in Windows paths.
  return $s.Replace('\', '\\')
}

function Invoke-OriginOgs([__ComObject]$origin, [string]$ogsPath, [string]$csvPath = '') {
  $section = Get-OgsPreferredSection $ogsPath
  $ogsLt = Escape-LabTalkPath $ogsPath
  $csvLt = Escape-LabTalkPath $csvPath

  $cmds = @()
  if ($section) {
    if ($csvPath) {
      $cmds += 'run.section("' + $ogsLt + '",' + $section + ',"' + $csvLt + '");'
      $cmds += 'run.section("' + $ogsLt + '","' + $section + '","' + $csvLt + '");'
      $cmds += 'run.section "' + $ogsLt + '","' + $section + '","' + $csvLt + '";'
      $cmds += 'run.section "' + $ogsLt + '",' + $section + ',"' + $csvLt + '";'
    }
    $cmds += 'run.section("' + $ogsLt + '",' + $section + ');'
    $cmds += 'run.section("' + $ogsLt + '","' + $section + '");'
    $cmds += 'run.section "' + $ogsLt + '","' + $section + '";'
    $cmds += 'run.section "' + $ogsLt + '",' + $section + ';'
  }
  if ($csvPath) {
    $cmds += 'run.section("' + $ogsLt + '",Main,"' + $csvLt + '");'
    $cmds += 'run.section("' + $ogsLt + '",main,"' + $csvLt + '");'
    $cmds += 'run.section("' + $ogsLt + '","Main","' + $csvLt + '");'
    $cmds += 'run.section("' + $ogsLt + '","main","' + $csvLt + '");'
    $cmds += 'run.section "' + $ogsLt + '","Main","' + $csvLt + '";'
    $cmds += 'run.section "' + $ogsLt + '","main","' + $csvLt + '";'
  }
  $cmds += 'run.section("' + $ogsLt + '",Main);'
  $cmds += 'run.section("' + $ogsLt + '",main);'
  $cmds += 'run.section("' + $ogsLt + '","Main");'
  $cmds += 'run.section("' + $ogsLt + '","main");'
  $cmds += 'run.section "' + $ogsLt + '","Main";'
  $cmds += 'run.section "' + $ogsLt + '","main";'
  $cmds += 'run "' + $ogsLt + '";'

  foreach ($cmd in ($cmds | Select-Object -Unique)) {
    try {
      Write-OriginBridgeLog "Executing OGS: $cmd"
      $ok = $origin.Execute($cmd)
      if ($ok) { return $true }
    } catch {
      Write-OriginBridgeLog "OGS execute failed: $($_.Exception.Message)"
    }
  }

  return $false
}

function Invoke-FallbackCsvPlot([__ComObject]$origin, [string]$csvPath, [bool]$createNewBook = $true) {
  if (-not $csvPath) { throw "No usable .csv found in package" }

  # Import CSV using the absolute path; relative paths are not reliable in Origin automation.
  $csvLt = Escape-LabTalkPath $csvPath
  $importCmd = ''
  if ($createNewBook) {
    $importCmd = 'newbook; impCSV fname:="' + $csvLt + '";'
  } else {
    $importCmd = 'impCSV fname:="' + $csvLt + '";'
  }
  Write-OriginBridgeLog "Importing CSV: $csvPath (newbook=$createNewBook)"
  $importOk = $origin.Execute($importCmd)
  if ((-not $importOk) -and (-not $createNewBook)) {
    Write-OriginBridgeLog "impCSV failed without newbook; retrying with newbook."
    $importOk = $origin.Execute('newbook; impCSV fname:="' + $csvLt + '";')
  }
  if (-not $importOk) { throw "Origin impCSV failed" }

  # Build plotxy mapping from CSV header: x1,y1,x2,y2,... -> (1,2) (3,4) ...
  $headerLine = Get-Content -LiteralPath $csvPath -TotalCount 1
  if (-not $headerLine) { throw "CSV header is empty" }
  $headerLine = $headerLine.TrimStart([char]0xFEFF).Trim()
  $colCount = ($headerLine -split ',').Count
  $pairsCount = [math]::Floor($colCount / 2)
  if ($pairsCount -lt 1) { $pairsCount = 1 }

  $pairs = @()
  for ($i = 0; $i -lt $pairsCount; $i++) {
    $x = 2 * $i + 1
    $y = 2 * $i + 2
    $pairs += "($x,$y)"
  }
  $pairsExpr = '(' + ($pairs -join ' ') + ')'

  $plotCmd = 'plotxy iy:=' + $pairsExpr + ' plot:=202;'
  Write-OriginBridgeLog "Plotting (plotxy): $pairsExpr"
  $plotOk = $origin.Execute($plotCmd)
  if (-not $plotOk) { throw "Origin plotxy failed" }
}

try {
  if (-not (Test-Path -LiteralPath $WorkDir)) {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
  }

  $internalDir = $WorkDir

  $script:LogPath = Join-Path $internalDir 'originbridge.log'
  try { Set-Content -Path $script:LogPath -Value "OriginBridge log started: $(Get-Date)" -Encoding UTF8 } catch {}
  $script:ErrorPath = Join-Path $internalDir 'error.txt'
  try { Set-Content -Path $script:ErrorPath -Value "" -Encoding UTF8 } catch {}
  Write-OriginBridgeLog "WorkDir: $WorkDir"
  Write-OriginBridgeLog "ErrorPath: $script:ErrorPath"

  $zipPath = Join-Path $internalDir 'origin_package.zip'
  $pkgDir = ''

  $local = $LocalZip.Trim()
  $pre = $ExtractDir.Trim()
  if (-not $pre -and -not $local) {
    # In "extract-only" mode we pass WorkDir as the extracted folder. If the caller forgot to pass
    # -ExtractDir, fall back to WorkDir so the automation can still run.
    $pre = $WorkDir.Trim()
    if ($pre) { Write-OriginBridgeLog "ExtractDir not provided; defaulting to WorkDir." }
  }
  if ($pre) {
    if (-not (Test-Path -LiteralPath $pre)) {
      throw "ExtractDir not found: $pre"
    }
    try {
      $preItem = Get-Item -LiteralPath $pre -ErrorAction Stop
      if (-not $preItem.PSIsContainer) { throw "ExtractDir is not a directory: $pre" }
      $pkgDir = $preItem.FullName
    } catch {
      throw "Invalid ExtractDir: $pre. $($_.Exception.Message)"
    }
    Write-OriginBridgeLog "Using pre-extracted package dir: $pkgDir"
  } else {
    $pkgDir = $WorkDir

    if (-not $local) { throw "Local ZIP path is empty" }
    if ($local -match '(?i)\\.crdownload$') {
      throw "Local ZIP looks like an in-progress browser download (.crdownload). Please wait until download completes, then select the final .zip file."
    }
    if (-not (Test-Path -LiteralPath $local)) {
      throw "Local ZIP not found: $local"
    }
    try {
      $item = Get-Item -LiteralPath $local -ErrorAction Stop
      if ($item.PSIsContainer) { throw "Local ZIP path is a directory: $local" }
      if ($item.Length -le 0) { throw "Local ZIP is empty (0 bytes): $local" }
    } catch {
      throw "Invalid local ZIP: $local. $($_.Exception.Message)"
    }

    Write-OriginBridgeLog "Using local package ZIP: $local"
    try { Remove-Item -Force -LiteralPath $zipPath -ErrorAction SilentlyContinue } catch {}
    Copy-Item -LiteralPath $local -Destination $zipPath -Force

    try {
      $zipLen = (Get-Item -LiteralPath $zipPath -ErrorAction Stop).Length
      if ($zipLen -le 0) { throw "Package ZIP is empty after download/copy (0 bytes)." }
    } catch {
      throw "Package ZIP not ready or invalid: $zipPath. $($_.Exception.Message)"
    }

    Write-OriginBridgeLog "Extracting: $zipPath -> $pkgDir"
    Expand-Archive -Path $zipPath -DestinationPath $pkgDir -Force
  }

  # Keep the extracted folder clean:
  # - Save Origin project alongside .ob (parent directory).
  # - Move package files (manifest/readme/csv/ogs/etc.) into .ob so they stay together with logs.
  $pkgSourceDir = $pkgDir
  if ($pre) {
    $pkgSourceDir = $pkgDir
    $pkgDir = $WorkDir
  }
  if ($pkgSourceDir -and (Test-Path -LiteralPath $pkgSourceDir) -and ($pkgDir -ne $pkgSourceDir)) {
    try {
      $srcFiles = Get-ChildItem -LiteralPath $pkgSourceDir -File -Force -ErrorAction SilentlyContinue
      foreach ($f in $srcFiles) {
        if (-not $f) { continue }
        if ($f.Extension -ieq '.opju' -or $f.Extension -ieq '.opj') { continue }
        $dest = Join-Path $pkgDir $f.Name
        if ($f.FullName -ieq $dest) { continue }
        try {
          Move-Item -Force -LiteralPath $f.FullName -Destination $dest -ErrorAction Stop
        } catch {
          try { Copy-Item -Force -LiteralPath $f.FullName -Destination $dest -ErrorAction Stop } catch {}
          try { Remove-Item -Force -LiteralPath $f.FullName -ErrorAction SilentlyContinue } catch {}
        }
      }
      Write-OriginBridgeLog "Relocated package files into WorkDir: $pkgDir"
    } catch {
      Write-OriginBridgeLog "Relocate package files failed: $($_.Exception.Message)"
    }
  }

  function Enumerate-FilesSafe([string]$root, [string]$pattern) {
    if (-not $root) { return @() }
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    try {
      return [System.IO.Directory]::EnumerateFiles($root, $pattern, [System.IO.SearchOption]::AllDirectories)
    } catch {
      try {
        $p = $pattern
        if ($p.StartsWith('*.')) { $p = $p.Substring(2) }
        $items = Get-ChildItem -Path $root -Recurse -File -Filter $p -ErrorAction SilentlyContinue
        return @($items | ForEach-Object { $_.FullName })
      } catch {
        return @()
      }
    }
  }

  $scanSw = [System.Diagnostics.Stopwatch]::StartNew()
  Write-OriginBridgeLog "Scanning package files under: $pkgDir"

  $ogs = $null
  foreach ($p in (Enumerate-FilesSafe $pkgDir '*.ogs')) {
    try {
      $fi = [System.IO.FileInfo]$p
      if ($fi.Name -match '^originbridge_job\.ogs$') { continue }
      if ($null -eq $ogs -or $fi.LastWriteTimeUtc -gt $ogs.LastWriteTimeUtc) { $ogs = $fi }
    } catch {}
  }

  $ogsBase = ''
  if ($ogs) {
    try { $ogsBase = [IO.Path]::GetFileNameWithoutExtension($ogs.Name) } catch { $ogsBase = '' }
  }

  $csvBestMatchOgsBase = $null
  $csvBestNonMetrics = $null
  $csvBestAny = $null
  foreach ($p in (Enumerate-FilesSafe $pkgDir '*.csv')) {
    try {
      $fi = [System.IO.FileInfo]$p
      if ($fi.Name -match '^originbridge_job\.csv$') { continue }

      $isMetrics = ($fi.Name -match 'metrics')
      if ($null -eq $csvBestAny -or $fi.LastWriteTimeUtc -gt $csvBestAny.LastWriteTimeUtc) { $csvBestAny = $fi }
      if (-not $isMetrics) {
        if ($null -eq $csvBestNonMetrics -or $fi.LastWriteTimeUtc -gt $csvBestNonMetrics.LastWriteTimeUtc) { $csvBestNonMetrics = $fi }
      }

      if ($ogsBase -and (-not $isMetrics)) {
        $b = ''
        try { $b = [IO.Path]::GetFileNameWithoutExtension($fi.Name) } catch { $b = '' }
        if ($b -eq $ogsBase) {
          if ($null -eq $csvBestMatchOgsBase -or $fi.LastWriteTimeUtc -gt $csvBestMatchOgsBase.LastWriteTimeUtc) { $csvBestMatchOgsBase = $fi }
        }
      }
    } catch {}
  }

  $csv = $null
  if ($csvBestMatchOgsBase) { $csv = $csvBestMatchOgsBase }
  elseif ($csvBestNonMetrics) { $csv = $csvBestNonMetrics }
  else { $csv = $csvBestAny }

  $csvPath = ''
  if ($csv) { $csvPath = $csv.FullName }

  $scanSw.Stop()
  $ogsHint = ''
  if ($ogs) { $ogsHint = $ogs.FullName }
  Write-OriginBridgeLog "Scan done in $($scanSw.ElapsedMilliseconds) ms. Latest OGS: $ogsHint"

  function Get-OriginExePath([string]$preferred) {
    $p = $preferred
    if ($null -ne $p) { $p = $p.Trim() }
    if ($p -and $p.Length -ge 2 -and $p.StartsWith('"') -and $p.EndsWith('"')) {
      $p = $p.Substring(1, $p.Length - 2)
      $p = $p.Trim()
    }
    if (-not $p) { return '' }

    try {
      $item = Get-Item -LiteralPath $p -ErrorAction Stop
      if ($item.PSIsContainer) { return '' }
      return $item.FullName
    } catch {
      return ''
    }
  }

  function New-OriginComObject([bool]$preferUi = $false) {
    $lastError = $null

    if ($preferUi) {
      # UI automation: ensure Origin UI is running and attach to that instance.
      # Important: If we attach too early after launching Origin, COM may spawn a second hidden
      # Origin process (-Embedding). Detect that case, terminate the extra process, and retry.
      $originProcName = ''
      try { $originProcName = [IO.Path]::GetFileNameWithoutExtension($originExePath) } catch { $originProcName = '' }

      if (-not (Test-OriginUiRunning $originExePath)) {
        try {
          $originWorkDir = ''
          try { $originWorkDir = Split-Path -Parent $originExePath } catch { $originWorkDir = '' }
          if ($originWorkDir) {
            Write-OriginBridgeLog "UI automation enabled; launching Origin UI: $originExePath (cwd: $originWorkDir)"
            Start-Process -FilePath $originExePath -WorkingDirectory $originWorkDir | Out-Null
          } else {
            Write-OriginBridgeLog "UI automation enabled; launching Origin UI: $originExePath"
            Start-Process -FilePath $originExePath | Out-Null
          }
        } catch {
          Write-OriginBridgeLog "Launching Origin UI failed (will still try COM). $($_.Exception.Message)"
        }

        $uiSw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($uiSw.ElapsedMilliseconds -lt 20000) {
          if (Test-OriginUiRunning $originExePath) { break }
          Start-Sleep -Milliseconds 300
        }
        $uiSw.Stop()
        Write-OriginBridgeLog "Origin UI wait before COM attach: $($uiSw.ElapsedMilliseconds) ms (running=$((Test-OriginUiRunning $originExePath)))"
      } else {
        Write-OriginBridgeLog "UI automation enabled; Origin UI already running."
      }

      $attachSw = [System.Diagnostics.Stopwatch]::StartNew()
      while ($attachSw.ElapsedMilliseconds -lt 20000) {
        $before = @()
        try { if ($originProcName) { $before = @(Get-Process -Name $originProcName -ErrorAction SilentlyContinue) } } catch { $before = @() }
        $beforeIds = @()
        try { $beforeIds = @($before | ForEach-Object { $_.Id }) } catch { $beforeIds = @() }

        try {
          $progId = 'Origin.ApplicationSI'
          Write-Host "Trying Origin COM ProgID (UI attach): $progId"
          $obj = New-Object -ComObject $progId

          $after = @()
          try { if ($originProcName) { $after = @(Get-Process -Name $originProcName -ErrorAction SilentlyContinue) } } catch { $after = @() }
          $newProcs = @()
          try { $newProcs = @($after | Where-Object { $beforeIds -notcontains $_.Id }) } catch { $newProcs = @() }
          $newHidden = @()
          try { $newHidden = @($newProcs | Where-Object { $_.MainWindowHandle -eq 0 }) } catch { $newHidden = @() }

          if ($newHidden.Count -gt 0) {
            Write-OriginBridgeLog "COM attach spawned extra Origin process(es) (likely -Embedding). Waiting for UI COM readiness and retrying."
            try { [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($obj) } catch {}
            $obj = $null
            foreach ($p in $newHidden) {
              try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
            }
            Start-Sleep -Milliseconds 700
            continue
          }

          return @{ ProgId = $progId; Object = $obj }
        } catch {
          $lastError = $_
          Start-Sleep -Milliseconds 300
        }
      }

      $msg = "Could not attach to Origin UI COM instance (ApplicationSI). Please start Origin manually and retry."
      if ($lastError) { $msg = "$msg`nLast error: $($lastError.Exception.Message)" }
      throw $msg
    }

    # Default: prefer a dedicated automation instance so we don't attach to (and accidentally
    # close) an already running Origin UI instance unless explicitly requested.
    $progIds = @('Origin.Application', 'Origin.ApplicationSI')
    if ((-not $preferUi) -and (Test-OriginUiRunning $originExePath)) {
      # If UI is already running, prefer attaching to it so we create a new workbook/graph
      # window inside the existing instance (avoids hitting instance limits and preserves
      # the user's current Origin session).
      $progIds = @('Origin.ApplicationSI', 'Origin.Application')
    }
    foreach ($progId in $progIds) {
      try {
        Write-Host "Trying Origin COM ProgID: $progId"
        $obj = New-Object -ComObject $progId
        return @{ ProgId = $progId; Object = $obj }
      } catch {
        $lastError = $_
        Write-Host "COM failed: $progId :: $($_.Exception.Message)"
      }
    }

    $msg = "Could not create Origin COM object. Make sure Origin is installed and its Automation/COM is registered."
    if ($lastError) { $msg = "$msg`nLast error: $($lastError.Exception.Message)" }
    throw $msg
  }

  $originExePath = Get-OriginExePath $OriginExe
  if (-not $originExePath) {
    throw "Origin.exe path is not configured or not found. Please set it in OriginBridge."
  }

  function Test-OriginUiRunning([string]$exePath) {
    try {
      if (-not $exePath) { return $false }
      $name = [IO.Path]::GetFileNameWithoutExtension($exePath)
      if (-not $name) { return $false }
      $p = Get-Process -Name $name -ErrorAction SilentlyContinue
      if ($null -eq $p) { return $false }
      $ui = @($p | Where-Object { $_.MainWindowHandle -ne 0 })
      return ($ui.Count -gt 0)
    } catch {
      return $false
    }
  }

  try {
    $originProcName = [IO.Path]::GetFileNameWithoutExtension($originExePath)
    $all = Get-Process -Name $originProcName -ErrorAction SilentlyContinue
    if ($all) {
      $ui = @($all | Where-Object { $_.MainWindowHandle -ne 0 })
      if (($ui.Count -eq 0) -and ($all.Count -ge 2)) {
        throw "Detected multiple Origin processes but no UI window is visible. Please close Origin and end all $originProcName.exe processes in Task Manager, then retry."
      }
    }
  } catch {
    Write-OriginBridgeLog "Origin process state check: $($_.Exception.Message)"
  }

  $origin = $null
  $originProgId = ''
  $attachedToUiInstance = $false
  $preferUiAutomation = Test-EnvTruthy $env:ORIGINBRIDGE_UI_AUTOMATION
  if ($preferUiAutomation) {
    Write-OriginBridgeLog "UI automation mode: ON (use Origin UI instance; keep Origin running; no Exit()/relaunch). Set ORIGINBRIDGE_UI_AUTOMATION=0 to disable."
  } else {
    Write-OriginBridgeLog "UI automation mode: OFF (use standalone COM instance; will Save() + Exit() + relaunch Origin UI). Set ORIGINBRIDGE_UI_AUTOMATION=1 to enable."
  }

  try {
    $comSw = [System.Diagnostics.Stopwatch]::StartNew()
    $originInfo = New-OriginComObject $preferUiAutomation
    $comSw.Stop()
    $originProgId = $originInfo.ProgId
    $origin = $originInfo.Object
    $attachedToUiInstance = ($originProgId -eq 'Origin.ApplicationSI')
    Write-OriginBridgeLog "Origin COM created in $($comSw.ElapsedMilliseconds) ms. ProgID: $originProgId"
    if ($attachedToUiInstance) {
      Write-OriginBridgeLog "Origin COM is ApplicationSI (single instance); will NOT call Exit()."
    }
  } catch {
    $comErr = $_.Exception.Message
    Write-OriginBridgeLog "Origin COM automation unavailable; falling back to launching Origin UI only. $comErr"
    if ($ogs) {
      try {
        $originWorkDir = ''
        try { $originWorkDir = Split-Path -Parent $originExePath } catch { $originWorkDir = '' }
        if ($originWorkDir) {
          Write-OriginBridgeLog "Launching Origin UI with .ogs: $originExePath (cwd: $originWorkDir) $($ogs.FullName)"
          Start-Process -FilePath $originExePath -WorkingDirectory $originWorkDir -ArgumentList @($ogs.FullName) | Out-Null
        } else {
          Write-OriginBridgeLog "Launching Origin UI with .ogs: $originExePath $($ogs.FullName)"
          Start-Process -FilePath $originExePath -ArgumentList @($ogs.FullName) | Out-Null
        }
        exit 0
      } catch {
        throw
      }
    } else {
      try {
        $originWorkDir = ''
        try { $originWorkDir = Split-Path -Parent $originExePath } catch { $originWorkDir = '' }
        if ($originWorkDir) {
          Write-OriginBridgeLog "Launching Origin UI (no .ogs found): $originExePath (cwd: $originWorkDir)"
          Start-Process -FilePath $originExePath -WorkingDirectory $originWorkDir | Out-Null
        } else {
          Write-OriginBridgeLog "Launching Origin UI (no .ogs found): $originExePath"
          Start-Process -FilePath $originExePath | Out-Null
        }
        exit 0
      } catch {
        throw
      }
    }
  }

  # NOTE:
  # - UI automation mode: show the COM instance UI and keep Origin running (no Exit()/relaunch).
  # - Non-UI mode: keep the automation instance hidden, Save() to .opju, Exit(), then relaunch UI to open the .opju.
  if (Test-EnvTruthy $env:ORIGINBRIDGE_UI_AUTOMATION) {
    try { $origin.Visible = $true } catch {}
  } elseif (-not $attachedToUiInstance) {
    $origin.Visible = $false
  }
  $beginSw = [System.Diagnostics.Stopwatch]::StartNew()
  $origin.BeginSession() | Out-Null
  $beginSw.Stop()
  Write-OriginBridgeLog "Origin BeginSession() took $($beginSw.ElapsedMilliseconds) ms"
  if (-not $attachedToUiInstance) {
    $newProjSw = [System.Diagnostics.Stopwatch]::StartNew()
    try { $origin.NewProject() | Out-Null } catch {}
    $newProjSw.Stop()
    Write-OriginBridgeLog "Origin NewProject() took $($newProjSw.ElapsedMilliseconds) ms"
  }

  $fallbackNewBook = $true
  if (-not $attachedToUiInstance) {
    # Fresh standalone automation instance; keep the project clean (avoid extra empty books).
    $fallbackNewBook = $false
  } elseif (Test-EnvTruthy $env:ORIGINBRIDGE_UI_AUTOMATION) {
    # UI automation: avoid creating an extra empty book in the user's workspace.
    $fallbackNewBook = $false
  }

  $ranOgs = $false
  $ogsText = ''
  $ogsHasDlgFile = $false
  $ogsUsesArg = $false
  if ($ogs) {
    try {
      $readOgsSw = [System.Diagnostics.Stopwatch]::StartNew()
      $ogsText = Get-Content -LiteralPath $ogs.FullName -Raw -ErrorAction Stop
      $readOgsSw.Stop()
      Write-OriginBridgeLog "Read OGS text took $($readOgsSw.ElapsedMilliseconds) ms"
      if ($ogsText -match '(?i)\bdlgfile\b') { $ogsHasDlgFile = $true }
      if ($ogsText -match '%1') { $ogsUsesArg = $true }
    } catch {
      $ogsText = ''
      $ogsHasDlgFile = $false
      $ogsUsesArg = $false
    }
  }

  $canRunOgs = $false
  if ($ogs) {
    $canRunOgs = $true
    if ($ogsHasDlgFile) {
      # Scripts containing dlgfile are interactive and often block COM automation even when an argument is provided.
      $canRunOgs = $false
    }
  }

  if ($canRunOgs) {
    $ogsPathOriginal = $ogs.FullName
    $csvPathOriginal = $csvPath
    $jobDir = $WorkDir

    $ogsPath = $ogsPathOriginal
    $csvPathForRun = $csvPathOriginal

    $ogsRunPath = Join-Path $jobDir 'originbridge_job.ogs'
    try { Copy-Item -Force -LiteralPath $ogsPathOriginal -Destination $ogsRunPath } catch {}
    try {
      if (Test-Path -LiteralPath $ogsRunPath) {
        $raw = Get-Content -LiteralPath $ogsRunPath -Raw -ErrorAction Stop
        # Avoid Origin modal popups ("Attention!") that can spawn many helper processes.
        $raw = [Regex]::Replace($raw, '(?im)^\s*type\s+-b\s+.*$', '')
        Set-Content -LiteralPath $ogsRunPath -Value $raw -Encoding UTF8 -ErrorAction SilentlyContinue
      }
    } catch {}
    if (Test-Path -LiteralPath $ogsRunPath) {
      $ogsPath = $ogsRunPath
    }

    if ($csvPathOriginal) {
      $csvRunPath = Join-Path $jobDir 'originbridge_job.csv'
      try { Copy-Item -Force -LiteralPath $csvPathOriginal -Destination $csvRunPath } catch {}
      if (Test-Path -LiteralPath $csvRunPath) {
        $csvPathForRun = $csvRunPath
      }
    }
    $csvPath = $csvPathForRun

    $ogsDir = Split-Path -Parent $ogsPath

    # Expose file paths to the OGS script (if it expects them).
    $workDirLt = Escape-LabTalkPath $WorkDir
    $pkgDirLt = Escape-LabTalkPath $pkgDir
    $ogsPathLt = Escape-LabTalkPath $ogsPath
    $ogsDirLt = Escape-LabTalkPath $ogsDir

    try { $origin.Execute('string ob_work_dir$="' + $workDirLt + '";') | Out-Null } catch {}
    try { $origin.Execute('string ob_pkg_dir$="' + $pkgDirLt + '";') | Out-Null } catch {}
    try { $origin.Execute('string ob_ogs_path$="' + $ogsPathLt + '";') | Out-Null } catch {}
    if ($csvPathForRun) {
      $csvPathLt = Escape-LabTalkPath $csvPathForRun
      try { $origin.Execute('string ob_csv_path$="' + $csvPathLt + '";') | Out-Null } catch {}
    }

    # Help relative paths inside the script.
    try { $origin.Execute('cd "' + $workDirLt + '";') | Out-Null } catch {}

    $ranOgs = Invoke-OriginOgs $origin $ogsPath $csvPathForRun
    if ($ranOgs) {
      Write-OriginBridgeLog "OGS executed successfully: $ogsPath"
    } else {
      Write-OriginBridgeLog "OGS execution failed, falling back to basic CSV plot: $ogsPath"
    }
  } elseif ($ogsHasDlgFile) {
    Write-OriginBridgeLog "OGS contains dlgfile; skipping OGS to avoid blocking in automation. ($($ogs.FullName))"
  } else {
    Write-OriginBridgeLog "No .ogs found in package, falling back to basic CSV plot."
  }

  if (-not $ranOgs) {
    # Fallback: Import CSV + plot raw column pairs.
    # This is less accurate than the mode-specific OGS script, but keeps compatibility.
    $csvFallbackSw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-FallbackCsvPlot $origin $csvPath $fallbackNewBook
    $csvFallbackSw.Stop()
    Write-OriginBridgeLog "Fallback CSV plot took $($csvFallbackSw.ElapsedMilliseconds) ms"
  }

  if ($attachedToUiInstance) {
    try { $origin.Visible = $true } catch {}
    try { $origin.Execute('win -a;') | Out-Null } catch {}
    try {
      $ws = New-Object -ComObject 'WScript.Shell'
      $null = $ws.AppActivate('Origin')
    } catch {}
    if (-not (Test-EnvTruthy $env:ORIGINBRIDGE_UI_AUTOMATION)) {
      Write-OriginBridgeLog "Attached to existing Origin UI instance; created windows in current workspace. Skipping Save()/Exit()."
      try { Release-ComObject $origin } catch {}
      $origin = $null
      exit 0
    }
    Write-OriginBridgeLog "UI automation enabled; will Save() and keep Origin open (no Exit()/relaunch)."
  }

  $projName = "originbridge.opju"
  $saveRoot = ''
  try { $saveRoot = Split-Path -Parent $WorkDir } catch { $saveRoot = '' }
  if (-not $saveRoot) { $saveRoot = $WorkDir }
  $projPath = Join-Path $saveRoot $projName

  if (Test-Path -LiteralPath $projPath) {
    try { Remove-Item -Force -LiteralPath $projPath } catch {}
  }

  Write-OriginBridgeLog "Saving Origin project: $projPath"
  $saveSw = [System.Diagnostics.Stopwatch]::StartNew()
  $saved = $origin.Save($projPath)
  $saveSw.Stop()
  Write-OriginBridgeLog "Origin Save() took $($saveSw.ElapsedMilliseconds) ms (ok=$saved)"
  if (-not $saved) { throw "Origin Save() returned false" }

  # Some Origin automation commands return success even when they fail silently.
  # Validate the project contains at least one graph page after Save(). If not, re-run fallback plotting.
  $searchAfterSave = ''
  $searchSw = [System.Diagnostics.Stopwatch]::StartNew()
  try { $searchAfterSave = $origin.ProjectSearch('G', $null, $null) } catch {}
  $searchSw.Stop()
  Write-OriginBridgeLog "Origin ProjectSearch('G') took $($searchSw.ElapsedMilliseconds) ms"
  if ($searchAfterSave -notmatch 'GraphPage') {
    Write-OriginBridgeLog "No GraphPage found after Save(); attempting fallback CSV plot."
    if (-not $attachedToUiInstance) {
      try { $origin.NewProject() | Out-Null } catch {}
    }
    Invoke-FallbackCsvPlot $origin $csvPath $fallbackNewBook

    if (Test-Path -LiteralPath $projPath) {
      try { Remove-Item -Force -LiteralPath $projPath } catch {}
    }

    Write-OriginBridgeLog "Saving Origin project (fallback): $projPath"
    $saved2 = $origin.Save($projPath)
    if (-not $saved2) { throw "Origin Save() returned false (fallback)" }

    $searchAfterSave2 = ''
    try { $searchAfterSave2 = $origin.ProjectSearch('G', $null, $null) } catch {}
    if ($searchAfterSave2 -notmatch 'GraphPage') {
      throw "Origin saved project but no GraphPage found (after fallback)"
    }
  }

  if (Test-EnvTruthy $env:ORIGINBRIDGE_UI_AUTOMATION) {
    try { $origin.Visible = $true } catch {}
    try { $origin.Execute('win -a;') | Out-Null } catch {}
    try {
      $ws = New-Object -ComObject 'WScript.Shell'
      $null = $ws.AppActivate('Origin')
    } catch {}
    Start-OriginBridgeCleanup $WorkDir $projPath ''
    try { Release-ComObject $origin } catch {}
    $origin = $null
    exit 0
  }

  # Close the automation instance, then open the saved project in a real UI window.
  $endSw = [System.Diagnostics.Stopwatch]::StartNew()
  try { $origin.EndSession() | Out-Null } catch {}
  $endSw.Stop()
  Write-OriginBridgeLog "Origin EndSession() took $($endSw.ElapsedMilliseconds) ms"

  $exitSw = [System.Diagnostics.Stopwatch]::StartNew()
  try { $origin.Exit() | Out-Null } catch {}
  $exitSw.Stop()
  Write-OriginBridgeLog "Origin Exit() took $($exitSw.ElapsedMilliseconds) ms"

  $releaseSw = [System.Diagnostics.Stopwatch]::StartNew()
  try { Release-ComObject $origin } catch {}
  $releaseSw.Stop()
  Write-OriginBridgeLog "Release COM took $($releaseSw.ElapsedMilliseconds) ms"
  $origin = $null

  $unlockWaitMs = 60000
  try {
    $raw = [string]$env:ORIGINBRIDGE_UNLOCK_WAIT_MS
    if ($raw) {
      $v = 0
      if ([int]::TryParse($raw.Trim(), [ref]$v)) {
        if ($v -lt 0) { $v = 0 }
        if ($v -gt 600000) { $v = 600000 }
        $unlockWaitMs = $v
      }
    }
  } catch {}

  $unlockSw = [System.Diagnostics.Stopwatch]::StartNew()
  $unlocked = Wait-FileUnlocked $projPath $unlockWaitMs
  $unlockSw.Stop()
  Write-OriginBridgeLog "Wait-FileUnlocked took $($unlockSw.ElapsedMilliseconds) ms (timeout=$unlockWaitMs, ok=$unlocked)"
  if (-not $unlocked) {
    Write-OriginBridgeLog "Project file still locked after waiting: $projPath"
  }

  if (-not (Test-Path -LiteralPath $projPath)) {
    throw "Project file was not created: $projPath"
  }

  $originWorkDir = ''
  try { $originWorkDir = Split-Path -Parent $originExePath } catch { $originWorkDir = '' }
  try {
    $openUiSw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($originWorkDir) {
      Write-OriginBridgeLog "Opening project in Origin UI: $originExePath (cwd: $originWorkDir) $projPath"
      Start-Process -FilePath $originExePath -WorkingDirectory $originWorkDir -ArgumentList @($projPath) | Out-Null
    } else {
      Write-OriginBridgeLog "Opening project in Origin UI: $originExePath $projPath"
      Start-Process -FilePath $originExePath -ArgumentList @($projPath) | Out-Null
    }
    $openUiSw.Stop()
    Write-OriginBridgeLog "Start-Process (Origin UI) returned in $($openUiSw.ElapsedMilliseconds) ms"
  } catch {
    Write-OriginBridgeLog "Start-Process Origin UI failed; falling back to file association. $($_.Exception.Message)"
    Start-Process -FilePath $projPath | Out-Null
  }

  Start-OriginBridgeCleanup $WorkDir $projPath ''
  exit 0
} catch {
  $msg = $_ | Out-String
  Write-OriginBridgeError $msg
  exit 1
}
"#
}
