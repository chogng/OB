use std::path::{Path, PathBuf};
use std::process::Command;

fn config_dir() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let p = PathBuf::from(appdata)
            .join("Appointer")
            .join("OriginBridge");
        if !p.as_os_str().is_empty() {
            return p;
        }
    }

    std::env::temp_dir().join("appointer-originbridge")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

#[cfg(target_os = "windows")]
fn normalize_windows_verbatim_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    let s = s.as_ref();

    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }

    path.to_path_buf()
}

#[cfg(not(target_os = "windows"))]
fn normalize_windows_verbatim_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

pub fn get_origin_exe_path() -> Result<Option<PathBuf>, String> {
    let path = config_path();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };

    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Ok(None);
    };

    let p = v
        .get("originExe")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .map(|p| normalize_windows_verbatim_path(&p));

    Ok(p)
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Err(format!("Config path has no parent: {}", path.display()));
    };
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create config dir {}: {e}", parent.display()))?;
    Ok(())
}

pub fn set_origin_exe_path(origin_exe: &Path) -> Result<PathBuf, String> {
    if origin_exe.as_os_str().is_empty() {
        return Err("Origin executable path is empty".to_string());
    }
    if !origin_exe.exists() {
        return Err(format!(
            "Origin executable not found: {}",
            origin_exe.display()
        ));
    }
    if !origin_exe.is_file() {
        return Err(format!(
            "Origin executable path is not a file: {}",
            origin_exe.display()
        ));
    }

    let normalized = origin_exe
        .canonicalize()
        .unwrap_or_else(|_| origin_exe.to_path_buf());
    let normalized = normalize_windows_verbatim_path(&normalized);

    let path = config_path();
    ensure_parent_dir(&path)?;

    let mut obj = match std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
    {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    obj.insert(
        "originExe".to_string(),
        serde_json::Value::String(normalized.to_string_lossy().to_string()),
    );

    let body = serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .map_err(|e| format!("Failed to serialize config JSON: {e}"))?;
    std::fs::write(&path, body)
        .map_err(|e| format!("Failed to write config file {}: {e}", path.display()))?;

    Ok(normalized)
}

pub fn clear_origin_exe_path() -> Result<(), String> {
    let path = config_path();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Ok(());
    };

    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Ok(());
    };

    let Some(obj) = v.as_object_mut() else {
        return Ok(());
    };

    obj.remove("originExe");
    ensure_parent_dir(&path)?;
    let body = serde_json::to_string_pretty(&v)
        .map_err(|e| format!("Failed to serialize config JSON: {e}"))?;
    std::fs::write(&path, body)
        .map_err(|e| format!("Failed to write config file {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn detect_origin_exe_candidates(enable_deep_scan: bool) -> Result<serde_json::Value, String> {
    let ps = r#"
$ErrorActionPreference = 'SilentlyContinue'

$EnableDeepScan = __ENABLE_DEEP_SCAN__

$candidates = @{}

function Normalize-ExePath([string]$raw) {
  if (-not $raw) { return '' }
  $s = $raw.Trim()
  if (-not $s) { return '' }

  try { $s = [Environment]::ExpandEnvironmentVariables($s) } catch { }

  if ($s -match '^\s*"(.*?)"') { return $matches[1] }
  if ($s -match '(?i)^\s*(.+?\.exe)\b') { return $matches[1] }
  return $s
}

function Add-Candidate([string]$path, [string]$source) {
  $path = Normalize-ExePath $path
  if (-not $path) { return }
  if (-not (Test-Path -LiteralPath $path)) { return }

  try {
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.PSIsContainer) { return }
    $full = $item.FullName
    if (-not $candidates.ContainsKey($full)) {
      $candidates[$full] = New-Object System.Collections.Generic.List[string]
    }
    if ($source -and -not $candidates[$full].Contains($source)) {
      $null = $candidates[$full].Add($source)
    }
  } catch {
    # ignore
  }
}

function Get-OriginExeRank([string]$p) {
  if (-not $p) { return 0 }
  $name = ''
  try { $name = [System.IO.Path]::GetFileName($p) } catch { $name = '' }
  switch -Regex ($name) {
    '(?i)^OriginPro64\.exe$' { return 40 }
    '(?i)^Origin64\.exe$' { return 30 }
    '(?i)^OriginPro\.exe$' { return 20 }
    '(?i)^Origin\.exe$' { return 10 }
    default { return 0 }
  }
}

function Add-OriginCandidatesFromDir([string]$dir, [string]$sourcePrefix) {
  if (-not $dir) { return }
  $dir = $dir.Trim()
  if (-not $dir) { return }
  try {
    $item = Get-Item -LiteralPath $dir -ErrorAction Stop
    if (-not $item.PSIsContainer) { return }
    $fullDir = $item.FullName
    Add-Candidate (Join-Path $fullDir 'Origin64.exe') ($sourcePrefix + ':dir')
    Add-Candidate (Join-Path $fullDir 'Origin.exe') ($sourcePrefix + ':dir')
    Add-Candidate (Join-Path $fullDir 'OriginPro64.exe') ($sourcePrefix + ':dir')
    Add-Candidate (Join-Path $fullDir 'OriginPro.exe') ($sourcePrefix + ':dir')
    Add-Candidate (Join-Path (Join-Path $fullDir '64Bit') 'Origin64.exe') ($sourcePrefix + ':dir')
    Add-Candidate (Join-Path (Join-Path $fullDir '64Bit') 'OriginPro64.exe') ($sourcePrefix + ':dir')
  } catch {
    # ignore
  }
}

function Emit-Results {
  $out = @()
  foreach ($p in $candidates.Keys) {
    $fileVersion = ''
    $productVersion = ''
    $productName = ''
    try {
      $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p)
      $fileVersion = $info.FileVersion
      $productVersion = $info.ProductVersion
      $productName = $info.ProductName
    } catch {
      # ignore
    }

    $version = if ($productVersion) { $productVersion } else { $fileVersion }
    $vobj = [version]'0.0.0.0'
    try { if ($version) { $vobj = [version]$version } } catch { $vobj = [version]'0.0.0.0' }

    $out += [pscustomobject]@{
      path = $p
      version = $version
      productName = $productName
      sources = @($candidates[$p])
      _rank = (Get-OriginExeRank $p)
      _v = $vobj
    }
  }

  $result = $out | Sort-Object _v, _rank -Descending | Select-Object path,version,productName,sources
  ConvertTo-Json -InputObject @($result) -Depth 6 -Compress
  exit 0
}

function Try-AppPaths {
  $keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Origin.exe',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Origin64.exe',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OriginPro.exe',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OriginPro64.exe',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\Origin.exe',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\Origin64.exe',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\OriginPro.exe',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\OriginPro64.exe',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Origin.exe',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Origin64.exe',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OriginPro.exe',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OriginPro64.exe',
    'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\Origin.exe',
    'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\Origin64.exe',
    'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\OriginPro.exe',
    'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\OriginPro64.exe'
  )

  foreach ($k in $keys) {
    try {
      $item = Get-Item -Path $k -ErrorAction Stop
      $v = $item.GetValue('')
      Add-Candidate $v ("registry:" + $k)

      $exe = Normalize-ExePath $v
      if ($exe -and (Test-Path -LiteralPath $exe)) {
        try {
          $fi = Get-Item -LiteralPath $exe -ErrorAction Stop
          if (-not $fi.PSIsContainer) {
            $parent = Split-Path -Parent $fi.FullName
            if ($parent) { Add-OriginCandidatesFromDir $parent ("registry-sibling:" + $k) }
          }
        } catch {
          # ignore
        }
      }
      if ($exe -and -not [System.IO.Path]::IsPathRooted($exe)) {
        $pathVal = $item.GetValue('Path')
        if ($pathVal) {
          $dirs = ($pathVal.ToString().Split(';') | ForEach-Object { $_.Trim() }) | Where-Object { $_ }
          foreach ($dir in $dirs) {
            try { $dir = [Environment]::ExpandEnvironmentVariables($dir) } catch { }
            if ($dir -match '^\s*"(.*)"\s*$') { $dir = $matches[1] }
            if ($dir) {
              Add-Candidate (Join-Path $dir $exe) ("registry-path:" + $k)
              Add-OriginCandidatesFromDir $dir ("registry-sibling:" + $k)
            }
          }
        }
      }
    } catch {
      # ignore
    }
  }
}

function Try-CommonInstallPaths {
  $pfRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
    Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
    Select-Object -Unique

  foreach ($root in $pfRoots) {
    $originLab = Join-Path $root 'OriginLab'
    if (-not (Test-Path -LiteralPath $originLab)) { continue }
    $dirs = Get-ChildItem -Path $originLab -Directory -ErrorAction SilentlyContinue
    foreach ($d in $dirs) {
      Add-Candidate (Join-Path $d.FullName 'Origin64.exe') ('path:' + $d.FullName)
      Add-Candidate (Join-Path $d.FullName 'Origin.exe') ('path:' + $d.FullName)
      Add-Candidate (Join-Path $d.FullName 'OriginPro64.exe') ('path:' + $d.FullName)
      Add-Candidate (Join-Path $d.FullName 'OriginPro.exe') ('path:' + $d.FullName)
      Add-Candidate (Join-Path (Join-Path $d.FullName '64Bit') 'Origin64.exe') ('path:' + $d.FullName)
      Add-Candidate (Join-Path (Join-Path $d.FullName '64Bit') 'OriginPro64.exe') ('path:' + $d.FullName)
    }
  }
}

function Try-Shortcuts {
  $shortcutDirs = @(
    (Join-Path $env:USERPROFILE 'Desktop'),
    (Join-Path $env:PUBLIC 'Desktop'),
    (Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu'),
    (Join-Path $env:ProgramData 'Microsoft\\Windows\\Start Menu')
  ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

  $wsh = $null
  try { $wsh = New-Object -ComObject WScript.Shell } catch { $wsh = $null }
  if (-not $wsh) { return }

  foreach ($dir in $shortcutDirs) {
    $lnks = Get-ChildItem -Path $dir -Recurse -Filter '*Origin*.lnk' -ErrorAction SilentlyContinue
    foreach ($lnk in $lnks) {
      try {
        $sc = $wsh.CreateShortcut($lnk.FullName)
        $target = Normalize-ExePath $sc.TargetPath
        if ($target -match '(?i)\\\\Origin(Pro)?(64)?\\.exe$') {
          Add-Candidate $target ("shortcut:" + $lnk.FullName)
        }
      } catch {
        # ignore
      }
    }
  }
}

function Try-DeepScan {
  $pfRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
    Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
    Select-Object -Unique

  foreach ($root in $pfRoots) {
    $originLab = Join-Path $root 'OriginLab'
    if (-not (Test-Path -LiteralPath $originLab)) { continue }
    $exes = Get-ChildItem -Path $originLab -Recurse -File -Filter 'Origin*.exe' -ErrorAction SilentlyContinue
    foreach ($exe in $exes) {
      if ($exe.Name -match '(?i)^Origin(Pro)?(64)?\\.exe$') {
        Add-Candidate $exe.FullName ('deep:' + $originLab)
      }
    }
  }
}

Try-AppPaths
if ($candidates.Count -gt 0) { Emit-Results }

Try-CommonInstallPaths
if ($candidates.Count -gt 0) { Emit-Results }

Try-Shortcuts
if ($candidates.Count -gt 0) { Emit-Results }

if ($EnableDeepScan) {
  Try-DeepScan
}
Emit-Results
"#;

    let ps = ps.replace(
        "__ENABLE_DEEP_SCAN__",
        if enable_deep_scan { "$true" } else { "$false" },
    );

    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"])
        .arg(ps)
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("Detect origin exe failed: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|e| format!("Invalid detect JSON: {e}"))?;
    Ok(v)
}

#[cfg(not(target_os = "windows"))]
pub fn detect_origin_exe_candidates(_enable_deep_scan: bool) -> Result<serde_json::Value, String> {
    Err("Origin detection is only supported on Windows".to_string())
}
