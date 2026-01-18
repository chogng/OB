//! OriginBridge: local helper for plotting Appointer Origin packages (Windows).
//!
//! This app consumes a local `device_analysis_origin.zip` (downloaded from Appointer's
//! "Export for Origin") and:
//! - extracts the ZIP package to a local work directory
//! - automates Origin via COM (OGS preferred, CSV fallback)
//! - saves a `.opju` project and opens it in Origin UI

mod utils;

#[tauri::command]
fn get_origin_exe_path() -> Result<Option<String>, String> {
    utils::settings::get_origin_exe_path().map(|p| p.map(|p| p.to_string_lossy().to_string()))
}

#[tauri::command]
fn set_origin_exe_path(path: String) -> Result<String, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("Origin executable path is empty".to_string());
    }
    let saved = utils::settings::set_origin_exe_path(std::path::Path::new(path))?;
    Ok(saved.to_string_lossy().to_string())
}

#[tauri::command]
fn clear_origin_exe_path() -> Result<(), String> {
    utils::settings::clear_origin_exe_path()
}

#[tauri::command]
fn detect_origin_exe_candidates(deep_scan: Option<bool>) -> Result<serde_json::Value, String> {
    utils::settings::detect_origin_exe_candidates(deep_scan.unwrap_or(false))
}

#[tauri::command]
fn get_origin_running_process_count() -> Result<u32, String> {
    #[cfg(target_os = "windows")]
    {
        let mut origin_exe = utils::settings::get_origin_exe_path()?;

        if origin_exe.is_none() {
            // Auto-detect if not configured (best-effort).
            let candidates = utils::settings::detect_origin_exe_candidates(false)
                .map_err(|e| format!("Auto-detection failed: {e}"))?;

            if let Some(arr) = candidates.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(path_str) = first.get("path").and_then(|v| v.as_str()) {
                        origin_exe = Some(std::path::PathBuf::from(path_str));
                    }
                }
            }
        }

        if let Some(origin_exe) = origin_exe {
            return Ok(utils::origin::origin_process_count(&origin_exe));
        }

        Ok(0)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(0)
    }
}

#[tauri::command]
fn prelaunch_origin_ui(reuse_origin_ui: Option<bool>) -> Result<bool, String> {
    let reuse_origin_ui = reuse_origin_ui.unwrap_or(true);

    #[cfg(target_os = "windows")]
    {
        let mut origin_exe = utils::settings::get_origin_exe_path()?;

        if origin_exe.is_none() {
            // Auto-detect if not configured (best-effort).
            let candidates = utils::settings::detect_origin_exe_candidates(false)
                .map_err(|e| format!("Auto-detection failed: {e}"))?;

            if let Some(arr) = candidates.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(path_str) = first.get("path").and_then(|v| v.as_str()) {
                        origin_exe = Some(std::path::PathBuf::from(path_str));
                    }
                }
            }
        }

        if let Some(origin_exe) = origin_exe {
            return Ok(utils::origin::prelaunch_origin(&origin_exe, reuse_origin_ui));
        }

        Ok(false)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}

#[tauri::command]
fn extract_zip_and_open_origin(
    zip_path: String,
    save_path: Option<String>,
    reuse_origin_ui: Option<bool>,
    plot_mode: Option<String>,
    worker_kind: Option<String>,
) -> Result<serde_json::Value, String> {
    let zip_path = zip_path.trim();
    if zip_path.is_empty() {
        return Err("ZIP path is empty".to_string());
    }

    let reuse_origin_ui = reuse_origin_ui.unwrap_or(true);

    #[cfg(target_os = "windows")]
    {
        let mut origin_exe = utils::settings::get_origin_exe_path()?;

        if origin_exe.is_none() {
            // Auto-detect if not configured
            let candidates = utils::settings::detect_origin_exe_candidates(false)
                .map_err(|e| format!("Auto-detection failed: {e}"))?;

            if let Some(arr) = candidates.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(path_str) = first.get("path").and_then(|v| v.as_str()) {
                        origin_exe = Some(std::path::PathBuf::from(path_str));
                    }
                }
            }
        }

        let origin_exe = origin_exe.ok_or_else(|| {
            "Origin 可执行文件未配置，且自动检测未找到 Origin，请手动配置。".to_string()
        })?;

        let result = utils::origin::extract_zip_and_launch_origin(
            std::path::Path::new(zip_path),
            &origin_exe,
            save_path,
            reuse_origin_ui,
            plot_mode,
            worker_kind,
        )
        .map_err(|e| format!("Failed to extract and open: {e}"))?;
        return Ok(result);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = zip_path;
        Err("This feature is only supported on Windows".to_string())
    }
}

/// Application entry point.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Normal app launch: show a small "ready" window.
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            get_origin_exe_path,
            set_origin_exe_path,
            clear_origin_exe_path,
            detect_origin_exe_candidates,
            get_origin_running_process_count,
            prelaunch_origin_ui,
            extract_zip_and_open_origin
        ])
        .setup(|_app| Ok(()))
        .run(tauri::generate_context!())
        .expect("error while running OriginBridge");
}
