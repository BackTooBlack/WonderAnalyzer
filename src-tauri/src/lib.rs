//! WonderAnalyzer — Tauri application shell.
//! Exposes the same `electronAPI` surface (via frontend/js/bridge.js) that the
//! Electron preload provided, so the frontend runs unchanged.

pub mod config_scanner;
pub mod malware;
pub mod obfuscation;
pub mod patterns_gen;
pub mod scanner;
pub mod structure;
pub mod verifier;

use serde::Serialize;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tauri::Manager;

/// Handle for a running scan: abort flag + join handle, so a new scan can
/// abort *and wait for* the previous one. Two live scans must never
/// interleave their events (overlapping scans double-counted the live stats).
pub struct ScanHandle {
    pub flag: Arc<AtomicBool>,
    pub join: Option<std::thread::JoinHandle<()>>,
}

pub struct ModScanState(pub Mutex<Option<ScanHandle>>);
pub struct ConfigScanState(pub Mutex<Option<ScanHandle>>);

/// Extract a readable message from a panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// Abort the previous scan and wait (off the async runtime) until its thread
/// has fully exited, then return a fresh flag for the new scan.
async fn reset_scan_slot(slot: &Mutex<Option<ScanHandle>>) -> Arc<AtomicBool> {
    let previous = {
        let mut s = slot.lock().unwrap();
        s.take()
    };
    if let Some(prev) = previous {
        prev.flag.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = prev.join {
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let _ = handle.join();
            })
            .await;
        }
    }
    Arc::new(AtomicBool::new(false))
}

fn default_mods_path() -> String {
    let base = std::env::var("APPDATA")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    std::path::Path::new(&base)
        .join(".minecraft")
        .join("mods")
        .to_string_lossy()
        .to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PathInfo {
    path: String,
    exists: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBundle {
    pub results: Vec<scanner::Analysis>,
    pub summary: scanner::ScanSummary,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartScanResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<ScanBundle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartConfigScanResponse {
    success: bool,
    #[serde(flatten)]
    result: Option<config_scanner::ConfigScanResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ===== Window controls =====

#[tauri::command]
fn window_minimize(app: tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.minimize();
    }
}

#[tauri::command]
fn window_maximize(app: tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        if w.is_maximized().unwrap_or(false) {
            let _ = w.unmaximize();
        } else {
            let _ = w.maximize();
        }
    }
}

#[tauri::command]
fn window_close(app: tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.close();
    }
}

// ===== Directory selection =====

#[tauri::command]
async fn select_directory() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Select Minecraft Mods Folder")
            .set_directory(default_mods_path())
            .pick_folder()
            .map(|p| p.to_string_lossy().to_string())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
fn get_default_mods_path() -> PathInfo {
    let path = default_mods_path();
    PathInfo { exists: std::path::Path::new(&path).exists(), path }
}

// ===== Mod scan =====

#[tauri::command]
async fn start_scan(
    app: tauri::AppHandle,
    state: tauri::State<'_, ModScanState>,
    dirpath: String,
) -> Result<StartScanResponse, String> {
    // Abort AND join any still-running scan first (Electron parity for the
    // abort; joining guarantees scans never interleave their events).
    let flag = reset_scan_slot(&state.0).await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let worker_flag = flag.clone();
    let join = std::thread::spawn(move || {
        // catch_unwind: a panic inside the scan becomes an error response
        // ("internal panic: …") instead of a dead, unexplained thread.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut ms = scanner::ModScanner::new(Some(app), worker_flag);
            ms.scan_directory(&dirpath)
        }))
        .unwrap_or_else(|payload| Err(format!("internal panic: {}", panic_message(payload.as_ref()))));
        let _ = tx.send(result);
    });
    *state.0.lock().unwrap() = Some(ScanHandle { flag, join: Some(join) });

    Ok(match rx.await {
        Ok(Ok((results, summary))) => StartScanResponse {
            success: true,
            results: Some(ScanBundle { results, summary }),
            error: None,
        },
        Ok(Err(error)) => StartScanResponse { success: false, results: None, error: Some(error) },
        Err(_) => StartScanResponse {
            success: false,
            results: None,
            error: Some("Scan thread terminated unexpectedly".into()),
        },
    })
}

#[tauri::command]
fn abort_scan(state: tauri::State<'_, ModScanState>) -> bool {
    // Only set the flag — keep the handle so the *next* scan can join it.
    if let Some(handle) = state.0.lock().unwrap().as_ref() {
        handle.flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    true
}

// ===== %APPDATA% cheat config scan =====

#[tauri::command]
fn get_appdata_path() -> Option<PathInfo> {
    let appdata = std::env::var("APPDATA").ok()?;
    Some(PathInfo { exists: std::path::Path::new(&appdata).exists(), path: appdata })
}

#[tauri::command]
async fn start_appdata_scan(
    app: tauri::AppHandle,
    state: tauri::State<'_, ConfigScanState>,
) -> Result<StartConfigScanResponse, String> {
    let appdata = match std::env::var("APPDATA") {
        Ok(a) if std::path::Path::new(&a).exists() => a,
        _ => {
            return Ok(StartConfigScanResponse {
                success: false,
                result: None,
                error: Some("%APPDATA% folder not found on this system".into()),
            })
        }
    };

    // Abort and join the previous config scan before starting a new one.
    let flag = reset_scan_slot(&state.0).await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let worker_flag = flag.clone();
    let join = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut cs = config_scanner::ConfigScanner::new(Some(app), worker_flag);
            cs.scan(&appdata)
        }))
        .map_err(|payload| format!("internal panic: {}", panic_message(payload.as_ref())));
        let _ = tx.send(result);
    });
    *state.0.lock().unwrap() = Some(ScanHandle { flag, join: Some(join) });

    Ok(match rx.await {
        Ok(Ok(result)) => StartConfigScanResponse { success: true, result: Some(result), error: None },
        Ok(Err(error)) => StartConfigScanResponse { success: false, result: None, error: Some(error) },
        Err(_) => StartConfigScanResponse {
            success: false,
            result: None,
            error: Some("Config scan thread terminated unexpectedly".into()),
        },
    })
}

#[tauri::command]
fn abort_config_scan(state: tauri::State<'_, ConfigScanState>) -> bool {
    if let Some(handle) = state.0.lock().unwrap().as_ref() {
        handle.flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    true
}

// ===== Headless CLI helpers (used by --scan-config / --scan-mods) =====

pub fn cli_scan_config(root: &str) -> config_scanner::ConfigScanResult {
    let scanner = config_scanner::ConfigScanner::new(None, Arc::new(AtomicBool::new(false)));
    let mut scanner = scanner;
    scanner.scan(root)
}

pub fn cli_scan_mods(dir: &str) -> Result<ScanBundle, String> {
    let mut ms = scanner::ModScanner::new(None, Arc::new(AtomicBool::new(false)));
    let (results, summary) = ms.scan_directory(dir)?;
    Ok(ScanBundle { results, summary })
}

/// Headless regression harness: repeatedly run scans in one process.
/// Reproduces the "app closes after 4–5 scans" failure mode — overlapping
/// scan threads and panics are reported instead of killing anything.
pub fn cli_stress_scans(mods_dir: &str, config_root: Option<&str>) -> Result<String, String> {
    let mut log = Vec::new();

    // Phase A: 6 sequential mod scans
    for i in 0..6 {
        cli_scan_mods(mods_dir).map_err(|e| format!("sequential scan {} failed: {}", i + 1, e))?;
        log.push(format!("seq{} ok", i + 1));
    }

    // Phase B: 3 overlapping mod scans (same process, concurrent threads)
    let mut handles = Vec::new();
    for _ in 0..3 {
        let d = mods_dir.to_string();
        handles.push(std::thread::spawn(move || cli_scan_mods(&d)));
    }
    for (i, h) in handles.into_iter().enumerate() {
        match h.join() {
            Ok(Ok(_)) => log.push(format!("par{} ok", i + 1)),
            Ok(Err(e)) => return Err(format!("parallel scan {} error: {}", i + 1, e)),
            Err(_) => return Err(format!("parallel scan {} PANICKED", i + 1)),
        }
    }

    // Phase C: config scans, sequential then overlapping
    if let Some(root) = config_root {
        for i in 0..3 {
            cli_scan_config(root);
            log.push(format!("cfg{} ok", i + 1));
        }
        let mut handles = Vec::new();
        for _ in 0..3 {
            let r = root.to_string();
            handles.push(std::thread::spawn(move || cli_scan_config(&r)));
        }
        for (i, h) in handles.into_iter().enumerate() {
            match h.join() {
                Ok(_) => log.push(format!("cfgpar{} ok", i + 1)),
                Err(_) => return Err(format!("config parallel {} PANICKED", i + 1)),
            }
        }
    }

    Ok(format!("STRESS_PASS ({})", log.join(", ")))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(ModScanState(Mutex::new(None)))
        .manage(ConfigScanState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            window_minimize,
            window_maximize,
            window_close,
            select_directory,
            get_default_mods_path,
            start_scan,
            abort_scan,
            get_appdata_path,
            start_appdata_scan,
            abort_config_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running WonderAnalyzer");
}
