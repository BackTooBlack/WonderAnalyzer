//! WonderAnalyzer — Tauri shell + headless CLI.
//!
//! GUI: commands/events mirror the Electron `window.electronAPI` surface that
//! frontend/js/bridge.js re-implements over Tauri invoke/listen.
//!
//! CLI (release builds are GUI-subsystem binaries; redirect output to a file):
//!   WonderAnalyzer.exe --scan-mods <dir-or-jar> [out.json]
//!   WonderAnalyzer.exe --scan-config <root> [out.json]
//!   WonderAnalyzer.exe --stress-scans <mods-dir> [cfg-root]
//! Unknown `--flags` print usage and exit with code 2 instead of launching
//! the GUI. Without arguments the Tauri GUI starts.

mod config_scanner;
mod malware;
mod obfuscation;
mod patterns_gen;
mod scanner;
mod verifier;

use serde_json::json;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

pub use config_scanner::ConfigScanOutput;
pub use scanner::ScanOutput;

static SCAN_ABORT: AtomicBool = AtomicBool::new(false);
static CONFIG_ABORT: AtomicBool = AtomicBool::new(false);

// ===== window controls =====

#[tauri::command]
fn window_minimize(window: tauri::Window) {
    let _ = window.minimize();
}

#[tauri::command]
fn window_maximize(window: tauri::Window) {
    if window.is_maximized().unwrap_or(false) {
        let _ = window.unmaximize();
    } else {
        let _ = window.maximize();
    }
}

#[tauri::command]
fn window_close(window: tauri::Window) {
    let _ = window.close();
}

// ===== directories =====

#[tauri::command]
fn select_directory(app: tauri::AppHandle) -> Option<String> {
    use tauri_plugin_dialog::DialogExt;
    app.dialog()
        .file()
        .set_directory(default_mods_dir().unwrap_or_default())
        .blocking_pick_folder()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.to_string_lossy().to_string())
}

fn default_mods_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("APPDATA")
        .map(|a| std::path::PathBuf::from(a).join(".minecraft").join("mods"))
}

#[tauri::command]
fn get_default_mods_path() -> serde_json::Value {
    let p = default_mods_dir().unwrap_or_default();
    json!({ "path": p.to_string_lossy(), "exists": p.is_dir() })
}

#[tauri::command]
fn get_appdata_path() -> Option<serde_json::Value> {
    let p = std::env::var_os("APPDATA")?;
    let p = std::path::PathBuf::from(p);
    Some(json!({ "path": p.to_string_lossy(), "exists": p.is_dir() }))
}

// ===== scans =====

#[tauri::command]
fn abort_scan() -> bool {
    SCAN_ABORT.store(true, Ordering::Relaxed);
    true
}

#[tauri::command]
fn abort_config_scan() -> bool {
    CONFIG_ABORT.store(true, Ordering::Relaxed);
    true
}

#[tauri::command]
fn start_scan(app: tauri::AppHandle, dirpath: String) -> serde_json::Value {
    SCAN_ABORT.store(false, Ordering::Relaxed);
    tauri::async_runtime::block_on(async move {
        let res = tauri::async_runtime::spawn_blocking(move || {
            use tauri::Emitter;
            let emitter = app;
            match scanner::scan_directory(Path::new(&dirpath), &SCAN_ABORT, |ev| match ev {
                scanner::ScanEvent::Progress {
                    total,
                    current,
                    phase,
                    current_mod,
                    percent,
                } => {
                    let _ = emitter.emit(
                        "scan-progress",
                        json!({
                            "phase": phase,
                            "current": current,
                            "total": total,
                            "percent": percent,
                            "currentMod": current_mod,
                        }),
                    );
                }
                scanner::ScanEvent::ModScanned { name, analysis } => {
                    let _ = emitter.emit(
                        "mod-scanned",
                        json!({ "name": name, "analysis": analysis }),
                    );
                }
            }) {
                Ok(out) => {
                    let _ = emitter.emit(
                        "scan-complete",
                        json!({ "results": out.results, "summary": out.summary }),
                    );
                    json!({ "success": true })
                }
                Err(e) => json!({ "success": false, "error": e }),
            }
        })
        .await;
        match res {
            Ok(v) => v,
            Err(_) => json!({ "success": false, "error": "scan task panicked" }),
        }
    })
}

#[tauri::command]
fn start_appdata_scan(app: tauri::AppHandle) -> serde_json::Value {
    CONFIG_ABORT.store(false, Ordering::Relaxed);
    let root = match std::env::var_os("APPDATA") {
        Some(r) => std::path::PathBuf::from(r),
        None => return json!({ "success": false, "error": "%APPDATA% folder not found on this system" }),
    };
    if !root.is_dir() {
        return json!({ "success": false, "error": "%APPDATA% folder not found on this system" });
    }

    tauri::async_runtime::block_on(async move {
        let res = tauri::async_runtime::spawn_blocking(move || {
            use tauri::Emitter;
            let emitter = app;
            match config_scanner::scan(&root, &CONFIG_ABORT, |ev| match ev {
                config_scanner::ConfigEvent::Progress {
                    phase,
                    current,
                    total,
                    percent,
                    current_mod,
                    found,
                    critical_count,
                    warning_count,
                } => {
                    let _ = emitter.emit(
                        "config-scan-progress",
                        json!({
                            "phase": phase,
                            "current": current,
                            "total": total,
                            "percent": percent,
                            "currentMod": current_mod,
                            "found": found,
                            "criticalCount": critical_count,
                            "warningCount": warning_count,
                        }),
                    );
                }
                config_scanner::ConfigEvent::Complete { results, summary } => {
                    let _ =
                        emitter.emit("config-scan-complete", json!({ "results": results, "summary": summary }));
                }
            }) {
                Ok(out) => json!({
                    "success": true,
                    "aborted": out.aborted,
                    "results": out.results,
                    "summary": out.summary,
                }),
                Err(e) => json!({ "success": false, "error": e }),
            }
        })
        .await;
        match res {
            Ok(v) => v,
            Err(_) => json!({ "success": false, "error": "scan task panicked" }),
        }
    })
}

// ===== CLI =====

const USAGE: &str = "Usage:
  WonderAnalyzer.exe --scan-mods <dir-or-jar> [out.json]    mod scan → JSON (file, or stdout)
  WonderAnalyzer.exe --scan-config <root> [out.json]        cheat-config scan → JSON (file, or stdout)
  WonderAnalyzer.exe --stress-scans <mods-dir> [cfg-root]   stability harness (15 scans)
Run with no arguments to launch the GUI.";

fn clog(line: &str) {
    let mut err = std::io::stderr();
    let _ = writeln!(err, "{}", line);
}

fn emit_json(value: &serde_json::Value, out: Option<&str>) -> i32 {
    let text = match serde_json::to_string(value) {
        Ok(t) => t,
        Err(e) => {
            clog(&format!("error: serializing results: {}", e));
            return 1;
        }
    };
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, text) {
                clog(&format!("error: writing {}: {}", path, e));
                return 1;
            }
            clog(&format!("wrote {}", path));
            0
        }
        None => {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.write_all(b"\n");
            let _ = stdout.flush();
            0
        }
    }
}

/// Headless entry point. Returns the process exit code.
pub fn run_cli(args: &[String]) -> i32 {
    config_scanner::TRACE.store(true, Ordering::Relaxed);
    let flag = args.first().map(String::as_str).unwrap_or("");

    match flag {
        "--scan-mods" => {
            let Some(dir) = args.get(1) else {
                clog(USAGE);
                return 2;
            };
            let out = args.get(2).map(String::as_str);
            SCAN_ABORT.store(false, Ordering::Relaxed);
            let res = scanner::scan_directory(Path::new(dir), &SCAN_ABORT, |ev| {
                if let scanner::ScanEvent::ModScanned { name, analysis } = ev {
                    clog(&format!(
                        "mod-scanned {} → {} ({})",
                        name, analysis.threat_level, analysis.threat_score
                    ));
                }
            });
            match res {
                Ok(output) => emit_json(
                    &json!({ "results": output.results, "summary": output.summary }),
                    out,
                ),
                Err(e) => {
                    clog(&format!("error: {}", e));
                    1
                }
            }
        }
        "--scan-config" => {
            let Some(root) = args.get(1) else {
                clog(USAGE);
                return 2;
            };
            let out = args.get(2).map(String::as_str);
            CONFIG_ABORT.store(false, Ordering::Relaxed);
            let res = config_scanner::scan(Path::new(root), &CONFIG_ABORT, |ev| {
                if let config_scanner::ConfigEvent::Progress { phase, .. } = ev {
                    clog(&format!("config-scan-progress {}", phase));
                }
            });
            match res {
                Ok(output) => emit_json(
                    &json!({ "results": output.results, "summary": output.summary }),
                    out,
                ),
                Err(e) => {
                    clog(&format!("error: {}", e));
                    1
                }
            }
        }
        "--stress-scans" => {
            let Some(mods_dir) = args.get(1) else {
                clog(USAGE);
                return 2;
            };
            run_stress(Path::new(mods_dir), args.get(2).map(String::as_str))
        }
        other => {
            if other.starts_with('-') {
                clog(USAGE);
                2
            } else {
                // Not a flag: fall back to the GUI (defensive parity).
                run_gui();
                0
            }
        }
    }
}

/// Stability harness: 7 mod scans + 8 config scans = 15, no panics allowed.
fn run_stress(mods_dir: &Path, cfg_root: Option<&str>) -> i32 {
    const MOD_SCANS: usize = 7;
    const CFG_SCANS: usize = 8;

    let cfg_root = cfg_root
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            mods_dir
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| mods_dir.to_path_buf())
        });

    let mut done = 0usize;
    for i in 0..MOD_SCANS {
        SCAN_ABORT.store(false, Ordering::Relaxed);
        match scanner::scan_directory(mods_dir, &SCAN_ABORT, |_| {}) {
            Ok(out) => {
                if out.results.is_empty() {
                    clog(&format!("STRESS_FAIL: mod scan {} returned no results", i));
                    return 1;
                }
                done += 1;
            }
            Err(e) => {
                clog(&format!("STRESS_FAIL: mod scan {}: {}", i, e));
                return 1;
            }
        }
    }
    if cfg_root.is_dir() {
        for i in 0..CFG_SCANS {
            CONFIG_ABORT.store(false, Ordering::Relaxed);
            match config_scanner::scan(&cfg_root, &CONFIG_ABORT, |_| {}) {
                Ok(_) => done += 1,
                Err(e) => {
                    clog(&format!("STRESS_FAIL: config scan {}: {}", i, e));
                    return 1;
                }
            }
        }
    }
    println!("STRESS_PASS ({} scans)", done);
    0
}

// ===== GUI =====

/// Best-effort probe for a WebView2 runtime, mirroring the places the
/// WebView2Loader itself looks. Microsoft ended WebView2 support for Windows
/// 7 at runtime 109 (January 2023), so there the evergreen
/// installer may simply be absent — better to say so than to crash inside
/// `tauri::Builder::run`. On Windows 10/11 the runtime ships with the OS and
/// this always returns true.
#[cfg(windows)]
fn webview2_runtime_present() -> bool {
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    // WebView2 Evergreen runtime client GUID (EdgeUpdate `Clients` key).
    const GUID: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as isize;
    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as isize;
    const RRF_RT_REG_SZ: u32 = 0x02;
    const ERROR_SUCCESS: i32 = 0;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            hkey: isize,
            lpsubkey: *const u16,
            lpvalue: *const u16,
            dwflags: u32,
            pdwtype: *mut u32,
            pvdata: *mut std::ffi::c_void,
            pcbdata: *mut u32,
        ) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    /// True when `hive\subkey` has a non-empty, non-uninstall `pv` string.
    fn reg_client_present(hive: isize, subkey: &str) -> bool {
        let sub = wide(subkey);
        let val = wide("pv");
        let mut buf = [0u16; 64];
        let mut typ = 0u32;
        let mut len = (buf.len() * 2) as u32;
        let rc = unsafe {
            RegGetValueW(
                hive,
                sub.as_ptr(),
                val.as_ptr(),
                RRF_RT_REG_SZ,
                &mut typ,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return false;
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let s: String = String::from_utf16_lossy(&buf[..n]);
        !s.is_empty() && s != "0.0.0.0"
    }

    // 1. Fixed-version override (how people run WebView2 109 on Win7).
    for var in ["WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", "WEBVIEW2_RELEASE_CHANNEL_FOLDER"] {
        if let Ok(dir) = std::env::var(var) {
            if PathBuf::from(&dir).is_dir() {
                return true;
            }
        }
    }
    // 2. Evergreen client keys: HKLM/HKCU, 64-bit and WOW6432Node views.
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        for view in ["SOFTWARE", "SOFTWARE\\WOW6432Node"] {
            if reg_client_present(hive, &format!("{}\\Microsoft\\EdgeUpdate\\Clients\\{}", view, GUID)) {
                return true;
            }
        }
    }
    // 3. Installed runtime directories (machine- and per-user-wide).
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(pf) = std::env::var("ProgramFiles(x86)") {
        dirs.push(PathBuf::from(pf));
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        dirs.push(PathBuf::from(pf));
    }
    if let Ok(pf) = std::env::var("LOCALAPPDATA") {
        dirs.push(PathBuf::from(pf));
    }
    dirs.iter()
        .any(|pf| pf.join("Microsoft").join("EdgeWebView").join("Application").is_dir())
}

#[cfg(not(windows))]
fn webview2_runtime_present() -> bool {
    true
}

#[cfg(windows)]
fn show_webview2_missing_message() {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(
            hwnd: isize,
            lptext: *const u16,
            lpcaption: *const u16,
            utype: u32,
        ) -> i32;
    }

    const MB_OK: u32 = 0x00;
    const MB_ICONWARNING: u32 = 0x10;
    const MB_SETFOREGROUND: u32 = 0x0001_0000;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    let text = concat!(
        "WonderAnalyzer's window needs the Microsoft Edge WebView2 runtime, ",
        "which was not found on this PC.\n\n",
        "Windows 7: only WebView2 version 109 runs there (Microsoft ",
        "ended support in January 2023). Install the \"Fixed Version 109\" ",
        "package from the Microsoft Edge archive:\n",
        "https://developer.microsoft.com/en-us/microsoft-edge/archive/webview2/\n\n",
        "If WebView2 109 is installed in a custom folder, set the ",
        "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER environment variable to that ",
        "folder and start WonderAnalyzer again.\n\n",
        "Scanning works without the GUI: open a command prompt in this ",
        "folder and run\n",
        "  WonderAnalyzer.exe --scan-mods <mods folder> [out.json]\n",
        "  WonderAnalyzer.exe --scan-config <root> [out.json]"
    );
    let caption = "WonderAnalyzer - WebView2 runtime missing";
    unsafe {
        MessageBoxW(
            0,
            wide(text).as_ptr(),
            wide(caption).as_ptr(),
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND,
        );
    }
}

pub fn run_gui() {
    if !webview2_runtime_present() {
        show_webview2_missing_message();
        std::process::exit(3);
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unknown_flag_prints_usage_and_exits_2() {
        assert_eq!(run_cli(&args(&["--definitely-unknown"])), 2);
    }

    #[test]
    fn scan_flags_require_their_path_argument() {
        assert_eq!(run_cli(&args(&["--scan-mods"])), 2);
        assert_eq!(run_cli(&args(&["--scan-config"])), 2);
        assert_eq!(run_cli(&args(&["--stress-scans"])), 2);
    }
}
