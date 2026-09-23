//! WonderAnalyzer entry point.
//! GUI by default; `--scan-config <dir>` / `--scan-mods <dir>` run headless
//! (used for functional testing of the Rust scanners).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 3 && args[1] == "--scan-config" {
        let result = wonder_analyzer_lib::cli_scan_config(&args[2]);
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("serialize error: {}", e),
        }
        return;
    }

    if args.len() >= 3 && args[1] == "--scan-mods" {
        match wonder_analyzer_lib::cli_scan_mods(&args[2]) {
            Ok(bundle) => match serde_json::to_string_pretty(&bundle) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("serialize error: {}", e),
            },
            Err(e) => eprintln!("error: {}", e),
        }
        return;
    }

    if args.len() >= 3 && args[1] == "--stress-scans" {
        let config_root = args.get(3).map(|s| s.as_str());
        match wonder_analyzer_lib::cli_stress_scans(&args[2], config_root) {
            Ok(msg) => println!("{}", msg),
            Err(e) => {
                eprintln!("STRESS_FAIL: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // An unknown `--flag` must NOT fall through to the GUI: a headless caller
    // would then wait forever on stdout held open by the WebView window.
    if args.len() >= 2 && args[1].starts_with("--") {
        eprintln!(
            "unknown flag: {}\nusage: {} [--scan-config <dir>] [--scan-mods <dir|jar>] [--stress-scans <mods-dir> [<config-root>]]",
            args[1], args[0]
        );
        std::process::exit(2);
    }

    wonder_analyzer_lib::run();
}
