#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        std::process::exit(wonder_analyzer::run_cli(&args));
    }
    wonder_analyzer::run_gui();
}
