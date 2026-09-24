fn main() {
    // Windows' System32\comctl32.dll is the legacy 5.82 copy; APIs like
    // TaskDialogIndirect only exist in the Common-Controls v6 side-by-side
    // assembly, which the loader only activates when the binary declares this
    // manifest dependency. Without it the process dies at startup with
    // 0xC0000139 (STATUS_ENTRYPOINT_NOT_FOUND) before main() runs.
    println!(
        "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
    );
    tauri_build::build()
}
