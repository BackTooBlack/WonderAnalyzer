fn main() {
    // The exe imports comctl32!TaskDialogIndirect (Common-Controls v6 only).
    // Without an SxS manifest declaring Microsoft.Windows.Common-Controls 6.0.0.0
    // the loader fails with STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139).
    //
    // tauri-winres' resource.lib only reaches *bin* targets, so unit-test
    // harness exes never receive its manifest. Instead:
    //   - winres embeds resources WITHOUT a manifest (keeps the icon only)
    //   - we embed app.manifest through unprefixed rustc-link-arg, which
    //     applies to every linked target (bins, lib tests, bin tests).
    let attrs = tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new_without_app_manifest(),
    );

    if let Err(error) = tauri_build::try_build(attrs) {
        eprintln!("tauri-build failed: {error:#}");
        std::process::exit(1);
    }

    let manifest = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("app.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
}
