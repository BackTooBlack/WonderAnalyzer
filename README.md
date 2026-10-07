# WonderAnalyzer

WonderAnalyzer is a desktop security analyzer for Minecraft. It inspects **mods** for cheats, malware and obfuscation, verifies their hashes against **Modrinth**, and automatically hunts **cheat configuration files** inside the Minecraft launcher folders of your `%APPDATA%`.

A portable `WonderAnalyzer.exe` (~8.6 MB) is included at the repository root — no installer, no dependencies to install.

## Features

**Mod scanner**
- Point it at any mods folder (or a single jar): threat scoring with critical / suspicious / warning / safe levels
- Parses `fabric.mod.json` / Forge metadata (mod id, version, loader, author)
- SHA-1 hash verification against the Modrinth API (with `megabase.vercel.app` fallback)
- Obfuscation detection: string encryption, control-flow tricks, packed/renamed classes
- Malware detection: webhook tokens, credentials theft, injectors, ransomware strings, suspicious native/library loads
- Structural analysis: nested jars, oversized/odd entries, mismatched metadata

**Cheat config scanner (`%APPDATA%`)**
- Discovers Minecraft launcher folders only — `.minecraft`, PrismLauncher, MultiMC, PolyMC, ATLauncher, HMCL, gdlauncher_next, CurseForge, Feather, Badlion, LabyMod, Modrinth, TLauncher, and more — via folder names, launcher marker files, and `versions/`+`libraries/` layout
- Reads only whitelisted config formats: `.config .conf .cfg .ini .txt .json .yaml .yml .toml .properties`
- 300+ cheat signatures with **strong / weak gating**: a file must look like a configuration *and* carry real cheat signal (one strong signature, two distinct weak ones, or a weak hit plus a cheat-signal filename/folder) before it is flagged — clean files stay clean
- Java-code pattern categories (mixins, access transformers, proxies) are excluded from config scans to avoid false positives
- Launcher **logs** (`latest.log`, `log.txt`, up to 32 MB) are scanned for cheat-module evidence — strong signatures only, so chat mentions can never flag a log
- Known **optimizers** (e.g. Marlow's Crystal Optimizer) are never flagged and never listed — clean files are skipped entirely, while the 💎 Optimizers summary chip still reports how many are in use
- **Clean files are skipped**: results contain only real threats — crash/diagnostic reports, official-client files, known optimizers and QoL configs never show up as findings

**UI**
- Modern dark theme: gradient actions, accent-edged result cards, launcher chips, pill filters, live scan counters, detail modal, search

## Quick start

Download or clone the repo and run `WonderAnalyzer.exe`. That's it.

- Portable, statically linked CRT — no VC++ Redistributable required
- Uses the system WebView2 (preinstalled on Windows 11; install the [WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) on older Windows 10)

## Build from source

Prerequisites:

1. [Node.js](https://nodejs.org/)
2. [Rust](https://rustup.rs/) (`rustup`, default stable toolchain)
3. Visual Studio Build Tools 2022 with **Desktop development with C++** and a **Windows SDK**

```bash
npm install
npm run build          # tauri build → src-tauri/target/release/wonder-analyzer.exe
```

**Windows 7 release builds (x64 + x86, the binaries shipped in `dist/`):**

```bash
rustup component add rust-src      # one-time: -Zbuild-std compiles std from source
node scripts/build-win-release.js          # both architectures (default)
node scripts/build-win-release.js x64      # only 64-bit → dist/WonderAnalyzer.exe
node scripts/build-win-release.js x86      # only 32-bit → dist/WonderAnalyzer-x86.exe
```

The script drives stable cargo with `RUSTC_BOOTSTRAP=1` + `-Zbuild-std` + `+crt-static` for the `x86_64-win7-windows-msvc` / `i686-win7-windows-msvc` targets (don't use a nightly toolchain — it hits a MAX_PATH link error in this checkout) and runs `tools/check-win7-compat.js` on every produced exe, failing the build if it would not start on Windows 7.

The legacy Electron build is still available:

```bash
npm run build:electron # electron-builder portable output in dist/
npm start               # run the Electron shell directly
```

## Headless CLI

Release builds are Windows GUI-subsystem binaries, so redirect output to a file:

```bash
WonderAnalyzer.exe --scan-config <root>                 # cheat-config scan, JSON to stdout
WonderAnalyzer.exe --scan-mods <dir-or-jar>             # mod scan, JSON to stdout
WonderAnalyzer.exe --stress-scans <mods-dir> [cfg-root] # stability harness (15 scans)
```

Unknown `--flags` exit with code `2` instead of launching the GUI.

## Windows 7 support

The release binaries in `dist/` are built specifically for **Windows 7 SP1 (64-bit and 32-bit)**:

- `dist/WonderAnalyzer.exe` — x64 (`x86_64-win7-windows-msvc`)
- `dist/WonderAnalyzer-x86.exe` — x86 (`i686-win7-windows-msvc`)

How Win7 compatibility is achieved and verified:

- Rust std is rebuilt from source with `-Zbuild-std` for the tier-3 `*-win7-windows-msvc` targets, so the binaries use Win7-era kernel32 APIs instead of the Win8+ imports (`WaitOnAddress`, `GetSystemTimePreciseAsFileTime`) that make normal builds die with `0xC0000139` before `main()` runs
- The CRT is linked statically (`+crt-static`) — no VC++ Redistributable or KB2999226 needed
- `node tools/check-win7-compat.js <exe>` is a static PE gate run automatically by `node scripts/build-win-release.js [x64|x86]`; it fails the build on any post-Win7 DLL/function import, a dynamic CRT, wrong machine type, or an OS/subsystem version above 6.1
- `node tools/audit-vt-strings.js <exe>` verifies no plaintext signature strings leak into the shipped binary

GUI notes for Windows 7: Microsoft ended WebView2 support at runtime **109** (January 2023), so the GUI needs the "Fixed Version 109" package from the [Microsoft Edge archive](https://developer.microsoft.com/en-us/microsoft-edge/archive/webview2/) (optionally pointed to by `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`). If WebView2 is missing, the app shows a message box with instructions instead of crashing.

**The CLI works on Windows 7 with no extra installs** — `--scan-mods`, `--scan-config`, and `--stress-scans` never touch WebView2.

Windows 8.1 is not a target of this build; only Windows 7 SP1 is verified.

## Development

- `node tools/gen-patterns.js` — regenerates `src-tauri/src/patterns_gen.rs` from `backend/patterns.js`, so the Rust scanners and the legacy JS scanners share one signature database (every regex is validated for Rust compatibility)
- `cargo test --manifest-path src-tauri/Cargo.toml` — 14 unit tests covering the false-positive gating (vanilla configs and QoL files must stay clean) and multibyte/UTF-8 safety
- `node scripts/check-scan.js <scan.json>` / `node scripts/check-cfg-scan.js <scan.json>` — end-to-end result checkers used by the verification battery

## Project structure

```
backend/        Legacy JS scanners + the canonical pattern database (patterns.js)
frontend/       HTML/CSS/JS UI (shared by Electron and Tauri via bridge.js)
src-tauri/      Rust port: scanners, verifier, pattern gen, Tauri shell, icons, manifest
tools/          Pattern generator (JS → Rust)
scripts/        Icon generator and E2E checkers
main.js         Electron main process (legacy build)
preload.js      Electron preload (legacy build)
WonderAnalyzer.exe  Portable build of the Tauri app
```

## License

[MIT](LICENSE) © Freebuff
