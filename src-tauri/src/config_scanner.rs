//! WonderAnalyzer — %APPDATA% Cheat Config Scanner (launcher-scoped), Rust
//! port of backend/configScanner.js plus the approved Rust-only additions:
//!   * mods/ is never entered — .jar files are never opened here (jar
//!     analysis belongs to the mod scanner) and its text is never read
//!     (forensics dumps must stay untouched)
//!   * launcher asset stores (assets/indexes|objects|virtual) skipped
//!   * per-line 256 KB cap so minified single-line JSON can't slow the DFA
//!   * comment-line freelook/freecam rule (prose about freecam integration
//!     never flags; an enabled `"freecam": true` still does)
//!   * trusted first-party clients / diagnostic files report as info only
//!   * diagnostic-shaped files (crash-*.txt, rasadhlp.dll, *.dmp) never
//!     contribute matches

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::malware::{engine, is_diagnostic_name};
use crate::scanner::{now_ms, Analysis, CategoryItem, StructuralFinding};

// ===== TRACE (CLI only — the GUI never enables it) =====

pub static TRACE: AtomicBool = AtomicBool::new(false);

macro_rules! trace {
    ($t0:expr, $($arg:tt)*) => {
        if TRACE.load(Ordering::Relaxed) {
            eprintln!("[{:>7.2}s] {}", $t0.elapsed().as_secs_f64(), format!($($arg)*));
        }
    };
}

// ===== constants (parity with configScanner.js) =====

const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;
const MAX_LOG_FILE_SIZE: u64 = 32 * 1024 * 1024;
const MAX_ANALYZE_SIZE: usize = 1024 * 1024;
const MAX_CANDIDATES: usize = 30_000;
const MAX_LINE_CAP: usize = 256_000; // minified single-line JSON safety cap

const TEXT_EXTENSIONS: &[&str] = &[
    ".config", ".conf", ".cfg", ".ini", ".txt", ".json", ".yaml", ".yml", ".toml", ".properties",
    ".log",
];

const CONFIG_EXTENSIONS: &[&str] = &[
    ".config", ".cfg", ".conf", ".ini", ".toml", ".properties", ".json", ".yml", ".yaml", ".txt",
];

const LAUNCHER_DIR_NAMES: &[&str] = &[
    ".minecraft", "minecraft", "prismlauncher", "prism launcher", "multimc", "polymc", "hmcl",
    ".hmcl", "atlauncher", "gdlauncher_next", "gdlauncher", "curseforge", "feather", ".feather",
    "featherclient", "badlion", "badlionclient", "labymod", ".labymod", "modrinth", ".modrinth",
    "tlauncher", ".tlauncher", "skyclient", ".skyclient", "shiginima", "lunarclient",
    ".lunarclient", "lunar client", "feather launcher", "badlion client",
];

const LAUNCHER_MARKER_FILES: &[&str] = &[
    "launcher_profiles.json",
    "minecraftinstances.json",
    "prismlauncher.cfg",
    "multimc.cfg",
    "polymc.cfg",
    "atlauncher.cfg",
    "accounts.json",
];

// NOTE: 'logs' is intentionally NOT skipped — .minecraft/logs/latest.log is
// a scan target (cheat-module evidence in game logs).
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "$recycle.bin",
    "system volume information",
    "cache",
    "caches",
    "code cache",
    "gpucache",
    "shadercache",
    "blob_storage",
    "service worker",
    "crashpad",
    "crashdumps",
    // Electron/browser profile junk (Feather, Badlion, LabyMod launchers):
    "local storage",
    "session storage",
    "network",
    "sentry",
    "partitions",
    "dawngraphitecache",
    "dawnwebgpucache",
    "dawncache",
    "indexeddb",
    "databases",
    "file system",
];

const ARTIFACT_DIR_EXACT_SRC: &[&[u8]] = &[
    &[32,63,52,51,46,50,119,55,59,57,40,53,41],
    &[116,32,63,52,51,46,50,119,55,59,57,40,53,41],
    &[32,63,52,51,46,50],
    &[116,32,63,52,51,46,50],
    &[116,44,59,42,63,57,54,51,63,52,46],
    &[44,59,42,63,57,54,51,63,52,46],
    &[116,44,59,42,63],
    &[44,59,42,63],
    &[45,47,40,41,46],
    &[116,45,47,40,41,46],
];
static ARTIFACT_DIR_EXACT: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    ARTIFACT_DIR_EXACT_SRC.iter().map(|b| crate::malware::decode(b)).collect()
});

const ARTIFACT_EXE_RE_SRC: &[u8] = &[114,101,51,115,114,32,63,52,51,46,50,1,119,5,6,41,7,101,55,59,57,40,53,41,101,38,6,56,44,59,42,63,6,56,38,6,56,45,47,40,41,46,6,56,38,59,40,51,41,46,53,51,41,38,59,51,55,45,59,40,63,38,59,41,46,53,54,60,53,38,52,53,44,53,54,51,52,63,38,42,59,52,62,59,45,59,40,63,38,54,51,43,47,51,62,1,119,5,6,41,7,101,56,53,47,52,57,63,38,40,51,41,63,1,119,5,6,41,7,101,57,54,51,63,52,46,38,62,53,40,46,1,119,5,6,41,7,101,45,59,40,63,38,56,54,63,59,57,50,50,59,57,49,38,41,59,54,1,119,5,6,41,7,101,50,59,57,49,38,50,53,40,51,53,52,38,42,50,53,56,53,41,115];

const CHEAT_MODULE_KEYS_SRC: &[&[u8]] = &[
    &[49,51,54,54,59,47,40,59],
    &[49,51,54,54,122,59,47,40,59],
    &[59,51,55,56,53,46],
    &[59,51,55,122,59,41,41,51,41,46],
    &[46,40,51,61,61,63,40,56,53,46],
    &[41,57,59,60,60,53,54,62],
    &[59,47,46,53,57,40,35,41,46,59,54],
    &[56,63,62,59,47,40,59],
    &[57,50,63,41,46,41,46,63,59,54],
    &[42,59,57,49,63,46,60,54,35],
    &[62,51,41,59,56,54,63,40],
    &[44,63,54,53,57,51,46,35],
    &[63,41,42],
    &[60,54,35],
    &[60,40,63,63,57,59,55],
    &[60,40,63,63,54,53,53,49],
    &[40,63,59,57,50],
    &[34,40,59,35],
    &[46,40,59,57,63,40,41],
    &[60,47,54,54,56,40,51,61,50,46],
    &[56,50,53,42],
    &[52,53,41,54,53,45],
    &[59,47,46,53,60,51,41,50],
    &[59,47,46,53,46,53,46,63,55],
    &[59,47,46,53,57,54,51,57,49,63,40],
    &[41,57,59,60,60,53,54,62,45,59,54,49],
    &[48,63,41,47,41,45,59,54,49],
    &[45,59,46,63,40,45,59,54,49],
    &[52,53,57,54,51,42],
    &[42,50,59,41,63],
    &[52,47,49,63,40],
    &[45,59,54,54,50,59,57,49],
    &[56,54,51,52,49],
    &[54,53,52,61,48,47,55,42],
    &[50,51,61,50,48,47,55,42],
    &[52,53,41,54,53,45,62,53,45,52],
    &[41,42,51,62,63,40,57,54,51,55,56],
];
static CHEAT_MODULE_KEYS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    CHEAT_MODULE_KEYS_SRC.iter().map(|b| crate::malware::decode(b)).collect()
});

const STRONG_KEYS_SRC: &[&[u8]] = &[
    &[49,51,54,54,59,47,40,59],
    &[59,51,55,56,53,46],
    &[46,40,51,61,61,63,40,56,53,46],
    &[41,57,59,60,60,53,54,62],
    &[59,47,46,53,57,40,35,41,46,59,54],
    &[56,63,62,59,47,40,59],
    &[57,50,63,41,46,41,46,63,59,54],
    &[42,59,57,49,63,46,60,54,35],
    &[62,51,41,59,56,54,63,40],
    &[59,47,46,53,57,54,51,57,49,63,40],
];
static STRONG_KEYS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    STRONG_KEYS_SRC.iter().map(|b| crate::malware::decode(b)).collect()
});

const OPTIMIZER_EXPLAINED_PATTERNS: &[&str] = &["CrystalOptimizer"];

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn sev_weight(s: &str) -> u32 {
    match s {
        "critical" => 40,
        "high" => 25,
        "medium" => 12,
        "low" => 5,
        _ => 5,
    }
}

// ===== file-name helpers =====

fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

// XOR-encoded with PATTERN_XOR_KEY (0x5a) — folder-name prefixes, decoded at
// call time so no cheat-tool name sits in the EXE as plaintext (VT).
static ARTIFACT_DIR_PREFIXES_SRC: &[&[u8]] = &[
    &[116,44,59,42,63],       // .vape
    &[32,63,52,51,46,50],     // zenith
    &[116,32,63,52,51,46,50], // .zenith
    &[45,47,40,41,46],        // wurst
    &[116,45,47,40,41,46],    // .wurst
];

fn is_artifact_dir_name(name_lower: &str) -> bool {
    ARTIFACT_DIR_EXACT.iter().any(|d| d.as_str() == name_lower)
        || ARTIFACT_DIR_PREFIXES_SRC
            .iter()
            .any(|p| name_lower.starts_with(&crate::malware::decode(p)))
}

fn verified_client_label(name_lower: &str) -> Option<&'static str> {
    match name_lower {
        ".feather" | "feather" | "featherclient" | "feather launcher" => Some("Feather Client"),
        "lunarclient" | ".lunarclient" | "lunar client" => Some("Lunar Client"),
        "badlion" | "badlionclient" | "badlion client" => Some("Badlion Client"),
        "labymod" | ".labymod" => Some("LabyMod"),
        _ => None,
    }
}

/// Report/forensics tool output folders — never read.
fn is_report_artifact_dir(lower: &str) -> bool {
    lower.contains("precisionscan") || lower.contains("mod-forensics") || lower.contains("forensics-report")
}

fn is_log_name(lower: &str) -> bool {
    lower.ends_with(".log") || lower == "log.txt" || lower == "logs.txt"
}

fn is_diagnostic_file(lower: &str) -> bool {
    is_diagnostic_name(lower)
}

fn is_candidate_ext(lower_name: &str) -> bool {
    let ext = match lower_name.rfind('.') {
        Some(i) => &lower_name[i..],
        None => return false,
    };
    TEXT_EXTENSIONS.contains(&ext)
}

fn file_ext(lower_name: &str) -> &str {
    match lower_name.rfind('.') {
        Some(i) => &lower_name[i..],
        None => "",
    }
}

fn detect_optimizer(file_name: &str, content: &str) -> Option<&'static str> {
    if file_name.to_ascii_lowercase().contains("marlow")
        || content.to_ascii_lowercase().contains("marlow")
    {
        return Some("Marlow's Crystal Optimizer");
    }
    None
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

// ===== config-shape gate =====

pub struct StructureInfo {
    pub is_config: bool,
    pub strength: u8,
}

fn analyze_structure(content: &str, ext: &str) -> StructureInfo {
    let trimmed = content.trim_start();
    let looks_json = trimmed.starts_with('{') || trimmed.starts_with('[');

    let mut json_valid = false;
    if looks_json {
        json_valid = serde_json::from_str::<serde_json::Value>(content).is_ok();
    }

    static KV_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?m)^\s*["'#A-Za-z0-9_\-. ]{1,80}["']?\s*[=:]\s*\S.{0,200}"#).unwrap()
    });
    static INI_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?m)^\s*\[[^\]\n]{1,100}\]\s*$").unwrap()
    });
    static KW_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(&crate::malware::decode(&[114,101,51,115,6,56,114,63,52,59,56,54,63,62,38,62,51,41,59,56,54,63,62,38,49,63,35,56,51,52,62,38,49,63,35,6,41,112,56,51,52,62,38,56,51,52,62,38,55,53,62,47,54,63,38,55,53,62,47,54,63,41,38,41,63,46,46,51,52,61,41,101,38,46,53,61,61,54,63,1,41,62,7,101,38,57,59,46,63,61,53,40,114,35,38,51,63,41,115,38,55,53,62,63,38,59,57,46,51,44,63,38,44,51,41,51,56,54,63,38,59,47,46,53,57,54,51,57,49,63,40,38,49,51,54,54,59,47,40,59,38,40,63,59,57,50,38,57,42,41,38,41,57,59,60,60,53,54,62,38,44,63,54,53,57,51,46,35,115,6,56]))
        .unwrap()
    });

    let kv_count = KV_RE.find_iter(content).count().min(5);
    let has_ini_section = INI_RE.is_match(content);
    let typed_config = CONFIG_EXTENSIONS.contains(&ext);
    let keyword_hit = KW_RE.is_match(content);

    let mut is_config = false;
    let mut strength = 0u8;
    if typed_config && (kv_count > 0 || json_valid || has_ini_section) {
        is_config = true;
        strength = 2;
    } else if json_valid {
        is_config = true;
        strength = 2;
    } else if looks_json && kv_count > 0 {
        is_config = true;
        strength = 1;
    } else if kv_count >= 2 {
        is_config = true;
        strength = 1;
    } else if kv_count >= 1 && keyword_hit {
        is_config = true;
        strength = 1;
    } else if has_ini_section && kv_count >= 1 {
        is_config = true;
        strength = 1;
    }

    StructureInfo { is_config, strength }
}

// ===== bare cheat-module keys =====

fn bare_key_matches(content: &str, already_matched: &[crate::malware::Match]) -> Vec<crate::malware::Match> {
    static BARE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?m)^\s*["']?([A-Za-z][A-Za-z0-9_. \-]{0,40})["']?\s*[=:]\s*(.*)$"#).unwrap()
    });
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for caps in BARE_RE.captures_iter(content) {
        let key_raw = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        let value = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        let key_norm: String = key_raw
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        if !CHEAT_MODULE_KEYS.contains(&key_norm) {
            continue;
        }
        let v = value.trim_matches(['"', '\'']).to_ascii_lowercase();
        let falsy = v.is_empty() || v == "false" || v == "0" || v == "off" || v == "null" || v == "[]";
        if falsy && !STRONG_KEYS.contains(&key_norm) {
            continue;
        }
        if seen.contains(&key_norm) {
            continue;
        }
        seen.push(key_norm.clone());
        let dup = already_matched.iter().any(|x| {
            x.pattern_name
                .to_ascii_lowercase()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                == key_norm
        });
        if dup {
            continue;
        }
        let context: String = caps
            .get(0)
            .map(|m| m.as_str().trim().chars().take(160).collect())
            .unwrap_or_default();
        out.push(crate::malware::Match {
            pattern_name: format!("Module:{}", key_raw),
            category: "🧩 Cheat Module Keys".to_string(),
            severity: "medium".to_string(),
            context: Some(context),
            file: None,
            match_type: "struct_bare_key".to_string(),
        });
    }
    out
}

// ===== events / output =====

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSummary {
    pub launchers: Vec<String>,
    pub indexed: usize,
    pub analyzed: usize,
    pub found: usize,
    pub critical: usize,
    pub warning: usize,
    pub optimizers: usize,
    pub artifacts: usize,
    pub clients: usize,
    pub timestamp: u64,
}

pub struct ConfigScanOutput {
    pub results: Vec<Analysis>,
    pub summary: ConfigSummary,
    pub aborted: bool,
}

pub enum ConfigEvent {
    Progress {
        phase: String,
        current: usize,
        total: usize,
        percent: u32,
        current_mod: Option<String>,
        found: usize,
        critical_count: usize,
        warning_count: usize,
    },
    Complete {
        results: Vec<Analysis>,
        summary: ConfigSummary,
    },
}

// ===== scan context =====

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Artifact,
}

struct Candidate {
    path: PathBuf,
    kind: Kind,
}

struct Ctx<'a> {
    abort: &'a AtomicBool,
    emit: &'a mut dyn FnMut(ConfigEvent),
    t0: Instant,
    scanned: usize,
    findings: Vec<Analysis>,
    walked_dirs: usize,
}

impl Ctx<'_> {
    fn aborted(&self) -> bool {
        self.abort.load(Ordering::Relaxed)
    }
    fn progress(&mut self, phase: String, current_mod: Option<String>, current: usize, total: usize) {
        let found = self.findings.iter().filter(|f| f.threat_level != "info").count();
        let critical = self.findings.iter().filter(|f| f.threat_level == "critical").count();
        let warning = self
            .findings
            .iter()
            .filter(|f| f.threat_level == "warning" || f.threat_level == "suspicious")
            .count();
        let percent = if total > 0 {
            (((current + 1) as f64 / total as f64) * 100.0).round() as u32
        } else {
            0
        };
        (self.emit)(ConfigEvent::Progress {
            phase,
            current: current + 1,
            total,
            percent,
            current_mod,
            found,
            critical_count: critical,
            warning_count: warning,
        });
    }
}

// ===== launcher discovery =====

fn is_launcher_dir(dir: &Path) -> bool {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if LAUNCHER_DIR_NAMES.contains(&name.as_str()) {
        return true;
    }
    for marker in LAUNCHER_MARKER_FILES {
        let p = dir.join(marker);
        if p.is_file() {
            return true;
        }
    }
    dir.join("versions").is_dir() && dir.join("libraries").is_dir()
}

fn discover(root: &Path, abort: &AtomicBool) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<PathBuf>) {
    let mut launchers: Vec<PathBuf> = Vec::new();
    let mut artifacts: Vec<PathBuf> = Vec::new();
    let mut root_exes: Vec<PathBuf> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let exe_re = Regex::new(&crate::malware::decode(ARTIFACT_EXE_RE_SRC)).unwrap();

    let top: Vec<PathBuf> = match std::fs::read_dir(root) {
        Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
        Err(_) => return (launchers, artifacts, root_exes),
    };

    for p in &top {
        if abort.load(Ordering::Relaxed) {
            break;
        }
        if p.is_file() {
            let lower = p
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if lower.ends_with(".exe") && exe_re.is_match(&lower) {
                root_exes.push(p.clone());
            }
        }
    }

    for p in &top {
        if abort.load(Ordering::Relaxed) {
            break;
        }
        if !p.is_dir() {
            continue;
        }
        let lower = p
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let key = lower.clone();
        if is_artifact_dir_name(&lower) {
            if !seen.contains(&key) {
                seen.push(key);
                artifacts.push(p.clone());
            }
            continue;
        }
        if is_launcher_dir(p) {
            if !seen.contains(&key) {
                seen.push(key);
                launchers.push(p.clone());
            }
            continue;
        }
        // Peek one level deeper for nested layouts like Vendor/.minecraft
        let subs: Vec<PathBuf> = match std::fs::read_dir(p) {
            Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
            Err(_) => continue,
        };
        for sp in &subs {
            if abort.load(Ordering::Relaxed) {
                break;
            }
            if !sp.is_dir() {
                continue;
            }
            let slower = sp
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if is_artifact_dir_name(&slower) {
                if !seen.contains(&slower) {
                    seen.push(slower.clone());
                    artifacts.push(sp.clone());
                }
            } else if is_launcher_dir(sp) && !seen.contains(&slower) {
                seen.push(slower.clone());
                launchers.push(sp.clone());
            }
        }
    }

    launchers.sort();
    artifacts.sort();
    root_exes.sort();
    (launchers, artifacts, root_exes)
}

// ===== candidate collection =====

fn is_asset_store(full: &Path) -> bool {
    let s = full.to_string_lossy().to_ascii_lowercase();
    let norm = s.replace('\\', "/");
    norm.ends_with("/assets/indexes")
        || norm.ends_with("/assets/objects")
        || norm.ends_with("/assets/virtual")
}

fn walk(
    dir: &Path,
    out: &mut Vec<Candidate>,
    ctx: &mut Ctx,
    in_artifact: bool,
) {
    if ctx.aborted() || out.len() >= MAX_CANDIDATES {
        return;
    }
    let entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => {
            let mut v: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            v.sort();
            v
        }
        Err(_) => return,
    };

    for full in entries {
        if ctx.aborted() || out.len() >= MAX_CANDIDATES {
            return;
        }
        let name = full
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if full.is_dir() {
            let dname = name.to_ascii_lowercase();
            if SKIP_DIRS.contains(&dname.as_str())
                || is_report_artifact_dir(&dname)
                || is_asset_store(&full)
            {
                continue;
            }
            if is_artifact_dir_name(&dname) {
                ctx.walked_dirs += 1;
                walk(&full, out, ctx, true);
                continue;
            }
            if dname == "mods" {
                // mods/ belongs to the mod scanner: jars are never opened
                // here and its text files (forensics dumps) are never read
                continue;
            }
            ctx.walked_dirs += 1;
            if ctx.walked_dirs % 100 == 0 {
                ctx.progress(
                    format!(
                        "Indexing launcher files — {} config file(s) found so far...",
                        out.len()
                    ),
                    Some(full.to_string_lossy().to_string()),
                    0,
                    0,
                );
            }
            walk(&full, out, ctx, in_artifact);
        } else if full.is_file() {
            let lower = name.to_ascii_lowercase();
            if !in_artifact && !is_candidate_ext(&lower) {
                continue;
            }
            let is_log = is_log_name(&lower);
            match std::fs::metadata(&full) {
                Ok(md) => {
                    let max = if is_log {
                        MAX_LOG_FILE_SIZE
                    } else {
                        MAX_FILE_SIZE
                    };
                    if !md.is_file() || md.len() == 0 || md.len() > max {
                        continue;
                    }
                }
                Err(_) => continue,
            }
            out.push(Candidate {
                path: full,
                kind: if in_artifact { Kind::Artifact } else { Kind::Text },
            });
        }
    }
}

// ===== content analysis =====

fn read_log_tail(path: &Path) -> std::io::Result<Vec<u8>> {
    let md = std::fs::metadata(path)?;
    if md.len() <= MAX_ANALYZE_SIZE as u64 {
        return std::fs::read(path);
    }
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::End(-(MAX_ANALYZE_SIZE as i64)))?;
    let mut buf = vec![0u8; MAX_ANALYZE_SIZE];
    let mut total = 0usize;
    while total < MAX_ANALYZE_SIZE {
        match f.read(&mut buf[total..MAX_ANALYZE_SIZE]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    buf.truncate(total);
    Ok(buf)
}

fn truncate_to_chars(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn build_finding(
    rel: &str,
    path: &Path,
    size: u64,
    matches: Vec<crate::malware::Match>,
    strength: u8,
    ext: &str,
    is_log: bool,
) -> Analysis {
    let mut score: u32 = 0;
    let mut max_sev = "low";
    for m in &matches {
        score += sev_weight(&m.severity);
        if sev_rank(&m.severity) > sev_rank(max_sev) {
            max_sev = &m.severity;
        }
    }
    if strength >= 2 {
        score += 10;
    }
    let file_name = base_name(rel);
    if engine().file_name_signal(file_name) {
        score += 10;
    }
    score = score.min(100);

    let threat_level = if max_sev == "critical" || score >= 70 {
        "critical"
    } else if max_sev == "high" || score >= 45 {
        "suspicious"
    } else {
        "warning"
    }
    .to_string();

    let mut categories: BTreeMap<String, Vec<CategoryItem>> = BTreeMap::new();
    for m in &matches {
        categories
            .entry(m.category.clone())
            .or_default()
            .push(CategoryItem {
                name: m.pattern_name.clone(),
                severity: m.severity.clone(),
                file: None,
                context: m.context.clone(),
                item_type: m.match_type.clone(),
            });
    }

    let kind_word = if is_log { "Cheat Log" } else { "Cheat Config" };
    let ext_disp = if ext.is_empty() { "no ext" } else { ext };

    Analysis {
        name: rel.to_string(),
        path: path.to_string_lossy().to_string(),
        size,
        size_formatted: format_size(size),
        hash: None,
        verified: false,
        verification_source: None,
        mod_loader: format!("{} ({})", kind_word, ext_disp),
        mod_version: None,
        mod_author: None,
        mod_id: None,
        threat_level,
        threat_score: score,
        files: vec![],
        categories,
        string_matches: matches,
        file_matches: vec![],
        structural_findings: vec![StructuralFinding {
            finding_type: "config_file".into(),
            severity: "info".into(),
            message: if is_log {
                format!(
                    "Cheat module evidence in game log — {} signature match(es) inside the file",
                    0
                )
            } else {
                format!(
                    "Content is a cheat configuration — {} signature match(es) inside the file",
                    0
                )
            },
            details: None,
        }],
        obfuscation_analysis: None,
        malware_findings: vec![],
        nested_jars: vec![],
        total_classes: 0,
        total_files: 0,
        suspicious_file_count: 0,
        fullwidth_strings: vec![],
        manifest: None,
        download_origin: None,
        is_config_scan: true,
        error: None,
    }
}

fn build_info_finding(
    rel: &str,
    path: &Path,
    size: u64,
    mod_id: &str,
    label: &str,
    message: String,
    matches: Vec<crate::malware::Match>,
) -> Analysis {
    let mut a = build_finding(rel, path, size, matches, 0, "", false);
    a.mod_loader = label.to_string();
    a.mod_id = Some(mod_id.to_string());
    a.threat_level = "info".into();
    a.threat_score = 0;
    a.categories = BTreeMap::new();
    a.structural_findings = vec![StructuralFinding {
        finding_type: mod_id.into(),
        severity: "info".into(),
        message,
        details: None,
    }];
    a.suspicious_file_count = 0;
    a
}

fn build_optimizer_finding(rel: &str, path: &Path, size: u64, ext: &str, optimizer: &str) -> Analysis {
    let mut a = build_finding(rel, path, size, vec![], 0, ext, false);
    a.mod_loader = optimizer.to_string();
    a.mod_id = Some("optimizer".into());
    a.threat_level = "info".into();
    a.threat_score = 0;
    a.categories = BTreeMap::new();
    a.structural_findings = vec![StructuralFinding {
        finding_type: "optimizer".into(),
        severity: "info".into(),
        message: format!(
            "{} detected — a performance optimizer, not a cheat. Reported only so you know which optimizer is in use.",
            optimizer
        ),
        details: None,
    }];
    a.suspicious_file_count = 0;
    a
}

/// Cheat-tool folder / executable discovered by name.
fn build_artifact_finding(rel: &str, abs: &Path, size: u64, label: &str, message: String) -> Analysis {
    let safe_rel = rel.replace('\\', "/");
    let item = CategoryItem {
        name: label.to_string(),
        severity: "critical".into(),
        file: None,
        context: Some(message.clone()),
        item_type: "string_match".into(),
    };
    let mut categories: BTreeMap<String, Vec<CategoryItem>> = BTreeMap::new();
    categories.insert("🎮 Cheat Tool Artifacts".to_string(), vec![item.clone()]);

    Analysis {
        name: safe_rel.clone(),
        path: abs.to_string_lossy().to_string(),
        size,
        size_formatted: format_size(size),
        hash: None,
        verified: false,
        verification_source: None,
        mod_loader: label.to_string(),
        mod_version: None,
        mod_author: None,
        mod_id: Some("artifact".into()),
        threat_level: "critical".into(),
        threat_score: 60,
        files: vec![],
        categories,
        string_matches: vec![crate::malware::Match {
            pattern_name: label.to_string(),
            category: "🎮 Cheat Tool Artifacts".to_string(),
            severity: "critical".into(),
            context: Some(safe_rel),
            file: None,
            match_type: "string_match".into(),
        }],
        file_matches: vec![],
        structural_findings: vec![StructuralFinding {
            finding_type: "artifact".into(),
            severity: "critical".into(),
            message,
            details: None,
        }],
        obfuscation_analysis: None,
        malware_findings: vec![],
        nested_jars: vec![],
        total_classes: 0,
        total_files: 0,
        suspicious_file_count: 1,
        fullwidth_strings: vec![],
        manifest: None,
        download_origin: None,
        is_config_scan: true,
        error: None,
    }
}

fn analyze_text_file(ctx: &mut Ctx, path: &Path, rel: &str, kind: Kind) -> Option<Analysis> {
    let file_name = base_name(rel).to_string();
    let lower_name = file_name.to_ascii_lowercase();
    let is_log = is_log_name(&lower_name);
    let is_diag = is_diagnostic_file(&lower_name);
    let is_artifact = kind == Kind::Artifact;

    // Verified first-party client files: mention only, never a threat
    let mut trusted: Option<&'static str> = None;
    for seg in rel.replace('\\', "/").to_ascii_lowercase().split('/') {
        if let Some(l) = verified_client_label(seg) {
            trusted = Some(l);
            break;
        }
    }

    let buf = if is_log {
        read_log_tail(path).ok()?
    } else {
        std::fs::read(path).ok()?
    };
    ctx.scanned += 1;

    // Binary sniff
    if buf.contains(&0) {
        return None;
    }
    let lossy = String::from_utf8_lossy(&buf);
    let content_owned = truncate_to_chars(&lossy, MAX_ANALYZE_SIZE).to_string();
    let content = content_owned.as_str();
    if content.trim().is_empty() {
        return None;
    }

    let ext = file_ext(&lower_name).to_string();
    let optimizer = detect_optimizer(&file_name, content);

    // Gate 1: config-shape (logs, diagnostics, artifacts, trusted skip it)
    let structure = analyze_structure(content, &ext);
    if !(is_log || is_diag || is_artifact || trusted.is_some()) && !structure.is_config {
        return optimizer.map(|o| build_optimizer_finding(rel, path, buf.len() as u64, &ext, o));
    }

    // Gate 2: cheat signatures
    let mut matches = engine().scan_config(content);
    if !is_log && !is_diag {
        let bare = bare_key_matches(content, &matches);
        matches.extend(bare);
    }
    if optimizer.is_some() {
        matches.retain(|m| !OPTIMIZER_EXPLAINED_PATTERNS.contains(&m.pattern_name.as_str()));
    }
    if is_log {
        matches.retain(|m| m.severity == "critical" || m.severity == "high");
    }
    if matches.is_empty() {
        return optimizer.map(|o| build_optimizer_finding(rel, path, buf.len() as u64, &ext, o));
    }

    // Context-forced outcomes
    if let Some(client) = trusted {
        return Some(build_info_finding(
            rel,
            path,
            buf.len() as u64,
            "client",
            &format!("{} (official files)", client),
            format!(
                "{} ships these files itself — matches are shown as an official-client mention and can never flag as a cheat.",
                client
            ),
            matches,
        ));
    }
    if is_diag {
        return Some(build_info_finding(
            rel,
            path,
            buf.len() as u64,
            "report",
            &format!("Diagnostic Report ({})", if ext.is_empty() { "txt" } else { &ext }),
            format!(
                "{} signature(s) matched inside a crash/diagnostic file — reported as mention only. Crash reports are never flagged as cheat configs.",
                matches.len()
            ),
            matches,
        ));
    }

    // Weak/strong gate: a single QoL name never flags a file
    let strong = matches.iter().any(|m| sev_rank(&m.severity) >= 3);
    let weak = matches.iter().filter(|m| sev_rank(&m.severity) < 3).count();
    let rel_lower = rel.replace('\\', "/").to_ascii_lowercase();
    static SIGNAL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(&crate::malware::decode(&[45,47,40,41,46,38,44,59,42,63,38,32,63,52,51,46,50,38,40,51,41,63,38,57,50,63,59,46,38,50,59,57,49,63,62,38,50,59,57,49,38,63,34,42,54,53,51,46,38,51,55,42,59,57,46])).unwrap()
    });
    let signal = engine().file_name_signal(&file_name) || SIGNAL_RE.is_match(&rel_lower);
    let pass = if is_artifact {
        !matches.is_empty()
    } else {
        strong || weak >= 2 || (weak >= 1 && signal)
    };
    if !pass {
        return optimizer.map(|o| build_optimizer_finding(rel, path, buf.len() as u64, &ext, o));
    }

    let match_count = matches.len();
    let mut finding = build_finding(
        rel,
        path,
        buf.len() as u64,
        matches,
        structure.strength,
        &ext,
        is_log,
    );
    // message parity with JS (counts the real match total)
    if let Some(sf) = finding.structural_findings.first_mut() {
        sf.message = if is_log {
            format!(
                "Cheat module evidence in game log — {} signature match(es) inside the file",
                match_count
            )
        } else {
            format!(
                "Content is a cheat configuration — {} signature match(es) inside the file",
                match_count
            )
        };
    }
    finding.suspicious_file_count = match_count;
    if is_artifact {
        finding.mod_id = Some("artifact".into());
        finding.mod_loader = format!(
            "Cheat Tool Artifact ({})",
            if ext.is_empty() { "no ext" } else { &ext }
        );
    }
    Some(finding)
}

// ===== top-level scan =====

fn rel_of(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .map(|r| r.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| p.to_string_lossy().replace('\\', "/"))
}

pub fn scan(
    root: &Path,
    abort: &AtomicBool,
    mut emit: impl FnMut(ConfigEvent),
) -> Result<ConfigScanOutput, String> {
    if !root.exists() {
        return Err(format!("{} not found", root.display()));
    }
    let t0 = Instant::now();
    let mut ctx = Ctx {
        abort,
        emit: &mut emit,
        t0,
        scanned: 0,
        findings: Vec::new(),
        walked_dirs: 0,
    };

    (ctx.emit)(ConfigEvent::Progress {
        phase: format!("Discovering Minecraft launchers in {}...", root.display()),
        current: 0,
        total: 0,
        percent: 0,
        current_mod: None,
        found: 0,
        critical_count: 0,
        warning_count: 0,
    });

    let (launchers, artifacts, root_exes) = discover(root, abort);
    let launcher_names: Vec<String> = {
        let mut v: Vec<String> = launchers.iter().map(|p| rel_of(root, p)).collect();
        v.sort();
        v
    };

    // Cheat-tool folders always report (even when empty) + root .exe rule
    for dir in &artifacts {
        if ctx.aborted() {
            break;
        }
        let rel = rel_of(root, dir);
        let base = base_name(&rel).to_string();
        let msg = format!(
            "\"{}\" is the data folder of a known cheat tool — detected by folder name",
            base
        );
        let f = build_artifact_finding(&rel, dir, 0, "Cheat Tool Artifact", msg);
        trace!(t0, "artifact-dir {}", rel);
        ctx.findings.push(f);
    }
    for exe in &root_exes {
        if ctx.aborted() {
            break;
        }
        let rel = rel_of(root, exe);
        let base = base_name(&rel).to_string();
        let size = std::fs::metadata(exe).map(|m| m.len()).unwrap_or(0);
        let msg = format!(
            "\"{}\" matches a known cheat tool's executable name",
            base
        );
        let f = build_artifact_finding(&rel, exe, size, "Cheat Tool Executable", msg);
        trace!(t0, "root-exe {}", rel);
        ctx.findings.push(f);
    }

    if ctx.aborted() {
        let summary = generate_summary(&ctx, 0, launcher_names);
        let results = std::mem::take(&mut ctx.findings);
        drop(ctx);
        return Ok(ConfigScanOutput {
            results,
            summary,
            aborted: true,
        });
    }

    (ctx.emit)(ConfigEvent::Progress {
        phase: if launchers.is_empty() {
            "No Minecraft launchers detected in %APPDATA%".to_string()
        } else {
            format!(
                "Found {} launcher(s): {}{}",
                launchers.len(),
                launcher_names.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
                if launcher_names.len() > 3 { "..." } else { "" }
            )
        },
        current: 0,
        total: 0,
        percent: 0,
        current_mod: None,
        found: 0,
        critical_count: 0,
        warning_count: 0,
    });

    // Index candidates
    let mut candidates: Vec<Candidate> = Vec::new();
    for dir in &launchers {
        if ctx.aborted() {
            break;
        }
        walk(dir, &mut candidates, &mut ctx, false);
    }
    for dir in &artifacts {
        if ctx.aborted() {
            break;
        }
        walk(dir, &mut candidates, &mut ctx, true);
    }
    let aborted_early = ctx.aborted();
    let total = candidates.len();
    trace!(t0, "indexed {} candidates in {} launcher(s)", total, launchers.len());

    // Analyze
    let step = (total / 200).max(1);
    for (i, cand) in candidates.iter().enumerate() {
        if ctx.aborted() {
            break;
        }
        let rel = rel_of(root, &cand.path);
        let t_file = Instant::now();
        let finding = analyze_text_file(&mut ctx, &cand.path, &rel, cand.kind);
        trace!(
            t0,
            "analyze {} ({:.2}s){}",
            rel,
            t_file.elapsed().as_secs_f64(),
            if finding.is_some() { " → FLAG" } else { "" }
        );
        let has_finding = finding.is_some();
        if let Some(f) = finding {
            ctx.findings.push(f);
        }
        let is_last = i == total - 1;
        if i % step == 0 || has_finding || is_last {
            ctx.progress(
                format!("Analyzing configs ({}/{})...", if is_last && !ctx.aborted() { i + 1 } else { i }, total),
                Some(rel),
                i,
                total,
            );
        }
    }

    let summary = generate_summary(&ctx, total, launcher_names);
    let aborted = ctx.aborted() || aborted_early;
    trace!(t0, "done: analyzed={} found={}", ctx.scanned, summary.found);
    let results = std::mem::take(&mut ctx.findings);
    drop(ctx);
    if !aborted {
        emit(ConfigEvent::Complete {
            results: results.clone(),
            summary: summary.clone(),
        });
    }
    Ok(ConfigScanOutput {
        results,
        summary,
        aborted,
    })
}

fn generate_summary(ctx: &Ctx, indexed: usize, launchers: Vec<String>) -> ConfigSummary {
    let non_info = |f: &&Analysis| f.threat_level != "info";
    ConfigSummary {
        launchers,
        indexed,
        analyzed: ctx.scanned,
        found: ctx.findings.iter().filter(non_info).count(),
        critical: ctx.findings.iter().filter(|f| f.threat_level == "critical").count(),
        warning: ctx
            .findings
            .iter()
            .filter(|f| f.threat_level == "warning" || f.threat_level == "suspicious")
            .count(),
        optimizers: ctx
            .findings
            .iter()
            .filter(|f| f.threat_level == "info" && f.mod_id.as_deref() == Some("optimizer"))
            .count(),
        artifacts: ctx
            .findings
            .iter()
            .filter(|f| f.mod_id.as_deref() == Some("artifact"))
            .count(),
        clients: ctx
            .findings
            .iter()
            .filter(|f| f.threat_level == "info" && f.mod_id.as_deref() == Some("client"))
            .count(),
        timestamp: now_ms(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn no_abort() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn w(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn make_jar(path: &Path, files: &[(&str, &[u8])]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let f = std::fs::File::create(path).unwrap();
        let mut z = ZipWriter::new(f);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in files {
            z.start_file(*name, opts).unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap();
    }

    /// Full fixture mirroring scripts/make-fixture.js + check-cfg-scan.js.
    fn build_fixture(root: &Path) {
        // .minecraft
        w(root, ".minecraft/options.txt", "lang:en_us\nrenderDistance:8\nfov:0.0\n");
        w(root, ".minecraft/launcher_profiles.json", "{\n  \"profiles\": {},\n  \"version\": 3\n}\n");
        w(root, ".minecraft/config/killaura.config", "KillAura = true\ncps = 14\n");
        w(root, ".minecraft/config/modules.json", "{\n  \"aimbot\": {\"enabled\": true}\n}\n");
        w(root, ".minecraft/config/scaffold-helper.txt", "scaffold = true\nbind = R\n");
        w(root, ".minecraft/config/qol-settings.json", "{\n  \"autoSort\": true\n}\n");
        w(root, ".minecraft/config/inventorysorter.cfg", "autoSort = true\n");
        w(
            root,
            ".minecraft/config/marlows-crystal-optimizer.cfg",
            "Marlow's Crystal Optimizer = enabled\ncrystal optimizer mode = fast\n",
        );
        w(
            root,
            ".minecraft/logs/latest.log",
            "[12:00:00] Joined\n[12:00:01] KillAura module activated\n",
        );
        w(
            root,
            ".minecraft/crash-reports/crash-2026-09-23_10.00.00-client.txt",
            "---- Minecraft Crash Report ----\nfreecam was active during the crash\nrasadhlp.dll: Remote Access AutoDial Helper (Microsoft Corporation)\nA \"killaura\" stack frame\n",
        );
        // mods/: never entered — text unread, jars skipped
        w(root, ".minecraft/mods/scan.log", "killaura aimbot scaffold found\n");
        w(root, ".minecraft/mods/PrecisionScan-x/scan.log", "killaura found\n");
        w(root, ".minecraft/mods/PrecisionScan-x/report.txt", "killaura report\n");
        make_jar(
            &root.join(".minecraft/mods/cheat-zkm.jar"),
            &[
                ("fabric.mod.json", br#"{"id":"zkmcheat","version":"0.1.0"}"#),
                ("zelix/a.class", &[0xca, 0xfe, 0xba, 0xbe, 1, 0, 0, 0]),
                ("klassmaster/b.class", b"junk"),
                ("klassemaster/c.class", b"junk"),
                ("META-INF/zkm.dat", b"zkm"),
                ("klimax/d.class", b"junk"),
                ("zz/e.class", b"junk"),
            ],
        );
        make_jar(
            &root.join(".minecraft/mods/echoclient-1.0.jar"),
            &[("fabric.mod.json", br#"{"id":"echoclient","version":"1.0"}"#)],
        );
        make_jar(
            &root.join(".minecraft/mods/legit-lib.jar"),
            &[
                ("fabric.mod.json", br#"{"id":"sodium","version":"0.6.0"}"#),
                ("net/caffeinemc/sodium/Main.class", &[0xca, 0xfe, 0xba, 0xbe]),
            ],
        );
        // PrismLauncher
        w(root, "PrismLauncher/prismlauncher.cfg", "[General]\ninstDir=instances\n");
        w(root, "PrismLauncher/instances/vanilla/autoSprint.txt", "autoSprint = true\n");
        // Feather (verified client — mention only)
        w(root, ".feather/modules.json", "{\n  \"killaura\": true,\n  \"esp\": true\n}\n");
        // artifacts
        w(root, "zenith-macros/profiles.json", "{\"profile\": \"zenith-macros\"}\n");
        w(root, ".vapeclient/cache", "vapeclient = v4\n");
        w(root, "zenith-macros.exe", "MZ fake executable");
        // non-launcher folder
        w(root, "NotALauncher/cheat.txt", "killaura = true\n");
        // asset store that must be skipped
        w(root, ".minecraft/assets/indexes/9.json", "{\"killaura\": true}\n");
    }

    #[test]
    fn full_fixture_matches_check_cfg_contract() {
        let root = std::env::temp_dir().join("wa_cfg_fixture");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        build_fixture(&root);

        let out = scan(&root, &no_abort(), |_| {}).unwrap();
        let s = &out.summary;
        let norm = |x: &str| x.replace('\\', "/");
        let find = |n: &str| {
            out.results
                .iter()
                .find(|f| norm(&f.name) == n)
                .map(|f| (f.threat_level.clone(), f.threat_score, f.mod_id.clone()))
        };

        assert_eq!(s.launchers.len(), 3, "launchers={:?}", s.launchers);
        assert_eq!(s.indexed, 15, "indexed (jars are not candidates)");
        assert_eq!(s.analyzed, 15, "analyzed (jars are not analyzed)");
        assert_eq!(s.found, 9, "found");
        assert_eq!(s.critical, 8, "critical");
        assert_eq!(s.warning, 1, "warning");
        assert_eq!(s.optimizers, 1, "optimizers");
        assert_eq!(s.artifacts, 5, "artifacts");
        assert_eq!(s.clients, 1, "clients");

        // must flag
        for (n, lvl) in [
            (".minecraft/config/killaura.config", "critical"),
            (".minecraft/config/modules.json", "critical"),
            (".minecraft/config/scaffold-helper.txt", "warning"),
            (".minecraft/logs/latest.log", "critical"),
            ("zenith-macros/profiles.json", "critical"),
            (".vapeclient/cache", "critical"),
            ("zenith-macros", "critical"),
            (".vapeclient", "critical"),
            ("zenith-macros.exe", "critical"),
        ] {
            let got = find(n).unwrap_or_else(|| panic!("MISSING {}", n));
            assert_eq!(got.0, lvl, "{} level", n);
        }

        // exact scores
        assert_eq!(find(".minecraft/config/killaura.config").unwrap().1, 60);
        assert_eq!(find(".minecraft/config/scaffold-helper.txt").unwrap().1, 32);

        // must NOT be flagged at all
        for n in [
            "NotALauncher/cheat.txt",
            ".minecraft/config/qol-settings.json",
            ".minecraft/config/inventorysorter.cfg",
            ".minecraft/options.txt",
            ".minecraft/launcher_profiles.json",
            "PrismLauncher/prismlauncher.cfg",
            "PrismLauncher/instances/vanilla/autoSprint.txt",
            ".minecraft/mods/scan.log",
            ".minecraft/mods/PrecisionScan-x/scan.log",
            ".minecraft/mods/PrecisionScan-x/report.txt",
            ".minecraft/mods/cheat-zkm.jar", // jars never opened by this scanner
            ".minecraft/mods/echoclient-1.0.jar",
            ".minecraft/mods/legit-lib.jar",
            ".minecraft/assets/indexes/9.json",
        ] {
            assert!(
                out.results.iter().all(|f| norm(&f.name) != n),
                "FALSE-POSITIVE {}",
                n
            );
        }

        // contexts
        let crash = out
            .results
            .iter()
            .find(|f| norm(&f.name).contains("crash-2026-09-23"))
            .expect("crash mention");
        assert_eq!(crash.threat_level, "info");
        assert_eq!(crash.mod_id.as_deref(), Some("report"));
        assert_eq!(crash.threat_score, 0);

        let feather = find(".feather/modules.json").expect("feather mention");
        assert_eq!(feather.0, "info");
        assert_eq!(feather.2.as_deref(), Some("client"));
        let feather_full = out
            .results
            .iter()
            .find(|f| norm(&f.name) == ".feather/modules.json")
            .unwrap();
        assert!(feather_full.mod_loader.contains("Feather"));
        assert_eq!(feather_full.threat_score, 0);

        let opt = out
            .results
            .iter()
            .find(|f| f.mod_id.as_deref() == Some("optimizer"))
            .expect("optimizer mention");
        assert!(opt.mod_loader.contains("Marlow"));
        assert_eq!(opt.threat_score, 0);

        // jars are never opened by the config scanner (jar analysis lives in
        // the mod scanner) — no result may reference a .jar at all
        assert!(
            out.results.iter().all(|f| !norm(&f.name).ends_with(".jar")),
            "config scan must never produce jar findings"
        );

        // info entries count (crash + feather + optimizer)
        let infos = out.results.iter().filter(|f| f.threat_level == "info").count();
        assert_eq!(infos, 3, "info entries");

        // category chips available for the UI filter tabs
        let ka = out
            .results
            .iter()
            .find(|f| norm(&f.name) == ".minecraft/config/killaura.config")
            .unwrap();
        assert!(ka.categories.keys().any(|k| k.contains("Combat")));
        assert!(ka.is_config_scan);
    }

    #[test]
    fn discovery_nested_and_root_exe() {
        let root = std::env::temp_dir().join("wa_cfg_disc");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        w(&root, "Vendor/.minecraft/options.txt", "a:1\n");
        w(&root, "Vendor/.minecraft/launcher_profiles.json", "{}\n");
        w(&root, "rise client.exe", "MZ");
        w(&root, "SomeTool/wurst hack.exe", "MZ"); // nested: outside the root-level rule
        w(&root, "plain/notlauncher.txt", "x");
        let (launchers, _, exes) = discover(&root, &no_abort());
        assert_eq!(launchers.len(), 1, "{:?}", launchers);
        assert!(launchers[0]
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with("Vendor/.minecraft"));
        assert_eq!(exes.len(), 1, "root exe rule: {:?}", exes);
        assert!(exes[0]
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with("rise client.exe"));
    }

    #[test]
    fn weak_gate_single_weak_without_signal_stays_clean() {
        let root = std::env::temp_dir().join("wa_cfg_gate");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        w(&root, ".minecraft/launcher_profiles.json", "{}\n");
        // one weak signature, neutral name/path → must not flag
        w(&root, ".minecraft/config/neutral.txt", "fullbright = on\n");
        // one weak + cheat-signal path → flags
        w(&root, ".minecraft/config/hackneutral.txt", "fullbright = on\n");
        let out = scan(&root, &no_abort(), |_| {}).unwrap();
        let norm = |x: &str| x.replace('\\', "/");
        assert!(
            out.results.iter().all(|f| norm(&f.name) != ".minecraft/config/neutral.txt"),
            "single weak w/o signal must stay clean"
        );
        // hackneutral: weak(5? low) + signal → warning… fullbright severity 'low'
        // → weak=1 + signal → passes gate → finding present
        assert!(
            out.results.iter().any(|f| norm(&f.name) == ".minecraft/config/hackneutral.txt"),
            "weak + cheat-signal path must flag"
        );
    }

    #[test]
    fn comment_freecam_never_flags_but_enabled_key_does() {
        let root = std::env::temp_dir().join("wa_cfg_fc");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        w(&root, ".minecraft/launcher_profiles.json", "{}\n");
        w(
            &root,
            ".minecraft/config/voicechat-client.properties",
            "# How listening to other players should work when using freecam mods\nfreelook.enabled=false\n",
        );
        w(&root, ".minecraft/config/freecam-on.json", "\"freecam\": true\n");
        let out = scan(&root, &no_abort(), |_| {}).unwrap();
        let norm = |x: &str| x.replace('\\', "/");
        assert!(
            out.results
                .iter()
                .all(|f| !norm(&f.name).ends_with("voicechat-client.properties")
                    || f.threat_level == "info"),
            "comment-line freecam must not flag voicechat.properties"
        );
        assert!(
            out.results
                .iter()
                .any(|f| norm(&f.name).ends_with("freecam-on.json")),
            "enabled freecam key must flag"
        );
    }
}
