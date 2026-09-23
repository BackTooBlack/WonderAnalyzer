//! %APPDATA% Cheat Config Scanner (launcher-scoped) — port of backend/configScanner.js
//!
//! Discovery of Minecraft launcher folders in %APPDATA%, whitelist of config
//! formats, config-shape gate + cheat signatures.
//!
//! FALSE-POSITIVE HARDENING (v1.2):
//!   * Only content-relevant categories are matched (Java-code categories like
//!     obfuscation/mixins/structural are JAR-only and were misfiring on configs)
//!   * Ambiguous quality-of-life signatures (AutoSort, AutoSprint, Fullbright...)
//!     are treated as WEAK: a single weak hit never flags a file. Flagging
//!     requires >=1 STRONG signature, >=2 distinct weak hits, or a weak hit
//!     plus a cheat-signal filename/folder (cheats/, wurst/, killaura.cfg...)
//!   * Bare cheat module keys (`"scaffold": {...}`, `fly = true`, `esp: 1`)
//!     are detected structurally as weak hits — catches real cheat configs
//!     that avoided flagging before.

use crate::patterns_gen::PATTERNS;
use crate::scanner::{format_size, Analysis, CategoryItem, StringMatch};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tauri::Emitter;

const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;
const MAX_ANALYZE_SIZE: usize = 1024 * 1024;
const MAX_CANDIDATES: usize = 30_000;
const MAX_MATCHES_PER_FILE: usize = 60;

const TEXT_EXTENSIONS: &[&str] = &[
    ".config", ".conf", ".cfg", ".ini", ".txt", ".json", ".yaml", ".yml", ".toml", ".properties",
];
const CONFIG_EXTENSIONS: &[&str] = &[
    ".config", ".cfg", ".conf", ".ini", ".toml", ".properties", ".json", ".yml", ".yaml", ".txt",
];

const LAUNCHER_DIR_NAMES: &[&str] = &[
    ".minecraft", "minecraft", "prismlauncher", "prism launcher", "multimc", "hmcl", ".hmcl",
    "atlauncher", "gdlauncher_next", "gdlauncher", "curseforge", "feather", ".feather",
    "featherclient", "badlion", "badlionclient", "labymod", ".labymod", "modrinth", ".modrinth",
    "tlauncher", ".tlauncher", "skyclient", ".skyclient", "shiginima",
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

const SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", "$recycle.bin", "system volume information", "cache", "caches",
    "code cache", "gpucache", "shadercache", "blob_storage", "service worker", "crashpad",
    "crashdumps", "logs",
];

/// Categories whose signatures make sense for *config file content*.
/// (Java-code categories are excluded — they fired on innocent config text.)
const CONFIG_SCAN_CATEGORIES: &[&str] = &[
    "combat", "crystal", "movement", "visual", "automation", "pvpUtility",
    "antiCheatBypass", "malware", "knownClients", "networkActivity", "fullwidth",
];
/// ClientFiles entries that ARE meaningful in configs.
const CONFIG_SCAN_EXTRA_NAMES: &[&str] = &["ClickGui", "TabGui"];

/// Ambiguous signatures: shared with legit quality-of-life mods/clients.
/// A single weak hit NEVER flags a file — see gating rules in analyze_file().
const WEAK_PATTERN_NAMES: &[&str] = &[
    "AutoSort", "AutoCraft", "AutoSmelt", "AutoFarm", "AutoShear", "AutoTool", "AutoSprint",
    "AutoWalk", "AutoEat", "AutoMine", "AutoFirework", "AutoFish", "AutoGap", "AutoRod",
    "AutoTPA", "AutoPearl", "AutoPot", "AutoDoubleHand", "AutoBridge",
    "Fullbright", "Waypoints", "NewChunks", "XRay", "Tracers", "OutlinePlayers", "HitBoxes",
    "Criticals", "JumpReset", "SprintReset", "NoJumpDelay", "ElytraSpeed", "AutoArmor",
    "BlockHit", "HitSelect", "ComboBreaker", "WTap", "Freelook", "AxeSpam",
];

/// Cheat folder names whose presence corroborates a weak hit.
const CHEAT_PATH_SEGMENTS: &[&str] = &[
    "cheats", "hacked", "wurst", "vape", "liquidbounce", "aristois", "salhack", "horion",
    "impactclient", "kami", "astolfo", "novoline", "inertia", "futureclient",
];

/// Cheat-signal file names (basename must contain one of these).
static SIGNAL_FILENAME_RE: OnceLock<Vec<regex::Regex>> = OnceLock::new();
fn signal_filename_res() -> &'static Vec<regex::Regex> {
    SIGNAL_FILENAME_RE.get_or_init(|| {
        ["hack", "cheat", "bypass", "kill.?aura", "aim.?assist", "aimbot", "auto.?click",
         "scaffold", "exploit", "click.?gui", "esp", "aura", "velocity", "nuker"]
            .iter()
            .map(|s| regex::Regex::new(&format!("(?i){}", s)).unwrap())
            .collect()
    })
}

/// Bare cheat-module keys inside configs: `"scaffold": {...}`, `fly = true`, `esp: 1`.
/// Detected structurally; counted as WEAK hits (need corroboration).
const MODULE_KEYS: &[&str] = &[
    "scaffold", "fly", "speed", "esp", "velocity", "phase", "jesus", "highjump", "longjump",
    "antivoid", "triggerbot",
];

fn module_key_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let alternation = MODULE_KEYS.join("|");
        regex::RegexBuilder::new(&format!(
            r#"(?i)^\s*"?(?:{})"?\s*[=:]\s*(?:true|false|\{{|"|\d)"#,
            alternation
        ))
        .build()
        .unwrap()
    })
}

fn module_key_capture_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let alternation = MODULE_KEYS.join("|");
        regex::RegexBuilder::new(&format!(r#"(?i)^\s*"?({})"?\s*[=:]"#, alternation))
            .build()
            .unwrap()
    })
}

fn severity_weight(sev: &str) -> u32 {
    match sev {
        "critical" => 40,
        "high" => 25,
        "medium" => 12,
        _ => 5,
    }
}
fn severity_rank(sev: &str) -> u32 {
    match sev {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSummary {
    pub launchers: Vec<String>,
    pub indexed: usize,
    pub analyzed: usize,
    pub found: usize,
    pub critical: usize,
    pub warning: usize,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigScanResult {
    pub results: Vec<Analysis>,
    pub summary: ConfigSummary,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub aborted: bool,
}

struct Structure {
    is_config: bool,
    strength: u32,
}

pub struct ConfigScanner {
    /// `None` in headless CLI mode (no events are emitted).
    app: Option<tauri::AppHandle>,
    aborted: Arc<AtomicBool>,
    findings: Vec<Analysis>,
    scanned: usize,
    critical_count: usize,
    warning_count: usize,
    walked_dirs: usize,
}

fn compiled_patterns() -> &'static Vec<(usize, regex::Regex)> {
    static CACHE: OnceLock<Vec<(usize, regex::Regex)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        PATTERNS
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                regex::RegexBuilder::new(p.source)
                    .case_insensitive(p.ci)
                    .build()
                    .ok()
                    .map(|re| (i, re))
            })
            .collect()
    })
}

fn pattern_eligible(idx: usize) -> bool {
    let p = &PATTERNS[idx];
    if CONFIG_SCAN_CATEGORIES.contains(&p.category_key) {
        true
    } else {
        p.category_key == "clientFiles" && CONFIG_SCAN_EXTRA_NAMES.contains(&p.name)
    }
}

impl ConfigScanner {
    pub fn new(app: Option<tauri::AppHandle>, aborted: Arc<AtomicBool>) -> Self {
        ConfigScanner {
            app,
            aborted,
            findings: Vec::new(),
            scanned: 0,
            critical_count: 0,
            warning_count: 0,
            walked_dirs: 0,
        }
    }

    fn emit(&self, channel: &str, payload: impl Serialize + Clone) {
        if let Some(app) = &self.app {
            let _ = app.emit(channel, payload);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_progress(&self, phase: &str, current: usize, total: usize, percent: usize, current_mod: Option<String>) {
        #[derive(Serialize, Clone)]
        #[serde(rename_all = "camelCase")]
        struct Progress {
            phase: String,
            current: usize,
            total: usize,
            percent: usize,
            current_mod: Option<String>,
            found: usize,
            critical_count: usize,
            warning_count: usize,
        }
        self.emit(
            "config-scan-progress",
            Progress {
                phase: phase.to_string(),
                current,
                total,
                percent,
                current_mod,
                found: self.findings.len(),
                critical_count: self.critical_count,
                warning_count: self.warning_count,
            },
        );
    }

    fn aborted(&self) -> bool {
        self.aborted.load(Ordering::Relaxed)
    }

    pub fn scan(&mut self, root_path: &str) -> ConfigScanResult {
        self.findings.clear();
        self.scanned = 0;
        self.critical_count = 0;
        self.warning_count = 0;
        self.walked_dirs = 0;

        self.emit_progress(&format!("Discovering Minecraft launchers in {}...", root_path), 0, 0, 0, None);

        let launchers = self.discover_launchers(root_path);
        let mut launcher_names: Vec<String> = launchers
            .iter()
            .map(|p| {
                std::path::Path::new(p)
                    .strip_prefix(root_path)
                    .map(|r| r.to_string_lossy().to_string())
                    .unwrap_or_else(|_| p.clone())
            })
            .collect();
        launcher_names.sort();

        if self.aborted() {
            return ConfigScanResult {
                results: vec![],
                summary: self.generate_summary(0, launcher_names),
                aborted: true,
            };
        }

        if launchers.is_empty() {
            self.emit_progress("No Minecraft launchers detected in %APPDATA%", 0, 0, 0, None);
        } else {
            let preview: Vec<&String> = launcher_names.iter().take(3).collect();
            let suffix = if launcher_names.len() > 3 { "..." } else { "" };
            self.emit_progress(
                &format!("Found {} launcher(s): {}{}", launchers.len(), preview.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "), suffix),
                0, 0, 0, None,
            );
        }

        // Phase 2: index config-format candidates
        let mut candidates: Vec<String> = Vec::new();
        for dir in &launchers {
            if self.aborted() {
                break;
            }
            self.walk(dir, &mut candidates, root_path);
        }

        let aborted_early = self.aborted();
        let total = candidates.len();
        let step = (total / 200).max(1);

        // Phase 3: analyze content
        for i in 0..total {
            if self.aborted() {
                break;
            }

            let file_path = candidates[i].clone();
            let rel_display = std::path::Path::new(&file_path)
                .strip_prefix(root_path)
                .map(|r| r.to_string_lossy().to_string())
                .unwrap_or_else(|_| file_path.clone());

            let finding = self.analyze_file(&file_path, &rel_display);
            if let Some(f) = &finding {
                self.findings.push(f.clone());
                if f.threat_level == "critical" {
                    self.critical_count += 1;
                } else {
                    self.warning_count += 1;
                }
            }

            let is_last = i == total - 1;
            if i % step == 0 || finding.is_some() || is_last {
                let done = if is_last && !self.aborted() { 1 } else { 0 };
                self.emit_progress(
                    &format!("Analyzing configs ({}/{})...", i + done, total),
                    i + 1,
                    total,
                    (((i + 1) as f64 / total as f64) * 100.0).round() as usize,
                    Some(rel_display.clone()),
                );
            }
        }

        let summary = self.generate_summary(total, launcher_names);

        if self.aborted() || aborted_early {
            return ConfigScanResult { results: self.findings.clone(), summary, aborted: true };
        }

        #[derive(Serialize, Clone)]
        struct Complete {
            results: Vec<Analysis>,
            summary: ConfigSummary,
        }
        self.emit("config-scan-complete", Complete {
            results: self.findings.clone(),
            summary: summary.clone(),
        });

        ConfigScanResult { results: self.findings.clone(), summary, aborted: false }
    }

    // ===== Launcher discovery =====

    fn discover_launchers(&self, root: &str) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();

        let add = |p: String, found: &mut Vec<String>, seen: &mut BTreeSet<String>| {
            let key = p.to_lowercase();
            if !seen.contains(&key) {
                seen.insert(key);
                found.push(p);
            }
        };

        let entries = match std::fs::read_dir(root) {
            Ok(e) => e,
            Err(_) => return found,
        };

        let dirs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.path())
            .collect();

        for dir in dirs {
            if self.aborted() {
                return found;
            }
            if self.is_launcher_dir(&dir) {
                add(dir.to_string_lossy().to_string(), &mut found, &mut seen);
                continue;
            }
            // Peek one level deeper for nested layouts like Vendor/.minecraft
            if let Ok(subs) = std::fs::read_dir(&dir) {
                for sub in subs.filter_map(|e| e.ok()) {
                    if self.aborted() {
                        return found;
                    }
                    if !sub.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        continue;
                    }
                    let sub_dir = sub.path();
                    if self.is_launcher_dir(&sub_dir) {
                        add(sub_dir.to_string_lossy().to_string(), &mut found, &mut seen);
                    }
                }
            }
        }

        found
    }

    fn is_launcher_dir(&self, dir: &std::path::Path) -> bool {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if LAUNCHER_DIR_NAMES.contains(&name.as_str()) {
            return true;
        }
        for marker in LAUNCHER_MARKER_FILES {
            if let Ok(md) = std::fs::metadata(dir.join(marker)) {
                if md.is_file() {
                    return true;
                }
            }
        }
        let versions = std::fs::metadata(dir.join("versions")).ok();
        let libraries = std::fs::metadata(dir.join("libraries")).ok();
        versions.map(|m| m.is_dir()).unwrap_or(false) && libraries.map(|m| m.is_dir()).unwrap_or(false)
    }

    // ===== File collection =====

    fn walk(&mut self, dir: &str, out: &mut Vec<String>, root: &str) {
        if self.aborted() || out.len() >= MAX_CANDIDATES {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            if self.aborted() || out.len() >= MAX_CANDIDATES {
                return;
            }

            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let full = entry.path();
            let full_str = full.to_string_lossy().to_string();

            if file_type.is_dir() {
                let lower = entry.file_name().to_string_lossy().to_lowercase();
                if SKIP_DIRS.contains(&lower.as_str()) {
                    continue;
                }
                self.walked_dirs += 1;
                if self.walked_dirs % 100 == 0 {
                    self.emit_progress(
                        &format!("Indexing launcher files — {} config file(s) found so far...", out.len()),
                        0, 0, 0,
                        Some(std::path::Path::new(&full_str).strip_prefix(root).map(|r| r.to_string_lossy().to_string()).unwrap_or_else(|_| full_str.clone())),
                    );
                }
                self.walk(&full_str, out, root);
            } else if file_type.is_file() {
                if !is_candidate(&entry.file_name().to_string_lossy()) {
                    continue;
                }
                if let Ok(md) = std::fs::metadata(&full) {
                    if md.is_file() && md.len() > 0 && md.len() <= MAX_FILE_SIZE {
                        out.push(full_str);
                    }
                }
            }
        }
    }

    // ===== Content analysis =====

    fn analyze_file(&mut self, file_path: &str, rel_path: &str) -> Option<Analysis> {
        let buf = std::fs::read(file_path).ok()?;
        self.scanned += 1;

        // Binary sniff
        if buf.contains(&0) {
            return None;
        }

        let mut content = String::from_utf8_lossy(&buf).to_string();
        if content.len() > MAX_ANALYZE_SIZE {
            // char-boundary safe truncation
            let mut end = MAX_ANALYZE_SIZE;
            while end > 0 && !content.is_char_boundary(end) {
                end -= 1;
            }
            content.truncate(end);
        }
        if content.trim().is_empty() {
            return None;
        }

        let ext = std::path::Path::new(file_path)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();

        // Gate 1: config-shaped content
        let structure = analyze_structure(&content, &ext);
        if !structure.is_config {
            return None;
        }

        // Gate 2: cheat signatures with false-positive hardening
        let matches = match_config_patterns(&content);
        if matches.is_empty() {
            return None;
        }

        let strong = matches.iter().filter(|m| !m.weak).count();
        let weak = matches.iter().filter(|m| m.weak).count();
        let basename = std::path::Path::new(file_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let path_l = file_path.to_lowercase();
        let signal_filename = signal_filename_res().iter().any(|re| re.is_match(&basename));
        let signal_path = path_l
            .split(['/', '\\'])
            .any(|seg| CHEAT_PATH_SEGMENTS.contains(&seg));

        let flagged = strong >= 1 || weak >= 2 || (weak >= 1 && (signal_filename || signal_path));
        if !flagged {
            return None;
        }

        Some(self.build_finding(rel_path, file_path, buf.len() as u64, &matches, &structure, &ext, strong, weak, signal_filename))
    }

    fn build_finding(
        &self,
        rel_path: &str,
        file_path: &str,
        size: u64,
        matches: &[ConfigMatch],
        structure: &Structure,
        ext: &str,
        _strong: usize,
        _weak: usize,
        signal_filename: bool,
    ) -> Analysis {
        let mut score: u32 = 0;
        let mut max_severity = "low".to_string();
        for m in matches {
            score += severity_weight(&m.severity);
            if severity_rank(&m.severity) > severity_rank(&max_severity) {
                max_severity = m.severity.clone();
            }
        }
        if structure.strength >= 2 {
            score += 10;
        }
        if signal_filename {
            score += 10;
        }
        score = score.min(100);

        let threat_level = if max_severity == "critical" || score >= 70 {
            "critical"
        } else if max_severity == "high" || score >= 45 {
            "suspicious"
        } else {
            "warning"
        };

        let mut categories: std::collections::BTreeMap<String, Vec<CategoryItem>> = Default::default();
        for m in matches {
            categories.entry(m.category.clone()).or_default().push(CategoryItem {
                name: m.pattern_name.clone(),
                severity: m.severity.clone(),
                file: None,
                context: m.context.clone(),
                item_type: "string_match".into(),
            });
        }

        let string_matches: Vec<StringMatch> = matches
            .iter()
            .map(|m| StringMatch {
                file: String::new(),
                pattern_name: m.pattern_name.clone(),
                category: m.category.clone(),
                severity: m.severity.clone(),
                match_type: "string_match".into(),
                context: m.context.clone(),
            })
            .collect();

        let display_ext = if ext.is_empty() { "no ext".to_string() } else { ext.to_string() };

        Analysis {
            name: rel_path.to_string(),
            path: file_path.to_string(),
            size,
            size_formatted: format_size(size),
            hash: None,
            verified: false,
            verification_source: None,
            mod_loader: format!("Cheat Config ({})", display_ext),
            mod_version: None,
            mod_author: None,
            mod_id: None,
            threat_level: threat_level.to_string(),
            threat_score: Some(score),
            files: vec![],
            categories,
            string_matches,
            file_matches: vec![],
            structural_findings: vec![crate::structure::StructuralFinding {
                finding_type: "config_file".into(),
                value: None,
                severity: "info".into(),
                message: format!("Content is a cheat configuration — {} signature match(es) inside the file", matches.len()),
                details: None,
            }],
            obfuscation_analysis: None,
            malware_findings: vec![],
            nested_jars: vec![],
            total_classes: 0,
            total_files: 0,
            suspicious_file_count: matches.len(),
            fullwidth_strings: vec![],
            manifest: None,
            download_origin: None,
            is_config_scan: true,
            error: None,
        }
    }

    fn generate_summary(&self, indexed: usize, launchers: Vec<String>) -> ConfigSummary {
        ConfigSummary {
            launchers,
            indexed,
            analyzed: self.scanned,
            found: self.findings.len(),
            critical: self.critical_count,
            warning: self.warning_count,
            timestamp: now_iso(),
        }
    }
}

fn is_candidate(file_name: &str) -> bool {
    let lower = file_name.to_lowercase();
    TEXT_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

struct ConfigMatch {
    pattern_name: String,
    category: String,
    severity: String,
    context: Option<String>,
    weak: bool,
}

/// Does the content look like a configuration file?
fn analyze_structure(content: &str, ext: &str) -> Structure {
    let trimmed = content.trim_start();
    let looks_json = trimmed.starts_with('{') || trimmed.starts_with('[');

    let mut json_valid = false;
    if looks_json {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
            if !v.is_null() || content.trim() == "null" {
                json_valid = true;
            }
        }
    }

    static KV_RE: OnceLock<regex::Regex> = OnceLock::new();
    let kv_re = KV_RE.get_or_init(|| {
        regex::Regex::new(r#"(?m)^\s*["'#A-Za-z0-9_\- .]{1,80}["']?\s*[=:]\s*\S.{0,200}"#).unwrap()
    });
    let kv_count = kv_re.find_iter(content).count().min(5);

    static INI_RE: OnceLock<regex::Regex> = OnceLock::new();
    let ini_re = INI_RE.get_or_init(|| regex::Regex::new(r"(?m)^\s*\[[^\]\n]{1,100}\]\s*$").unwrap());
    let has_ini_section = ini_re.is_match(content);

    let typed_config = CONFIG_EXTENSIONS.contains(&ext);
    static KW_RE: OnceLock<regex::Regex> = OnceLock::new();
    let kw_re = KW_RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)\b(enabled|disabled|keybind|key\s*bind|bind|module|modules|settings?|toggle[sd]?|categor(y|ies)|mode|active|visible|autoclicker|killaura|reach|cps|scaffold|velocity)\b",
        )
        .unwrap()
    });
    let keyword_hit = kw_re.is_match(content);

    let mut is_config = false;
    let mut strength = 0u32;

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

    Structure { is_config, strength }
}

/// Run eligible cheat signatures line-aware, classify strong vs weak, and
/// detect bare cheat module keys structurally.
fn match_config_patterns(content: &str) -> Vec<ConfigMatch> {
    let mut matches: Vec<ConfigMatch> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let lines: Vec<&str> = content.split('\n').collect();
    let weak_names: BTreeSet<&str> = WEAK_PATTERN_NAMES.iter().copied().collect();

    'outer:    for (idx, re) in compiled_patterns() {
        if !pattern_eligible(*idx) {
            continue;
        }
        if matches.len() >= MAX_MATCHES_PER_FILE {
            break 'outer;
        }
        let p = &PATTERNS[*idx];

        if p.category.contains("Fullwidth") {
            if re.is_match(content) {
                let key = format!("{}:{}", p.name, p.category);
                if seen.insert(key) {
                    matches.push(ConfigMatch {
                        pattern_name: p.name.to_string(),
                        category: p.category.to_string(),
                        severity: p.severity.to_string(),
                        context: None,
                        weak: false,
                    });
                }
            }
            continue;
        }

        if let Some(line) = lines.iter().find(|l| re.is_match(l)) {
            let key = format!("{}:{}", p.name, p.category);
            if seen.insert(key) {
                matches.push(ConfigMatch {
                    pattern_name: p.name.to_string(),
                    category: p.category.to_string(),
                    severity: p.severity.to_string(),
                    context: Some(line.trim().chars().take(200).collect()),
                    weak: weak_names.contains(p.name),
                });
            }
        }
    }

    // Structural bare-module-key detection (weak hits)
    for line in &lines {
        if matches.len() >= MAX_MATCHES_PER_FILE {
            break;
        }
        if module_key_regex().is_match(line) {
            if let Some(caps) = module_key_capture_regex().captures(line) {
                let key = caps[1].to_lowercase();
                let dedup_key = format!("modulekey:{}", key);
                if seen.insert(dedup_key) {
                    matches.push(ConfigMatch {
                        pattern_name: format!("{} (module key)", key),
                        category: "🧩 Module Structure".to_string(),
                        severity: "medium".to_string(),
                        context: Some(line.trim().chars().take(200).collect()),
                        weak: true,
                    });
                }
            }
        }
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> ConfigScanner {
        ConfigScanner::new(None, Arc::new(AtomicBool::new(false)))
    }

    /// Write content to a temp file and run analyze_file; returns Some if flagged.
    fn scan_content(file_name: &str, content: &str) -> Option<Analysis> {
        let dir = std::env::temp_dir().join(format!("wa-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(file_name);
        std::fs::write(&path, content).unwrap();
        let mut s = scanner();
        let res = s.analyze_file(&path.to_string_lossy(), file_name);
        let _ = std::fs::remove_file(&path);
        res
    }

    #[test]
    fn clean_vanilla_options_not_flagged() {
        let content = "lang:en_us\nrenderDistance:8\ngamma:1.0\nenableVsync:true\nfov:80\n";
        assert!(scan_content("options.txt", content).is_none(), "vanilla options.txt must be clean");
    }

    #[test]
    fn single_weak_qos_signature_not_flagged() {
        // AutoSprint alone is a legit quality-of-life mod setting
        let content = "{\n  \"autoSprint\": true,\n  \"autoJump\": false\n}";
        assert!(scan_content("labymod-settings.json", content).is_none(),
            "a single weak QoL signature must not flag a file");
    }

    #[test]
    fn single_weak_in_cfg_not_flagged() {
        let content = "autoSort = true\nsortMode = inventory\n";
        assert!(scan_content("inventorysorter.cfg", content).is_none());
    }

    #[test]
    fn strong_killaura_config_flagged_critical() {
        let content = "KillAura = true\nattackRange = 3.4\ncps = 12\n";
        let f = scan_content("aura.config", content).expect("killaura config must be flagged");
        assert_eq!(f.threat_level, "critical");
        assert!(f.is_config_scan);
    }

    #[test]
    fn killaura_json_module_flagged() {
        let content = "{\"killaura\":{\"enabled\":false,\"keyBind\":\"RSHIFT\"},\"mode\":\"Switch\"}";
        let f = scan_content("modules.json", content).expect("killaura module json must be flagged");
        assert_eq!(f.threat_level, "critical");
    }

    #[test]
    fn two_weak_hits_flagged() {
        let content = "\"scaffold\": {\"enabled\": true}\n\"fly\": {\"enabled\": false}\n";
        let f = scan_content("clientmods.json", content).expect("two weak module keys must flag");
        assert!(f.threat_level == "critical" || f.threat_level == "suspicious" || f.threat_level == "warning");
    }

    #[test]
    fn weak_plus_cheat_filename_flagged() {
        let content = "autoSprint = true\n";
        let f = scan_content("scaffold-helper.txt", content)
            .expect("weak hit + cheat-signal filename must flag");
        assert!(!f.is_config_scan == false); // still a config finding
    }

    #[test]
    fn prose_with_keywords_not_flagged() {
        // matches keywords but is not config-shaped (no key=value / json)
        let content = "I was using killaura in that video and it was so fun\n";
        assert!(scan_content("notes.txt", content).is_none(), "prose is not a config");
    }

    #[test]
    fn java_category_patterns_skipped_in_config_scan() {
        // "module manager" (clientFiles/ModuleSystem) alone used to flag innocent files
        let content = "moduleManager = true\nmoduleName = ExampleMod\n";
        assert!(scan_content("modsettings.txt", content).is_none(),
            "Java-code categories must not flag config files");
    }

    #[test]
    fn aimbot_pattern_new_signature() {
        let content = "aimbot = true\nfov = 90\n";
        let f = scan_content("combat.json", content).expect("aimbot config must be flagged");
        assert_eq!(f.threat_level, "critical");
    }

    #[test]
    fn structure_gate_rejects_binary_junk() {
        let content = "....\x01\x02 not a config at all";
        assert!(scan_content("junk.txt", content).is_none());
    }
}
