//! Core JAR Scanner Engine — port of backend/scanner.js
//! Reads mods from disk, extracts entries, coordinates all analysis modules.

use crate::malware::{scan_for_malware, MalwareFinding};
use crate::obfuscation::{analyze_obfuscation, ObfuscationAnalysis};
use crate::patterns_gen::{PATTERNS, SUSPICIOUS_FILE_NAME_SOURCES};
use crate::structure::{analyze_structure, StructuralFinding};
use crate::verifier::verify_hash;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tauri::Emitter;

const MAX_TEXT_BYTES: u64 = 50_000; // JS truncates extracted text at 50 000 bytes

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct JarEntry {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TextFile {
    pub file: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StringMatch {
    pub file: String,
    pub pattern_name: String,
    pub category: String,
    pub severity: String,
    #[serde(rename = "type")]
    pub match_type: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMatch {
    pub file: String,
    pub pattern_name: String,
    pub category: String,
    pub severity: String,
    #[serde(rename = "type")]
    pub match_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryItem {
    pub name: String,
    pub severity: String,
    pub file: Option<String>,
    pub context: Option<String>,
    #[serde(rename = "type")]
    pub item_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NestedJar {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FullwidthString {
    pub file: String,
    pub raw: String,
    pub decoded: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub size_formatted: String,
    pub hash: Option<String>,
    pub verified: bool,
    pub verification_source: Option<String>,
    pub mod_loader: String,
    pub mod_version: Option<String>,
    pub mod_author: Option<String>,
    pub mod_id: Option<String>,
    pub threat_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_score: Option<u32>,
    /// Full zip entry list — kept for internal analysis only; the UI reads
    /// totalFiles/totalClasses + match lists, so it is never serialized
    /// (shipping thousands of entries per jar over IPC crashed the WebView
    /// after repeated scans).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<JarEntry>,
    pub categories: BTreeMap<String, Vec<CategoryItem>>,
    pub string_matches: Vec<StringMatch>,
    pub file_matches: Vec<FileMatch>,
    pub structural_findings: Vec<StructuralFinding>,
    pub obfuscation_analysis: Option<ObfuscationAnalysis>,
    pub malware_findings: Vec<MalwareFinding>,
    pub nested_jars: Vec<NestedJar>,
    pub total_classes: usize,
    pub total_files: usize,
    pub suspicious_file_count: usize,
    pub fullwidth_strings: Vec<FullwidthString>,
    pub manifest: Option<BTreeMap<String, String>>,
    pub download_origin: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_config_scan: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub total: usize,
    pub safe: usize,
    pub suspicious: usize,
    pub critical: usize,
    pub obfuscated: usize,
    pub errors: usize,
    pub timestamp: String,
}

pub struct ModScanner {
    /// `None` in headless CLI mode (no events are emitted).
    pub app: Option<tauri::AppHandle>,
    pub aborted: Arc<AtomicBool>,
    pub results: Vec<Analysis>,
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

fn compiled_file_name_patterns() -> &'static Vec<regex::Regex> {
    static CACHE: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    CACHE.get_or_init(|| {
        SUSPICIOUS_FILE_NAME_SOURCES
            .iter()
            .filter_map(|s| regex::Regex::new(s).ok())
            .collect()
    })
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

impl ModScanner {
    pub fn new(app: Option<tauri::AppHandle>, aborted: Arc<AtomicBool>) -> Self {
        ModScanner { app, aborted, results: Vec::new() }
    }

    fn emit(&self, channel: &str, payload: impl Serialize + Clone) {
        if let Some(app) = &self.app {
            let _ = app.emit(channel, payload);
        }
    }

    /// Scan a directory for mod JAR files. Returns (results, summary) or Err(message).
    pub fn scan_directory(&mut self, dir_path: &str) -> Result<(Vec<Analysis>, ScanSummary), String> {
        self.results.clear();

        if !std::path::Path::new(dir_path).is_dir() {
            return Err(format!("Directory not found: {}", dir_path));
        }

        let mut jar_files: Vec<String> = std::fs::read_dir(dir_path)
            .map_err(|_| format!("Directory not found: {}", dir_path))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| n.to_lowercase().ends_with(".jar"))
            .collect();
        jar_files.sort();

        if jar_files.is_empty() {
            return Err("No .jar files found in the selected directory".to_string());
        }

        #[derive(Serialize, Clone)]
        #[serde(rename_all = "camelCase")]
        struct Progress<'a> {
            total: usize,
            current: usize,
            phase: &'a str,
            current_mod: Option<&'a str>,
            percent: usize,
        }

        self.emit("scan-progress", Progress {
            total: jar_files.len(),
            current: 0,
            phase: "Starting scan...",
            current_mod: None,
            percent: 0,
        });

        let total = jar_files.len();
        for (i, file_name) in jar_files.iter().enumerate() {
            if self.aborted.load(Ordering::Relaxed) {
                break;
            }

            let jar_path = std::path::Path::new(dir_path).join(file_name);
            let jar_size = std::fs::metadata(&jar_path).map(|m| m.len()).unwrap_or(0);

            self.emit("scan-progress", Progress {
                total,
                current: i,
                phase: &format!("Scanning {}...", file_name),
                current_mod: Some(file_name),
                percent: ((i as f64 / total as f64) * 100.0).round() as usize,
            });

            let analysis = match self.analyze_mod(&jar_path, file_name, jar_size) {
                Ok(a) => a,
                Err(err) => Analysis {
                    name: file_name.clone(),
                    path: jar_path.to_string_lossy().to_string(),
                    size: jar_size,
                    size_formatted: format_size(jar_size),
                    hash: None,
                    verified: false,
                    verification_source: None,
                    mod_loader: "Unknown".into(),
                    mod_version: None,
                    mod_author: None,
                    mod_id: None,
                    threat_level: "error".into(),
                    threat_score: None,
                    files: vec![],
                    categories: BTreeMap::new(),
                    string_matches: vec![],
                    file_matches: vec![],
                    structural_findings: vec![],
                    obfuscation_analysis: None,
                    malware_findings: vec![],
                    nested_jars: vec![],
                    total_classes: 0,
                    total_files: 0,
                    suspicious_file_count: 0,
                    fullwidth_strings: vec![],
                    manifest: None,
                    download_origin: None,
                    is_config_scan: false,
                    error: Some(err),
                },
            };

            #[derive(Serialize, Clone)]
            struct ModScanned<'a> {
                name: &'a str,
                analysis: &'a Analysis,
            }
            self.emit("mod-scanned", ModScanned { name: file_name, analysis: &analysis });
            self.results.push(analysis);
        }

        let summary = self.generate_summary();

        #[derive(Serialize, Clone)]
        struct Complete {
            results: Vec<Analysis>,
            summary: ScanSummary,
        }
        // An aborted scan (user cancel, or superseded by a new scan) must not
        // broadcast results — the listener may already belong to the next scan.
        if !self.aborted.load(Ordering::Relaxed) {
            self.emit("scan-complete", Complete {
                results: self.results.clone(),
                summary: summary.clone(),
            });
        }

        Ok((self.results.clone(), summary))
    }

    fn analyze_mod(&self, jar_path: &std::path::Path, file_name: &str, file_size: u64) -> Result<Analysis, String> {
        let mut analysis = Analysis {
            name: file_name.to_string(),
            path: jar_path.to_string_lossy().to_string(),
            size: file_size,
            size_formatted: format_size(file_size),
            hash: None,
            verified: false,
            verification_source: None,
            mod_loader: "Unknown".into(),
            mod_version: None,
            mod_author: None,
            mod_id: None,
            threat_level: "safe".into(),
            threat_score: Some(0),
            files: vec![],
            categories: BTreeMap::new(),
            string_matches: vec![],
            file_matches: vec![],
            structural_findings: vec![],
            obfuscation_analysis: None,
            malware_findings: vec![],
            nested_jars: vec![],
            total_classes: 0,
            total_files: 0,
            suspicious_file_count: 0,
            fullwidth_strings: vec![],
            manifest: None,
            download_origin: None,
            is_config_scan: false,
            error: None,
        };

        // Step 1: hash (SHA-1, streamed)
        analysis.hash = Some(calculate_sha1(jar_path)?);

        // Step 2: verify against Modrinth (network best-effort)
        if let Some(hash) = &analysis.hash {
            let verification = verify_hash(hash);
            analysis.verified = verification.verified;
            analysis.verification_source = verification.source;
        }

        // Step 3: extract + analyze contents
        let jar_contents = extract_jar_contents(jar_path)?;

        analysis.total_files = jar_contents.entries.len();
        analysis.total_classes = jar_contents.entries.iter().filter(|e| e.name.ends_with(".class")).count();
        analysis.nested_jars = jar_contents.nested_jars.clone();
        // analysis.files intentionally left empty — events must stay small.

        // Step 4: manifest
        if let Some(manifest_content) = &jar_contents.manifest {
            let props = parse_manifest(manifest_content);
            analysis.mod_version = props
                .get("Implementation-Version")
                .or_else(|| props.get("Specification-Version"))
                .cloned();
            analysis.mod_author = props.get("Created-By").cloned();
            analysis.manifest = Some(props);
        }

        // Step 5-7
        analysis.file_matches = match_file_patterns(&jar_contents.entries);
        analysis.string_matches = match_string_patterns(&jar_contents.text_content);
        analysis.fullwidth_strings = detect_fullwidth(&jar_contents.text_content);

        // Step 8: nested JAR structural finding
        if !jar_contents.nested_jars.is_empty() {
            analysis.structural_findings.push(StructuralFinding {
                finding_type: "nested_jars".into(),
                value: None,
                severity: "warning".into(),
                message: format!("Found {} nested JAR(s) inside META-INF/jars/", jar_contents.nested_jars.len()),
                details: Some(serde_json::Value::Array(
                    jar_contents.nested_jars.iter().map(|j| serde_json::Value::String(j.name.clone())).collect(),
                )),
            });
        }

        // Step 9-11
        analysis.obfuscation_analysis = Some(analyze_obfuscation(&jar_contents.entries, &jar_contents.text_content));
        analysis.malware_findings = scan_for_malware(&jar_contents.text_content);

        let structural = analyze_structure(&jar_contents.entries, &jar_contents.text_content);
        analysis.mod_loader = structural
            .iter()
            .find(|s| s.finding_type == "mod_loader")
            .and_then(|s| s.value.clone())
            .unwrap_or_else(|| "Unknown".to_string());
        analysis.mod_id = structural
            .iter()
            .find(|s| s.finding_type == "mod_id")
            .and_then(|s| s.value.clone());
        analysis.structural_findings.extend(structural);

        // Step 12-13
        calculate_threat_score(&mut analysis);
        analysis.categories = categorize_findings(&analysis);
        analysis.suspicious_file_count = analysis.file_matches.len() + analysis.string_matches.len() + analysis.malware_findings.len();

        Ok(analysis)
    }

    fn generate_summary(&self) -> ScanSummary {
        let total = self.results.len();
        let safe = self.results.iter().filter(|r| r.verified || r.threat_level == "safe").count();
        let suspicious = self
            .results
            .iter()
            .filter(|r| r.threat_level == "suspicious" || r.threat_level == "warning")
            .count();
        let critical = self.results.iter().filter(|r| r.threat_level == "critical").count();
        let obfuscated = self
            .results
            .iter()
            .filter(|r| r.obfuscation_analysis.as_ref().map(|o| o.is_obfuscated).unwrap_or(false))
            .count();
        let errors = self.results.iter().filter(|r| r.threat_level == "error").count();

        ScanSummary { total, safe, suspicious, critical, obfuscated, errors, timestamp: now_iso() }
    }
}

struct JarContents {
    entries: Vec<JarEntry>,
    manifest: Option<String>,
    nested_jars: Vec<NestedJar>,
    text_content: Vec<TextFile>,
}

fn text_entry_regexes() -> &'static Vec<regex::Regex> {
    static CACHE: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    CACHE.get_or_init(|| {
        vec![
            regex::Regex::new(r"(?i)\.(json|txt|cfg|properties|mcmeta|xml|yml|yaml|toml|lang|gradle)$").unwrap(),
            regex::Regex::new(r"(?i)mixin.*\.json$").unwrap(),
            regex::Regex::new(r"(?i)^META-INF/jars/.*\.jar$").unwrap(),
        ]
    })
}

fn extract_jar_contents(jar_path: &std::path::Path) -> Result<JarContents, String> {
    let file = File::open(jar_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;

    let mut entries = Vec::new();
    let mut manifest: Option<String> = None;
    let mut nested_jars = Vec::new();
    let mut text_content = Vec::new();

    for i in 0..archive.len() {
        let mut zf = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = zf.name().to_string();
        let entry = JarEntry {
            name: name.clone(),
            compressed_size: zf.compressed_size(),
            uncompressed_size: zf.size(),
            is_directory: name.ends_with('/'),
        };
        entries.push(entry);

        let is_manifest = name.eq_ignore_ascii_case("META-INF/MANIFEST.MF");
        let is_text = text_entry_regexes()[0].is_match(&name)
            || text_entry_regexes()[1].is_match(&name)
            || text_entry_regexes()[2].is_match(&name);

        if is_manifest || is_text {
            let mut buf = Vec::new();
            let mut limited = (&mut zf).take(MAX_TEXT_BYTES);
            let _ = limited.read_to_end(&mut buf);
            let content = String::from_utf8_lossy(&buf).to_string();

            if is_manifest {
                manifest = Some(content.clone());
            }
            if text_entry_regexes()[2].is_match(&name) {
                nested_jars.push(NestedJar { name: name.clone(), size: zf.size() });
            }
            text_content.push(TextFile { file: name, content });
        }
    }

    Ok(JarContents { entries, manifest, nested_jars, text_content })
}

fn calculate_sha1(jar_path: &std::path::Path) -> Result<String, String> {
    let mut file = File::open(jar_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha1::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn parse_manifest(content: &str) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();
    let mut last_key: Option<String> = None;

    for line in content.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with(' ') {
            if let Some(key) = &last_key {
                let entry = props.entry(key.clone()).or_insert_with(String::new);
                entry.push_str(line.trim_start());
            }
        } else if let Some(idx) = line.find(':') {
            if idx > 0 {
                let key = line[..idx].trim().to_string();
                let value = line[idx + 1..].trim().to_string();
                last_key = Some(key.clone());
                props.insert(key, value);
            }
        }
    }
    props
}

fn match_file_patterns(entries: &[JarEntry]) -> Vec<FileMatch> {
    let mut matches = Vec::new();

    for entry in entries {
        if entry.is_directory {
            continue;
        }

        for (idx, re) in compiled_patterns() {
            if re.is_match(&entry.name) {
                let p = &PATTERNS[*idx];
                matches.push(FileMatch {
                    file: entry.name.clone(),
                    pattern_name: p.name.to_string(),
                    category: p.category.to_string(),
                    severity: p.severity.to_string(),
                    match_type: "file_match".into(),
                });
            }
        }

        for re in compiled_file_name_patterns() {
            if re.is_match(&entry.name) {
                matches.push(FileMatch {
                    file: entry.name.clone(),
                    pattern_name: "SuspiciousFileName".into(),
                    category: "📂 Suspicious Files".into(),
                    severity: "medium".into(),
                    match_type: "file_name".into(),
                });
            }
        }
    }

    matches
}

fn match_string_patterns(text_files: &[TextFile]) -> Vec<StringMatch> {
    let mut matches: Vec<StringMatch> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for tf in text_files {
        if tf.content.is_empty() {
            continue;
        }
        let lines: Vec<&str> = tf.content.split('\n').collect();

        for (idx, re) in compiled_patterns() {
            let p = &PATTERNS[*idx];

            if p.category.contains("Fullwidth") {
                if re.is_match(&tf.content) {
                    let key = format!("{}:{}:{}", tf.file, p.name, p.category);
                    if seen.insert(key) {
                        matches.push(StringMatch {
                            file: tf.file.clone(),
                            pattern_name: p.name.to_string(),
                            category: p.category.to_string(),
                            severity: p.severity.to_string(),
                            match_type: "string_match".into(),
                            context: None,
                        });
                    }
                }
                continue;
            }

            if let Some(line) = lines.iter().find(|l| re.is_match(l)) {
                let key = format!("{}:{}:{}", tf.file, p.name, p.category);
                if seen.insert(key) {
                    matches.push(StringMatch {
                        file: tf.file.clone(),
                        pattern_name: p.name.to_string(),
                        category: p.category.to_string(),
                        severity: p.severity.to_string(),
                        match_type: "string_match".into(),
                        context: Some(line.trim().chars().take(200).collect()),
                    });
                }
            }
        }
    }

    matches
}

fn fullwidth_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"[\u{FF21}-\u{FF3A}\u{FF41}-\u{FF5A}\u{FF10}-\u{FF19}]{2,}").unwrap())
}

fn detect_fullwidth(text_files: &[TextFile]) -> Vec<FullwidthString> {
    let mut results = Vec::new();
    for tf in text_files {
        if tf.content.is_empty() {
            continue;
        }
        for m in fullwidth_regex().find_iter(&tf.content) {
            let raw = m.as_str().to_string();
            results.push(FullwidthString {
                file: tf.file.clone(),
                decoded: fullwidth_to_ascii(&raw),
                raw,
            });
        }
    }
    results
}

fn fullwidth_to_ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            if (0xFF01..=0xFF5E).contains(&cp) {
                char::from_u32(cp - 0xFEE0).unwrap_or(c)
            } else if cp == 0x3000 {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn severity_weight_file(sev: &str) -> f64 {
    match sev {
        "critical" => 25.0,
        "high" => 15.0,
        "medium" => 8.0,
        "low" => 3.0,
        _ => 0.0,
    }
}

fn severity_weight_string(sev: &str) -> f64 {
    match sev {
        "critical" => 20.0,
        "high" => 12.0,
        "medium" => 6.0,
        "low" => 2.0,
        _ => 0.0,
    }
}

fn severity_weight_malware(sev: &str) -> f64 {
    match sev {
        "critical" => 35.0,
        "high" => 20.0,
        "medium" => 10.0,
        _ => 0.0,
    }
}

fn calculate_threat_score(analysis: &mut Analysis) {
    if analysis.verified {
        analysis.threat_score = Some(0);
        analysis.threat_level = "safe".into();
        return;
    }

    let mut score = 0.0;

    for m in &analysis.file_matches {
        score += severity_weight_file(&m.severity);
    }
    for m in &analysis.string_matches {
        score += severity_weight_string(&m.severity);
    }
    for f in &analysis.malware_findings {
        score += severity_weight_malware(&f.severity);
    }
    if let Some(obf) = &analysis.obfuscation_analysis {
        score += obf.score as f64 * 0.5;
    }
    score += analysis.nested_jars.len() as f64 * 5.0;
    for f in &analysis.structural_findings {
        if f.severity == "critical" {
            score += 15.0;
        } else if f.severity == "warning" {
            score += 5.0;
        }
    }

    let capped = score.min(100.0).round() as u32;
    analysis.threat_score = Some(capped);
    analysis.threat_level = if capped >= 70 {
        "critical"
    } else if capped >= 45 {
        "suspicious"
    } else if capped >= 20 {
        "warning"
    } else {
        "safe"
    }
    .to_string();
}

fn categorize_findings(analysis: &Analysis) -> BTreeMap<String, Vec<CategoryItem>> {
    let mut categories: BTreeMap<String, Vec<CategoryItem>> = BTreeMap::new();

    let mut add = |category: &str, name: &str, severity: &str, file: &str, context: Option<&str>, item_type: &str| {
        categories.entry(category.to_string()).or_default().push(CategoryItem {
            name: name.to_string(),
            severity: severity.to_string(),
            file: Some(file.to_string()),
            context: context.map(String::from),
            item_type: item_type.to_string(),
        });
    };

    for m in &analysis.file_matches {
        add(&m.category, &m.pattern_name, &m.severity, &m.file, None, &m.match_type);
    }
    for m in &analysis.string_matches {
        add(&m.category, &m.pattern_name, &m.severity, &m.file, m.context.as_deref(), &m.match_type);
    }

    categories
}
