//! Core JAR scanner engine (Rust port of backend/scanner.js + structure.js
//! + malware.js) with the approved scanner fixes:
//!   * boundary-safe class-sample truncation (lossy UTF-8 may not cut at
//!     byte 262144 — walking `cut` down to a char boundary first)
//!   * printable_hay extraction before any class-byte pattern pass
//!   * freelook/freecam never fire on jar content (only real configs/logs)
//!   * diagnostic files (crash-*.txt, hs_err_*, *.dmp, rasadhlp.dll) inside
//!     jars can never threat-flag
//!   * module-info.class never causes a flag
//!   * known-legit manifest ids are never threat-flagged unless ZKM-obfuscated
//!   * hash verification prewarmed in parallel (verifier::prewarm)

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{atomic::AtomicBool, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::malware::{
    engine, is_diagnostic_name, is_known_legit, printable_hay, Match,
};
use crate::obfuscation::{self, ObfuscationAnalysis, ZELIX_MIN_MARKERS};
use crate::verifier;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ===== shapes =====

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryInfo {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NestedJar {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuralFinding {
    #[serde(rename = "type")]
    pub finding_type: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MalwareFinding {
    pub name: String,
    pub severity: String,
    #[serde(rename = "type")]
    pub finding_type: String,
    pub file: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FullwidthHit {
    pub file: String,
    pub raw: String,
    pub decoded: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryItem {
    pub name: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(rename = "type")]
    pub item_type: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_source: Option<String>,
    pub mod_loader: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mod_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mod_author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mod_id: Option<String>,
    pub threat_level: String,
    pub threat_score: u32,
    pub files: Vec<EntryInfo>,
    pub categories: BTreeMap<String, Vec<CategoryItem>>,
    pub string_matches: Vec<Match>,
    pub file_matches: Vec<Match>,
    pub structural_findings: Vec<StructuralFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfuscation_analysis: Option<ObfuscationAnalysis>,
    pub malware_findings: Vec<MalwareFinding>,
    pub nested_jars: Vec<NestedJar>,
    pub total_classes: usize,
    pub total_files: usize,
    pub suspicious_file_count: usize,
    pub fullwidth_strings: Vec<FullwidthHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_origin: Option<serde_json::Value>,
    /// true only for %APPDATA% config-scan findings (UI gates category chips on it)
    #[serde(skip_serializing_if = "is_false")]
    pub is_config_scan: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModSummary {
    pub total: usize,
    pub safe: usize,
    pub suspicious: usize,
    pub critical: usize,
    pub obfuscated: usize,
    pub errors: usize,
    pub timestamp: u64,
}

#[derive(Debug)]
pub struct ScanOutput {
    pub results: Vec<Analysis>,
    pub summary: ModSummary,
}

pub enum ScanEvent {
    Progress {
        total: usize,
        current: usize,
        phase: String,
        current_mod: Option<String>,
        percent: u32,
    },
    ModScanned {
        name: String,
        analysis: Analysis,
    },
}

// ===== shared regexes =====

static TEXT_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(json|txt|cfg|properties|mcmeta|xml|yml|yaml|toml|lang|gradle)$")
        .unwrap()
});
static MIXIN_CONFIG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)mixin.*\.json$").unwrap());
static NESTED_JAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^META-INF/jars/.*\.jar$").unwrap());
static FULLWIDTH_RUN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\x{FF21}-\x{FF3A}\x{FF41}-\x{FF5A}\x{FF10}-\x{FF19}]{2,}").unwrap()
});
static VERSION_DIR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"1\.\d+(\.\d+)?").unwrap());

// ===== malware rules (port of backend/malware.js — one hit per file) =====

// Signature sources/names/types are XOR-encoded (PATTERN_XOR_KEY) and decoded
// once at init — none of this vocabulary may sit in the shipped EXE as
// plaintext (AV string heuristics / VirusTotal).
struct MalwareRule {
    re: Regex,
    name: String,
    severity: &'static str,
    finding_type: String,
}

static MALWARE_RULES: LazyLock<Vec<MalwareRule>> = LazyLock::new(|| {
    let defs: &[(&[u8], bool, &[u8], &'static str, &[u8])] = &[
        // XOR-encoded (PATTERN_XOR_KEY) — decoded once at init so none of this
        // signature vocabulary sits in the shipped EXE as plaintext (VT).
        // code_execution
        (&[8,47,52,46,51,55,63,6,116,61,63,46,8,47,52,46,51,55,63,6,114,6,115,6,116,63,34,63,57,6,41,112,6,114], false, &[8,47,52,46,51,55,63,116,63,34,63,57,114,115], "critical", &[57,53,62,63,5,63,34,63,57,47,46,51,53,52]),
        (&[52,63,45,6,41,113,10,40,53,57,63,41,41,24,47,51,54,62,63,40,6,41,112,6,114], false, &[10,40,53,57,63,41,41,24,47,51,54,62,63,40], "critical", &[57,53,62,63,5,63,34,63,57,47,46,51,53,52]),
        (&[6,116,63,34,63,57,6,41,112,6,114,1,120,125,7,1,4,120,125,7,112,42,53,45,63,40,41,50,63,54,54], true, &[10,53,45,63,40,9,50,63,54,54,122,31,34,63,57,47,46,51,53,52], "critical", &[57,53,62,63,5,63,34,63,57,47,46,51,53,52]),
        (&[6,116,63,34,63,57,6,41,112,6,114,1,120,125,7,1,4,120,125,7,112,57,55,62,6,116,63,34,63], true, &[25,23,30,122,31,34,63,57,47,46,51,53,52], "critical", &[57,53,62,63,5,63,34,63,57,47,46,51,53,52]),
        (&[6,116,63,34,63,57,6,41,112,6,114,1,120,125,7,1,4,120,125,7,112,56,59,41,50], true, &[24,59,41,50,122,31,34,63,57,47,46,51,53,52], "critical", &[57,53,62,63,5,63,34,63,57,47,46,51,53,52]),
        // network_activity
        (&[52,63,45,6,41,113,15,8,22,6,41,112,6,114], false, &[15,8,22,122,25,53,52,52,63,57,46,51,53,52], "high", &[52,63,46,45,53,40,49,5,59,57,46,51,44,51,46,35]),
        (&[18,46,46,42,15,8,22,25,53,52,52,63,57,46,51,53,52,38,18,46,46,42,25,54,51,63,52,46,38,53,42,63,52,25,53,52,52,63,57,46,51,53,52], false, &[18,14,14,10,122,25,54,51,63,52,46], "high", &[52,63,46,45,53,40,49,5,59,57,46,51,44,51,46,35]),
        (&[6,116,42,53,41,46,6,41,112,6,114,38,6,116,61,63,46,6,41,112,6,114,116,112,50,46,46,42], true, &[18,14,14,10,122,8,63,43,47,63,41,46], "high", &[52,63,46,45,53,40,49,5,59,57,46,51,44,51,46,35]),
        (&[60,63,46,57,50,6,41,112,6,114,38,2,23,22,18,46,46,42,8,63,43,47,63,41,46,38,59,34,51,53,41,38,53,49,50,46,46,42], true, &[18,14,14,10,122,28,63,46,57,50], "high", &[52,63,46,45,53,40,49,5,59,57,46,51,44,51,46,35]),
        (&[9,53,57,49,63,46,6,41,112,6,114,38,9,63,40,44,63,40,9,53,57,49,63,46,38,30,59,46,59,61,40,59,55,9,53,57,49,63,46], false, &[8,59,45,122,9,53,57,49,63,46], "critical", &[52,63,46,45,53,40,49,5,59,57,46,51,44,51,46,35]),
        (&[30,59,46,59,21,47,46,42,47,46,9,46,40,63,59,55,116,112,45,40,51,46,63,38,45,40,51,46,63,24,35,46,63,41,116,112,50,46,46,42], true, &[30,59,46,59,122,15,42,54,53,59,62], "critical", &[52,63,46,45,53,40,49,5,59,57,46,51,44,51,46,35]),
        // file_access
        (&[15,41,63,40,6,6,6,6,116,112,27,42,42,30,59,46,59,6,6,6,6,8,53,59,55,51,52,61,6,6,6,6,114,23,51,57,40,53,41,53,60,46,6,6,6,6,13,51,52,62,53,45,41,6,6,6,6,9,46,59,40,46,38,62,51,41,57,53,40,62,38,57,50,40,53,55,63,38,60,51,40,63,60,53,34,38,53,42,63,40,59,38,56,40,59,44,63,115], true, &[27,57,57,63,41,41,51,52,61,122,24,40,53,45,41,63,40,122,30,59,46,59], "critical", &[60,51,54,63,5,59,57,57,63,41,41]),
        (&[6,116,55,51,52,63,57,40,59,60,46,6,6,6,6,114,41,59,44,63,41,38,44,63,40,41,51,53,52,41,38,59,41,41,63,46,41,6,6,6,6,51,52,62,63,34,63,41,38,54,51,56,40,59,40,51,63,41,38,54,59,47,52,57,50,63,40,115], true, &[27,57,57,63,41,41,51,52,61,122,23,51,52,63,57,40,59,60,46,122,28,51,54,63,41], "critical", &[60,51,54,63,5,59,57,57,63,41,41]),
        (&[6,116,41,41,50,6,6,6,6,51,62,5,40,41,59,38,6,116,41,41,50,6,6,6,6,59,47,46,50,53,40,51,32,63,62,5,49,63,35,41], true, &[27,57,57,63,41,41,51,52,61,122,9,9,18,122,17,63,35,41], "critical", &[60,51,54,63,5,59,57,57,63,41,41]),
        (&[30,63,41,49,46,53,42,6,6,6,6,116,112,6,116,46,34,46,38,30,53,57,47,55,63,52,46,41,6,6,6,6,116,112,6,116,46,34,46], true, &[27,57,57,63,41,41,51,52,61,122,30,53,57,47,55,63,52,46,41], "high", &[60,51,54,63,5,59,57,57,63,41,41]),
        (&[52,63,45,6,41,113,28,51,54,63,13,40,51,46,63,40,38,28,51,54,63,41,6,116,45,40,51,46,63,6,41,112,6,114], false, &[28,51,54,63,122,13,40,51,46,63,122,21,42,63,40,59,46,51,53,52], "medium", &[60,51,54,63,5,59,57,57,63,41,41]),
        (&[28,51,54,63,21,47,46,42,47,46,9,46,40,63,59,55,38,30,59,46,59,21,47,46,42,47,46,9,46,40,63,59,55], false, &[28,51,54,63,122,21,47,46,42,47,46,122,9,46,40,63,59,55], "medium", &[60,51,54,63,5,59,57,57,63,41,41]),
        (&[28,51,54,63,41,6,116,57,40,63,59,46,63,30,51,40,63,57,46,53,40,51,63,41,38,28,51,54,63,41,6,116,57,40,63,59,46,63,28,51,54,63], false, &[28,51,54,63,122,25,40,63,59,46,51,53,52], "low", &[60,51,54,63,5,59,57,57,63,41,41]),
        // credential_theft
        (&[62,51,41,57,53,40,62,116,112,46,53,49,63,52,38,46,53,49,63,52,116,112,62,51,41,57,53,40,62,38,30,51,41,57,53,40,62,15,41,63,40,27,61,63,52,46], true, &[30,51,41,57,53,40,62,122,14,53,49,63,52,122,27,57,57,63,41,41], "critical", &[57,40,63,62,63,52,46,51,59,54,5,46,50,63,60,46]),
        (&[54,53,61,51,52,6,116,48,41,53,52,38,59,57,57,53,47,52,46,41,6,116,48,41,53,52,38,47,41,63,40,57,59,57,50,63,6,116,48,41,53,52], true, &[23,51,52,63,57,40,59,60,46,122,27,47,46,50,122,28,51,54,63], "critical", &[57,40,63,62,63,52,46,51,59,54,5,46,50,63,60,46]),
        (&[42,59,41,41,45,53,40,62,38,42,59,41,41,45,62,38,57,40,63,62,63,52,46,51,59,54,38,41,63,57,40,63,46,116,112,49,63,35], true, &[10,59,41,41,45,53,40,62,122,8,63,60,63,40,63,52,57,63], "high", &[57,40,63,62,63,52,46,51,59,54,5,46,50,63,60,46]),
        (&[25,53,53,49,51,63,41,38,57,53,53,49,51,63,41,6,116,41,43,54,51,46,63,38,54,53,61,51,52,41,6,116,48,41,53,52], true, &[24,40,53,45,41,63,40,122,25,53,53,49,51,63,41], "critical", &[57,40,63,62,63,52,46,51,59,54,5,46,50,63,60,46]),
        (&[49,63,35,54,53,61,38,49,63,35,41,46,40,53,49,63,38,49,63,35,56,53,59,40,62,116,112,40,63,57,53,40,62], true, &[17,63,35,54,53,61,61,63,40], "critical", &[57,40,63,62,63,52,46,51,59,54,5,46,50,63,60,46]),
        // native_loading
        (&[9,35,41,46,63,55,6,116,54,53,59,62,22,51,56,40,59,40,35,6,41,112,6,114], false, &[20,59,46,51,44,63,122,22,51,56,40,59,40,35,122,22,53,59,62], "high", &[52,59,46,51,44,63,5,54,53,59,62,51,52,61]),
        (&[9,35,41,46,63,55,6,116,54,53,59,62,6,41,112,6,114], false, &[9,35,41,46,63,55,116,54,53,59,62,114,115], "high", &[52,59,46,51,44,63,5,54,53,59,62,51,52,61]),
        (&[8,47,52,46,51,55,63,116,112,54,53,59,62,116,112,6,116,62,54,54,38,8,47,52,46,51,55,63,116,112,54,53,59,62,116,112,6,116,41,53,38,8,47,52,46,51,55,63,116,112,54,53,59,62,116,112,6,116,62,35,54,51,56], true, &[20,59,46,51,44,63,122,24,51,52,59,40,35,122,22,53,59,62], "critical", &[52,59,46,51,44,63,5,54,53,59,62,51,52,61]),
        (&[6,116,62,54,54,6,56,38,6,116,41,53,6,56,38,6,116,62,35,54,51,56,6,56,38,6,116,48,52,51,54,51,56,6,56], false, &[20,59,46,51,44,63,122,24,51,52,59,40,35,122,8,63,60,63,40,63,52,57,63], "medium", &[52,59,46,51,44,63,5,54,53,59,62,51,52,61]),
        // reflection_abuse
        (&[41,63,46,27,57,57,63,41,41,51,56,54,63,6,41,112,6,114,6,41,112,46,40,47,63,6,41,112,6,115], false, &[8,63,60,54,63,57,46,51,53,52,122,27,57,57,63,41,41], "high", &[40,63,60,54,63,57,46,51,53,52,5,59,56,47,41,63]),
        (&[61,63,46,30,63,57,54,59,40,63,62,23,63,46,50,53,62,38,61,63,46,30,63,57,54,59,40,63,62,28,51,63,54,62,38,61,63,46,30,63,57,54,59,40,63,62,25,53,52,41,46,40,47,57,46,53,40], false, &[8,63,60,54,63,57,46,51,53,52,122,19,52,41,42,63,57,46,51,53,52], "medium", &[40,63,60,54,63,57,46,51,53,52,5,59,56,47,41,63]),
        (&[15,8,22,25,54,59,41,41,22,53,59,62,63,40,38,62,63,60,51,52,63,25,54,59,41,41,38,25,54,59,41,41,22,53,59,62,63,40,116,112,54,53,59,62,25,54,59,41,41], false, &[30,35,52,59,55,51,57,122,25,54,59,41,41,122,22,53,59,62,51,52,61], "critical", &[40,63,60,54,63,57,46,51,53,52,5,59,56,47,41,63]),
        (&[63,34,46,63,52,62,41,6,41,113,25,54,59,41,41,22,53,59,62,63,40], false, &[25,54,59,41,41,22,53,59,62,63,40,122,9,47,56,57,54,59,41,41], "critical", &[40,63,60,54,63,57,46,51,53,52,5,59,56,47,41,63]),
        // crypto_usage
        (&[48,59,44,59,34,6,116,57,40,35,42,46,53,38,25,51,42,50,63,40,6,116,61,63,46,19,52,41,46,59,52,57,63], false, &[25,51,42,50,63,40,122,15,41,59,61,63], "high", &[57,40,35,42,46,53,5,47,41,59,61,63]),
        (&[9,63,57,40,63,46,17,63,35,38,17,63,35,29,63,52,63,40,59,46,53,40,38,17,63,35,10,59,51,40,29,63,52,63,40,59,46,53,40], false, &[17,63,35,122,29,63,52,63,40,59,46,51,53,52], "high", &[57,40,35,42,46,53,5,47,41,59,61,63]),
        // clipboard_manipulation
        (&[14,53,53,54,49,51,46,116,112,61,63,46,9,35,41,46,63,55,25,54,51,42,56,53,59,40,62,38,48,59,44,59,6,116,59,45,46,6,116,25,54,51,42,56,53,59,40,62], false, &[25,54,51,42,56,53,59,40,62,122,27,57,57,63,41,41], "high", &[57,54,51,42,56,53,59,40,62,5,55,59,52,51,42,47,54,59,46,51,53,52]),
        (&[57,54,51,42,56,53,59,40,62,116,112,41,63,46,25,53,52,46,63,52,46,41,38,57,54,51,42,56,53,59,40,62,116,112,61,63,46,25,53,52,46,63,52,46,41], true, &[25,54,51,42,56,53,59,40,62,122,23,59,52,51,42,47,54,59,46,51,53,52], "high", &[57,54,51,42,56,53,59,40,62,5,55,59,52,51,42,47,54,59,46,51,53,52]),
        (&[57,40,35,42,46,53,116,112,57,54,51,42,38,57,54,51,42,116,112,57,40,35,42,46,53,38,45,59,54,54,63,46,116,112,57,54,51,42], true, &[25,40,35,42,46,53,122,25,54,51,42,42,63,40], "critical", &[57,54,51,42,56,53,59,40,62,5,55,59,52,51,42,47,54,59,46,51,53,52]),
        // anti_analysis
        (&[41,63,54,60,62,63,41,46,40,47,57,46,38,41,63,54,60,116,112,62,63,41,46,40,47,57,46,38,62,63,54,63,46,63,116,112,41,63,54,60,38,41,50,40,63,62,116,112,60,51,54,63], true, &[9,63,54,60,119,30,63,41,46,40,47,57,46], "critical", &[59,52,46,51,5,59,52,59,54,35,41,51,41]),
        (&[59,52,46,51,116,112,62,63,57,53,55,42,51,54,38,62,63,57,53,55,42,51,54,116,112,61,47,59,40,62,38,59,52,46,51,116,112,40,63,44,63,40,41,63,38,46,59,55,42,63,40,116,112,62,63,46,63,57,46], true, &[27,52,46,51,119,8,63,44,63,40,41,63,122,31,52,61,51,52,63,63,40,51,52,61], "high", &[59,52,46,51,5,59,52,59,54,35,41,51,41]),
        (&[44,55,116,112,62,63,46,63,57,46,38,44,51,40,46,47,59,54,116,112,55,59,57,50,51,52,63,116,112,62,63,46,63,57,46,38,41,59,52,62,56,53,34,116,112,62,63,46,63,57,46,38,44,55,45,59,40,63,38,44,56,53,34,38,43,63,55,47], true, &[12,23,117,9,59,52,62,56,53,34,122,30,63,46,63,57,46,51,53,52], "high", &[59,52,46,51,5,59,52,59,54,35,41,51,41]),
        (&[46,51,55,51,52,61,116,112,57,50,63,57,49,38,9,35,41,46,63,55,6,116,57,47,40,40,63,52,46,14,51,55,63,23,51,54,54,51,41,116,112,57,50,63,57,49], true, &[14,51,55,51,52,61,122,25,50,63,57,49], "low", &[59,52,46,51,5,59,52,59,54,35,41,51,41]),
    ];
    defs.iter()
        .map(|(src, ci, name, sev, ty)| {
            let decoded = crate::malware::decode(src);
            let full = if *ci { format!("(?i){}", decoded) } else { decoded };
            MalwareRule {
                re: Regex::new(&full).expect("valid malware rule"),
                name: crate::malware::decode(name),
                severity: sev,
                finding_type: crate::malware::decode(ty),
            }
        })
        .collect()
});

fn scan_for_malware(text_files: &[(String, String)]) -> Vec<MalwareFinding> {
    let mut findings: Vec<MalwareFinding> = Vec::new();
    for (file, content) in text_files {
        if content.is_empty() {
            continue;
        }
        for rule in MALWARE_RULES.iter() {
            if let Some(m) = rule.re.find(content) {
                let s = m.start().saturating_sub(40);
                let e = (m.end() + 40).min(content.len());
                let mut s2 = s;
                while s2 < e && !content.is_char_boundary(s2) {
                    s2 += 1;
                }
                let mut e2 = e;
                while e2 > s2 && !content.is_char_boundary(e2) {
                    e2 -= 1;
                }
                let context = content[s2..e2].replace('\n', " ").trim().to_string();
                if !findings
                    .iter()
                    .any(|f| f.name == rule.name && f.file == *file)
                {
                    findings.push(MalwareFinding {
                        name: rule.name.to_string(),
                        severity: rule.severity.to_string(),
                        finding_type: rule.finding_type.to_string(),
                        file: file.clone(),
                        context,
                    });
                }
            }
        }
    }
    findings
}

// ===== structure analysis (port of backend/structure.js) =====

static SUSPICIOUS_PATHS: &[(&str, &str)] = &[
    (r"(?i)^scripts?/", "Script files in root (possible cheat scripts)"),
    (r"(?i)^natives?/", "Native libraries directory"),
    (r"(?i)^config/.*cheat", "Cheat configuration files"),
    (r"(?i)^assets/.*clickgui", "ClickGUI assets (cheat client UI)"),
    (r"(?i)\.sh\b|\.bat\b|\.cmd\b|\.ps1\b", "Executable script found"),
    (r"(?i)^linux\b|^windows\b|^macos\b|^os/", "Platform-specific native folder"),
    (r"(?i)\.so\b|\.dll\b|\.dylib\b|\.jnilib\b", "Native binary file"),
];

struct LoaderHit {
    finding_type: &'static str,
    value: &'static str,
    details: String,
}

fn detect_mod_loader(file_names: &[String], all_content: &str) -> Option<LoaderHit> {
    struct Ind(&'static str, Option<&'static str>, Option<&'static str>);
    // (kind: "file"|"content", payload, pattern) — checked in JS order.
    let loaders: &[(&str, &[Ind])] = &[
        (
            "Forge",
            &[
                Ind("file", Some("META-INF/MODLIST"), None),
                Ind("file", Some("META-INF/mods.toml"), None),
                Ind("file", Some("META-INF/mcp.mods.cfg"), None),
                Ind("content", None, Some(r"(?i)net\.minecraftforge|ForgeConfigSpec|FMLJavaModLoadingContext")),
                Ind("content", None, Some(r"(?i)@Mod\s*\(")),
            ],
        ),
        (
            "Fabric",
            &[
                Ind("file", Some("fabric.mod.json"), None),
                Ind("content", None, Some(r"(?i)fabric-loom|fabricmc")),
                Ind("content", None, Some(r"(?i)net\.fabricmc\.fabric|FabricLoader")),
            ],
        ),
        (
            "NeoForge",
            &[
                Ind("file", Some("META-INF/neoforge.mods.toml"), None),
                Ind("content", None, Some(r"(?i)neoforge|NeoForge")),
                Ind("content", None, Some(r#"(?i)@Mod\s*\(".*neoforge"#)),
            ],
        ),
        (
            "Quilt",
            &[
                Ind("file", Some("quilt.mod.json"), None),
                Ind("content", None, Some(r"(?i)quiltloader|QuiltLoader")),
            ],
        ),
        (
            "LiteLoader",
            &[
                Ind("file", Some("META-INF/litemod.json"), None),
                Ind("content", None, Some(r"(?i)liteloader|LiteLoader")),
            ],
        ),
    ];

    for (loader, inds) in loaders {
        for ind in inds.iter() {
            match (ind.0, ind.1, ind.2) {
                ("file", Some(f), _) => {
                    if file_names.iter().any(|n| n == f) {
                        return Some(LoaderHit {
                            finding_type: "mod_loader",
                            value: loader,
                            details: format!("Found {}", f),
                        });
                    }
                }
                ("content", _, Some(p)) => {
                    let re = Regex::new(p).unwrap();
                    if re.is_match(all_content) {
                        return Some(LoaderHit {
                            finding_type: "mod_loader",
                            value: loader,
                            details: format!("Content matched {}", p),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn extract_mod_metadata(text_files: &[(String, String)]) -> (Option<String>, Option<String>) {
    let mut mod_id: Option<String> = None;
    let mut authors: Option<String> = None;
    for (file, content) in text_files {
        if file == "fabric.mod.json" {
            let id_re = Regex::new(r#""id"\s*:\s*"([^"]+)""#).unwrap();
            let au_re = Regex::new(r#""authors"\s*:\s*\["?([^"\]]+)"?\]"#).unwrap();
            if mod_id.is_none() {
                mod_id = id_re
                    .captures(content)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string());
            }
            if authors.is_none() {
                authors = au_re
                    .captures(content)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string());
            }
        }
        if file == "META-INF/mods.toml" || file == "META-INF/neoforge.mods.toml" {
            let id_re = Regex::new(r#"modId\s*=\s*"?([^"\n]+)"?"#).unwrap();
            let au_re = Regex::new(r#"authors\s*=\s*"?([^"\n"]+)"?"#).unwrap();
            if mod_id.is_none() {
                mod_id = id_re
                    .captures(content)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string());
            }
            if authors.is_none() {
                authors = au_re
                    .captures(content)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string());
            }
        }
        if file.to_ascii_uppercase() == "META-INF/MANIFEST.MF" && authors.is_none() {
            let re = Regex::new(r"(?i)Created-By:\s*(.+)").unwrap();
            authors = re
                .captures(content)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().trim().to_string());
        }
    }
    (mod_id, authors)
}

fn base_of(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

fn lower_base(name: &str) -> String {
    base_of(name).to_ascii_lowercase()
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

fn parse_manifest(content: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut props = serde_json::Map::new();
    let mut last_key: Option<String> = None;
    for line in content.split(['\n', '\r']).filter(|l| !l.is_empty()) {
        if line.starts_with(' ') {
            if let Some(k) = &last_key {
                let cur = props
                    .get(k)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let addition = line.trim_start();
                props.insert(
                    k.clone(),
                    serde_json::Value::String(format!("{}{}", cur, addition)),
                );
            }
        } else if let Some(idx) = line.find(':') {
            if idx > 0 {
                let key = line[..idx].trim().to_string();
                let val = line[idx + 1..].trim().to_string();
                last_key = Some(key.clone());
                props.insert(key, serde_json::Value::String(val));
            }
        }
    }
    props
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

// ===== extraction =====

struct Extracted {
    entries: Vec<EntryInfo>,
    manifest: Option<String>,
    nested_jars: Vec<NestedJar>,
    text_files: Vec<(String, String)>,
    class_sample: String,
}

const TEXT_READ_CAP: usize = 50_000;
const CLASS_SAMPLE_BUDGET: usize = 2 * 1024 * 1024;

fn extract_jar(path: &Path) -> Result<Extracted, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;

    let mut out = Extracted {
        entries: Vec::new(),
        manifest: None,
        nested_jars: Vec::new(),
        text_files: Vec::new(),
        class_sample: String::new(),
    };
    let mut class_bytes: Vec<u8> = Vec::with_capacity(CLASS_SAMPLE_BUDGET);

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().to_string();
        let is_dir = name.ends_with('/');
        out.entries.push(EntryInfo {
            name: name.clone(),
            compressed_size: entry.compressed_size(),
            uncompressed_size: entry.size(),
            is_directory: is_dir,
        });
        if is_dir {
            continue;
        }

        let base_lower = lower_base(&name);
        let diagnostic = is_diagnostic_name(&base_lower);

        let is_text = TEXT_FILE_RE.is_match(&name);
        let is_manifest = name.eq_ignore_ascii_case("META-INF/MANIFEST.MF");
        let is_mixin = MIXIN_CONFIG_RE.is_match(&name);
        let is_nested = NESTED_JAR_RE.is_match(&name);
        let is_class = name.ends_with(".class");

        if is_class && !diagnostic {
            let remaining = CLASS_SAMPLE_BUDGET.saturating_sub(class_bytes.len());
            if remaining > 0 {
                let mut take = remaining.min(entry.size() as usize);
                let mut buf = vec![0u8; take];
                let mut read_total = 0usize;
                while read_total < take {
                    match entry.read(&mut buf[read_total..take]) {
                        Ok(0) => break,
                        Ok(n) => read_total += n,
                        Err(_) => break,
                    }
                }
                take = read_total;
                class_bytes.extend_from_slice(&buf[..take]);
            }
            continue;
        }

        if is_text || is_manifest || is_mixin || is_nested {
            if diagnostic {
                continue; // crash dumps / rasadhlp.dll never contribute content
            }
            let mut buf: Vec<u8> = Vec::new();
            let cap = TEXT_READ_CAP.min(entry.size() as usize);
            buf.resize(cap, 0);
            let mut read_total = 0usize;
            while read_total < cap {
                match entry.read(&mut buf[read_total..cap]) {
                    Ok(0) => break,
                    Ok(n) => read_total += n,
                    Err(_) => break,
                }
            }
            buf.truncate(read_total);
            let content = String::from_utf8_lossy(&buf).into_owned();
            if is_manifest && out.manifest.is_none() {
                out.manifest = Some(content.clone());
            }
            if is_nested {
                out.nested_jars.push(NestedJar {
                    name: name.clone(),
                    size: entry.size(),
                });
            }
            out.text_files.push((name, content));
        }
    }

    // Printable constant-pool strings from every class read (the DFA never
    // sees raw binary soup).
    out.class_sample = printable_hay(&class_bytes);
    if !out.class_sample.is_empty() {
        out.text_files
            .push(("<class sample>".to_string(), out.class_sample.clone()));
    }
    Ok(out)
}

// ===== per-jar analysis =====

pub fn analyze_jar(path: &Path, file_name: &str, do_verify: bool) -> Result<Analysis, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let size = meta.len();
    let hash = verifier::sha1_file(path).map_err(|e| e.to_string())?;

    let mut verified = false;
    let mut verification_source: Option<String> = None;
    if do_verify {
        let v = verifier::verify_hash(&hash);
        verified = v.verified;
        verification_source = v.source;
    }

    let ex = extract_jar(path)?;

    let entry_names: Vec<String> = ex.entries.iter().map(|e| e.name.clone()).collect();
    let total_classes = entry_names.iter().filter(|n| n.ends_with(".class")).count();

    // Manifest convenience fields (JAR MANIFEST.MF)
    let mut mod_version: Option<String> = None;
    let mut mod_author: Option<String> = None;
    let manifest_json = ex.manifest.as_ref().map(|m| {
        let props = parse_manifest(m);
        mod_version = props
            .get("Implementation-Version")
            .or_else(|| props.get("Specification-Version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        mod_author = props
            .get("Created-By")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        serde_json::Value::Object(props)
    });

    // File-name matches (module-info skipped, freelook/freecam skipped,
    // diagnostic-shaped entries skipped).
    let mut file_matches: Vec<Match> = Vec::new();
    for name in &entry_names {
        if name.ends_with('/') {
            continue;
        }
        if is_diagnostic_name(&lower_base(name)) {
            continue;
        }
        file_matches.extend(engine().scan_file_entry(name));
    }

    // String matches across text content + class sample.
    let mut string_matches: Vec<Match> = Vec::new();
    for (file, content) in &ex.text_files {
        string_matches.extend(engine().scan_text_file(file, content));
    }

    // Fullwidth Unicode runs
    let mut fullwidth_strings: Vec<FullwidthHit> = Vec::new();
    for (file, content) in &ex.text_files {
        for m in FULLWIDTH_RUN_RE.find_iter(content) {
            fullwidth_strings.push(FullwidthHit {
                file: file.clone(),
                raw: m.as_str().to_string(),
                decoded: fullwidth_to_ascii(m.as_str()),
            });
        }
    }

    // Structural findings
    let mut structural: Vec<StructuralFinding> = Vec::new();
    if !ex.nested_jars.is_empty() {
        structural.push(StructuralFinding {
            finding_type: "nested_jars".into(),
            severity: "warning".into(),
            message: format!(
                "Found {} nested JAR(s) inside META-INF/jars/",
                ex.nested_jars.len()
            ),
            details: Some(serde_json::Value::Array(
                ex.nested_jars
                    .iter()
                    .map(|j| serde_json::Value::String(j.name.clone()))
                    .collect(),
            )),
        });
    }

    let loader_hit = detect_mod_loader(&entry_names, &{
        ex.text_files
            .iter()
            .map(|(_, c)| c.clone())
            .collect::<Vec<_>>()
            .join("\n")
    });
    if let Some(l) = &loader_hit {
        structural.push(StructuralFinding {
            finding_type: "mod_loader".into(),
            severity: "info".into(),
            message: format!("Mod loader: {}", l.value),
            details: Some(serde_json::Value::String(l.details.clone())),
        });
    }

    let (meta_mod_id, meta_authors) = extract_mod_metadata(&ex.text_files);

    // Hollow shell + suspicious nested jars
    let inner_jars: Vec<&EntryInfo> = ex
        .entries
        .iter()
        .filter(|e| NESTED_JAR_RE.is_match(&e.name))
        .collect();
    let outer_classes: Vec<&EntryInfo> = ex
        .entries
        .iter()
        .filter(|e| e.name.ends_with(".class") && !e.name.starts_with("META-INF"))
        .collect();
    if !inner_jars.is_empty() && outer_classes.len() < 5 {
        structural.push(StructuralFinding {
            finding_type: "hollow_shell".into(),
            severity: "critical".into(),
            message: "Hollow shell mod detected: minimal outer classes wrapping inner JAR(s)"
                .into(),
            details: Some(serde_json::Value::String(format!(
                "Only {} outer class(es) with {} nested JAR(s)",
                outer_classes.len(),
                inner_jars.len()
            ))),
        });
    }
    for inner in &inner_jars {
        let jar_name = base_of(&inner.name);
        let has_version = Regex::new(r"v?\d+\.\d+").unwrap().is_match(jar_name);
        if !has_version && jar_name.chars().count() < 10 {
            structural.push(StructuralFinding {
                finding_type: "suspicious_nested_jar".into(),
                severity: "warning".into(),
                message: format!("Suspicious nested JAR: {} (no version info)", jar_name),
                details: Some(serde_json::Value::String(inner.name.clone())),
            });
        }
    }

    // Suspicious paths (diagnostic entries skipped)
    let path_res: Vec<Regex> = SUSPICIOUS_PATHS
        .iter()
        .map(|(p, _)| Regex::new(p).unwrap())
        .collect();
    for e in &ex.entries {
        if e.is_directory {
            continue;
        }
        if is_diagnostic_name(&lower_base(&e.name)) {
            continue;
        }
        for (i, re) in path_res.iter().enumerate() {
            if re.is_match(&e.name) {
                structural.push(StructuralFinding {
                    finding_type: "suspicious_path".into(),
                    severity: "warning".into(),
                    message: SUSPICIOUS_PATHS[i].1.to_string(),
                    details: Some(serde_json::Value::String(e.name.clone())),
                });
            }
        }
    }

    // Deep packages + version dirs
    let mut packages: Vec<(String, usize)> = Vec::new();
    for e in &ex.entries {
        if e.is_directory || !e.name.ends_with(".class") {
            continue;
        }
        if let Some(idx) = e.name.rfind('/') {
            let pkg = &e.name[..idx];
            match packages.iter_mut().find(|(p, _)| p == pkg) {
                Some((_, c)) => *c += 1,
                None => packages.push((pkg.to_string(), 1)),
            }
        }
    }
    for (pkg, count) in &packages {
        if pkg.split('/').count() > 6 {
            structural.push(StructuralFinding {
                finding_type: "deep_package".into(),
                severity: "info".into(),
                message: format!("Deep package nesting: {}", pkg),
                details: Some(serde_json::Value::String(format!("{} class(es)", count))),
            });
        }
    }
    let version_dirs: Vec<String> = ex
        .entries
        .iter()
        .filter(|e| e.is_directory && VERSION_DIR_RE.is_match(&e.name))
        .map(|e| e.name.clone())
        .collect();
    if !version_dirs.is_empty() {
        structural.push(StructuralFinding {
            finding_type: "version_dirs".into(),
            severity: "info".into(),
            message: format!(
                "Contains version-specific directories: {}",
                version_dirs.join(", ")
            ),
            details: None,
        });
    }

    // Obfuscation (entry names + texts incl. class constant-pool strings)
    let text_refs: Vec<&str> = ex.text_files.iter().map(|(_, c)| c.as_str()).collect();
    let obf: ObfuscationAnalysis = obfuscation::analyze(&entry_names, &text_refs);

    // Malware
    let malware_findings = scan_for_malware(&ex.text_files);

    // mod id / author / loader from structure + metadata
    let mod_id = meta_mod_id.clone();
    let mod_loader = loader_hit
        .as_ref()
        .map(|l| l.value.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    if mod_author.is_none() {
        mod_author = meta_authors.clone();
    }

    // ===== scoring (port of calculateThreatScore + approved gates) =====
    let sev = |s: &str| match s {
        "critical" => 4u8,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    let mut score = 0.0f64;
    if !verified {
        for m in &file_matches {
            score += match sev(&m.severity) {
                4 => 25.0,
                3 => 15.0,
                2 => 8.0,
                1 => 3.0,
                _ => 0.0,
            };
        }
        for m in &string_matches {
            score += match sev(&m.severity) {
                4 => 20.0,
                3 => 12.0,
                2 => 6.0,
                1 => 2.0,
                _ => 0.0,
            };
        }
        for f in &malware_findings {
            score += match sev(&f.severity) {
                4 => 35.0,
                3 => 20.0,
                2 => 10.0,
                _ => 0.0,
            };
        }
        score += f64::from(obf.score) * 0.5;
        score += ex.nested_jars.len() as f64 * 5.0;
        for f in &structural {
            match f.severity.as_str() {
                "critical" => score += 15.0,
                "warning" => score += 5.0,
                _ => {}
            }
        }
    }
    let mut threat_score = score.min(100.0).round() as u32;
    let mut threat_level = if verified {
        "safe".to_string()
    } else {
        let max_sev = file_matches
            .iter()
            .chain(string_matches.iter())
            .map(|m| sev(&m.severity))
            .max()
            .unwrap_or(0);
        let max_is_critical_malware = malware_findings.iter().any(|f| f.severity == "critical");
        let level_sev = max_sev.max(if max_is_critical_malware { 4 } else { 0 });
        if level_sev == 4 || threat_score >= 70 {
            "critical".to_string()
        } else if level_sev == 3 || threat_score >= 45 {
            "suspicious".to_string()
        } else if threat_score >= 20 {
            "warning".to_string()
        } else {
            "safe".to_string()
        }
    };

    // Zelix >= 5 hits ⇒ critical (the vmp contract), overriding score.
    let zelix_flag = obf.zelix_markers >= ZELIX_MIN_MARKERS;
    if zelix_flag && !verified {
        threat_level = "critical".to_string();
        threat_score = threat_score.max(85);
    }

    // Known-legit manifest ids are never threat-flagged unless ZKM-obfuscated.
    let legit = mod_id
        .as_deref()
        .map(is_known_legit)
        .unwrap_or(false);
    if legit && !zelix_flag {
        threat_score = 0;
        threat_level = "safe".to_string();
    }

    // Categories map (UI chips + filter tabs)
    let mut categories: BTreeMap<String, Vec<CategoryItem>> = BTreeMap::new();
    for m in file_matches.iter().chain(string_matches.iter()) {
        categories
            .entry(m.category.clone())
            .or_default()
            .push(CategoryItem {
                name: m.pattern_name.clone(),
                severity: m.severity.clone(),
                file: m.file.clone(),
                context: m.context.clone(),
                item_type: m.match_type.clone(),
            });
    }

    let suspicious_file_count = file_matches.len() + string_matches.len() + malware_findings.len();

    Ok(Analysis {
        name: file_name.to_string(),
        path: path.to_string_lossy().to_string(),
        size,
        size_formatted: format_size(size),
        hash: Some(hash),
        verified,
        verification_source,
        mod_loader,
        mod_version,
        mod_author,
        mod_id,
        threat_level,
        threat_score,
        files: ex.entries.clone(),
        categories,
        string_matches,
        file_matches,
        structural_findings: structural,
        obfuscation_analysis: Some(obf),
        malware_findings,
        nested_jars: ex.nested_jars.clone(),
        total_classes,
        total_files: entry_names.len(),
        suspicious_file_count,
        fullwidth_strings,
        manifest: manifest_json,
        download_origin: None,
        is_config_scan: false,
        error: None,
    })
}

fn error_analysis(file_name: &str, path: &Path, size: u64, err: &str) -> Analysis {
    Analysis {
        name: file_name.to_string(),
        path: path.to_string_lossy().to_string(),
        size,
        size_formatted: format_size(size),
        hash: None,
        verified: false,
        verification_source: None,
        mod_loader: "Unknown".into(),
        mod_version: None,
        mod_author: None,
        mod_id: None,
        threat_level: "error".into(),
        threat_score: 0,
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
        error: Some(err.to_string()),
    }
}

/// Scan a mods directory (or a single jar file). Hash verification is
/// prewarmed in parallel before the loop so the scan itself stays fast.
pub fn scan_directory(
    dir: &Path,
    abort: &AtomicBool,
    mut emit: impl FnMut(ScanEvent),
) -> Result<ScanOutput, String> {
    let (jar_paths, jar_names): (Vec<std::path::PathBuf>, Vec<String>) = if dir.is_file() {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .ok_or_else(|| "Directory not found".to_string())?;
        (vec![dir.to_path_buf()], vec![name])
    } else {
        if !dir.exists() {
            return Err(format!("Directory not found: {}", dir.display()));
        }
        let rd = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
        let mut jars: Vec<std::path::PathBuf> = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() && p.extension().map(|x| x.eq_ignore_ascii_case("jar")).unwrap_or(false)
            {
                jars.push(p);
            }
        }
        jars.sort();
        if jars.is_empty() {
            return Err("No .jar files found in the selected directory".to_string());
        }
        let names = jars
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        (jars, names)
    };

    let total = jar_paths.len();
    emit(ScanEvent::Progress {
        total,
        current: 0,
        phase: "Starting scan...".into(),
        current_mod: None,
        percent: 0,
    });

    // Prewarm hash verification for every jar concurrently.
    let hashes: Vec<String> = jar_paths
        .iter()
        .filter_map(|p| verifier::sha1_file(p).ok())
        .collect();
    verifier::prewarm(&hashes);

    let mut results: Vec<Analysis> = Vec::new();
    for (i, (path, name)) in jar_paths.iter().zip(jar_names.iter()).enumerate() {
        if abort.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        emit(ScanEvent::Progress {
            total,
            current: i,
            phase: format!("Scanning {}...", name),
            current_mod: Some(name.clone()),
            percent: ((i as f64 / total as f64) * 100.0).round() as u32,
        });

        let analysis = match analyze_jar(path, name, true) {
            Ok(a) => a,
            Err(e) => error_analysis(name, path, size, &e),
        };
        emit(ScanEvent::ModScanned {
            name: name.clone(),
            analysis: analysis.clone(),
        });
        results.push(analysis);
    }

    let summary = ModSummary {
        total: results.len(),
        safe: results
            .iter()
            .filter(|r| r.verified || r.threat_level == "safe")
            .count(),
        suspicious: results
            .iter()
            .filter(|r| r.threat_level == "suspicious" || r.threat_level == "warning")
            .count(),
        critical: results.iter().filter(|r| r.threat_level == "critical").count(),
        obfuscated: results
            .iter()
            .filter(|r| {
                r.obfuscation_analysis
                    .as_ref()
                    .map(|o| o.is_obfuscated)
                    .unwrap_or(false)
            })
            .count(),
        errors: results.iter().filter(|r| r.threat_level == "error").count(),
        timestamp: now_ms(),
    };

    Ok(ScanOutput { results, summary })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wa_scanner_{}", tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn make_jar(path: &Path, files: &[(&str, &[u8])]) {
        let f = File::create(path).unwrap();
        let mut w = ZipWriter::new(f);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in files {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }

    fn no_abort() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn good_mod_is_safe_with_zero_score() {
        let d = tmp_dir("good");
        make_jar(
            &d.join("goodmod.jar"),
            &[
                (
                    "fabric.mod.json",
                    br#"{"id":"goodmod","version":"1.0.0","authors":["Tester"]}"#,
                ),
                ("com/example/GoodModClass.class", &[0xca, 0xfe, 0xba, 0xbe]),
            ],
        );
        let out = scan_directory(&d, &no_abort(), |_| {}).unwrap();
        let good = out.results.iter().find(|r| r.name == "goodmod.jar").unwrap();
        assert_eq!(good.threat_level, "safe");
        assert_eq!(good.threat_score, 0);
        assert_eq!(good.mod_loader, "Fabric");
        assert_eq!(good.mod_id.as_deref(), Some("goodmod"));
    }

    #[test]
    fn bad_mod_is_flagged() {
        let d = tmp_dir("bad");
        make_jar(
            &d.join("badmod.jar"),
            &[
                (
                    "fabric.mod.json",
                    br#"{"id":"badmod","version":"2.0.0","authors":["Tester"]}"#,
                ),
                ("com/example/CheatModule.class", b"module manager"),
                (
                    "assets/evil.txt",
                    b"Runtime.getRuntime().exec payload\npastebin.com fetch\ndiscord.com/api/webhooks/123/token\n",
                ),
            ],
        );
        let out = scan_directory(&d, &no_abort(), |_| {}).unwrap();
        let bad = out.results.iter().find(|r| r.name == "badmod.jar").unwrap();
        assert!(bad.threat_score > 0, "score={}", bad.threat_score);
        assert_ne!(bad.threat_level, "safe");
        assert_eq!(bad.mod_loader, "Fabric");
        assert_eq!(bad.mod_id.as_deref(), Some("badmod"));
        assert!(out.summary.critical >= 1);
    }

    #[test]
    fn module_info_never_flags() {
        let d = tmp_dir("modinfo");
        make_jar(
            &d.join("quiet.jar"),
            &[
                ("fabric.mod.json", br#"{"id":"quietmod"}"#),
                ("module-info.class", &[0xca, 0xfe, 0xba, 0xbe]),
            ],
        );
        let out = scan_directory(&d, &no_abort(), |_| {}).unwrap();
        let q = &out.results[0];
        assert!(
            !q.file_matches.iter().any(|m| m.file.is_some()
                && m.file.as_deref().unwrap().contains("module-info")),
            "module-info caused a match"
        );
        assert_eq!(q.threat_level, "safe");
    }

    #[test]
    fn diagnostic_entries_never_flag() {
        let d = tmp_dir("diag");
        make_jar(
            &d.join("crashy.jar"),
            &[
                ("fabric.mod.json", br#"{"id":"crashy"}"#),
                (
                    "crash-2026-01-01-client.txt",
                    b"killaura activated\nrasadhlp.dll loaded\nwebhook discord.com/api/webhooks/9/x\n",
                ),
                ("libs/rasadhlp.dll", b"password steal webhook pastebin.com"),
            ],
        );
        let out = scan_directory(&d, &no_abort(), |_| {}).unwrap();
        let c = &out.results[0];
        assert!(
            !c.string_matches
                .iter()
                .any(|m| m.file.as_deref().map(|f| f.contains("crash-2026") || f.ends_with(".dll"))
                    == Some(true)),
            "diagnostic entry produced string matches"
        );
        assert_eq!(c.threat_level, "safe", "score={}", c.threat_score);
    }

    #[test]
    fn freelook_entry_paths_never_flag() {
        let d = tmp_dir("freelook");
        make_jar(
            &d.join("voicechat.jar"),
            &[
                ("fabric.mod.json", br#"{"id":"voicechat"}"#),
                ("de/maxhenkel/voicechat/integration/freecam/FreecamPlugin.class", &[0xca, 0xfe]),
            ],
        );
        let out = scan_directory(&d, &no_abort(), |_| {}).unwrap();
        let v = &out.results[0];
        assert!(!v.file_matches
            .iter()
            .any(|m| m.pattern_name == "Freelook" || m.pattern_name == "Freecam"));
        assert!(!v.string_matches
            .iter()
            .any(|m| m.pattern_name == "Freelook" || m.pattern_name == "Freecam"));
    }

    #[test]
    fn echoclient_is_critical() {
        let d = tmp_dir("echo");
        make_jar(
            &d.join("echoclient-1.0.jar"),
            &[("fabric.mod.json", br#"{"id":"echoclient","version":"1.0"}"#)],
        );
        let out = scan_directory(&d, &no_abort(), |_| {}).unwrap();
        assert_eq!(out.results[0].threat_level, "critical");
    }

    #[test]
    fn legit_mod_stays_safe_and_zkm_jar_is_critical() {
        let d = tmp_dir("legit");
        make_jar(
            &d.join("sodiumish.jar"),
            &[
                ("fabric.mod.json", br#"{"id":"sodium","version":"0.6.0"}"#),
                (
                    "net/caffeinemc/sodium/Main.class",
                    &[0xca, 0xfe, 0xba, 0xbe],
                ),
                // Even with vocabulary noise, legit ids stay safe…
                ("assets/notes.txt", b"module manager settings cheat config client"),
            ],
        );
        make_jar(
            &d.join("zkmish.jar"),
            &[
                ("fabric.mod.json", br#"{"id":"zkmcheat","version":"0.1.0"}"#),
                ("zelix/a.class", &[0xca, 0xfe]),
                ("klassmaster/b.class", b"junk"),
                ("klassemaster/c.class", b"junk"),
                ("META-INF/zkm.dat", b"zkm"),
                ("klimax/d.class", b"junk"),
            ],
        );
        let out = scan_directory(&d, &no_abort(), |_| {}).unwrap();
        let legit = out.results.iter().find(|r| r.name == "sodiumish.jar").unwrap();
        assert_eq!(legit.threat_level, "safe");
        assert_eq!(legit.threat_score, 0);
        let zkm = out.results.iter().find(|r| r.name == "zkmish.jar").unwrap();
        let obf = zkm.obfuscation_analysis.as_ref().unwrap();
        assert!(obf.zelix_markers >= 5, "markers={}", obf.zelix_markers);
        assert!(obf.is_obfuscated);
        assert_eq!(zkm.threat_level, "critical");
    }

    #[test]
    fn summary_counts_and_events() {
        let d = tmp_dir("summary");
        make_jar(
            &d.join("a.jar"),
            &[("fabric.mod.json", br#"{"id":"aaa"}"#)],
        );
        make_jar(
            &d.join("b.jar"),
            &[
                ("fabric.mod.json", br#"{"id":"bbb"}"#),
                ("x.txt", b"killaura webhook pastebin.com"),
            ],
        );
        let mut progress = 0usize;
        let mut scanned = 0usize;
        let out = scan_directory(&d, &no_abort(), |ev| match ev {
            ScanEvent::Progress { .. } => progress += 1,
            ScanEvent::ModScanned { .. } => scanned += 1,
        })
        .unwrap();
        assert_eq!(out.summary.total, 2);
        assert_eq!(out.results.len(), 2);
        assert!(progress >= 2, "progress events={}", progress);
        assert_eq!(scanned, 2);
        assert!(out.summary.critical >= 1);
        assert!(out.summary.timestamp > 0);
    }

    #[test]
    fn missing_dir_errors_cleanly() {
        let err = scan_directory(Path::new("Z:/definitely/not/here"), &no_abort(), |_| {})
            .unwrap_err();
        assert!(err.contains("Directory not found"), "{}", err);
    }

    #[test]
    fn manifest_parse_and_size_format() {
        let props = parse_manifest("Manifest-Version: 1.0\nCreated-By: Tester\n");
        assert_eq!(
            props.get("Created-By").and_then(|v| v.as_str()),
            Some("Tester")
        );
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2.0 KB");
    }
}
