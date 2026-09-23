//! Obfuscation Detection Engine — port of backend/obfuscation.js

use crate::patterns_gen::PATTERNS;
use crate::scanner::{JarEntry, TextFile};
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Indicator {
    #[serde(rename = "type")]
    pub indicator_type: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ObfuscatorSig {
    pub name: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClassNamingAnalysis {
    pub single_letter_ratio: f64,
    pub short_name_ratio: f64,
    pub numeric_ratio: f64,
    pub unicode_ratio: f64,
    pub gibberish_ratio: f64,
    pub total: usize,
    pub single_letter: usize,
    pub short_names: usize,
    pub numeric: usize,
    pub unicode: usize,
    pub gibberish: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PackageAnalysis {
    pub total_packages: usize,
    pub single_letter_package_ratio: f64,
    pub deep_obfuscated_paths: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ObfuscationAnalysis {
    pub is_obfuscated: bool,
    pub score: u32,
    pub indicators: Vec<Indicator>,
    pub obfuscator_signatures: Vec<ObfuscatorSig>,
    pub class_naming_analysis: Option<ClassNamingAnalysis>,
    pub package_analysis: Option<PackageAnalysis>,
    pub details: Vec<String>,
}

fn obfuscator_patterns() -> &'static Vec<(usize, regex::Regex)> {
    static CACHE: OnceLock<Vec<(usize, regex::Regex)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = Vec::new();
        for (i, p) in PATTERNS.iter().enumerate() {
            if p.category_key == "obfuscation_signatures" {
                if let Ok(re) = regex::RegexBuilder::new(p.source)
                    .case_insensitive(p.ci)
                    .build()
                {
                    out.push((i, re));
                }
            }
        }
        out
    })
}

/// Analyze file entries and content for obfuscation indicators.
pub fn analyze_obfuscation(entries: &[JarEntry], text_files: &[TextFile]) -> ObfuscationAnalysis {
    let class_files: Vec<&JarEntry> = entries
        .iter()
        .filter(|e| e.name.ends_with(".class") && !e.is_directory)
        .collect();

    if class_files.is_empty() {
        return ObfuscationAnalysis::default();
    }

    let class_naming = analyze_class_names(&class_files);
    let package_analysis = analyze_packages(entries);
    let obf_signatures = detect_obfuscator_signatures(text_files);

    let mut result = ObfuscationAnalysis {
        class_naming_analysis: Some(class_naming.clone()),
        package_analysis: Some(package_analysis.clone()),
        obfuscator_signatures: obf_signatures.clone(),
        ..Default::default()
    };

    let mut score = 0.0f64;

    if class_naming.single_letter_ratio > 0.3 {
        score += class_naming.single_letter_ratio * 30.0;
        result.indicators.push(Indicator {
            indicator_type: "single_letter_classes".into(),
            severity: "high".into(),
            message: format!("{}% of classes use single-letter names", (class_naming.single_letter_ratio * 100.0).round()),
        });
    }
    if class_naming.short_name_ratio > 0.5 {
        score += class_naming.short_name_ratio * 25.0;
        result.indicators.push(Indicator {
            indicator_type: "short_class_names".into(),
            severity: "medium".into(),
            message: format!("{}% of classes have names ≤2 characters", (class_naming.short_name_ratio * 100.0).round()),
        });
    }
    if class_naming.numeric_ratio > 0.1 {
        score += class_naming.numeric_ratio * 25.0;
        result.indicators.push(Indicator {
            indicator_type: "numeric_class_names".into(),
            severity: "high".into(),
            message: format!("{}% of classes use numeric names", (class_naming.numeric_ratio * 100.0).round()),
        });
    }
    if class_naming.unicode_ratio > 0.05 {
        score += class_naming.unicode_ratio * 30.0;
        result.indicators.push(Indicator {
            indicator_type: "unicode_class_names".into(),
            severity: "critical".into(),
            message: format!("{}% of classes use Unicode names", (class_naming.unicode_ratio * 100.0).round()),
        });
    }
    if package_analysis.single_letter_package_ratio > 0.5 {
        score += package_analysis.single_letter_package_ratio * 20.0;
        result.indicators.push(Indicator {
            indicator_type: "single_letter_packages".into(),
            severity: "medium".into(),
            message: format!("{}% of packages use single-letter names", (package_analysis.single_letter_package_ratio * 100.0).round()),
        });
    }
    if package_analysis.deep_obfuscated_paths > 0 {
        score += package_analysis.deep_obfuscated_paths as f64 * 3.0;
        result.indicators.push(Indicator {
            indicator_type: "deep_obfuscated_paths".into(),
            severity: "medium".into(),
            message: format!("Found {} deeply nested obfuscated package paths", package_analysis.deep_obfuscated_paths),
        });
    }
    if !obf_signatures.is_empty() {
        score += obf_signatures.len() as f64 * 15.0;
        for sig in &obf_signatures {
            result.indicators.push(Indicator {
                indicator_type: "obfuscator_signature".into(),
                severity: "high".into(),
                message: format!("Detected {} obfuscator signature", sig.name),
            });
        }
    }
    if class_naming.gibberish_ratio > 0.2 {
        score += class_naming.gibberish_ratio * 15.0;
        result.indicators.push(Indicator {
            indicator_type: "gibberish_names".into(),
            severity: "medium".into(),
            message: format!("{}% of classes appear to have gibberish names", (class_naming.gibberish_ratio * 100.0).round()),
        });
    }

    result.score = score.round().min(100.0) as u32;
    result.is_obfuscated = result.score > 25;
    result
}

fn analyze_class_names(class_files: &[&JarEntry]) -> ClassNamingAnalysis {
    let total = class_files.len();
    let (mut single, mut short_names, mut numeric, mut unicode, mut gibberish) = (0usize, 0usize, 0usize, 0usize, 0usize);

    for file in class_files {
        let base = file.name.rsplit('/').next().unwrap_or(&file.name);
        let name = base.strip_suffix(".class").unwrap_or(base);
        let name = percent_decode_lossy(name);

        if name.chars().count() == 1 {
            single += 1;
            short_names += 1;
        } else if name.chars().count() <= 2 {
            short_names += 1;
        }

        if !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()) {
            numeric += 1;
        }
        if name.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '$' || c == '_')) {
            unicode += 1;
        }
        let len = name.chars().count();
        if len > 2 && name.chars().all(|c| "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ".contains(c)) {
            gibberish += 1;
        }
    }

    let r = |n: usize| if total > 0 { n as f64 / total as f64 } else { 0.0 };
    ClassNamingAnalysis {
        single_letter_ratio: r(single),
        short_name_ratio: r(short_names),
        numeric_ratio: r(numeric),
        unicode_ratio: r(unicode),
        gibberish_ratio: r(gibberish),
        total,
        single_letter: single,
        short_names,
        numeric,
        unicode,
        gibberish,
    }
}

/// Zip entry names may be percent-encoded UTF-8; decode best-effort like JS Buffer utf-8.
fn percent_decode_lossy(s: &str) -> String {
    // JS path: name.split('/').pop().replace('.class','') — zip crate hands us decoded names already
    s.to_string()
}

fn analyze_packages(entries: &[JarEntry]) -> PackageAnalysis {
    let mut packages = std::collections::BTreeSet::new();
    for entry in entries {
        if entry.is_directory {
            continue;
        }
        let parts: Vec<&str> = entry.name.split('/').collect();
        if parts.len() > 1 {
            packages.insert(parts[..parts.len() - 1].join("/"));
        }
    }

    let mut single_letter_packages = 0usize;
    let mut deep_obfuscated = 0usize;

    for pkg in &packages {
        let segments: Vec<&str> = pkg.split('/').collect();
        let all_single = segments.iter().all(|s| s.len() == 1 && s.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false));
        if all_single && segments.len() > 1 {
            single_letter_packages += 1;
        }
        if segments.len() > 3 && segments.iter().all(|s| s.len() <= 2) {
            deep_obfuscated += 1;
        }
    }

    let total = packages.len();
    PackageAnalysis {
        total_packages: total,
        single_letter_package_ratio: if total > 0 { single_letter_packages as f64 / total as f64 } else { 0.0 },
        deep_obfuscated_paths: deep_obfuscated,
    }
}

fn detect_obfuscator_signatures(text_files: &[TextFile]) -> Vec<ObfuscatorSig> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for tf in text_files {
        if tf.content.is_empty() {
            continue;
        }
        for (_, re) in obfuscator_patterns() {
            if re.is_match(&tf.content) {
                // find pattern name for this regex
                for p in PATTERNS.iter() {
                    if p.category_key == "obfuscation_signatures" && p.source == re.as_str() {
                        if seen.insert(p.name.to_string()) {
                            out.push(ObfuscatorSig { name: p.name.into(), severity: p.severity.into() });
                        }
                        break;
                    }
                }
            }
        }
    }
    out
}
