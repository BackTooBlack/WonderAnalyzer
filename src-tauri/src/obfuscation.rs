//! Obfuscation detection: class/package naming heuristics, known-obfuscator
//! signatures, and Zelix/KlassMaster *marker hit counting* (>=5 hits means
//! the jar was run through ZKM — counting distinct keywords missed the real
//! vmp jar, which stamps `ZKM26.0.2` 96 times and uses none of the longer
//! keywords).

use serde::{Deserialize, Serialize};

use crate::malware::engine;

/// Lowercased marker keywords. Substring hits are summed (not deduped).
pub const ZELIX_MARKERS_SRC: &[&[u8]] = &[
    &[32,63,54,51,34],
    &[49,54,59,41,41,55,59,41,46,63,40],
    &[49,54,59,41,41,63,55,59,41,46,63,40],
    &[49,54,59,41,41,122,55,59,41,46,63,40],
    &[32,49,55],
    &[49,54,51,55,59,34],
];
pub static ZELIX_MARKERS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    ZELIX_MARKERS_SRC.iter().map(|b| crate::malware::decode(b)).collect()
});
pub const ZELIX_MIN_MARKERS: u32 = 5;

/// Total marker *hits* across a haystack (case-insensitive).
pub fn count_zelix_markers(hay: &str) -> u32 {
    let lower = hay.to_ascii_lowercase();
    ZELIX_MARKERS
        .iter()
        .map(|m| lower.matches(m.as_str()).count() as u32)
        .sum()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Indicator {
    #[serde(rename = "type")]
    pub indicator_type: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub name: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NamingAnalysis {
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PackageAnalysis {
    pub total_packages: usize,
    pub single_letter_package_ratio: f64,
    pub deep_obfuscated_paths: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ObfuscationAnalysis {
    pub is_obfuscated: bool,
    pub score: u32,
    pub indicators: Vec<Indicator>,
    pub obfuscator_signatures: Vec<Signature>,
    pub class_naming_analysis: NamingAnalysis,
    pub package_analysis: PackageAnalysis,
    pub details: Vec<String>,
    /// Zelix/KlassMaster marker hits (>= ZELIX_MIN_MARKERS ⇒ critical).
    pub zelix_markers: u32,
}

fn is_consonant_gibberish(name: &str) -> bool {
    if name.chars().count() <= 2 {
        return false;
    }
    name.chars().all(|c| "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ".contains(c))
}

fn analyze_class_names(class_files: &[String]) -> NamingAnalysis {
    let total = class_files.len();
    let mut a = NamingAnalysis {
        total,
        ..Default::default()
    };
    if total == 0 {
        return a;
    }
    for full in class_files {
        let base = full.rsplit(['/', '\\']).next().unwrap_or(full);
        let name = base.strip_suffix(".class").unwrap_or(base);
        let chars = name.chars().count();
        if chars == 1 {
            a.single_letter += 1;
            a.short_names += 1;
        } else if chars <= 2 {
            a.short_names += 1;
        }
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()) {
            a.numeric += 1;
        }
        if name
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '$' || c == '_'))
        {
            a.unicode += 1;
        }
        if is_consonant_gibberish(name) {
            a.gibberish += 1;
        }
    }
    let t = total as f64;
    a.single_letter_ratio = a.single_letter as f64 / t;
    a.short_name_ratio = a.short_names as f64 / t;
    a.numeric_ratio = a.numeric as f64 / t;
    a.unicode_ratio = a.unicode as f64 / t;
    a.gibberish_ratio = a.gibberish as f64 / t;
    a
}

fn analyze_packages(entries: &[String]) -> PackageAnalysis {
    let mut packages: Vec<String> = Vec::new();
    for e in entries {
        if e.ends_with('/') {
            continue;
        }
        if let Some(idx) = e.rfind('/') {
            let pkg = &e[..idx];
            if !packages.iter().any(|p| p == pkg) {
                packages.push(pkg.to_string());
            }
        }
    }
    let mut single = 0usize;
    let mut deep = 0usize;
    for pkg in &packages {
        let segs: Vec<&str> = pkg.split('/').collect();
        let all_single = segs.len() > 1
            && segs
                .iter()
                .all(|s| s.chars().count() == 1 && s.chars().all(|c| c.is_ascii_lowercase()));
        if all_single {
            single += 1;
        }
        if segs.len() > 3 && segs.iter().all(|s| s.chars().count() <= 2) {
            deep += 1;
        }
    }
    let total = packages.len();
    PackageAnalysis {
        total_packages: total,
        single_letter_package_ratio: if total > 0 {
            single as f64 / total as f64
        } else {
            0.0
        },
        deep_obfuscated_paths: deep,
    }
}

/// `entries` — every jar entry name (directories with trailing '/'),
/// `texts`   — extra haystacks (manifest, entry names blob, class sample).
pub fn analyze(entries: &[String], texts: &[&str]) -> ObfuscationAnalysis {
    let class_files: Vec<String> = entries
        .iter()
        .filter(|e| e.ends_with(".class") && !e.ends_with('/'))
        .cloned()
        .collect();

    // Marker haystack: every entry name (class paths, META-INF stamps, ...)
    // + every provided text (manifest, class constant-pool strings, ...).
    let mut marker_hay = entries.join("\n");
    for t in texts {
        marker_hay.push('\n');
        marker_hay.push_str(t);
    }
    let zelix_markers = count_zelix_markers(&marker_hay);

    if class_files.is_empty() {
        return ObfuscationAnalysis {
            zelix_markers,
            ..Default::default()
        };
    }

    let class_naming = analyze_class_names(&class_files);
    let package_analysis = analyze_packages(entries);

    // Known-obfuscator signatures across names + texts.
    let mut sig_hay = entries.join("\n");
    for t in texts {
        sig_hay.push('\n');
        sig_hay.push_str(t);
    }
    let obfuscator_signatures: Vec<Signature> = engine()
        .obfuscator_signatures(&sig_hay)
        .into_iter()
        .map(|(name, severity)| Signature {
            name,
            severity: severity.to_string(),
        })
        .collect();

    let mut score = 0.0f64;
    let mut indicators: Vec<Indicator> = Vec::new();

    if class_naming.single_letter_ratio > 0.3 {
        score += class_naming.single_letter_ratio * 30.0;
        indicators.push(Indicator {
            indicator_type: "single_letter_classes".into(),
            severity: "high".into(),
            message: format!(
                "{:.0}% of classes use single-letter names",
                class_naming.single_letter_ratio * 100.0
            ),
        });
    }
    if class_naming.short_name_ratio > 0.5 {
        score += class_naming.short_name_ratio * 25.0;
        indicators.push(Indicator {
            indicator_type: "short_class_names".into(),
            severity: "medium".into(),
            message: format!(
                "{:.0}% of classes have names ≤2 characters",
                class_naming.short_name_ratio * 100.0
            ),
        });
    }
    if class_naming.numeric_ratio > 0.1 {
        score += class_naming.numeric_ratio * 25.0;
        indicators.push(Indicator {
            indicator_type: "numeric_class_names".into(),
            severity: "high".into(),
            message: format!(
                "{:.0}% of classes use numeric names",
                class_naming.numeric_ratio * 100.0
            ),
        });
    }
    if class_naming.unicode_ratio > 0.05 {
        score += class_naming.unicode_ratio * 30.0;
        indicators.push(Indicator {
            indicator_type: "unicode_class_names".into(),
            severity: "critical".into(),
            message: format!(
                "{:.0}% of classes use Unicode names",
                class_naming.unicode_ratio * 100.0
            ),
        });
    }
    if package_analysis.single_letter_package_ratio > 0.5 {
        score += package_analysis.single_letter_package_ratio * 20.0;
        indicators.push(Indicator {
            indicator_type: "single_letter_packages".into(),
            severity: "medium".into(),
            message: format!(
                "{:.0}% of packages use single-letter names",
                package_analysis.single_letter_package_ratio * 100.0
            ),
        });
    }
    if package_analysis.deep_obfuscated_paths > 0 {
        score += package_analysis.deep_obfuscated_paths as f64 * 3.0;
        indicators.push(Indicator {
            indicator_type: "deep_obfuscated_paths".into(),
            severity: "medium".into(),
            message: format!(
                "Found {} deeply nested obfuscated package paths",
                package_analysis.deep_obfuscated_paths
            ),
        });
    }
    if !obfuscator_signatures.is_empty() {
        score += obfuscator_signatures.len() as f64 * 15.0;
        for sig in &obfuscator_signatures {
            indicators.push(Indicator {
                indicator_type: "obfuscator_signature".into(),
                severity: "high".into(),
                message: format!("Detected {} obfuscator signature", sig.name),
            });
        }
    }
    if class_naming.gibberish_ratio > 0.2 {
        score += class_naming.gibberish_ratio * 15.0;
        indicators.push(Indicator {
            indicator_type: "gibberish_names".into(),
            severity: "medium".into(),
            message: format!(
                "{:.0}% of classes appear to have gibberish names",
                class_naming.gibberish_ratio * 100.0
            ),
        });
    }

    let score = score.min(100.0).round() as u32;
    let is_obfuscated = score > 25 || zelix_markers >= ZELIX_MIN_MARKERS;

    ObfuscationAnalysis {
        is_obfuscated,
        score,
        indicators,
        obfuscator_signatures,
        class_naming_analysis: class_naming,
        package_analysis,
        details: Vec::new(),
        zelix_markers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zelix_counts_hits_not_distinct_keywords() {
        // The real vmp jar: 96× "ZKM26.0.2" stamps, none of the long words.
        let hay = "ZKM26.0.2 ZKM26.0.2 ZKM26.0.2 ZKM26.0.2 ZKM26.0.2 ZKM26.0.2";
        assert!(count_zelix_markers(hay) >= ZELIX_MIN_MARKERS);
        // Distinct-keyword counting would have said 1.
        let distinct: Vec<&str> = ZELIX_MARKERS
            .iter()
            .map(|s| s.as_str())
            .filter(|m| hay.to_ascii_lowercase().contains(*m))
            .collect();
        assert_eq!(distinct.len(), 1);
    }

    #[test]
    fn fixture_zkm_jar_is_obfuscated_critical() {
        let entries: Vec<String> = [
            "fabric.mod.json",
            "zelix/a.class",
            "klassmaster/b.class",
            "klassemaster/c.class",
            "META-INF/zkm.dat",
            "klimax/d.class",
            "zz/e.class",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let manifest = "{\"id\":\"zkmcheat\",\"version\":\"0.1.0\"}";
        let a = analyze(&entries, &[manifest, "META-INF/zkm.dat"]);
        assert!(a.zelix_markers >= 5, "markers={}", a.zelix_markers);
        assert!(a.is_obfuscated);
        assert!(a.score > 25);
    }

    #[test]
    fn clean_jar_not_obfuscated() {
        let entries: Vec<String> = [
            "fabric.mod.json",
            "net/caffeinemc/sodium/Main.class",
            "net/caffeinemc/sodium/Options.class",
            "net/caffeinemc/sodium/config/SodiumConfig.class",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = analyze(&entries, &["{\"id\":\"sodium\"}"]);
        assert!(!a.is_obfuscated, "score={} markers={}", a.score, a.zelix_markers);
        assert_eq!(a.zelix_markers, 0);
    }

    #[test]
    fn no_classes_returns_default_with_markers() {
        let entries: Vec<String> = vec!["fabric.mod.json".to_string()];
        let a = analyze(&entries, &["zkm"]);
        assert!(!a.is_obfuscated);
        assert_eq!(a.score, 0);
        assert_eq!(a.zelix_markers, 1);
    }
}
