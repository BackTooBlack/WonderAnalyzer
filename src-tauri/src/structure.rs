//! Structural Analysis Module — port of backend/structure.js

use crate::scanner::{JarEntry, TextFile};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StructuralFinding {
    #[serde(rename = "type")]
    pub finding_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Analyze the structural characteristics of a mod.
pub fn analyze_structure(entries: &[JarEntry], text_files: &[TextFile]) -> Vec<StructuralFinding> {
    let mut findings = Vec::new();

    // 1. Mod loader detection
    if let Some(loader_info) = detect_mod_loader(entries, text_files) {
        findings.push(StructuralFinding {
            finding_type: "mod_loader".into(),
            value: Some(loader_info.0),
            severity: "info".into(),
            message: format!("Mod loader: {}", loader_info.1),
            details: Some(Value::String(loader_info.1)),
        });
    }

    // 2. Mod metadata
    let mod_info = extract_mod_metadata(text_files);
    if let Some(mod_id) = &mod_info.0 {
        findings.push(StructuralFinding {
            finding_type: "mod_id".into(),
            value: Some(mod_id.clone()),
            severity: "info".into(),
            message: format!("Mod ID: {}", mod_id),
            details: None,
        });
    }
    if let Some(authors) = &mod_info.1 {
        findings.push(StructuralFinding {
            finding_type: "mod_author".into(),
            value: Some(authors.clone()),
            severity: "info".into(),
            message: format!("Author(s): {}", authors),
            details: None,
        });
    }

    // 3. Hollow shell detection
    let inner_jars: Vec<&JarEntry> = entries
        .iter()
        .filter(|e| regex_is_nested_jar(&e.name))
        .collect();
    let outer_classes: Vec<&JarEntry> = entries
        .iter()
        .filter(|e| e.name.ends_with(".class") && !e.name.starts_with("META-INF"))
        .collect();

    if !inner_jars.is_empty() && outer_classes.len() < 5 {
        findings.push(StructuralFinding {
            finding_type: "hollow_shell".into(),
            value: None,
            severity: "critical".into(),
            message: "Hollow shell mod detected: minimal outer classes wrapping inner JAR(s)".into(),
            details: Some(Value::String(format!(
                "Only {} outer class(es) with {} nested JAR(s)",
                outer_classes.len(),
                inner_jars.len()
            ))),
        });
    }

    // 4. Suspicious nested JARs without version info
    let nested_re = regex::Regex::new(r"v?\d+\.\d+").unwrap();
    for jar in &inner_jars {
        let jar_name = jar.name.rsplit('/').next().unwrap_or(&jar.name);
        if !nested_re.is_match(jar_name) && jar_name.len() < 10 {
            findings.push(StructuralFinding {
                finding_type: "suspicious_nested_jar".into(),
                value: None,
                severity: "warning".into(),
                message: format!("Suspicious nested JAR: {} (no version info)", jar_name),
                details: Some(Value::String(jar.name.clone())),
            });
        }
    }

    // 5. Suspicious file locations
    static SUSPICIOUS_PATHS: &[(&str, &str)] = &[
        (r"(?i)^scripts?/", "Script files in root (possible cheat scripts)"),
        (r"(?i)^natives?/", "Native libraries directory"),
        (r"(?i)^config/.*cheat", "Cheat configuration files"),
        (r"(?i)^assets/.*clickgui", "ClickGUI assets (cheat client UI)"),
        (r"(?i)\.sh$|\.sh\b|\.bat\b|\.cmd\b|\.ps1\b", "Executable script found"),
        (r"(?i)^linux\b|^windows\b|^macos\b|^os/", "Platform-specific native folder"),
        (r"(?i)\.so\b|\.dll\b|\.dylib\b|\.jnilib\b", "Native binary file"),
    ];

    for entry in entries {
        if entry.is_directory {
            continue;
        }
        for (pattern, message) in SUSPICIOUS_PATHS {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(&entry.name) {
                    findings.push(StructuralFinding {
                        finding_type: "suspicious_path".into(),
                        value: None,
                        severity: "warning".into(),
                        message: message.to_string(),
                        details: Some(Value::String(entry.name.clone())),
                    });
                }
            }
        }
    }

    // 6. Package depth
    let mut packages: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for entry in entries {
        if entry.is_directory || !entry.name.ends_with(".class") {
            continue;
        }
        let parts: Vec<&str> = entry.name.split('/').collect();
        if parts.len() > 1 {
            *packages.entry(parts[..parts.len() - 1].join("/")).or_insert(0) += 1;
        }
    }
    for (pkg, count) in &packages {
        if pkg.split('/').count() > 6 {
            findings.push(StructuralFinding {
                finding_type: "deep_package".into(),
                value: None,
                severity: "info".into(),
                message: format!("Deep package nesting: {}", pkg),
                details: Some(Value::String(format!("{} class(es)", count))),
            });
        }
    }

    // 7. Version-specific directories
    let version_re = regex::Regex::new(r"\d+\.\d+(\.\d+)?").unwrap();
    let version_dirs: Vec<String> = entries
        .iter()
        .filter(|e| e.is_directory && version_re.is_match(&e.name))
        .map(|e| e.name.clone())
        .collect();
    if !version_dirs.is_empty() {
        findings.push(StructuralFinding {
            finding_type: "version_dirs".into(),
            value: None,
            severity: "info".into(),
            message: format!("Contains version-specific directories: {}", version_dirs.join(", ")),
            details: None,
        });
    }

    findings
}

fn regex_is_nested_jar(name: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)^META-INF/jars/.*\.jar$").unwrap()).is_match(name)
}

/// Returns (loader_type, details)
fn detect_mod_loader(entries: &[JarEntry], text_files: &[TextFile]) -> Option<(String, String)> {
    struct Indicator {
        file: Option<&'static str>,
        pattern: Option<&'static str>,
        ci: bool,
    }
    const INDICATORS: &[(&str, &[Indicator])] = &[
        ("Forge", &[
            Indicator { file: Some("META-INF/MODLIST"), pattern: None, ci: false },
            Indicator { file: Some("META-INF/mods.toml"), pattern: None, ci: false },
            Indicator { file: Some("META-INF/mcp.mods.cfg"), pattern: None, ci: false },
            Indicator { file: None, pattern: Some(r"net\.minecraftforge|ForgeConfigSpec|FMLJavaModLoadingContext"), ci: true },
            Indicator { file: None, pattern: Some(r"@Mod\s*\("), ci: false },
        ]),
        ("Fabric", &[
            Indicator { file: Some("fabric.mod.json"), pattern: None, ci: false },
            Indicator { file: None, pattern: Some(r"fabric-loom|fabricmc"), ci: true },
            Indicator { file: None, pattern: Some(r"net\.fabricmc\.fabric|FabricLoader"), ci: true },
        ]),
        ("NeoForge", &[
            Indicator { file: Some("META-INF/neoforge.mods.toml"), pattern: None, ci: false },
            Indicator { file: None, pattern: Some(r"neoforge|NeoForge"), ci: false },
            Indicator { file: None, pattern: Some(r#"@Mod\s*\(".*neoforge"#), ci: false },
        ]),
        ("Quilt", &[
            Indicator { file: Some("quilt.mod.json"), pattern: None, ci: false },
            Indicator { file: None, pattern: Some(r"quiltloader|QuiltLoader"), ci: true },
        ]),
        ("LiteLoader", &[
            Indicator { file: Some("META-INF/litemod.json"), pattern: None, ci: false },
            Indicator { file: None, pattern: Some(r"liteloader|LiteLoader"), ci: true },
        ]),
    ];

    let file_names: std::collections::BTreeSet<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let all_content: String = text_files
        .iter()
        .map(|t| t.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    for (loader, indicators) in INDICATORS {
        for ind in indicators.iter() {
            if let Some(f) = ind.file {
                if file_names.contains(f) {
                    return Some((loader.to_string(), format!("Found {}", f)));
                }
            }
            if let Some(pat) = ind.pattern {
                if let Ok(re) = regex::RegexBuilder::new(pat).case_insensitive(ind.ci).build() {
                    if re.is_match(&all_content) {
                        return Some((loader.to_string(), format!("Content matched {}", pat)));
                    }
                }
            }
        }
    }
    None
}

/// Returns (mod_id, authors)
fn extract_mod_metadata(text_files: &[TextFile]) -> (Option<String>, Option<String>) {
    let (mut mod_id, mut authors) = (None, None);
    let re_id_json = regex::Regex::new(r#""id"\s*:\s*"([^"]+)""#).unwrap();
    let re_auth_json = regex::Regex::new(r#""authors"\s*:\s*\["?([^"\]]+)"?\]"#).unwrap();
    let re_id_toml = regex::Regex::new(r#"modId\s*=\s*"?([^"\n]+)"?"#).unwrap();
    let re_auth_toml = regex::Regex::new(r#"authors\s*=\s*"?([^"\n"]+)"?"#).unwrap();
    let re_created = regex::Regex::new(r"(?i)Created-By:\s*(.+)").unwrap();

    for tf in text_files {
        if tf.file == "fabric.mod.json" {
            if let Some(c) = re_id_json.captures(&tf.content) {
                mod_id.get_or_insert(c[1].to_string());
            }
            if let Some(c) = re_auth_json.captures(&tf.content) {
                authors.get_or_insert(c[1].to_string());
            }
        }
        if tf.file == "META-INF/mods.toml" || tf.file == "META-INF/neoforge.mods.toml" {
            if let Some(c) = re_id_toml.captures(&tf.content) {
                mod_id.get_or_insert(c[1].trim().to_string());
            }
            if let Some(c) = re_auth_toml.captures(&tf.content) {
                authors.get_or_insert(c[1].trim().to_string());
            }
        }
        if tf.file.eq_ignore_ascii_case("META-INF/MANIFEST.MF") {
            if authors.is_none() {
                if let Some(c) = re_created.captures(&tf.content) {
                    authors = Some(c[1].trim().to_string());
                }
            }
        }
    }

    (mod_id, authors)
}
