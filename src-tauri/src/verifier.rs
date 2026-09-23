//! Hash Verification Module — verifies SHA-1 hashes against Modrinth,
//! with megabase.vercel.app as fallback. Port of backend/verifier.js.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loaders: Vec<String>,
    #[serde(default, rename = "gameVersions", skip_serializing_if = "Vec::is_empty")]
    pub game_versions: Vec<String>,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .user_agent("WonderAnalyzer/2.0")
        .build()
}

/// Verify a SHA-1 hash against the Modrinth API, falling back to megabase.
pub fn verify_hash(hash: &str) -> Verification {
    let not_found = Verification { verified: false, source: None, ..Default::default() };
    let url = format!("https://api.modrinth.com/v2/version_file/{}", hash);
    match agent().get(&url).set("Accept", "application/json").call() {
        Ok(resp) => {
            if let Ok(v) = resp.into_json::<serde_json::Value>() {
                if let Some(title) = v.get("project").and_then(|p| p.get("title")).and_then(|t| t.as_str()) {
                    return Verification {
                        verified: true,
                        source: Some("Modrinth".into()),
                        project: Some(title.to_string()),
                        version: v.get("version_number").and_then(|x| x.as_str()).map(String::from),
                        loaders: v.get("loaders").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect()).unwrap_or_default(),
                        game_versions: v.get("game_versions").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect()).unwrap_or_default(),
                    };
                } else if let Some(pid) = v.get("project_id").and_then(|x| x.as_str()) {
                    return Verification {
                        verified: true,
                        source: Some("Modrinth".into()),
                        project: Some(pid.to_string()),
                        version: v.get("version_number").and_then(|x| x.as_str()).map(String::from),
                        loaders: v.get("loaders").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect()).unwrap_or_default(),
                        game_versions: v.get("game_versions").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect()).unwrap_or_default(),
                    };
                }
            }
            // 200 without parseable project → try megabase
            verify_against_megabase(hash)
        }
        Err(ureq::Error::Status(_code, _resp)) => verify_against_megabase(hash),
        Err(_) => not_found,
    }
}

/// Fallback verification against megabase.
pub fn verify_against_megabase(hash: &str) -> Verification {
    let not_found = Verification { verified: false, source: None, ..Default::default() };
    let url = format!("https://megabase.vercel.app/api/query?hash={}", hash);
    match agent().get(&url).set("Accept", "application/json").call() {
        Ok(resp) => {
            match resp.into_json::<serde_json::Value>() {
                Ok(v) => {
                    let found = v.get("found").and_then(|x| x.as_bool()).unwrap_or(false);
                    let has_project = v.get("project").map(|p| !p.is_null()).unwrap_or(false);
                    if found || has_project {
                        Verification {
                            verified: true,
                            source: Some("Megabase".into()),
                            project: v.get("project").and_then(|x| x.as_str()).map(String::from).or(Some("Unknown".into())),
                            version: v.get("version").and_then(|x| x.as_str()).map(String::from).or(Some("Unknown".into())),
                            loaders: vec![],
                            game_versions: vec![],
                        }
                    } else {
                        not_found
                    }
                }
                Err(_) => not_found,
            }
        }
        Err(_) => not_found,
    }
}
