//! SHA-1 hashing + hash verification against Modrinth (megabase fallback).
//! Results are cached process-wide and can be prewarmed concurrently, which
//! is what took the real-mods scan from ~97 s of inline sequential HTTP down
//! to one parallel network pass.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub verified: bool,
    pub source: Option<String>,
    pub project: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub loaders: Vec<String>,
    #[serde(default)]
    pub game_versions: Vec<String>,
}

fn cache() -> &'static Mutex<HashMap<String, Verification>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Verification>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .build()
}

fn unverified() -> Verification {
    Verification::default()
}

/// Two HTTP lookups worst-case (Modrinth → megabase), 8 s timeout each,
/// process-cached by hash.
pub fn verify_hash(hash: &str) -> Verification {
    if let Ok(map) = cache().lock() {
        if let Some(v) = map.get(hash) {
            return v.clone();
        }
    }
    let v = verify_uncached(hash);
    if let Ok(mut map) = cache().lock() {
        map.insert(hash.to_string(), v.clone());
    }
    v
}

fn verify_uncached(hash: &str) -> Verification {
    let agent = agent();

    // 1) Modrinth
    let url = format!("https://api.modrinth.com/v2/version_file/{}", hash);
    match agent
        .get(&url)
        .set("User-Agent", "WonderAnalyzer/1.0")
        .set("Accept", "application/json")
        .call()
    {
        Ok(resp) if resp.status() == 200 => {
            if let Ok(body) = resp.into_string() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                    let project = val.get("project").cloned();
                    let title = project
                        .as_ref()
                        .and_then(|p| p.get("title"))
                        .and_then(|t| t.as_str())
                        .map(|s| s.to_string());
                    let project_id = project
                        .as_ref()
                        .and_then(|p| p.as_str())
                        .map(|s| s.to_string());
                    return Verification {
                        verified: true,
                        source: Some("Modrinth".into()),
                        project: title.or(project_id).or_else(|| Some("Unknown".into())),
                        version: val
                            .get("version_number")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| Some("Unknown".into())),
                        loaders: val
                            .get("loaders")
                            .and_then(|l| l.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        game_versions: val
                            .get("game_versions")
                            .and_then(|l| l.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    };
                }
            }
        }
        _ => {}
    }

    // 2) Megabase fallback
    let url = format!("https://megabase.vercel.app/api/query?hash={}", hash);
    match agent
        .get(&url)
        .set("User-Agent", "WonderAnalyzer/1.0")
        .set("Accept", "application/json")
        .call()
    {
        Ok(resp) if resp.status() == 200 => {
            if let Ok(body) = resp.into_string() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                    let found = val.get("found").and_then(|f| f.as_bool()).unwrap_or(false);
                    let has_project = val.get("project").and_then(|p| p.as_str()).is_some();
                    if found || has_project {
                        return Verification {
                            verified: true,
                            source: Some("Megabase".into()),
                            project: val
                                .get("project")
                                .and_then(|p| p.as_str())
                                .map(|s| s.to_string())
                                .or_else(|| Some("Unknown".into())),
                            version: val
                                .get("version")
                                .and_then(|p| p.as_str())
                                .map(|s| s.to_string())
                                .or_else(|| Some("Unknown".into())),
                            loaders: Vec::new(),
                            game_versions: Vec::new(),
                        };
                    }
                }
            }
        }
        _ => {}
    }

    unverified()
}

/// Fill the cache for many hashes concurrently (8 workers). Inline per-jar
/// verification used to dominate the mod scan's runtime.
pub fn prewarm(hashes: &[String]) {
    const WORKERS: usize = 8;
    let unique: Vec<String> = {
        let mut seen: Vec<String> = Vec::new();
        let map = cache().lock().map(|m| m.clone()).unwrap_or_default();
        for h in hashes {
            if !h.is_empty() && !seen.contains(h) && !map.contains_key(h) {
                seen.push(h.clone());
            }
        }
        seen
    };
    if unique.is_empty() {
        return;
    }
    let workers = WORKERS.min(unique.len());
    let chunk_size = unique.len().div_ceil(workers);
    std::thread::scope(|scope| {
        for chunk in unique.chunks(chunk_size) {
            let chunk: Vec<String> = chunk.to_vec();
            scope.spawn(move || {
                for h in chunk {
                    let v = verify_uncached(&h);
                    if let Ok(mut map) = cache().lock() {
                        map.insert(h, v);
                    }
                }
            });
        }
    });
}

/// SHA-1 of a file, lowercase hex (Modrinth's identifier).
pub fn sha1_file(path: &Path) -> std::io::Result<String> {
    use sha1::{Digest, Sha1};
    let mut file = File::open(path)?;
    let mut hasher = Sha1::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha1_matches_fips_abc() {
        let dir = std::env::temp_dir().join("wa_verifier_test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("abc.txt");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"abc").unwrap();
        drop(f);
        assert_eq!(
            sha1_file(&p).unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn cache_roundtrip() {
        let v = Verification {
            verified: true,
            source: Some("Test".into()),
            project: Some("p".into()),
            version: Some("1".into()),
            loaders: vec![],
            game_versions: vec![],
        };
        cache()
            .lock()
            .unwrap()
            .insert("cachetest-hash".to_string(), v.clone());
        assert!(verify_hash("cachetest-hash").verified);
        cache().lock().unwrap().remove("cachetest-hash");
    }
}
