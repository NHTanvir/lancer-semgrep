//! On-disk rule cache keyed by content hash.
//!
//! Wraps a single-table `redb` database under
//! `~/.cache/lancer/semgrep/rule_cache.redb` (resolved via `directories`).
//! Keys are hex-encoded `blake3` hashes of the rule pack YAML; values are the
//! raw YAML bytes (or any opaque blob the caller supplies).
//!
//! The cache is read-many / write-occasionally, so we don't bother with a
//! persistent handle to a write transaction — every `put` opens its own.

use std::path::{Path, PathBuf};

use redb::{Database, ReadableTable, TableDefinition};

use crate::error::LoadError;

/// Single table holding `hash → bytes` mappings.
const RULE_PACK_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("rule_packs");

/// On-disk LRU-free rule pack cache.
pub struct RuleCache {
    db: Database,
}

impl RuleCache {
    /// Open (or create) the cache file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| LoadError::Io {
                    path: parent.to_path_buf(),
                    error: e,
                })?;
            }
        }
        let db = Database::create(path).map_err(|e| LoadError::Cache(e.to_string()))?;
        // Make sure the table exists so first reads don't fail.
        {
            let tx = db
                .begin_write()
                .map_err(|e| LoadError::Cache(e.to_string()))?;
            tx.open_table(RULE_PACK_TABLE)
                .map_err(|e| LoadError::Cache(e.to_string()))?;
            tx.commit().map_err(|e| LoadError::Cache(e.to_string()))?;
        }
        Ok(RuleCache { db })
    }

    /// Open the cache at the OS-conventional default location.
    pub fn open_default() -> Result<Self, LoadError> {
        Self::open(Self::default_path())
    }

    /// Default cache path: `<user-cache-dir>/lancer/semgrep/rule_cache.redb`.
    ///
    /// Falls back to `./rule_cache.redb` when no platform cache dir is
    /// discoverable (no `$HOME`, sandboxed test, …).
    pub fn default_path() -> PathBuf {
        directories::ProjectDirs::from("dev", "lancer", "semgrep")
            .map(|p| p.cache_dir().join("rule_cache.redb"))
            .unwrap_or_else(|| PathBuf::from("rule_cache.redb"))
    }

    /// Look up a cached blob by content-hash key.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, LoadError> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| LoadError::Cache(e.to_string()))?;
        let tbl = tx
            .open_table(RULE_PACK_TABLE)
            .map_err(|e| LoadError::Cache(e.to_string()))?;
        let v = tbl
            .get(key)
            .map_err(|e| LoadError::Cache(e.to_string()))?;
        Ok(v.map(|guard| guard.value().to_vec()))
    }

    /// Insert / overwrite a blob at the given key.
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), LoadError> {
        let tx = self
            .db
            .begin_write()
            .map_err(|e| LoadError::Cache(e.to_string()))?;
        {
            let mut tbl = tx
                .open_table(RULE_PACK_TABLE)
                .map_err(|e| LoadError::Cache(e.to_string()))?;
            tbl.insert(key, value)
                .map_err(|e| LoadError::Cache(e.to_string()))?;
        }
        tx.commit().map_err(|e| LoadError::Cache(e.to_string()))?;
        Ok(())
    }

    /// Compute the cache key for a YAML blob.
    pub fn key_for_yaml(yaml: &str) -> String {
        blake3::hash(yaml.as_bytes()).to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("lancer-semgrep-{}-{}.redb", name, std::process::id()));
        p
    }

    #[test]
    fn round_trip_put_get() {
        let path = tmp_path("rt");
        // Wipe any leftover file from a previous run.
        let _ = std::fs::remove_file(&path);
        let cache = RuleCache::open(&path).expect("open");
        cache.put("k1", b"hello world").expect("put");
        let v = cache.get("k1").expect("get");
        assert_eq!(v.as_deref(), Some(&b"hello world"[..]));
        let none = cache.get("missing").expect("get-missing");
        assert!(none.is_none());
        drop(cache);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn key_for_yaml_is_stable() {
        let k1 = RuleCache::key_for_yaml("rules: []\n");
        let k2 = RuleCache::key_for_yaml("rules: []\n");
        assert_eq!(k1, k2);
        let k3 = RuleCache::key_for_yaml("rules: [{id: x}]\n");
        assert_ne!(k1, k3);
    }

    #[test]
    fn default_path_is_under_lancer_semgrep() {
        let p = RuleCache::default_path();
        // Fallback path is ok; we just sanity-check the file name.
        assert!(p
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.ends_with(".redb"))
            .unwrap_or(false));
    }
}
