//! Persistent compiled-pattern cache.
//!
//! Keyed by the BLAKE3 hash of the *rule YAML text* so that "same rule text"
//! always hits the cache regardless of source path. Value is opaque bytes —
//! the cache doesn't know what's inside; callers serialise whatever compiled
//! shape they want (bincode-encoded `PatternAst`, postcard, raw JSON, …).

use std::path::{Path, PathBuf};

use redb::{Database, TableDefinition};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("compiled_patterns");

/// On-disk cache for compiled rule patterns.
pub struct RuleCache {
    db: Database,
}

impl RuleCache {
    /// Open or create the cache database at `path`. Parent directory must
    /// already exist; callers can use `RuleCache::default_path` + `create_dir_all`
    /// to set that up.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, crate::SemgrepError> {
        let db = Database::create(path.as_ref())
            .map_err(|e| crate::SemgrepError::Redb(e.to_string()))?;
        Ok(Self { db })
    }

    /// Default location: `~/.cache/lancer/semgrep/compiled_patterns.redb`
    /// (or the per-OS equivalent via the `directories` crate).
    pub fn default_path() -> PathBuf {
        directories::ProjectDirs::from("dev", "lancer", "semgrep")
            .map(|p| p.cache_dir().join("compiled_patterns.redb"))
            .unwrap_or_else(|| PathBuf::from("compiled_patterns.redb"))
    }

    /// Content-hash key for a rule YAML text.
    pub fn key_for_pattern(pattern_yaml_or_str: &str) -> String {
        blake3::hash(pattern_yaml_or_str.as_bytes()).to_hex().to_string()
    }

    /// Look up an entry. Returns `None` when the key is absent.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, crate::SemgrepError> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| crate::SemgrepError::Redb(e.to_string()))?;
        let tbl = tx
            .open_table(TABLE)
            .map_err(|e| crate::SemgrepError::Redb(e.to_string()))?;
        let v = tbl
            .get(key)
            .map_err(|e| crate::SemgrepError::Redb(e.to_string()))?;
        Ok(v.map(|g| g.value().to_vec()))
    }

    /// Insert / overwrite an entry.
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), crate::SemgrepError> {
        let tx = self
            .db
            .begin_write()
            .map_err(|e| crate::SemgrepError::Redb(e.to_string()))?;
        {
            let mut tbl = tx
                .open_table(TABLE)
                .map_err(|e| crate::SemgrepError::Redb(e.to_string()))?;
            tbl.insert(key, value)
                .map_err(|e| crate::SemgrepError::Redb(e.to_string()))?;
        }
        tx.commit()
            .map_err(|e| crate::SemgrepError::Redb(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_deterministic() {
        let a = RuleCache::key_for_pattern("rules:\n  - id: x\n");
        let b = RuleCache::key_for_pattern("rules:\n  - id: x\n");
        let c = RuleCache::key_for_pattern("rules:\n  - id: y\n");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
