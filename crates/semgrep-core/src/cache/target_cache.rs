//! In-process parsed-document cache.
//!
//! Generic over the parsed-doc type so semgrep-core doesn't need to know
//! about tree-sitter types. The binary crate (lancer-semgrep) instantiates
//! `TargetCache<ParsedDoc>` where `ParsedDoc` owns its tree-sitter `Tree` +
//! source bytes.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;

/// Cache keyed by `(path, blake3(content))`. Two scans of the same path with
/// the same content share the parsed tree; modified files automatically miss.
pub struct TargetCache<T> {
    inner: DashMap<(PathBuf, [u8; 32]), Arc<T>>,
}

impl<T> Default for TargetCache<T> {
    fn default() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }
}

impl<T> TargetCache<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up or compute. The closure runs at most once per key even under
    /// contention (DashMap entry-API serializes inserts on the same shard).
    pub fn get_or_insert_with<F: FnOnce() -> T>(
        &self,
        path: PathBuf,
        content_hash: [u8; 32],
        f: F,
    ) -> Arc<T> {
        self.inner
            .entry((path, content_hash))
            .or_insert_with(|| Arc::new(f()))
            .clone()
    }

    /// Stable hash of source bytes. Used as part of the cache key.
    pub fn hash_content(content: &[u8]) -> [u8; 32] {
        *blake3::hash(content).as_bytes()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_first_call() {
        let cache: TargetCache<u32> = TargetCache::new();
        let h = TargetCache::<u32>::hash_content(b"hello");
        let mut calls = 0;
        let _ = cache.get_or_insert_with(PathBuf::from("/a"), h, || {
            calls += 1;
            7
        });
        let v = cache.get_or_insert_with(PathBuf::from("/a"), h, || {
            calls += 1;
            99
        });
        assert_eq!(*v, 7);
        assert_eq!(calls, 1);
    }

    #[test]
    fn distinct_content_hashes_distinct_entries() {
        let h1 = TargetCache::<u32>::hash_content(b"a");
        let h2 = TargetCache::<u32>::hash_content(b"b");
        assert_ne!(h1, h2);
    }
}
