//! Persistent user preferences.
//!
//! Stored as JSON under the platform's per-user config directory
//! (`~/.config/lancer/semgrep/` on Linux, `%APPDATA%\lancer\semgrep\` on
//! Windows, `~/Library/Application Support/dev.lancer.semgrep/` on macOS).
//! The `directories::ProjectDirs` crate handles the platform mapping.
//!
//! Loaded once in [`crate::gui::app::LancerApp::new`] and saved in `Drop`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Snapshot of the bits of [`crate::gui::state::AppState`] that should
/// survive across app restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedConfig {
    /// Dark / light theme.
    #[serde(default)]
    pub theme: super::theme::Theme,
    /// Most-recently-opened folders (newest first).
    #[serde(default)]
    pub recent_dirs: Vec<PathBuf>,
    /// Sidebar width in logical pixels (0.0 ⇒ use default 240 px).
    #[serde(default)]
    pub left_panel_width: f32,
    /// Detail pane width in logical pixels (0.0 ⇒ use default 340 px).
    #[serde(default)]
    pub right_panel_width: f32,
}

impl PersistedConfig {
    /// Absolute path to the JSON config file (platform-specific).
    ///
    /// Falls back to a relative `lancer-semgrep-config.json` when
    /// `ProjectDirs` cannot determine a home dir (rare — usually means the
    /// user is running in a stripped-down sandbox).
    pub fn path() -> PathBuf {
        directories::ProjectDirs::from("dev", "lancer", "semgrep")
            .map(|p| p.config_dir().join("lancer-semgrep-config.json"))
            .unwrap_or_else(|| PathBuf::from("lancer-semgrep-config.json"))
    }

    /// Read + decode the JSON config. Returns `Default::default()` on any
    /// error (missing file, invalid JSON, schema drift) — we never block
    /// startup over a bad config file.
    pub fn load() -> Self {
        let p = Self::path();
        std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Best-effort save. Ignores I/O errors — losing prefs on disk-full is
    /// not worth surfacing to the user mid-shutdown.
    pub fn save(&self) {
        let p = Self::path();
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(p, json);
        }
    }
}
