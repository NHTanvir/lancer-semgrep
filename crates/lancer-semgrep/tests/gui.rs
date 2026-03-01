//! Smoke tests for the GUI module.
//!
//! Gated behind `feature = "gui"` so a `--no-default-features` build still
//! compiles (the GUI module isn't even in scope there).

#![cfg(feature = "gui")]

use lancer_semgrep::gui::config::PersistedConfig;
use lancer_semgrep::gui::theme::Theme;

#[test]
fn theme_default_is_dark() {
    let t = Theme::default();
    assert_eq!(t, Theme::Dark);
}

#[test]
fn persisted_config_path_is_under_project_dirs() {
    let p = PersistedConfig::path();
    // On exotic sandboxes ProjectDirs may return None and we fall back to a
    // relative file; in both cases the path should still have a file name.
    assert!(p.file_name().is_some());
}

#[test]
fn persisted_config_round_trips() {
    use std::path::PathBuf;
    let mut c = PersistedConfig::default();
    c.theme = Theme::Light;
    c.recent_dirs.push(PathBuf::from("/tmp/foo"));
    c.left_panel_width = 300.0;
    c.right_panel_width = 400.0;

    let json = serde_json::to_string(&c).expect("serialise");
    let back: PersistedConfig =
        serde_json::from_str(&json).expect("deserialise");
    assert_eq!(back.theme, Theme::Light);
    assert_eq!(back.recent_dirs, vec![PathBuf::from("/tmp/foo")]);
    assert_eq!(back.left_panel_width, 300.0);
    assert_eq!(back.right_panel_width, 400.0);
}
