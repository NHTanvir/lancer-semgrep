//! Dark / light theme toggle.
//!
//! Stored in [`crate::gui::config::PersistedConfig`] so the choice survives
//! restarts. Wired through the Settings menu in [`crate::gui::menubar`].

use serde::{Deserialize, Serialize};

/// User-selected colour scheme.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize,
)]
pub enum Theme {
    /// Default — easier on the eyes for security review sessions.
    #[default]
    Dark,
    Light,
}

impl Theme {
    /// Apply this theme to the egui context.
    ///
    /// Called once per frame from `LancerApp::update`; egui's visuals are
    /// idempotent so re-applying every frame is fine and lets the
    /// menubar's radio buttons take effect immediately.
    pub fn apply(self, ctx: &egui::Context) {
        match self {
            Theme::Dark => ctx.set_visuals(egui::Visuals::dark()),
            Theme::Light => ctx.set_visuals(egui::Visuals::light()),
        }
    }
}
