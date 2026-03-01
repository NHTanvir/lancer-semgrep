//! Pure-data application state for [`crate::gui::app::LancerApp`].
//!
//! Kept deliberately POD so it can be passed by `&mut` into the individual
//! pane render functions without any locking. The Tokio worker thread does
//! NOT touch this struct — it ships [`crate::gui::scan_runner::ScanMessage`]s
//! across a `crossbeam_channel`, and the egui paint thread is the sole
//! mutator.

use semgrep_output::ScanReport;
use std::path::PathBuf;

/// All user-visible UI state in one place.
#[derive(Default)]
pub struct AppState {
    /// Folder the user picked (via dialog, recent list, or drag-drop).
    pub target_dir: Option<PathBuf>,
    /// Free-text `--config` source the sidebar will hand to `ConfigSource::parse`.
    pub config_input: String,
    /// Latest completed scan result (None until a scan finishes).
    pub scan_report: Option<ScanReport>,
    /// Row in [`Self::scan_report`]`.findings` currently shown in the detail pane.
    pub selected_finding_idx: Option<usize>,
    /// True iff a scan worker is currently running.
    pub scan_in_flight: bool,
    /// Latest progress snapshot, updated as `ScanMessage::Progress` arrives.
    pub progress: Progress,
    /// Recently-opened folders (capped at 8 in the menubar handler).
    pub recent_dirs: Vec<PathBuf>,
    /// One-line transient status (shown in the bottom bar).
    pub status_message: String,
    /// Sidebar width persisted across sessions.
    pub left_panel_width: f32,
    /// Detail pane width persisted across sessions.
    pub right_panel_width: f32,
}

/// Progress snapshot from the scan worker.
///
/// `total == 0` is the indeterminate state (enumerating, or no total known
/// yet). The sidebar progress bar renders that as a half-full bar.
#[derive(Default, Debug, Clone)]
pub struct Progress {
    pub current: usize,
    pub total: usize,
    pub stage: String,
}
