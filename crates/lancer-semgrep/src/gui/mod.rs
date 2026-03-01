//! Native eframe/egui GUI. Gated behind `gui` cargo feature.
//!
//! Three-pane layout (left: targets/jobs; center: findings table; right:
//! selected-finding detail). Long-running scans go through `scan_runner` on
//! a Tokio task pool; progress arrives via `crossbeam_channel` so the
//! egui paint thread never blocks. See plan §"GUI (Lancer-standard pattern)".

pub mod app;
pub mod config;
pub mod http_server;
pub mod menubar;
pub mod panes;
pub mod scan_runner;
pub mod state;
pub mod statusbar;
pub mod theme;

pub use app::LancerApp;

/// Launch the GUI. Blocks the current thread until the window closes.
///
/// `eframe::run_native` owns its own event loop, so this function returns
/// only when the user closes the main window (or `LancerApp` requests a
/// close via `ViewportCommand::Close`).
pub fn launch() -> eyre::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("lancer-semgrep"),
        ..Default::default()
    };
    eframe::run_native(
        "lancer-semgrep",
        options,
        Box::new(|cc| Ok(Box::new(LancerApp::new(cc)))),
    )
    .map_err(|e| eyre::eyre!("eframe error: {e}"))
}
