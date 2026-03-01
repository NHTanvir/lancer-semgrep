//! The top-level egui application.
//!
//! Owns [`AppState`], the persisted [`PersistedConfig`], the optional in-
//! flight [`ScanHandle`], and the toast queue. Every frame it:
//!
//! 1. Applies the current theme.
//! 2. Drains the scan worker channel (if any).
//! 3. Renders menu bar / status bar / sidebar / detail / center pane.
//! 4. Renders queued toast notifications.
//!
//! On drop it flushes the current state back into the persisted config.

use eframe::{App, CreationContext, Frame};

use crate::gui::config::PersistedConfig;
use crate::gui::scan_runner::{ScanHandle, ScanMessage};
use crate::gui::state::{AppState, Progress};

/// The eframe application. Held by the `eframe::run_native` event loop.
pub struct LancerApp {
    /// All UI state.
    state: AppState,
    /// Persisted prefs (theme, recent dirs, panel widths).
    config: PersistedConfig,
    /// Channel into the background scan worker, when one is running.
    scan_handle: Option<ScanHandle>,
    /// Pending toast notifications (egui-notify).
    toasts: egui_notify::Toasts,
}

impl LancerApp {
    /// Construct the app from eframe's creation context.
    ///
    /// Loads the persisted config and seeds the initial panel widths.
    pub fn new(_cc: &CreationContext<'_>) -> Self {
        let config = PersistedConfig::load();
        let mut state = AppState::default();
        state.left_panel_width = if config.left_panel_width > 0.0 {
            config.left_panel_width
        } else {
            240.0
        };
        state.right_panel_width = if config.right_panel_width > 0.0 {
            config.right_panel_width
        } else {
            340.0
        };
        state.recent_dirs = config.recent_dirs.clone();
        Self {
            state,
            config,
            scan_handle: None,
            toasts: egui_notify::Toasts::default(),
        }
    }
}

impl App for LancerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        self.config.theme.apply(ctx);

        // Drain scan messages if a scan is in flight. We pull the receiver
        // out of `self.scan_handle` as a cheap clone so we don't carry a
        // borrow on `self.scan_handle` into the loop body (where we need to
        // mutate `self.state` and possibly null out the handle).
        let rx_opt = self.scan_handle.as_ref().map(|h| h.rx.clone());
        if let Some(rx) = rx_opt {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMessage::Progress { current, total, stage } => {
                        self.state.progress =
                            Progress { current, total, stage };
                    }
                    ScanMessage::Done(report) => {
                        self.state.scan_report = Some(*report);
                        self.state.scan_in_flight = false;
                        self.state.selected_finding_idx = None;
                        self.toasts.success("scan complete");
                    }
                    ScanMessage::Error(e) => {
                        self.state.scan_in_flight = false;
                        self.toasts.error(format!("scan failed: {e}"));
                    }
                    ScanMessage::Cancelled => {
                        self.state.scan_in_flight = false;
                        self.toasts.info("scan cancelled");
                    }
                }
            }
            if !self.state.scan_in_flight {
                self.scan_handle = None;
            }
        }

        crate::gui::menubar::draw(ctx, &mut self.state, &mut self.config);

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            crate::gui::statusbar::draw(ui, &self.state);
        });

        egui::SidePanel::left("sidebar")
            .resizable(true)
            .default_width(self.state.left_panel_width)
            .show(ctx, |ui| {
                crate::gui::panes::sidebar::draw(
                    ui,
                    &mut self.state,
                    &mut self.scan_handle,
                    &mut self.toasts,
                );
            });

        egui::SidePanel::right("detail")
            .resizable(true)
            .default_width(self.state.right_panel_width)
            .show(ctx, |ui| {
                crate::gui::panes::detail::draw(ui, &self.state);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            crate::gui::panes::findings_table::draw(ui, &mut self.state);
        });

        self.toasts.show(ctx);

        // While a scan is running, request continuous repaints so progress
        // updates show up without waiting for user input.
        if self.state.scan_in_flight {
            ctx.request_repaint();
        }
    }
}

impl Drop for LancerApp {
    fn drop(&mut self) {
        self.config.recent_dirs = self.state.recent_dirs.clone();
        self.config.left_panel_width = self.state.left_panel_width;
        self.config.right_panel_width = self.state.right_panel_width;
        self.config.save();
    }
}
