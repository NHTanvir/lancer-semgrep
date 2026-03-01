//! Bottom status bar.
//!
//! Shows item count, scan stage / progress, and any transient status
//! message. Stateless — pure render of [`AppState`].

use crate::gui::state::AppState;

pub fn draw(ui: &mut egui::Ui, state: &AppState) {
    ui.horizontal(|ui| {
        let count = state
            .scan_report
            .as_ref()
            .map(|r| r.findings.len())
            .unwrap_or(0);
        ui.label(format!("Items: {count}"));
        ui.separator();
        if state.scan_in_flight {
            ui.label(format!(
                "Scanning: {} ({}/{})",
                state.progress.stage, state.progress.current, state.progress.total
            ));
        } else {
            ui.label("Idle");
        }
        ui.separator();
        if !state.status_message.is_empty() {
            ui.label(&state.status_message);
        }
    });
}
