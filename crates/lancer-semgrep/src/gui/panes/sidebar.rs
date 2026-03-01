//! Left sidebar: targets / config / Run + Stop / recent dirs.
//!
//! Drag-and-drop is honoured: dragging a folder onto the window populates
//! `target_dir`.

use crate::gui::scan_runner::{spawn_scan, ScanHandle};
use crate::gui::state::AppState;

pub fn draw(
    ui: &mut egui::Ui,
    state: &mut AppState,
    handle: &mut Option<ScanHandle>,
    toasts: &mut egui_notify::Toasts,
) {
    ui.heading("Targets");
    ui.separator();
    if let Some(p) = &state.target_dir {
        ui.label(p.display().to_string());
    } else {
        ui.weak("(no folder selected)");
    }
    if ui.button("Choose folder…").clicked() {
        if let Some(p) = rfd::FileDialog::new().pick_folder() {
            if !state.recent_dirs.contains(&p) {
                state.recent_dirs.insert(0, p.clone());
                state.recent_dirs.truncate(8);
            }
            state.target_dir = Some(p);
        }
    }
    ui.add_space(8.0);

    ui.heading("Config");
    ui.text_edit_singleline(&mut state.config_input);
    ui.label("e.g. `p/python`, `./rules/`, or `auto`");

    ui.add_space(8.0);

    ui.horizontal(|ui| {
        let scan_btn = ui.add_enabled(
            !state.scan_in_flight,
            egui::Button::new("Run Scan"),
        );
        if scan_btn.clicked() {
            if let Some(dir) = state.target_dir.clone() {
                let mut rs = semgrep_rules::RuleSet::new();
                let mut config_err = false;
                match semgrep_rules::ConfigSource::parse(&state.config_input) {
                    semgrep_rules::ConfigSource::File(p) => {
                        match semgrep_rules::load_file(&p) {
                            Ok(r) => rs.extend(r),
                            Err(e) => {
                                toasts.error(format!("config: {e}"));
                                config_err = true;
                            }
                        }
                    }
                    semgrep_rules::ConfigSource::Dir(p) => {
                        match semgrep_rules::load_dir(&p) {
                            Ok(r) => rs.extend(r),
                            Err(e) => {
                                toasts.error(format!("config: {e}"));
                                config_err = true;
                            }
                        }
                    }
                    _ => {
                        toasts.info("registry sources not yet wired");
                        config_err = true;
                    }
                }
                if !config_err {
                    if rs.is_empty() {
                        toasts.warning("no rules loaded — nothing to scan");
                    } else {
                        state.scan_in_flight = true;
                        state.progress = Default::default();
                        *handle = Some(spawn_scan(vec![dir], rs));
                    }
                }
            } else {
                toasts.warning("pick a folder first");
            }
        }
        if state.scan_in_flight {
            if ui.button("Stop").clicked() {
                if let Some(h) = handle {
                    h.cancel.store(
                        true,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
        }
    });

    if state.scan_in_flight {
        let frac = if state.progress.total == 0 {
            0.5
        } else {
            state.progress.current as f32 / state.progress.total as f32
        };
        ui.add(
            egui::ProgressBar::new(frac).text(state.progress.stage.clone()),
        );
    }

    ui.add_space(8.0);
    ui.heading("Recent");
    let recent = state.recent_dirs.clone();
    for p in &recent {
        if ui.link(p.display().to_string()).clicked() {
            state.target_dir = Some(p.clone());
        }
    }

    // Drag-and-drop: any dropped folder becomes the new target.
    let dropped: Vec<egui::DroppedFile> =
        ui.ctx().input(|i| i.raw.dropped_files.clone());
    for f in dropped {
        if let Some(p) = f.path {
            if p.is_dir() {
                if !state.recent_dirs.contains(&p) {
                    state.recent_dirs.insert(0, p.clone());
                    state.recent_dirs.truncate(8);
                }
                state.target_dir = Some(p);
            }
        }
    }
}
