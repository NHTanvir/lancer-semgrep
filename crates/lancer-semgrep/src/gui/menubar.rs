//! Top menu bar: File / Settings / Help.
//!
//! Uses egui's built-in `menu::bar` instead of native `muda` menus so the
//! build stays cross-platform without per-OS native-menu glue. The plan
//! mentions `muda`; we defer it to a follow-up task.

use crate::gui::config::PersistedConfig;
use crate::gui::state::AppState;
use crate::gui::theme::Theme;

/// Render the top menu bar.
///
/// `state` is mutated for File-menu actions (open folder, pick from recent,
/// quit). `config` is mutated for Settings (theme).
pub fn draw(
    ctx: &egui::Context,
    state: &mut AppState,
    config: &mut PersistedConfig,
) {
    egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open Folder…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        if !state.recent_dirs.contains(&p) {
                            state.recent_dirs.insert(0, p.clone());
                            state.recent_dirs.truncate(8);
                        }
                        state.target_dir = Some(p);
                    }
                    ui.close_menu();
                }
                ui.separator();
                if !state.recent_dirs.is_empty() {
                    ui.menu_button("Recent", |ui| {
                        let recent = state.recent_dirs.clone();
                        for p in &recent {
                            if ui.button(p.display().to_string()).clicked() {
                                state.target_dir = Some(p.clone());
                                ui.close_menu();
                            }
                        }
                    });
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });

            ui.menu_button("Tools", |ui| {
                ui.label("(tool actions wire up in later tasks)");
            });

            ui.menu_button("Settings", |ui| {
                ui.label("Theme");
                ui.radio_value(&mut config.theme, Theme::Dark, "Dark");
                ui.radio_value(&mut config.theme, Theme::Light, "Light");
            });

            ui.menu_button("Help", |ui| {
                ui.label(format!(
                    "lancer-semgrep v{}",
                    env!("CARGO_PKG_VERSION")
                ));
                ui.label("Rust clone of semgrep — part of the Lancer toolkit.");
            });
        });
    });
}
