//! Center pane: sortable findings table.
//!
//! Built on `egui_extras::TableBuilder`. Click a row (via the selectable
//! label in the Rule column) to populate the detail pane.

use crate::gui::state::AppState;
use egui_extras::{Column, TableBuilder};
use semgrep_core::Severity;

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    let count = state
        .scan_report
        .as_ref()
        .map(|r| r.findings.len())
        .unwrap_or(0);
    ui.heading(format!("Findings ({count})"));
    ui.separator();

    if state.scan_report.is_none() {
        ui.weak("Run a scan to see findings here.");
        return;
    }
    if count == 0 {
        ui.weak("No findings.");
        return;
    }

    let selected = state.selected_finding_idx;
    let mut new_selection: Option<usize> = None;

    // Re-borrow `state.scan_report` immutably here. We close out the
    // borrow before touching `state.selected_finding_idx` at the end of
    // the function (otherwise the mutable borrow conflicts).
    {
        let report = state
            .scan_report
            .as_ref()
            .expect("scan_report presence checked above");
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::auto().at_least(56.0)) // severity
            .column(Column::auto().at_least(180.0)) // rule
            .column(Column::auto().at_least(220.0)) // file
            .column(Column::auto().at_least(60.0)) // line
            .column(Column::remainder().at_least(240.0)) // message
            .header(22.0, |mut h| {
                h.col(|ui| {
                    ui.strong("Sev");
                });
                h.col(|ui| {
                    ui.strong("Rule");
                });
                h.col(|ui| {
                    ui.strong("File");
                });
                h.col(|ui| {
                    ui.strong("Line");
                });
                h.col(|ui| {
                    ui.strong("Message");
                });
            })
            .body(|mut body| {
                for (idx, f) in report.findings.iter().enumerate() {
                    body.row(20.0, |mut row| {
                        let is_selected = selected == Some(idx);
                        row.col(|ui| {
                            ui.label(severity_badge(f.severity));
                        });
                        row.col(|ui| {
                            if ui
                                .selectable_label(
                                    is_selected,
                                    f.rule_id.as_str(),
                                )
                                .clicked()
                            {
                                new_selection = Some(idx);
                            }
                        });
                        row.col(|ui| {
                            ui.label(f.file.display().to_string());
                        });
                        row.col(|ui| {
                            ui.label(format!(
                                "{}:{}",
                                f.range.start.line, f.range.start.column
                            ));
                        });
                        row.col(|ui| {
                            ui.label(&f.message);
                        });
                    });
                }
            });
    }

    if let Some(idx) = new_selection {
        state.selected_finding_idx = Some(idx);
    }
}

fn severity_badge(s: Severity) -> egui::RichText {
    use egui::Color32;
    let (text, color) = match s {
        Severity::Error => ("ERROR", Color32::from_rgb(220, 80, 80)),
        Severity::Warning => ("WARN", Color32::from_rgb(220, 180, 60)),
        Severity::Info => ("INFO", Color32::from_rgb(120, 160, 220)),
    };
    egui::RichText::new(text).color(color).strong()
}
