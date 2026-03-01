//! Right pane: full detail of the selected finding.
//!
//! Read-only view of `AppState`. Pulls the finding indexed by
//! `selected_finding_idx` out of the latest [`semgrep_output::ScanReport`].

use crate::gui::state::AppState;

pub fn draw(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("Detail");
    ui.separator();

    let Some(idx) = state.selected_finding_idx else {
        ui.weak("Select a finding to see details.");
        return;
    };
    let Some(report) = &state.scan_report else {
        return;
    };
    let Some(f) = report.findings.get(idx) else {
        return;
    };

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.label(
            egui::RichText::new(f.rule_id.as_str())
                .strong()
                .size(16.0),
        );
        ui.separator();
        ui.label(format!("Severity: {:?}", f.severity));
        ui.label(format!("File: {}", f.file.display()));
        ui.label(format!(
            "Line: {}:{}",
            f.range.start.line, f.range.start.column
        ));
        ui.add_space(6.0);
        ui.label("Message:");
        ui.indent("msg_indent", |ui| {
            ui.label(&f.message);
        });
        ui.add_space(6.0);

        if let Some(trace) = &f.dataflow_trace {
            ui.collapsing("Dataflow trace", |ui| {
                ui.label(format!(
                    "source: {}:{}",
                    trace.source.file.display(),
                    trace.source.range.start.line
                ));
                for p in &trace.propagators {
                    ui.label(format!(
                        "  via: {}:{}",
                        p.file.display(),
                        p.range.start.line
                    ));
                }
                ui.label(format!(
                    "sink: {}:{}",
                    trace.sink.file.display(),
                    trace.sink.range.start.line
                ));
                if let Some(label) = &trace.taint_label {
                    ui.label(format!("label: {label}"));
                }
            });
        }

        if !f.metavars.is_empty() {
            ui.collapsing("Metavariables", |ui| {
                for (k, v) in &f.metavars {
                    ui.label(format!("{k} = {}", v.abstract_content));
                }
            });
        }

        // Advisory link: only render when the rule's metadata block carries
        // an `advisory_id` string. `metadata` is `serde_json::Value`, so we
        // poke at it via `.get(...).and_then(.as_str)`.
        if let Some(adv) = f
            .metadata
            .get("advisory_id")
            .and_then(|v| v.as_str())
        {
            ui.hyperlink_to(
                format!("advisory: {adv}"),
                semgrep_output::advisory_url(adv),
            );
        }
    });
}
