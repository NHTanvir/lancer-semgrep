//! Background worker that runs a scan and ships progress / results back via
//! a `crossbeam_channel` so the egui paint thread never blocks.
//!
//! The worker spins up its own current-thread Tokio runtime — we deliberately
//! avoid sharing the binary's main runtime so the GUI can be launched from
//! arbitrary entry points (including from a thread that itself is already
//! inside a Tokio context).

use crossbeam_channel::{unbounded, Receiver, Sender};
use semgrep_output::ScanReport;
use semgrep_rules::RuleSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::scan::run::{run_scan, ScanOpts};

/// Wire-format messages flowing from worker → UI.
pub enum ScanMessage {
    /// A pulse of progress. `total == 0` means indeterminate.
    Progress {
        current: usize,
        total: usize,
        stage: String,
    },
    /// Terminal: scan finished, report attached.
    Done(Box<ScanReport>),
    /// Terminal: scan blew up.
    Error(String),
    /// Terminal: cancellation flag was set before completion.
    Cancelled,
}

/// Handle to a running scan. Held by the UI so it can drain progress and
/// flip the cancel flag.
pub struct ScanHandle {
    pub rx: Receiver<ScanMessage>,
    pub cancel: Arc<AtomicBool>,
}

/// Spawn a worker thread that runs [`crate::scan::run::run_scan`] over
/// `targets` with `ruleset`.
///
/// The returned [`ScanHandle`] is the only way the UI talks to the worker:
/// `rx.try_recv()` drains progress / completion on each repaint, and
/// `cancel.store(true)` requests an early exit. The worker checks the cancel
/// flag at coarse boundaries (before/after the actual scan call) — `run_scan`
/// itself is currently not cancellation-aware, but the worker still exits
/// promptly enough for the UI to feel responsive.
pub fn spawn_scan(targets: Vec<PathBuf>, ruleset: RuleSet) -> ScanHandle {
    let (tx, rx): (Sender<ScanMessage>, Receiver<ScanMessage>) = unbounded();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_w = cancel.clone();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(ScanMessage::Error(format!("runtime: {e}")));
                return;
            }
        };

        let _ = tx.send(ScanMessage::Progress {
            current: 0,
            total: 0,
            stage: "enumerating".into(),
        });
        if cancel_w.load(Ordering::Relaxed) {
            let _ = tx.send(ScanMessage::Cancelled);
            return;
        }

        let opts = ScanOpts {
            targets,
            enumerate: semgrep_core::scan::EnumerateOpts::default(),
            baseline_commit: None,
            diff_depth: 0,
            jobs: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            dataflow_traces: false,
        };

        let _ = tx.send(ScanMessage::Progress {
            current: 0,
            total: 0,
            stage: "scanning".into(),
        });
        let report = rt.block_on(run_scan(&opts, &ruleset));

        if cancel_w.load(Ordering::Relaxed) {
            let _ = tx.send(ScanMessage::Cancelled);
            return;
        }
        let _ = tx.send(ScanMessage::Done(Box::new(report)));
    });
    ScanHandle { rx, cancel }
}
