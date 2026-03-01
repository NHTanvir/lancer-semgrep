//! Local HTTP server on `127.0.0.1:<auto-port>` for cross-tool integration
//! with the rest of the Lancer ecosystem. Writes the chosen port to
//! `%TEMP%/lancer-semgrep.port` so other Lancer tools can find it.
//!
//! Endpoints:
//! - `GET  /v1/state`  — current jobs / progress (returns JSON)
//! - `POST /v1/import` — accept a target/file/record (future: pull into the
//!   target list — currently a no-op stub)
//! - `GET  /v1/export?format=json` — pull current findings as JSON
//!
//! Loopback-only — any non-loopback peer is rejected at accept time.
//!
//! **Status**: this server is wired into the crate but not yet started from
//! [`crate::gui::app::LancerApp`]. The integration with the egui lifecycle
//! is deferred to a follow-up task. To enable, instantiate it from
//! `LancerApp::new` with an `Arc<Mutex<AppState>>` carrying a snapshot of
//! the live UI state.

use std::sync::{Arc, Mutex};

use crate::gui::state::AppState;

/// Lightweight TCP listener wrapper holding the chosen port.
pub struct LocalServer {
    pub port: u16,
}

impl LocalServer {
    /// Spawn a TCP listener on `127.0.0.1:0` and write the chosen port to
    /// `%TEMP%/lancer-semgrep.port`.
    ///
    /// `state` is shared with the GUI thread. Reads are short (a snapshot of
    /// the scan report metadata) so contention is minimal.
    pub fn spawn(state: Arc<Mutex<AppState>>) -> std::io::Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let port_file = std::env::temp_dir().join("lancer-semgrep.port");
        let _ = std::fs::write(&port_file, port.to_string());

        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                if let Ok(mut sock) = incoming {
                    let state = state.clone();
                    std::thread::spawn(move || {
                        let _ = handle_request(&mut sock, &state);
                    });
                }
            }
        });
        Ok(Self { port })
    }
}

/// Parse the request line + headers, route, write the response.
///
/// Hand-rolled HTTP — we don't need a full router here, just three known
/// endpoints over short JSON payloads.
fn handle_request(
    sock: &mut std::net::TcpStream,
    state: &Arc<Mutex<AppState>>,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};

    let peer = sock.peer_addr()?;
    if !peer.ip().is_loopback() {
        return Ok(());
    }

    let mut reader = BufReader::new(sock.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let (method, path) = (parts[0], parts[1]);

    // Drain headers until the empty line.
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h)?;
        if n == 0 || h == "\r\n" || h == "\n" {
            break;
        }
    }

    let (status, body) = match (method, path.split('?').next().unwrap_or("/"))
    {
        ("GET", "/v1/state") => {
            let st = state.lock().unwrap();
            let payload = serde_json::json!({
                "scan_in_flight": st.scan_in_flight,
                "items": st.scan_report.as_ref().map(|r| r.findings.len()).unwrap_or(0),
                "stage": st.progress.stage,
                "current": st.progress.current,
                "total": st.progress.total,
            });
            (
                200,
                serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into()),
            )
        }
        ("GET", "/v1/export") => {
            let st = state.lock().unwrap();
            let body = st
                .scan_report
                .as_ref()
                .map(|r| {
                    serde_json::to_string(r).unwrap_or_else(|_| "{}".into())
                })
                .unwrap_or_else(|| "{}".into());
            (200, body)
        }
        ("POST", "/v1/import") => {
            // We don't easily know Content-Length without parsing headers
            // ourselves. For v0 we drain whatever is left buffered and
            // acknowledge — wiring this into the target list is future work.
            let mut buf = Vec::new();
            let _ = reader.read_to_end(&mut buf);
            (202, "{\"accepted\":true}".to_string())
        }
        _ => (404, "{\"error\":\"not found\"}".to_string()),
    };

    let head = format!(
        "HTTP/1.1 {status} OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes())?;
    sock.write_all(body.as_bytes())?;
    sock.flush()?;
    Ok(())
}
