//! Task 9 — a real, minimal MCP server speaking the newline-JSON-RPC wire
//! `StdioMcpTransport` (Task 6) writes: one JSON-RPC request per stdin
//! line, one response per stdout line. Task 9's `tests/integration.rs`
//! spawns this binary as a real OS child process and drives the full
//! spawn → discover → namespace → dispatch → MRTR → EOF-shutdown lifecycle
//! against it.
//!
//! Deliberately synchronous std I/O: the transport issues one request at a
//! time and awaits its response, so a line-at-a-time blocking loop is the
//! simplest honest counterpart. Exits on stdin EOF (the transport's
//! shutdown/drop mechanism), never touching the protocol on stderr —
//! stderr is the daemon log channel (§7.3), never protocol.
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn main() {
    // Task 11 fix (finding 2 review coverage): `bad-schema` argv mode makes
    // the server announce a tool whose `inputSchema` is a non-object string
    // — the malformed discovery shape `McpHost::start` must fail closed on
    // without echoing the payload. Default (no-arg) behavior is unchanged;
    // every other test spawns this binary with no args.
    let args: Vec<String> = std::env::args().collect();
    let bad_schema = args.iter().any(|arg| arg == "bad-schema");
    // Phase 3 review-fix coverage: `pidfile:<path>` announces this process's
    // own pid before serving. The transport spawns the server as its own
    // process-group leader, so the host's pgid == this pid, and lifecycle
    // tests (`host.shutdown()` confirmed; partial-startup teardown) can
    // then verify against `/proc` that the REAL child is gone rather than
    // trusting the teardown's return value alone.
    if let Some(path) = args.iter().find_map(|a| a.strip_prefix("pidfile:")) {
        std::fs::write(path, format!("{}\n", std::process::id())).expect("write pidfile");
    }
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    // Opaque server-side booking state (§10.1): the real server would seal
    // this; the fake just holds the arguments it saw on the first
    // book_flight call and echoes a fixed requestState string.
    let mut booking_state: Option<Value> = None;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            Ok(_) => continue,
            Err(_) => break,
        };
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");

        let response = match method {
            // bad-schema mode: the marker string rides as the tool's whole
            // `inputSchema` value. If the host's fail-closed path ever
            // echoes the schema payload through its error, the host test's
            // no-leak assertion catches it.
            "server/discover" if bad_schema => json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": "2026-07-28",
                    "tools": [
                        {"name": "bad_schema", "description": "announces a non-object input schema", "inputSchema": "__UNTRUSTED_SCHEMA_PAYLOAD__"}
                    ]
                }
            }),
            "server/discover" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": "2026-07-28",
                    "tools": [
                        {"name": "whoami", "description": "returns the caller identity", "inputSchema": {}},
                        {"name": "book_flight", "description": "books a flight, asks for fare class", "inputSchema": {}}
                    ]
                }
            }),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                // MRTR retry marker (§10.1): present only when the caller
                // echoes a server-minted requestState back at us.
                let request_state = params
                    .get("_meta")
                    .and_then(|m| m.get("requestState"))
                    .and_then(Value::as_str);

                match (name, request_state) {
                    ("whoami", _) => json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "content": [{"type": "text", "text": "daemon-service-account"}], "isError": false }
                    }),
                    ("book_flight", None) => {
                        booking_state =
                            Some(params.get("arguments").cloned().unwrap_or(Value::Null));
                        json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": {
                                "resultType": "input_required",
                                "inputRequests": [{"id": "fare_class", "prompt": "which fare class?", "schema": null}],
                                "requestState": "opaque-booking-state-1"
                            }
                        })
                    }
                    ("book_flight", Some("opaque-booking-state-1")) => {
                        let _ = booking_state.take();
                        json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": { "content": [{"type": "text", "text": "booked: economy fare"}], "isError": false }
                        })
                    }
                    _ => {
                        json!({ "jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unknown tool or stale requestState"} })
                    }
                }
            }
            _ => {
                json!({ "jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"} })
            }
        };

        let _ = writeln!(stdout, "{}", response);
        let _ = stdout.flush();
    }
}
