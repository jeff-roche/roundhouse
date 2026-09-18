//! A minimal HTTP/1.1 stand-in for Anthropic's Messages API, for driving the
//! real `round-daemon-internal` binary through `ROUNDHOUSE_ANTHROPIC_BASE_URL`.
//!
//! It serves one request per connection (`connection: close`) and decides
//! each reply from the request body alone, so two sessions sharing one mock
//! cannot steal each other's replies:
//!
//! - a body carrying a `tool_result` block gets the final text reply. If it
//!   also carries [`HOLD_AFTER_TOOL_MARKER`], it is parked first until the
//!   test releases it (see [`MockAnthropic::next_held_request`]);
//! - any other body carrying [`HOLD_MARKER`] is parked the same way, then
//!   gets the final text reply (a turn with no tool call);
//! - any other body gets a `tool_use` block asking for `read` of the path the
//!   mock was built with.
//!
//! In [`Mode::Fail`] every request gets a `400` with an Anthropic error body.
//!
//! The SSE shapes are copied from `roundhouse-daemon`'s `submit_turn_e2e.rs`
//! (`tool_call_cassette`, `final_text_cassette`); this crate deliberately takes
//! no dependency on the daemon.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;

/// A user message containing this text is held open by the mock until the
/// test releases it.
pub const HOLD_MARKER: &str = "HOLD-THIS-TURN-OPEN";

/// A user message containing this text runs its `read` tool call, and then
/// the request carrying the tool result is held until the test releases it.
/// Must not contain [`HOLD_MARKER`].
pub const HOLD_AFTER_TOOL_MARKER: &str = "PAUSE-AFTER-THE-TOOL";

/// The final assistant text every completed turn ends with.
pub const FINAL_TEXT: &str = "the mock model is done";

/// How the mock answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Serve a `read` tool call, then a final text reply.
    Script,
    /// Answer every request with a `400` Anthropic error.
    Fail,
}

/// A running mock. Dropping it aborts the accept loop.
pub struct MockAnthropic {
    base_url: String,
    held: Mutex<mpsc::UnboundedReceiver<oneshot::Sender<()>>>,
    bodies: Arc<std::sync::Mutex<Vec<String>>>,
    accept_loop: JoinHandle<()>,
}

impl MockAnthropic {
    /// Binds an ephemeral loopback port and starts serving.
    pub async fn start(mode: Mode, read_path: &Path) -> MockAnthropic {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind the mock Anthropic listener");
        let port = listener.local_addr().unwrap().port();
        let (held_tx, held_rx) = mpsc::unbounded_channel();
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let config = Arc::new(Config {
            mode,
            read_path: read_path.to_path_buf(),
            held_tx,
            bodies: bodies.clone(),
        });
        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve_one(stream, config.clone()));
            }
        });
        MockAnthropic {
            base_url: format!("http://127.0.0.1:{port}"),
            held: Mutex::new(held_rx),
            bodies,
            accept_loop,
        }
    }

    /// The value for `ROUNDHOUSE_ANTHROPIC_BASE_URL`.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Every `/v1/messages` request body received so far, in arrival order.
    pub fn request_bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }

    /// Waits until a request carrying [`HOLD_MARKER`] has arrived, and
    /// returns the sender that releases it. The request is answered only once
    /// the sender is used (or dropped).
    pub async fn next_held_request(&self) -> oneshot::Sender<()> {
        self.held
            .lock()
            .await
            .recv()
            .await
            .expect("the mock's accept loop is still running")
    }
}

impl Drop for MockAnthropic {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

struct Config {
    mode: Mode,
    read_path: PathBuf,
    held_tx: mpsc::UnboundedSender<oneshot::Sender<()>>,
    bodies: Arc<std::sync::Mutex<Vec<String>>>,
}

async fn serve_one(mut stream: TcpStream, config: Arc<Config>) {
    let Some((path, body)) = read_request(&mut stream).await else {
        return;
    };
    if path != "/v1/messages" {
        write_response(&mut stream, "404 Not Found", "text/plain", b"not found").await;
        return;
    }
    let body = String::from_utf8_lossy(&body).into_owned();
    config.bodies.lock().unwrap().push(body.clone());
    if config.mode == Mode::Fail {
        let error = serde_json::json!({
            "type": "error",
            "error": {"type": "invalid_request_error", "message": "the mock refuses this request"},
        });
        write_response(
            &mut stream,
            "400 Bad Request",
            "application/json",
            error.to_string().as_bytes(),
        )
        .await;
        return;
    }
    let sse = if body.contains("\"tool_result\"") {
        if body.contains(HOLD_AFTER_TOOL_MARKER) && !hold(&config).await {
            return;
        }
        final_text_cassette(FINAL_TEXT)
    } else if body.contains(HOLD_MARKER) {
        if !hold(&config).await {
            return;
        }
        final_text_cassette(FINAL_TEXT)
    } else {
        tool_call_cassette(
            "read",
            &serde_json::json!({ "path": config.read_path.to_string_lossy() }),
        )
    };
    write_response(&mut stream, "200 OK", "text/event-stream", &sse).await;
}

/// Parks the current request until the test releases it, or drops the
/// sender. `false` if the test is no longer listening.
async fn hold(config: &Config) -> bool {
    let (release_tx, release_rx) = oneshot::channel();
    if config.held_tx.send(release_tx).is_err() {
        return false;
    }
    let _ = release_rx.await;
    true
}

/// Reads one request's head and its `content-length` body. Returns the
/// request path and body, or `None` if the peer went away first.
async fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?.to_string();
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        assert_ne!(
            name, "transfer-encoding",
            "the mock only understands content-length request bodies"
        );
        if name == "content-length" {
            content_length = value.trim().parse().expect("a numeric content-length");
        }
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((path, body))
}

async fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    );
    // The daemon may have given up on this request; nothing to do then.
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}

fn sse_frame(event: &str, data: serde_json::Value) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

/// Assistant text followed by one `tool_use` block for `tool_name`.
fn tool_call_cassette(tool_name: &str, tool_input: &serde_json::Value) -> Vec<u8> {
    let mut body = String::new();
    body += &sse_frame(
        "message_start",
        serde_json::json!({
            "type": "message_start",
            "message": {"id": "msg_1", "usage": {"input_tokens": 10, "cache_read_input_tokens": 0}},
        }),
    );
    body += &sse_frame(
        "content_block_start",
        serde_json::json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""},
        }),
    );
    body += &sse_frame(
        "content_block_delta",
        serde_json::json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "Let me read that file."},
        }),
    );
    body += &sse_frame(
        "content_block_stop",
        serde_json::json!({"type": "content_block_stop", "index": 0}),
    );
    body += &sse_frame(
        "content_block_start",
        serde_json::json!({
            "type": "content_block_start", "index": 1,
            "content_block": {"type": "tool_use", "id": "call_0", "name": tool_name},
        }),
    );
    body += &sse_frame(
        "content_block_delta",
        serde_json::json!({
            "type": "content_block_delta", "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": tool_input.to_string()},
        }),
    );
    body += &sse_frame(
        "content_block_stop",
        serde_json::json!({"type": "content_block_stop", "index": 1}),
    );
    body += &sse_frame(
        "message_delta",
        serde_json::json!({
            "type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 5},
        }),
    );
    body += &sse_frame("message_stop", serde_json::json!({"type": "message_stop"}));
    body.into_bytes()
}

/// One final, text-only assistant turn.
fn final_text_cassette(text: &str) -> Vec<u8> {
    let mut body = String::new();
    body += &sse_frame(
        "message_start",
        serde_json::json!({
            "type": "message_start",
            "message": {"id": "msg_2", "usage": {"input_tokens": 10, "cache_read_input_tokens": 0}},
        }),
    );
    body += &sse_frame(
        "content_block_start",
        serde_json::json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""},
        }),
    );
    body += &sse_frame(
        "content_block_delta",
        serde_json::json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": text},
        }),
    );
    body += &sse_frame(
        "content_block_stop",
        serde_json::json!({"type": "content_block_stop", "index": 0}),
    );
    body += &sse_frame(
        "message_delta",
        serde_json::json!({
            "type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 5},
        }),
    );
    body += &sse_frame("message_stop", serde_json::json!({"type": "message_stop"}));
    body.into_bytes()
}
