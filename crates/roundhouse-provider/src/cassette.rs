//! ## The `.cassette` file format
//!
//! A `.cassette` file is a plain-text-with-binary-tail recording of one HTTP
//! response, kept deliberately simple so a human reviewer can open it and
//! read it directly (§13.3 makes "skim the cassette list" a review step):
//!
//! ```text
//! <status code>
//! <header name>: <header value>
//! <header name>: <header value>
//! ...
//! <blank line>
//! <raw response body, verbatim — SSE text, JSON, or any other bytes>
//! ```
//!
//! - Line 1 is the bare HTTP status code (e.g. `200`, `429`).
//! - Every line after that, up to the first blank line, is one
//!   `Name: value` header pair. The header table may be empty (a status
//!   line immediately followed by a blank line).
//! - Everything after the first blank line, byte for byte, is the response
//!   body. It is never re-parsed or reformatted by
//!   [`CassetteTransport::from_file`] — an SSE body's own internal blank
//!   lines (between frames) are part of the body and are left alone, since
//!   only the *first* blank line in the file is treated as the
//!   header/body separator.
//!
//! Every task that "adds a cassette" (Tasks 4-17) writes a file in this
//! format under `testdata/cassettes/<profile>/`.

use futures::future::BoxFuture;
use std::io;
use std::path::Path;

use crate::transport::{
    chunk_body, stream_from_chunks, HttpRequest, HttpResponseStream, HttpTransport, TransportError,
};

/// How to split a replayed cassette body into chunks, for the conformance
/// suite's fold-determinism check (`roundhouse-conformance`'s
/// `check_fold_determinism`): a decoder that accidentally depends on chunk
/// alignment must fail when replayed at a boundary it doesn't expect.
///
/// Both `Fixed` and `Prime` map onto the same underlying
/// [`CassetteTransport::chunk_size`] field — `Prime` exists as a distinct,
/// self-documenting variant (chunk sizes chosen specifically to be unlikely
/// to land on any structured boundary in a wire format) rather than because
/// the transport treats it differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkStrategy {
    /// Replay the whole body in a single chunk.
    WholeBody,
    /// Replay in fixed-size chunks of `n` bytes.
    Fixed(usize),
    /// Replay in chunks of a prime size `n`, chosen to avoid accidentally
    /// aligning with any fixed-width structure in the wire format.
    Prime(usize),
}

impl ChunkStrategy {
    fn chunk_size(self) -> usize {
        match self {
            ChunkStrategy::WholeBody => 0,
            ChunkStrategy::Fixed(n) => n,
            ChunkStrategy::Prime(n) => n,
        }
    }
}

/// A test double that replays a pre-recorded HTTP response body, split into
/// fixed-size chunks (for adversarial chunking tests), regardless of the
/// actual request received.
pub struct CassetteTransport {
    /// HTTP status code to replay.
    pub status: u16,
    /// Response headers to replay as key-value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes to replay.
    pub body: Vec<u8>,
    /// Chunk size in bytes; 0 means return the whole body in one chunk.
    pub chunk_size: usize,
}

impl HttpTransport for CassetteTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async move {
            let chunks = chunk_body(self.body.clone(), self.chunk_size);
            Ok(HttpResponseStream {
                status: self.status,
                headers: self.headers.clone(),
                body: stream_from_chunks(chunks),
            })
        })
    }
}

impl CassetteTransport {
    /// Loads a `.cassette` file (see this module's doc comment for the
    /// format) and builds a [`CassetteTransport`] that will replay it,
    /// chunked per `chunking`.
    pub fn from_file(path: &Path, chunking: ChunkStrategy) -> io::Result<Self> {
        let raw = std::fs::read(path)?;
        let invalid = |msg: String| io::Error::new(io::ErrorKind::InvalidData, msg);

        let (header_end, body_start) = find_header_body_separator(&raw).ok_or_else(|| {
            invalid(format!(
                "{}: missing blank line separating the status/header block from the body",
                path.display()
            ))
        })?;
        let body = raw[body_start..].to_vec();

        let header_block = std::str::from_utf8(&raw[..header_end]).map_err(|e| {
            invalid(format!(
                "{}: status/header block is not valid UTF-8: {e}",
                path.display()
            ))
        })?;
        let mut lines = header_block.lines();

        let status_line = lines
            .next()
            .ok_or_else(|| invalid(format!("{}: missing status line", path.display())))?;
        let status: u16 = status_line.trim().parse().map_err(|e| {
            invalid(format!(
                "{}: invalid status line {status_line:?}: {e}",
                path.display()
            ))
        })?;

        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or_else(|| {
                invalid(format!(
                    "{}: invalid header line {line:?} (expected \"Name: value\")",
                    path.display()
                ))
            })?;
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }

        Ok(CassetteTransport {
            status,
            headers,
            body,
            chunk_size: chunking.chunk_size(),
        })
    }
}

/// Finds the first blank-line separator (`"\r\n\r\n"` or `"\n\n"`) in `raw`
/// and returns `(index where the header block ends, index where the body
/// starts)`. Only the *first* such separator counts — an SSE body's own
/// internal blank lines (between frames) come after it and are left as part
/// of the body.
fn find_header_body_separator(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        return Some((pos, pos + 4));
    }
    find_subslice(raw, b"\n\n").map(|pos| (pos, pos + 2))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
