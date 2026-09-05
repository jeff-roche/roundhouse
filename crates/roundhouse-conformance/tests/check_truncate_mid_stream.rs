//! Self-test for `roundhouse_conformance::checks::check_truncate_mid_stream`
//! (Task 12, Ruling R16). This crate does not force one truncation-signaling
//! encoding on every codec (see `roundhouse-provider`'s
//! `src/decode_guard.rs` module doc for why): a codec may either return
//! `Err` on truncation (the "strict" group) or return `Ok` without ever
//! fabricating a `MessageStop` (the "absence" group). The one outcome that
//! is illegitimate under BOTH encodings is `Ok(events)` that DOES contain a
//! `MessageStop` for an input that was truncated before the wire's real
//! terminal marker -- that is the exact property this check proves, and the
//! only one of the three fakes below it may ever fail.

use futures::StreamExt;
use roundhouse_conformance::checks::check_truncate_mid_stream;
use roundhouse_provider::{
    BlockKind, BoxFut, Capabilities, ChatRequest, ChatStream, HttpRequest, ModelId, Plan, Provider,
    ProviderError, RequestCtx, StreamEvent, TokenCount,
};
use std::path::PathBuf;

/// The synthetic cassette's terminal marker. Everything before it in
/// `testdata/cassettes/truncate_mid_stream_self_test.cassette` is partial
/// content a real wire format would have streamed so far; everything after
/// it is trailer bytes a real wire format can still send AFTER its own
/// terminal (Ruling R3: `bedrock_converse`'s post-`messageStop` metadata
/// frame, `openai_chat`'s trailing `data: [DONE]`) -- the check must locate
/// the terminal and truncate strictly before it, never merely by a flat
/// byte fraction of the whole body.
const MARKER: &str = "##TERMINAL##";

fn cassette_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes/truncate_mid_stream_self_test.cassette")
}

fn request() -> ChatRequest {
    roundhouse_conformance::fixtures::simple_request()
}

/// Reads everything `ctx.transport` will hand back for a `send` call --
/// exactly what a real decode loop's SSE/eventstream parser would receive,
/// minus any actual wire-format parsing (these fakes don't need one; they
/// only need to know how many bytes of the cassette they were given).
async fn collect_body(ctx: &RequestCtx) -> Vec<u8> {
    let resp = ctx
        .transport
        .send(HttpRequest {
            method: "POST".into(),
            url: "https://fake.invalid".into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .expect("the CassetteTransport this check builds never fails to `send`");
    let mut bytes = Vec::new();
    let mut body = resp.body;
    while let Some(chunk) = body.next().await {
        bytes.extend_from_slice(&chunk.expect("CassetteTransport never yields a transport error"));
    }
    bytes
}

fn text_block_start() -> StreamEvent {
    StreamEvent::BlockStart {
        index: 0,
        kind: BlockKind::Text,
    }
}

fn saw_marker(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).contains(MARKER)
}

/// A broken subject: reports a clean completion (with a `MessageStop`)
/// regardless of how much of the cassette it actually received. This is the
/// exact defect Cross-Cutting #2 exists to catch, and the only one of the
/// three fakes here the check must fail.
struct FabricatingSubject;

impl Provider for FabricatingSubject {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "https://fake.invalid/fabricating".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let _ = collect_body(ctx).await;
            Ok(ChatStream(Box::pin(futures::stream::iter(vec![
                text_block_start(),
                StreamEvent::MessageStop,
            ]))))
        })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

/// Mimics the "absence" group (`google_genai`/`openai_responses`/
/// `bedrock_converse`): always `Ok`, and emits `MessageStop` only when the
/// full terminal marker was actually received. Never fabricates.
struct AbsenceEncodingSubject;

impl Provider for AbsenceEncodingSubject {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "https://fake.invalid/absence".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let bytes = collect_body(ctx).await;
            let mut events = vec![text_block_start()];
            if saw_marker(&bytes) {
                events.push(StreamEvent::MessageStop);
            }
            Ok(ChatStream(Box::pin(futures::stream::iter(events))))
        })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

/// Mimics the "strict" group (`anthropic_messages`/`openai_chat`/
/// `cohere_v2`): `Err` when the full terminal marker was not received,
/// `Ok` with a real `MessageStop` when it was.
struct StrictEncodingSubject;

impl Provider for StrictEncodingSubject {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "https://fake.invalid/strict".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let bytes = collect_body(ctx).await;
            if saw_marker(&bytes) {
                Ok(ChatStream(Box::pin(futures::stream::iter(vec![
                    text_block_start(),
                    StreamEvent::MessageStop,
                ]))))
            } else {
                Err(ProviderError::StreamInterrupted {
                    partial: String::new(),
                })
            }
        })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

#[tokio::test]
async fn a_subject_that_fabricates_message_stop_on_truncation_fails_the_check() {
    let failures =
        check_truncate_mid_stream(&FabricatingSubject, &request(), &cassette_path(), None).await;
    assert!(
        !failures.is_empty(),
        "a subject that always reports a clean completion regardless of truncation must be \
         caught by the check"
    );
}

#[tokio::test]
async fn an_absence_encoding_subject_passes_the_check() {
    let failures =
        check_truncate_mid_stream(&AbsenceEncodingSubject, &request(), &cassette_path(), None)
            .await;
    assert!(
        failures.is_empty(),
        "an absence-encoding subject (Ok, no MessageStop when truncated) must pass: {failures:#?}"
    );
}

#[tokio::test]
async fn a_strict_encoding_subject_passes_the_check() {
    let failures =
        check_truncate_mid_stream(&StrictEncodingSubject, &request(), &cassette_path(), None).await;
    assert!(
        failures.is_empty(),
        "a strict-encoding subject (Err when truncated) must pass: {failures:#?}"
    );
}
