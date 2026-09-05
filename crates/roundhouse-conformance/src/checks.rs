//! The individual conformance property checks (§9.10), each returning a
//! `Vec<String>` of human-readable failure descriptions (empty = passed).
//! [`crate::run`] wires these together per case; each is also independently
//! unit-tested here so a regression in one check is caught at the smallest
//! possible scope.

use crate::mask::{flatten_object_keys, SerializeOnlyMask};
use futures::StreamExt;
use roundhouse_core::Usage;
use roundhouse_provider::{
    BlockDelta, BlockKind, CassetteTransport, ChatRequest, ChatStream, ChunkStrategy, ContentBlock,
    IdOrigin, Provider, RequestCtx, Signature, StreamEvent, ToolCallId,
};
use std::collections::BTreeMap;
use std::path::Path;

/// The four chunk boundaries every case is replayed at (§9.10: "fold
/// determinism across chunk boundaries"). `WholeBody` also stands in for
/// the stream/non-stream equivalence check: whole-body delivery is the
/// closest a streaming transport gets to a unary response.
const CHUNK_STRATEGIES: [ChunkStrategy; 4] = [
    ChunkStrategy::WholeBody,
    ChunkStrategy::Fixed(1),
    ChunkStrategy::Fixed(3),
    ChunkStrategy::Prime(17),
];

/// §9.10's generic property test: no field outside the resolved
/// `serialize_only` mask may appear anywhere in the encoded wire body.
pub fn check_mask(wire_body: &serde_json::Value, mask: &SerializeOnlyMask) -> Vec<String> {
    let mut keys = Vec::new();
    flatten_object_keys(wire_body, "", &mut keys);
    keys.into_iter()
        .filter(|k| !mask.permits(k))
        .map(|k| {
            format!(
                "field `{k}` appears in the encoded body but is outside the resolved serialize_only mask"
            )
        })
        .collect()
}

/// A normalized `ChatStream`, folded down to its final content blocks and
/// usage totals. Compared structurally (via `serde_json::to_value`, §14c of
/// REALITY-CORRECTIONS) rather than via a derived `PartialEq`, since
/// nothing in the frozen IR/stream path derives it.
#[derive(Debug, Clone)]
pub struct FoldedResult {
    pub blocks: Vec<ContentBlock>,
    pub usage: Usage,
    pub loss_events: Vec<String>,
    /// Whether `StreamEvent::MessageStop` was observed anywhere in the
    /// folded stream. Task 12 (Ruling R16): `check_truncate_mid_stream`
    /// needs this to tell a genuine terminal apart from one this crate's
    /// own fold previously discarded (`StreamEvent::MessageStop => {}` was
    /// a pure no-op before this field existed).
    pub saw_message_stop: bool,
}

impl FoldedResult {
    fn structurally_eq(&self, other: &Self) -> bool {
        serde_json::to_value(&self.blocks).ok() == serde_json::to_value(&other.blocks).ok()
            && serde_json::to_value(&self.usage).ok() == serde_json::to_value(&other.usage).ok()
            && self.loss_events == other.loss_events
            && self.saw_message_stop == other.saw_message_stop
    }
}

/// One content block accumulating its deltas between `BlockStart` and
/// `BlockStop`.
struct OpenBlock {
    kind: BlockKind,
    text: String,
    tool_args: String,
    thinking_text: String,
    thinking_signature: Option<String>,
}

/// Folds a `ChatStream` into a [`FoldedResult`] by implementing the real
/// per-index block fold: `BlockStart` opens a buffer keyed by `index`,
/// `BlockDelta` appends to it, `BlockStop` seals it into `blocks` (§12a of
/// REALITY-CORRECTIONS — the brief's version left this as a bare comment,
/// which made every round-trip-fidelity check vacuous).
pub async fn fold_stream(mut stream: ChatStream) -> FoldedResult {
    let mut open: BTreeMap<u32, OpenBlock> = BTreeMap::new();
    let mut blocks = Vec::new();
    let mut usage = Usage::default();
    let mut loss_events = Vec::new();
    let mut saw_message_stop = false;

    while let Some(event) = stream.next().await {
        match event {
            StreamEvent::BlockStart { index, kind } => {
                open.insert(
                    index,
                    OpenBlock {
                        kind,
                        text: String::new(),
                        tool_args: String::new(),
                        thinking_text: String::new(),
                        thinking_signature: None,
                    },
                );
            }
            StreamEvent::BlockDelta { index, delta } => match open.get_mut(&index) {
                Some(block) => match delta {
                    BlockDelta::Text(t) => block.text.push_str(&t),
                    BlockDelta::ToolArgsFragment(f) => block.tool_args.push_str(&f),
                    BlockDelta::Thinking { text, signature } => {
                        block.thinking_text.push_str(&text);
                        if signature.is_some() {
                            block.thinking_signature = signature;
                        }
                    }
                },
                None => loss_events.push(format!(
                    "BlockDelta for index {index} arrived with no matching BlockStart"
                )),
            },
            StreamEvent::BlockStop { index } => match open.remove(&index) {
                Some(block) => blocks.push(seal_block(block, index)),
                None => loss_events.push(format!(
                    "BlockStop for index {index} arrived with no matching BlockStart"
                )),
            },
            StreamEvent::UsageDelta {
                input_tokens,
                output_tokens,
                cache_read_tokens,
            } => {
                if let Some(v) = input_tokens {
                    usage.input_tokens = v;
                }
                if let Some(v) = output_tokens {
                    usage.output_tokens = v;
                }
                if let Some(v) = cache_read_tokens {
                    usage.cache_read_tokens = v;
                }
            }
            StreamEvent::MessageStop => saw_message_stop = true,
        }
    }

    for index in open.keys() {
        loss_events.push(format!("block at index {index} never received a BlockStop"));
    }

    FoldedResult {
        blocks,
        usage,
        loss_events,
        saw_message_stop,
    }
}

fn seal_block(block: OpenBlock, index: u32) -> ContentBlock {
    match block.kind {
        BlockKind::Text => ContentBlock::Text {
            text: block.text,
            cache: None,
            citations: Vec::new(),
        },
        BlockKind::Thinking => ContentBlock::Thinking {
            text: block.thinking_text,
            signature: block.thinking_signature.map(Signature),
            redacted: false,
        },
        BlockKind::ToolUse { name, provider_id } => {
            let input = serde_json::from_str(&block.tool_args)
                .unwrap_or(serde_json::Value::Object(Default::default()));
            let (id, id_origin) = match provider_id {
                Some(pid) => (ToolCallId(pid), IdOrigin::Provider),
                None => (
                    ToolCallId(format!("synthesized-{index}")),
                    IdOrigin::Synthesized,
                ),
            };
            ContentBlock::ToolUse {
                id,
                id_origin,
                name,
                input,
                cache: None,
            }
        }
    }
}

/// Replays `request` against `cassette_path` once per [`CHUNK_STRATEGIES`]
/// entry and asserts the folded result is identical across all of them.
///
/// Per §12a of REALITY-CORRECTIONS, the codec-generic way to get a
/// `ChatStream` out of recorded bytes is the one the real code already
/// uses: build a `RequestCtx` whose transport is a `CassetteTransport`, then
/// call the subject's own `Provider::stream_chat` and fold what comes back
/// — there is no `replay_as_chat_stream` method, and none is needed.
///
/// `expected_error` (fix-round-1 C7 on Task 5): `None` for the ordinary
/// success-path case, where any `Err` from `stream_chat` is a harness
/// failure. `Some(predicate)` for a case whose cassette is *supposed* to make
/// `stream_chat` fail (an HTTP error status, or an in-band terminal failure
/// event) — there, an `Ok` result is the failure, a non-matching `Err` is
/// also a failure (the codec errored, but not with the right disposition),
/// and a matching `Err` is a pass with no `FoldedResult` to compare across
/// chunk strategies (there is nothing to fold).
///
/// `credentials` (fix-round-1 H3 on Phase 6 Task 7): threads
/// `ConformanceSubject::credentials()` into the `RequestCtx` built for every
/// chunk strategy, so a credential-REQUIRED provider (no meaningful bare-
/// `api_key` fallback — SigV4 cannot sign a request from a bare string) can
/// actually reach its cassette transport instead of failing closed on a
/// missing credential before `stream_chat` ever calls `HttpTransport::send`.
pub async fn check_fold_determinism<P: Provider>(
    provider: &P,
    request: &ChatRequest,
    cassette_path: &Path,
    expected_error: Option<fn(&roundhouse_provider::ProviderError) -> bool>,
    credentials: Option<std::sync::Arc<dyn roundhouse_provider::credential::CredentialProvider>>,
) -> (Vec<String>, Option<FoldedResult>) {
    let mut failures = Vec::new();
    let mut results: Vec<FoldedResult> = Vec::new();

    for strategy in CHUNK_STRATEGIES {
        let transport = match CassetteTransport::from_file(cassette_path, strategy) {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!(
                    "could not load cassette {} for chunk strategy {strategy:?}: {e}",
                    cassette_path.display()
                ));
                continue;
            }
        };
        let ctx = RequestCtx {
            trace_id: None,
            transport: std::sync::Arc::new(transport),
            api_key: "conformance-test-key".into(),
            credentials: credentials.clone(),
        };
        match (provider.stream_chat(request, &ctx).await, expected_error) {
            (Ok(_), Some(_)) => failures.push(format!(
                "expected stream_chat to fail replaying cassette {} at chunk strategy {strategy:?}, \
                 but it returned a successful stream",
                cassette_path.display()
            )),
            (Ok(stream), None) => results.push(fold_stream(stream).await),
            (Err(e), Some(predicate)) => {
                if !predicate(&e) {
                    failures.push(format!(
                        "stream_chat failed replaying cassette {} at chunk strategy {strategy:?}, \
                         but the error didn't match the declared expected_error predicate: {e}",
                        cassette_path.display()
                    ));
                }
                // A matching error is a pass for this strategy: there is
                // nothing to fold, so no `FoldedResult` is pushed.
            }
            (Err(e), None) => failures.push(format!(
                "stream_chat failed replaying cassette {} at chunk strategy {strategy:?}: {e}",
                cassette_path.display()
            )),
        }
    }

    for pair in results.windows(2) {
        if !pair[0].structurally_eq(&pair[1]) {
            failures.push(format!(
                "fold determinism violated for cassette {}: folded result differs between chunk strategies",
                cassette_path.display()
            ));
        }
    }

    (failures, results.into_iter().next())
}

/// Task 12 (Cross-Cutting #2), sharpened by Ruling R16: proves a
/// `ConformanceSubject`'s decoder never lies about truncation, under
/// EITHER of this codebase's two legitimate encodings (see
/// `roundhouse_provider::decode_guard`'s module doc): a "strict" codec
/// returns `Err` when its stream is cut before its own terminal event; an
/// "absence" codec returns `Ok` but never fabricates
/// `StreamEvent::MessageStop` it did not actually observe. Both are
/// correct. The one outcome that is illegitimate under *both* encodings —
/// and the only one this check fails on — is `Ok(events)` that DOES
/// contain a `MessageStop` for an input truncated before the wire's real
/// terminal marker.
///
/// **Locating the terminal (Ruling R3)** without any codec-specific
/// wire-format knowledge (needed since one codec's framing is binary, not
/// SSE): replaying a byte-for-byte PREFIX of the cassette body through the
/// subject's own `Provider::stream_chat` and folding the result is exactly
/// what a truncated connection looks like from the codec's point of view,
/// for any wire format. [`locate_terminal_end`] finds the *minimal* prefix
/// length that reaches the terminal via a linear scan — **not** a binary
/// search: "does this prefix decode to an `Ok` stream containing
/// `MessageStop`" is NOT monotonic in prefix length for every codec. A
/// binary-framed codec whose wire format legitimately sends bytes AFTER its
/// own terminal (`bedrock_converse`'s post-`messageStop` metadata frame) is
/// `true` at the terminal, `false` again while that later frame is
/// mid-flight (`EventStreamDecoder::is_mid_frame`), then `true` once more
/// at the full body — verified empirically against this exact codec during
/// review: a binary search over that shape silently converged on
/// `terminal_end == n` (the whole body), defeating the entire point of
/// locating the terminal, while every one of its self-tests and wired-in
/// codec checks still reported green (the located-wrong terminal happened
/// to fall in Ruling R3's own "safe" region for the wired cassette, a
/// coverage gap rather than a wrong verdict — see
/// `locate_terminal_end`'s own unit test for a case that pins the
/// difference directly rather than relying on `check_truncate_mid_stream`'s
/// output to reveal it). Cassettes here are on the order of 1 KB, so an
/// O(n) scan of cheap in-memory decodes costs nothing.
///
/// Truncating at fractions of `terminal_end` (rather than of the whole
/// body, which is what the task's original, rejected design did)
/// guarantees every truncation point this check tests lands strictly
/// before the terminal, so a codec that correctly sends bytes after its
/// own terminal can never be false-failed by a truncation point that
/// actually retained the terminal and only dropped trailing bytes.
///
/// If the whole cassette never decodes to a `MessageStop` at all, there is
/// no terminal to truncate before — not this check's job (an ordinary
/// successful-completion cassette is `check_fold_determinism`'s job), so it
/// returns no failures.
pub async fn check_truncate_mid_stream<P: Provider>(
    provider: &P,
    request: &ChatRequest,
    cassette_path: &Path,
    credentials: Option<std::sync::Arc<dyn roundhouse_provider::credential::CredentialProvider>>,
) -> Vec<String> {
    let mut failures = Vec::new();

    let full = match CassetteTransport::from_file(cassette_path, ChunkStrategy::WholeBody) {
        Ok(t) => t,
        Err(e) => {
            failures.push(format!(
                "could not load cassette {} for truncate-mid-stream check: {e}",
                cassette_path.display()
            ));
            return failures;
        }
    };

    let Some(terminal_end) = locate_terminal_end(provider, request, &full, &credentials).await
    else {
        // The whole (untruncated) cassette never reaches a MessageStop at
        // all — nothing to locate a terminal before.
        return failures;
    };

    for pct in [25u64, 50, 75] {
        let cut = (terminal_end as u64 * pct / 100) as usize;
        if decode_prefix_saw_message_stop(provider, request, &full, cut, &credentials).await {
            failures.push(format!(
                "cassette {} decoded a MessageStop after truncating to {cut} of {terminal_end} \
                 bytes ({pct}% of the located terminal, strictly before it) — a truncated \
                 stream must never be indistinguishable from a clean completion",
                cassette_path.display()
            ));
        }
    }

    failures
}

/// The minimal prefix length of `full`'s body that decodes to an `Ok`
/// stream containing `MessageStop`, or `None` if no prefix (including the
/// whole body) ever does. A linear scan, deliberately not a binary search
/// — see [`check_truncate_mid_stream`]'s doc comment for why bisection
/// silently gives the wrong answer for a codec whose "did we reach the
/// terminal" signal isn't monotonic in prefix length.
async fn locate_terminal_end<P: Provider>(
    provider: &P,
    request: &ChatRequest,
    full: &CassetteTransport,
    credentials: &Option<std::sync::Arc<dyn roundhouse_provider::credential::CredentialProvider>>,
) -> Option<usize> {
    let n = full.body.len();
    for len in 0..=n {
        if decode_prefix_saw_message_stop(provider, request, full, len, credentials).await {
            return Some(len);
        }
    }
    None
}

/// Replays the first `len` bytes of `full`'s body and reports whether the
/// resulting stream is `Ok` AND contains `StreamEvent::MessageStop`. `Err`,
/// or an `Ok` stream without `MessageStop`, both report `false` — both are
/// legitimate non-lying responses to a truncated input, per this check's
/// own doc comment.
async fn decode_prefix_saw_message_stop<P: Provider>(
    provider: &P,
    request: &ChatRequest,
    full: &CassetteTransport,
    len: usize,
    credentials: &Option<std::sync::Arc<dyn roundhouse_provider::credential::CredentialProvider>>,
) -> bool {
    let transport = CassetteTransport {
        status: full.status,
        headers: full.headers.clone(),
        body: full.body[..len].to_vec(),
        chunk_size: 0,
    };
    let ctx = RequestCtx {
        trace_id: None,
        transport: std::sync::Arc::new(transport),
        api_key: "conformance-test-key".into(),
        credentials: credentials.clone(),
    };
    match provider.stream_chat(request, &ctx).await {
        Ok(stream) => fold_stream(stream).await.saw_message_stop,
        Err(_) => false,
    }
}

/// §9.3's usage invariant: `input_tokens` is the *total* tokens presented
/// (including cache reads), so it can never be smaller than
/// `cache_read_tokens`.
pub fn check_usage_invariants(usage: &Usage) -> Vec<String> {
    let mut failures = Vec::new();
    if usage.input_tokens < usage.cache_read_tokens {
        failures.push(format!(
            "usage invariant violated: input_tokens ({}) < cache_read_tokens ({}) — §9.3 requires \
             input_tokens to be total tokens presented, including cache reads",
            usage.input_tokens, usage.cache_read_tokens,
        ));
    }
    failures
}

/// §9.1: "loss is a first-class, logged event." Anything present in the
/// original request that isn't recognizably present in the decoded result
/// must have a matching declared loss event — an undeclared drop is a bug,
/// not a known, logged degradation.
///
/// Compares **multiplicity per kind**, not mere presence (fix round 1, D3):
/// the shared 16-case golden corpus includes `parallel_tool_calls`, which
/// this check must be able to catch — two `ToolUse` blocks going in and one
/// coming out is a real drop even though `ToolUse` as a kind is still
/// "present" in the decoded result. A declared loss event only excuses the
/// gap for a kind if it names that kind as a whole, delimited token (see
/// [`loss_event_names_kind`]) — plain substring matching (the original
/// implementation's `e.contains(kind)`) let an unrelated loss event whose
/// text happened to contain the kind name as part of a larger word silently
/// satisfy the check.
pub fn check_round_trip_fidelity(
    original_request_blocks: &[ContentBlock],
    decoded_blocks: &[ContentBlock],
    declared_loss_events: &[String],
) -> Vec<String> {
    let mut failures = Vec::new();

    let original_counts = count_by_kind(original_request_blocks);
    let decoded_counts = count_by_kind(decoded_blocks);

    for (kind, original_count) in &original_counts {
        let decoded_count = decoded_counts.get(kind).copied().unwrap_or(0);
        if *original_count <= decoded_count {
            continue;
        }
        let missing = original_count - decoded_count;
        let declared = declared_loss_events
            .iter()
            .any(|e| loss_event_names_kind(e, kind));
        if !declared {
            failures.push(format!(
                "content block kind `{kind}` count mismatch on round-trip: request has \
                 {original_count}, decoded result has {decoded_count} (missing {missing}), and \
                 no declared LossEvent names `{kind}`"
            ));
        }
    }

    failures
}

fn count_by_kind(blocks: &[ContentBlock]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for block in blocks {
        *counts.entry(block_kind_name(block)).or_insert(0) += 1;
    }
    counts
}

/// A declared loss event "names" `kind` only when `kind` appears as a
/// whole, delimited token in the event's text (split on any non-alphanumeric
/// character) — never merely as a substring of a larger word. Without this,
/// a loss event describing something unrelated whose text happens to
/// contain `kind` as a fragment (e.g. "ContextText" containing "Text")
/// would silently excuse an unrelated drop.
fn loss_event_names_kind(event: &str, kind: &str) -> bool {
    event
        .split(|c: char| !c.is_alphanumeric())
        .any(|token| token == kind)
}

fn block_kind_name(block: &ContentBlock) -> &'static str {
    match block {
        ContentBlock::Text { .. } => "Text",
        ContentBlock::Image { .. } => "Image",
        ContentBlock::Document { .. } => "Document",
        ContentBlock::ToolUse { .. } => "ToolUse",
        ContentBlock::ToolResult { .. } => "ToolResult",
        ContentBlock::Thinking { .. } => "Thinking",
        ContentBlock::Opaque { .. } => "Opaque",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn check_mask_flags_a_key_outside_the_mask() {
        let mask = SerializeOnlyMask {
            mandatory: vec!["model".into()],
            allowed: vec![],
        };
        let failures = check_mask(&json!({"model": "x", "frobnicate": true}), &mask);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("frobnicate"));
    }

    #[test]
    fn check_mask_is_silent_when_every_key_is_permitted() {
        let mask = SerializeOnlyMask {
            mandatory: vec!["model".into()],
            allowed: vec!["temperature".into()],
        };
        let failures = check_mask(&json!({"model": "x", "temperature": 0.5}), &mask);
        assert!(failures.is_empty());
    }

    #[test]
    fn usage_invariant_flags_input_tokens_below_cache_read_tokens() {
        let usage = Usage {
            input_tokens: 1,
            output_tokens: 5,
            cache_read_tokens: 2,
        };
        let failures = check_usage_invariants(&usage);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("input_tokens"));
    }

    #[test]
    fn usage_invariant_passes_when_input_tokens_covers_cache_reads() {
        let usage = Usage {
            input_tokens: 10,
            output_tokens: 5,
            cache_read_tokens: 2,
        };
        assert!(check_usage_invariants(&usage).is_empty());
    }

    #[test]
    fn round_trip_fidelity_flags_an_undeclared_drop() {
        let original = vec![ContentBlock::Text {
            text: "hi".into(),
            cache: None,
            citations: vec![],
        }];
        let decoded: Vec<ContentBlock> = vec![];
        let failures = check_round_trip_fidelity(&original, &decoded, &[]);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("Text"));
    }

    #[test]
    fn round_trip_fidelity_accepts_a_declared_loss_event() {
        let original = vec![ContentBlock::Text {
            text: "hi".into(),
            cache: None,
            citations: vec![],
        }];
        let decoded: Vec<ContentBlock> = vec![];
        let declared = vec!["dropped a Text block: unsupported by this profile".to_string()];
        assert!(check_round_trip_fidelity(&original, &decoded, &declared).is_empty());
    }

    fn tool_use(id: &str) -> ContentBlock {
        ContentBlock::ToolUse {
            id: ToolCallId(id.into()),
            id_origin: IdOrigin::Provider,
            name: "search".into(),
            input: serde_json::json!({}),
            cache: None,
        }
    }

    /// D3 (fix round 1): the shared 16-case golden corpus includes
    /// `parallel_tool_calls` — two `ToolUse` blocks going in, one coming
    /// out. A presence-only check (is `ToolUse` present *at all* in the
    /// decoded result?) is blind to this, since `ToolUse` as a kind did
    /// survive. This must catch the count mismatch.
    #[test]
    fn round_trip_fidelity_flags_a_multiplicity_drop_not_just_presence() {
        let original = vec![tool_use("call-1"), tool_use("call-2")];
        let decoded = vec![tool_use("call-1")]; // one ToolUse silently dropped
        let failures = check_round_trip_fidelity(&original, &decoded, &[]);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("ToolUse"));
        assert!(failures[0].contains('2')); // original count
        assert!(failures[0].contains('1')); // decoded count
    }

    #[test]
    fn round_trip_fidelity_accepts_a_declared_loss_event_that_names_the_multiplicity_gap() {
        let original = vec![tool_use("call-1"), tool_use("call-2")];
        let decoded = vec![tool_use("call-1")];
        let declared = vec!["parallel ToolUse calls beyond the first are collapsed".to_string()];
        assert!(check_round_trip_fidelity(&original, &decoded, &declared).is_empty());
    }

    /// D3: loss-event matching must be exact (whole-token), not substring —
    /// a declared loss event whose text happens to contain the kind name as
    /// a fragment of an unrelated word must not silence a real drop.
    #[test]
    fn round_trip_fidelity_does_not_accept_a_coincidental_substring_match() {
        let original = vec![ContentBlock::Text {
            text: "hi".into(),
            cache: None,
            citations: vec![],
        }];
        let decoded: Vec<ContentBlock> = vec![];
        // "ContextText" contains "Text" as a substring but is not the whole
        // token "Text" — must not satisfy the check.
        let declared = vec!["ContextText field removed".to_string()];
        let failures = check_round_trip_fidelity(&original, &decoded, &declared);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("Text"));
    }

    #[tokio::test]
    async fn fold_stream_seals_text_blocks_by_index() {
        let events = vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::Text,
            },
            StreamEvent::BlockDelta {
                index: 0,
                delta: BlockDelta::Text("hello ".into()),
            },
            StreamEvent::BlockDelta {
                index: 0,
                delta: BlockDelta::Text("world".into()),
            },
            StreamEvent::BlockStop { index: 0 },
            StreamEvent::UsageDelta {
                input_tokens: Some(10),
                output_tokens: Some(5),
                cache_read_tokens: Some(2),
            },
            StreamEvent::MessageStop,
        ];
        let stream = ChatStream(Box::pin(futures::stream::iter(events)));
        let result = fold_stream(stream).await;

        assert_eq!(result.blocks.len(), 1);
        match &result.blocks[0] {
            ContentBlock::Text { text, .. } => assert_eq!(text, "hello world"),
            other => panic!("expected a Text block, got {other:?}"),
        }
        assert_eq!(result.usage.input_tokens, 10);
        assert_eq!(result.usage.output_tokens, 5);
        assert_eq!(result.usage.cache_read_tokens, 2);
        assert!(result.loss_events.is_empty());
    }

    #[tokio::test]
    async fn fold_stream_reports_a_delta_with_no_matching_block_start_as_a_loss_event() {
        let events = vec![StreamEvent::BlockDelta {
            index: 0,
            delta: BlockDelta::Text("orphaned".into()),
        }];
        let stream = ChatStream(Box::pin(futures::stream::iter(events)));
        let result = fold_stream(stream).await;

        assert!(result.blocks.is_empty());
        assert_eq!(result.loss_events.len(), 1);
        assert!(result.loss_events[0].contains("BlockDelta"));
    }

    /// A fake decoder with a real chunk-alignment bug: it reports how many
    /// transport chunks it received as the text of its one block, so its
    /// output genuinely differs between `WholeBody` and `Fixed`/`Prime`
    /// replays of the same cassette. Proves `check_fold_determinism` is not
    /// vacuously green — it must actually invoke `Provider::stream_chat`
    /// against a real `CassetteTransport` built from the cassette file, not
    /// just compare a hardcoded stream against itself.
    struct ChunkSensitiveProvider;

    impl Provider for ChunkSensitiveProvider {
        fn capabilities(
            &self,
            _model: &roundhouse_provider::ModelId,
        ) -> roundhouse_provider::Capabilities {
            roundhouse_provider::Capabilities::default()
        }

        fn resolve(
            &self,
            _req: &ChatRequest,
        ) -> Result<roundhouse_provider::Plan, roundhouse_provider::ProviderError> {
            Ok(roundhouse_provider::Plan {
                endpoint: "https://fake.invalid".into(),
            })
        }

        fn stream_chat<'a>(
            &'a self,
            _req: &'a ChatRequest,
            ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, roundhouse_provider::ProviderError>>
        {
            Box::pin(async move {
                let resp = ctx
                    .transport
                    .send(roundhouse_provider::HttpRequest {
                        method: "POST".into(),
                        url: "https://fake.invalid".into(),
                        headers: vec![],
                        body: vec![],
                    })
                    .await
                    .expect("cassette transport never fails");
                let chunk_count = resp.body.count().await;
                let events = vec![
                    StreamEvent::BlockStart {
                        index: 0,
                        kind: BlockKind::Text,
                    },
                    StreamEvent::BlockDelta {
                        index: 0,
                        delta: BlockDelta::Text(format!("chunks={chunk_count}")),
                    },
                    StreamEvent::BlockStop { index: 0 },
                ];
                Ok(ChatStream(Box::pin(futures::stream::iter(events))))
            })
        }

        fn count_tokens<'a>(
            &'a self,
            _req: &'a ChatRequest,
            _ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<roundhouse_provider::TokenCount, roundhouse_provider::ProviderError>,
        > {
            Box::pin(async { Ok(roundhouse_provider::TokenCount::default()) })
        }
    }

    #[tokio::test]
    async fn check_fold_determinism_catches_a_chunk_sensitive_decoder() {
        let cassette_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/cassettes/simple.cassette");
        let request = crate::fixtures::simple_request();

        let (failures, _) = check_fold_determinism(
            &ChunkSensitiveProvider,
            &request,
            &cassette_path,
            None,
            None,
        )
        .await;

        assert!(
            failures
                .iter()
                .any(|f| f.contains("fold determinism violated")),
            "expected a fold-determinism failure for a decoder whose output depends on chunk \
             boundaries, got: {failures:#?}"
        );
    }

    /// A fake reproducing `bedrock_converse`'s exact non-monotonic shape:
    /// `Ok` + `MessageStop` the instant the real terminal's bytes are fully
    /// present (byte 8 here), `Err` while a LEGITIMATE later frame (the
    /// post-terminal metadata frame bedrock always sends) is mid-flight,
    /// and `Ok` + `MessageStop` again once the whole body -- metadata frame
    /// included -- is present. "Does this prefix decode with a MessageStop"
    /// is therefore `false, ..., true (at 8), false, ..., true (at 16)` --
    /// NOT a single false-then-true transition.
    struct NonMonotonicTerminalProvider;

    /// Byte offset at which this fake's terminal is fully present.
    const NON_MONOTONIC_TERMINAL_END: usize = 3;
    /// Total body length (terminal + a trailing, legitimate "metadata"
    /// frame after it).
    const NON_MONOTONIC_BODY_LEN: usize = 20;

    impl Provider for NonMonotonicTerminalProvider {
        fn capabilities(
            &self,
            _model: &roundhouse_provider::ModelId,
        ) -> roundhouse_provider::Capabilities {
            roundhouse_provider::Capabilities::default()
        }

        fn resolve(
            &self,
            _req: &ChatRequest,
        ) -> Result<roundhouse_provider::Plan, roundhouse_provider::ProviderError> {
            Ok(roundhouse_provider::Plan {
                endpoint: "https://fake.invalid".into(),
            })
        }

        fn stream_chat<'a>(
            &'a self,
            _req: &'a ChatRequest,
            ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, roundhouse_provider::ProviderError>>
        {
            Box::pin(async move {
                let resp = ctx
                    .transport
                    .send(roundhouse_provider::HttpRequest {
                        method: "POST".into(),
                        url: "https://fake.invalid".into(),
                        headers: vec![],
                        body: vec![],
                    })
                    .await
                    .expect("cassette transport never fails");
                let mut received_len = 0usize;
                let mut body = resp.body;
                while let Some(chunk) = body.next().await {
                    received_len += chunk
                        .expect("CassetteTransport never yields a transport error")
                        .len();
                }
                match received_len {
                    len if len == NON_MONOTONIC_TERMINAL_END || len == NON_MONOTONIC_BODY_LEN => {
                        Ok(ChatStream(Box::pin(futures::stream::iter(vec![
                            StreamEvent::MessageStop,
                        ]))))
                    }
                    len if len > NON_MONOTONIC_TERMINAL_END && len < NON_MONOTONIC_BODY_LEN => {
                        Err(roundhouse_provider::ProviderError::StreamInterrupted {
                            partial: String::new(),
                        })
                    }
                    _ => Ok(ChatStream(Box::pin(futures::stream::iter(Vec::new())))),
                }
            })
        }

        fn count_tokens<'a>(
            &'a self,
            _req: &'a ChatRequest,
            _ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<roundhouse_provider::TokenCount, roundhouse_provider::ProviderError>,
        > {
            Box::pin(async { Ok(roundhouse_provider::TokenCount::default()) })
        }
    }

    /// Pins the exact defect found in review: bisection over a
    /// non-monotonic "did we reach the terminal" signal silently converges
    /// on the WRONG (later) true point. This test is RED against a binary
    /// search (it returns `Some(16)`, the whole body) and GREEN against a
    /// linear scan (it returns `Some(8)`, the real, minimal terminal).
    #[tokio::test]
    async fn locate_terminal_end_finds_the_minimal_terminal_not_a_later_one_past_a_gap() {
        let full = CassetteTransport {
            status: 200,
            headers: vec![],
            body: vec![0u8; NON_MONOTONIC_BODY_LEN],
            chunk_size: 0,
        };
        let request = crate::fixtures::simple_request();

        let terminal_end =
            locate_terminal_end(&NonMonotonicTerminalProvider, &request, &full, &None).await;

        assert_eq!(
            terminal_end,
            Some(NON_MONOTONIC_TERMINAL_END),
            "must locate the real, minimal terminal (byte {NON_MONOTONIC_TERMINAL_END}), not \
             the whole body (byte {NON_MONOTONIC_BODY_LEN}) a binary search wrongly converges \
             on when the signal isn't monotonic"
        );
    }
}
