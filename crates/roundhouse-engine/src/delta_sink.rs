//! `DeltaCoalescer`: batches a provider's raw stream deltas
//! (`roundhouse_provider::BlockDelta`) into persistable
//! `roundhouse_core::Delta`s, applying the flush rules from plan 14 (Phase 8
//! Task 19, lane B, Task 6).
//!
//! Pure and synchronous by design: no clock, no sleeps, no I/O, no async.
//! Callers own time (`Instant`, passed explicitly) and persistence (the
//! returned `Delta`s are handed to a `TaskRunner`/`EventWriter` elsewhere —
//! Task 7 does that wiring, not this module).
//!
//! **Flush rules** (brief, plan 14):
//! - at about [`FLUSH_SIZE_THRESHOLD`] of buffered text;
//! - on a kind change (e.g. `Text` -> `ToolArgs`);
//! - on [`DeltaCoalescer::block_stop`];
//! - on [`DeltaCoalescer::finish`];
//! - when `now - last_flush >= `[`FLUSH_INTERVAL`].
//!
//! No emitted `Delta`'s `serde_json` serialization may reach
//! `roundhouse_core::BLOB_INLINE_THRESHOLD` bytes.
//!
//! **Controller ruling R1 (split-safe holdback):** a size- or time-triggered
//! flush never decides its own split point. It calls an injected [`SplitFn`]
//! — whose contract mirrors `roundhouse_store::Redactor::safe_split_len`
//! plus `roundhouse_store::EventWriter::redaction_split_for_flush`'s holdback
//! — for **every** non-final split point, including the size-shrink needed
//! when JSON escaping alone pushes a chunk past `BLOB_INLINE_THRESHOLD`
//! (shrinking the requested `max` and re-querying the splitter each time,
//! never re-deciding a smaller split point on its own: a match that lies
//! wholly to one side of the splitter's chosen `k` is not guaranteed safe
//! against an arbitrary *smaller* point picked without asking the splitter
//! again). `DeltaCoalescer` never holds an `EventWriter` or a `Redactor`
//! itself — it only calls whatever is injected — so it stays pure,
//! synchronous, and ignorant of the store. A final flush
//! ([`DeltaCoalescer::block_stop`], [`DeltaCoalescer::finish`]) releases
//! everything, splitter or not — the splitter is a holdback-for-more-bytes
//! mechanism, and a final flush has no more bytes coming.
//!
//! **Controller ruling R3 (thinking signature vs. the size limit):** a
//! thinking signature always rides the delta that closes its block. To keep
//! that closing delta small, the coalescer always emits its buffered
//! thinking *text* as separate, signature-less, plain-chunked deltas first,
//! then a final delta carrying an empty `text` and the signature — so the
//! closing delta's own size is just the signature's, never inflated by
//! leftover text. If the signature alone still serializes to
//! `BLOB_INLINE_THRESHOLD` or more, that final delta is still emitted
//! (there is no text left to shed, so shrinking it further would mean
//! silently dropping bytes of the signature, which is not an option: see
//! `Delta::Thinking`'s "must round-trip verbatim" contract).

use std::time::{Duration, Instant};

use roundhouse_core::{Delta, BLOB_INLINE_THRESHOLD};
use roundhouse_provider::BlockDelta;

/// Roughly 2 KiB of buffered (pre-serialization) text: the raw-byte trigger
/// for a mid-block flush (brief, plan 14: "about 2 KiB of text"). A trigger
/// only, not the hard cap on what gets emitted -- `BLOB_INLINE_THRESHOLD`,
/// measured on the actual `serde_json` serialization, is the hard cap, and a
/// buffer that reaches this many raw bytes can still need a tighter,
/// escape-aware shrink to fit under it.
pub const FLUSH_SIZE_THRESHOLD: usize = 2048;

/// 250ms = 4Hz, matching `docs/architecture/08-ui-design.md` §11.2's
/// "coalesced 4Hz session summaries". A pending buffer this old gets flushed
/// even when it is far below [`FLUSH_SIZE_THRESHOLD`], so a slow trickle of
/// tokens still reaches the store promptly instead of waiting indefinitely
/// for enough bytes to accumulate.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Returns the largest safe split point `k <= min(max, bytes.len())` for a
/// buffer that may still grow (more bytes may arrive after `bytes`), with
/// the redaction holdback already applied by whoever constructed this
/// closure. `0` means nothing is safely flushable yet -- the caller must
/// keep buffering and try again later (with more bytes, or at a final
/// flush, which does not call this at all -- see the module doc's R1
/// summary).
///
/// `roundhouse_store::EventWriter::redaction_split_for_flush` is the
/// production implementation this wraps (Task 7): one `ArcSwap` load of the
/// writer's live `Redactor` per call, so a single non-final flush sees one
/// consistent redactor snapshot for both the holdback and the split
/// decision.
pub type SplitFn = Box<dyn Fn(&[u8], usize) -> usize + Send>;

/// The kind of content a `Pending` run is buffering. Determined per
/// `BlockDelta` variant; a kind change flushes whatever is pending first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingKind {
    Text,
    ToolArgs,
    Thinking,
}

impl PendingKind {
    fn of(delta: &BlockDelta) -> Self {
        match delta {
            BlockDelta::Text(_) => PendingKind::Text,
            BlockDelta::ToolArgsFragment(_) => PendingKind::ToolArgs,
            BlockDelta::Thinking { .. } => PendingKind::Thinking,
        }
    }

    /// Wraps `text` in the `Delta` variant this kind produces. `Thinking`'s
    /// `signature` is always `None` here -- the one delta that ever carries
    /// a signature is built directly at the closing flush (see
    /// `DeltaCoalescer::close_pending`), never through this generic path.
    fn make(self, text: String) -> Delta {
        match self {
            PendingKind::Text => Delta::Text { text },
            PendingKind::ToolArgs => Delta::ToolArgs { fragment: text },
            PendingKind::Thinking => Delta::Thinking {
                text,
                signature: None,
            },
        }
    }
}

struct Pending {
    kind: PendingKind,
    text: String,
    signature: Option<String>,
}

/// Pure, synchronous batcher from `BlockDelta` to `Delta`. See the module
/// doc for the flush rules and controller rulings R1/R3.
pub struct DeltaCoalescer {
    splitter: SplitFn,
    pending: Option<Pending>,
    last_flush: Option<Instant>,
}

impl DeltaCoalescer {
    pub fn new(splitter: SplitFn) -> Self {
        DeltaCoalescer {
            splitter,
            pending: None,
            last_flush: None,
        }
    }

    /// Buffers `delta`, flushing whatever was pending first if `delta`'s
    /// kind differs from it, and returns whatever a size/time/escape trigger
    /// safely released (in order; never reordered). May return more than one
    /// `Delta` (a kind-change flush plus a size-triggered flush of the new
    /// kind, for instance).
    pub fn push(&mut self, delta: BlockDelta, now: Instant) -> Vec<Delta> {
        let incoming_kind = PendingKind::of(&delta);
        let mut out = Vec::new();

        let needs_fresh_pending = match &self.pending {
            None => true,
            Some(pending) if pending.kind != incoming_kind => {
                out.extend(self.close_pending());
                true
            }
            Some(_) => false,
        };
        if needs_fresh_pending {
            self.pending = Some(Pending {
                kind: incoming_kind,
                text: String::new(),
                signature: None,
            });
            self.last_flush = Some(now);
        }

        let pending = self
            .pending
            .as_mut()
            .expect("a pending run was just ensured above");
        match delta {
            BlockDelta::Text(t) => pending.text.push_str(&t),
            BlockDelta::ToolArgsFragment(f) => pending.text.push_str(&f),
            BlockDelta::Thinking { text, signature } => {
                pending.text.push_str(&text);
                // A signature fragment arrives as its own zero-text delta
                // (see `fold_stream_to_blocks` in `infer.rs`) once the
                // thinking text is complete; once set, a later `None` must
                // never clobber it.
                if signature.is_some() {
                    pending.signature = signature;
                }
            }
        }

        while let Some(flushed) = self.attempt_nonfinal_flush(now) {
            out.push(flushed);
        }
        out
    }

    /// A block ended: release everything pending for it, regardless of what
    /// the splitter would say (R1). Takes `now` for API symmetry with
    /// `push`; a subsequent `push` starting a fresh pending run resets the
    /// flush-interval baseline on its own regardless of this call's `now`.
    pub fn block_stop(&mut self, now: Instant) -> Vec<Delta> {
        let out = self.close_pending();
        self.last_flush = Some(now);
        out
    }

    /// The stream ended: release everything pending, regardless of what the
    /// splitter would say (R1). No `Instant` needed -- this is a terminal
    /// release, not a time-triggered one.
    pub fn finish(&mut self) -> Vec<Delta> {
        self.close_pending()
    }

    /// Whether a mid-stream (non-final) flush should be attempted right now:
    /// the buffer reached [`FLUSH_SIZE_THRESHOLD`] raw bytes, its actual
    /// serialization already reached `BLOB_INLINE_THRESHOLD` (JSON escaping
    /// can multiply a byte several times over -- this can trip before the
    /// raw-byte trigger does), or [`FLUSH_INTERVAL`] has elapsed since the
    /// last flush.
    fn should_attempt_flush(&self, now: Instant) -> bool {
        let Some(pending) = &self.pending else {
            return false;
        };
        if pending.text.is_empty() {
            return false;
        }
        if pending.text.len() >= FLUSH_SIZE_THRESHOLD {
            return true;
        }
        let whole = pending.kind.make(pending.text.clone());
        if serialized_len(&whole) >= BLOB_INLINE_THRESHOLD {
            return true;
        }
        matches!(self.last_flush, Some(last) if now.duration_since(last) >= FLUSH_INTERVAL)
    }

    /// Attempts one redaction-safe, size-bounded, non-final flush (R1): every
    /// candidate split point -- both the initial size/time-triggered ask and
    /// any further shrink needed to fit `BLOB_INLINE_THRESHOLD` -- goes
    /// through `self.splitter`, never decided locally. Returns `None` (and
    /// leaves the buffer untouched) when no trigger fired or the splitter has
    /// nothing safe to release yet.
    fn attempt_nonfinal_flush(&mut self, now: Instant) -> Option<Delta> {
        if !self.should_attempt_flush(now) {
            return None;
        }
        let kind = self.pending.as_ref().unwrap().kind;
        let mut max = {
            let text = &self.pending.as_ref().unwrap().text;
            FLUSH_SIZE_THRESHOLD.min(text.len())
        };

        loop {
            let raw_k = {
                let text = &self.pending.as_ref().unwrap().text;
                (self.splitter)(text.as_bytes(), max)
            };
            if raw_k == 0 {
                // Nothing is safely flushable yet -- keep buffering.
                return None;
            }
            let text = &self.pending.as_ref().unwrap().text;
            let k = floor_char_boundary(text, raw_k.min(text.len()));
            if k == 0 {
                return None;
            }
            let chunk = text[..k].to_string();
            let delta = kind.make(chunk.clone());
            if serialized_len(&delta) < BLOB_INLINE_THRESHOLD {
                let pending = self.pending.as_mut().unwrap();
                pending.text.drain(..k);
                self.last_flush = Some(now);
                return Some(delta);
            }
            // Too big once serialized: shrink the requested max by exactly
            // one character and re-query the splitter (R1) -- never assume a
            // smaller point inside the splitter's own chosen `k` is safe
            // without asking again.
            let shrunk = floor_char_boundary(&chunk, chunk.len().saturating_sub(1));
            if shrunk == 0 || shrunk >= max {
                // Cannot make further progress (a single character's own
                // serialization should never reach BLOB_INLINE_THRESHOLD in
                // practice, but guard against looping forever regardless).
                return None;
            }
            max = shrunk;
        }
    }

    /// Final release of whatever is pending (block_stop/finish/kind change):
    /// releases everything, bypassing the splitter entirely (R1) -- there is
    /// no more data coming for this run, so there is nothing left to hold
    /// back. Still respects `BLOB_INLINE_THRESHOLD` by chunking.
    fn close_pending(&mut self) -> Vec<Delta> {
        let Some(pending) = self.pending.take() else {
            return Vec::new();
        };
        let Pending {
            kind,
            text,
            signature,
        } = pending;
        match kind {
            PendingKind::Thinking => {
                // R3: peel all buffered text into earlier, signature-less
                // deltas first, so the closing delta -- the only one
                // carrying the signature -- is as small as it can be.
                let mut out = chunk_into_deltas(&text, |t| PendingKind::Thinking.make(t));
                if let Some(sig) = signature {
                    // Emitted unconditionally, even if the signature alone
                    // reaches BLOB_INLINE_THRESHOLD (R3's exemption): there
                    // is no text left to shed, and a signature must
                    // round-trip verbatim, so it is never truncated.
                    out.push(Delta::Thinking {
                        text: String::new(),
                        signature: Some(sig),
                    });
                }
                out
            }
            _ => chunk_into_deltas(&text, move |t| kind.make(t)),
        }
    }
}

fn serialized_len(delta: &Delta) -> usize {
    serde_json::to_vec(delta)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

/// The largest `char`-boundary index `<= idx` in `s` (`s.len()` if
/// `idx >= s.len()`). Mirrors the standalone version of nightly's
/// `str::floor_char_boundary`. Flooring a split point returned by
/// `SplitFn`/`Redactor::safe_split_len` this way is always safe against
/// cutting a reported match -- see that method's doc comment's proof.
fn floor_char_boundary(s: &str, idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    let mut idx = idx;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Final-release chunking (no splitter/redaction holdback involved -- R1's
/// block_stop/finish "releases everything, splitter or not"): splits `text`
/// into char-boundary-aligned prefixes, greedily as large as possible, such
/// that each one's `make`-wrapped `Delta` serializes under
/// `BLOB_INLINE_THRESHOLD`.
fn chunk_into_deltas(text: &str, make: impl Fn(String) -> Delta) -> Vec<Delta> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let take = max_fit_prefix_len(rest, &make);
        let (chunk, remainder) = rest.split_at(take);
        out.push(make(chunk.to_string()));
        rest = remainder;
    }
    out
}

/// The largest char-boundary prefix length of `s` (`1..=s.len()`) whose
/// `make`-wrapped `Delta` still serializes under `BLOB_INLINE_THRESHOLD`.
/// Assumes a single character's own serialization never reaches
/// `BLOB_INLINE_THRESHOLD` (4096 bytes is generous even for a worst-case
/// `\uXXXX` escape plus envelope), so the first char boundary always
/// qualifies and this never returns 0 for a non-empty `s` -- callers can
/// rely on it to make forward progress.
fn max_fit_prefix_len(s: &str, make: &impl Fn(String) -> Delta) -> usize {
    let mut boundaries = s
        .char_indices()
        .map(|(i, _)| i)
        .skip(1)
        .chain(std::iter::once(s.len()));
    let mut best = boundaries
        .next()
        .expect("s is non-empty, so it has at least one char boundary after 0");
    for boundary in boundaries {
        if serialized_len(&make(s[..boundary].to_string())) < BLOB_INLINE_THRESHOLD {
            best = boundary;
        } else {
            break;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(delta: &Delta) -> &str {
        match delta {
            Delta::Text { text } => text,
            Delta::ToolArgs { fragment } => fragment,
            Delta::Thinking { text, .. } => text,
            other => panic!("expected a text-shaped delta in this test, got {other:?}"),
        }
    }

    fn signature_of(delta: &Delta) -> Option<&str> {
        match delta {
            Delta::Thinking { signature, .. } => signature.as_deref(),
            _ => None,
        }
    }

    fn concat_text(deltas: &[Delta]) -> String {
        deltas.iter().map(text_of).collect()
    }

    fn serialized_len(delta: &Delta) -> usize {
        serde_json::to_vec(delta).expect("Delta serializes").len()
    }

    /// No holdback, no redaction concerns: always releases exactly what was
    /// asked for.
    fn identity_splitter() -> SplitFn {
        Box::new(|bytes: &[u8], max: usize| max.min(bytes.len()))
    }

    /// Models "nothing is safely flushable yet" unconditionally -- the
    /// degenerate holdback case R1 calls out: a non-final flush must emit
    /// nothing and keep buffering.
    fn zero_splitter() -> SplitFn {
        Box::new(|_bytes: &[u8], _max: usize| 0)
    }

    // -------------------------------------------------------------------
    // Flush rule: about FLUSH_SIZE_THRESHOLD bytes of buffered text.
    // -------------------------------------------------------------------

    #[test]
    fn flushes_when_pending_text_reaches_about_two_kib() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();
        let text = "a".repeat(FLUSH_SIZE_THRESHOLD);

        let out = sink.push(BlockDelta::Text(text.clone()), now);

        assert_eq!(
            out.len(),
            1,
            "reaching the size threshold must flush immediately"
        );
        assert!(matches!(out[0], Delta::Text { .. }));
        assert_eq!(text_of(&out[0]), text);
        assert!(
            sink.finish().is_empty(),
            "the whole buffer was already flushed"
        );
    }

    #[test]
    fn does_not_flush_a_small_amount_of_text_early() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();

        let out = sink.push(BlockDelta::Text("hello".into()), now);

        assert!(
            out.is_empty(),
            "a few bytes must not trigger an early flush"
        );
    }

    // -------------------------------------------------------------------
    // Flush rule: BlockStop.
    // -------------------------------------------------------------------

    #[test]
    fn block_stop_releases_whatever_is_still_pending() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();
        assert!(sink.push(BlockDelta::Text("hello".into()), now).is_empty());

        let stopped = sink.block_stop(now);

        assert_eq!(concat_text(&stopped), "hello");
    }

    #[test]
    fn block_stop_on_an_empty_pending_buffer_is_a_no_op() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        assert!(sink.block_stop(Instant::now()).is_empty());
    }

    // -------------------------------------------------------------------
    // Flush rule: a kind change.
    // -------------------------------------------------------------------

    #[test]
    fn kind_change_flushes_the_previous_kind_before_starting_the_next() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();
        assert!(sink.push(BlockDelta::Text("hello".into()), now).is_empty());

        let out = sink.push(BlockDelta::ToolArgsFragment("{}".into()), now);

        assert_eq!(out.len(), 1, "the kind change must flush the Text run");
        assert!(matches!(out[0], Delta::Text { .. }));
        assert_eq!(text_of(&out[0]), "hello");

        let stopped = sink.block_stop(now);
        assert_eq!(stopped.len(), 1);
        assert!(matches!(stopped[0], Delta::ToolArgs { .. }));
        assert_eq!(text_of(&stopped[0]), "{}");
    }

    // -------------------------------------------------------------------
    // Flush rule: finish.
    // -------------------------------------------------------------------

    #[test]
    fn finish_releases_whatever_is_still_pending() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();
        assert!(sink.push(BlockDelta::Text("tail".into()), now).is_empty());

        let out = sink.finish();

        assert_eq!(concat_text(&out), "tail");
    }

    #[test]
    fn finish_on_an_empty_coalescer_is_a_no_op() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        assert!(sink.finish().is_empty());
    }

    // -------------------------------------------------------------------
    // Flush rule: the 250ms / FLUSH_INTERVAL cadence. Instants are built
    // directly via arithmetic -- no sleeps, no clock.
    // -------------------------------------------------------------------

    #[test]
    fn flushes_after_the_flush_interval_even_below_the_size_threshold() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let t0 = Instant::now();
        assert!(sink.push(BlockDelta::Text("abc".into()), t0).is_empty());

        let t1 = t0 + FLUSH_INTERVAL;
        let out = sink.push(BlockDelta::Text("def".into()), t1);

        assert_eq!(concat_text(&out), "abcdef");
    }

    #[test]
    fn does_not_flush_before_the_flush_interval_elapses() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let t0 = Instant::now();
        assert!(sink.push(BlockDelta::Text("abc".into()), t0).is_empty());

        let t1 = t0 + FLUSH_INTERVAL - Duration::from_millis(1);
        let out = sink.push(BlockDelta::Text("def".into()), t1);

        assert!(
            out.is_empty(),
            "must not flush a moment before the interval elapses"
        );
    }

    // -------------------------------------------------------------------
    // Never emit a Delta whose serialized size reaches BLOB_INLINE_THRESHOLD:
    // measure the actual serialization (JSON escapes can multiply bytes),
    // not the raw byte count.
    // -------------------------------------------------------------------

    #[test]
    fn oversized_serialization_triggers_a_flush_before_the_raw_size_threshold() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();
        // A NUL byte escapes to six bytes in JSON -- a 6x inflation. 700 raw
        // bytes is comfortably under FLUSH_SIZE_THRESHOLD, but the serialized
        // delta is already past BLOB_INLINE_THRESHOLD.
        let text: String = "\u{0}".repeat(700);
        assert!(text.len() < FLUSH_SIZE_THRESHOLD, "test premise");
        assert!(
            serialized_len(&Delta::Text { text: text.clone() }) >= BLOB_INLINE_THRESHOLD,
            "test premise: escaping alone must already exceed the threshold"
        );

        let out = sink.push(BlockDelta::Text(text.clone()), now);

        assert_eq!(
            out.len(),
            1,
            "the oversized serialization must trigger exactly one flush"
        );
        assert!(serialized_len(&out[0]) < BLOB_INLINE_THRESHOLD);
        assert!(
            text.starts_with(text_of(&out[0])),
            "the flushed chunk must be a prefix of the pushed text"
        );

        let rest = sink.finish();
        assert_eq!(
            text_of(&out[0]).to_string() + &concat_text(&rest),
            text,
            "no bytes may be lost or reordered across the split"
        );
    }

    #[test]
    fn escape_heavy_text_is_chunked_by_measured_serialized_size_at_final_release() {
        // A splitter that always reports "nothing safely flushable yet": push
        // must never force output mid-stream (R1), so this heavily escaped
        // buffer accumulates in full and only `finish` releases it.
        let mut sink = DeltaCoalescer::new(zero_splitter());
        let now = Instant::now();
        let text: String = "\u{0}".repeat(4000);

        let out = sink.push(BlockDelta::Text(text.clone()), now);
        assert!(
            out.is_empty(),
            "a splitter reporting nothing safely flushable must never force output"
        );

        let released = sink.finish();

        assert!(
            released.len() > 1,
            "4000 escaped NULs cannot fit in a single BLOB_INLINE_THRESHOLD-bounded delta"
        );
        for delta in &released {
            assert!(matches!(delta, Delta::Text { .. }));
            let size = serialized_len(delta);
            assert!(
                size < BLOB_INLINE_THRESHOLD,
                "every released delta must stay under the inline threshold, got {size}"
            );
        }
        assert_eq!(
            concat_text(&released),
            text,
            "splitting must not drop or reorder any character"
        );
    }

    // -------------------------------------------------------------------
    // Holdback / split-safe behaviour (Controller ruling R1): a non-final
    // flush must never land inside a secret the splitter reports, and a
    // splitter reporting 0 keeps everything buffered until a final release.
    // -------------------------------------------------------------------

    #[test]
    fn a_split_that_would_land_inside_a_secret_moves_back_to_the_secrets_start() {
        // Fakes what `Redactor::safe_split_len` guarantees: a naive split
        // point landing inside a known match gets moved back to the match's
        // start, never handing back a truncated half.
        const SECRET_START: usize = 2040;
        const SECRET_END: usize = 2060;
        let splitter: SplitFn = Box::new(|bytes, max| {
            let naive = max.min(bytes.len());
            if naive > SECRET_START && naive < SECRET_END {
                SECRET_START
            } else {
                naive
            }
        });
        let mut sink = DeltaCoalescer::new(splitter);
        let now = Instant::now();

        let mut text = "a".repeat(SECRET_START);
        text.push_str(&"S".repeat(SECRET_END - SECRET_START));
        text.push_str("trailing-tail");

        let out = sink.push(BlockDelta::Text(text.clone()), now);

        assert_eq!(out.len(), 1);
        let flushed = text_of(&out[0]);
        assert_eq!(
            flushed.len(),
            SECRET_START,
            "must stop exactly before the secret, never inside it"
        );
        assert!(
            !flushed.contains('S'),
            "no fragment of the secret may leak into the flushed chunk"
        );

        let rest = sink.finish();
        assert_eq!(
            flushed.to_string() + &concat_text(&rest),
            text,
            "no bytes may be lost or reordered"
        );
    }

    // -------------------------------------------------------------------
    // A thinking signature rides the delta that closes its block.
    // -------------------------------------------------------------------

    #[test]
    fn thinking_signature_rides_the_delta_that_closes_the_block() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();
        assert!(sink
            .push(
                BlockDelta::Thinking {
                    text: "because X implies Y".into(),
                    signature: None,
                },
                now,
            )
            .is_empty());
        // Real providers (Anthropic) send the signature as its own zero-text
        // delta once the thinking text is complete -- see
        // `fold_stream_to_blocks`'s `BlockDelta::Thinking` arm in `infer.rs`.
        assert!(sink
            .push(
                BlockDelta::Thinking {
                    text: String::new(),
                    signature: Some("sig-abc".into()),
                },
                now,
            )
            .is_empty());

        let out = sink.block_stop(now);

        let (last, earlier) = out.split_last().expect("at least the closing delta");
        assert_eq!(signature_of(last), Some("sig-abc"));
        assert_eq!(
            text_of(last),
            "",
            "the closing delta carries as little text as possible"
        );
        for d in earlier {
            assert!(matches!(d, Delta::Thinking { .. }));
            assert_eq!(
                signature_of(d),
                None,
                "only the closing delta may carry the signature"
            );
        }
        assert_eq!(
            earlier.iter().map(text_of).collect::<String>(),
            "because X implies Y"
        );
    }

    #[test]
    fn thinking_without_a_signature_closes_like_plain_text() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();
        assert!(sink
            .push(
                BlockDelta::Thinking {
                    text: "no signature here".into(),
                    signature: None,
                },
                now,
            )
            .is_empty());

        let out = sink.block_stop(now);

        assert_eq!(concat_text(&out), "no signature here");
        for d in &out {
            assert_eq!(signature_of(d), None);
        }
    }

    // -------------------------------------------------------------------
    // R3: an oversized signature is still emitted at the closing flush.
    // -------------------------------------------------------------------

    #[test]
    fn oversized_signature_is_emitted_inline_anyway_at_the_closing_flush() {
        let mut sink = DeltaCoalescer::new(identity_splitter());
        let now = Instant::now();
        let huge_signature = "x".repeat(BLOB_INLINE_THRESHOLD * 2);
        assert!(sink
            .push(
                BlockDelta::Thinking {
                    text: "short reasoning".into(),
                    signature: None,
                },
                now,
            )
            .is_empty());
        assert!(sink
            .push(
                BlockDelta::Thinking {
                    text: String::new(),
                    signature: Some(huge_signature.clone()),
                },
                now,
            )
            .is_empty());

        let out = sink.block_stop(now);

        let (last, earlier) = out.split_last().expect("at least the closing delta");
        assert_eq!(signature_of(last), Some(huge_signature.as_str()));
        assert_eq!(text_of(last), "");
        let size = serialized_len(last);
        assert!(
            size >= BLOB_INLINE_THRESHOLD,
            "test premise: the signature alone must already exceed the threshold, got {size}"
        );
        assert_eq!(
            earlier.iter().map(text_of).collect::<String>(),
            "short reasoning"
        );
    }
}
