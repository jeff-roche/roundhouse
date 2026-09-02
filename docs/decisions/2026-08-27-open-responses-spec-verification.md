# Open Responses 2026-04-24 spec verification (§9.4 gate)

Blocking pre-task for Phase 6 Task 5 (`openai-responses` codec). The task brief's
own encode/decode sketch is explicitly "the documented shape... not a verified
line-by-line read" — this note is that read, done before writing any codec code.

VERDICT: repo and revision exist exactly as named. Fetched the real OpenAPI spec
and read it directly (not summarized secondhand). Several concrete divergences
from the brief's sketch were found; each is contained to `encode.rs`/`decode.rs`
per §9.4's design intent, listed below.

## Correction (fix-round-1) — this note originally overclaimed

The paragraphs below, as first written, said the streaming event-type strings
were "confirmed the named event *type strings* exist verbatim as
`components.schemas` entries." **That claim is true and also not enough, and
stating it without that caveat overclaimed what was actually verified.** What
was checked was that a schema named e.g. `ResponseReasoningSummaryDeltaStreamingEvent`
*exists* in `components.schemas` — not that the literal string `decode.rs`
matches against is that schema's authoritative `type.enum`/`type.default`
value. Those are two different fields on the same schema object, and they can
disagree: `ResponseReasoningSummaryDeltaStreamingEvent`'s `description` field
says *"the type of the event, always `response.reasoning_summary.delta`"* —
**stale prose, and wrong** — while its `enum`/`default` (the fields that
actually constrain the wire value) say `"response.reasoning_summary_text.delta"`.
The original `decode.rs` matched the `description`'s string, almost certainly
because it reads like the authoritative one and comes first when skimming the
schema by eye.

Consequence, traced by fix-round-1's security review: `output_item.added`
opened a `Thinking` block, every real reasoning-summary delta then fell
through `decode_stream_event`'s `_ => Vec::new()` catch-all as an
"unrecognized" event, and `output_item.done` closed the block anyway — so a
real reasoning-enabled response decoded to an **empty, unsigned**
`ContentBlock::Thinking`. `roundhouse-engine/src/infer.rs`'s own doc comment
names this exact failure shape ("bricked sessions on resume": a provider that
requires its prior signed thinking block echoed back gets a content-free one).
The hand-authored `reasoning.cassette` used the same wrong string, so the
conformance suite was green against a cassette that shared the decoder's own
hallucination — nothing in the original suite could have caught it, because
both halves agreed with each other, not with the real spec.

**The structural fix** (not "read more carefully" — a gate that only ever
worked by care was always going to fail again): `tests/openai_responses_event_type_tripwire.rs`
vendors every `components.schemas` entry ending `StreamingEvent`'s real
`type.enum`/`type.default` value (never its `description`) into
`testdata/open_responses_2026-04-24_event_types.txt`, and asserts every
event-type string literal `decode.rs` actually matches on is a member of that
list. This is what should have existed from Step 0; it exists now, is
un-ignored, and is exercised by fix-round-1's own break-and-restore check
(see the task report).

The same "verified a general shape, missed a specific sub-detail" pattern
also produced a second, independent miss (fix-round-1 C3, not caught by the
tripwire because it's about content-*shape* rather than event-*type* strings):
this note's original "Input items" bullet below correctly named
`UserMessageItemParam`'s content-part type (`input_text`) but never checked
whether `AssistantMessageItemParam` (a **separate** union member, real content
parts `output_text`/`refusal`) uses the same one — it doesn't, and the
original `encode.rs` emitted `input_text` for both roles, making every
multi-turn request that replays a prior assistant `Text` reply invalid on the
wire. Fixed in `encode.rs` (role-aware content-part type); see the task report
for the golden-snapshot diff this produced.

## What was fetched

- `gh api repos/openresponses/openresponses` — the repo exists at
  `github.com/openresponses/openresponses` (org `openresponses`, Apache-2.0,
  1104 stars, default branch `main`, `homepage: https://openresponses.org`). No
  404, no redirect, no org move (unlike Task 1's `models.dev` case).
- `gh api repos/openresponses/openresponses/contents/public/openapi` — lists a
  dated-revision directory scheme: `public/openapi/<YYYY-MM-DD>/openapi.json`
  plus a `public/openapi/openapi.json` "latest" pointer. A `2026-04-24` directory
  exists exactly as the brief names it.
- `curl -sL https://raw.githubusercontent.com/openresponses/openresponses/main/public/openapi/2026-04-24/openapi.json`
  — 138,849 bytes, valid JSON, `info.version == "2026-04-24"`, `info.title ==
  "Open Responses"`. Two paths: `/responses` and `/responses/compact`. This is
  the actual OpenAPI 3.x document read below (byte-identical to the "latest"
  pointer file, i.e. `2026-04-24` is also the current spec as of this fetch).

Every field name and shape cited below was read directly out of
`components.schemas` in that fetched document (via a local Python script parsing
the downloaded JSON — not recalled from training, not guessed).

## Assumed shape vs. verified shape

- **Request envelope**: `{ model, input, instructions, tools, tool_choice,
  reasoning: { effort, summary }, stream, max_output_tokens, temperature, top_p,
  ... }` (schema `CreateResponseBody`, 25 top-level properties). **CONFIRMED**
  for every field the brief's sketch and this codec actually use: `model`,
  `input`, `instructions`, `tools`, `tool_choice`, `reasoning.effort`, `stream`,
  `max_output_tokens`. **DIVERGED**: there is no `stop` / `stop_sequences` field
  anywhere in `CreateResponseBody` — Open Responses has no stop-sequence
  mechanism at all (unlike Chat Completions). Contained fix: `encode.rs` never
  emits a `stop` field; `Params.stop` is silently dropped for this codec
  regardless of length (exercised by the `long_stop_sequence_list` golden case).
- **Input items** (`ItemParam`, discriminated union on `type`): `message`
  (`role` + `content` array of parts), `function_call` (`{type, call_id, name,
  arguments}` — **CONFIRMED** field names match the brief exactly),
  `function_call_output`. **DIVERGED (found in initial verification)**:
  `FunctionCallOutputItemParam`'s real, required fields are exactly `{call_id,
  type, output}` (plus optional `id`/`status`) — **there is no `is_error` field
  at all**. The brief's sketch invents `"is_error": is_error`. Contained fix:
  `encode_block`'s `ToolResult` arm never emits `is_error`; a tool error has no
  wire representation in this codec (see `encode.rs`'s comment on that arm).
  **DIVERGED (missed in initial verification, found in fix-round-1 C3)**: the
  `message` item type is not one shape — `UserMessageItemParam` (`role:
  "user"`, content parts `input_text`/`input_image`/`input_file`) and
  `AssistantMessageItemParam` (`role: "assistant"`, content parts
  `output_text`/`refusal`) are **separate union members** with different
  content-part `type` values for the same-looking `Text` block. The original
  verification pass read `UserMessageItemParam`'s shape and never checked
  whether the assistant variant reused it — it doesn't. See the "Correction"
  section above for how this was found and fixed.
- **Tool definitions** (`FunctionToolParam`): `{type: "function", name,
  description, parameters, strict}`. **CONFIRMED** — matches the brief's
  `{"type": "function", "name": ..., "description": ..., "parameters": ...}`
  exactly (`parameters` holds the JSON-Schema object, same as the brief's
  `t.input_schema`).
- **`tool_choice`** (`ToolChoiceParam`): a bare string enum `"none" | "auto" |
  "required"`, or `{type: "function", name}` for a forced single tool
  (`SpecificFunctionParam`). **DIVERGED (minor)** from the brief's unstated
  assumption / from the sibling `openai-chat` codec's shape: the named-tool form
  here is `{"type": "function", "name": ...}` — **no nested `"function": {...}`
  wrapper** the way Chat Completions' `tool_choice` uses. Contained fix:
  `encode_tool_choice`'s `Named` arm emits the flat two-key object, not the
  `openai_chat` codec's nested one.
- **Streaming event keying**: the original pass here confirmed the named event
  *schemas* exist in `components.schemas` (`ResponseOutputItemAddedStreamingEvent`,
  `ResponseOutputItemDoneStreamingEvent`, `ResponseOutputTextDeltaStreamingEvent`,
  `ResponseFunctionCallArgumentsDeltaStreamingEvent`,
  `ResponseReasoningSummaryDeltaStreamingEvent`, `ResponseCompletedStreamingEvent`)
  — **that is weaker than what it was written to sound like**; see the
  "Correction" section above for the fix-round-1 finding this let through
  uncaught (the reasoning-summary event's real `type.enum` value is
  `"response.reasoning_summary_text.delta"`, not the
  `"response.reasoning_summary.delta"` this note originally repeated from the
  same schema's stale `description` field). **DIVERGED**: the
  brief's sketch assumes every one of these events carries a flat top-level
  `item_id` field it can read uniformly. The real schemas split into two shapes:
  - `response.output_item.added` / `response.output_item.done` carry `{type,
    sequence_number, output_index, item}` — **no top-level `item_id`**. The
    item's id lives nested at `item.id`, and `item.type` (`message` |
    `function_call` | `reasoning` | ...) is what determines the block kind.
  - `response.output_text.delta` / `response.function_call_arguments.delta` /
    `response.reasoning_summary_text.delta` / `response.refusal.delta` carry a
    genuine top-level `item_id` alongside a `delta` string.
  - **Missed in initial verification, found in fix-round-1 C2**: this note
    never surveyed the terminal-failure event schemas at all
    (`ResponseFailedStreamingEvent`, `ResponseIncompleteStreamingEvent`,
    `ErrorStreamingEvent`) even though they are just as real and spec-mandated
    as the success-path ones, and arrive **in-band after an HTTP 200** — the
    original `decode.rs` had no branch for any of them, so a failed,
    truncated, or content-filtered inference decoded as an empty-but-`Ok`
    stream, which `run_chat_turn` would record as a completed task on an
    immutable event row. Fixed: `decode_openai_responses_stream` now returns
    `Result<Vec<StreamEvent>, StreamFailure>` and short-circuits on any of the
    three; `provider.rs` classifies the failure through the same `[errors]`-
    table path as an HTTP-level error. `response.refusal.delta` (a real,
    non-terminal delta this note also never surveyed) is now carried as
    `BlockDelta::Text` rather than silently dropped.

    Contained fix: `decode.rs` extracts the keying id differently per event
    type — `item.id` (+ `item.type` for the block-kind switch) for the two
    `output_item.*` events, top-level `item_id` for the three delta events —
    both funneled through the same `DeltaKeyer::index_for` call so downstream
    code still sees one normalized `index: u32` regardless of which shape
    produced it.
  - `FunctionCall`'s real shape also separates `id` (the item's stream identity)
    from `call_id` (the correlation token that a later `function_call_output`
    must reference) — two different strings. Contained fix: `decode.rs` keys
    the `DeltaKeyer` by `item.id` but sets `BlockKind::ToolUse.provider_id` from
    `item.call_id` (falling back to `item.id` if `call_id` is absent), so a
    folded `ContentBlock::ToolUse`'s id is the one a caller would actually need
    to echo back in a `function_call_output.call_id`.
- **Usage / cache accounting** (`Usage` schema): `{input_tokens, output_tokens,
  total_tokens, input_tokens_details: {cached_tokens}, output_tokens_details}`.
  **CONFIRMED exactly** as the brief's `decode_usage` sketch assumes:
  `input_tokens` is the total (cache-inclusive) figure, and
  `input_tokens_details.cached_tokens` is the cache-read breakdown — this is the
  one part of the brief's sketch that needed no changes at all.
- **Non-text content model (images/documents)**: `input_image` items carry
  `image_url` (a fully-qualified URL or a `data:` URL with inline base64 —
  **no separate base64 field**); `input_file` items carry `filename` +
  `file_data` (base64) or `file_url`. **CONFIRMED** these exist in the spec.
  **Scope decision, not a spec divergence**: this task does not implement
  `Image`/`Document` block encoding. `roundhouse-provider` has no `base64`
  dependency today, and both existing codecs in this crate
  (`openai_chat::encode`, `anthropic_messages::encode`) already establish the
  precedent of dropping `Image`/`Document` blocks in this scope with a
  "Phase 2 LossEvent" comment — this codec follows that same precedent rather
  than being the first to add a new dependency for two decorative golden cases.
  Flagged in the task report for the orchestrator's visibility, since Phase 6 is
  explicitly "provider breadth" and a later batch task may want real image/file
  support.
- **Reasoning effort vocabulary** (`ReasoningEffortEnum`): real values are
  `none | low | medium | high | xhigh` (5 values). **DIVERGED (informational,
  not corrected)**: the brief's `openai-responses.toml` declares a 4-value
  vocabulary (`none, low, medium, high`) and maps `ReasoningIntent::Max` to
  `"high"`, never using `"xhigh"`. Per this project's process rules, the brief's
  exact TOML content is authoritative unless it's factually wrong about an API
  *shape* (REALITY-CORRECTIONS' domain) — omitting `xhigh` is a product
  decision about how conservatively to map `Max`, not an incorrect shape (a
  4-value vocabulary is a valid subset of the real enum), so the TOML is shipped
  as the brief specifies. Left here as a note for a future task that might want
  a dedicated `xhigh` tier.
- **Reasoning models forbidding `temperature`/`top_p`**: this codec's one
  profile (`openai-responses.toml`) only ever matches `gpt-5*` models, which are
  real OpenAI reasoning models that reject `temperature`/`top_p` entirely. This
  is *not* something the fetched OpenAPI schema itself states (the schema models
  `temperature`/`top_p` as ordinary optional numbers with no per-model
  restriction annotation) — it is documented OpenAI product behavior outside
  this spec document. Given that, `encode.rs` never encodes `temperature`/
  `top_p` at all (unconditionally, not via a per-model check), which is both the
  simplest implementation and correct for every model this profile's
  `[[model]]` entries actually match. Called out explicitly as an assumption
  not verified against this OpenAPI document, for the `temperature_forbidden_model`
  golden case's benefit.

## Divergences found and how they were contained

Found during initial verification, fixed inside `encode.rs`/`decode.rs` only:

1. Never emit `stop` (dropped `Params.stop`, any length) — `encode.rs`.
2. Never emit `is_error` on `function_call_output` — `encode.rs`.
3. `tool_choice`'s named-tool form is `{"type":"function","name":...}`, not
   `openai_chat`'s nested `{"type":"function","function":{"name":...}}` —
   `encode.rs`.
4. `response.output_item.added`/`.done` key off nested `item.id`/`item.type`;
   the delta events key off top-level `item_id` — `decode.rs`.
5. `BlockKind::ToolUse.provider_id` is sourced from `item.call_id`, not
   `item.id` — `decode.rs`.

Found in fix-round-1 review (the initial pass missed these; see the
"Correction" section above), fixed inside `encode.rs`/`decode.rs`/`provider.rs`
only:

6. The reasoning-summary event's real `type` value is
   `"response.reasoning_summary_text.delta"`, not
   `"response.reasoning_summary.delta"` — `decode.rs`, plus the structural
   tripwire test (`tests/openai_responses_event_type_tripwire.rs`) and its
   vendored spec data (`testdata/open_responses_2026-04-24_event_types.txt`).
7. `AssistantMessageItemParam`'s content parts are `output_text`, not
   `UserMessageItemParam`'s `input_text` — `encode.rs` is now role-aware.
8. `response.failed`/`response.incomplete`/`error` are real, spec-mandated,
   in-band terminal-failure events this codec never surveyed or handled —
   `decode.rs` now surfaces them as `Err(StreamFailure)`;
   `response.refusal.delta` (also unsurveyed) is now carried as
   `BlockDelta::Text` instead of dropped.
9. `temperature`/`top_p` are gated on whether the *matched model* has a
   `[model.reasoning]` entry (data), not hardcoded off for every model this
   codec's `encode`/`decode` will ever be reused against — `encode.rs`. Not a
   spec-shape divergence; a design fix so Task 16's non-reasoning
   `openai-responses` providers aren't silently blocked from sending them.
10. The base URL now resolves through the §9.9 seam
    (`resolve_base_url`/host-only recording) and the `responses` path segment
    is appended on the parsed `Url` (preserving any query string a gateway
    `base_url` carries) rather than by string concatenation — `provider.rs`.
    Not a spec-shape divergence; a hardening fix.
11. `Image`/`Document` blocks are still not *encoded* (unchanged scope
    decision — no `base64` dependency, see above), but a request containing
    one is now rejected by `resolve()` before it ever reaches `encode`, since
    there is no `LossEvent` type anywhere in this codebase to declare a
    silent drop against — `provider.rs`.

Also found while fixing the above, not itself a spec-shape issue:
`sse_stream::SseStream` silently drops the LAST frame of a body unless it is
followed by a blank-line terminator. Every `.cassette` file in this codec put
its most consequential frame last (`response.completed`'s usage figure for
the four original cassettes; the terminal-failure event for the new C2
cassettes) with no trailing blank line, so those frames were silently never
decoding — the four original conformance cases stayed green only because
`check_usage_invariants`' `input_tokens >= cache_read_tokens` degenerately
holds at `0 >= 0` when usage never decodes at all. Fixed by adding the
trailing terminator to every SSE cassette, with a permanent regression test
(`tests/openai_responses_cassette_sse_termination_test.rs`) asserting every
SSE-typed cassette under `testdata/cassettes/openai_responses/` has one.

No other task, type, or crate in this plan needed to change to contain any of
the above, except the one deliberate, authorized crossing into
`roundhouse-conformance` (fix-round-1 C7: `ConformanceCase` gained an
`expected_error` field so an error-status cassette can run through the
generic harness) — confirming §9.4's design claim that the narrow-waist IR
absorbs a per-codec spec surprise without rippling outward, while the one
genuine harness gap this task hit got fixed at its actual source.
