# Open Responses 2026-04-24 spec verification (§9.4 gate)

Blocking pre-task for Phase 6 Task 5 (`openai-responses` codec). The task brief's
own encode/decode sketch is explicitly "the documented shape... not a verified
line-by-line read" — this note is that read, done before writing any codec code.

VERDICT: repo and revision exist exactly as named. Fetched the real OpenAPI spec
and read it directly (not summarized secondhand). Several concrete divergences
from the brief's sketch were found; each is contained to `encode.rs`/`decode.rs`
per §9.4's design intent, listed below.

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
  (`role` + `content` array of `input_text`/`input_image`/`input_file` parts),
  `function_call` (`{type, call_id, name, arguments}` — **CONFIRMED** field names
  match the brief exactly), `function_call_output`. **DIVERGED**:
  `FunctionCallOutputItemParam`'s real, required fields are exactly `{call_id,
  type, output}` (plus optional `id`/`status`) — **there is no `is_error` field
  at all**. The brief's sketch invents `"is_error": is_error`. Contained fix:
  `encode_block`'s `ToolResult` arm never emits `is_error`; a tool error has no
  wire representation in this codec (see `encode.rs`'s comment on that arm).
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
- **Streaming event keying**: confirmed the named event *type strings* exist
  verbatim as `components.schemas` entries (`ResponseOutputItemAddedStreamingEvent`,
  `ResponseOutputItemDoneStreamingEvent`, `ResponseOutputTextDeltaStreamingEvent`,
  `ResponseFunctionCallArgumentsDeltaStreamingEvent`,
  `ResponseReasoningSummaryDeltaStreamingEvent`, `ResponseCompletedStreamingEvent`),
  matching the brief's `response.output_item.added` /
  `response.function_call_arguments.delta` / `response.output_item.done` names
  and its prose mention of `response.reasoning_summary.delta`. **DIVERGED**: the
  brief's sketch assumes every one of these events carries a flat top-level
  `item_id` field it can read uniformly. The real schemas split into two shapes:
  - `response.output_item.added` / `response.output_item.done` carry `{type,
    sequence_number, output_index, item}` — **no top-level `item_id`**. The
    item's id lives nested at `item.id`, and `item.type` (`message` |
    `function_call` | `reasoning` | ...) is what determines the block kind.
  - `response.output_text.delta` / `response.function_call_arguments.delta` /
    `response.reasoning_summary.delta` carry a genuine top-level `item_id`
    alongside a `delta` string.

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

Every divergence above was fixed inside `crates/roundhouse-provider/src/codec/openai_responses/{encode,decode}.rs` only:

1. Never emit `stop` (dropped `Params.stop`, any length) — `encode.rs`.
2. Never emit `is_error` on `function_call_output` — `encode.rs`.
3. `tool_choice`'s named-tool form is `{"type":"function","name":...}`, not
   `openai_chat`'s nested `{"type":"function","function":{"name":...}}` —
   `encode.rs`.
4. `response.output_item.added`/`.done` key off nested `item.id`/`item.type`;
   the three delta events key off top-level `item_id` — `decode.rs`.
5. `BlockKind::ToolUse.provider_id` is sourced from `item.call_id`, not
   `item.id` — `decode.rs`.
6. Never encode `Image`/`Document` blocks (scope decision, not a spec fix) —
   `encode.rs`.

No other task, type, or crate in this plan was touched to contain any of the
above — confirming §9.4's design claim that the narrow-waist IR absorbs a
per-codec spec surprise without rippling outward.
