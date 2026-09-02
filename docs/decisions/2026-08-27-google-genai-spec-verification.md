# Google GenAI (Gemini) spec verification (§9.4 gate) — Task 6

Blocking pre-task for Phase 6 Task 6 (`google-genai` codec). The task brief's
`EndpointMode::{Interactions,GenerateContent}` sketch is explicitly a
"documented shape... not a verified line-by-line read" — this is that read,
done before writing `encode.rs`/`decode.rs`.

**VERDICT (headline finding): the brief's working bet — that `contents[].parts[]`,
`functionCall`, and `thoughtSignature` are shared between the two endpoint
modes — is FALSE.** The two endpoint modes have genuinely different content
models, not just different envelopes. Per the brief's own explicit fallback
instruction ("if verification finds the content model... diverged... split
into two codecs at that point; per §9.4 this is 'a mechanical, localized
refactor'"), I did not force a shared block-encoding helper across modes.
I kept the single-codec, single-`Provider`, `EndpointMode`-switch *file
structure* the brief and REALITY-CORRECTIONS' `EndpointKind::GoogleGenai`
(a single enum variant — `crates/roundhouse-provider/src/profile/reasoning.rs`)
both assume, but `encode()`/the stream decoder each internally dispatch to two
independent, non-shared construction/decoding paths per `mode`. See
"Divergence 1" below for the concrete evidence and what changed as a result.

## What was fetched

All of the following were fetched with `curl` directly (not paraphrased
through a summarizing tool) so field names and enum values below are read
from the raw JSON, not from prose.

1. `https://ai.google.dev/api/interactions-api.md.txt` (200, 121101 bytes) —
   the Interactions API's REST reference page in Markdown form, linked from
   `https://ai.google.dev/gemini-api/docs/interactions-overview`. States: "You
   are viewing the beta version of the Interactions API. Endpoints are under
   `/v1beta/`." and links `https://ai.google.dev/static/api/interactions.openapi.json`.
2. `https://ai.google.dev/static/api/interactions.openapi.json` (200, 379890
   bytes) — the **authoritative machine-readable OpenAPI document** for the
   Interactions API. `info.version == "v1beta"`, `info.title == "Gemini API"`,
   `x-google-revision: "0"`. Parsed with a local Python script (not recalled
   from training) — every schema/field name/enum value quoted below was read
   directly out of `components.schemas` in this file, the same
   verify-the-enum-not-the-prose discipline REALITY-CORRECTIONS §13b demands.
3. `https://ai.google.dev/api/generate-content.md.txt` (200, 226804 bytes) —
   the REST reference for the **legacy** `models.generateContent` /
   `models.streamGenerateContent` methods (this is real Markdown-rendered
   prose, not an OpenAPI JSON for this doc — Google does not publish a
   separate machine-readable OpenAPI file for the legacy surface the way it
   does for Interactions — so field names here are read from the page's own
   literal "JSON representation" code blocks, which are exact, not summarized).
4. `https://ai.google.dev/gemini-api/docs/api-errors.md.txt` (200) — dedicated
   Interactions API error-code reference page, titled "This page provides a
   reference for all Interactions API error codes."
5. `https://ai.google.dev/gemini-api/docs/troubleshooting` (200, fetched via
   WebFetch for orientation only, then corroborated against the primary
   sources above) — mentions the literal tokens `429 RESOURCE_EXHAUSTED` and
   `503 UNAVAILABLE` for "an error indicating you should retry."

Two more pages were fetched **only for orientation** via a paraphrasing tool
(WebFetch, whose own description says it "processes content with a small,
fast model") before the raw fetches above, and are called out here
specifically because one of them was **caught being wrong** when
cross-checked against the raw OpenAPI JSON — the exact class of error
REALITY-CORRECTIONS §13b warns about, just one layer earlier (research tooling
paraphrase, not spec prose):

- `https://ai.google.dev/gemini-api/docs/migrate-to-interactions` — its
  paraphrase of the Interactions API's function-calling response shape
  (`steps[].type == "function_call"`, flat `name`/`arguments`) turned out to
  match the real schema once checked (`FunctionCallStep`).
- `https://ai.google.dev/gemini-api/docs/interactions/thinking.md.txt` — its
  paraphrase said a `thought` step's fields are `signature` (required) and
  `summary` (optional) content items — but a **second**, more general
  paraphrase of the REST reference (attempted before the raw OpenAPI fetch)
  claimed the `thought` step's shape was `{"type": "thought", "content":
  [...]}`. These two paraphrases of the same underlying page **disagreed with
  each other**. The raw OpenAPI JSON (`components.schemas.ThoughtStep`)
  settled it: `{"type": "thought", "signature"?: <base64 string>, "summary"?:
  [ThoughtSummaryContent]}` — no `content` field at all. **Every field name
  and enum value in this document past this point is sourced from the raw
  OpenAPI JSON or the legacy REST page's literal "JSON representation" code
  block, never from a paraphrasing tool's prose summary.**

I did **not** find, and am not claiming to have found, a machine-readable
OpenAPI document for the legacy `generateContent`/`streamGenerateContent`
surface, nor a page giving that surface's exact HTTP error-body JSON shape
(the `api-errors.md.txt` page found is explicit that it documents "all
Interactions API error codes" — a different surface). Where this document
relies on the long-standing, extremely stable `google.rpc.Status`-style error
envelope (`{"error": {"code": <int>, "message": <str>, "status":
"<UPPER_SNAKE>"}}`) for the legacy surface, that is flagged below as
corroborated-but-not-directly-fetched, not verified line-by-line the way the
Interactions API's error page was.

## Divergence 1 (headline): the content model is NOT shared between modes

Verified directly from `interactions.openapi.json`'s `components.schemas`:

- `CreateModelInteractionParams.input` is `InteractionsInput`, a `oneOf` of
  `Content | Step[] | Content[] | string` — **there is no `contents` field at
  all.**
- The response's `steps[]` array is a `oneOf`-discriminated union
  (`discriminator: {propertyName: "type"}` on the parent `Step` schema) of
  `UserInputStep`, `ModelOutputStep`, `FunctionCallStep`, `FunctionResultStep`,
  `ThoughtStep`, plus built-in-tool step pairs (`CodeExecutionCallStep`/
  `CodeExecutionResultStep`, `GoogleSearchCallStep`/`GoogleSearchResultStep`,
  etc.) — **there is no `candidates[].content.parts[]` at all.**
- `FunctionCallStep`'s real, required fields (`required: ["arguments", "id",
  "name", "type"]`) are flat on the step itself: `{"type": "function_call",
  "id": "call_98231", "name": "get_weather", "arguments": {"location": "Boston,
  MA"}}` — not nested inside a `parts[]` array item the way `functionCall` is
  in legacy `Part`.
- `ThoughtStep`'s real fields are `signature` (base64 string) and `summary`
  (`ThoughtSummaryContent[]`) — thinking is a **dedicated step type**, not a
  `thought`/`thoughtSignature` pair attached to an ordinary content `Part`.

By contrast, the legacy `generateContent`/`streamGenerateContent` surface
**does** genuinely match the brief's sketch — verified from
`generate-content.md.txt`'s literal JSON-representation blocks:

- `Content`: `{"parts": [Part], "role": string}` — request body is
  `{"contents": [Content], ...}`.
- `Part`: `{"thought": boolean, "thoughtSignature": string, "text": string |
  "functionCall": FunctionCall | "functionResponse": FunctionResponse | ...}`
  — `thought`/`thoughtSignature` genuinely are attached to an ordinary `Part`
  here, matching the brief's assumption for *this* endpoint.
- `FunctionCall`: `{"id": string, "name": string, "args": object}`.
- `FunctionResponse`: `{"id": string, "name": string, "response": object,
  "parts": [FunctionResponsePart], "willContinue": boolean, "scheduling": enum}`.

**Consequence for the implementation**: `encode()` and the stream decoder each
take `mode: EndpointMode` and dispatch to two independent functions
(`encode_interactions`/`encode_generate_content`,
`decode_interactions_stream`/`decode_generate_content_stream`) that share only
the handful of things that genuinely are mode-independent (role→string,
tool-name/description/schema extraction, the shared `EncodeError` type). This
is the brief's own anticipated "mechanical, localized refactor," done inside
the one `google_genai` module/file set rather than as two top-level codecs —
the profile schema's `EndpointKind::GoogleGenai` is a single enum variant
(`crates/roundhouse-provider/src/profile/reasoning.rs`), so the rest of the
system treats "google-genai" as one wire family regardless of this internal
split.

**Consequence for the brief's Step 1 test**: the brief's
`golden_single_turn_text_generate_content_mode_matches_content_shape` test
asserts `interactions["contents"][0]["parts"] == legacy["contents"][0]["parts"]`.
Given the finding above, `encode(&req, &profile, EndpointMode::Interactions)`
has **no `contents` key at all** — that assertion is unconditionally false
(a panic on `Value::Null == Value::Null` would trivially "pass" if both sides
happened to index-miss the same way, which is exactly the "vacuously true"
failure mode REALITY-CORRECTIONS warns about, so I did not even want the
accidental-pass version of this). I rewrote the test to assert something true
and meaningful about the two encodings instead: both encode the same input
text into their own real wire shape (`input[0]["content"][0]["text"]` for
Interactions, `contents[0]["parts"][0]["text"]` for GenerateContent), and both
snapshots are kept as separate golden artifacts. See
`tests/golden_google_genai.rs` and the task report for the exact rewritten
assertion.

## Divergence 2: reasoning is Effort-kind for Interactions, Budget-kind for GenerateContent — not both Budget-kind

The brief's TOML declares one `[model.reasoning]` entry: `kind = "budget"`,
`field = "/generationConfig/thinkingConfig/thinkingBudget"`, vocabulary `["0",
"1024", "8192", "24576"]`. Verified:

- `GenerationConfig` (Interactions API, `interactions.openapi.json`) has
  properties `["image_config", "max_output_tokens", "seed", "speech_config",
  "stop_sequences", "thinking_level", "thinking_summaries", "tool_choice",
  "transcription_config", "video_config"]` — **no numeric thinking-budget
  field of any kind.** `thinking_level` is a `ThinkingLevel` enum: `["minimal",
  "low", "medium", "high"]` (no `"max"`).
- Legacy `generateContent`'s `GenerationConfig.thinkingConfig` (per
  `generate-content.md.txt`'s literal JSON representation) is `{"includeThoughts":
  boolean, "thinkingBudget": integer, "thinkingLevel": enum}` — **this** is
  where a numeric token budget genuinely exists, and the brief's own field
  path (`/generationConfig/thinkingConfig/thinkingBudget`, camelCase
  `generationConfig` — the legacy surface's exact JSON casing, not the
  Interactions API's `generation_config` snake_case) is real and correct for
  this endpoint specifically.

So the brief's TOML is real, but it describes `GenerateContent` mode, not the
Interactions default. (Aside: `ReasoningControl.field` is documentation only
in this codebase today — no codec, including Task 5's, actually does a
dynamic JSON-pointer insertion keyed off it; every codec hardcodes the literal
wire placement in `encode.rs` and uses the profile only for
`kind`/`vocabulary`/`map`. Confirmed by grep: `field` is never read outside
its own struct definition.)

**What I did**: `GenerateContent` mode uses the profile's Budget-kind
`ReasoningControl` exactly as the brief specifies
(`generationConfig.thinkingConfig.thinkingBudget`, an integer parsed from
`control.resolve(intent)?`). `Interactions` mode uses a small, hardcoded
`ReasoningIntent -> ThinkingLevel` mapping in `encode.rs` (`Off` → field
omitted, `Low` → `"low"`, `Medium` → `"medium"`, `High`/`Max` → `"high"`,
since the real vocabulary has no `"max"` tier) written into
`generation_config.thinking_level`, **not** routed through the profile's
Budget control (the wire vocabularies are incompatible — a numeric budget
string like `"8192"` is not a legal `thinking_level` value — and
`ModelEntry` supports exactly one `ReasoningControl` per model, so there is no
schema room for two). This is the same category of decision as `role_str`/
`encode_tool_choice` elsewhere in this crate treating a small, fixed,
spec-mandated wire enum as code rather than profile data. The brief's own
framing ("Gemini uses thinkingBudget, a Budget-kind ReasoningControl —
exercises the OTHER ReasoningKind variant") is honored: the golden
`reasoning_on`/`reasoning_off`/`reasoning_budget_variant` cases run under
`EndpointMode::GenerateContent`, where Budget-kind is the thing actually being
exercised; one extra golden case (`reasoning_on_interactions_thinking_level`)
covers the verified, real Interactions-mode `thinking_level` path.

## Divergence 3: temperature/top_p do not exist at all in the Interactions API today

Checked the full property list of `CreateModelInteractionParams` (top level)
and `GenerationConfig` (nested) — **neither contains `temperature`, `top_p`,
or `top_k` in any form.** This is a structural fact about the wire schema, not
a per-model policy: it is not possible to send a temperature to any model via
the Interactions API as specified today. Legacy `generateContent`'s
`GenerationConfig` genuinely has `temperature`/`topP`/`topK` (confirmed from
its literal JSON representation), with no documented interaction or exclusion
against `thinkingConfig` — unlike OpenAI's `gpt-5*` reasoning family (Task 5's
finding), nothing in the fetched Gemini spec forbids temperature alongside
reasoning.

**What I did**: `golden_temperature_forbidden_model` now documents and
asserts the real, verified fact for `EndpointMode::Interactions` — temperature
and top_p are never encoded for *any* model, because the field does not exist
on that surface, not because of a per-model reasoning gate. A companion case,
`temperature_and_top_p_are_forwarded_under_generate_content_mode`, proves the
same request's temperature/top_p **are** forwarded once encoded under
`EndpointMode::GenerateContent`, demonstrating the divergence is about which
wire endpoint supports the field at all, not a hardcoded "never send this"
policy baked into the codec.

## Divergence 4: the profile's `[errors]` table used the wrong (legacy) vocabulary

The brief's TOML declares `"RESOURCE_EXHAUSTED"`, `"UNAVAILABLE"`,
`"PERMISSION_DENIED"` — the classic `google.rpc.Code` UPPER_SNAKE vocabulary.
Verified from `https://ai.google.dev/gemini-api/docs/api-errors.md.txt`
("This page provides a reference for all **Interactions API** error codes"):
the Interactions API's real error vocabulary is **lowercase `snake_case`**,
delivered as `{"error": {"code": "<snake_case>", "message": "<str>"}}` both
over plain HTTP and as the `error` field of an in-stream SSE `error` event
(`event_type: "error"`). Its documented table includes (among others):
`rate_limit_exceeded` (429, "exceeded your per-minute or per-second... limit"),
`quota_exceeded` (429, "exceeded your daily quota"), `service_unavailable`
(503, "temporarily overloaded or down"), `permission_denied` (403, "API key
does not have permission" — an authorization failure, **not** a billing/quota
one), `model_not_found` (404), `not_found` (404). A closing note on the page
states explicitly: "Any error code not listed above falls back to the
`snake_case` version of the HTTP status" — further confirming this is a
`snake_case`-only vocabulary, not the classic UPPER_SNAKE one.

Since Task 6's conformance suite runs against `EndpointMode::Interactions`
(the brief's own instruction — "that's Gemini's default surface per §9.2"),
using the brief's literal UPPER_SNAKE keys would make the profile's `[errors]`
table **silently never match** any real Interactions API response — the exact
"schema exists, value never checked" failure class REALITY-CORRECTIONS §13b
warns about, just for a config table instead of a decoder match arm.

**What I did**: corrected the profile's `[errors]` table to the verified real
codes, preserving the brief's original *intent* per entry:
`rate_limit_exceeded` → `shed_concurrency` (same disposition the brief gave
its rate-limit entry), `service_unavailable` → `retry_backoff` (same
disposition the brief gave its capacity entry), `quota_exceeded` → `fatal` /
`category = "quota"` (the brief's `PERMISSION_DENIED` entry carried `category
= "quota"`, signalling its *intent* was billing exhaustion, not bare
authorization — `quota_exceeded`'s description literally is "You have
exceeded your daily quota," an exact match for that intent; the real
`permission_denied` code is a plain API-key-authorization failure with no
quota semantics at all, so mapping the brief's quota-flavoured entry onto it
would have been the same "name looks similar, meaning doesn't match" mistake
Task 5's C1 made). Built a tripwire mirroring Task 5's:
`testdata/google_genai_interactions_api-errors_2026_error_codes.txt` vendors
the full documented code list from the fetched page, and
`tests/google_genai_wire_literal_tripwire.rs` asserts every code string the
profile TOML declares, and every event-type/step-type literal
`decode.rs` matches on, is a member of the corresponding vendored list.

**A second, load-bearing consequence of this same finding**: `crate::errors::
classify` (`errors.rs`, shared infrastructure used by every codec) hardcodes
`v.pointer("/error/type")` to read the provider's error code — but the real
Interactions API error envelope names that field `code`, not `type`
(`{"error": {"code": "rate_limit_exceeded", "message": "..."}}`). Passing the
raw wire body straight to `classify()` would never match the profile's
`code_table` regardless of how the table's keys are spelled, since it is
looking at the wrong JSON pointer. I did not change `errors.rs` (shared by
Task 5's codec and any later one; changing its hardcoded pointer is out of
this task's scope and would need a cross-codec audit). Instead
`provider.rs` remaps the real body into the shape `classify()` expects
(`{"error": {"type": <code>, "message": <message>}}`) immediately before
calling it, in both the HTTP-status-error branch and the in-band
`StreamFailure` branch — the same kind of adapter Task 5's
`stream_failure_body()` already established for a different reason (there,
building a body from a `StreamFailure` struct; here, renaming one field of an
already-real body).

### Correction (fix-round-1 F4): the legacy `toolConfig`/`functionCallingConfig` citation was wrong

`encode_generate_content_tool_config`'s original doc comment cited
`generate-content.md.txt` as the verification source for
`toolConfig.functionCallingConfig`'s `mode`/`allowedFunctionNames` shape.
That citation was itself wrong in the same way as Task 5's C1: `allowedFunctionNames`
appears **zero** times in `generate-content.md.txt`, and of the `mode` values
this codec sends (`"ANY"`, `"NONE"`), only `"ANY"` appears there at all (in
unrelated code samples, not a schema definition). The **values are correct**
— confirmed at `https://ai.google.dev/api/caching.md.txt`'s
`FunctionCallingConfig`/`Mode` sections, which is the real schema location
for this type (`CachedContent.toolConfig` in the caching API references the
same `FunctionCallingConfig` shape `generateContent`'s `toolConfig` field
uses) — but the document named as having verified them did not contain them.
Fixed in both the code comment and this record; no wire behavior changed.

## Divergence 5 (minor, in this codec's favor): `is_error` and `stop_sequences` DO exist here

Two places where this codec's real spec is *more* permissive than Task 5's
`openai-responses` finding, flagged explicitly because it would be easy to
mechanically copy Task 5's opposite conclusion across:

- `FunctionResultStep.is_error` is a real, optional boolean field (verified:
  present in `interactions.openapi.json`'s `FunctionResultStep` schema) —
  unlike Open Responses' `FunctionCallOutputItemParam`, which Task 5 found has
  no such field at all. This codec's `tool_result_is_error` golden case
  therefore asserts `is_error` **is** forwarded, not dropped.
- Interactions API's `GenerationConfig.stop_sequences` is a real array field
  (verified, same property list as Divergence 3) — unlike Open Responses,
  which Task 5 found has no stop-sequence mechanism at all. This codec's
  `long_stop_sequence_list` golden case therefore asserts the list **is**
  forwarded (Google's real cap is 5 entries per `generate-content.md.txt`'s
  `stopSequences` doc, "up to 5" — the codec does not itself truncate or
  validate this; that is left to the server, matching this crate's existing
  precedent of not client-side-validating provider limits).

## Divergence 6 (scope decision, not a spec-shape finding): Image/Document/Thinking/Opaque are not encoded — all four now fail closed

Matches Task 5's own established precedent and reasoning, re-confirmed rather
than assumed. **Corrected by fix-round-1 F1** (originally this codec silently
dropped `Thinking`/`Opaque` via `Ok(None)`, which the review found is NOT
the same situation as `openai_responses`' accepted `Thinking` precedent —
see below):

- `roundhouse-provider` has no `base64` dependency today, and both `ImageContent`/
  `DocumentContent` (Interactions) and `Blob` (legacy `inlineData`) require
  base64-encoded bytes on the wire. `encode_block` returns
  `Err(EncodeError::UnencodableMedia(kind))` — naming which block kind
  (`"Image"` or `"Document"`) rather than a single shared, indistinguishable
  message (a carried-forward fix from Task 5's review, applied here from the
  start) — for both endpoint modes, and `GoogleGenAiProvider::resolve` fails
  closed on it as a cheap pre-flight, with the guard that actually matters
  living in `stream_chat`'s `encode(...)?` propagation (Task 5's fix-round-2
  D1 lesson: the guard must live on the path production callers actually
  take, not only on `resolve`, which has zero production callers in this
  workspace).
- `ContentBlock::Thinking` is **also** not encoded in either mode, and
  **also** now returns `Err(EncodeError::UnencodableMedia("Thinking"))`, not
  `Ok(None)` as originally shipped. The distinction from `openai_responses`'
  accepted `Thinking` precedent (silently dropped there, no error) is load-
  bearing, not cosmetic: that codec never receives a resendable
  `encrypted_content` for `Thinking` in the first place, so dropping it is a
  genuine no-op. Gemini's spec, by contrast, **documents this round-trip as
  required**: `missing_thought_signature` is a real, standalone Interactions
  error code ("The response is missing a required thought signature") and
  `MISSING_THOUGHT_SIGNATURE` a real legacy `FinishReason` — both verified in
  the fetched specs. Silently dropping a `Thinking` block here doesn't fail
  loudly the way a genuinely-unsupported-forever case should; it quietly
  breaks multi-step tool use downstream with no record of why. Correctly
  reconstructing the real round-trip (attaching a signature to a step, and
  per some documentation to the *first* of several parallel function calls
  specifically) needs cross-block state this task's per-block
  `encode_block(role, block) -> Result<Option<Value>, _>` signature cannot
  express, and remains out of scope here — but failing closed until that's
  built is the honest choice, not silence. Flagged under Concerns in the
  task report.
  **Fix-round-2 G4 — the consequence of this ruling that was not written down
  when F1 landed:** `roundhouse-engine/src/infer.rs` folds a decoded
  `BlockKind::Thinking` into a persisted `ContentBlock::Thinking`, and by
  design that block is resent as history on the next turn. After F1 (and
  after F8 extends the same recognition to the legacy surface, where
  thought-flagged text previously folded harmlessly into `Text` and encoded
  fine), **any turn whose history contains a `Thinking` block now hard-fails
  `encode` with `Unsupported`** — so on a thinking-enabled model, this makes
  turn 2 onward unusable rather than merely degraded, for as long as this
  codec has no cross-block signature attachment. The ruling stands (loud
  beats silent, and — confirmed by grep — nothing in `roundhouse-daemon` or
  `roundhouse-engine` references `google_genai` yet, so no user is affected
  by this today), but anyone wiring this codec into the daemon/engine needs
  to hit this sentence before they hit turn 2's failure: either build the
  real cross-block signature round-trip first, or accept that this codec is
  single-turn-only on thinking-enabled models until it exists.
- `ContentBlock::Opaque` is likewise changed to
  `Err(EncodeError::UnencodableMedia("Opaque"))`, for consistency with the
  ruling above rather than a distinct spec finding of its own — this
  decoder never produces an `Opaque` block itself, so the case is not known
  to be reachable in practice today, but failing closed costs nothing and
  avoids silently trusting that a future caller can never hand this codec
  one from a different provider.

## Known gap (equal prominence to the one above): `EndpointMode::GenerateContent` has thinner test coverage than Interactions

The brief instructs running the full conformance suite only against
`EndpointMode::Interactions` ("that's Gemini's default surface per §9.2"),
which is honored — Interactions is the fully cassette-driven,
`ConformanceSubject`-tested surface. That instruction does **not** mean
`GenerateContent` is untested, but its coverage is real and narrower, and a
future reader pointing this codec at real legacy traffic should know exactly
where the edges are:

- **Fix-round-1 F3 added integration coverage this codec did not originally
  have**: one success cassette
  (`testdata/cassettes/google_genai/generate_content_text.cassette`) and one
  error cassette (`generate_content_error_429.cassette`), both replayed
  through the real `GoogleGenAiProvider::stream_chat` (not just synthetic
  unit-test frames) — see `conformance_google_genai.rs`'s
  `generate_content_mode_text_cassette_decodes_via_real_stream_chat`/
  `generate_content_mode_error_429_cassette_classifies_via_the_status_remap_branch`.
  This is what caught nothing new by itself, but it is what would have
  caught F2 mechanically had it existed from the start — F2 (an
  unconditional `MessageStop`, the one real defect this fix round found) was
  invisible to unit tests built from well-formed synthetic frames, since
  those can only confirm the decoder agrees with itself.
- **What remains cassette-free**: `GenerateContent` mode does not have a
  full `ConformanceSubject` (mask/round-trip-fidelity/fold-determinism-
  across-chunk-boundaries checks) the way Interactions does — a second one
  was judged not required by fix-round-1's review, and Interactions
  correctly stays canonical. The legacy positional text-continuation
  heuristic (`decode_generate_content_stream`'s "does this part continue the
  currently-open text/thinking block?" logic) is unit-tested directly
  (`decode.rs`'s `generate_content_stream_tests` module) against synthetic
  multi-chunk scenarios, but has not been exercised against real,
  multi-chunk legacy traffic.

## Streaming envelope facts (verified, feeding `decode.rs`)

- **Interactions API**: request sets `"stream": true` in the JSON body (a
  request-body field, `CreateModelInteractionParams.stream`) — there is no
  separate `:streamInteraction` method. SSE frames are `data: {...}` where the
  payload is one of `InteractionSseEvent`'s `oneOf` members, discriminated by
  `event_type` (verified `const` values): `"interaction.created"`,
  `"step.start"` (`{index, step}`), `"step.delta"` (`{index, delta}`, `delta`
  discriminated by its own `type`: `"text"`, `"arguments_delta"`,
  `"thought_signature"`, `"thought_summary"`, plus several built-in-tool/media
  delta kinds not supported by this codec), `"step.stop"` (`{index,
  step_usage, usage}`), `"interaction.status_update"` (`{interaction_id,
  status}`), `"interaction.completed"` (`{interaction}`, whose nested partial
  resource carries `status` and optionally `usage`), `"error"` (`{error:
  {code, message}}`). Note: `ContentStart`/`ContentDelta`/`ContentStop`
  schemas (`event_type` `"content.start"`/`"content.delta"`/`"content.stop"`)
  exist in `components.schemas` but are **not** members of
  `InteractionSseEvent`'s `oneOf` — i.e. they are not part of the documented
  top-level event union this API actually emits per this spec revision, so
  `decode.rs` does not dispatch on them (a genuinely-unrecognized frame is
  skipped, matching this crate's established "skip malformed/unrecognized
  frames" precedent — this is not a case of silently dropping a *known*
  terminal/failure event, which is enumerated explicitly below).
- **Terminal/failure events, enumerated explicitly** (Task 5's C2 lesson):
  a standalone `"error"` event is always a `StreamFailure`.
  `"interaction.completed"`'s nested `interaction.status` of `"completed"` or
  `"requires_action"` (the normal, successful end of a tool-call turn — the
  model is waiting for a `function_result`, not failing) decodes usage (if
  present) and emits `MessageStop`; `"failed"`, `"cancelled"`, or
  `"incomplete"` is a `StreamFailure`. `"interaction.created"` and
  `"interaction.status_update"` are recognized-and-ignored (progress pings;
  `"interaction.completed"` is the authoritative end-of-stream signal per the
  spec's own step/event design) rather than falling through the generic
  unrecognized-frame bucket.
- **Legacy `streamGenerateContent`**: requires `?alt=sse` on the URL
  (confirmed: every code sample for this method in `generate-content.md.txt`
  includes it) — without it the endpoint streams a raw JSON array instead of
  SSE. Each `data:` frame is a complete, partial `GenerateContentResponse`
  (`{candidates: [{content: {parts, role}, finishReason, index}],
  usageMetadata, promptFeedback}`) — there is no `event_type`/discriminator
  on the frame itself, matching REALITY-CORRECTIONS' "Gemini's positional-
  no-key parts" description for *this* endpoint specifically. `finishReason`
  values verified from the fetched `FinishReason` enum: `STOP` (normal),
  `MAX_TOKENS` (treated as a `StreamFailure`, matching Task 5's
  `response.incomplete` precedent — a truncated generation must not read as a
  clean success), and a long tail of content-safety/malformed-call reasons
  (`SAFETY`, `RECITATION`, `PROHIBITED_CONTENT`, `MALFORMED_FUNCTION_CALL`,
  etc. — all treated as `StreamFailure`). `promptFeedback.blockReason` set
  (the prompt itself was blocked, zero candidates returned) is also a
  `StreamFailure`. Function calls in this legacy stream arrive as a single,
  complete `Part` (verified: `FunctionCall.args` has no delta/fragment
  counterpart in the schema the way Open Responses' `arguments` does), so the
  decoder treats each `functionCall` part as one immediate
  `BlockStart`+`BlockDelta`+`BlockStop` triple rather than an incrementally
  assembled one. `Part.thought: boolean` is a SIBLING field alongside
  `text`, not an alternative union member (fix-round-1 F8 — the original
  decoder folded thought-flagged text into the visible message); a part with
  `thought: true` now opens a dedicated `Thinking` block instead. See "Known
  gap" above for exactly what this mode's test coverage does and does not
  include.

## Auth

`x-goog-api-key: $GEMINI_API_KEY` — confirmed directly from a `curl` code
sample in the `Function` schema's `x-codeSamples` in the fetched OpenAPI JSON,
matching the brief's TOML (`auth = { kind = "header_key", header =
"x-goog-api-key" }`) exactly. No divergence.
