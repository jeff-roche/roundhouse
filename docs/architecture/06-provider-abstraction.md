# Roundhouse Architecture — Provider Abstraction

> The narrow-waist intermediate representation, codec tiers, the `Provider` trait,
> quirk profiles, escape hatches, the capability/pricing dataset, errors and retries,
> credentials, and the testing strategy built for parallel agent authorship. See
> `docs/superpowers/plans/2026-08-27-phase1-vertical-slice.md` (the first two codecs)
> and `docs/superpowers/plans/2026-08-27-phase6-provider-breadth.md` (the remaining
> ~23 provider profiles).

## 9. Provider abstraction

### 9.1 Thesis

1. **The in-memory IR is not the wire format.** The IR is a content-block list in the
   *Anthropic shape* — ordered heterogeneous blocks, `thinking` with an attached
   signature, `tool_result` as a block rather than a role, per-block cache breakpoints —
   because that shape is the only one lossless for the hardest provider. Anthropic→OpenAI
   is a flattening (lossy in known, enumerable ways); the reverse is a widening.
   **Always make the IR the superset; lose information only on the way out.**
2. **Codecs are code; providers are data.** Seven codecs, ~28 declarative profiles. A new
   provider is a TOML file plus a cassette, not a Rust module.
3. **Loss is a first-class, logged event.** Every downgrade (dropped thinking signature,
   dropped `cache_control`, synthesized tool-call id, unsupported `tool_choice`) emits a
   `LossEvent` onto the `infer` task — what makes cross-provider sub-agent spawning
   debuggable instead of mysterious.

### 9.2 Landscape corrections (2026-08-27)

GitHub Models is fully retired (2026-07-30) — dropped from the target list. Gemini's
default surface is now the **Interactions API**, not `generateContent` (legacy but
supported). Bedrock has **three** distinct paths, not one — new Claude models use
`bedrock-mantle.{region}.api.aws/anthropic/v1/messages`, a real Anthropic Messages
endpoint over ordinary SSE, not the binary eventstream Converse API. "OpenAI-compatible"
is now **three** wire formats (Chat, Responses, Anthropic Messages), and most large
providers speak two or three. From GPT-5.4, **OpenAI Chat Completions is a degraded path**
for frontier OpenAI models (no tool calling above `reasoning_effort: none`) — force the
Responses wire instead. An industry-backed schema exists: **Open Responses `2026-04-24`**
(NVIDIA, Vercel, OpenRouter, HuggingFace, Databricks, AWS, OpenAI) — we adopt its *shape*,
not its wire format verbatim, since it lacks cache breakpoints, thinking signatures, and
non-text output content.

### 9.3 The narrow waist

```rust
pub struct ChatRequest {
    pub model: ModelId,
    pub system: Vec<SystemBlock>,          // Vec, not String — cache breakpoints live here
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDef>,
    pub tool_choice: ToolChoice,
    pub params: Params,                    // every field Option; NO builder defaults
    pub reasoning: ReasoningRequest,
    pub response_format: ResponseFormat,
    pub ext: ProviderExt,                  // typed, closed extension slot — §9.6
    pub extra: BTreeMap<String, Value>,    // raw passthrough, gated
    pub policy: RequestPolicy,             // Error | Drop | Downgrade on unsupported
}

pub enum ContentBlock {
    Text     { text: String, cache: Option<CacheBreakpoint>, citations: Vec<Citation> },
    Image    { source: MediaSource, cache: Option<CacheBreakpoint> },
    Document { source: MediaSource, title: Option<String>, cache: Option<CacheBreakpoint> },
    ToolUse  { id: ToolCallId, id_origin: IdOrigin, name: SmolStr, input: Value,
               cache: Option<CacheBreakpoint> },
    ToolResult { tool_use_id: ToolCallId, content: Vec<ToolResultPart>, is_error: bool,
                 cache: Option<CacheBreakpoint> },
    Thinking { text: String, signature: Option<Signature>, redacted: bool },
    /// Round-trips verbatim to the SAME (provider, model); dropped with a
    /// LossEvent on cross-provider handoff.
    Opaque   { provider: ProviderId, kind: SmolStr, raw: Box<RawValue> },
}
```

**`Signature` absence is the normal case, not exceptional.** No third-party Anthropic
emulator reproduces round-trippable thinking signatures; `Option<Signature>` is cheap and
correct off first-party Anthropic/Bedrock/Vertex. `IdOrigin::Synthesized` covers Ollama,
which emits no tool-call id at all — we mint a deterministic one and strip it back out on
re-encode to Ollama, keeping it in the log so the agent loop's dispatch has a stable key.

**Cache-breakpoint placement is owned by context assembly (`roundhouse-agent`), not the
provider layer, and it's automatic.** The agent loop already renders every request in a
fixed, deterministic order (§15.4: system prompt → tool definitions → memory →
compaction summary/retained-window boundary → current turn), and each layer is
progressively less stable than the one before — exactly the signal placement needs.
Context assembly places a breakpoint right after each stability boundary automatically,
up to whatever `CacheSupport::max_breakpoints` a provider's profile declares (§9.5),
dropping the least-stable boundary first if a provider supports fewer. (Anthropic's own
4-breakpoint cap lines up almost exactly with these four natural layers.) No new config
surface for the common case; an advanced override just sets the existing per-block
`cache: Option<CacheBreakpoint>` field directly — nothing new to build for that either.

**Usage normalization (the #1 source of silent cost bugs):** `input_tokens` is always
*total tokens presented, including cache reads*. OpenAI-family `prompt_tokens` already
includes `cached_tokens`; Anthropic's `input_tokens` **excludes**
`cache_read_input_tokens` — the Anthropic decoder adds them back. One invariant checked in
the conformance suite: `input_tokens >= cache_read_tokens`. Four wire shapes
(flat/nested/hit-miss-pair/Anthropic-split), one decoded `Usage` struct, one
`UsageDecoder` recorded per task for audit.

**Streaming is the only path — there is no non-streaming method.** A completion is
`fold(stream)`; adapters over unary transports synthesize the event sequence. Delta
reassembly is normalized behind a `DeltaKeyer` that maps each provider's native key
(OpenAI's per-tool-call index, Anthropic's content-block index, Responses' `item_id`,
Gemini's positional-no-key parts, Ollama's whole-value-no-key) onto one `index: u32` the
core sees. Normative rules the conformance suite checks on every adapter: structure is
always synthesized (`BlockStart` before `BlockDelta` before `BlockStop`); tool-argument
JSON fragments are concatenated and **parsed exactly once at `BlockStop`, never
incrementally**; an empty argument buffer yields `{}`, not an error; tool identity settles
at stop, synthesizing an id if none arrived; thinking signatures may attach after the text
and are held until stop; usage is last-write-wins per field unless flagged cumulative;
block order is arrival order and is never reordered — positional signature contracts
(Gemini) depend on this holding exactly.

### 9.4 The `Provider` trait and adapter tiers

```rust
pub trait Provider: Send + Sync + 'static {
    fn capabilities(&self, model: &ModelId) -> Capabilities;
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError>; // pure
    fn stream_chat<'a>(&'a self, req: &'a ChatRequest, ctx: &'a RequestCtx)
        -> BoxFut<'a, Result<ChatStream, ProviderError>>;
    fn count_tokens<'a>(&'a self, req: &'a ChatRequest, ctx: &'a RequestCtx)
        -> BoxFut<'a, Result<TokenCount, ProviderError>>;
    fn list_models<'a>(&'a self, ctx: &'a RequestCtx)
        -> BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> { /* default: Unsupported */ }
}
```

Boxed futures, not `async_trait` — the registry is `HashMap<ProviderId, Arc<dyn
Provider>>` and retry/fallback middleware are decorators over it, so object safety is
non-negotiable. **The streaming-retry rule**: a stream may be transparently retried only
before the first token reaches the caller; once a token has been observed, a transport
failure surfaces as `StreamInterrupted { partial }` and the *agent loop* decides —
resuming means re-sending a prefix, which changes billing and discards reasoning-model
state that cannot be reconstructed.

**Four core codecs, not twenty-five** — 80% of models.dev's 203 providers already run on
one OpenAI-compatible adapter, corroborated empirically:

| Codec | Providers |
|---|---|
| `openai-chat` | OpenRouter, Together, Fireworks, Groq, Cerebras, Mistral, DeepSeek, Moonshot/Kimi, Z.ai, Qwen (compat mode), xAI, LM Studio, vLLM/SGLang/llama.cpp, Ollama `/v1`, Azure OpenAI, NVIDIA NIM, DeepInfra, … |
| `anthropic-messages` | Anthropic first-party, Bedrock (new Claude models), Vertex Anthropic, Microsoft Foundry, Qwen/OpenRouter/DeepInfra Anthropic-compat |
| `openai-responses` (Open Responses) | OpenAI first-party, NVIDIA, Vercel, OpenRouter, HuggingFace, Databricks, AWS |
| `google-genai` | Gemini Interactions API (default), `generateContent` (legacy), Vertex Gemini |

**Bespoke:** `bedrock-converse` (legacy non-Claude Bedrock only — binary eventstream +
SigV4; shrinking in relevance as Claude models move to real Messages), `cohere-v2`,
`ollama-native` (only if Ollama-specific features are needed beyond its OpenAI shim).
**Real count: 7 codecs, ~28 profiles, 2 transport shims** (`sigv4-eventstream`,
`azure-deployment-routing`) — roughly 3,500–4,500 lines of adapter code total, ~60% in
the first two codecs. Endpoint preference is per-model and ordered in the profile, which
is how "Chat Completions degraded for frontier OpenAI" becomes data (`[responses, chat]`
with `chat` marked `degraded`) instead of a hardcoded branch.

**`openai-responses` is a working assumption, gated before it's actually built.** The
design followed the documented *shape* of Open Responses `2026-04-24` and OpenAI's own
public Responses API (which does use `item_id`-keyed streaming deltas), not a
line-by-line read of the published OpenAPI spec — not on Phase 1's critical path
(`openai-chat`/`anthropic-messages` cover the priority cases, §13.2), so there's room to
verify before it's needed. **Gate:** before this adapter is written, an agent reads the
real spec (`github.com/openresponses/openresponses`) and produces the 16-case golden
corpus (§9.10) against the verified spec. If it diverges from what's assumed here, the
blast radius is contained to this one codec's encode/decode — the narrow-waist IR (§9.3)
is deliberately a superset abstracted away from any single wire format precisely so a
surprise in one codec never ripples into the core types everything else depends on.

**`google-genai` is one codec with an internal `EndpointMode::{Interactions,
GenerateContent}` switch, not two codecs — same gating pattern as above.** Gemini's two
surfaces differ in envelope and statefulness (session/state via `previous_interaction_id`,
`background=true`) — the part vendors churn often — not, by working assumption, in the
underlying content representation (`contents[].parts[]`, `functionCall`,
`thoughtSignature`), which is far more expensive for a vendor to change since it's what
the model itself was trained to speak. Content-block encode/decode is shared between
modes; only envelope handling branches. If verification specifically finds the content
model itself diverged (not just the envelope), splitting into two codecs is a mechanical,
localized refactor — contained to this one provider family by the same superset-IR
design.

### 9.5 The quirk profile

TOML, one file per provider, `build.rs`-deserialized so a typo is a build error, not a
production 400. The correctness case:

```toml
id = "moonshot"
codec = "openai-chat"
[defaults]
allow_raw_extra = false                        # hard-errors on unknown fields
params = { mode = "allow_only", fields = ["max_output_tokens", "stop"] }  # NOT temperature/top_p/n/…

[[model]]
match = ["kimi-k3*"]
reasoning = { kind = "effort", field = "/reasoning_effort",
              vocabulary = ["none", "low", "medium", "high"],
              map = { off = "none", low = "low", medium = "medium", high = "high", max = "high" } }

[errors]
"engine_overloaded_error"      = { disposition = "retry_backoff" }
"rate_limit_reached_error"     = { disposition = "shed_concurrency" }
"exceeded_current_quota_error" = { disposition = "fatal", category = "quota" }   # billing — never retry
```

`ReasoningControl` is a **closed enum keyed by (provider, model)**, not two `Option`s —
Kimi k3 takes only `reasoning_effort`, k2.x takes only `thinking{budget_tokens}`, sending
the wrong one is a 400, and the effort vocabulary itself varies by model even within one
provider (glm-5.3: 3 values; glm-5.2: 7). A caller-facing ordinal `Intent` (`Off | Low |
Medium | High | Max`) plus a per-profile `map` is what makes that divergence a data change
instead of an `if provider == "moonshot"`.

### 9.6 Escape hatches

**Rule:** a feature is core if (a) ≥2 independent providers expose it and (b) the agent
loop must reason about it to be correct; otherwise it is an extension. Tool calling,
caching, thinking, images: core. `previous_response_id`, Bedrock guardrail ids, Ollama
`keep_alive`: extension. Three mechanisms, in order of preference: a **closed typed
extension enum** (`ProviderExt`, one variant per family, exhaustively matched so a new
variant can't be silently ignored); **raw passthrough** (`extra` map, merged last, only
when the profile allows it, and colliding with a codec-owned key is an error, never a
silent overwrite); and **opaque blocks + signatures** for provider-native content that
round-trips within a provider and is explicitly `LossEvent`-logged on cross-provider
handoff via a mandatory `sanitize_for(target)` pass.

**Cross-provider thinking-signature handoff defaults to drop-and-log, not refuse.**
"Handoff" here specifically means seeding a newly-spawned sub-agent's initial context on
a different provider (§7) — the parent's own ongoing conversation with Anthropic is
unaffected and keeps its signatures intact. Dropping is safe because Anthropic's
"echo byte-identically" constraint is specific to continuing *with* Anthropic and simply
doesn't apply once handing off elsewhere, and because the information a new provider
actually needs to proceed sensibly — the concrete `tool_use`/`tool_result` history —
stays fully intact; only the private reasoning trace is dropped. Refusing outright would
undermine cross-provider sub-agent spawning (a core differentiator) for a soft
reasoning-quality concern rather than a hard correctness one, so `LossEvent` visibility
is the right-sized intervention. **The stricter behaviour a demanding tool-heavy
workflow might want already exists with no new mechanism**: `ChatRequest.policy:
RequestPolicy` (§9.3) has an `Error` variant alongside the default `Drop` — set it
per-request to hard-fail on signature loss instead of silently degrading.

### 9.7 Capability & pricing dataset

**models.dev as primary** (provider-scoped, matches our `(provider, model)` key,
7,351 model entries, MIT), **LiteLLM's `model_prices_and_context_window.json` as a
pricing-only secondary** — kept for long-tail aggregator/reseller cache-rate coverage,
**not** the frontier-model cache-cost case originally assumed here. Measured
(Phase 6 Task 9, fix rounds 1-2, against the live files): even after id-normalizing
the four providers where prompt caching dominates cost (anthropic, openai, google,
amazon-bedrock — reconciliation 0/213 → 199/213), LiteLLM supplies a cache rate
models.dev lacks for only 42 of 7,056 priced models (0.6%), 5 of them from those four
providers; anthropic alone contributes zero net-new despite 14/14 reconciled.
models.dev already carries cache rates for the frontier providers on its own. Per-token
not per-million — unit mismatch is a real bug source, normalized to `PicoUsdPerToken(u64)`
on ingest. **Vendor at build time** (`include_bytes!`, parsed lazily, ~2MB compressed) as
the source of truth; a weekly CI job refreshes and opens a **human-reviewable PR** — model
pricing changes should be reviewed, not silently pulled. Runtime refresh is opt-in and
never blocks a request. Unknown models degrade **explicitly**: unknown context disables
local truncation entirely (guessing 128k and truncating a 1M-context model is worse than a
clean provider 400); unknown pricing yields `Cost::Unknown` with tokens still recorded —
because **cost is a derived view over `(usage, pricing_snapshot_id)`, never a stored
column**, historical tasks are backfillable when pricing lands later.

**Dataset licensing is gated, not resolved by discussion.** Prior research flagged both
as believed-MIT with one caveat: LiteLLM's `model_prices_and_context_window.json` carries
no license header of its own, inherited only by repo-level license — confirm this holds
before vendoring, not something reasoning can settle. **Gate:** a license check runs
before Phase 6 (provider breadth) starts, since that's the first phase that actually
depends on the vendored snapshot; if either source turns out unsuitable, the fallback is
narrower — vendor only per-provider public pricing pages directly, at the cost of losing
the cross-provider dataset's convenience, not the correctness of any cost calculation.

### 9.8 Errors & retries

Classification order: **provider error code** (from the profile's `[errors]` table) →
**message regex** (profile-supplied fallback) → **HTTP status default**. Never `?` on
JSON parsing in the error path — a provider outage must not become a decode panic; bodies
may be raw HTML (Moonshot's 900s 504) or truncated.

| Category | Disposition |
|---|---|
| Overloaded (capacity, not your fault) | Retry with full-jitter backoff |
| Rate-limited (your request rate) | **Shed concurrency** (halve the per-`(provider,model)` semaphore) then retry |
| Quota exhausted (billing) | **Fatal — never retry.** Retrying burns time and cannot succeed |
| 5xx / timeout | Retry, capped attempts, bounded by the caller's deadline not just attempt count |
| 400 (shape rejected) | Fatal — never retry a request the server rejected on shape |
| 404 model | Fallback to next provider in chain |

A per-`(provider, model)` circuit breaker opens after 5 consecutive overloaded/5xx within
30s and half-opens after 10s. **No proactive rate-limit budgeting** — most of the fleet
(Bedrock, Gemini, Cerebras, Mistral, Moonshot, Z.ai, Qwen) publishes no `x-ratelimit-*`
headers at all, and Microsoft Foundry actively strips Anthropic's; concurrency is an
adaptive AIMD semaphore driven by shed-concurrency dispositions instead. **Dedup on
streaming retry is ours, not the provider's**: each attempt is its own row keyed by
`(task_id, attempt_no, request_fingerprint)`; at most one attempt reaches `Committed`;
cost sums across *all* attempts since the provider bills every one it processed.

### 9.9 Credentials

One `CredentialProvider` trait behind bearer/header-key/OAuth-refresh (single-flight,
60s skew)/SigV4/Azure-Entra/exec-command implementations. Base URL resolves as: explicit
override → `ROUNDHOUSE_<PROVIDER>_BASE_URL` env → profile default; an override is recorded on
the task as **host only**, never a full URL with query string (some gateways put keys in
query params). Keys stay out of the log by construction: a `Secret<String>` newtype with
no `Serialize` impl and exactly four `expose()` call sites enforced by a grep-based test;
header capture for the log is **allow-list only**; a final redaction pass regexes every
persisted error body for API-key-shaped strings, bearer tokens, and JWTs, because
providers echo request bodies in 400s more often than you'd like.

**Sub-agent credential scoping resolves via §6.1's rule: credentials are never inherited
or copied — a child resolves its own, and only for a provider it was explicitly
authorized to use.** A credential is a *capability* (it lets an agent spend money and
consume rate-limit budget), so it follows the "never automatic" half of the spawn-boundary
rule, not the "flows down freely" half. Concretely: `agent_spawn`'s `provider` field
(§7.6) is already the explicit grant — there is no separate mechanism to design. What was
missing is the enforcement rule, now added: the `agent` task's `TaskParams::Agent{
provider, model, tier_request }` (§6.2) is evaluated by the *parent's own* policy scope
before the child is created, so a workspace authorized only for Anthropic and local
providers cannot have a sub-agent anywhere in its tree spawn against OpenRouter — policy
narrows only, never widens, at every level of nesting (§6.2's precedence rule, applied
transitively). Once authorized, the child calls the same daemon-side credential
resolution chain (keyring → env → profile default) independently; it never receives the
parent's in-memory `Secret` handle. What *is* visible to a child automatically — the
"read" half — is the capability query of which providers are configured at all (via the
same mechanism `list_models`/`peers` already expose), so a model can reason about what it
*could* ask to be authorized for without ever holding the material itself.

### 9.10 Testing strategy — built for parallel agent authorship

Everything rests on one seam, `HttpTransport`, injected via `RequestCtx` — no adapter ever
constructs a `reqwest::Client` directly, so tests inject a `CassetteTransport`.

1. **Golden codec snapshots** — `encode`/`decode` are pure functions; a frozen 16-case
   corpus (multi-turn, cache breakpoints, forced tool choice, parallel tools, reasoning
   on/off, unicode, a temperature-forbidden model, …) produces `insta` snapshots checked
   into the repo. **This is the single highest-leverage artifact for reviewing an
   agent-written adapter** — a human diffs the exact JSON a provider will receive.
2. **Cassettes** — raw SSE bytes verbatim (including malformed keepalive comments and
   multi-byte UTF-8 split across chunk boundaries), replayed at adversarial byte-boundary
   chunking (1 byte, 3 bytes, prime-sized, whole-body) to catch frame-splitting bugs.
3. **Conformance suite as a library** — every adapter's test file is ~10 lines calling
   `roundhouse_conformance::run::<Adapter>()`, which checks stream/non-stream equivalence, fold
   determinism under re-chunking, round-trip fidelity modulo declared `LossEvent`s, a
   **generic property test that no field outside the resolved `serialize_only` mask ever
   appears in the encoded body** (the Kimi regression test, free for every adapter), and
   usage invariants.
4. **Live smoke** — six assertions against a real key, never in CI, run once before a
   profile is promoted from `experimental` to `supported`.

**Definition of done for a parallel adapter agent**, made explicit so it can be handed to
one agent per provider with no ambiguity: profile TOML deserializes; ≥16 golden snapshots
committed and non-empty; ≥6 cassettes (text, tools, parallel tools, reasoning, error-429,
error-500); `conformance().assert_green()`; zero `todo!()`/`unimplemented!()`; every
`Unsupported` return is justified by a profile field. CI gates on all of this plus "every
profile has ≥1 cassette."

### 9.11 Open questions

~~Open Responses field verification.~~ **Gated, not resolved by discussion (§9.4):**
verify against the real spec before the adapter is written, not before Phase 1; a
surprise is contained to this one codec's encode/decode, never the core IR.

~~Is `google-genai` one codec or two?~~ **Decided (§9.4): one, with an internal
`EndpointMode` switch, gated the same way as #16** — content representation is stickier
than envelope, so shared decode logic is the working bet; split only if verification
proves the content model itself diverged.

~~Thinking-signature handoff: refuse or drop-and-log?~~ **Decided (§9.6): drop-and-log by
default.** The Anthropic byte-identical-echo constraint doesn't apply once handing off
elsewhere, and the information a new provider needs (tool history) stays intact. The
stricter behaviour already exists with zero new mechanism — `RequestPolicy::Error`.

~~Cache-breakpoint placement policy.~~ **Decided (§9.3): owned by context assembly,
automatic, derived from the same deterministic render order already established for
memory (§15.4)** — one breakpoint per stability layer, no new config surface.

~~Dataset licensing.~~ **Gated, not decided by discussion (§9.7):** both believed MIT,
with LiteLLM's pricing file specifically flagged (no license header of its own,
inherited only via the repo). Check runs before Phase 6 starts; fallback if either turns
out unsuitable is narrower vendoring of per-provider pricing pages directly.

*(All of §9's open questions are now resolved.)*

~~Sub-agent credential scoping.~~ **Resolved (§6.1, §9.9):** never inherited or copied —
a child independently resolves its own credentials, gated by the parent's own policy
scope narrowing the set of providers it may even request.



