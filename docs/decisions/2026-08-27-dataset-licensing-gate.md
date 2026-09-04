# Dataset licensing gate — models.dev + LiteLLM pricing (§9.7)

Blocking pre-task for Phase 6 (Provider Breadth). Task 9 (dataset ingestion) may not
begin until this record states a verdict for both sources.

MODELS_DEV_LICENSE: MIT
LITELLM_LICENSE: MIT (repo-level, applies to the file in question; enterprise/ carves out a separate license but model_prices_and_context_window.json is not under enterprise/, and it has no header of its own)
FALLBACK_ACTIVE: false

## Findings

- **Canonical repo is not `sst/models.dev`.** The plan's probe URL
  `https://raw.githubusercontent.com/sst/models.dev/main/LICENSE` 404s because the
  org has moved. `curl -sI https://github.com/sst/models.dev` returns `301` to
  `https://github.com/anomalyco/models.dev`. `curl -s
  https://api.github.com/repos/anomalyco/models.dev` confirms this is the live repo
  (description: "An open-source database of AI models."), default branch `dev`.

- **models.dev license.** `curl -s
  https://api.github.com/repos/anomalyco/models.dev/license` returns a `license`
  object with `"spdx_id": "MIT"`, pointing at
  `https://raw.githubusercontent.com/anomalyco/models.dev/dev/LICENSE`. Fetching
  that URL directly returns the standard MIT license text, copyright "models.dev",
  2025. No caveats, no carve-outs.

- **models.dev dataset vs. code licensing.** `curl -s
  https://api.github.com/repos/anomalyco/models.dev/contents/` lists the repo root:
  the model data lives in-repo as TOML files under `models/` (33 provider
  directories) and `providers/` (213 provider directories, each with a
  `provider.toml` and a `models/*.toml` per model), plus a generated
  `models.json` at the root. Fetched a sample model file directly
  (`curl -s
  https://raw.githubusercontent.com/anomalyco/models.dev/dev/providers/openai/models/gpt-4.1-mini.toml`)
  and the provider file
  (`.../providers/openai/provider.toml`) — neither carries a license header,
  SPDX tag, or reference to a separate license. No `LICENSE`, `LICENSE-DATA`, or
  similarly named file exists anywhere but the repo root (checked root listing and
  the `models/`, `providers/openai/`, and `providers/openai/models/` directory
  listings via the GitHub contents API). The repo's own README
  (`curl -s https://raw.githubusercontent.com/anomalyco/models.dev/dev/README.md`)
  describes the data as generated from these same in-repo TOML files with no
  mention of a separate data license. Conclusion: the dataset is **not** separately
  licensed from the code — both are covered by the single root MIT `LICENSE` file.
  (As a scale sanity check: `https://models.dev/api.json`, fetched live, sums to
  7,493 models across 212 providers — the same dataset the plan estimated at
  "~7,351 entries"; the small difference is just dataset growth since the plan was
  written, not a different dataset.)

- **LiteLLM repository license.** `curl -s
  https://raw.githubusercontent.com/BerriAI/litellm/main/LICENSE` returns 200. The
  file states: *"All content that resides under the `enterprise/` directory of
  this repository ... is licensed under the license defined in
  `enterprise/LICENSE`. Content outside of the above mentioned directories ... is
  available under the MIT license as defined below,"* followed by the standard MIT
  license text (Copyright (c) 2023 Berri AI). So LiteLLM is MIT **outside**
  `enterprise/`, with a separate (unexamined, and irrelevant here) license inside
  it.

- **Path of `model_prices_and_context_window.json`.** Confirmed by direct fetch
  that the file lives at the **repository root**, not under `enterprise/`:
  `curl -sI https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json`
  returns `200`, while both
  `curl -sI https://raw.githubusercontent.com/BerriAI/litellm/main/litellm/model_prices_and_context_window.json`
  and an `enterprise/`-prefixed guess return `404`/non-existent. Being at repo
  root, outside `enterprise/`, it falls under the MIT-licensed portion of the
  repo.

- **`model_prices_and_context_window.json` header check.** Fetched the raw file
  (`curl -s
  https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json`)
  and inspected the first ~200 lines directly (a `sample_spec` documentation
  block, then real entries starting with
  `"1024-x-1024/50-steps/bedrock/amazon.n..."`). `grep -i -E
  "license|copyright|spdx"` over those lines returns no match. The file is plain
  JSON with no comments, no SPDX tag, and no embedded license/copyright text of
  any kind — this is confirmed by inspecting the raw file directly, not inferred.
  This is the exact caveat §9.7 flagged as unconfirmed; it is now confirmed: the
  file carries no license header of its own and is covered solely by the
  repo-level LICENSE, which — for this file's path — is MIT.

## Fallback plan

Not activated. Both sources are confirmed MIT for the material Phase 6 needs
(models.dev's full TOML-backed dataset, and LiteLLM's root-level
`model_prices_and_context_window.json`). If a future re-check finds either
license changed, was misidentified, or that LiteLLM's `enterprise/` boundary
moved to cover the pricing file, the fallback is: stop vendoring the
cross-provider dataset via `include_bytes!` entirely, and instead vendor only
per-provider public pricing pages directly (e.g. openai.com/api/pricing,
anthropic.com/pricing) as small, per-provider TOML/JSON fixtures checked in next
to that provider's quirk profile (§9.5). This loses the cross-provider dataset's
convenience (one ingest, ~28 providers covered) but not the correctness of any
individual cost calculation — `Cost::Unknown` still applies to anything not
covered by a vendored page.

## Follow-up: measured LiteLLM contribution (Task 9, fix rounds 1-2)

This record's licensing verdict stands unchanged (both sources MIT,
`FALLBACK_ACTIVE: false`). This note corrects the *rationale* text carried in
`docs/architecture/06-provider-abstraction.md` §9.7 and
`crates/roundhouse-provider/src/pricing/litellm.rs`'s module doc, which
originally justified vendoring LiteLLM as a secondary source because it is
"better on cache-write/per-image cost corner cases" — a claim that was never
measured against the live data until code review asked for it.

**Measured, against the live-fetched files:** of 7,056 priced models.dev
models and 3,518 LiteLLM entries, only 332 (4.7%) reconcile by exact
`"<provider>/<model>"` id match, and LiteLLM supplies a cache rate models.dev
lacks (the actual "corner case" value-add) for just 37 of them (0.5%). The
frontier providers where prompt caching is the dominant real-world cost
pattern — the entire stated motivation — reconciled at **zero** under an
exact-match lookup: anthropic 0/14, openai 0/43, google 0/33,
amazon-bedrock 0/123.

Fix round 2 added minimal bare-id normalization for exactly those four
providers (LiteLLM's real key convention for them is the bare upstream model
name, not models.dev's id shape). Reconciliation jumped to 199/213, but
**net-new cache coverage rose only 5 models** — anthropic +0/14, openai
+2/43, google +2/33, amazon-bedrock +1/123 — for a global total of 42/7,056
(0.6%).

**Conclusion: the merge is kept, but the reason is coverage of long-tail
aggregators/resellers, not the frontier-model cache-cost case originally
assumed.** models.dev already carries cache rates for the frontier providers
on its own; LiteLLM's measured contribution there is negligible even after
fixing the id mismatch that could have been masking a real signal. The merge
stays because it is real, tested, and hardened (a plausibility ceiling on
rates, parse validation before vendoring, and a CI test that force-evaluates
the parsed snapshot) — not because the original per-provider rationale held
up under measurement.
