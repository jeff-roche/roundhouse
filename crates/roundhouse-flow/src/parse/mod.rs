//! YAML parsing of the top-level workflow definition (§8.9). Untrusted
//! input: this module's job is to turn workflow-author-supplied YAML text
//! into a typed [`WorkflowDef`] that fails closed on anything it doesn't
//! recognise. Anchor/alias expansion — the one resource a small hostile
//! document could previously make the parser spend without limit — is
//! bounded by [`MAX_EXPANDED_WEIGHT`]; read the history section below,
//! including the paragraph on what that bound does *not* cover, before
//! wiring this to anything that accepts untrusted YAML.
//!
//! Step bodies are typed by [`steps`] (`StepDef`, `StepBody`,
//! `steps::parse_step`), which this module hands each `WorkflowDef.steps` /
//! `.catch` / `.finally` entry to individually — `WorkflowDef` itself keeps
//! `steps`/`catch`/`finally` as raw `serde_yaml::Value` (see its doc
//! comment), so a caller who wants typed steps calls `steps::parse_step` on
//! each entry, and `steps::topological_order` to get a `needs:`-respecting
//! run order.
//!
//! # CLOSED (Task X1): the anchor/alias fan-out denial of service
//!
//! Kept as history rather than deleted, because three fix rounds on this
//! module each shipped a claim that parse cost *was* bounded and each was
//! falsified by measurement. What follows is what the attack was, what
//! bounds it now, and — stated as plainly as the rest — what that bound
//! still does not cover.
//!
//! **The attack.** An anchor/alias fan-out: one large anchored leaf
//! collection, then a handful of levels that each alias the previous level
//! a few times. All brackets are balanced, nesting is one level deep, there
//! is no oversized field and no deep recursion — so none of this module's
//! shape-based checks looked at it at all.
//!
//! **What it cost, measured release-build through the real
//! `parse_workflow`** (leaf list of `n` plain scalars, fan 4, levels tuned
//! to sit just under `serde_yaml`'s own repetition limit):
//!
//! | document size | parse cost |
//! |---|---|
//! | 2,268 B | 137 ms |
//! | 2,300 B | 537 ms |
//! | 2,332 B | 2.1 s |
//! | 2,364 B | 8.1 s |
//! | 4,396 B | 33.9 s |
//!
//! An independent security review measured the same class of payload at
//! 821 B → 489 ms, 1,525 B → 2.4 s, 2,229 B → 3.8 s, 5,749 B → 9.5 s and
//! 32,768 B → **287.8 s**.
//!
//! **The finding was worse than CPU, which the original write-up missed.**
//! Task X1 measured the same family's memory, in a child process under a
//! 2 GiB `ulimit -v` so it could not take the host down: 2,268 B → 141 MB,
//! 2,300 B → 555 MB, and 2,332 B → **allocation failure, exceeding a 2 GiB
//! address space**. Uncapped, this family was twice observed by the kernel
//! OOM killer at ~35 GiB resident while this very task was being measured.
//! A document that OOMs a host is a materially worse finding than one that
//! spins a core, and the earlier write-up above — CPU only — understated it.
//!
//! **Why no byte cap closes it.** The 2,229-byte review payload is *smaller
//! than the frozen §8.9 fixture* (2,271 B), so there is no cap that admits
//! legitimate workflows and excludes the attack. `serde_yaml` 0.9.34's
//! alias guard is `jumpcount > events.len() * 100`
//! (`serde_yaml-0.9.34/src/de.rs:478-480`) — a budget *proportional to the
//! document*, not an absolute one — while the cost of each individual jump
//! is itself proportional to the subtree that jump expands, so raising
//! [`MAX_YAML_BYTES`] raised the attacker's jump budget and the price of
//! spending each unit of it at once. Underneath that guard the raw
//! expansion is exponential: measured with the metered walk (which
//! allocates nothing, so this is safe to run), the same family visits
//! 5,026 → 21,048 → 85,134 → 341,476 → 1,366,842 → 5,468,304 nodes as the
//! document grows 2,140 → 2,300 bytes, i.e. ×4 per 32 bytes of source.
//!
//! **What bounds it now: [`MAX_EXPANDED_WEIGHT`], enforced by
//! `expansion::check_expansion` before `serde_yaml::from_str` is called.**
//! The check walks the document with the real deserializer under a visitor
//! that produces only a running weight — a per-node constant plus each
//! scalar's own length — and aborts the walk, and with it the demand-driven
//! expansion the walk is driving, the moment the total passes the ceiling.
//! It does not predict the expansion; it incurs it under a meter and stops.
//! Its unit is the quantity that materializes rather than a proxy for it,
//! which is what the withdrawn `MAX_ALIAS_TOKENS` guard was not — and what
//! this check's own first unit, a plain node count, also was not: see the
//! second attack below. Read `src/parse/expansion.rs`'s module doc for the
//! mechanism, what the weight does and does not imply about memory, and
//! what a change in `serde_yaml`'s internals would break.
//!
//! Re-measured at **fix round 3** (captions name the round: with three
//! fixes, "after the fix" is ambiguous), release build, through the real
//! `parse_workflow` — every payload from both tables above, plus a
//! 260,364-byte member at the byte cap:
//!
//! | document | before | after (release) |
//! |---|---|---|
//! | 706 B fan-out | 123 ms | rejected in 13.5 ms |
//! | 2,268 B fan-out | 137 ms | rejected in 8.7 ms |
//! | 2,332 B fan-out | 2.1 s | rejected in 8.7 ms |
//! | 2,364 B fan-out | 8.1 s | rejected in 8.7 ms |
//! | 4,396 B fan-out | 33.9 s | rejected in 8.8 ms |
//! | 32,764 B fan-out | 287.8 s (review) | rejected in 10.7 ms |
//! | 260,364 B fan-out | not previously measured | rejected in 24.5 ms |
//! | 2,388 B tag-wrapped fan-out | not previously measured | rejected in 8.7 ms |
//!
//! Debug builds — what `cargo test` produces — run 3.8-216.4 ms across the
//! full payload set. Process peak resident memory for the whole rejection
//! sweep was 22 MB, against the ~35 GiB this family reached unbounded.
//!
//! ## The second attack: one large anchored scalar, aliased many times
//!
//! Found by a security review of the *first* fix, and the reason
//! [`MAX_EXPANDED_WEIGHT`] weighs bytes rather than counting nodes. That
//! first version charged one unit per node and discarded each scalar's
//! length, so a single node could carry an arbitrarily large aliased
//! payload. Aliasing an `L`-byte anchored scalar `K` times in a **flat**
//! sequence cost `K` at the meter while materializing `K x L` bytes for
//! real — and a flat sequence keeps alias jumps proportional to events, so
//! `serde_yaml`'s repetition guard never fires either. Measured against
//! that version: a **180,138-byte document was admitted** and drove the real
//! parse to **4,593 MB** resident; a 260,210-byte one hit allocation failure
//! past a 2 GiB address space.
//!
//! | document | before (node-count unit) | after (byte-weight unit, fix round 3) |
//! |---|---|---|
//! | 180,104 B, `K`=40,000 `L`=60,000 | admitted, 4,593 MB resident | rejected in 3.9 ms |
//! | 126,104 B, `K`=2,000 `L`=120,000 | admitted | rejected in 1.1 ms |
//! | 346,182 B, `K`=43,000 `L`=131,072 | admitted, allocation failure >2 GiB | rejected by [`MAX_YAML_BYTES`] |
//!
//! The lesson generalises past this module: **a meter whose unit omits an
//! axis of the cost cannot bound that axis**, however faithfully it tracks
//! the axes it does charge. Node count tracked CPU well and memory not at
//! all.
//!
//! # The axis inventory
//!
//! Three rounds of this bound each shipped an unbounded axis: node count
//! omitted materialized memory, byte weight omitted the source length of
//! non-string scalars, and a digit-run source scan (since deleted) omitted
//! the core-tag route.
//! A fourth round then had to correct a row that said *unbounded* when it
//! was closable. All four were found by asking "is it bounded?", a question
//! with no falsifiable negative. This table replaces that question. Every
//! row is attackable on its own, and **a missing row is the defect this
//! exists to prevent** — so the rows worth reading hardest are the ones that
//! still say *unbounded*, and the next-hardest is any row that recently
//! stopped saying it. **A fifth round then had to change a row back**: the
//! non-string-scalar row claimed [`MAX_INTEGER_SCALAR_VISITS`] bounded the
//! integer half when it bounds only the count of decodes. So both directions
//! of error have now happened here, which is why "what bounds it" is a column
//! and not a sentence.
//!
//! All figures release build, end to end through [`parse_workflow`], one
//! document per child process under a `ulimit -v` ceiling so each peak is
//! attributable to one payload — 8 GiB for the fix-round-5 figures, 16 GiB
//! for fix round 6's.
//!
//! | cost axis | what bounds it | ceiling | measured worst | measured how |
//! |---|---|---|---|---|
//! | **Expansion CPU** — walking and re-walking aliased subtrees | [`MAX_EXPANDED_WEIGHT`], enforced during the walk that incurs it — but what it bounds is the *number of nodes walked*, not the work each node costs (`expansion::check_expansion`'s doc) | 2,621,440 | 24.5 ms to reject a 260,364 B fan-out at the byte cap; **9,435.7 ms admitted** for the integer maximiser of the row below, which is the worst admitted document found. (Fix round 5 published 1,603.3 ms here from the *float* maximiser. That is a real float figure, but round 5's tuning does not reproduce on today's tree — see [`MAX_FLOAT_SCALAR_VISITS`]' table — and round 6's retuned float maximiser measures 1,519.1 ms. Either way the float axis was never the worst: see the two decode rows) | `parse_workflow` wall clock, one doc per child; the 9,435.7 ms figure under `ulimit -v 16777216` at fix round 6, the 24.5 ms one at fix round 3 |
//! | **Materialized memory** — the `Value` tree the authorized parse builds | same weight budget, via the node budget `ceiling / NODE_WEIGHT_BYTES` = 327,680 | 2,621,440 | **≥101.9 MB** admitted, from a **15,106-byte** document. Worst shape: one-element sequences nested 110 deep, 67 of them, aliased 43x — what caps it is `serde_yaml`'s own ~128 recursion limit, not any constant of ours | `VmHWM`, one doc per child |
//! | **Container allocation** — `Vec`/`IndexMap` capacity slack, ~288 B for a 1-element `Vec` charged 8 | same weight budget; *under-priced*, and the under-pricing compounds with depth | 2,621,440 | same row as above — this is why the memory maximiser is a deep container shape rather than a scalar one | as above |
//! | **Float decode CPU** — `dec2flt` re-scanning a long token on every alias expansion | [`MAX_FLOAT_SCALAR_VISITS`], via a charge at `visit_f64`. Route-independent at the *serde trait* level: `visit_f32` forwards to `visit_f64`, so no float arrival misses the charge even if `serde_yaml` changes width. **The charge caps the count of decodes, not the cost of one** | 5,041 float visits; the count cap and the byte cap together permit 5,041 × [`MAX_YAML_BYTES`] = 1.32 GB of `dec2flt` scanning | **admitted: 1,519.1 ms** (249,582 B exponent maximiser — `!!float` with 245,000 digits in the exponent, aliased 4,970x, tuned just under the ceiling. The count cap is what binds here: this shape makes 4,971 float visits against the 5,041 ceiling, and one notch wider is rejected. Fix round 5 published 1,603.3 ms for the same family at 259,742 B, but *that tuning does not reproduce* — see [`MAX_FLOAT_SCALAR_VISITS`]' table). Same family before the charge: **18,318.9 ms** burned on a 257,442 B document before `serde_yaml`'s own repetition guard stopped it. Rejection *is* the cheap case here: 353–750 ms across four rejected tunings | `parse_workflow` wall clock, one doc per child under `ulimit -v 16777216` |
//! | **Integer decode CPU** — `from_str_radix` re-scanning a long token on every alias expansion | **UNBOUNDED in the cost sense** — [`MAX_YAML_BYTES`] only, and *not* [`MAX_INTEGER_SCALAR_VISITS`]. The charge caps the *count* of integer decodes at 65,536 and prices no part of the per-decode cost, which is O(token). The maximiser spends 43,674 of those 65,536 visits, so **the charge never fires**; what limits the attacker is the byte cap, and the work it admits is quadratic in it (`~B²/12` scanned bytes per walk, and there are two walks). The count cap and the byte cap together permit 65,536 × [`MAX_YAML_BYTES`] = **17.2 GB** of `from_str_radix` scanning — a ceiling in the absence of a bound, not a bound. **This is an ACCEPTED RESIDUAL under ruling P63**, decided by the project owner against the orchestrator's recommendation. It *would* be covered by the same out-of-process `RLIMIT_CPU` remedy named below for the tokenizing row — **recommended, not implemented**: nothing in this workspace applies an `RLIMIT_CPU` to a parse today | none that binds | **admitted: 9,435.7 ms** (re-runs 8,821.4 / 9,312.1 / 9,431.1), 262,143 B, peak RSS 13.5 MB. Shape: one anchored `0x` + 131,019 zeros + `1` integer token aliased 43,673x in a flat flow sequence inside one step. The `0x` prefix is what matters — `serde_yaml`'s radix branches sit *above* its `digits_but_not_number` diversion, so the token decodes successfully instead of being diverted to `visit_str`; see [`expansion::FLOAT_SCALAR_WEIGHT_BYTES`]. **Rejection is NOT the cheap case on this axis**, unlike floats: the same token aliased 18,710x as *top-level steps* costs **3,747.7 ms** before `TooManySteps` fires, because that check runs after both walks | `parse_workflow` wall clock, one doc per child under `ulimit -v 16777216`, with the live constants printed from inside the test binary (P60) |
//! | **`flatten` re-buffering** — `PermissionRuleDefWire` buffering through serde `Content` | weight budget; the re-visit is over an owned buffer, so a constant multiple of already-expanded content | 2,621,440 | 21.4 ms, 14.2 MB (15,298 B document) | as above |
//! | **Alias jump count** | `serde_yaml`'s own `jumpcount > events.len() * 100`, plus the weight budget | library-internal | the billion-laughs payload stops here, 1.2 ms | `parse_workflow` |
//! | **Tokenizing raw text into the event list** | **UNBOUNDED.** [`MAX_YAML_BYTES`] caps the input; [`nesting_depth_bound_violation`] is best-effort and explicitly not a boundary. **It is also what currently hides the worst case** — the shape below is only reachable in practice because that scan happens to reject deep bracket runs, so anyone relaxing [`MAX_FLOW_NESTING_DEPTH`] unblocks it | none | **427 ms and 45.7 MB** for 262,144 bytes of `[`, fed to `serde_yaml` directly with this crate's scan bypassed (51.4 ms at 32 KiB, 207 ms at 128 KiB — roughly linear for *this* shape, the only one measured) | raw `serde_yaml::from_str` |
//! | **Downstream of parsing** — tasks a parsed workflow dispatches | **not this module.** [`crate::caps`] (ruling P47) | n/a | n/a | n/a |
//!
//! The two decode rows and the Expansion CPU row were re-measured at **fix
//! round 6**; the remaining rows carry fix-round-5 figures. The shape a figure
//! was measured against is part of the figure, so every row names one.
//!
//! **Task 14 (lane W5) correction to the Integer decode CPU row above, not
//! re-measured (a full re-measurement of this table is out of scope for a
//! guard-relocation fix round):** that row's cell still says "**recommended,
//! not implemented**: nothing in this workspace applies an `RLIMIT_CPU` to
//! a parse today". That has been false since Task 14's first commits —
//! `round-yaml-parse-helper` is exactly that remedy — and is doubly false
//! now that fix round 1 (ruling W5-20) moved `expansion::check_expansion`
//! into it too. The row's **9,435.7 ms admitted** figure for the
//! 262,143-byte maximiser is pre-Task-14 history, not current behaviour:
//! that document's *typed-deserialize* half alone already needed roughly
//! its own ~9.4 s (the structural-doubling paragraph below), which exceeds
//! `parse::helper::HELPER_CPU_LIMIT` (2 s) by itself, so this specific
//! maximiser is now killed as `ParseError::ExceededParseResourceBound`
//! rather than admitted — confirmed behaviourally, not remeasured for
//! timing, by `tests/bounded_parse_out_of_process.rs`'s
//! `an_admitted_but_expensive_alias_document_is_rejected_by_the_out_of_process_bound`
//! (a smaller but analogous shape, 230,000 zeros / 10,000 aliases). This is
//! a **narrowing**, not a new gap: a pathological document that used to
//! finish admitted, slowly, in the daemon's own process now gets rejected
//! instead. It does not mean the *count* cap
//! ([`MAX_INTEGER_SCALAR_VISITS`]) fires — it still doesn't, for the
//! reasons the row gives — only that wall-clock/CPU cost is no longer the
//! axis nothing bounds.
//!
//! **Round 5's version of these rows had a single "non-string scalar" row
//! covering both floats and integers, and it named
//! [`MAX_INTEGER_SCALAR_VISITS`] as what bounds the integer half.** That was
//! the "wrong what-bounds-it" defect this inventory exists to catch — worse
//! than a missing row, because it tells the next engineer to stop looking. The
//! integer half is bounded by the byte cap and nothing else; the rows are now
//! split so each is attackable on its own.
//!
//! ## The structural doubling, which no in-process meter can see
//!
//! `WorkflowDef.steps` is `Vec<serde_yaml::Value>`, so after the metered
//! walk admits a document, `serde_yaml::from_str` in [`parse_workflow`]
//! **re-walks the whole alias structure through the same callbacks,
//! unmetered**. Every decode the meter counted happens a second time. An
//! admitted document therefore costs roughly twice its metered walk —
//! which is why the admitted figure, not the rejection figure, is the one
//! the rows above report.
//!
//! This is not closable by any meter here, for a reason worth stating
//! plainly: the meter is what *authorises* the second walk. Bounding it
//! needs either a parse that yields typed steps directly (so there is one
//! walk) or the out-of-process remedy below, which bounds the process
//! regardless of how many walks happen inside it.
//!
//! ## The two open rows, and the remedy for both
//!
//! **Fix round 3 published this section with two open rows and said the
//! numeric-decode axis could not be closed in-process. Fix round 5 published
//! it with one, claiming the numeric axis closed. Both were wrong, in
//! opposite directions, and the pair is the most useful thing on this page.**
//! Round 3's error first. Two
//! remedies had been tried and disproved — a source pre-scan
//! (a digit-run source scan, since deleted) and intercepting `serde_yaml`'s
//! dispatch — and "unclosable" was concluded from those two failures. But
//! both were attempts to work out *which route* a long token arrives on,
//! and a third option was available that does not care: **price the
//! callback**. Every route — plain, `!!float`, a verbatim tag, a remapped
//! `%TAG` handle, a percent-encoded suffix, and at least three more
//! spellings — converges on the same five visitor methods. Charging there is
//! route-independent by construction and stays correct for spellings nobody
//! has enumerated. It is five lines; see
//! [`expansion::FLOAT_SCALAR_WEIGHT_BYTES`].
//!
//! The lesson, since this is the fifth entry in this module's history of
//! bounds that looked complete: **"we tried everything" is a claim about a
//! search, and a search has a shape.** Both disproved options were of one
//! shape (identify the route); the option that worked was of another (price
//! the arrival). An inventory row saying "unbounded, nothing in-process can
//! close this" tells the next engineer to stop looking, which is why it is
//! the one kind of row that has to clear a higher bar than the others.
//!
//! **Round 5's error, which is the reason there are two open rows again.**
//! Pricing the callback *does* work, and it capped the *count* of decodes as
//! claimed. What round 5 then wrote — that per-decode work was therefore
//! bounded — does not follow, and the sentence it rested on
//! (`expansion.rs`'s "no integer route performs an O(token) decode that
//! succeeds") was false as a matter of `serde_yaml`'s source. The
//! **integer decode row is open**: see it for the mechanism, the measured
//! 9,435.7 ms admitted document, and ruling **P63**, under which the project
//! owner looked at that number, priced it against shrinking
//! [`MAX_YAML_BYTES`] and [`MAX_TOP_LEVEL_STEPS`], and **accepted it**. It is
//! open in the inventory sense — nothing bounds it but the byte cap — and
//! closed in the decision sense. Do not reopen it by looking for a seventh
//! in-process bound; reopen it, if at all, by revisiting the product question
//! of how large a workflow document may be.
//!
//! **Tokenizing remains genuinely open**, and for a different reason than
//! the one round 3 gave for both: its cost is incurred *before any visitor
//! runs*, so there is no callback to price. There is no analogous third
//! option, and this is stated as the current state of the search rather than
//! as a proof of impossibility.
//!
//! **Recommended remedy for both: parse out of process under `RLIMIT_CPU`**
//! (remedy (B) from the original task). It bounds wall-clock and memory for
//! the whole pipeline regardless of which stage spends them, which is
//! precisely the property an in-process meter cannot have. `roundhouse-sandbox`
//! exists for this confinement. Owner: whoever wires the first production
//! caller, because that is the change that makes any of this reachable —
//! `parse_workflow` still has no caller outside this crate.
//!
//! Interim lever if either needs to be smaller before then: lower
//! [`MAX_YAML_BYTES`]. It is the only input both stages scale with, and the
//! integer row scales with it *quadratically* — the maximiser's work is
//! `~B²/12` per walk — so it is a disproportionately effective lever there.
//! It is also a product limit on how large a workflow file may be, and would
//! need [`MAX_TOP_LEVEL_STEPS`] lowered with it to keep the coherence argument
//! below intact; that pairing is why P63 declined it rather than why it would
//! not work.
//!
//! ## How the axis list was arrived at
//!
//! For the expansion stage it is a closed enumeration of the visitor
//! callbacks `serde_yaml` can invoke, with the source provenance given on
//! [`expansion::FLOAT_SCALAR_WEIGHT_BYTES`], and at the serde trait level
//! rather than only at `serde_yaml`'s dispatch — which is what makes the
//! enumeration's completeness stop mattering for *which callbacks get
//! charged*.
//!
//! **That completeness argument never covered *how much* to charge, and
//! round 5 treated it as if it had.** Knowing that every numeric arrival is
//! priced says nothing about what the arrival cost to produce; that lives in
//! `serde_yaml`'s decoders, not in the callback surface. Round 5 sized the
//! integer charge from a claim about those decoders that was false, and the
//! closed enumeration above did not and could not catch it. The fifth
//! omission was therefore not a missing callback but a missing *factor* in an
//! existing row.
//!
//! **Fix round 2's version of this paragraph claimed the same thing and was
//! wrong, in the most instructive direction.** It named the right surface —
//! `visit_scalar` *and* `visit_untagged_scalar` — and then reasoned only
//! about the second, so it missed `visit_scalar`'s own core-tag dispatch. It
//! then concluded that "a fourth omitted axis would most likely live outside
//! the walk". The fourth omission was **inside** the walk, in the surface
//! that paragraph called closed. The lesson recorded rather than paraphrased:
//! naming a surface is not examining it, and an enumeration that cannot be
//! re-checked against numbered source lines is not one.
//!
//! For the stages outside the walk — tokenizing before it, `flatten` and
//! `Value` construction after it — there is no equivalent closed argument.
//! Those rows are enumerated and measured, which per P18 is an observation
//! and not a proof. **Where a sixth omission would live is not something this
//! comment should guess at again** — round 2 guessed "outside the walk" and
//! the next one was inside it. What it can say is that five have now been
//! found, four of them inside the walk, and that the two remaining open rows
//! are open for different reasons: tokenizing because of *where* the cost is
//! spent (before any callback exists to price), the integer decode because a
//! priced callback still says nothing about what the decode behind it cost.
//! Neither is open because of which unit measures it, and that distinction is
//! load-bearing: collapsing it is exactly what round 3 got wrong when it
//! generalised from two failed remedies to "unclosable".
//!
//! **An in-process timeout was never the answer and still is not.**
//! `serde_yaml::from_str` is a synchronous call into `unsafe-libyaml` with
//! no cancellation points, so `tokio::task::spawn_blocking` plus a timeout
//! only stops the *caller* waiting; the blocking thread keeps burning a
//! core until the parse finishes on its own. That converts a stalled
//! request into a leaked pinned core, which is worse, not better. The two
//! remedies an earlier version of this comment proposed — parsing out of
//! process under `RLIMIT_CPU`, or replacing the parser with one exposing a
//! caller-controlled work budget — remain the heavier options that would
//! also cover the tokenizing stage. Neither was taken: the meter reaches
//! the same place for the expansion stage without a process spawn per parse
//! in a library crate, or a dependency change against a phase that pins
//! versions deliberately.
//!
//! **Reachability, unchanged:** `parse_workflow` still has no production
//! caller — only this crate's own tests reach it. Whoever wires the first
//! real caller (a trigger, a job submission, an API endpoint that accepts
//! workflow YAML) inherits the *residual* above, which is smaller than what
//! it inherited before but is not nothing.
//!
//! ## Task 14 (lane W5), completed by fix round 1: both `serde_yaml`
//! ## walks over untrusted input now run out of process
//!
//! The "parse out of process under `RLIMIT_CPU`" remedy this section
//! recommended is now real for the stage that used to be
//! `let def: WorkflowDef = serde_yaml::from_str(yaml)?;`:
//! [`helper::parse_via_helper`] runs that deserialization in a separate
//! `round-yaml-parse-helper` process, spawned under
//! `roundhouse_sandbox::bounded_parse::run_bounded_subprocess`'s CPU
//! (Linux), wall-clock (every platform) and output-size bound.
//!
//! **What Task 14's original commits closed: the *structural doubling*
//! this section describes, by construction.** The helper deserializes into
//! a `serde_yaml::Value` (where the real alias-following and
//! numeric-decode work happens) and re-serializes it alias-free;
//! [`parse_workflow`]'s own second `serde_yaml` call then runs over *that*
//! alias-free output — a plain linear parse, not a second walk of the
//! original alias structure.
//!
//! **What Task 14's original commits left open, and what fix round 1
//! (ruling W5-20) closed:** `expansion::check_expansion` — the fast-path
//! guard that at the time still ran *before* [`helper::parse_via_helper`],
//! entirely in this process — is not a cheap approximation of the real
//! parse. It builds a real `serde_yaml::Deserializer` and drives it with
//! `deserialize_any` (`expansion.rs`'s own doc comment: "use the real
//! deserializer as its own budget meter"), so for every numeric scalar it
//! triggers the exact same `from_str_radix`/`dec2flt` decode the typed
//! deserialize does, once per alias expansion — the identical cost this
//! whole module doc is about, paid a *first* time. Task 14's original
//! commits moved only the *second* walk's copy of that cost out of
//! process, leaving the first exactly as unbounded as before Task 14 —
//! measured by the orchestrator at ~10-11s wall clock on a payload whose
//! bounded half alone should have finished in ~2s. Fix round 1 moves
//! `check_expansion` itself into `round-yaml-parse-helper`, alongside the
//! typed deserialize it used to run ahead of (see
//! `src/bin/round_yaml_parse_helper.rs` and `parse::helper`'s module doc
//! for the verdict protocol this needed, since a bare exit code cannot
//! carry [`ParseError::TooManyNumericScalars`]'s or
//! [`ParseError::ExpandsTooLarge`]'s data). Both walks now run inside the
//! same child, under the same `RLIMIT_CPU`/wall-clock/output bound — see
//! `tests/bounded_parse_out_of_process.rs`'s
//! `an_admitted_but_expensive_alias_document_is_rejected_by_the_out_of_process_bound`,
//! which measures the same pathological payload finishing in ~2.01s
//! post-fix, against 9.79s pre-fix on the same machine.
//!
//! **`check_expansion` moving does not make it redundant with the CPU
//! bound, and ruling W5-20 is explicit that it must not be dropped in
//! favour of it:** a moderate fan-out of cheap scalars can exceed
//! [`MAX_EXPANDED_WEIGHT`] while staying well under the helper's 2-second
//! CPU bound — only the guard rejects that shape, which is what
//! `tests/bounded_parse_out_of_process.rs`'s
//! `a_moderate_fan_out_of_cheap_scalars_is_rejected_by_the_moved_guard_not_the_resource_bound`
//! pins.
//!
//! **What is still not closed (ruling W5-6, independent of the point
//! above, and unaffected by fix round 1):** [`MAX_YAML_BYTES`] and
//! [`nesting_depth_bound_violation`] remain functionally untouched — still
//! best-effort, over-rejection bug included (see
//! `nesting_depth_bound_violation`'s own doc comment); Phase 5's parked
//! over-rejection regression is **not** addressed by this task. Those two
//! checks are the only `serde_yaml`-adjacent guards that still run in this
//! process — and neither one is itself a `serde_yaml` call: the first is a
//! byte-length comparison, the second a linear scan of the raw text. Every
//! actual `serde_yaml` walk over attacker-controlled input now happens
//! inside the bounded child; the only `serde_yaml` call left in this
//! process is [`parse_workflow`]'s final linear parse of the helper's
//! already-alias-free output.
//!
//! # Bounds this module does enforce, and exactly what each is worth
//!
//! - **Anchors/aliases ("billion laughs"):** `serde_yaml` 0.9's event
//!   loader stores an alias as a single `Event::Alias(id)` marker rather
//!   than eagerly expanding it (`serde_yaml::loader`), so parsing raw YAML
//!   into its internal event list is already linear in input size.
//!   Materializing a Rust value that follows an alias is bounded by a jump
//!   counter internal to `serde_yaml`'s deserializer
//!   (`jumpcount > document.events.len() * 100` triggers
//!   `RepetitionLimitExceeded`). It is true that this makes expansion
//!   non-exponential, and it is true that the guard is on by default in
//!   0.9.34 and needs no configuration. **What earlier versions of this
//!   doc comment also said — that "total alias-expansion work is capped at
//!   roughly 100x the document's event count" — was wrong**, and the cap
//!   ruling in fix round 3 was built on it. It conflates the number of
//!   jumps with the cost of a jump: the counter bounds how many jumps
//!   happen, not how much each one expands, and each expands a subtree
//!   whose size is itself proportional to the document. See
//!   `rejects_a_billion_laughs_style_alias_bomb` in
//!   `tests/parse_top_level.rs`, which exercises the guard directly —
//!   though since Task X1 that payload is stopped during
//!   [`MAX_EXPANDED_WEIGHT`]'s walk rather than by the typed parse. Which
//!   of the two limits stops it is measured rather than assumed — see
//!   `rejects_a_billion_laughs_style_alias_bomb`, whose comment records
//!   it. Either way `parse_workflow` returns before deserializing for
//!   real.
//!
//!   **This module's alias check is a metered walk, not a count.** Fix
//!   round 4 **on Task 10** shipped a count (`MAX_ALIAS_TOKENS`, rejecting
//!   above 64 tokens matching `*[A-Za-z0-9_-]`) as best-effort defence in
//!   depth; fix round 5 **on Task 10** removed it, because it turned out to
//!   cost more than it bought. (Task numbers, because Task X1 has its own
//!   rounds 4 and 5 and they did different things — round 4 there added the
//!   numeric-visit charge, round 5 split it. See [`MAX_FLOW_NESTING_DEPTH`]
//!   and `an_alias_heavy_prose_prompt_parses` for the same convention.) It
//!   could not bound the attack — at a fixed 64 alias tokens,
//!   cost spans over 3,000x purely by widening the anchored leaf list (10
//!   leaves 9.6 ms, 100 leaves 160 ms, 1,000 leaves 4.26 s, 5,000 leaves
//!   29.3 s), so alias count and parse cost are close to independent and
//!   no threshold yields a ceiling. Meanwhile it rejected real workflows:
//!   the pattern is also markdown emphasis, so a 4,719-byte `agent.prompt`
//!   using `*word*` and `**bold**` in ordinary prose was rejected outright
//!   (measured), as were `src/*rs` and `rm *tmp`. Task X1's
//!   [`MAX_EXPANDED_WEIGHT`] is deliberately not another count of that
//!   kind: it weighs what the deserializer actually produced while
//!   following the aliases — nodes *and* the bytes they carry — so its unit
//!   cannot decouple from cost the way an alias-token count did, and it
//!   cannot see a `*word*` in a block scalar at all, since a block scalar
//!   is one node charged its own length once. See the history section
//!   above.
//! - **Pathological nesting depth, materializing a Rust value:** bounded by
//!   `serde_yaml`'s own `remaining_depth: 128` recursion guard
//!   (`RecursionLimitExceeded`), on by default. **This guard applies only
//!   to the deserialize-events-into-a-Rust-value stage — not to
//!   tokenizing/scanning the raw text into events in the first place**,
//!   which happens first and unconditionally. Fix round 1 on Task 10
//!   (finding H2) found that an earlier version of this doc comment
//!   conflated the two stages, incorrectly implying nesting depth was
//!   fully bounded before that scan was added below.
//! - **Pathological nesting depth, scanning the raw text:** measured
//!   directly (not merely inferred from the library's guards above) to be
//!   quadratic-or-worse in a document consisting of deeply nested flow
//!   collections (e.g. a long run of unclosed `[`) — a ~50 KB payload of
//!   nothing but `[` cost single-digit seconds *before* `serde_yaml` ever
//!   reaches the point of returning `RecursionLimitExceeded`. This is a
//!   property of tokenizing the text, not of any one YAML library's
//!   internals.
//!
//!   **Two earlier scan designs were each found — by execution, not
//!   reasoning — to have their own bypass, which is why the scan below
//!   claims nothing:**
//!   - Round 1 shipped a quote-tracking scan claiming to skip quoted
//!     content safely. A quote character in perfectly ordinary YAML
//!     (`name: don't`) desynchronized it permanently, silently disabling
//!     the depth bound for the rest of the document.
//!   - Round 2 replaced it with a scan that dropped quote-tracking (on the
//!     reasoning that over-counting brackets is always safe) but detected
//!     a `|`/`>` block-scalar opener via a bare `rfind(':')` over the
//!     whole line, with no awareness of flow-collection context. Both
//!     review lenses independently found the same consequence from that:
//!     a *comment* line containing a colon (`# x: |`) or a colon inside an
//!     *unclosed flow collection on the same line* (`items: ["note: |`)
//!     could be misread as a real block-scalar opener, which then hid
//!     every subsequent more-indented line — including a bracket bomb —
//!     from the depth counter entirely. Measured (release, via the real
//!     `parse_workflow`): the comment-line variant cost 531ms at 20 KB,
//!     5.85s at 80 KB, and over 12.6 minutes of pinned CPU at the (then)
//!     1 MiB byte cap.
//!
//!   **Round 3's conclusion: a text scan that must model enough of YAML to
//!   protect a YAML parser is the wrong shape for a soundness guarantee,
//!   and a fourth heuristic patch would only be the same bet a fourth
//!   time.** [`nesting_depth_bound_violation`] is kept — its rule for
//!   *what a block-scalar body is* is independently sound (verified: real
//!   `|`, `|2`, `|-`, `>` bodies are linear in `serde_yaml`, and a 30,000-
//!   bracket genuine `prompt: |` parses in 177µs), so it still buys real
//!   over-rejection relief and rejects the cases it does understand very
//!   cheaply — but it is now explicitly **best-effort defence in depth,
//!   not a security boundary**. It does not claim, and must never again
//!   claim, that it can only over-count or that it closes an entire bug
//!   class. (Round 3 did add a further-hardened opener check — see
//!   [`is_block_scalar_indicator_line`] — closing both bypasses found so
//!   far, and raised [`MAX_FLOW_NESTING_DEPTH`] from 64 to 256 alongside
//!   it, since 65 *unbalanced* brackets spread across comments or quoted
//!   scalars in an ordinary workflow — e.g. a shell-matcher regex like
//!   `"[a-z"` — is a real way to hit the old bound for a reason that isn't
//!   present. But no claim of soundness rides on that hardening; it is
//!   just today's best-effort, not tomorrow's guarantee.)
//!
//!   **Fix round 3 then claimed "the real bound is [`MAX_YAML_BYTES`], now
//!   32 KiB", sized off that cost curve so that "the worst case *at the
//!   cap* — regardless of payload shape — is bounded to roughly a second
//!   and a half of one-shot CPU". That claim was wrong and is retracted.**
//!   It was true only for the one payload shape it was measured against (a
//!   run of unclosed `[`, which really is linear-ish: 32 KiB of it costs
//!   ~80 ms, 256 KiB ~650 ms). It was false in general: the anchor/alias
//!   fan-out in the history section above cost *minutes* well inside
//!   32 KiB, and the review measured 287.8 s at exactly the 32 KiB cap —
//!   roughly 190x the claimed ceiling. **A byte cap is not a bound on parse
//!   cost, and that is still true**: what bounds the fan-out is
//!   [`MAX_EXPANDED_WEIGHT`], not [`MAX_YAML_BYTES`], and the shape measured
//!   in this bullet — an unclosed-bracket run, whose cost is in the
//!   tokenizer rather than in expansion — is still bounded by nothing but
//!   the byte cap.
//! - **Overall document size / "huge number of steps":** these are coarse
//!   sanity bounds on absurd input — [`MAX_YAML_BYTES`] on the raw input
//!   before it is handed to `serde_yaml`, and [`MAX_TOP_LEVEL_STEPS`] /
//!   [`MAX_CATCH_HANDLERS`] / [`MAX_FINALLY_HANDLERS`] on the parsed
//!   result's lists. **None of them is a security bound**, and the two
//!   size-shaped ones interact on purpose: see [`MAX_YAML_BYTES`].

mod expansion;
mod helper;
pub mod steps;
pub mod types;

// Task 14 fix round 1 (ruling W5-20): `check_expansion` now runs inside
// `round-yaml-parse-helper`, not in this process — see this module's doc
// comment and `parse_workflow`'s body below. The helper binary is a
// separate crate that links this crate's *library* and can therefore only
// reach `pub` items, so these two are re-exported here rather than
// duplicated (a second copy of the guard is exactly what ruling W5-20's
// "reachability" note forbids). `#[doc(hidden)]` keeps them out of this
// crate's advertised public API — they exist for exactly one caller.
#[doc(hidden)]
pub use expansion::{check_expansion, Verdict};

pub use types::WorkflowDef;
use types::{UnattendedDef, UnattendedEscalate};

use thiserror::Error;

/// 256 KiB. **Not a security bound.** Fix round 3 set this to 32 KiB and
/// called it "the real DoS bound"; that claim is retracted (see the module
/// doc comment's history section — the anchor/alias fan-out cost minutes of
/// CPU at a fraction of even the old 32 KiB, so no cap could separate
/// hostile from legitimate; [`MAX_EXPANDED_WEIGHT`] is what separates them
/// now, and it weighs the *expanded* document rather than the source).
/// This constant's coarse-sanity job is refusing to even look at an
/// absurdly large document — but it is load-bearing in two further ways.
/// First, [`MAX_EXPANDED_WEIGHT`] must stay large enough to admit any
/// alias-free document this cap allows, which is asserted at compile time
/// beside that constant. Second, and added at fix round 6: it is now the
/// **only** thing limiting the integer-decode axis of the module doc's axis
/// inventory. See "What raising it costs now" below before touching it.
///
/// **Why 256 KiB and not 32 KiB.** 32 KiB was chosen as a security number
/// and is far too tight as a sanity number: [`MAX_TOP_LEVEL_STEPS`] admits
/// 500 top-level steps, which at 32 KiB leaves ~65 bytes per step — less
/// than a bare `- id: x` / `tool: y` / `with: {...}` step costs, and
/// nowhere near a step carrying an agent prompt. 256 KiB leaves ~524 bytes
/// per step at the step limit, which is a realistic step with a modest
/// prompt. That makes the two constants coherent rather than one silently
/// unreachable behind the other.
///
/// **The interaction, stated explicitly and intended:** a workflow
/// approaching [`MAX_TOP_LEVEL_STEPS`] whose steps carry substantial agent
/// prompts will hit *this* cap first and be rejected as `TooLarge` rather
/// than as `TooManySteps`. That is fine. Both are coarse sanity bounds on
/// obviously-absurd input, neither is a security bound, and neither is
/// tuned to be the one that fires.
///
/// **What raising it cost, stated plainly** (written when the raise
/// happened, kept as history): because expansion cost was then O(bytes²),
/// 32 KiB -> 256 KiB multiplied the theoretical worst case by ~64x. That
/// was acceptable only because this was never a bound — the review had
/// already measured 287.8 s at exactly 32 KiB, so the number being made
/// larger already admitted an unusable-machine outcome.
///
/// **What raising it costs now.** Task X1 changed the relationship, and fix
/// round 1 changed it again. [`MAX_EXPANDED_WEIGHT`] is an independently
/// chosen constant, so raising this cap does **not** raise the expansion
/// ceiling — it raises the weight an alias-free document may legitimately
/// reach, and the `const` assert beside [`MAX_EXPANDED_WEIGHT`] fails the
/// build once that outgrows the ceiling. Raising this cap therefore forces
/// an explicit decision about the expansion ceiling instead of silently
/// widening it, which is the opposite of what the previous round did. The
/// metered walk's cost is linear in nodes (measured: 21.9 ms for the
/// 131,044-node densest alias-free sequence at the cap, 26.6 ms for the
/// 262,070-node densest mapping), so re-measure rather than assuming that
/// linearity holds arbitrarily far.
///
/// **The part that is not linear, and is why P63 is about this constant.**
/// The axis inventory's *integer decode* row is limited by this cap and by
/// nothing else, and it does not scale linearly with it: the maximiser's work
/// is `~B²/12` scanned bytes per walk and there are two walks, so raising this
/// cap raises that residual **quadratically**. At today's 256 KiB that is
/// 5.7 GB scanned per walk, measured at **9,435.7 ms admitted** for a
/// 262,143-byte document (fix round 6). Ruling **P63** is exactly the decision
/// to keep this document size with that residual accepted, so this is the
/// constant where that decision has to be visible: raising it reopens P63,
/// and lowering it is the disproportionately effective interim lever the
/// module doc names. See the integer decode row and
/// [`expansion::FLOAT_SCALAR_WEIGHT_BYTES`]' residual section.
///
/// For scale: the frozen §8.9 fixture is 2,271 bytes.
///
/// **Task 14 (lane W5) update, fix round 1 (ruling W5-20).** The
/// 9,435.7 ms P63 figure is the cost of *one* real `serde_yaml` walk over
/// the maximiser, and the module doc's "structural doubling" paragraph
/// records that an admitted document pays it twice: once in
/// `expansion::check_expansion`'s metered pass, once in the typed
/// deserialize. Task 14's original commits moved only the *second* walk
/// out of process, leaving the first — and with it, roughly half of
/// P63's accepted cost — genuinely unbounded in this process. **Fix round
/// 1 closed that gap**: `check_expansion` now runs inside
/// `round-yaml-parse-helper` too, so both walks are under
/// `roundhouse_sandbox::bounded_parse`'s CPU/wall-clock bound (see
/// [`super`]'s module doc's fix-round-1 section). P63's accepted residual
/// is therefore no longer "roughly halved, not superseded" as the previous
/// version of this paragraph said — the whole 9,435.7 ms admitted figure
/// (were `MAX_YAML_BYTES` ever raised enough to reproduce it again) would
/// now run to completion inside the same ~2-CPU-second-plus-overhead
/// bound `tests/bounded_parse_out_of_process.rs` measures, not half of it
/// in this process and half of it bounded.
pub const MAX_YAML_BYTES: usize = 262_144;

/// The maximum **expanded byte weight** a workflow document may produce once
/// its anchors and aliases are followed. This is the bound that closes the
/// anchor/alias denial of service; see the module doc comment's history
/// section for the attacks and `src/parse/expansion.rs` for the mechanism.
///
/// # Unit
///
/// [`expansion::NODE_WEIGHT_BYTES`] per node handed to the deserializer's
/// visitor — each scalar, each sequence, each mapping, each mapping *key* —
/// **plus each scalar's own byte length**. An alias contributes the full
/// weight of the subtree it expands to, every time it expands.
///
/// It is not a byte count of the source, not an alias count, and not a
/// nesting depth. It is also no longer a *node* count: fix round 1 replaced
/// that unit after a security review proved it does not bound memory —
/// `visit_str` discarded the string's length, so aliasing one large anchored
/// scalar `K` times cost `K` at the meter while materializing `K x L` bytes
/// for real. A 180,138-byte document was admitted and drove the parse to
/// 4,593 MB resident. Every previous attempt at this bound was a proxy that
/// decoupled from the cost it was meant to bound; the node count was the
/// fourth. Charging the bytes makes the unit the quantity that actually
/// materializes.
///
/// # Derivation of the number
///
/// It is an **absolute** ceiling, chosen independently of the byte cap.
/// Proportionality to the document is the defect in `serde_yaml`'s own
/// `jumpcount > events.len() * 100` guard: it hands a larger attacker
/// budget for a larger attack.
///
/// The constraint the number has to satisfy is that **every alias-free
/// document under [`MAX_YAML_BYTES`] is admitted**, so that nothing can be
/// rejected here for being large — only for amplifying. For an alias-free
/// document of `B` source bytes:
///
/// - **at most `B` nodes.** Every node needs at least one source byte, and
///   the densest encoding reaches exactly that: a flow mapping with omitted
///   values, `{a,a,a,…}`, yields one node per byte (measured: 262,070 nodes
///   in 262,144 bytes, 1.00 nodes/byte). An earlier version of this comment
///   claimed the densest encoding was `[x,x,…]` at *two* bytes per node,
///   which is false — that shape measures 0.50 nodes/byte and `{a,a,…}` is
///   twice as dense. Flow forms denser still (`{,,,}`, `[,,,]`, `{:,:,}`)
///   are rejected outright by `serde_yaml`, so 1.00 is the constructible
///   maximum.
/// - **at most `B` bytes of expanded scalar content**, since without an
///   alias every scalar's value is at most its own source text (escapes and
///   `!!binary` shrink; nothing grows).
///
/// So an alias-free document weighs at most
/// `B * (NODE_WEIGHT_BYTES + 1)` = **2,359,296** at today's constants —
/// **90.0% of this ceiling, a 10.0% margin**. Fix round 2 tightened the
/// ceiling from 4 MiB to this, because the margin is what sets the node
/// budget and therefore the memory axis. Round 2 justified that with a
/// 101 MB -> 65.5 MB comparison across two *different* shapes, which was not
/// a valid comparison; fix round 3 re-measured the same maximising shape
/// (one-element sequences nested 110 deep, aliased) at both values:
/// **159.1 MB at 4 MiB against 101.9 MB at 2,621,440**, a 36% reduction
/// scaling as the algebra predicts. So the tightening did buy something,
/// though less than round 2 claimed and against a worse absolute number than
/// round 2 knew. The margin is
/// deliberately small and the `const` assert below is what makes that safe
/// — an over-tight ceiling fails the build rather than silently rejecting
/// legitimate documents.
///
/// The densest document that actually *parses* weighs 1,179,423
/// (`[x,x,…]` at the byte cap, 45.0% of the ceiling); the denser
/// `{a,a,…}` at 2,227,640 (85.0%) is what the derivation has to cover but
/// `serde_yaml` rejects it for duplicate keys, so it bounds the arithmetic
/// rather than the behaviour.
///
/// **This derivation is about non-numeric nodes only, and fix round 5
/// narrowed what it promises.** Numeric scalars are charged
/// [`expansion::FLOAT_SCALAR_WEIGHT_BYTES`] /
/// [`expansion::INTEGER_SCALAR_WEIGHT_BYTES`] rather than
/// [`expansion::NODE_WEIGHT_BYTES`], so an alias-free document *can* now be
/// rejected — for carrying more numbers than [`MAX_FLOAT_SCALAR_VISITS`] or
/// [`MAX_INTEGER_SCALAR_VISITS`] allows, never for its size. The sentence
/// below says "or legitimate documents start being rejected"; that remains
/// true of the size axis it guards, and is no longer true of documents in
/// general.
///
/// That relationship is a real inequality between two independently chosen
/// constants, and it is asserted in a `const` block below, so raising
/// [`MAX_YAML_BYTES`] past what this ceiling can cover **fails the build**.
/// (The equivalent guard in the previous round was
/// `MAX_EXPANDED_NODES >= MAX_YAML_BYTES` where the former was *defined* as
/// the latter — a tautology that could not fail for any value. That is the
/// `MAX_ALIAS_TOKENS` defect one level up: a guard that reads as protection
/// while protecting nothing.)
///
/// # What a document at this ceiling costs — measured, release build
///
/// Weight is a charge model, not a memory measurement. What it implies
/// directly is only that expanded scalar bytes are at most this ceiling and
/// node count at most `ceiling / NODE_WEIGHT_BYTES` = 327,680. What *that*
/// costs was measured, one document per child process under an 8 GiB
/// `ulimit -v`: **worst admitted peak RSS ≥101.9 MB**, from a 15,106-byte
/// document whose shape is one-element sequences nested 110 deep, aliased.
/// About 52 MB of that is inherent — the densest alias-free document that
/// `parse_workflow` actually accepts measures 51.6 MB on its own. The
/// ≥ is not decoration: fix rounds 2 and 3 each published a worst case that
/// the next reviewer beat by finding a shape that had not been probed
/// (36 MB, then 65.5 MB, now 101.9 MB), so treat this as the worst *found*
/// and see the axis inventory for which rows are open.
///
/// Rejection is cheap **when this ceiling is what rejects**: every attack
/// payload in the module doc comment's history tables is rejected in
/// 0.6-24.5 ms release (3.8-216.4 ms debug), re-measured at fix round 3
/// across every payload the tables name, with process peak RSS of
/// 3.7-9.3 MB. It is *not* cheap when a later check rejects: a document whose
/// aliases are top-level steps passes this ceiling, is deserialized in full,
/// and only then trips [`MAX_TOP_LEVEL_STEPS`] — measured at 3,747.7 ms for
/// the integer maximiser of the axis inventory's integer decode row (fix
/// round 6). The two-walk design means a legitimate document is walked
/// twice: measured overhead is 0.07 ms on the frozen §8.9 fixture (2,271 B)
/// and 21.9 ms on a maximally dense 256 KiB document, the worst case the
/// byte cap allows.
pub const MAX_EXPANDED_WEIGHT: usize = 2_621_440;

// The derivation above, as a check that can actually fail: an alias-free
// document under the byte cap weighs at most MAX_YAML_BYTES * (node weight +
// 1), and that must fit under the ceiling or legitimate documents start
// being rejected. Two independently chosen constants, so this is an
// inequality rather than a tautology — raising MAX_YAML_BYTES to 512 KiB
// fails this at compile time. `the_densest_alias_free_documents_under_the_byte_cap_still_parse`
// in `tests/parse_top_level.rs` is the behavioural half of the same guard.
/// How many scalars `serde_yaml` decodes as **floats** one document may
/// expand to. Derived, not chosen: [`MAX_EXPANDED_WEIGHT`] divided by what a
/// float visit costs.
///
/// **Bounding the count does not bound the work, and an earlier version of
/// this line said it did.** A decoded scalar can never be longer than its
/// source and [`MAX_YAML_BYTES`] caps that, so both factors are capped — but
/// both factors being capped is not the same as their product being small.
/// What the two caps together *permit* is `5,041 x 262,144` = 1.32 GB of
/// `dec2flt` scanning. What actually holds the worst admitted float document
/// to 1,519.1 ms is that the count cap **binds** on this axis: the maximiser
/// makes 4,971 visits against the 5,041 ceiling and one notch wider is
/// rejected. The integer axis is the counter-case — there the equivalent cap
/// never fires and 17.2 GB is a ceiling in the absence of a bound; see
/// [`MAX_INTEGER_SCALAR_VISITS`] and
/// [`expansion::FLOAT_SCALAR_WEIGHT_BYTES`]' "count of decodes, not the cost
/// of one" section, whose framing this paragraph now matches.
///
/// # Measured, and against which shape
///
/// All figures release, one document per child process under a `ulimit -v`
/// ceiling — 8 GiB for the round-5 rows, 16 GiB for round 6's; the `round`
/// column says which. The shape is the **exponent maximiser**: `!!float` on a
/// double-quoted scalar whose digits sit in the *exponent* (`1.5e-999…9`)
/// and are folded every 512 characters by escaped line continuations. That
/// shape matters — the same document with the digits in the *mantissa*
/// costs ~3.9x less (97.6 ms against 383.8 ms for the same ~174 KB), because
/// `dec2flt` parses mantissa digits eight at a time and the exponent
/// byte-at-a-time. Earlier rounds published figures from mantissa payloads
/// and were low every time. (Round 5 published this mantissa payload as both
/// 94.9 ms in prose and 97.6 ms in the table below, in one commit. 97.6 ms is
/// the figure its report and commit message carry, so that is the one kept
/// here — and `383.8 / 97.6` is 3.9x, not the 4.0x the 94.9 pairing gave.)
///
/// | payload | bytes | result | round |
/// |---|---|---|---|
/// | exponent maximiser, 245,000 digits, aliased 4,970x, tuned just under the ceiling | 249,582 | **ADMITTED, 1,519.1 ms** | 6 |
/// | the same shape with 240,000 digits and a 2,000-entry pad list | 248,302 | **ADMITTED, 1,489.2 ms** | 6 |
/// | the same shape, 200,000 digits, with a 20,000-entry pad list spending 180,000 of the weight budget on the pad | 243,678 | rejected, 589.8 ms | 6 |
/// | exponent maximiser, tuned just under the ceiling | 259,742 | ADMITTED, 1,603.3 ms — **this tuning does not reproduce; see below** | 5 |
/// | the same family with floats uncharged (round 3's behaviour) | 257,442 | **18,318.9 ms** burned, then stopped by `serde_yaml`'s own repetition guard | 5 |
/// | exponent maximiser, rejected by the ceiling | 174,146 | rejected, 383.8 ms | 5 |
/// | the same digits in the *mantissa* instead | 174,143 | rejected, 97.6 ms — 3.9x cheaper | 5 |
///
/// **The round-5 admitted row does not reproduce, and the round-6 rows are
/// the ones to follow.** Round 5's parameters for it (`n = m = 71` with a
/// 20,000-entry pad list) are *rejected* on today's tree: the third round-6
/// row above shows a 20,000-entry pad spending 180,000 of the weight budget on
/// its own, and `n = m = 71` puts the visit count at `1 + 71 + 5,041 = 5,113`,
/// over the 5,041 ceiling. Fix round 6 had to retune to `n = m = 70` with a
/// much smaller pad to obtain an admitted document at all, which is where
/// 1,519.1 ms comes from. The round-5 rows are kept rather than deleted
/// because the 18,318.9 ms pre-charge row beneath is what justifies the charge
/// existing, and the two were measured together; round 5's exact parameters
/// were **not** re-measured, so what is retracted is the row's
/// reproducibility, not the family's figures. This is the standard stated at
/// the top of the axis inventory — the shape a figure was measured against is
/// part of the figure — applied to a row that predates it.
///
/// **The admitted figure is the one that matters** — for *this* axis a
/// rejection is the cheap case. It is ~2x the metered walk alone, because of
/// the structural doubling described in this module's axis inventory.
///
/// **"Rejection is cheap" does not carry across to integers**, and round 5
/// implied it did by publishing one row for both: on the integer axis the
/// same family is rejected only *after* both walks complete, measured at
/// 3,747.7 ms. See [`MAX_INTEGER_SCALAR_VISITS`] and the inventory's integer
/// decode row.
///
/// # What it over-rejects
///
/// A workflow whose `map.over` lists hold more than 5,041 **float** items in
/// total. One full 2,000-item map step of floats is admitted with 2.5x
/// headroom; three are not. Integer ids — the shape
/// [`crate::caps::MAX_MAP_ITEMS`] is actually written for — are charged
/// sixteen times less (`512 / 32 = 16`) and are covered to 65,536; see
/// [`MAX_INTEGER_SCALAR_VISITS`], and read its residual note before treating
/// that as the same kind of coverage.
pub const MAX_FLOAT_SCALAR_VISITS: usize =
    MAX_EXPANDED_WEIGHT / (expansion::NODE_WEIGHT_BYTES + expansion::FLOAT_SCALAR_WEIGHT_BYTES);

/// How many scalars `serde_yaml` decodes as **integers** one document may
/// expand to. Derived the same way, from the sixteen-times-smaller
/// [`expansion::INTEGER_SCALAR_WEIGHT_BYTES`] (`512 / 32 = 16`; an earlier
/// version of this line said "eight", which is the arithmetic of a value this
/// constant no longer has, and following it back to 64 would land at 36,408
/// visits — 1.1% above the tripwire below, so the build would *not* catch it).
///
/// # This caps a count, not a cost, and the difference is measured
///
/// **It is not a bound on integer-decode work and must not be cited as one.**
/// A `serde_yaml` integer decode is O(token length) and the visitor never sees
/// the token, so this ceiling and [`MAX_YAML_BYTES`] together permit
/// `65,536 x 262,144` = **17.2 GB** of `from_str_radix` scanning. Measured
/// fix round 6: a 262,143-byte document — one anchored `0x` + 131,019 zeros +
/// `1` aliased 43,673 times — is **ADMITTED in 9,435.7 ms**, and it makes only
/// 43,674 integer visits, so this ceiling is never reached and plays no part
/// in the outcome. What limits that attacker is [`MAX_YAML_BYTES`].
///
/// That is an **accepted residual** under ruling P63 rather than an open
/// question: the project owner weighed it against lowering [`MAX_YAML_BYTES`]
/// and [`MAX_TOP_LEVEL_STEPS`] and chose to keep the document size. See this
/// module's axis inventory (integer decode row) and
/// [`expansion::FLOAT_SCALAR_WEIGHT_BYTES`] for the `serde_yaml` mechanism.
///
/// # The value, sized against the corpus in the over-rejection direction
///
/// Sized against the binding corpus case rather than chosen: the largest
/// `map`-over-numeric-ids workflow [`MAX_YAML_BYTES`] admits at all is
/// **18 map steps x 2,000 six-digit ids = 36,001 integer scalars in 253,952
/// bytes** (measured, fix round 5; a 19th step exceeds the byte cap). 65,536
/// is 1.82x that. Fix round 4 charged integers at the float rate, which
/// admitted only 5,041 and refused a **42,384-byte, alias-free**
/// three-map-step workflow — a shape this crate blesses through
/// [`crate::caps::MAX_MAP_ITEMS`]. That corpus constraint is real and it is
/// also why the residual above cannot be closed by moving this constant:
/// admitting 36,001 integers needs a charge of at most 64, and the closing
/// security review put the charge needed to bound the attack at ~481
/// (reported, not re-measured here).
pub const MAX_INTEGER_SCALAR_VISITS: usize =
    MAX_EXPANDED_WEIGHT / (expansion::NODE_WEIGHT_BYTES + expansion::INTEGER_SCALAR_WEIGHT_BYTES);

// Tripwire, mirroring the one on MAX_EXPANDED_WEIGHT and for the same
// reason: nothing else protects the corpus margin these constants were
// derived against. 36,001 is the largest map-over-ids workflow the byte cap
// admits (measured, fix round 5); 2,000 is one full MAX_MAP_ITEMS list of
// float items. Shrinking either budget below its corpus figure fails the
// build rather than silently starting to refuse realistic workflows. It is a
// tripwire for attention, not a proof.
const _: () = assert!(
    MAX_INTEGER_SCALAR_VISITS >= 36_001,
    "MAX_INTEGER_SCALAR_VISITS dropped below the largest map-over-ids workflow the byte \
     cap admits (36,001 integer scalars, measured). Re-derive it against that corpus \
     document and update MAX_MAP_ITEMS' doc in the same change."
);
const _: () = assert!(
    MAX_FLOAT_SCALAR_VISITS >= 2_000,
    "MAX_FLOAT_SCALAR_VISITS dropped below one full MAX_MAP_ITEMS list of float items, \
     so a single legitimate map step would be refused."
);

// Upper tripwire. The assert below bounds the ceiling from *below* only, so
// the whole upper half of the argument — that the ceiling is small enough for
// the memory axis's worst case to stay where it was measured — was unguarded,
// and widening it back to 4 MiB stayed green across the crate. This asserts
// no memory number, and it is not a proof of anything: it is a tripwire for
// attention, so that widening the ceiling has to be a deliberate two-line
// edit landing next to the derivation it invalidates. Measured, same
// maximising shape (one-element sequences nested 110 deep, aliased): 101.9 MB
// at 2,621,440 against 159.1 MB at 4 MiB.
const _: () = assert!(
    MAX_EXPANDED_WEIGHT <= 2_621_440,
    "MAX_EXPANDED_WEIGHT was widened: the memory figures in this module's axis \
     inventory were measured at 2,621,440 and scale roughly linearly with it. \
     Re-measure the deep-container maximiser and update the inventory in the \
     same change."
);

const _: () = assert!(
    MAX_YAML_BYTES * (expansion::NODE_WEIGHT_BYTES + 1) <= MAX_EXPANDED_WEIGHT,
    "MAX_EXPANDED_WEIGHT is too small for MAX_YAML_BYTES: an alias-free document at \
     the byte cap could weigh more than the ceiling and be rejected for being large \
     rather than for amplifying"
);

/// No real workflow needs hundreds of top-level steps — a `map` step
/// already provides fan-out — so this bounds a maliciously (or
/// accidentally) huge step list without constraining legitimate use. See
/// [`MAX_YAML_BYTES`] for how the two interact: a 500-step workflow with
/// real prompts in it hits the byte cap before it hits this one.
pub const MAX_TOP_LEVEL_STEPS: usize = 500;
pub const MAX_CATCH_HANDLERS: usize = 50;
pub const MAX_FINALLY_HANDLERS: usize = 50;
/// Maximum nesting depth of `[`/`{` flow collections
/// [`nesting_depth_bound_violation`]'s best-effort scan will tolerate
/// before rejecting a document early — comfortably under `serde_yaml`'s
/// own 128-deep recursion guard, so a legitimate document (§8.9's fixture
/// nests at most a handful of levels) is never affected. Raised from 64 to
/// 256 in fix round 3 on Task 10: since the scan counts every `[`/`{`
/// outside a block-scalar body unconditionally (including ones inside
/// comments or quoted scalars, which are not real nesting at all), 65
/// *unbalanced* bracket characters spread across such content — e.g. a
/// shell-matcher allowlist regex like `"[a-z"` — was a realistic way for
/// an ordinary workflow to hit this bound for a reason that isn't present
/// in the actual document. This scan is best-effort, not a security
/// boundary — and neither is [`MAX_YAML_BYTES`], which fix round 3 wrongly
/// called "the real bound". **Nor is [`MAX_EXPANDED_WEIGHT`] a bound on parse
/// cost**, which an earlier version of this paragraph said it was: what it
/// bounds is the number of nodes the expansion stage walks, not the work each
/// one costs (`expansion::check_expansion`'s doc states this), which is why a
/// 262,143-byte integer document sits comfortably inside the weight ceiling
/// and still costs 9,435.7 ms. So **two** stages are limited by nothing but
/// the byte cap: the tokenizing stage this scan tries to help with, and
/// integer decoding. See the module doc comment's axis inventory — the
/// tokenizing row and the integer decode row — and its history section.
pub const MAX_FLOW_NESTING_DEPTH: usize = 256;
/// Maximum leading-whitespace width (raw character count, not "levels") any
/// one line may open with. Not a precise measure of block-style YAML
/// nesting depth — that would require reimplementing YAML's own
/// indentation rules — but a cheap, conservative, parser-independent bound
/// on how far a single line can indent, generous enough that no real
/// workflow (or the depth `serde_yaml` itself already tolerates) comes
/// close to it.
pub const MAX_LEADING_INDENT_CHARS: usize = 512;

/// The payload of [`ParseError::Yaml`]. Almost always [`YamlFailure::Direct`]
/// — a genuine `serde_yaml::Error` produced by a real `serde_yaml` call in
/// *this* process (there is exactly one left: [`parse_workflow`]'s final
/// linear parse of the helper's already-alias-free output).
///
/// **[`YamlFailure::FromHelper`] exists because of Task 14 fix round 1
/// (ruling W5-20).** `expansion::check_expansion` now runs inside
/// `round-yaml-parse-helper`, a separate process, and a `serde_yaml::Error`
/// cannot cross that boundary: the crate exposes no public constructor that
/// reattaches a [`serde_yaml::Error::location`] to a bare message (its
/// `Location`/`Pos`/`Mark` types are private to `serde_yaml` itself — see
/// `parse::helper`'s module doc for the wire format). So a syntax error the
/// helper catches is sent back as plain text plus, when the original error
/// had one, its `(line, column)` pair — [`ParseError::location`] returns
/// that pair for [`YamlFailure::FromHelper`] exactly as it would have
/// returned the equivalent `serde_yaml::Error`'s own location before this
/// fix, which is what keeps `yaml_syntax_error_reports_a_line_and_column`
/// passing unchanged.
#[derive(Debug)]
pub enum YamlFailure {
    /// A `serde_yaml::Error` this process produced itself.
    Direct(serde_yaml::Error),
    /// Reconstructed from `round-yaml-parse-helper`'s tagged stderr line:
    /// the original error's `Display` text, and its `(line, column)` if it
    /// had one.
    FromHelper {
        message: String,
        location: Option<(usize, usize)>,
    },
}

impl std::fmt::Display for YamlFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YamlFailure::Direct(err) => write!(f, "{err}"),
            YamlFailure::FromHelper { message, .. } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for YamlFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            YamlFailure::Direct(err) => Some(err),
            YamlFailure::FromHelper { .. } => None,
        }
    }
}

// Deliberately NOT `#[from]` on the `ParseError::Yaml` field (see below) —
// this is a second, independent `From` impl for a different source type
// (`serde_yaml::Error`, not `YamlFailure`), which is what every remaining
// real `serde_yaml` call site in this crate needs `?` to keep working
// exactly as before this fix.
impl From<serde_yaml::Error> for ParseError {
    fn from(err: serde_yaml::Error) -> Self {
        ParseError::Yaml(YamlFailure::Direct(err))
    }
}

/// Why [`parse_workflow`] rejected a document. Every variant names what was
/// wrong; [`ParseError::Yaml`] additionally carries a line/column when the
/// underlying error has one (see [`ParseError::location`]) —
/// [`YamlFailure`]'s own `Display` already includes it for the
/// [`YamlFailure::Direct`] case, since this module's `#[error(...)]`
/// message wraps `{0}` verbatim.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error(
        "workflow YAML is {actual} bytes, exceeding the {max}-byte limit enforced on untrusted workflow input"
    )]
    TooLarge { actual: usize, max: usize },

    #[error("workflow declares {actual} top-level steps, exceeding the limit of {max}")]
    TooManySteps { actual: usize, max: usize },

    #[error("workflow declares {actual} catch handlers, exceeding the limit of {max}")]
    TooManyCatchHandlers { actual: usize, max: usize },

    #[error("workflow declares {actual} finally handlers, exceeding the limit of {max}")]
    TooManyFinallyHandlers { actual: usize, max: usize },

    #[error(
        "permissions.unattended.escalate is `park`, which requires both `deadline` and `on_timeout` (§8.5: \"Escalate is configurable per job: Park{{deadline, on_timeout}}\")"
    )]
    ParkEscalationRequiresDeadlineAndOnTimeout,

    #[error(
        "workflow YAML nests {depth} deep, exceeding the {max}-deep limit enforced before parsing (a best-effort check that rejects one expensive-to-scan shape early; it is not a bound on parse cost — see this module's doc comment)"
    )]
    TooDeeplyNested { depth: usize, max: usize },

    #[error(
        "a line in the workflow YAML opens with {width} characters of leading whitespace, exceeding the {max}-character limit enforced before parsing"
    )]
    ExcessiveIndentWidth { width: usize, max: usize },

    #[error(
        "workflow YAML is only {actual_bytes} bytes but expands past the {max}-byte weight ceiling once its anchors and aliases are followed, and once the numbers in it are counted. It is rejected before the document is deserialized. This is not a size limit: a small document can reach it by amplifying through aliases, or by carrying a very large inline list of numbers (see this module's doc comment)"
    )]
    ExpandsTooLarge { actual_bytes: usize, max: usize },

    #[error(
        "workflow YAML contains more than {max} {kind} scalars, which is the limit on how many numbers one document may make the parser decode (each is decoded again on every anchor/alias expansion, at a cost proportional to its length). This is not about anchors or aliases: an ordinary document with a very long inline list of numbers reaches it. Split the list, or move it out of the workflow file"
    )]
    TooManyNumericScalars { kind: &'static str, max: usize },

    #[error("workflow YAML parse error: {0}")]
    Yaml(#[from] YamlFailure),

    /// The out-of-process YAML-parsing helper (Task 14, lane W5) could not
    /// be located or spawned. Deliberately never a silent fallback to an
    /// in-process `serde_yaml::from_str` — see `helper`'s module doc
    /// comment for why.
    #[error("workflow YAML helper is unavailable: {0}")]
    HelperUnavailable(String),

    /// The out-of-process helper (Task 14, lane W5) hit its own CPU,
    /// wall-clock, or output-size bound and was killed. Reaching this
    /// variant means the document passed every in-process guard above
    /// ([`MAX_YAML_BYTES`], [`nesting_depth_bound_violation`]) but still
    /// cost more than the real resource bound allows once handed to the
    /// bounded child — exactly the residual this task closes (see this
    /// module's doc comment's axis inventory, integer-decode row). Since
    /// Task 14 fix round 1 (ruling W5-20), "handed to the bounded child"
    /// includes `expansion::check_expansion`'s own metered walk, not only
    /// the typed deserialize that follows it — the kill can land during
    /// either.
    #[error(
        "workflow YAML exceeded the out-of-process parsing resource bound and was rejected: {0}"
    )]
    ExceededParseResourceBound(#[source] roundhouse_sandbox::bounded_parse::BoundedParseError),

    #[error("step id {id:?} is invalid: {reason}")]
    InvalidStepId { id: String, reason: String },

    #[error("step {step:?} declares {actual} `needs` entries, exceeding the limit of {max}")]
    TooManyNeeds {
        step: String,
        actual: usize,
        max: usize,
    },

    #[error(
        "duplicate step id {id:?} — step ids must be unique within the list passed to `topological_order`"
    )]
    DuplicateStepId { id: String },

    #[error(
        "step {step:?} declares `needs: [{needs:?}]`, but no step with that id exists in the same list"
    )]
    UnknownStepDependency { step: String, needs: String },

    #[error("the `needs:` graph has a cycle; these steps could never become ready: {steps:?}")]
    StepGraphCycle { steps: Vec<String> },

    #[error("step {step:?}: {reason}")]
    InvalidStepBody { step: String, reason: String },
}

impl ParseError {
    /// 1-based line/column of the failure, when the underlying error
    /// carries one. `serde_yaml`'s YAML-syntax errors and most
    /// schema-shape errors (missing/unknown field, bad enum variant) do;
    /// this module's own whole-document bound checks (e.g.
    /// [`ParseError::TooLarge`]) don't, since they aren't tied to one
    /// location in the document.
    pub fn location(&self) -> Option<(usize, usize)> {
        match self {
            ParseError::Yaml(YamlFailure::Direct(err)) => {
                err.location().map(|loc| (loc.line(), loc.column()))
            }
            ParseError::Yaml(YamlFailure::FromHelper { location, .. }) => *location,
            _ => None,
        }
    }
}

/// Parses raw workflow YAML text (§8.9) into a [`WorkflowDef`]. Consumes
/// `roundhouse_flow::job::Body::to_workflow_yaml`'s output — every `Body`
/// variant lowers to this same shape, so a `Body::Prompt` job is not a
/// special case here.
pub fn parse_workflow(yaml: &str) -> Result<WorkflowDef, ParseError> {
    if yaml.len() > MAX_YAML_BYTES {
        return Err(ParseError::TooLarge {
            actual: yaml.len(),
            max: MAX_YAML_BYTES,
        });
    }

    match nesting_depth_bound_violation(yaml) {
        Some(NestingViolation::FlowDepth(depth)) => {
            return Err(ParseError::TooDeeplyNested {
                depth,
                max: MAX_FLOW_NESTING_DEPTH,
            });
        }
        Some(NestingViolation::IndentWidth(width)) => {
            return Err(ParseError::ExcessiveIndentWidth {
                width,
                max: MAX_LEADING_INDENT_CHARS,
            });
        }
        None => {}
    }

    // Task 14 fix round 1 (ruling W5-20): `expansion::check_expansion` used
    // to run HERE, in this process, before the real deserialization below.
    // It no longer does — it runs inside `round-yaml-parse-helper` now,
    // alongside the deserialize it used to only guard, because it is
    // itself a real `serde_yaml` walk over attacker-controlled input (see
    // `expansion`'s own module doc and this module's doc comment's history
    // section) and was therefore the "first walk" of the structural-
    // doubling residual Task 14 did not close. `parse_via_helper` below now
    // runs the guard and the typed deserialize as one bounded unit;
    // `TooManyNumericScalars` and `ExpandsTooLarge` are reconstructed from
    // the helper's tagged stderr on the way back (`parse::helper`'s module
    // doc has the wire format) — the two variants are unchanged, only where
    // they are produced moved.
    //
    // Task 14 (lane W5): the real `serde_yaml` deserialization — the stage
    // that actually walks and materializes every anchor/alias expansion,
    // and the one no in-process check above can bound the *cost* of, only
    // reject some shapes of before paying it — runs out of process, under
    // a real CPU/wall-clock/output-size bound (`helper::parse_via_helper`).
    // The two checks above ([`MAX_YAML_BYTES`], [`nesting_depth_bound_violation`])
    // remain load-bearing as a fast-path rejection for the shapes they
    // understand — see each of their own doc comments for why neither is
    // the security boundary; that boundary is now entirely inside the
    // bounded child. The bytes that come back are already alias-free (the
    // helper deserializes into a `serde_yaml::Value` and re-serializes
    // it), so this second `serde_yaml` call is a plain linear parse, not a
    // second unmetered walk of the original alias structure.
    let expanded_yaml = helper::parse_via_helper(yaml)?;
    let def: WorkflowDef = serde_yaml::from_slice(&expanded_yaml)?;

    if def.steps.len() > MAX_TOP_LEVEL_STEPS {
        return Err(ParseError::TooManySteps {
            actual: def.steps.len(),
            max: MAX_TOP_LEVEL_STEPS,
        });
    }
    if def.catch.len() > MAX_CATCH_HANDLERS {
        return Err(ParseError::TooManyCatchHandlers {
            actual: def.catch.len(),
            max: MAX_CATCH_HANDLERS,
        });
    }
    if def.finally.len() > MAX_FINALLY_HANDLERS {
        return Err(ParseError::TooManyFinallyHandlers {
            actual: def.finally.len(),
            max: MAX_FINALLY_HANDLERS,
        });
    }

    validate_unattended(&def.permissions.unattended)?;

    Ok(def)
}

fn validate_unattended(unattended: &UnattendedDef) -> Result<(), ParseError> {
    if unattended.escalate == UnattendedEscalate::Park
        && (unattended.deadline.is_none() || unattended.on_timeout.is_none())
    {
        return Err(ParseError::ParkEscalationRequiresDeadlineAndOnTimeout);
    }
    Ok(())
}

/// Which of [`nesting_depth_bound_violation`]'s two bounds was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NestingViolation {
    FlowDepth(usize),
    IndentWidth(usize),
}

/// A cheap, `serde_yaml`-independent, line-oriented pass over the raw text
/// that rejects two shapes of pathological nesting *before* the text is
/// handed to `serde_yaml` at all: `[`/`{` flow-collection depth beyond
/// [`MAX_FLOW_NESTING_DEPTH`], and any line whose leading whitespace
/// exceeds [`MAX_LEADING_INDENT_CHARS`]. Returns the specific violation, or
/// `None` if the document stays within both bounds.
///
/// # This is best-effort defence in depth, not a security boundary
///
/// (Fix round 3 on Task 10, finding H2, after two earlier versions of this
/// doc comment claimed soundness properties that execution then falsified
/// — see the module doc comment for the full history.) Fix round 3 said
/// "the actual bound on untrusted-input cost is [`MAX_YAML_BYTES`]"; that
/// is retracted too. Task X1 added [`MAX_EXPANDED_WEIGHT`], which bounds the
/// *number of nodes* the expansion stage walks — not that stage's work, and
/// not this stage at all: nothing bounds the cost of tokenizing raw text into
/// `serde_yaml`'s event list, which is what this function is a partial,
/// best-effort palliative for. This function exists only to reject the cases
/// it happens to understand cheaply, before paying `serde_yaml`'s cost on
/// them; it is not claimed to catch everything, and a future crafted input
/// finding a new way past it would not be a regression of any promise this
/// function makes.
///
/// **Task 14 (lane W5) update — this claim is unchanged, read carefully.**
/// This function is still best-effort defence in depth, not a security
/// boundary, and the known false positive below is untouched — ruling
/// W5-6 explicitly did not authorize touching it. **The tokenizing cost
/// this comment says nothing bounds is now capped, as of Task 14 fix
/// round 1 (ruling W5-20):** both the typed deserialize and
/// `expansion::check_expansion` — the latter of which used to run
/// entirely in this process, before this function's caller ever reached
/// any out-of-process bound, and pay the same tokenizing cost a second,
/// earlier, unbounded time — now run inside the same
/// `roundhouse_sandbox::bounded_parse`-bounded child (see [`super`]'s
/// module doc's fix-round-1 section). This function itself is still not
/// what closes that: it remains a best-effort pre-parse rejection, not the
/// thing that bounds the cost when it doesn't reject. See `expansion.rs`'s
/// own doc comment and [`super`]'s module doc for the current state.
///
/// # Known false positive (fix round 4 on Task 10): documented, not fixed
///
/// The `depth` counter below is global across lines and counts every
/// `[`/`{` outside a block-scalar body, including ones inside a `#`
/// comment or a quoted scalar, which carry no structural nesting at all.
/// Fix round 3 additionally made [`is_block_scalar_indicator_line`] refuse
/// to recognise a block-scalar opener while `depth > 0` (to close a real
/// bypass). The two together produce an over-rejection round 3 did not
/// have: **one net-unbalanced `[` or `{` anywhere earlier in the document
/// — in a comment, or in a quoted allowlist argument like `"[a-z"` —
/// suppresses block-scalar recognition for the rest of the document, so
/// every later `prompt: |` body is bracket-counted as if it were
/// structure.** A 473-byte document that `serde_yaml` parses without
/// complaint is then rejected as `TooDeeplyNested`; see
/// `known_false_positive_bracket_heavy_prompt_after_an_unbalanced_bracket`
/// in `tests/parse_top_level.rs`, which pins the exact reproduction.
///
/// **Left unfixed deliberately.** Every candidate fix (skip comment lines
/// when counting; reset `depth` at column 0) is another text heuristic of
/// exactly the kind that has been bypassed three times in this module, and
/// each trades a rare false positive for a fresh chance at a false
/// negative. Since this scan is best-effort defence in depth and not a
/// boundary, its false-positive rate is a usability property, not a
/// security one — and tripping it requires 256 opening brackets that the
/// counter never cancels. *Well-nested* content — `[a-z]`, `- [x]`,
/// `[text](url)`, `[INFO]`, JSON examples in a prompt — cancels and never
/// accumulates. Note the precise condition: it is well-nestedness, not
/// mere balance. Because `depth` uses `saturating_sub(1)`, closes that
/// arrive ahead of their opens clamp at zero rather than going negative,
/// so a globally *balanced* but ill-nested run (`]]]…[[[`) still
/// accumulates. That shape is contrived, and it is in the over-rejection
/// direction, but the distinction is worth stating rather than rounding
/// off to "balanced". The error message names the bound, so an author who
/// somehow hits it can see why.
///
/// It still does not track quote state (an earlier version did, and a
/// quote character in an entirely ordinary position — `name: don't` — could
/// desynchronize it permanently). Every `[`/`{`/`]`/`}` outside a
/// block-scalar body counts toward `depth`, including ones that happen to
/// sit inside a quoted flow scalar — this can over-count (occasionally
/// rejecting a document with an unusually bracket-heavy quoted scalar,
/// mitigated by [`MAX_FLOW_NESTING_DEPTH`]'s 256 headroom), but a bracket
/// that never gets to the counter at all (this scan's actual failure mode
/// twice now) is the more serious direction.
///
/// The one content this scan skips outright is a block scalar's body
/// (`is_block_scalar_indicator_line` / the `in_block_scalar` handling
/// below): `serde_yaml` itself decides where such a body ends purely by
/// indentation (strictly more indented than the line that opened it, or
/// blank), so this scan uses the identical rule. That rule itself is
/// sound — the risk was never in "what is a block-scalar body," it was in
/// correctly recognising when one starts; see
/// `is_block_scalar_indicator_line`'s own doc comment for round 3's
/// hardening of that specific detector.
fn nesting_depth_bound_violation(yaml: &str) -> Option<NestingViolation> {
    let mut depth: usize = 0;
    let mut in_block_scalar = false;
    let mut block_scalar_parent_indent: usize = 0;

    for line in yaml.split('\n') {
        let indent = line.chars().take_while(|&c| c == ' ' || c == '\t').count();
        let trimmed = line.trim();

        if in_block_scalar {
            if trimmed.is_empty() {
                continue; // a blank line never ends a block scalar
            }
            if indent > block_scalar_parent_indent {
                continue; // still inside the block scalar's body — not scanned at all
            }
            in_block_scalar = false; // this line is at or below the parent's indentation: the block ended before it
        }

        if indent > MAX_LEADING_INDENT_CHARS {
            return Some(NestingViolation::IndentWidth(indent));
        }

        if is_block_scalar_indicator_line(trimmed, depth) {
            in_block_scalar = true;
            block_scalar_parent_indent = indent;
            // The indicator itself (`prompt: |`) carries no brackets of its
            // own interest, but scan it anyway below for uniformity — a
            // key name could theoretically carry a stray `[`/`{`.
        }

        for c in line.chars() {
            match c {
                '[' | '{' => {
                    depth += 1;
                    if depth > MAX_FLOW_NESTING_DEPTH {
                        return Some(NestingViolation::FlowDepth(depth));
                    }
                }
                ']' | '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }

    None
}

/// True if `trimmed` (a line with leading whitespace already stripped) is
/// exactly a YAML block-scalar indicator (`|` or `>`), optionally followed
/// by a chomping indicator (`+`/`-`) and/or an explicit indentation digit
/// (`1`-`9`) in either order — the value-position content of a `key: |`,
/// `key: |-2`, or `- |` line, ignoring a trailing `# comment`.
///
/// `depth_before_line` is the bracket-nesting depth carried into this line
/// from everything scanned so far (i.e. before this line's own `[`/`{`/
/// `]`/`}` characters are counted).
///
/// # Fix round 3 on Task 10, finding H2 (defence in depth, not soundness)
///
/// An earlier version found the indicator with a bare
/// `without_comment.rfind(':')` over the *whole* line, with no concept of
/// where the line actually sits structurally. Both review lenses
/// independently found the same two ways that went wrong, and both are
/// really the same underlying mistake (a colon match with no awareness of
/// context):
/// - **A pure-comment line** (`# x: |`) has a colon in ordinary comment
///   prose, which used to be read as a real mapping-value indicator,
///   opening (bogus) block-scalar mode for the rest of the document.
/// - **A colon inside an unclosed flow collection opened earlier on the
///   *same* line** (`items: ["note: |`) used to be read the same way,
///   even though YAML has no block scalars in flow context at all.
///
/// This version closes both, still without needing to track quote state
/// (that's exactly what fix round 2 removed, for good reason — see the
/// module doc comment): a line starting with `#` is never a value
/// position, full stop; and the colon this function keys off of must be
/// the last one that sits at this line's own top level (`depth_before_line`
/// plus this line's own bracket changes up to that point equal to zero),
/// not merely the last colon found anywhere in the line's text.
fn is_block_scalar_indicator_line(trimmed: &str, depth_before_line: usize) -> bool {
    if depth_before_line > 0 {
        // Still inside a flow collection opened on an earlier line — YAML
        // has no block scalars in flow context, so nothing on this line
        // (which is itself flow-collection content) can open one.
        return false;
    }
    if trimmed.starts_with('#') {
        return false; // a pure-comment line is never a value position
    }

    // A block-scalar indicator can only legally be followed by whitespace,
    // its own modifier characters, or a comment before the newline — a
    // trailing `# comment` is stripped the same simple way regardless
    // (this heuristic is only used to *detect* the indicator, never to
    // decide what counts as a bracket, so a false negative here just means
    // a block scalar's body gets bracket-scanned like ordinary text, which
    // is the over-counting/over-rejection direction, not a bypass).
    let without_comment = strip_trailing_comment(trimmed);

    // Track bracket depth *within this line* to find the last colon that
    // sits at the line's own top level (depth zero) — a colon inside a
    // `{...}`/`[...]` opened earlier on this same line is a nested key,
    // not a mapping-value indicator.
    let mut local_depth: i64 = 0;
    let mut top_level_colon_idx: Option<usize> = None;
    for (i, c) in without_comment.char_indices() {
        match c {
            '[' | '{' => local_depth += 1,
            ']' | '}' => local_depth = (local_depth - 1).max(0),
            ':' if local_depth == 0 => top_level_colon_idx = Some(i),
            _ => {}
        }
    }

    let value_part = if let Some(idx) = top_level_colon_idx {
        without_comment[idx + 1..].trim()
    } else if let Some(rest) = without_comment.strip_prefix("- ") {
        rest.trim()
    } else {
        without_comment.trim()
    };

    is_block_scalar_indicator_token(value_part)
}

fn strip_trailing_comment(line: &str) -> &str {
    match line.find(" #") {
        Some(idx) => line[..idx].trim_end(),
        None => line,
    }
}

fn is_block_scalar_indicator_token(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some('|') | Some('>') => {}
        _ => return false,
    }
    let rest: &str = chars.as_str();
    if rest.len() > 2 {
        return false;
    }
    let mut seen_digit = false;
    let mut seen_chomp = false;
    for c in rest.chars() {
        match c {
            '+' | '-' if !seen_chomp => seen_chomp = true,
            '1'..='9' if !seen_digit => seen_digit = true,
            _ => return false,
        }
    }
    true
}
