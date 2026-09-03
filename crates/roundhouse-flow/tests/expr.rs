use roundhouse_flow::expr::{
    eval, eval_delimited_expression, interpolate, interpolate_json, ExprContext, ExprError,
    ExpressionSource, JsonTemplateSource, TemplateSource,
};
use serde_json::{json, Value};

fn ctx() -> ExprContext {
    let mut c = ExprContext::new();
    c.set_public("inputs", json!({"repo": "acme/widgets", "max_prs": 10}));
    c.set_public(
        "steps",
        json!({
            "list_prs": { "output": [{"number": 1}, {"number": 2}, {"number": 3}] },
            "review": { "output": { "findings": [{"id": "a"}] } }
        }),
    );
    c
}

// ---- Brief's Step 1 tests, verbatim ----

#[test]
fn property_access_and_indexing() {
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("inputs.repo"), &ctx())
            .unwrap()
            .value,
        json!("acme/widgets")
    );
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("steps.list_prs.output[0].number"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(1)
    );
}

#[test]
fn ternary_and_len() {
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("len(steps.review.output.findings) > 0"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(true)
    );
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file(
                "len(steps.review.output.findings) > 0 ? 'has findings' : 'clean'"
            ),
            &ctx()
        )
        .unwrap()
        .value,
        json!("has findings")
    );
}

#[test]
fn slice_default_contains_flatten_json_env_are_the_full_function_set() {
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("slice(steps.list_prs.output, 0, 2)"),
            &ctx()
        )
        .unwrap()
        .value,
        json!([{"number":1},{"number":2}])
    );
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("default(missing.field, 'fallback')"),
            &ctx()
        )
        .unwrap()
        .value,
        json!("fallback")
    );
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("contains(inputs.repo, 'widgets')"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(true)
    );
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("flatten([[1,2],[3]])"),
            &ctx()
        )
        .unwrap()
        .value,
        json!([1, 2, 3])
    );
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("json('{\"a\":1}')"),
            &ctx()
        )
        .unwrap()
        .value,
        json!({"a":1})
    );
    std::env::set_var("ROUNDHOUSE_TEST_VAR", "hello");
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("env('ROUNDHOUSE_TEST_VAR')"),
            &ctx()
        )
        .unwrap()
        .value,
        json!("hello")
    );
}

#[test]
fn interpolate_substitutes_expr_blocks_inside_a_larger_string() {
    let out = interpolate(
        TemplateSource::from_workflow_file(
            "Review PR #${{ steps.list_prs.output[0].number }} in ${{ inputs.repo }}",
        ),
        &ctx(),
    )
    .unwrap()
    .into_unredacted_for_dispatch();
    assert_eq!(out, "Review PR #1 in acme/widgets");
}

#[test]
fn interpolate_json_walks_every_string_leaf_of_a_steps_with_block() {
    // §8.9's `with: { method: GET, url: "...${{ inputs.repo }}..." }` — the
    // whole block, not one hand-picked field, must be interpolated, and
    // non-string leaves (numbers, bools, nesting) must pass through
    // untouched (finding 8: this is the fix that makes ${{ inputs.* }} in
    // the reference workflow evaluate to something other than Null).
    let with = json!({
        "method": "GET",
        "url": "https://api.github.com/repos/${{ inputs.repo }}/pulls",
        "retries": 3,
        "headers": { "Accept": "application/vnd.github+json" }
    });
    let resolved = interpolate_json(JsonTemplateSource::from_workflow_file(&with), &ctx())
        .unwrap()
        .into_unredacted_for_dispatch();
    assert_eq!(
        resolved["url"],
        json!("https://api.github.com/repos/acme/widgets/pulls")
    );
    assert_eq!(resolved["method"], json!("GET"));
    assert_eq!(resolved["retries"], json!(3));
    assert_eq!(
        resolved["headers"]["Accept"],
        json!("application/vnd.github+json")
    );
}

// ---- `value_to_string`'s object/array rendering (review round 1, code
// lens Minor 2): reasonable, but unspecified by the brief and previously
// untested. Pinned here. ----

#[test]
fn interpolating_an_object_or_array_value_renders_it_as_compact_json() {
    let mut c = ExprContext::new();
    c.set_public("obj", json!({"a": 1, "b": [1, 2]}));
    c.set_public("arr", json!([1, "two", null]));
    assert_eq!(
        interpolate(TemplateSource::from_workflow_file("${{ obj }}"), &c)
            .unwrap()
            .into_unredacted_for_dispatch(),
        r#"{"a":1,"b":[1,2]}"#
    );
    assert_eq!(
        interpolate(TemplateSource::from_workflow_file("${{ arr }}"), &c)
            .unwrap()
            .into_unredacted_for_dispatch(),
        r#"[1,"two",null]"#
    );
}

// ---- Additional coverage for this task's identified risks ----

#[test]
fn unknown_function_is_a_typed_error() {
    let err = eval(ExpressionSource::from_workflow_file("nope(1)"), &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::UnknownFunction(name) if name == "nope"));
}

#[test]
fn trailing_garbage_is_rejected() {
    let err = eval(
        ExpressionSource::from_workflow_file("inputs.repo extra"),
        &ctx(),
    )
    .unwrap_err();
    assert!(matches!(err, ExprError::UnexpectedToken(_, _)));
}

#[test]
fn comparisons_and_equality_operators_work() {
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("1 == 1"), &ctx())
            .unwrap()
            .value,
        json!(true)
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("1 != 2"), &ctx())
            .unwrap()
            .value,
        json!(true)
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("2 >= 2"), &ctx())
            .unwrap()
            .value,
        json!(true)
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("1 <= 0"), &ctx())
            .unwrap()
            .value,
        json!(false)
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("'a' == 'a'"), &ctx())
            .unwrap()
            .value,
        json!(true)
    );
}

#[test]
fn missing_root_and_missing_field_resolve_to_null_not_an_error() {
    // `default()`'s whole purpose depends on a missing path resolving to
    // Null rather than erroring.
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("missing"), &ctx())
            .unwrap()
            .value,
        json!(null)
    );
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("inputs.nonexistent"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(null)
    );
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("inputs.nonexistent.deeper.still"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(null)
    );
}

#[test]
fn array_literal_and_nested_indexing() {
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("[1,2,3][1]"), &ctx())
            .unwrap()
            .value,
        json!(2)
    );
}

#[test]
fn integer_literals_compare_equal_to_context_data_regardless_of_number_representation() {
    // steps.list_prs.output[0].number came from `json!(1)` (an int-backed
    // Number); a float-backed context value (e.g. `map.over` item data
    // that happened to serialize as `1.0`) must compare equal to the same
    // literal too — `==`/`!=` must not be representation-sensitive.
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("steps.list_prs.output[0].number == 1"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(true)
    );
    let mut c = ctx();
    c.set_public("float_one", json!(1.0));
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("float_one == 1"), &c)
            .unwrap()
            .value,
        json!(true)
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("float_one != 1"), &c)
            .unwrap()
            .value,
        json!(false)
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("float_one == 2"), &c)
            .unwrap()
            .value,
        json!(false)
    );
}

// ---- Unterminated string literal: verified to panic in the brief's own
// illustrative code (byte-index-out-of-bounds on `expr[p.pos..]` once
// `pos` runs past the end of the string) before this task fixed it. Must
// be a typed error, not a crash. ----

#[test]
fn unterminated_string_literal_is_a_typed_error_not_a_panic() {
    let err = eval(ExpressionSource::from_workflow_file("'abc"), &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::Unterminated));
}

#[test]
fn unterminated_string_literal_inside_a_larger_expression_is_a_typed_error() {
    // The opening quote before "abc" never finds a matching closing quote
    // anywhere in the rest of the expression.
    let err = eval(
        ExpressionSource::from_workflow_file("default('abc, x)"),
        &ctx(),
    )
    .unwrap_err();
    assert!(matches!(err, ExprError::Unterminated));
}

// ---- Risk 3: untrusted `map.over` data reaching the context; size, depth,
// and non-ASCII content. ----

#[test]
fn large_string_context_values_evaluate_without_error() {
    let mut c = ExprContext::new();
    let big = "x".repeat(200_000);
    c.set_public("pr", json!({"title": big.clone()}));
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("pr.title"), &c)
            .unwrap()
            .value,
        json!(big)
    );
}

#[test]
fn deeply_nested_context_values_are_indexed_by_direct_path_without_walking_the_whole_tree() {
    // Build a 500-level-deep object; the expression only asks for one
    // fixed path through it, so evaluating it should not depend on
    // whatever else the object contains at sibling positions.
    let mut inner = json!("bottom");
    for _ in 0..500 {
        inner = json!({ "next": inner });
    }
    let mut c = ExprContext::new();
    c.set_public("pr", inner);
    let mut path = String::from("pr");
    for _ in 0..500 {
        path.push_str(".next");
    }
    assert_eq!(
        eval(ExpressionSource::from_workflow_file(&path), &c)
            .unwrap()
            .value,
        json!("bottom")
    );
}

#[test]
fn non_ascii_context_values_round_trip_through_property_access_and_interpolation() {
    let mut c = ExprContext::new();
    c.set_public(
        "pr",
        json!({"title": "Fix \u{1F41B} in \u{00e9}migr\u{00e9} module — “quoted”"}),
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("pr.title"), &c)
            .unwrap()
            .value,
        json!("Fix \u{1F41B} in \u{00e9}migr\u{00e9} module — “quoted”")
    );
    let out = interpolate(
        TemplateSource::from_workflow_file("Title: ${{ pr.title }}"),
        &c,
    )
    .unwrap()
    .into_unredacted_for_dispatch();
    assert_eq!(
        out,
        "Title: Fix \u{1F41B} in \u{00e9}migr\u{00e9} module — “quoted”"
    );
}

#[test]
fn context_value_containing_the_expression_delimiter_itself_is_not_special() {
    // A `map.over` item field containing literal `${{` text (e.g. a PR
    // title someone typed `${{ }}` into) must read back as plain data when
    // accessed via property access — this is not `interpolate`, so there
    // is nothing to substitute.
    let mut c = ExprContext::new();
    c.set_public("pr", json!({"title": "look: ${{ secrets.GH_TOKEN }}"}));
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("pr.title"), &c)
            .unwrap()
            .value,
        json!("look: ${{ secrets.GH_TOKEN }}")
    );
}

// ---- Risk 3 / module doc: single-pass substitution, no re-evaluation of
// substituted output (template-injection). ----

#[test]
fn interpolation_is_single_pass_and_does_not_re_evaluate_substituted_output() {
    // `json()` decodes the JSON string literal's own `\"` escapes into a
    // value that, once substituted, looks exactly like a second `${{ }}`
    // expression. A re-evaluating (multi-pass) implementation would try to
    // evaluate `${{ inputs.repo }}` a second time and produce
    // "acme/widgets" in the output; a single-pass one leaves it as literal
    // text.
    let out = interpolate(
        TemplateSource::from_workflow_file(r#"payload: ${{ json('"${{ inputs.repo }}"') }}"#),
        &ctx(),
    )
    .unwrap()
    .into_unredacted_for_dispatch();
    assert_eq!(out, "payload: ${{ inputs.repo }}");
}

#[test]
fn a_literal_expression_delimiter_produced_by_one_substitution_does_not_feed_a_later_one() {
    // Two placeholders in one template: the first's substituted output
    // contains a literal, unpaired-looking `${{`, but the *template's own*
    // second placeholder (after it, in the original text) must still be
    // evaluated normally — proving the scan resumes in the original
    // template, not inside what was just written.
    let mut c = ExprContext::new();
    c.set_public("a", json!("${{"));
    c.set_public("b", json!("real"));
    let out = interpolate(
        TemplateSource::from_workflow_file("${{ a }} then ${{ b }}"),
        &c,
    )
    .unwrap()
    .into_unredacted_for_dispatch();
    assert_eq!(out, "${{ then real");
}

// ---- Unpaired `${{` is a deliberate error, not left literal. ----

#[test]
fn an_unpaired_opening_delimiter_is_an_error() {
    let err = interpolate(
        TemplateSource::from_workflow_file("prefix ${{ inputs.repo without a closer"),
        &ctx(),
    )
    .unwrap_err();
    assert!(matches!(err, ExprError::Unterminated));
}

#[test]
fn text_with_no_delimiter_at_all_passes_through_unchanged() {
    let out = interpolate(
        TemplateSource::from_workflow_file("plain text, no expressions here"),
        &ctx(),
    )
    .unwrap()
    .into_unredacted_for_dispatch();
    assert_eq!(out, "plain text, no expressions here");
}

// ---- `find_closing_delimiter` correctness (review round 1, code lens):
// an unterminated quote inside one block must not "borrow" a closing
// quote from ordinary prose after that block's own intended end, silently
// merging it with a later, well-formed block. ----

#[test]
fn an_apostrophe_in_prose_between_two_blocks_does_not_merge_them() {
    // Exact repro from review round 1: block one's string literal never
    // closes before its own `}}`; before the fix, the apostrophe in "it's"
    // (ordinary prose, not expression syntax) was accepted as the closing
    // quote, which then let the scan consume straight through a second,
    // well-formed `${{ inputs.repo }}` placeholder and misattribute the
    // resulting parse error to unrelated prose text
    // (`UnexpectedToken(28, "'s own apostrophe ${{ inputs.repo")`).
    // After the fix, the apostrophe is rejected as a candidate close
    // (what follows it, "s own apostrophe...", is not a plausible
    // expression continuation), no other quote character exists in the
    // rest of the input, and the correct diagnosis is that block one's
    // string is genuinely unterminated.
    let err = interpolate(
        TemplateSource::from_workflow_file(
            "${{ 'oops }} plain text with it's own apostrophe ${{ inputs.repo }}",
        ),
        &ctx(),
    )
    .unwrap_err();
    assert!(matches!(err, ExprError::Unterminated));
}

#[test]
fn an_open_quote_can_still_silently_absorb_a_later_block_when_the_forgery_looks_syntactically_valid(
) {
    // Open question from review round 1 ruling P17: can a crafted template
    // make a cross-block quote-merge parse *cleanly*, silently absorbing a
    // well-formed second block into a string value with no error at all?
    // Yes — constructed deliberately, not accidentally encountered. Block
    // one's own string literal never closes before its intended `}}`, but
    // the *next* occurrence of `'` in the template happens to be placed
    // right before a `}}`, which is exactly the shape
    // `looks_like_a_real_string_close` is designed to accept (a string
    // immediately followed by the block terminator is completely normal,
    // e.g. `${{ 'hello' }}`). The fix in this round narrows the specific
    // apostrophe-in-prose shape above; it cannot and does not close this
    // general hole, because this grammar has no escape mechanism at all —
    // any quote character in prose can be made to look like a legitimate
    // close by whoever writes the template, and a purely local lookahead
    // cannot distinguish "intentional data" from "accidental forgery" once
    // both are followed by the same plausible-looking byte. This residual
    // is real, is not fixed here, and is recorded rather than papered
    // over — see `find_closing_delimiter`'s doc comment for the full
    // reasoning and what closing it for real would require.
    let mut c = ExprContext::new();
    c.set_public("real", json!("REAL_VALUE"));
    let out = interpolate(
        TemplateSource::from_workflow_file(
            "${{ 'oops }} filler ${{ real }} trailing' }} rest of template",
        ),
        &c,
    )
    .unwrap()
    .into_unredacted_for_dispatch();
    // No error at all, and `real` was never evaluated: its own `${{ }}`
    // markers survive as literal characters inside the absorbed string,
    // exactly as if the whole first block had been one intentional
    // string literal.
    assert_eq!(out, "oops }} filler ${{ real }} trailing rest of template");
    assert!(!out.contains("REAL_VALUE"));
}

// ---- Cost: recursion-depth guard against nested-bracket stack overflow. ----

#[test]
fn deeply_nested_array_literals_within_the_depth_limit_evaluate() {
    let depth = 40;
    let mut expr = String::new();
    for _ in 0..depth {
        expr.push('[');
    }
    expr.push('1');
    for _ in 0..depth {
        expr.push(']');
    }
    // Index through every level with [0] to unwrap back down to the 1.
    let mut access = expr.clone();
    for _ in 0..depth {
        access.push_str("[0]");
    }
    assert_eq!(
        eval(ExpressionSource::from_workflow_file(&access), &ctx())
            .unwrap()
            .value,
        json!(1)
    );
}

#[test]
fn excessive_bracket_nesting_is_a_typed_error_not_a_stack_overflow() {
    let depth = 5_000;
    let mut expr = String::new();
    for _ in 0..depth {
        expr.push('[');
    }
    expr.push('1');
    for _ in 0..depth {
        expr.push(']');
    }
    let err = eval(ExpressionSource::from_workflow_file(&expr), &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::ExpressionTooDeep(_)));
}

#[test]
fn excessive_ternary_chaining_is_a_typed_error_not_a_stack_overflow() {
    let depth = 5_000;
    let mut expr = String::new();
    for _ in 0..depth {
        expr.push_str("true ? ");
    }
    expr.push('1');
    for _ in 0..depth {
        expr.push_str(" : 0");
    }
    let err = eval(ExpressionSource::from_workflow_file(&expr), &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::ExpressionTooDeep(_)));
}

#[test]
fn excessive_function_call_nesting_is_a_typed_error_not_a_stack_overflow() {
    let depth = 5_000;
    let mut expr = String::new();
    for _ in 0..depth {
        expr.push_str("default(");
    }
    expr.push('1');
    expr.push_str(", 2");
    for _ in 0..depth {
        expr.push(')');
    }
    let err = eval(ExpressionSource::from_workflow_file(&expr), &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::ExpressionTooDeep(_)));
}

// ---- Cost: flat (non-nested) expressions are roughly linear, not
// quadratic, in their own length — measured, not assumed. Split into two
// tests (review round 1, Minor 1 + S-Imp-1): the original test's name
// claimed to cover "long flat expressions" generally, but its shape (a bare
// `pr.next.next...` chain rooted directly at a `ctx` variable) only ever
// exercises the *borrowed* path through `parse_primary_chain`. The *owned*
// path — reached once a chain's root has already left `ctx`'s borrow, e.g.
// via `default(...)` — had its own, separate quadratic defect (S-Imp-1),
// which this borrowed-only test could not have caught and did not claim
// to.
//
// Fix round 2, item 4: both tests used to compare wall-clock time at two
// depths against an identical `< 40.0x` ratio — the same fragile shape
// twice, which is what round 1's own brief asked to move away from and
// round 2 faulted for doubling instead of reducing. Two non-wall-clock
// alternatives were considered and rejected, for concrete reasons, not by
// default:
//
// - **An allocation-byte-count via a custom `#[global_allocator]`** would
//   measure the real defect directly (a per-step whole-remaining-subtree
//   clone allocates memory proportional to what it clones, which a timer
//   only sees indirectly) — this was actually implemented and measured
//   during this fix round, and it worked. It was reverted because it
//   requires `unsafe impl GlobalAlloc`, and this workspace forbids unsafe
//   code everywhere via a workspace-level lint (`unsafe_code = "forbid"` in
//   the root `Cargo.toml`, applied here through `[lints] workspace = true`)
//   — confirmed by actually attempting the build, not assumed: `cargo test`
//   on the implementation rejected it with "implementation of an `unsafe`
//   method ... requested on the command line with `-F unsafe-code`". This is
//   a hard constraint recorded in `AGENTS.md` ("`#![forbid(unsafe_code)]`
//   everywhere except one confined module in `roundhouse-sandbox`"), not a
//   style preference this fix round can waive for its own test binary.
// - **A hand-rolled operation counter** (e.g. a `#[cfg(test)]` `Cell<usize>`
//   incremented inside `index_field`/`index_array`) was considered and
//   rejected on a different ground: counting *how many times* the
//   owned-chain arms run is `O(depth)` in both the fixed and the pre-fix
//   code — the defect was never about call *count*, it was about the *size*
//   of what each call cloned. A counter that only counts calls would not
//   actually detect a regression back to `.cloned()`; it would report the
//   same fixed, small number in both cases and pass either way, which is
//   worse than the flake it would replace: a green test that cannot fail on
//   the exact regression it exists to catch, right up until someone
//   trusts it.
//
// What is done instead: each measurement below takes the **minimum** of
// several repeated timings at each depth (noise from CPU scheduling or
// machine load can only ever add time, never subtract it, so the minimum
// across repetitions converges toward the noise-free cost — the same
// technique benchmarking harnesses such as Criterion use), and the depth
// ratio between the two measurements is widened well past what round 1
// used, so that expected-linear and would-be-quadratic scaling separate by
// orders of magnitude rather than by single-digit multiples, leaving a wide
// dead zone in between for the assertion threshold to sit in without being
// close to either. Still wall-clock, and said so plainly rather than
// re-labelled — but a materially more robust measurement of the same
// property, not a second copy of the fragile one. ----

/// Runs `f` `tries` times and returns the minimum elapsed duration —
/// scheduling noise and machine load can only slow a given run down, never
/// speed it up, so the minimum across several tries is the closest available
/// approximation of the noise-free cost. See the block comment above for why
/// this replaces a single-shot wall-clock measurement here.
fn min_elapsed(tries: usize, mut f: impl FnMut()) -> std::time::Duration {
    (0..tries)
        .map(|_| {
            let start = std::time::Instant::now();
            f();
            start.elapsed()
        })
        .min()
        .expect("tries > 0")
}

#[test]
fn long_flat_expressions_over_the_borrowed_chain_path_do_not_show_quadratic_blowup() {
    // A deeply chained-but-flat property access: `pr.next.next...next`,
    // rooted directly at the `pr` context variable so every step stays on
    // the `Cow::Borrowed` path. This exercises parse_primary_chain's loop,
    // never parse_ternary's recursion, so it is not bounded by
    // MAX_EXPR_DEPTH and is the right shape to check for length-driven
    // quadratic cost on this specific path.
    fn time_chain(depth: usize) -> std::time::Duration {
        let mut inner = json!("bottom");
        for _ in 0..depth {
            inner = json!({ "next": inner });
        }
        let mut c = ExprContext::new();
        c.set_public("pr", inner);
        let mut path = String::from("pr");
        for _ in 0..depth {
            path.push_str(".next");
        }
        min_elapsed(9, || {
            let _ = eval(ExpressionSource::from_workflow_file(&path), &c)
                .unwrap()
                .value;
        })
    }

    // Depths kept well under the ~2,000-4,000-level range where a
    // deeply-nested `serde_json::Value`'s own recursive `Drop` impl can
    // overflow the stack on its own (measured separately, unrelated to
    // this parser — see the module doc comment's "Cost" section) so this
    // test measures parsing/evaluation cost, not `Value`'s drop cost.
    let small = time_chain(80);
    let large = time_chain(1_600); // 20x the length
    let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-9);
    // A linear implementation lands near 20x; a quadratic one lands near
    // 400x. 150x sits in the wide gap between the two rather than close to
    // either, so ordinary noise on a linear run (even several-fold, which
    // min-of-9 already suppresses) cannot cross it.
    assert!(
        ratio < 150.0,
        "expected roughly linear scaling (~20x for a 20x length increase), measured {ratio}x \
         (small={small:?}, large={large:?})"
    );
}

#[test]
fn long_flat_expressions_over_the_owned_chain_path_do_not_show_quadratic_blowup() {
    // Regression for S-Imp-1: `default(missing, pr)` flips the chain's root
    // from `Cow::Borrowed` to `Cow::Owned` (since `default` always returns
    // an owned `Value`), then `.next` is walked `depth` times entirely on
    // the owned path — the exact shape whose `index_field`/`index_array`
    // used to clone the whole remaining subtree at every step. See the
    // module doc comment's "Cost" section for the measured before/after
    // numbers this test is a permanent, CI-safe stand-in for (that
    // exploration used explicit byte padding and a standalone release
    // harness to get precise figures; this test just has to keep failing
    // if the quadratic behavior comes back).
    fn time_owned_chain(depth: usize) -> std::time::Duration {
        let mut inner = json!("bottom");
        for _ in 0..depth {
            inner = json!({ "next": inner, "pad": "x".repeat(200) });
        }
        let mut c = ExprContext::new();
        c.set_public("pr", inner);
        let mut path = String::from("default(missing, pr)");
        for _ in 0..depth {
            path.push_str(".next");
        }
        min_elapsed(9, || {
            let _ = eval(ExpressionSource::from_workflow_file(&path), &c)
                .unwrap()
                .value;
        })
    }

    let small = time_owned_chain(30);
    let large = time_owned_chain(600); // 20x the length
    let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-9);
    // Same widened margin and same reasoning as the borrowed-path test
    // above: ~20x expected for linear scaling, ~400x for a quadratic
    // regression, 150x sitting well clear of both.
    assert!(
        ratio < 150.0,
        "expected roughly linear scaling (~20x for a 20x length increase) on the owned chain \
         path, measured {ratio}x (small={small:?}, large={large:?})"
    );
}

// ---- Secrets: this module cannot tell a secret apart from any other
// value, so it must not leak whatever it is handed via Debug. ----

#[test]
fn expr_context_debug_never_prints_bound_values() {
    let mut c = ExprContext::new();
    c.set_public(
        "secrets",
        json!({"GH_TOKEN": "super-secret-value-should-not-print"}),
    );
    c.set_public("inputs", json!({"repo": "acme/widgets"}));
    let debug_output = format!("{c:?}");
    assert!(!debug_output.contains("super-secret-value-should-not-print"));
    assert!(!debug_output.contains("acme/widgets"));
    // The root names themselves are not secret and are allowed to appear.
    assert!(debug_output.contains("secrets"));
    assert!(debug_output.contains("inputs"));
}

#[test]
fn expr_error_never_embeds_a_context_value() {
    let mut c = ExprContext::new();
    c.set_public(
        "secrets",
        json!({"GH_TOKEN": "super-secret-value-should-not-print"}),
    );
    // Trigger a variety of error paths and confirm none of them echo the
    // secret value back in the error's Display text.
    let errs = [
        eval(
            ExpressionSource::from_workflow_file("nope(secrets.GH_TOKEN)"),
            &c,
        )
        .unwrap_err()
        .to_string(),
        eval(
            ExpressionSource::from_workflow_file("secrets.GH_TOKEN )"),
            &c,
        )
        .unwrap_err()
        .to_string(),
        eval(
            ExpressionSource::from_workflow_file("json(secrets.GH_TOKEN)"),
            &c,
        )
        .unwrap_err()
        .to_string(),
    ];
    for e in errs {
        assert!(
            !e.contains("super-secret-value-should-not-print"),
            "error text leaked a context value: {e}"
        );
    }
}

// ---- `env()` reads the real process environment, not a workflow-scoped
// view — documented residual, pinned so it is a recorded choice. ----

#[test]
fn env_function_reads_the_real_process_environment_documented_residual() {
    std::env::set_var("ROUNDHOUSE_TEST_ENV_RESIDUAL", "process-wide-value");
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("env('ROUNDHOUSE_TEST_ENV_RESIDUAL')"),
            &ctx()
        )
        .unwrap()
        .value,
        json!("process-wide-value")
    );
}

#[test]
fn env_function_returns_null_for_an_unset_variable() {
    std::env::remove_var("ROUNDHOUSE_TEST_ENV_DEFINITELY_UNSET");
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("env('ROUNDHOUSE_TEST_ENV_DEFINITELY_UNSET')"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(null)
    );
}

// ---- `json()` can decode escapes into control characters not literally
// present in the source text — documented residual, pinned. ----

#[test]
fn json_function_can_decode_escapes_into_control_characters_documented_residual() {
    let out = eval(
        ExpressionSource::from_workflow_file(r#"json('"a\nb"')"#),
        &ctx(),
    )
    .unwrap()
    .value;
    assert_eq!(out, json!("a\nb"));
    if let Value::String(s) = out {
        assert!(s.contains('\n'));
    } else {
        panic!("expected a string");
    }
}

#[test]
fn json_function_rejects_invalid_json_as_a_typed_error() {
    let err = eval(
        ExpressionSource::from_workflow_file("json('not json')"),
        &ctx(),
    )
    .unwrap_err();
    assert!(matches!(err, ExprError::Json(_)));
    // Strengthened per review round 1 (S-Min-4): the rendered text is a
    // fixed category string, not `serde_json::Error`'s own `Display` (which
    // would include a line/column derived from the input).
    assert_eq!(
        err.to_string(),
        "json() argument is not valid JSON (syntax error)"
    );
}

#[test]
fn json_error_never_carries_a_byte_offset_derived_from_the_argument_length() {
    // Regression for S-Min-4: `json()`'s argument is any expression, so
    // `json(secrets.TOKEN)` is valid syntax, and `serde_json::Error`'s own
    // `Display` echoes a line/column that is a property of the secret's
    // own length, not its bytes. These are the exact two shapes review
    // round 1 measured leaking "column 13" (the secret's exact length,
    // classified `Eof`) and "column 6" (the length of its leading numeric
    // run, classified `Syntax`) before this fix.
    let mut c = ExprContext::new();
    c.set_public(
        "secrets",
        json!({"a": "\"unterminated", "b": "12345abcdef"}),
    );
    let eof_err = eval(ExpressionSource::from_workflow_file("json(secrets.a)"), &c)
        .unwrap_err()
        .to_string();
    let syntax_err = eval(ExpressionSource::from_workflow_file("json(secrets.b)"), &c)
        .unwrap_err()
        .to_string();
    for msg in [&eof_err, &syntax_err] {
        assert!(!msg.contains("column"), "leaked a column offset: {msg}");
        assert!(
            !msg.chars().any(|c| c.is_ascii_digit()),
            "leaked a digit derived from the secret's length: {msg}"
        );
    }
    assert_eq!(
        eof_err,
        "json() argument is not valid JSON (unexpected end of input)"
    );
    assert_eq!(
        syntax_err,
        "json() argument is not valid JSON (syntax error)"
    );
}

// ---- Case sensitivity: identifiers are looked up by exact byte string,
// matching Task 3's case-sensitive reserved-root check on `map.as`. ----

#[test]
fn root_lookup_is_case_sensitive() {
    let mut c = ExprContext::new();
    c.set_public("steps", json!({"real": true}));
    c.set_public("Steps", json!({"shadow": true}));
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("steps.real"), &c)
            .unwrap()
            .value,
        json!(true)
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("Steps.shadow"), &c)
            .unwrap()
            .value,
        json!(true)
    );
    // The two roots never collide: asking the "wrong-case" root for the
    // other's field resolves to Null, not a cross-read.
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("steps.shadow"), &c)
            .unwrap()
            .value,
        json!(null)
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("Steps.real"), &c)
            .unwrap()
            .value,
        json!(null)
    );
}

// ---- `eval` carries the same P20 trust assertion as `interpolate` /
// `interpolate_json` (ruling P22, fix round 3, item 1). `eval` is `pub`,
// takes an expression with no `${{ }}` delimiters at all, and was the
// shortest path to the P20 abuse before this fix (measured on HEAD with a
// planted key: `eval("env('ANTHROPIC_API_KEY')", &ctx)` returned the
// daemon's provider key — see `expr.rs`'s `ExpressionSource` doc comment).
// This test does not re-plant a real-looking secret name (deliberately: a
// test that reads `env('ANTHROPIC_API_KEY')` for real would depend on
// whatever happens to be in *this* process's own environment, which is
// exactly the residual `expr.rs`'s "`env()` is a second, independent
// secret-exposure surface" section already documents as unowned). It pins
// the type-level assertion instead: `eval` only compiles against an
// `ExpressionSource`, not a bare `&str`, so every caller must go through
// the same greppable `::from_workflow_file` call `interpolate` /
// `interpolate_json` require. ----

#[test]
fn eval_requires_an_expression_source_not_a_bare_str() {
    // If this compiles, `eval` is symmetric with `interpolate` /
    // `interpolate_json` — all three public entry points require the
    // caller to assert workflow-file trust before this module will
    // evaluate their text.
    std::env::set_var("ROUNDHOUSE_TEST_EVAL_TRUST_VAR", "trusted-value");
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("env('ROUNDHOUSE_TEST_EVAL_TRUST_VAR')"),
            &ctx()
        )
        .unwrap()
        .value,
        json!("trusted-value")
    );
}

// ---- Ruling P29 (supersedes P21 and P24): `preserve_order` is ACCEPTED
// workspace-wide — the pinned ACP SDK enables it unconditionally, and
// vendoring it out was considered and rejected. The old
// `preserve_order_feature_is_off` test asserted the feature stayed off,
// which would fail at merge on that approved decision. Its fix-round-2
// replacement, `evaluation_and_interpolation_do_not_depend_on_object_key_insertion_order`,
// was then found VACUOUS (fix round 3, item 6): its payload was two
// `serde_json::Map`s holding `z:1, a:2, m:3` inserted forward and reversed,
// and with `preserve_order` OFF both are the same `BTreeMap` — measured
// iteration order `["a","m","z"]` for both — so every `via_forward ==
// via_reversed` assertion compared a value with itself; with `preserve_order`
// ON, `Map` is an `IndexMap` whose `PartialEq` is order-independent by
// definition. It could not fail on the property it named under either
// setting.
//
// This is its replacement, and its property is genuinely observable: that
// `interpolate_json` associates each *template* key with its own resolved
// value — by key, never by position — when the template's keys are authored
// in a different order from the context object's. Payload: a template
// authored `{"beta_out": "${{ src.beta }}", "alpha_out": "${{ src.alpha }}",
// "gamma_out": "${{ src.gamma }}"}` (b, a, g) against a context object
// authored `{"alpha": "A-VALUE", "gamma": "G-VALUE", "beta": "B-VALUE"}`
// (a, g, b) — three keys, three distinct values, and the two orderings
// disagree at every position. An implementation that paired template keys
// with resolved values by iteration position rather than by key produces a
// different mapping and fails; the assertions are on the parsed structure,
// never on `to_string()` output (STANDING.md, ruling P29). ----

#[test]
fn interpolate_json_associates_template_keys_with_values_by_key_not_by_iteration_position() {
    let mut src = serde_json::Map::new();
    src.insert("alpha".to_string(), json!("A-VALUE"));
    src.insert("gamma".to_string(), json!("G-VALUE"));
    src.insert("beta".to_string(), json!("B-VALUE"));

    let mut ctx = ExprContext::new();
    ctx.set_public("src", Value::Object(src));

    let mut template = serde_json::Map::new();
    template.insert("beta_out".to_string(), json!("${{ src.beta }}"));
    template.insert("alpha_out".to_string(), json!("${{ src.alpha }}"));
    template.insert("gamma_out".to_string(), json!("${{ src.gamma }}"));
    let template = Value::Object(template);

    let out = interpolate_json(JsonTemplateSource::from_workflow_file(&template), &ctx)
        .unwrap()
        .into_unredacted_for_dispatch();

    assert_eq!(
        out,
        json!({"alpha_out": "A-VALUE", "beta_out": "B-VALUE", "gamma_out": "G-VALUE"}),
        "each template key must carry its own resolved value regardless of the order either \
         object's keys were authored in"
    );

    // The same property one level down, where a positional implementation
    // has a second chance to go wrong: a nested object whose keys are in yet
    // another order.
    let mut nested = serde_json::Map::new();
    nested.insert("gamma_out".to_string(), json!("${{ src.gamma }}"));
    nested.insert("beta_out".to_string(), json!("${{ src.beta }}"));
    let nested_template = json!({"inner": Value::Object(nested), "alpha_out": "${{ src.alpha }}"});
    let nested_out = interpolate_json(
        JsonTemplateSource::from_workflow_file(&nested_template),
        &ctx,
    )
    .unwrap()
    .into_unredacted_for_dispatch();
    assert_eq!(
        nested_out,
        json!({"alpha_out": "A-VALUE", "inner": {"beta_out": "B-VALUE", "gamma_out": "G-VALUE"}}),
    );
}

// ---- `7b441b4`'s bare-`}` tightening changes the `ExprError` variant a
// `}`-continuation input produces (fix round 3, m-4): a candidate closing
// quote followed by a lone `}` used to be accepted as a plausible
// continuation (so the scan kept going, found no real `}}`, and the parser
// later raised `UnexpectedToken` on the leftover text); it is now rejected,
// so the scan itself reports `Unterminated`. Strictly information-reducing
// (no secret text differs between the two variants), but a public-API
// behaviour change for any caller matching on `ExprError`, previously
// asserted nowhere. ----

#[test]
fn a_lone_closing_brace_is_unterminated_not_unexpected_token() {
    // `'x'` closes at its second quote; what immediately follows (after
    // whitespace) is a single `}`, not `}}`. Before this fix, a lone `}`
    // was accepted as a plausible continuation, so the string closed here,
    // the scan found the real `}}` two bytes later, and the resulting inner
    // expression `'x' }` failed to *parse* (trailing garbage after the
    // string literal) — `ExprError::UnexpectedToken`. After this fix, the
    // lone `}` is rejected (it is not paired), so the string is treated as
    // still open, no later quote character exists to close it, and the
    // scan itself reports `ExprError::Unterminated` instead — it never
    // reaches the parser at all.
    let err = interpolate(TemplateSource::from_workflow_file("${{ 'x' } }}"), &ctx()).unwrap_err();
    assert!(
        matches!(err, ExprError::Unterminated),
        "expected Unterminated, got {err:?}"
    );
}

// ---- `eval_delimited_expression` (fix round 1, item 4): the form §8.9
// documents for `when:` and `map.over` — a whole field that must be exactly
// one `${{ ... }}` block, evaluated to its own typed `Value` rather than
// stringified the way `interpolate` would. ----

#[test]
fn a_delimited_boolean_expression_evaluates_to_a_typed_bool_not_a_string() {
    assert_eq!(
        eval_delimited_expression(TemplateSource::from_workflow_file("${{ 1 == 1 }}"), &ctx())
            .unwrap()
            .value,
        json!(true)
    );
    assert_eq!(
        eval_delimited_expression(TemplateSource::from_workflow_file("${{ 1 == 2 }}"), &ctx())
            .unwrap()
            .value,
        json!(false)
    );
}

#[test]
fn a_delimited_expression_using_a_property_chain_matches_the_documented_when_examples() {
    // Taken verbatim from §8.9's own reference workflow.
    assert_eq!(
        eval_delimited_expression(
            TemplateSource::from_workflow_file("${{ len(steps.review.output.findings) > 0 }}"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(true)
    );
}

#[test]
fn a_delimited_expression_tolerates_surrounding_whitespace() {
    assert_eq!(
        eval_delimited_expression(
            TemplateSource::from_workflow_file("  ${{ 1 == 1 }}  "),
            &ctx()
        )
        .unwrap()
        .value,
        json!(true)
    );
}

#[test]
fn a_delimited_expression_with_a_quoted_double_brace_does_not_truncate_early() {
    // Reuses `find_closing_delimiter`'s quote-aware scan: the `}}` inside
    // the string argument must not be mistaken for the block's own
    // terminator.
    assert_eq!(
        eval_delimited_expression(
            TemplateSource::from_workflow_file("${{ contains('a}}b', '}}') }}"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(true)
    );
}

#[test]
fn a_bare_undelimited_field_is_rejected_as_not_delimited() {
    let err = eval_delimited_expression(TemplateSource::from_workflow_file("1 == 1"), &ctx())
        .unwrap_err();
    assert!(
        matches!(err, ExprError::NotADelimitedExpression(_)),
        "expected NotADelimitedExpression, got {err:?}"
    );
}

#[test]
fn trailing_content_after_the_closing_delimiter_is_rejected() {
    let err = eval_delimited_expression(
        TemplateSource::from_workflow_file("${{ 1 == 1 }} extra"),
        &ctx(),
    )
    .unwrap_err();
    assert!(
        matches!(err, ExprError::NotADelimitedExpression(_)),
        "expected NotADelimitedExpression, got {err:?}"
    );
}

#[test]
fn an_unterminated_delimited_field_is_unterminated_not_not_delimited() {
    let err = eval_delimited_expression(TemplateSource::from_workflow_file("${{ 1 == 1"), &ctx())
        .unwrap_err();
    assert!(
        matches!(err, ExprError::Unterminated),
        "expected Unterminated, got {err:?}"
    );
}

#[test]
fn a_delimited_field_whose_inner_expression_calls_an_unknown_function_names_the_real_problem() {
    // This is the exact payload the fix-1 brief's endorsed-but-vacuous test
    // used (`${{ not_a_real_function(1) }}`) — with delimiter-stripping now
    // in place, it genuinely reaches the unknown-function path, unlike a
    // bare `eval` call on the same still-delimited text (which dies on the
    // leading `$` at position 0 — see `probe_old_bare_eval_on_delimited_when_text`
    // in this task's fix report for the measured old-code error text).
    let err = eval_delimited_expression(
        TemplateSource::from_workflow_file("${{ not_a_real_function(1) }}"),
        &ctx(),
    )
    .unwrap_err();
    assert!(
        matches!(err, ExprError::UnknownFunction(ref f) if f == "not_a_real_function"),
        "expected UnknownFunction(\"not_a_real_function\"), got {err:?}"
    );
}

// ---- Fix round 4, item B (ruling P35): the non-secret binding path is
// self-announcing, and a rebinding can never lower a root's provenance. ----

#[test]
fn a_public_rebinding_cannot_untaint_a_root_that_was_bound_as_secret() {
    // Payload: root `k` bound as `{"pw": "SECRETVALUE12345"}` through
    // `set_secret`, then rebound to the IDENTICAL value through
    // `set_public` — the exact sequence measured to un-taint before this
    // fix. Pre-fix, `${{ k.pw }}` came back `secret_derived == false` with
    // the value unchanged, so `Evaluated`'s `Debug` — which exists
    // specifically to print `***` — printed `SECRETVALUE12345` in cleartext,
    // because it trusts the flag. The next two callers of this API are
    // Task 6's `map.as` per-item binding (which rebinds one loop name per
    // item) and Task 8 folding tool outputs into `steps.<id>.output`.
    let mut c = ExprContext::new();
    c.set_secret("k", json!({"pw": "SECRETVALUE12345"}));
    c.set_public("k", json!({"pw": "SECRETVALUE12345"}));

    let evaluated = eval(ExpressionSource::from_workflow_file("k.pw"), &c).unwrap();
    assert_eq!(
        evaluated.value,
        json!("SECRETVALUE12345"),
        "the real value is unchanged — only the taint bit is at stake here"
    );
    assert!(
        evaluated.secret_derived,
        "a `set_public` rebinding must not lower a root already marked secret"
    );

    let rendered = format!("{evaluated:?}");
    assert!(
        !rendered.contains("SECRETVALUE12345"),
        "Evaluated's Debug trusts the taint flag, so an un-tainted root leaks here: {rendered}"
    );
    assert!(
        rendered.contains("***"),
        "…and prints the placeholder instead"
    );

    // The same is true through the interpolation entry points, which is
    // where the value actually reaches a log.
    let interpolated =
        interpolate(TemplateSource::from_workflow_file("pw=${{ k.pw }}"), &c).unwrap();
    assert_eq!(interpolated.redacted_for_logging(), "pw=***");
    assert_eq!(
        interpolated.unredacted_for_dispatch(),
        "pw=SECRETVALUE12345"
    );
}

#[test]
fn a_root_that_was_only_ever_bound_publicly_is_not_secret_derived() {
    // The other direction, so the test above cannot pass by making
    // everything secret. Payload: the same `{"pw": "SECRETVALUE12345"}`
    // value, bound only through `set_public`, on a context that also holds a
    // genuinely secret root under a DIFFERENT name — monotonicity is per
    // root name, not per context.
    let mut c = ExprContext::new();
    c.set_secret("other", json!("a-real-secret-value"));
    c.set_public("k", json!({"pw": "SECRETVALUE12345"}));

    let evaluated = eval(ExpressionSource::from_workflow_file("k.pw"), &c).unwrap();
    assert!(
        !evaluated.secret_derived,
        "a root the caller asserted is non-secret must stay readable in a log"
    );
    assert!(format!("{evaluated:?}").contains("SECRETVALUE12345"));
}

#[test]
fn narrowing_a_roots_secret_paths_by_rebinding_unions_rather_than_replaces() {
    // Payload: `steps` bound with `["a", "output"]` secret, then rebound
    // with only `["b", "output"]` — a caller that forgot the earlier entry.
    // Both must stay secret, because dropping `a` would silently un-taint
    // `${{ steps.a.output.body }}` for every step after the rebinding.
    let mut c = ExprContext::new();
    c.set_with_secret_paths(
        "steps",
        json!({"a": {"output": {"body": "AAAA-SECRET"}}, "b": {"output": {"body": "BBBB-SECRET"}}}),
        [vec!["a".to_string(), "output".to_string()]],
    );
    c.set_with_secret_paths(
        "steps",
        json!({"a": {"output": {"body": "AAAA-SECRET"}}, "b": {"output": {"body": "BBBB-SECRET"}}}),
        [vec!["b".to_string(), "output".to_string()]],
    );

    for path in ["steps.a.output.body", "steps.b.output.body"] {
        assert!(
            eval(ExpressionSource::from_workflow_file(path), &c)
                .unwrap()
                .secret_derived,
            "{path} must stay tainted after the narrowing rebinding"
        );
    }
    // …and the narrowing still does not taint an undeclared sibling path.
    assert!(
        !eval(ExpressionSource::from_workflow_file("steps.a.status"), &c)
            .unwrap()
            .secret_derived,
        "path precision is not sacrificed to monotonicity"
    );
}

// ---- Fix round 4, item F: a non-numeric subscript is a typed error, not a
// silent Null. ----

#[test]
fn a_string_subscript_is_a_typed_error_rather_than_silently_evaluating_to_null() {
    // Payload: `steps['list_prs'].output` — the shape a reader who expects
    // JS/Python-style string keying writes. `[..]` in this grammar indexes an
    // array by position only, so this was never implemented; before this fix
    // it evaluated to `Null` and the whole chain after it silently collapsed,
    // which is what let a security probe of exactly this shape look like it
    // proved something about taint when it proved nothing.
    let err = eval(
        ExpressionSource::from_workflow_file("steps['list_prs'].output"),
        &ctx(),
    )
    .unwrap_err();
    match &err {
        ExprError::NonNumericIndex {
            position,
            index_expression,
        } => {
            assert_eq!(
                index_expression, "'list_prs'",
                "the SOURCE text, not the value"
            );
            assert_eq!(*position, 6, "the byte offset of the subscript expression");
        }
        other => panic!("expected NonNumericIndex, got {other:?}"),
    }
    assert!(
        err.to_string()
            .contains("`[..]` indexes an array by position"),
        "the message must say what to write instead: {err}"
    );
}

#[test]
fn a_fractional_or_absent_subscript_is_the_same_typed_error() {
    // Two more shapes that used to be silent `Null`s: a fractional index and
    // a subscript naming a root that is not bound at all.
    for (expr, expected_source) in [
        ("inputs.max_prs[1.5]", "1.5"),
        ("inputs.max_prs[nosuchroot]", "nosuchroot"),
    ] {
        let err = eval(ExpressionSource::from_workflow_file(expr), &ctx()).unwrap_err();
        match err {
            ExprError::NonNumericIndex {
                index_expression, ..
            } => assert_eq!(index_expression, expected_source),
            other => panic!("expected NonNumericIndex for {expr}, got {other:?}"),
        }
    }
}

#[test]
fn a_subscript_that_is_a_number_but_out_of_range_is_still_an_ordinary_null() {
    // The boundary of item F: an out-of-range *numeric* index is a missing
    // lookup, exactly like a `.field` that is not present, and stays `Null`.
    // Only a subscript that is not a number at all is an error.
    assert_eq!(
        eval(
            ExpressionSource::from_workflow_file("steps.list_prs.output[99]"),
            &ctx()
        )
        .unwrap()
        .value,
        json!(null)
    );
}

#[test]
fn slice_bounds_still_tolerate_a_missing_or_non_numeric_argument() {
    // `as_index`'s other caller is deliberately unchanged: `slice(a)` and
    // `slice(a, 1)` are legal calls, and treating a missing bound as an error
    // would reject them rather than catch a mistake.
    let mut c = ExprContext::new();
    c.set_public("a", json!([1, 2, 3, 4]));
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("slice(a)"), &c)
            .unwrap()
            .value,
        json!([1, 2, 3, 4])
    );
    assert_eq!(
        eval(ExpressionSource::from_workflow_file("slice(a, 2)"), &c)
            .unwrap()
            .value,
        json!([3, 4])
    );
}
