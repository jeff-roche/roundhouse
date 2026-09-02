use roundhouse_flow::expr::{
    eval, interpolate, interpolate_json, ExprContext, ExprError, JsonTemplateSource, TemplateSource,
};
use serde_json::{json, Value};

fn ctx() -> ExprContext {
    let mut c = ExprContext::new();
    c.set("inputs", json!({"repo": "acme/widgets", "max_prs": 10}));
    c.set(
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
    assert_eq!(eval("inputs.repo", &ctx()).unwrap(), json!("acme/widgets"));
    assert_eq!(
        eval("steps.list_prs.output[0].number", &ctx()).unwrap(),
        json!(1)
    );
}

#[test]
fn ternary_and_len() {
    assert_eq!(
        eval("len(steps.review.output.findings) > 0", &ctx()).unwrap(),
        json!(true)
    );
    assert_eq!(
        eval(
            "len(steps.review.output.findings) > 0 ? 'has findings' : 'clean'",
            &ctx()
        )
        .unwrap(),
        json!("has findings")
    );
}

#[test]
fn slice_default_contains_flatten_json_env_are_the_full_function_set() {
    assert_eq!(
        eval("slice(steps.list_prs.output, 0, 2)", &ctx()).unwrap(),
        json!([{"number":1},{"number":2}])
    );
    assert_eq!(
        eval("default(missing.field, 'fallback')", &ctx()).unwrap(),
        json!("fallback")
    );
    assert_eq!(
        eval("contains(inputs.repo, 'widgets')", &ctx()).unwrap(),
        json!(true)
    );
    assert_eq!(
        eval("flatten([[1,2],[3]])", &ctx()).unwrap(),
        json!([1, 2, 3])
    );
    assert_eq!(eval("json('{\"a\":1}')", &ctx()).unwrap(), json!({"a":1}));
    std::env::set_var("ROUNDHOUSE_TEST_VAR", "hello");
    assert_eq!(
        eval("env('ROUNDHOUSE_TEST_VAR')", &ctx()).unwrap(),
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
    .unwrap();
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
    let resolved = interpolate_json(JsonTemplateSource::from_workflow_file(&with), &ctx()).unwrap();
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
    c.set("obj", json!({"a": 1, "b": [1, 2]}));
    c.set("arr", json!([1, "two", null]));
    assert_eq!(
        interpolate(TemplateSource::from_workflow_file("${{ obj }}"), &c).unwrap(),
        r#"{"a":1,"b":[1,2]}"#
    );
    assert_eq!(
        interpolate(TemplateSource::from_workflow_file("${{ arr }}"), &c).unwrap(),
        r#"[1,"two",null]"#
    );
}

// ---- Additional coverage for this task's identified risks ----

#[test]
fn unknown_function_is_a_typed_error() {
    let err = eval("nope(1)", &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::UnknownFunction(name) if name == "nope"));
}

#[test]
fn trailing_garbage_is_rejected() {
    let err = eval("inputs.repo extra", &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::UnexpectedToken(_, _)));
}

#[test]
fn comparisons_and_equality_operators_work() {
    assert_eq!(eval("1 == 1", &ctx()).unwrap(), json!(true));
    assert_eq!(eval("1 != 2", &ctx()).unwrap(), json!(true));
    assert_eq!(eval("2 >= 2", &ctx()).unwrap(), json!(true));
    assert_eq!(eval("1 <= 0", &ctx()).unwrap(), json!(false));
    assert_eq!(eval("'a' == 'a'", &ctx()).unwrap(), json!(true));
}

#[test]
fn missing_root_and_missing_field_resolve_to_null_not_an_error() {
    // `default()`'s whole purpose depends on a missing path resolving to
    // Null rather than erroring.
    assert_eq!(eval("missing", &ctx()).unwrap(), json!(null));
    assert_eq!(eval("inputs.nonexistent", &ctx()).unwrap(), json!(null));
    assert_eq!(
        eval("inputs.nonexistent.deeper.still", &ctx()).unwrap(),
        json!(null)
    );
}

#[test]
fn array_literal_and_nested_indexing() {
    assert_eq!(eval("[1,2,3][1]", &ctx()).unwrap(), json!(2));
}

#[test]
fn integer_literals_compare_equal_to_context_data_regardless_of_number_representation() {
    // steps.list_prs.output[0].number came from `json!(1)` (an int-backed
    // Number); a float-backed context value (e.g. `map.over` item data
    // that happened to serialize as `1.0`) must compare equal to the same
    // literal too — `==`/`!=` must not be representation-sensitive.
    assert_eq!(
        eval("steps.list_prs.output[0].number == 1", &ctx()).unwrap(),
        json!(true)
    );
    let mut c = ctx();
    c.set("float_one", json!(1.0));
    assert_eq!(eval("float_one == 1", &c).unwrap(), json!(true));
    assert_eq!(eval("float_one != 1", &c).unwrap(), json!(false));
    assert_eq!(eval("float_one == 2", &c).unwrap(), json!(false));
}

// ---- Unterminated string literal: verified to panic in the brief's own
// illustrative code (byte-index-out-of-bounds on `expr[p.pos..]` once
// `pos` runs past the end of the string) before this task fixed it. Must
// be a typed error, not a crash. ----

#[test]
fn unterminated_string_literal_is_a_typed_error_not_a_panic() {
    let err = eval("'abc", &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::Unterminated));
}

#[test]
fn unterminated_string_literal_inside_a_larger_expression_is_a_typed_error() {
    // The opening quote before "abc" never finds a matching closing quote
    // anywhere in the rest of the expression.
    let err = eval("default('abc, x)", &ctx()).unwrap_err();
    assert!(matches!(err, ExprError::Unterminated));
}

// ---- Risk 3: untrusted `map.over` data reaching the context; size, depth,
// and non-ASCII content. ----

#[test]
fn large_string_context_values_evaluate_without_error() {
    let mut c = ExprContext::new();
    let big = "x".repeat(200_000);
    c.set("pr", json!({"title": big.clone()}));
    assert_eq!(eval("pr.title", &c).unwrap(), json!(big));
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
    c.set("pr", inner);
    let mut path = String::from("pr");
    for _ in 0..500 {
        path.push_str(".next");
    }
    assert_eq!(eval(&path, &c).unwrap(), json!("bottom"));
}

#[test]
fn non_ascii_context_values_round_trip_through_property_access_and_interpolation() {
    let mut c = ExprContext::new();
    c.set(
        "pr",
        json!({"title": "Fix \u{1F41B} in \u{00e9}migr\u{00e9} module — “quoted”"}),
    );
    assert_eq!(
        eval("pr.title", &c).unwrap(),
        json!("Fix \u{1F41B} in \u{00e9}migr\u{00e9} module — “quoted”")
    );
    let out = interpolate(
        TemplateSource::from_workflow_file("Title: ${{ pr.title }}"),
        &c,
    )
    .unwrap();
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
    c.set("pr", json!({"title": "look: ${{ secrets.GH_TOKEN }}"}));
    assert_eq!(
        eval("pr.title", &c).unwrap(),
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
    .unwrap();
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
    c.set("a", json!("${{"));
    c.set("b", json!("real"));
    let out = interpolate(
        TemplateSource::from_workflow_file("${{ a }} then ${{ b }}"),
        &c,
    )
    .unwrap();
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
    .unwrap();
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
    c.set("real", json!("REAL_VALUE"));
    let out = interpolate(
        TemplateSource::from_workflow_file(
            "${{ 'oops }} filler ${{ real }} trailing' }} rest of template",
        ),
        &c,
    )
    .unwrap();
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
    assert_eq!(eval(&access, &ctx()).unwrap(), json!(1));
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
    let err = eval(&expr, &ctx()).unwrap_err();
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
    let err = eval(&expr, &ctx()).unwrap_err();
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
    let err = eval(&expr, &ctx()).unwrap_err();
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
        c.set("pr", inner);
        let mut path = String::from("pr");
        for _ in 0..depth {
            path.push_str(".next");
        }
        min_elapsed(9, || {
            let _ = eval(&path, &c).unwrap();
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
        c.set("pr", inner);
        let mut path = String::from("default(missing, pr)");
        for _ in 0..depth {
            path.push_str(".next");
        }
        min_elapsed(9, || {
            let _ = eval(&path, &c).unwrap();
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
    c.set(
        "secrets",
        json!({"GH_TOKEN": "super-secret-value-should-not-print"}),
    );
    c.set("inputs", json!({"repo": "acme/widgets"}));
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
    c.set(
        "secrets",
        json!({"GH_TOKEN": "super-secret-value-should-not-print"}),
    );
    // Trigger a variety of error paths and confirm none of them echo the
    // secret value back in the error's Display text.
    let errs = [
        eval("nope(secrets.GH_TOKEN)", &c).unwrap_err().to_string(),
        eval("secrets.GH_TOKEN )", &c).unwrap_err().to_string(),
        eval("json(secrets.GH_TOKEN)", &c).unwrap_err().to_string(),
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
        eval("env('ROUNDHOUSE_TEST_ENV_RESIDUAL')", &ctx()).unwrap(),
        json!("process-wide-value")
    );
}

#[test]
fn env_function_returns_null_for_an_unset_variable() {
    std::env::remove_var("ROUNDHOUSE_TEST_ENV_DEFINITELY_UNSET");
    assert_eq!(
        eval("env('ROUNDHOUSE_TEST_ENV_DEFINITELY_UNSET')", &ctx()).unwrap(),
        json!(null)
    );
}

// ---- `json()` can decode escapes into control characters not literally
// present in the source text — documented residual, pinned. ----

#[test]
fn json_function_can_decode_escapes_into_control_characters_documented_residual() {
    let out = eval(r#"json('"a\nb"')"#, &ctx()).unwrap();
    assert_eq!(out, json!("a\nb"));
    if let Value::String(s) = out {
        assert!(s.contains('\n'));
    } else {
        panic!("expected a string");
    }
}

#[test]
fn json_function_rejects_invalid_json_as_a_typed_error() {
    let err = eval("json('not json')", &ctx()).unwrap_err();
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
    c.set(
        "secrets",
        json!({"a": "\"unterminated", "b": "12345abcdef"}),
    );
    let eof_err = eval("json(secrets.a)", &c).unwrap_err().to_string();
    let syntax_err = eval("json(secrets.b)", &c).unwrap_err().to_string();
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
    c.set("steps", json!({"real": true}));
    c.set("Steps", json!({"shadow": true}));
    assert_eq!(eval("steps.real", &c).unwrap(), json!(true));
    assert_eq!(eval("Steps.shadow", &c).unwrap(), json!(true));
    // The two roots never collide: asking the "wrong-case" root for the
    // other's field resolves to Null, not a cross-read.
    assert_eq!(eval("steps.shadow", &c).unwrap(), json!(null));
    assert_eq!(eval("Steps.real", &c).unwrap(), json!(null));
}
