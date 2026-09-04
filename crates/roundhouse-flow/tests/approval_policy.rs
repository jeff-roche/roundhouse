use roundhouse_flow::approval_policy::{
    default_for_unattended, evaluate_unattended_approval, resolve_notify_timeout, ApprovalOutcome,
    ApprovalPolicy, OnApprovalTimeout, PreapprovedBundle,
};
use std::time::Duration;

#[test]
fn scheduled_sessions_default_to_deny_all_which_blocks_not_fails() {
    // §6.4: "Scheduled sessions default to DenyAll — but the task blocks
    // rather than failing, so a human can attach later and unblock it."
    let policy = default_for_unattended();
    assert_eq!(policy, ApprovalPolicy::DenyAll);
    let outcome = evaluate_unattended_approval(&policy, "shell:git-push");
    assert_eq!(
        outcome,
        ApprovalOutcome::Blocked,
        "blocked, never Failed — a human can attach later and unblock it"
    );
}

#[test]
fn preapproved_bundle_only_approves_its_own_declared_rules() {
    // §6.4: "There is no 'unattended = auto-approve'; you write a
    // Preapproved bundle and it is a reviewable artifact" — i.e. only rules
    // the bundle explicitly names are approved, everything else still blocks.
    //
    // Two entries, and the second one is probed as well as the first (P92):
    // a bundle of one cannot tell a scan that stops after position 1 from a
    // scan that reads the whole list.
    let policy = ApprovalPolicy::Preapproved {
        bundle: PreapprovedBundle {
            name: "nightly-lint-bundle".to_string(),
            version: 1,
            approved_rule_ids: vec![
                "shell:cargo-test".to_string(),
                "shell:cargo-clippy".to_string(),
            ],
        },
    };
    assert_eq!(
        evaluate_unattended_approval(&policy, "shell:cargo-test"),
        ApprovalOutcome::Approved
    );
    assert_eq!(
        evaluate_unattended_approval(&policy, "shell:cargo-clippy"),
        ApprovalOutcome::Approved,
        "the bundle approves every id it names, not merely the first one"
    );
    assert_eq!(
        evaluate_unattended_approval(&policy, "shell:git-push"),
        ApprovalOutcome::Blocked,
        "a rule the bundle never named is not auto-approved just because *some* Preapproved bundle exists"
    );
}

/// Rule ids are matched by exact string equality with no normalisation, which
/// is a stated choice (see `evaluate_unattended_approval`'s doc comment): any
/// widening — case folding, prefix matching, globbing — would approve strings
/// the reviewer of the bundle never read. Pinned here so "no normalisation"
/// is a test rather than a claim in a comment.
#[test]
fn a_rule_id_that_merely_resembles_an_approved_one_is_not_approved() {
    let policy = ApprovalPolicy::Preapproved {
        bundle: PreapprovedBundle {
            name: "nightly-lint-bundle".to_string(),
            version: 1,
            approved_rule_ids: vec!["shell:cargo-test".to_string()],
        },
    };
    for near_miss in [
        "shell:cargo-tes",
        "shell:cargo-test --all",
        "SHELL:CARGO-TEST",
        "shell:cargo-test\n",
        "",
    ] {
        assert_eq!(
            evaluate_unattended_approval(&policy, near_miss),
            ApprovalOutcome::Blocked,
            "{near_miss:?} is not the string the bundle approved"
        );
    }
}

/// The load path rejects a blank `approved_rule_ids` entry, but the fields
/// are `pub`, so a hand-built bundle can still carry one — and that is the
/// only value in this module that fails *open*: a broken caller passing no
/// rule id at all would match it. `evaluate_unattended_approval` therefore
/// refuses a blank `rule_id` before it scans, which is why this bundle,
/// which no document could produce, still approves nothing blank.
///
/// The blank entries sit *behind* a well-formed one, so a scan truncated to
/// position 1 could not make this pass by accident (P92).
#[test]
fn a_blank_rule_id_is_never_approved_even_by_a_hand_built_bundle_carrying_one() {
    let policy = ApprovalPolicy::Preapproved {
        bundle: PreapprovedBundle {
            name: "hand-built-bundle".to_string(),
            version: 1,
            approved_rule_ids: vec![
                "shell:cargo-test".to_string(),
                String::new(),
                "   ".to_string(),
            ],
        },
    };
    for blank in ["", "   ", "\n"] {
        assert_eq!(
            evaluate_unattended_approval(&policy, blank),
            ApprovalOutcome::Blocked,
            "{blank:?} is a broken caller passing no rule id, not an authored grant"
        );
    }
    assert_eq!(
        evaluate_unattended_approval(&policy, "shell:cargo-test"),
        ApprovalOutcome::Approved,
        "the guard refuses a blank caller id; it does not disable the rest of the bundle"
    );
}

#[test]
fn notify_applies_on_timeout_when_no_response_arrives() {
    let notify_deny = ApprovalPolicy::Notify {
        sink: "desktop".to_string(),
        timeout: Duration::from_secs(3600),
        on_timeout: OnApprovalTimeout::Deny,
    };
    assert_eq!(
        evaluate_unattended_approval(&notify_deny, "shell:git-push"),
        ApprovalOutcome::PendingNotify
    );

    // The `match` below is exhaustive on purpose, and that is the point of
    // the loop: adding a variant to `OnApprovalTimeout` breaks the build
    // here. It is the tripwire for the obligation recorded on that enum —
    // a run-level `Approve` cannot be added without the
    // `UncheckedOnTimeout`-equivalent gating `hitl.rs` built for exactly
    // that value. (Same mechanism `tests/hitl.rs` uses to make a new
    // `SuspendReason` variant a build break rather than a stale comment.)
    for on_timeout in [OnApprovalTimeout::Deny, OnApprovalTimeout::Fail] {
        let expected = match on_timeout {
            OnApprovalTimeout::Deny => ApprovalOutcome::Denied,
            OnApprovalTimeout::Fail => ApprovalOutcome::Failed,
        };
        assert_eq!(resolve_notify_timeout(&on_timeout), expected);
    }
}

/// The one outcome an unattended `Interactive` must NOT produce is
/// [`ApprovalOutcome::PendingNotify`]: nothing can resolve it. There is no
/// sink to answer and no `on_timeout` to fire, so the run would wait
/// forever. `Blocked` is fail-closed and is exactly §6.4's `DenyAll`
/// semantics — a human attaches later and unblocks it.
#[test]
fn interactive_in_an_unattended_run_blocks_rather_than_pending_on_nothing() {
    let outcome = evaluate_unattended_approval(&ApprovalPolicy::Interactive, "shell:git-push");
    // The `assert_eq!` is the whole test. An `assert_ne!` against
    // `PendingNotify` alongside it would be an assertion that cannot fail —
    // the equality above already settles every other variant — and this
    // task's brief was specifically about a test body that cannot fail, so
    // the reason it would have carried is written here instead: PendingNotify
    // is only resolvable via `resolve_notify_timeout`, which needs an
    // `on_timeout` that `Interactive` does not carry.
    assert_eq!(
        outcome,
        ApprovalOutcome::Blocked,
        "an unattended Interactive run has no human to interact with; PendingNotify here has no \
         sink to answer it and no timeout to fire, i.e. a permanent hang"
    );
}

/// §6.4: "you write a `Preapproved` bundle and it is a reviewable artifact."
/// Written by a human, read by a reviewer — so it must load from a document.
#[test]
fn a_preapproved_bundle_loads_from_the_document_a_human_writes() {
    let doc = "
name: nightly-lint-bundle
version: 3
approved_rule_ids:
  - shell:cargo-test
  - shell:cargo-clippy
";
    let bundle: PreapprovedBundle =
        serde_yaml::from_str(doc).expect("a well-formed bundle document must load");
    assert_eq!(
        bundle,
        PreapprovedBundle {
            name: "nightly-lint-bundle".to_string(),
            version: 3,
            approved_rule_ids: vec![
                "shell:cargo-test".to_string(),
                "shell:cargo-clippy".to_string()
            ],
        }
    );
    let policy = ApprovalPolicy::Preapproved { bundle };
    assert_eq!(
        evaluate_unattended_approval(&policy, "shell:cargo-clippy"),
        ApprovalOutcome::Approved
    );
    assert_eq!(
        evaluate_unattended_approval(&policy, "shell:git-push"),
        ApprovalOutcome::Blocked
    );
}

/// A misspelled key in a security artifact must be a load error, not a
/// silently ignored field — the crate-wide `deny_unknown_fields` stance in
/// `parse::types`, applied to the one document this module owns.
///
/// What the derive buys here is the *better error*, not the only error.
/// `approved_rule_ids` is required with no `#[serde(default)]`, so
/// `aproved_rule_ids:` already fails to load without `deny_unknown_fields` —
/// but it fails as ``missing field `approved_rule_ids` ``, naming the key the
/// author did *not* type. With the derive, the error names the key they did,
/// which is the difference between a reviewer finding the typo and a reviewer
/// re-reading a document that looks correct. (Giving the field a
/// `#[serde(default)]` would make the weaker sentence true and trade a load
/// error for a silently empty allowlist — the wrong direction for a grant.)
#[test]
fn a_bundle_with_a_misspelled_key_is_rejected_rather_than_silently_emptied() {
    let doc = "
name: nightly-lint-bundle
version: 3
aproved_rule_ids:
  - shell:cargo-test
";
    let err = serde_yaml::from_str::<PreapprovedBundle>(doc)
        .expect_err("a misspelled key must be rejected");
    assert!(
        err.to_string().contains("aproved_rule_ids"),
        "the error must name the offending key, got: {err}"
    );
}

/// The bundle's `name` is the only text identifying it in a run record or a
/// review, so an empty one is rejected on the same ground as
/// `HitlError::EmptyGateTitle`.
#[test]
fn a_bundle_with_a_blank_name_is_rejected() {
    let doc = "
name: '   '
version: 1
approved_rule_ids: []
";
    let err =
        serde_yaml::from_str::<PreapprovedBundle>(doc).expect_err("a blank name must be rejected");
    assert!(
        err.to_string().contains("name"),
        "the error must say which field is at fault, got: {err}"
    );
}

/// Matching is exact, so a rule id written with surrounding whitespace would
/// silently never match — an approval the author believes they granted and
/// the reviewer believes they read, which grants nothing. Rejected at load
/// rather than trimmed at match time: normalising here would widen what the
/// reviewed strings mean (see
/// `a_rule_id_that_merely_resembles_an_approved_one_is_not_approved`).
///
/// Checked in a list of two, with the offending entry once last and once
/// first. One ordering pins only half of it (P92): with the bad id last, a
/// validation loop truncated to `.take(1)` still passes; with it first, a
/// loop starting at `.skip(1)` does. The measured sweep produced exactly
/// that second survivor after the first ordering alone was added.
#[test]
fn a_bundle_rule_id_with_surrounding_whitespace_is_rejected_wherever_it_sits() {
    for doc in [
        "
name: nightly-lint-bundle
version: 1
approved_rule_ids:
  - shell:cargo-test
  - \"shell:cargo-clippy \"
",
        "
name: nightly-lint-bundle
version: 1
approved_rule_ids:
  - \"shell:cargo-clippy \"
  - shell:cargo-test
",
    ] {
        let Err(err) = serde_yaml::from_str::<PreapprovedBundle>(doc) else {
            panic!("an untrimmed rule id must be rejected, but this loaded: {doc}");
        };
        let message = err.to_string();
        assert!(
            message.contains("shell:cargo-clippy "),
            "the error must quote what the author wrote, got: {message} (from {doc})"
        );
    }
}

/// An empty rule id would approve a caller that passes `""` as its rule id,
/// which is a broken caller rather than an authored grant.
///
/// Both orderings again, for the reason the whitespace test above records.
#[test]
fn a_bundle_with_an_empty_rule_id_is_rejected_wherever_it_sits() {
    for doc in [
        "
name: nightly-lint-bundle
version: 1
approved_rule_ids:
  - shell:cargo-test
  - ''
",
        "
name: nightly-lint-bundle
version: 1
approved_rule_ids:
  - ''
  - shell:cargo-test
",
    ] {
        let Err(err) = serde_yaml::from_str::<PreapprovedBundle>(doc) else {
            panic!("an empty rule id must be rejected, but this loaded: {doc}");
        };
        assert!(
            err.to_string().contains("approved_rule_ids"),
            "the error must name the field, got: {err} (from {doc})"
        );
    }
}

/// A bundle that names no rules is deliberately *not* an error: it approves
/// nothing, which is the fail-closed direction, and a reviewer striking every
/// entry out of a bundle should get "approves nothing" rather than a document
/// that no longer loads. Pinned so the permissiveness is a decision rather
/// than an untested gap in the two rejections above.
#[test]
fn a_bundle_that_approves_nothing_loads_and_behaves_exactly_like_deny_all() {
    let doc = "
name: nightly-lint-bundle
version: 1
approved_rule_ids: []
";
    let bundle: PreapprovedBundle =
        serde_yaml::from_str(doc).expect("an empty bundle must still load");
    let policy = ApprovalPolicy::Preapproved { bundle };
    assert_eq!(
        evaluate_unattended_approval(&policy, "shell:cargo-test"),
        evaluate_unattended_approval(&default_for_unattended(), "shell:cargo-test"),
    );
    assert_eq!(
        evaluate_unattended_approval(&policy, "shell:cargo-test"),
        ApprovalOutcome::Blocked
    );
}

/// The run-level ceiling is never derived from the per-rule knob underneath
/// it, so `approval_policy.rs` imports nothing from `hitl.rs` (see that
/// module's doc comment).
///
/// This is a module-dependency convention, and a convention can only be
/// checked by looking at the source — which is what
/// `xtask/tests/no_raw_event_mutation.rs` already does for the
/// event-mutation ban, scoped here to the one file. The test this replaces
/// tried to assert the same thing with a body of one `let` binding and a
/// comment reading *"the absence of any such import is the assertion"*; a
/// test cannot observe another file's imports, so it passed unconditionally.
///
/// Two known limits, stated rather than implied. It skips line comments only
/// (`//`, `///`, `//!`), so this module's prose may discuss `hitl` freely but
/// a block comment mentioning it would trip the scan; and it is a plain
/// substring match, so an unrelated identifier containing `hitl` trips it
/// too. Both failure modes point the reader at the module doc, which is the
/// intent.
#[test]
fn the_run_level_policy_module_never_imports_the_per_rule_escalate_it_composes_with() {
    const SOURCE: &str = include_str!("../src/approval_policy.rs");
    let offenders: Vec<String> = SOURCE
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.trim_start();
            !code.starts_with("//") && code.contains("hitl")
        })
        .map(|(index, line)| format!("  src/approval_policy.rs:{}: {}", index + 1, line.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "approval_policy.rs must not reference hitl's types in code — the run-level ceiling is not \
         built out of the per-rule knob it sits above:\n{}",
        offenders.join("\n")
    );
}
