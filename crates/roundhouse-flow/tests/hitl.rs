//! §8.11's "one mechanism" decision, pinned: "Three sources of human waits
//! — an explicit `gate` step, an unattended permission `Escalate`, and
//! mid-step elicitation — resolve to **one mechanism**: an `AwaitingHuman`
//! task with a JSON-Schema form that TUI and web render from the same
//! schema."
//!
//! The load-bearing test here is
//! [`an_explicit_gate_step_and_a_permission_escalation_produce_the_same_task_shape`]:
//! it builds an `AwaitingHuman` from each of the two sources with equivalent
//! configuration and asserts the two values are equal in *every* field once
//! `source` is normalized. That is the "one mechanism" property stated as an
//! equality rather than as prose.
//!
//! Ruling P29: `serde_json/preserve_order` is live workspace-wide, so object
//! key iteration is insertion-ordered, not sorted. Nothing here asserts on
//! serialized JSON text — `form_schema` is compared as a parsed
//! `serde_json::Value` (whose map equality is order-insensitive) or indexed
//! key by key.

use roundhouse_core::{PolicyDecision, SessionId, SuspendReason, TaskId};
use roundhouse_flow::hitl::{
    AwaitingHuman, Escalate, Escalation, HitlError, HumanWaitSource, UncheckedOnTimeout,
};
use roundhouse_flow::parse::steps::{parse_step, StepBody};
use roundhouse_flow::parse::types::{OnTimeout, RetryDef, UnattendedDef, UnattendedEscalate};
use roundhouse_flow::retry::{retry_policy_from_def, DurationParseError, RetryPolicyError};
use std::time::Duration;

/// Parses one `gate:` step and hands back exactly the four fields
/// `StepBody::Gate` carries, so every test below starts from real parser
/// output rather than hand-built values.
fn gate_fields(yaml: &str) -> (String, serde_json::Value, String, OnTimeout) {
    let step = parse_step(&serde_yaml::from_str(yaml).unwrap()).unwrap();
    let StepBody::Gate {
        title,
        form,
        timeout,
        on_timeout,
    } = step.body
    else {
        panic!("expected a gate step");
    };
    (title, form, timeout, on_timeout)
}

#[test]
fn an_explicit_gate_step_and_a_permission_escalation_produce_the_same_task_shape() {
    let (title, form, timeout, on_timeout) = gate_fields(
        "id: gate\ngate: { title: 'Allow `git push`?', form: { approve: { type: boolean } }, timeout: 12h, on_timeout: deny }",
    );
    // The same task id on both sides: this test is about the shape the two
    // sources produce, not about identity minting.
    let task_id = TaskId::new();

    let from_gate =
        AwaitingHuman::from_gate(task_id, &title, &form, &timeout, &on_timeout).unwrap();
    let from_escalate = AwaitingHuman::from_escalate(
        task_id,
        "Allow `git push`?",
        Duration::from_secs(12 * 3600),
        &OnTimeout::Deny,
    );

    assert_eq!(from_gate.source, HumanWaitSource::Gate);
    assert_eq!(from_escalate.source, HumanWaitSource::PermissionEscalate);

    // §8.11's "one mechanism": with equivalent configuration the two differ
    // in `source` and in nothing else — same form schema, same relative
    // deadline, same on_timeout, same task id.
    assert_eq!(
        from_gate,
        AwaitingHuman {
            source: HumanWaitSource::Gate,
            ..from_escalate.clone()
        }
    );
    assert_eq!(
        from_gate.timeout_after,
        Some(Duration::from_secs(12 * 3600))
    );
    assert_eq!(from_gate.on_timeout.as_written(), &OnTimeout::Deny);
}

#[test]
fn the_deadline_is_a_relative_duration_not_an_absolute_instant() {
    // Ruling P65 #4: `roundhouse-flow` reads no clock. `24h` becomes
    // `Duration::from_secs(86_400)`, and the relative -> absolute conversion
    // belongs to the park site (Task 17), which is the only place "now" is
    // genuinely known. Two builds of the same gate are therefore *equal*,
    // which would be false of any wall-clock-derived deadline.
    let (title, form, timeout, on_timeout) =
        gate_fields("id: g\ngate: { title: t, timeout: 24h, on_timeout: deny }");
    let task_id = TaskId::new();
    let first = AwaitingHuman::from_gate(task_id, &title, &form, &timeout, &on_timeout).unwrap();
    let second = AwaitingHuman::from_gate(task_id, &title, &form, &timeout, &on_timeout).unwrap();

    assert_eq!(first.timeout_after, Some(Duration::from_secs(86_400)));
    assert_eq!(first, second);
}

#[test]
fn the_form_schema_is_a_json_schema_object_carrying_the_gates_declared_fields() {
    let (title, form, timeout, on_timeout) = gate_fields(
        "id: g\ngate: { title: 'Post review?', form: { approve: { type: boolean, default: true }, note: { type: string } }, timeout: 24h, on_timeout: deny }",
    );
    let awaiting =
        AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout).unwrap();

    // P29: parsed structure, never `to_string()`.
    assert_eq!(awaiting.form_schema["type"], serde_json::json!("object"));
    assert_eq!(
        awaiting.form_schema["title"],
        serde_json::json!("Post review?")
    );
    assert_eq!(
        awaiting.form_schema["properties"]["approve"]["type"],
        serde_json::json!("boolean")
    );
    assert_eq!(
        awaiting.form_schema["properties"]["approve"]["default"],
        serde_json::json!(true)
    );
    assert_eq!(
        awaiting.form_schema["properties"]["note"]["type"],
        serde_json::json!("string")
    );
}

#[test]
fn a_permission_escalations_form_asks_the_one_question_a_permission_wait_has() {
    let awaiting = AwaitingHuman::from_escalate(
        TaskId::new(),
        "Allow `git push`?",
        Duration::from_secs(3600),
        &OnTimeout::Deny,
    );

    assert_eq!(awaiting.form_schema["type"], serde_json::json!("object"));
    assert_eq!(
        awaiting.form_schema["title"],
        serde_json::json!("Allow `git push`?")
    );
    assert_eq!(
        awaiting.form_schema["properties"]["approve"]["type"],
        serde_json::json!("boolean")
    );
}

#[test]
fn a_gate_timeout_and_a_retry_backoff_reject_the_same_malformed_duration_text() {
    // Ruling P65 #5: one parser, so a gate timeout and a retry backoff can
    // never disagree about what `"10 s"` means. Every string below is one
    // the retry parser's own regression test (`tests/retry.rs`) already
    // pins as rejected; this asserts the gate path rejects the identical
    // set through the identical function.
    for bad in ["10 s", "10sec", "-5s", "10", "", "1hh", "h"] {
        let err = AwaitingHuman::from_gate(
            TaskId::new(),
            "t",
            &serde_json::json!({}),
            bad,
            &OnTimeout::Deny,
        )
        .unwrap_err();
        assert_eq!(
            err,
            HitlError::InvalidGateTimeout {
                value: bad.to_string(),
                source: DurationParseError::Invalid,
            },
            "gate timeout {bad:?}"
        );

        let retry_err = retry_policy_from_def(&RetryDef {
            base: Some(bad.to_string()),
            ..RetryDef::default()
        })
        .unwrap_err();
        assert!(
            matches!(retry_err, RetryPolicyError::InvalidDuration { .. }),
            "retry base {bad:?} gave {retry_err:?}"
        );
    }
}

#[test]
fn a_gate_timeout_that_overflows_seconds_is_rejected_not_silently_wrapped() {
    let err = AwaitingHuman::from_gate(
        TaskId::new(),
        "t",
        &serde_json::json!({}),
        "99999999999999999h",
        &OnTimeout::Deny,
    )
    .unwrap_err();
    assert_eq!(
        err,
        HitlError::InvalidGateTimeout {
            value: "99999999999999999h".to_string(),
            source: DurationParseError::Overflow,
        }
    );
}

#[test]
fn a_gate_form_that_is_not_an_object_is_rejected_rather_than_producing_an_invalid_schema() {
    // `GateBodyDef::form` is an unconstrained `serde_json::Value`, so
    // `form: [1, 2]` parses. Dropping it under `properties` would hand the
    // TUI and the web UI a JSON Schema neither can render.
    let err = AwaitingHuman::from_gate(
        TaskId::new(),
        "t",
        &serde_json::json!([1, 2]),
        "1h",
        &OnTimeout::Deny,
    )
    .unwrap_err();
    assert_eq!(err, HitlError::FormIsNotAnObject { actual: "array" });
}

#[test]
fn escalate_is_the_evaluated_form_of_the_unattended_wire_block() {
    let park = UnattendedDef {
        escalate: UnattendedEscalate::Park,
        deadline: Some("24h".to_string()),
        on_timeout: Some(OnTimeout::Deny),
    };
    assert_eq!(
        Escalate::try_from(&park).unwrap(),
        Escalate::Park {
            deadline: Duration::from_secs(86_400),
            on_timeout: OnTimeout::Deny,
        }
    );

    assert_eq!(
        Escalate::try_from(&UnattendedDef {
            escalate: UnattendedEscalate::DenyAndContinue,
            deadline: None,
            on_timeout: None,
        })
        .unwrap(),
        Escalate::DenyAndContinue
    );
    assert_eq!(
        Escalate::try_from(&UnattendedDef {
            escalate: UnattendedEscalate::Fail,
            deadline: None,
            on_timeout: None,
        })
        .unwrap(),
        Escalate::Fail
    );
}

#[test]
fn park_without_a_deadline_and_on_timeout_is_rejected_by_the_evaluated_form_too() {
    // `parse_workflow` already rejects this shape
    // (`ParseError::ParkEscalationRequiresDeadlineAndOnTimeout`), but
    // `UnattendedDef` is constructible without going through it, so the
    // conversion must not assume the document was validated.
    for def in [
        UnattendedDef {
            escalate: UnattendedEscalate::Park,
            deadline: None,
            on_timeout: Some(OnTimeout::Deny),
        },
        UnattendedDef {
            escalate: UnattendedEscalate::Park,
            deadline: Some("24h".to_string()),
            on_timeout: None,
        },
    ] {
        assert_eq!(
            Escalate::try_from(&def).unwrap_err(),
            HitlError::ParkRequiresDeadlineAndOnTimeout
        );
    }

    assert_eq!(
        Escalate::try_from(&UnattendedDef {
            escalate: UnattendedEscalate::Park,
            deadline: Some("24 h".to_string()),
            on_timeout: Some(OnTimeout::Deny),
        })
        .unwrap_err(),
        HitlError::InvalidEscalateDeadline {
            value: "24 h".to_string(),
            source: DurationParseError::Invalid,
        }
    );
}

#[test]
fn only_an_ask_escalates_and_each_job_level_escalate_shape_resolves_it_differently() {
    let task_id = TaskId::new();
    let park = Escalate::Park {
        deadline: Duration::from_secs(3600),
        on_timeout: OnTimeout::Deny,
    };

    // §8.5 point 1: `decide()` is pure and total. `Allow`/`Deny` are already
    // settled, so no `Escalate` shape touches them.
    for escalate in [park.clone(), Escalate::DenyAndContinue, Escalate::Fail] {
        for settled in [PolicyDecision::Allow, PolicyDecision::Deny] {
            assert_eq!(
                escalate.apply(settled, task_id, "Allow `git push`?"),
                Escalation::Decided(settled),
                "{escalate:?} changed a settled {settled:?}"
            );
        }
    }

    let Escalation::Park(awaiting) = park.apply(PolicyDecision::Ask, task_id, "Allow `git push`?")
    else {
        panic!("Escalate::Park must park an Ask on the AwaitingHuman mechanism");
    };
    assert_eq!(awaiting.source, HumanWaitSource::PermissionEscalate);
    assert_eq!(awaiting.task_id, task_id);
    assert_eq!(awaiting.timeout_after, Some(Duration::from_secs(3600)));
    assert_eq!(awaiting.on_timeout.as_written(), &OnTimeout::Deny);

    // §8.5 point 3: `DenyAndContinue` turns the `Ask` into a plain `Deny`;
    // rendering it as a structured tool error is the executor's job.
    assert_eq!(
        Escalate::DenyAndContinue.apply(PolicyDecision::Ask, task_id, "t"),
        Escalation::Decided(PolicyDecision::Deny)
    );
    assert_eq!(
        Escalate::Fail.apply(PolicyDecision::Ask, task_id, "t"),
        Escalation::Fail
    );
}

#[test]
fn a_gate_timeout_that_parses_to_zero_is_rejected_so_no_wait_is_born_already_expired() {
    // `parse_duration_str("0s")` is `Ok(Duration::ZERO)` — zero rejection was
    // never in the parser; it lives in `retry.rs`'s `resolve_duration`, which
    // is retry-only. Without a counterpart here, `timeout: 0s` produces a
    // human wait whose window is already closed: it resolves per `on_timeout`
    // with no human able to see it, while still appearing in the run record
    // as a configured approval gate. Task 17 cannot catch it — it receives a
    // `Duration` and cannot tell an authored `0s` from a legitimately elapsed
    // one.
    for zero in ["0s", "0m", "0h", "0d", "00s", "000000s"] {
        let (title, form, timeout, on_timeout) = gate_fields(&format!(
            "id: g\ngate: {{ title: t, timeout: '{zero}', on_timeout: approve }}"
        ));
        let err = AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout)
            .unwrap_err();
        assert_eq!(
            err,
            HitlError::ZeroDeadline {
                field: "gate.timeout",
                value: zero.to_string(),
            },
            "gate timeout {zero:?}"
        );
    }
}

#[test]
fn an_unattended_park_deadline_that_parses_to_zero_is_rejected_on_the_same_grounds() {
    // The escalate site does this for *every* `PolicyDecision::Ask` in an
    // unattended run, so the same degenerate value is worse here than at a
    // single gate.
    for zero in ["0s", "0m", "0h", "0d", "00s", "000000s"] {
        assert_eq!(
            Escalate::try_from(&UnattendedDef {
                escalate: UnattendedEscalate::Park,
                deadline: Some(zero.to_string()),
                on_timeout: Some(OnTimeout::Approve),
            })
            .unwrap_err(),
            HitlError::ZeroDeadline {
                field: "permissions.unattended.deadline",
                value: zero.to_string(),
            },
            "unattended deadline {zero:?}"
        );
    }
}

#[test]
fn a_zero_duration_is_now_rejected_on_the_gate_the_escalate_and_the_retry_paths_alike() {
    // The claim `from_gate`'s doc used to make — that a gate's `timeout` is
    // rejected exactly as a retry's `base` is — was true of malformed text
    // and false of degenerate-but-valid text. This pins the parity that now
    // actually holds, on the same `"0s"` through all three entry points.
    assert!(matches!(
        retry_policy_from_def(&RetryDef {
            base: Some("0s".to_string()),
            ..RetryDef::default()
        })
        .unwrap_err(),
        RetryPolicyError::ZeroDuration { field: "base", .. }
    ));

    let (title, form, timeout, on_timeout) =
        gate_fields("id: g\ngate: { title: t, timeout: '0s', on_timeout: deny }");
    assert!(matches!(
        AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout).unwrap_err(),
        HitlError::ZeroDeadline { .. }
    ));

    assert!(matches!(
        Escalate::try_from(&UnattendedDef {
            escalate: UnattendedEscalate::Park,
            deadline: Some("0s".to_string()),
            on_timeout: Some(OnTimeout::Deny),
        })
        .unwrap_err(),
        HitlError::ZeroDeadline { .. }
    ));
}

#[test]
fn gate_on_timeout_approve_reaches_awaiting_human_unchecked_because_its_precondition_is_run_time() {
    // §8.11: "`approve` is permitted only when the run's policy is narrower
    // than the job default" — a fact about the bound, running policy, not
    // about the document. `parse/steps.rs` defers it deliberately
    // (`gate_on_timeout_approve_parses_without_checking_its_run_time_precondition`)
    // and this module preserves that deferral: the executor, which holds the
    // run's effective policy, owns the check.
    let (title, form, timeout, on_timeout) =
        gate_fields("id: g\ngate: { title: t, timeout: 1h, on_timeout: approve }");
    let awaiting =
        AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout).unwrap();
    assert_eq!(awaiting.on_timeout.as_written(), &OnTimeout::Approve);
}

#[test]
fn reading_an_unchecked_on_timeout_as_a_decision_requires_supplying_the_run_time_fact() {
    // The deferral is a type, not a comment: the only way to a decision is
    // `resolve`, whose argument *is* §8.11's precondition. `false` fails
    // closed (§8.5 point 5, "capabilities narrow downward only") by
    // downgrading `approve` to `deny`; nothing else carries a precondition,
    // so nothing else moves in either direction.
    let approve = UncheckedOnTimeout::new(OnTimeout::Approve);
    assert_eq!(approve.resolve(false), OnTimeout::Deny);
    assert_eq!(approve.resolve(true), OnTimeout::Approve);
    // ...while the written value is still available for *rendering* the wait
    // ("approves on timeout"), which is what `as_written` is named for.
    assert_eq!(approve.as_written(), &OnTimeout::Approve);

    for unconditioned in [
        OnTimeout::Deny,
        OnTimeout::Fail,
        OnTimeout::Default("${{ inputs.fallback }}".to_string()),
    ] {
        let wrapped = UncheckedOnTimeout::new(unconditioned.clone());
        assert_eq!(wrapped.resolve(false), unconditioned, "{unconditioned:?}");
        assert_eq!(wrapped.resolve(true), unconditioned, "{unconditioned:?}");
    }
}

#[test]
fn every_suspend_reason_is_classified_so_a_sixth_core_variant_breaks_the_build() {
    // `SuspendReason` has five variants, not three: the three human waits
    // §8.11 unifies, plus the two messaging waits, which are not human waits
    // at all. This `match` has no wildcard arm, so adding a sixth core
    // variant fails to compile here rather than quietly falling through a
    // stale comment.
    fn human_wait_source_of(reason: &SuspendReason) -> Option<HumanWaitSource> {
        match reason {
            SuspendReason::WorkflowGate { .. } => Some(HumanWaitSource::Gate),
            SuspendReason::AwaitingApproval { .. } => Some(HumanWaitSource::PermissionEscalate),
            SuspendReason::AwaitingElicitation { .. } => Some(HumanWaitSource::Elicitation),
            SuspendReason::AwaitingReply | SuspendReason::AwaitingPeer { .. } => None,
        }
    }

    assert_eq!(
        human_wait_source_of(&SuspendReason::WorkflowGate {
            step_ref: "deploy".to_string()
        }),
        Some(HumanWaitSource::Gate)
    );
    assert_eq!(
        human_wait_source_of(&SuspendReason::AwaitingApproval {
            rule: None,
            params_digest: [0u8; 32],
        }),
        Some(HumanWaitSource::PermissionEscalate)
    );
    assert_eq!(
        human_wait_source_of(&SuspendReason::AwaitingElicitation {
            schema: serde_json::json!({"type": "object"}),
        }),
        Some(HumanWaitSource::Elicitation)
    );
    assert_eq!(human_wait_source_of(&SuspendReason::AwaitingReply), None);
    assert_eq!(
        human_wait_source_of(&SuspendReason::AwaitingPeer {
            session: SessionId::new(),
        }),
        None
    );
}

#[test]
fn a_gate_that_declares_no_form_asks_the_same_question_an_escalation_asks() {
    // `form:` is optional and defaults to `{}`, which as a schema is
    // `properties: {}` — no field expressing the decision, while every
    // escalation gets `{"approve": {"type": "boolean"}}`. That is the one
    // shape where §8.11's "TUI and web render from the same schema" would
    // hand the two renderers materially different instructions for the same
    // question, so a formless gate falls back to the escalation's field.
    let (title, form, timeout, on_timeout) =
        gate_fields("id: g\ngate: { title: 'Allow `git push`?', timeout: 1h, on_timeout: deny }");
    let formless =
        AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout).unwrap();
    assert_eq!(
        formless.form_schema["properties"]["approve"]["type"],
        serde_json::json!("boolean")
    );

    // An explicitly empty `form: {}` is indistinguishable from an omitted one
    // by the time it reaches here — `GateBodyDef` defaults the field to the
    // same `{}` — so it resolves the same way.
    let (title, form, timeout, on_timeout) = gate_fields(
        "id: g\ngate: { title: 'Allow `git push`?', form: {}, timeout: 1h, on_timeout: deny }",
    );
    let empty_form =
        AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout).unwrap();
    assert_eq!(empty_form.form_schema, formless.form_schema);

    // A gate that *does* declare fields has stated the form in full and is
    // left exactly as written — no approve field is injected alongside.
    let (title, form, timeout, on_timeout) = gate_fields(
        "id: g\ngate: { title: t, form: { note: { type: string } }, timeout: 1h, on_timeout: deny }",
    );
    let declared =
        AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout).unwrap();
    assert_eq!(
        declared.form_schema["properties"]["note"]["type"],
        serde_json::json!("string")
    );
    assert_eq!(
        declared.form_schema["properties"]["approve"],
        serde_json::Value::Null
    );
}

#[test]
fn a_gate_with_an_empty_title_is_rejected_rather_than_rendered_as_an_unlabelled_prompt() {
    // `GateBodyDef::title` is an unconstrained `String`, and `""` reaches
    // `form_schema`'s `"title"` and out to both renderers as an approval
    // prompt with nothing on it saying what is being approved.
    for blank in ["''", "'   '", "\"\\t\""] {
        let (title, form, timeout, on_timeout) = gate_fields(&format!(
            "id: g\ngate: {{ title: {blank}, timeout: 1h, on_timeout: deny }}"
        ));
        assert_eq!(
            AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout)
                .unwrap_err(),
            HitlError::EmptyGateTitle,
            "gate title {blank}"
        );
    }
}

#[test]
fn on_timeout_default_carries_its_argument_verbatim_with_evaluation_still_deferred() {
    let (title, form, timeout, on_timeout) = gate_fields(
        "id: g\ngate: { title: t, timeout: 1h, on_timeout: 'default(${{ inputs.fallback }})' }",
    );
    let awaiting =
        AwaitingHuman::from_gate(TaskId::new(), &title, &form, &timeout, &on_timeout).unwrap();

    // Uninterpolated source text, not a value: the `${{ }}` expression
    // language evaluates it at timeout time, not here.
    assert_eq!(
        awaiting.on_timeout.as_written(),
        &OnTimeout::Default("${{ inputs.fallback }}".to_string())
    );
}
