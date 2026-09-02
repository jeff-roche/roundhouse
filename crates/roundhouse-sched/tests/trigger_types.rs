use chrono_tz::Tz;
use roundhouse_core::{Address, JobId, WorkspaceId};
use roundhouse_sched::trigger::{
    Binding, CatchUp, DstAmbiguous, DstGap, OverlapPolicy, TriggerSpec,
};
use std::time::Duration;

#[test]
fn cron_trigger_round_trips_through_json_with_required_tz() {
    let spec = TriggerSpec::Cron {
        expr: "0 2 * * *".to_string(),
        tz: Tz::America__New_York,
        catch_up: CatchUp::Latest,
        jitter: Duration::from_secs(0),
        dst_gap: DstGap::FireAtGapEnd,
        dst_ambiguous: DstAmbiguous::First,
    };
    let json = serde_json::to_string(&spec).expect("serialize");
    // tz must be serialized as an IANA name, never a fixed offset
    assert!(json.contains("America/New_York"));
    let back: TriggerSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(spec, back);
}

/// Fix round 2, finding L1: `OverlapPolicy` clamps `Concurrent`'s `max`
/// and `Queue`'s `depth` to their sanity ceilings at *deserialize* time —
/// a persisted `Binding` never carries an unbounded value in the first
/// place, rather than the ceiling only existing as a use-site `.min()` in
/// `roundhouse-sched::admission::decide_admission`.
#[test]
fn overlap_policy_concurrent_max_is_clamped_at_deserialize_time() {
    let json = r#"{"Concurrent":{"max":4294967295}}"#;
    let policy: OverlapPolicy = serde_json::from_str(json).expect("deserialize");
    assert_eq!(
        policy,
        OverlapPolicy::Concurrent {
            max: roundhouse_sched::trigger::MAX_OVERLAP_CONCURRENCY
        }
    );
}

#[test]
fn overlap_policy_queue_depth_is_clamped_at_deserialize_time() {
    let json = r#"{"Queue":{"depth":5000}}"#;
    let policy: OverlapPolicy = serde_json::from_str(json).expect("deserialize");
    assert_eq!(
        policy,
        OverlapPolicy::Queue {
            depth: roundhouse_sched::trigger::MAX_OVERLAP_QUEUE_DEPTH
        }
    );
}

#[test]
fn overlap_policy_queue_within_bounds_round_trips_unchanged() {
    let policy = OverlapPolicy::Queue { depth: 8 };
    let json = serde_json::to_string(&policy).expect("serialize");
    let back: OverlapPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, back);
}

/// Fix round 3, finding 1: the manual `Deserialize` impl added for L1
/// deserializes into a private `OverlapPolicyWire` shadow type first, then
/// matches on it — a mismatch between that shadow's variant shapes and
/// `OverlapPolicy`'s own externally-tagged representation would silently
/// break persisted config for whichever variant(s) it affected, with no
/// prior test to catch it (the round-1/round-2 clamp tests only exercise
/// `Concurrent`/`Queue`, and only ever as struct variants). Unit variants
/// in particular are where this would bite hardest — they serialize as a
/// bare JSON string (`"Skip"`), not an object, which is a different shape
/// entirely from the struct variants the existing tests cover.
#[test]
fn overlap_policy_skip_round_trips_unchanged() {
    let policy = OverlapPolicy::Skip;
    let json = serde_json::to_string(&policy).expect("serialize");
    assert_eq!(json, "\"Skip\"");
    let back: OverlapPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, back);
}

#[test]
fn overlap_policy_cancel_previous_round_trips_unchanged() {
    let policy = OverlapPolicy::CancelPrevious;
    let json = serde_json::to_string(&policy).expect("serialize");
    assert_eq!(json, "\"CancelPrevious\"");
    let back: OverlapPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, back);
}

#[test]
fn overlap_policy_concurrent_within_bounds_round_trips_unchanged() {
    let policy = OverlapPolicy::Concurrent { max: 4 };
    let json = serde_json::to_string(&policy).expect("serialize");
    let back: OverlapPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, back);
}

#[test]
fn binding_default_overlap_policy_is_skip_for_cron() {
    let binding = Binding::new_cron(JobId::new(), "0 2 * * *".to_string(), Tz::America__New_York);
    assert_eq!(binding.overlap, OverlapPolicy::Skip);
}

#[test]
fn message_trigger_binds_on_an_address_not_a_topic_string() {
    // A4: "Message binds on an Address (§7.2), not a topic string" — §7.3
    // deliberately cut topic pub/sub, so this variant must carry a real
    // Address the daemon-side bus already knows how to resolve.
    let workspace = WorkspaceId::new();
    let spec = TriggerSpec::Message {
        address: Address::Handle {
            workspace,
            name: "nightly-digest-listener".to_string(),
        },
        filter: Some("payload.kind == 'digest_request'".to_string()),
    };
    let binding = Binding::new(JobId::new(), spec);
    assert_eq!(binding.overlap, OverlapPolicy::Queue { depth: 8 });
    // The binding's own id doubles, deterministically, as the SessionId the
    // bus registers a mailbox under for this handle — see Task 4's
    // bind_message_trigger, which is what actually calls HandleRegistry.
    assert_eq!(
        binding.trigger_session_id().as_uuid(),
        binding.id.as_uuid(),
        "trigger_session_id is a pure re-typing of the binding's own id, not a second minted identity"
    );
}
