use chrono::{TimeZone, Utc};
use chrono_tz::Tz;
use roundhouse_sched::cron::{fire_all_ambiguous, is_ambiguous_local, next_fire_after};
use roundhouse_sched::trigger::{DstAmbiguous, DstGap};
use std::time::Duration;

#[test]
fn spring_forward_gap_fires_at_gap_end() {
    // America/New_York, 2026-03-08: 02:00 local does not exist (springs to 03:00).
    // A "0 2 * * *" cron with FireAtGapEnd must fire at the first valid instant, 03:00 local.
    let tz = Tz::America__New_York;
    let after = Utc.with_ymd_and_hms(2026, 3, 8, 0, 0, 0).unwrap();
    let next = next_fire_after(
        "0 2 * * *",
        tz,
        after,
        &DstGap::FireAtGapEnd,
        &DstAmbiguous::First,
        Duration::ZERO,
    )
    .expect("computes next fire");
    let local = next.with_timezone(&tz);
    assert_eq!((local.format("%H:%M").to_string()), "03:00");
}

#[test]
fn fall_back_ambiguous_hour_fires_first_occurrence_by_default() {
    // America/New_York, 2026-11-01: 01:00-02:00 local occurs twice.
    let tz = Tz::America__New_York;
    let after = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap(); // before the fold, in UTC
    let next = next_fire_after(
        "30 1 * * *",
        tz,
        after,
        &DstGap::FireAtGapEnd,
        &DstAmbiguous::First,
        Duration::ZERO,
    )
    .expect("computes next fire");
    // The first occurrence of 01:30 local on 2026-11-01 is EDT (UTC-4), i.e. 05:30 UTC.
    assert_eq!(next, Utc.with_ymd_and_hms(2026, 11, 1, 5, 30, 0).unwrap());
}

#[test]
fn fall_back_ambiguous_hour_fires_second_occurrence_when_configured() {
    // Same fold as above, but DstAmbiguous::Second must resolve to the EST
    // (UTC-5) occurrence, i.e. 06:30 UTC, not the EDT one.
    let tz = Tz::America__New_York;
    let after = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap();
    let next = next_fire_after(
        "30 1 * * *",
        tz,
        after,
        &DstGap::FireAtGapEnd,
        &DstAmbiguous::Second,
        Duration::ZERO,
    )
    .expect("computes next fire");
    assert_eq!(next, Utc.with_ymd_and_hms(2026, 11, 1, 6, 30, 0).unwrap());
}

#[test]
fn fall_back_ambiguous_hour_next_fire_after_both_resolves_to_first_occurrence() {
    // review round 1, item 1: no test ever passed DstAmbiguous::Both to
    // next_fire_after, leaving the `Both => first` arm unexercised. Same
    // real 2026-11-01 fold as the other ambiguous tests: `Both` must
    // resolve `next_fire_after`'s single-instant return to the first
    // (EDT/UTC-4) occurrence, 05:30 UTC — the real double-fire is
    // `fire_all_ambiguous`, covered separately below.
    let tz = Tz::America__New_York;
    let after = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap();
    let next = next_fire_after(
        "30 1 * * *",
        tz,
        after,
        &DstGap::FireAtGapEnd,
        &DstAmbiguous::Both,
        Duration::ZERO,
    )
    .expect("computes next fire");
    assert_eq!(next, Utc.with_ymd_and_hms(2026, 11, 1, 5, 30, 0).unwrap());
}

#[test]
fn fire_all_ambiguous_returns_both_real_instants_of_the_fold() {
    // review round 1, item 1: fire_all_ambiguous had zero test coverage. A
    // typo swapping first/second, or returning the same instant twice,
    // would have gone undetected. Assert both full UTC instants (not
    // formatted "HH:MM" strings) against the real 2026-11-01
    // America/New_York fold: 01:30 local occurs once at EDT (UTC-4, i.e.
    // 05:30 UTC) and once at EST (UTC-5, i.e. 06:30 UTC).
    let tz = Tz::America__New_York;
    let after = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap();
    let instants = fire_all_ambiguous("30 1 * * *", tz, after).expect("finds the fold");
    assert_eq!(
        instants,
        vec![
            Utc.with_ymd_and_hms(2026, 11, 1, 5, 30, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 11, 1, 6, 30, 0).unwrap(),
        ]
    );
}

#[test]
fn fire_all_ambiguous_is_empty_when_the_schedule_never_hits_a_fold() {
    // A schedule that never lands on the ambiguous local hour at all (here,
    // noon, nowhere near either 2026 DST transition) must not fabricate an
    // ambiguous pair.
    let tz = Tz::America__New_York;
    let after = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap();
    let instants = fire_all_ambiguous("0 12 * * *", tz, after).expect("computes fine");
    assert!(instants.is_empty());
}

#[test]
fn is_ambiguous_local_detects_the_fold_and_rejects_unambiguous_times() {
    let tz = Tz::America__New_York;
    // 2026-11-01T01:30:00 local occurs twice (the fold this file tests
    // elsewhere).
    let folded = chrono::NaiveDate::from_ymd_opt(2026, 11, 1)
        .unwrap()
        .and_hms_opt(1, 30, 0)
        .unwrap();
    assert!(is_ambiguous_local(tz, folded));

    // An ordinary, unambiguous wall-clock time on the same day is not.
    let ordinary = chrono::NaiveDate::from_ymd_opt(2026, 11, 1)
        .unwrap()
        .and_hms_opt(12, 0, 0)
        .unwrap();
    assert!(!is_ambiguous_local(tz, ordinary));
}

#[test]
fn spring_forward_gap_skips_when_configured() {
    // With DstGap::Skip, the nonexistent 02:00 occurrence must not be fired
    // at all — the next fire is the following day's 02:00 (which exists).
    let tz = Tz::America__New_York;
    let after = Utc.with_ymd_and_hms(2026, 3, 8, 0, 0, 0).unwrap();
    let next = next_fire_after(
        "0 2 * * *",
        tz,
        after,
        &DstGap::Skip,
        &DstAmbiguous::First,
        Duration::ZERO,
    )
    .expect("computes next fire");
    let local = next.with_timezone(&tz);
    assert_eq!(
        local.format("%Y-%m-%d %H:%M").to_string(),
        "2026-03-09 02:00"
    );
}

#[test]
fn jitter_perturbs_the_fire_time_deterministically() {
    // finding 9: jitter was parsed and stored but never read anywhere.
    let tz = Tz::UTC;
    let after = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let base = next_fire_after(
        "0 2 * * *",
        tz,
        after,
        &DstGap::FireAtGapEnd,
        &DstAmbiguous::First,
        Duration::ZERO,
    )
    .unwrap();
    let jittered = next_fire_after(
        "0 2 * * *",
        tz,
        after,
        &DstGap::FireAtGapEnd,
        &DstAmbiguous::First,
        Duration::from_secs(300),
    )
    .unwrap();
    assert!(
        jittered >= base,
        "jitter only ever delays, never fires early"
    );
    assert!(
        jittered < base + chrono::Duration::seconds(300),
        "jitter never exceeds the configured window"
    );

    // Recomputing from the same inputs must reproduce the exact same
    // jittered instant — a binding's "when will this actually fire" answer
    // cannot change on every drift-triggered recompute (Task 3).
    let jittered_again = next_fire_after(
        "0 2 * * *",
        tz,
        after,
        &DstGap::FireAtGapEnd,
        &DstAmbiguous::First,
        Duration::from_secs(300),
    )
    .unwrap();
    assert_eq!(
        jittered, jittered_again,
        "jitter is deterministic, not re-rolled on every recompute"
    );
}

#[test]
fn invalid_cron_expression_is_rejected() {
    let tz = Tz::UTC;
    let after = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let result = next_fire_after(
        "not a cron expr",
        tz,
        after,
        &DstGap::FireAtGapEnd,
        &DstAmbiguous::First,
        Duration::ZERO,
    );
    assert!(result.is_err());
}
