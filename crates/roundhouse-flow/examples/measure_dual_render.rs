//! End-to-end cost of ruling P33's dual rendering, re-runnable from the tree.
//!
//! `cargo run --release -p roundhouse-flow --example measure_dual_render`
//!
//! # Why this file exists (fix round 4, item G)
//!
//! Fix round 3 measured this with an equivalent throwaway harness and then
//! **deleted it before committing**, so its figures (−1.1 % / −0.4 % / +5.0 %
//! wall clock, +32 kB peak RSS) lived only in a report and no later reader
//! could re-run them. This phase's own history is that unreproducible numbers
//! get repeated as fact — ruling P18 exists because six "bounded" /
//! "negligible" claims in this crate were falsified by execution. A number
//! nobody can re-derive is a claim, not a measurement, so the harness is now
//! part of the tree.
//!
//! # What it measures, and what it deliberately does not
//!
//! It times the whole public path — `parse_workflow` -> `Executor::new` ->
//! `run_to_completion` — because that is the only thing a caller of this crate
//! ever pays. That total is dominated by `parse_step` over every step's
//! `serde_yaml::Value` and by the sink's own `serde_json` work; the second
//! rendering is a small term inside it. It does **not** isolate the cost of
//! building the redacted rendering alone, and it does not measure a `map.over`
//! fan-out (Task 6, does not exist yet), allocation counts, or any workload
//! above `parse::MAX_YAML_BYTES` (262,144), which caps what `parse_workflow`
//! accepts at all.
//!
//! # Comparing two trees
//!
//! This harness uses only public API that is unchanged since commit `e06149b`
//! (the pre-P33 base): `parse_workflow`, `RunContext`, `Executor::new`,
//! `run_to_completion`, `TaskSink`. To reproduce a base-vs-fix delta, check
//! out the other tree, drop this file into `crates/roundhouse-flow/examples/`,
//! and run it there — it compiles against both.

use roundhouse_core::{EventPayload, TaskId, TaskKind};
use roundhouse_flow::exec::{Executor, RunContext, RunId, TaskSink};
use roundhouse_flow::expr::EnvAllowlist;
use roundhouse_flow::parse::parse_workflow;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Serializes every emitted payload, the way a real sink writing to the
/// `events` table would, so the measurement includes what the redacted
/// rendering actually costs to persist rather than only to build.
struct CountingSink {
    events: usize,
    bytes: usize,
}

impl TaskSink for CountingSink {
    fn emit(
        &mut self,
        _task_id: TaskId,
        _parent: Option<TaskId>,
        _kind: TaskKind,
        payload: EventPayload,
    ) {
        self.events += 1;
        self.bytes += serde_json::to_string(&payload)
            .map(|s| s.len())
            .unwrap_or(0);
    }
}

/// Builds a workflow of `steps` `tool:` steps, each with `leaves` `with:`
/// fields. One leaf in four references `${{ secrets.TOKEN }}` (so it is
/// secret-derived and the two renderings differ); the rest reference
/// `${{ inputs.repo }}` (so both renderings are byte-identical). That ratio is
/// the one fix round 3 used, kept so the two sets of figures are comparable.
fn workload_yaml(steps: usize, leaves: usize) -> String {
    let mut yaml = String::from(
        "name: measure\nversion: 1\ninputs: {}\ndefaults: { isolation: worktree }\n\
         permissions: { default: deny, unattended: { escalate: fail } }\nsteps:\n",
    );
    for s in 0..steps {
        yaml.push_str(&format!("  - id: s{s}\n    tool: shell\n    with:\n"));
        for l in 0..leaves {
            if l % 4 == 0 {
                yaml.push_str(&format!(
                    "      f{l}: \"prefix-{l}-${{{{ secrets.TOKEN }}}}-suffix\"\n"
                ));
            } else {
                yaml.push_str(&format!(
                    "      f{l}: \"prefix-{l}-${{{{ inputs.repo }}}}-suffix\"\n"
                ));
            }
        }
    }
    yaml
}

fn run_once(yaml: &str) -> (Duration, usize, usize) {
    let def = parse_workflow(yaml).expect("workload YAML parses");
    let mut sink = CountingSink {
        events: 0,
        bytes: 0,
    };
    let mut secrets = HashMap::new();
    secrets.insert("TOKEN".to_string(), "sk-measurement-token-0001".to_string());
    let run_ctx = RunContext {
        inputs: serde_json::json!({"repo": "acme/widgets"}),
        vars: serde_json::json!({}),
        secrets,
        run_id: RunId::new(),
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: None,
    };
    let start = Instant::now();
    let mut exec = Executor::new(&def, &mut sink, run_ctx).expect("secrets clear the length floor");
    let outcomes = exec.run_to_completion().expect("the workload runs");
    let elapsed = start.elapsed();
    assert!(!outcomes.is_empty());
    (elapsed, sink.events, sink.bytes)
}

/// Peak resident set size of this process so far, in kB, from
/// `/proc/self/status`'s `VmHWM`. Linux-only; returns `None` elsewhere, in
/// which case the RSS column is simply not reported.
fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb| kb.parse().ok())
}

fn main() {
    // Min of N, not a mean: the minimum is the least noisy estimator of the
    // work actually done, since scheduler noise can only add time.
    const REPEATS: usize = 7;
    let workloads = [(100usize, 20usize), (150, 20), (30, 100)];

    println!("workload                     yaml_bytes   min_of_7   events   sink_bytes");
    for (steps, leaves) in workloads {
        let yaml = workload_yaml(steps, leaves);
        let mut best = Duration::MAX;
        let mut events = 0;
        let mut bytes = 0;
        for _ in 0..REPEATS {
            let (elapsed, e, b) = run_once(&yaml);
            best = best.min(elapsed);
            events = e;
            bytes = b;
        }
        println!(
            "{steps:>4} steps x {leaves:>3} leaves   {:>10}   {:>7} us   {events:>6}   {bytes:>10}",
            yaml.len(),
            best.as_micros(),
        );
    }
    match peak_rss_kb() {
        Some(kb) => println!("\nprocess peak RSS (VmHWM): {kb} kB"),
        None => println!("\nprocess peak RSS: unavailable on this platform"),
    }
}
