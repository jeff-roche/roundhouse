// §8.6 / §11.4's Runs inbox — the batch-triage view for "50 overnight runs."
//
// **This component never re-sorts `GET /api/runs`'s response (ruling R15).**
// The server's `sort_for_triage` (`runs.rs`) is a stable sort on
// `(!needs_human, Reverse(severity), outcome == Nothing)`; re-sorting here
// would silently diverge from that order the moment either side changes
// independently of the other. Every row below renders in the exact index
// order `res.runs` arrived in. What this component *is* allowed to do —
// and does — is label each row with its bucket (derived, never used to
// reorder) and collapse the genuinely no-op runs into one line (§11.4:
// "no-op runs must cost zero attention"; `runs.rs`'s own docs call this
// collapsing a client rendering job, not a server one).
//
// **"No-op" means `outcome === "nothing"` AND `needs_human === false`
// (ruling R15, amended) — not `outcome` alone.** The two fields are
// orthogonal axes on the server (`roundhouse_flow::report::Outcome`'s own
// doc comment), so a run can legally report `{"outcome":"nothing",
// "needs_human":true}`; collapsing on `outcome` alone would bury exactly
// the run this section's own rule exists to surface. See
// `isCollapsibleNoOp` and `bucketLabel` below.

import { createResource, createSignal, For, Show } from "solid-js";

import { fetchRuns, type DiffedFinding, type Finding, type Report, type RunSummary, type RunsResult } from "./api";

const REPORT_KNOWN_KEYS = [
  "outcome",
  "severity",
  "headline",
  "needs_human",
  "cost",
  "findings",
  "artifacts",
  "next_actions",
];

const FINDING_KNOWN_KEYS = ["id", "title", "severity", "location"];

/**
 * A row's triage bucket, derived from `(report.needs_human, report.outcome)`
 * — never from position. `Report.needs_human` and `Outcome` are orthogonal
 * axes (`roundhouse_flow::report::Outcome`'s own doc comment: "what the run
 * *found*" vs. "where the run *is*"), so `needs_human` is checked first,
 * matching the sort's own primary key (`sort_for_triage`'s own comment:
 * "`!needs_human` puts the runs wanting a human first" — `needs_human` is
 * the PRIMARY key, `outcome == Nothing` only tertiary), and `outcome` only
 * decides the label among runs that do not need a human.
 *
 * **This is why a run must never be treated as a no-op on `outcome` alone**
 * (see `buildDisplayRows` below): `outcome: "needs_human"` is itself one of
 * the five closed wire variants of `Outcome`, reachable through this
 * client's own type — a run can legally report `{"outcome":"nothing",
 * "needs_human":true}`, and `validate_report` ties neither field to the
 * other. The `default` arm below is the only genuinely defensive one, for a
 * sixth wire value this client does not yet know about.
 */
export function bucketLabel(report: Report): string {
  if (report.needs_human) {
    return "NEEDS YOU";
  }
  switch (report.outcome) {
    case "failed":
      return "FAILED";
    case "nothing":
      return "NO-OP";
    case "findings":
      return "FINDINGS";
    case "changed":
      return "LANDED";
    case "needs_human":
      // `needs_human: false` with `outcome: "needs_human"` is a
      // theoretically legal but unusual combination (the two are
      // orthogonal axes) — the boolean already won the label above when it
      // is true, so this arm exists only for the false case, and the
      // outcome value itself is the honest label for it.
      return "NEEDS HUMAN (OUTCOME)";
    default:
      return `OUTCOME: ${String(report.outcome)}`;
  }
}

/** Ruling R15 (amended): a run collapses into the no-op summary only when
 * it is BOTH `outcome === "nothing"` AND `needs_human === false`. A run
 * that needs a human is, by definition, not a no-op — collapsing on
 * `outcome` alone would bury exactly the run §11.4's "no-op runs must cost
 * zero attention" rule exists to surface (`report.rs`'s own warning:
 * "the Runs inbox would silently omit precisely the runs an operator most
 * needs to see"). */
function isCollapsibleNoOp(run: RunSummary): boolean {
  return run.report.outcome === "nothing" && !run.report.needs_human;
}

export type DisplayRow =
  | { kind: "run"; run: RunSummary }
  | { kind: "collapsed"; runs: RunSummary[] };

/**
 * Builds the rendered row sequence from the server's own order. Every
 * genuinely no-op run (`isCollapsibleNoOp`: `outcome === "nothing"` AND
 * `needs_human === false`) is pulled out of its individual position and
 * merged into ONE collapsed row, placed where the *first* such run
 * appeared — because no-op runs are not necessarily contiguous (the sort
 * key is `(!needs_human, Reverse(severity), outcome == Nothing)`, so a
 * high-severity run sorts ahead of a low-severity `changed` run regardless
 * of outcome), and §11.4 asks for the collapse regardless. Every other run
 * keeps its exact relative order and position around that one collapsed
 * row — nothing else moves.
 *
 * **Checking `needs_human` here, not just `outcome`, is the whole point.**
 * A run reporting `{"outcome":"nothing","needs_human":true}` is — by
 * definition — not a no-op: something about it wants a human's attention
 * even though nothing changed. Collapsing it into "N no-op runs" would bury
 * exactly the run §11.4's "no-op runs must cost zero attention" rule exists
 * to surface.
 */
export function buildDisplayRows(runs: RunSummary[]): DisplayRow[] {
  const rows: DisplayRow[] = [];
  let collapsed: RunSummary[] | null = null;

  for (const run of runs) {
    if (isCollapsibleNoOp(run)) {
      if (collapsed === null) {
        collapsed = [];
        rows.push({ kind: "collapsed", runs: collapsed });
      }
      collapsed.push(run);
    } else {
      rows.push({ kind: "run", run });
    }
  }

  return rows;
}

function extraEntries(data: Record<string, unknown>, known: string[]): [string, unknown][] {
  return Object.entries(data).filter(([key]) => !known.includes(key));
}

/**
 * `Report.extra`/`Finding.extra` are `#[serde(flatten)]` open maps of
 * job-defined keys — attacker-influenceable content from a workflow. Text
 * only, always: no `innerHTML`, no markup interpretation, whatever the
 * value's shape.
 */
function formatExtraValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function ExtraFields(props: { data: Record<string, unknown>; known: string[] }) {
  return (
    <For each={extraEntries(props.data, props.known)}>
      {([key, value]) => (
        <div class="extra-field">
          <span class="extra-key">{key}</span>: <span class="extra-value">{formatExtraValue(value)}</span>
        </div>
      )}
    </For>
  );
}

/**
 * A finding's own `extra` map may carry a `status` key of its own — that is
 * a job-defined field and must never be confused with `diffed.status`, the
 * diff verdict computed one level up in `runs.rs::DiffedFindingJson`
 * (deliberately nested rather than flattened there for exactly this
 * collision). Both are rendered, labelled distinctly.
 */
function FindingRow(props: { diffed: DiffedFinding }) {
  const finding = () => props.diffed.finding as Finding & Record<string, unknown>;

  return (
    <li class="finding">
      <span class="finding-diff-status" data-diff-status={props.diffed.status}>
        {props.diffed.status}
      </span>
      <span class="finding-title">{finding().title}</span>
      <span class="finding-severity">{finding().severity}</span>
      <span class="finding-location">{finding().location}</span>
      <ExtraFields data={finding()} known={FINDING_KNOWN_KEYS} />
    </li>
  );
}

function RunRow(props: { run: RunSummary }) {
  const report = () => props.run.report as Report & Record<string, unknown>;

  return (
    <li class="run" data-run-id={props.run.run_id}>
      <span class="bucket-label">{bucketLabel(report())}</span>
      <span class="headline">{report().headline}</span>
      <span class="severity">{report().severity}</span>
      <span class="cost">
        ${report().cost.usd.toFixed(2)} / {report().cost.tokens} tokens
      </span>
      {/* `binding_id` is `null` for a manually-invoked run — there is no
          binding to have diffed against, so this says that plainly rather
          than rendering an empty cell. */}
      <span class="binding-id">{props.run.binding_id ?? "manually invoked"}</span>
      <ExtraFields data={report()} known={REPORT_KNOWN_KEYS} />
      <Show when={props.run.diffed_findings.length > 0}>
        <ul class="findings">
          <For each={props.run.diffed_findings}>{(diffed) => <FindingRow diffed={diffed} />}</For>
        </ul>
      </Show>
    </li>
  );
}

function CollapsedNoOpRow(props: { runs: RunSummary[] }) {
  const [expanded, setExpanded] = createSignal(false);

  return (
    <li class="collapsed-noop">
      <button type="button" onClick={() => setExpanded((value) => !value)}>
        {props.runs.length} no-op run{props.runs.length === 1 ? "" : "s"} — nothing changed
        {expanded() ? " (hide)" : " (show)"}
      </button>
      <Show when={expanded()}>
        <ul>
          <For each={props.runs}>{(run) => <RunRow run={run} />}</For>
        </ul>
      </Show>
    </li>
  );
}

function RunsList(props: { runs: RunSummary[] }) {
  return (
    <Show when={props.runs.length > 0} fallback={<p class="runs-empty">Nothing needs you — the inbox is empty.</p>}>
      <ul class="run-list">
        <For each={buildDisplayRows(props.runs)}>
          {(row) => (row.kind === "run" ? <RunRow run={row.run} /> : <CollapsedNoOpRow runs={row.runs} />)}
        </For>
      </ul>
    </Show>
  );
}

/**
 * The three outcomes `fetchRuns()` can return, rendered as three visibly
 * different states — a successful **empty** inbox ("nothing needs you") must
 * never look like `unavailable` ("no store attached" / "at the concurrency
 * bound") or `error` (a query failure), and vice versa.
 */
function ResultBody(props: { result: RunsResult }) {
  return (
    <>
      <Show when={props.result.kind === "unavailable"}>
        <p class="runs-unavailable">
          This daemon's runs inbox is not available right now:{" "}
          {(props.result as { kind: "unavailable"; reason: string }).reason}
        </p>
      </Show>
      <Show when={props.result.kind === "error"}>
        <p class="runs-error">
          Loading the runs inbox failed: {(props.result as { kind: "error"; reason: string }).reason}
        </p>
      </Show>
      <Show when={props.result.kind === "ok"}>
        <RunsList runs={(props.result as { kind: "ok"; runs: RunSummary[] }).runs} />
      </Show>
    </>
  );
}

export function RunsInbox() {
  const [result] = createResource(fetchRuns);

  return (
    <section class="runs-inbox" aria-label="Runs inbox">
      <h2>Runs</h2>
      <Show when={!result.loading} fallback={<p class="runs-loading">Loading runs…</p>}>
        <Show when={result()}>{(res) => <ResultBody result={res()} />}</Show>
      </Show>
    </section>
  );
}
