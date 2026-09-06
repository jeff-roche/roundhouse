import { render } from "solid-js/web";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { RunSummary } from "./api";
import { bucketLabel, buildDisplayRows, RunsInbox } from "./RunsInbox";

function run(id: string, overrides: Partial<RunSummary["report"]> = {}, bindingId: string | null = null): RunSummary {
  return {
    run_id: id,
    binding_id: bindingId,
    report: {
      outcome: "findings",
      severity: "low",
      headline: `headline-${id}`,
      needs_human: false,
      cost: { usd: 0, tokens: 0 },
      findings: [],
      artifacts: [],
      next_actions: [],
      ...overrides,
    },
    diffed_findings: [],
  };
}

function mockFetch(response: { ok: boolean; status: number; json: () => Promise<unknown> }): void {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
}

function mount(): HTMLDivElement {
  const container = document.createElement("div");
  document.body.appendChild(container);
  render(() => <RunsInbox />, container);
  return container;
}

beforeEach(() => {
  window.sessionStorage.clear();
});

describe("bucketLabel", () => {
  it("labels a run that needs a human first, regardless of outcome", () => {
    expect(bucketLabel({ outcome: "failed", needs_human: true } as never)).toBe("NEEDS YOU");
  });

  it("labels the remaining outcomes when needs_human is false", () => {
    expect(bucketLabel({ outcome: "failed", needs_human: false } as never)).toBe("FAILED");
    expect(bucketLabel({ outcome: "nothing", needs_human: false } as never)).toBe("NO-OP");
    expect(bucketLabel({ outcome: "findings", needs_human: false } as never)).toBe("FINDINGS");
    expect(bucketLabel({ outcome: "changed", needs_human: false } as never)).toBe("LANDED");
  });

  it("handles the needs_human OUTCOME variant explicitly rather than falling through to the default arm", () => {
    // `"needs_human"` is one of Outcome's five closed wire variants
    // (api.ts), reachable through this file's own type — not the
    // unreachable case a prior version's comment claimed. This pins the
    // `needs_human: false` case (the `true` case is already covered above,
    // since the boolean wins regardless of outcome).
    expect(bucketLabel({ outcome: "needs_human", needs_human: false } as never)).toBe("NEEDS HUMAN (OUTCOME)");
  });
});

describe("buildDisplayRows", () => {
  it("keeps every non-nothing run in its exact relative order and position", () => {
    const a = run("a", { outcome: "needs_human", needs_human: true, severity: "high" });
    const nothing1 = run("n1", { outcome: "nothing" });
    const b = run("b", { outcome: "changed" });
    const nothing2 = run("n2", { outcome: "nothing" });
    const c = run("c", { outcome: "failed" });

    const rows = buildDisplayRows([a, nothing1, b, nothing2, c]);

    expect(rows).toEqual([
      { kind: "run", run: a },
      { kind: "collapsed", runs: [nothing1, nothing2] },
      { kind: "run", run: b },
      { kind: "run", run: c },
    ]);
  });

  it("produces no collapsed row at all when nothing is a no-op", () => {
    const a = run("a", { outcome: "changed" });
    expect(buildDisplayRows([a])).toEqual([{ kind: "run", run: a }]);
  });

  it("never collapses a nothing-outcome run that also needs a human (ruling R15, amended)", () => {
    // {"outcome":"nothing","needs_human":true} is a legal combination — the
    // two fields are orthogonal axes on the server — and it is, by
    // definition, not a no-op: something about it wants a human's
    // attention. Fix round 1 (whole-branch review): the prior version
    // collapsed on `outcome` alone and buried this run.
    const needsHumanButNothing = run("nh", { outcome: "nothing", needs_human: true });
    const genuineNoOp = run("noop", { outcome: "nothing", needs_human: false });

    const rows = buildDisplayRows([needsHumanButNothing, genuineNoOp]);

    expect(rows).toEqual([
      { kind: "run", run: needsHumanButNothing },
      { kind: "collapsed", runs: [genuineNoOp] },
    ]);
  });
});

describe("RunsInbox rendering", () => {
  it("renders a successful empty inbox as a reassuring message, distinct from unavailable/error", async () => {
    mockFetch({ ok: true, status: 200, json: async () => [] });
    const container = mount();

    await vi.waitFor(() => expect(container.textContent).toContain("Nothing needs you"));

    expect(container.querySelector(".runs-unavailable")).toBeNull();
    expect(container.querySelector(".runs-error")).toBeNull();
  });

  it("renders 503 as unavailable, not as an empty inbox and not as a generic error", async () => {
    mockFetch({ ok: false, status: 503, json: async () => ({ error: "at the concurrency bound" }) });
    const container = mount();

    await vi.waitFor(() => expect(container.querySelector(".runs-unavailable")).not.toBeNull());

    expect(container.textContent).toContain("at the concurrency bound");
    expect(container.textContent).not.toContain("Nothing needs you");
    expect(container.querySelector(".runs-error")).toBeNull();
  });

  it("renders 500 as an error, distinct from both unavailable and an empty inbox", async () => {
    mockFetch({ ok: false, status: 500, json: async () => ({ error: "the query failed" }) });
    const container = mount();

    await vi.waitFor(() => expect(container.querySelector(".runs-error")).not.toBeNull());

    expect(container.textContent).toContain("the query failed");
    expect(container.querySelector(".runs-unavailable")).toBeNull();
  });

  it("renders runs in the server's exact order, even when it looks wrong, and never re-sorts", async () => {
    // Reverse of what `sort_for_triage` would produce from this set — see
    // `api.test.ts` for the same argument against `fetchRuns` directly. This
    // pins the same property one layer up, against the actual DOM order.
    const best = run("best", { needs_human: true, severity: "high", outcome: "findings" });
    const worst = run("worst", { needs_human: false, severity: "low", outcome: "changed" });
    const server = [worst, best];
    mockFetch({ ok: true, status: 200, json: async () => server });
    const container = mount();

    await vi.waitFor(() => expect(container.querySelectorAll(".run").length).toBeGreaterThan(0));

    const ids = Array.from(container.querySelectorAll(".run")).map((el) => el.getAttribute("data-run-id"));
    expect(ids).toEqual(["worst", "best"]);
  });

  it("renders binding_id null as a manually-invoked run, not an empty cell", async () => {
    mockFetch({ ok: true, status: 200, json: async () => [run("a", {}, null)] });
    const container = mount();

    await vi.waitFor(() => expect(container.textContent).toContain("manually invoked"));
  });

  it("collapses nothing-outcome runs to one line by default, expandable", async () => {
    mockFetch({
      ok: true,
      status: 200,
      json: async () => [run("a", { outcome: "nothing" }), run("b", { outcome: "nothing" })],
    });
    const container = mount();

    await vi.waitFor(() => expect(container.querySelector(".collapsed-noop")).not.toBeNull());

    // Collapsed by default: the individual runs are not rendered as `.run` rows.
    expect(container.querySelectorAll(".run").length).toBe(0);
    expect(container.textContent).toContain("2 no-op runs");

    const button = container.querySelector("button") as HTMLButtonElement;
    button.click();

    await vi.waitFor(() => expect(container.querySelectorAll(".run").length).toBe(2));
  });

  it("renders extra Report/Finding fields as text, and does not let a finding's own status shadow the diff verdict", async () => {
    const withExtra: RunSummary = {
      run_id: "a",
      binding_id: "b-1",
      report: {
        outcome: "findings",
        severity: "med",
        headline: "h",
        needs_human: false,
        cost: { usd: 1.5, tokens: 42 },
        findings: [],
        artifacts: [],
        next_actions: [],
        job_defined_key: "job-defined-value",
      } as never,
      diffed_findings: [
        {
          finding: {
            id: "f1",
            title: "finding title",
            severity: "high",
            location: "src/foo.rs:1",
            // A job-defined `status` on the finding itself — must not be
            // confused with the diff verdict below.
            status: "job-says-open",
          } as never,
          status: "persisting",
        },
      ],
    };
    mockFetch({ ok: true, status: 200, json: async () => [withExtra] });
    const container = mount();

    await vi.waitFor(() => expect(container.querySelector(".finding")).not.toBeNull());

    expect(container.textContent).toContain("job_defined_key");
    expect(container.textContent).toContain("job-defined-value");

    const diffStatus = container.querySelector(".finding-diff-status");
    expect(diffStatus?.textContent).toBe("persisting");
    expect(diffStatus?.getAttribute("data-diff-status")).toBe("persisting");

    // The finding's own job-defined `status` extra field still renders
    // (it is legitimate content), just not in place of the diff verdict.
    expect(container.textContent).toContain("job-says-open");
  });
});
