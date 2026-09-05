import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  asAck,
  asTaskDelta,
  asTaskEvent,
  asTextDelta,
  connectSessionEvents,
  fetchRuns,
  postInteraction,
  type RunSummary,
} from "./api";

function mockFetch(response: {
  ok: boolean;
  status: number;
  json?: () => Promise<unknown>;
  text?: () => Promise<string>;
}): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      json: async () => ({}),
      ...response,
    }),
  );
}

function run(id: string): RunSummary {
  return {
    run_id: id,
    binding_id: null,
    report: {
      outcome: "findings",
      severity: "low",
      headline: "h",
      needs_human: false,
      cost: { usd: 0, tokens: 0 },
      findings: [],
      artifacts: [],
      next_actions: [],
    },
    diffed_findings: [],
  };
}

beforeEach(() => {
  window.sessionStorage.clear();
});

describe("fetchRuns", () => {
  it("returns the server's array in the order it arrived, without re-sorting", async () => {
    // Deliberately in an order that the client's own triage rule would
    // reverse if it re-sorted: the server already applied
    // `sort_for_triage` and the client must trust it verbatim.
    const server = [run("z"), run("a"), run("m")];
    mockFetch({ ok: true, status: 200, json: async () => server });

    const result = await fetchRuns();

    expect(result).toEqual({ kind: "ok", runs: server });
  });

  it("treats an empty array as a real, successful answer distinct from unavailable", async () => {
    mockFetch({ ok: true, status: 200, json: async () => [] });

    const result = await fetchRuns();

    expect(result).toEqual({ kind: "ok", runs: [] });
  });

  it("reports 503 (no store attached / at the concurrency bound) as unavailable", async () => {
    mockFetch({
      ok: false,
      status: 503,
      json: async () => ({ error: "this API is at its concurrency bound" }),
    });

    const result = await fetchRuns();

    expect(result).toEqual({
      kind: "unavailable",
      reason: "this API is at its concurrency bound",
    });
  });

  it("reports 500 (a query failure) as an error, distinct from both 503 and an empty inbox", async () => {
    mockFetch({
      ok: false,
      status: 500,
      json: async () => ({ error: "the runs inbox failed while loading the runs inbox" }),
    });

    const result = await fetchRuns();

    expect(result).toEqual({
      kind: "error",
      status: 500,
      reason: "the runs inbox failed while loading the runs inbox",
    });
  });
});

describe("postInteraction", () => {
  it("sends exactly the kind/text keys the backend accepts, nothing else", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 501,
      json: async () => ({ error: "not implemented" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await postInteraction("sess-1", { kind: "steer", text: "look here" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/sessions/sess-1/interactions");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ kind: "steer", text: "look here" });
  });

  it("models the backend's current 501 as a first-class outcome, not a swallowed error", async () => {
    mockFetch({
      ok: false,
      status: 501,
      json: async () => ({
        error:
          "this daemon parses interactions but cannot yet deliver one: no session-actor sink is wired to this route, so nothing received it",
      }),
    });

    const result = await postInteraction("sess-1", { kind: "soft_interrupt" });

    expect(result.kind).toBe("not_implemented");
  });
});

describe("tolerance of #[non_exhaustive] variants", () => {
  it("does not throw on an unrecognised top-level ClientEvent key, and reports no match", () => {
    const event = { SomeFutureVariant: { anything: 1 } };

    expect(() => asTaskEvent(event)).not.toThrow();
    expect(() => asAck(event)).not.toThrow();
    expect(asTaskEvent(event)).toBeUndefined();
    expect(asAck(event)).toBeUndefined();
  });

  it("does not throw on an unrecognised EventPayload/Delta variant either", () => {
    const payload = { SomeFuturePayload: { anything: 1 } };
    expect(asTaskDelta(payload)).toBeUndefined();

    const delta = { SomeFutureDelta: { anything: 1 } };
    expect(asTextDelta(delta)).toBeUndefined();
  });

  it("still reads the known TaskEvent/TaskDelta/Text shape", () => {
    const event = {
      TaskEvent: {
        session_id: "sess-1",
        task_id: null,
        payload: { TaskDelta: { delta: { Text: { text: "hi" } } } },
      },
    };

    const envelope = asTaskEvent(event);
    expect(envelope?.session_id).toBe("sess-1");

    const delta = asTaskDelta(envelope!.payload);
    expect(asTextDelta(delta!.delta)).toEqual({ text: "hi" });
  });
});

describe("connectSessionEvents onerror", () => {
  // A minimal stand-in for the browser's `EventSource`. Real `readyState`
  // values: 0 = CONNECTING, 1 = OPEN, 2 = CLOSED — mirrored here so
  // `api.ts`'s own `EventSource.CLOSED` comparison (against this stubbed
  // global) means the same thing a real one would.
  class FakeEventSource {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 2;
    readyState = FakeEventSource.CONNECTING;
    onerror: (() => void) | null = null;
    close() {
      this.readyState = FakeEventSource.CLOSED;
    }
    addEventListener() {}
    fireError(): void {
      this.onerror?.();
    }
  }

  beforeEach(() => {
    vi.stubGlobal("EventSource", FakeEventSource);
  });

  it("reports a permanently refused open (readyState CLOSED) as terminal", () => {
    let terminal: boolean | undefined;
    const source = connectSessionEvents("sess-1", {
      onEvent: () => {},
      onResyncRequired: () => {},
      onStreamError: () => {},
      onError: (t) => {
        terminal = t;
      },
    }) as unknown as FakeEventSource;

    // A non-2xx or wrong-content-type response fails an `EventSource`
    // connection outright (per spec) — the browser sets `readyState` to
    // `CLOSED` and will not retry. That is what a bad session id/cursor
    // `400`, or a `401`/`403` from the LAN gate, looks like from here.
    source.readyState = FakeEventSource.CLOSED;
    source.fireError();

    expect(terminal).toBe(true);
  });

  it("reports a transient drop (readyState CONNECTING) as non-terminal", () => {
    let terminal: boolean | undefined;
    const source = connectSessionEvents("sess-1", {
      onEvent: () => {},
      onResyncRequired: () => {},
      onStreamError: () => {},
      onError: (t) => {
        terminal = t;
      },
    }) as unknown as FakeEventSource;

    // The browser is already retrying on its own here — this is the
    // ordinary "the connection dropped, reconnecting" case, not a refusal.
    source.readyState = FakeEventSource.CONNECTING;
    source.fireError();

    expect(terminal).toBe(false);
  });
});
