import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  asAck,
  asStderrDelta,
  asStdoutDelta,
  asTaskDelta,
  asTaskEvent,
  asTextDelta,
  connectSessionEvents,
  fetchRuns,
  isResyncRequired,
  isStreamErrorShape,
  postInteraction,
  type Outcome,
  type RunSummary,
  type Severity,
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

function run(
  id: string,
  overrides: { severity?: Severity; outcome?: Outcome; needsHuman?: boolean } = {},
): RunSummary {
  return {
    run_id: id,
    binding_id: null,
    report: {
      outcome: overrides.outcome ?? "findings",
      severity: overrides.severity ?? "low",
      headline: "h",
      needs_human: overrides.needsHuman ?? false,
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
    // Four runs whose `severity`/`outcome`/`needs_human` all differ, laid
    // out in the exact REVERSE of what `sort_for_triage`
    // (`(!needs_human, Reverse(severity), outcome == Nothing)`) would
    // produce from this set. A weaker fixture where every run shares the
    // same severity/outcome/needs_human would let a *triage-consistent*
    // client-side re-sort pass this test as a no-op — this one is
    // deliberately not already triage-sorted, so re-sorting it with
    // `sort_for_triage`'s own rule, or any other rule, changes the order
    // and fails the assertion below.
    const best = run("best-needs-human-high-findings", {
      needsHuman: true,
      severity: "high",
      outcome: "findings",
    });
    const second = run("second-needs-human-low-findings", {
      needsHuman: true,
      severity: "low",
      outcome: "findings",
    });
    const third = run("third-no-human-high-changed", {
      needsHuman: false,
      severity: "high",
      outcome: "changed",
    });
    const worst = run("worst-no-human-low-nothing", {
      needsHuman: false,
      severity: "low",
      outcome: "nothing",
    });
    // Correct triage order would be [best, second, third, worst]; the
    // server response below is its exact reverse.
    const server = [worst, third, second, best];
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

  it("reports a non-array 200 body as an error, never as a silent empty inbox (fix round 2)", async () => {
    // A 200 with, say, `{}` or a string body must never render the same
    // as a real, successful empty inbox — that would reproduce exactly
    // the confusion runs.rs's own docs argue against for the server side.
    mockFetch({ ok: true, status: 200, json: async () => ({ not: "an array" }) });

    const result = await fetchRuns();

    expect(result.kind).toBe("error");
    expect(result).not.toEqual({ kind: "ok", runs: [] });
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

  it("reports a 2xx as ok, not as an error — the day another lane wires a real sink", async () => {
    // Every non-501 status used to fall through to the error arm, which was
    // harmless only because the handler answers nothing but 501 today.
    mockFetch({ ok: true, status: 200, json: async () => ({}) });

    const result = await postInteraction("sess-1", { kind: "hard_cancel" });

    expect(result).toEqual({ kind: "ok" });
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

describe("asStdoutDelta / asStderrDelta", () => {
  it("decodes a JSON array of byte numbers as UTF-8 text, not base64", () => {
    const bytes = Array.from(new TextEncoder().encode("hello\n"));

    expect(asStdoutDelta({ Stdout: bytes })).toEqual({ text: "hello\n" });
    expect(asStderrDelta({ Stderr: bytes })).toEqual({ text: "hello\n" });
  });

  it("does not throw and reports no match on a non-array or non-numeric value", () => {
    expect(asStdoutDelta({ Stdout: "already-a-string" })).toBeUndefined();
    expect(asStdoutDelta({ Stdout: [1, "not-a-number", 3] })).toBeUndefined();
    expect(asStdoutDelta({})).toBeUndefined();
    expect(asStderrDelta({ Text: { text: "not stderr" } })).toBeUndefined();
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

describe("connectSessionEvents malformed frames (fix round 1, M5)", () => {
  // Unlike the onerror-only fake above, this one captures named listeners
  // so a test can fire `resync_required`/`stream_error` with an arbitrary
  // (including malformed) body.
  class FakeEventSource {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 2;
    readyState = FakeEventSource.CONNECTING;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    closed = false;
    private listeners = new Map<string, Array<(event: MessageEvent) => void>>();

    addEventListener(name: string, callback: (event: MessageEvent) => void): void {
      const existing = this.listeners.get(name) ?? [];
      existing.push(callback);
      this.listeners.set(name, existing);
    }

    close(): void {
      this.readyState = FakeEventSource.CLOSED;
      this.closed = true;
    }

    emitMessage(rawData: string): void {
      this.onmessage?.({ data: rawData, lastEventId: "" } as MessageEvent);
    }

    emitNamed(name: string, rawData: string): void {
      for (const callback of this.listeners.get(name) ?? []) {
        callback({ data: rawData } as MessageEvent);
      }
    }
  }

  beforeEach(() => {
    vi.stubGlobal("EventSource", FakeEventSource);
  });

  it("drops a malformed onmessage frame and keeps streaming, rather than throwing", () => {
    const onEvent = vi.fn();
    const source = connectSessionEvents("sess-1", {
      onEvent,
      onResyncRequired: () => {},
      onStreamError: () => {},
      onError: () => {},
    }) as unknown as FakeEventSource;

    expect(() => source.emitMessage("{not valid json")).not.toThrow();
    expect(onEvent).not.toHaveBeenCalled();
    expect(source.closed).toBe(false);

    // The stream keeps going: a subsequent well-formed frame still reaches onEvent.
    source.emitMessage(JSON.stringify({ Ack: { api_version: 0 } }));
    expect(onEvent).toHaveBeenCalledTimes(1);
  });

  // Fix round 2 (found alongside the dispatched items, same class):
  // `JSON.parse("null")` succeeds — it is not a syntax error — so a literal
  // `null` body used to reach `onEvent` uncast and unchecked, which then
  // throws downstream wherever the caller accesses a field on it (e.g.
  // `SessionView`'s `toLogLine`). `42`/`[]`/`{}` don't throw here (property
  // access on a boxed number or an empty object is just `undefined`), so
  // `null` is the one value this handler must gate on directly.
  it("drops a null onmessage frame rather than passing it to onEvent", () => {
    const onEvent = vi.fn();
    const source = connectSessionEvents("sess-1", {
      onEvent,
      onResyncRequired: () => {},
      onStreamError: () => {},
      onError: () => {},
    }) as unknown as FakeEventSource;

    expect(() => source.emitMessage("null")).not.toThrow();
    expect(onEvent).not.toHaveBeenCalled();
    expect(source.closed).toBe(false);
  });

  it("falls back to the terminal onStreamError state on a malformed resync_required body", () => {
    const onStreamError = vi.fn();
    const onResyncRequired = vi.fn();
    const source = connectSessionEvents("sess-1", {
      onEvent: () => {},
      onResyncRequired,
      onStreamError,
      onError: () => {},
    }) as unknown as FakeEventSource;

    expect(() => source.emitNamed("resync_required", "{not valid json")).not.toThrow();

    // Terminal either way — the connection is already close()d — but the
    // malformed body means this can't honestly claim to be a real
    // resync_required (no resume_from/oldest_retained to report), so it
    // falls back to the generic terminal handler instead.
    expect(onResyncRequired).not.toHaveBeenCalled();
    expect(onStreamError).toHaveBeenCalledOnce();
    expect(source.closed).toBe(true);
  });

  it("falls back to the terminal onStreamError state on a malformed stream_error body too", () => {
    const onStreamError = vi.fn();
    const source = connectSessionEvents("sess-1", {
      onEvent: () => {},
      onResyncRequired: () => {},
      onStreamError,
      onError: () => {},
    }) as unknown as FakeEventSource;

    expect(() => source.emitNamed("stream_error", "{not valid json")).not.toThrow();

    expect(onStreamError).toHaveBeenCalledOnce();
    expect(source.closed).toBe(true);
  });

  it("still reports a well-formed resync_required/stream_error normally", () => {
    const onStreamError = vi.fn();
    const onResyncRequired = vi.fn();
    const source = connectSessionEvents("sess-1", {
      onEvent: () => {},
      onResyncRequired,
      onStreamError,
      onError: () => {},
    }) as unknown as FakeEventSource;

    source.emitNamed("resync_required", JSON.stringify({ resume_from: 5, oldest_retained: 10 }));
    expect(onResyncRequired).toHaveBeenCalledWith({ resume_from: 5, oldest_retained: 10 });
    expect(onStreamError).not.toHaveBeenCalled();
  });

  // Fix round 2: `JSON.parse` succeeds on a value that is syntactically
  // valid JSON but not the expected shape — `null`, `42`, `[]`, `{}`, and
  // a record with a wrong-typed field all parse without throwing. Round 1
  // only checked for a JSON *syntax* error; these pin that a JSON-valid,
  // wrong-shaped body takes the same terminal-fallback path.
  //
  // A second review found the original wrong-typed-field case
  // (`{ resume_from: "not-a-number" }`) is a *missing* field for
  // `StreamError` (whose only field is `error`), not a wrong-typed one —
  // so it never actually exercised a wrong-typed `error` on that listener.
  // `{ error: 42 }` is wrong-typed for `stream_error` and, since it has no
  // `resume_from`/`oldest_retained` either, still exercises the
  // missing-field path for `resync_required` — one entry covers both.
  const jsonValidButWrongShape = [
    "null",
    "42",
    "[]",
    "{}",
    JSON.stringify({ resume_from: "not-a-number" }),
    JSON.stringify({ error: 42 }),
  ];

  it.each(jsonValidButWrongShape)(
    "falls back to onStreamError for a JSON-valid but wrong-shaped resync_required body: %s",
    (rawBody) => {
      const onStreamError = vi.fn();
      const onResyncRequired = vi.fn();
      const source = connectSessionEvents("sess-1", {
        onEvent: () => {},
        onResyncRequired,
        onStreamError,
        onError: () => {},
      }) as unknown as FakeEventSource;

      expect(() => source.emitNamed("resync_required", rawBody)).not.toThrow();

      expect(onResyncRequired).not.toHaveBeenCalled();
      expect(onStreamError).toHaveBeenCalledOnce();
    },
  );

  it.each(jsonValidButWrongShape)(
    "falls back to onStreamError for a JSON-valid but wrong-shaped stream_error body: %s",
    (rawBody) => {
      const onStreamError = vi.fn();
      const source = connectSessionEvents("sess-1", {
        onEvent: () => {},
        onResyncRequired: () => {},
        onStreamError,
        onError: () => {},
      }) as unknown as FakeEventSource;

      expect(() => source.emitNamed("stream_error", rawBody)).not.toThrow();

      // Called exactly once with a fallback message, never with the raw
      // (wrong-shaped) parsed value itself.
      expect(onStreamError).toHaveBeenCalledOnce();
      const [reported] = onStreamError.mock.calls[0] as [{ error: string }];
      expect(typeof reported.error).toBe("string");
    },
  );
});

describe("isResyncRequired / isStreamErrorShape", () => {
  it("accepts only the correct shape", () => {
    expect(isResyncRequired({ resume_from: 1, oldest_retained: 2 })).toBe(true);
    expect(isResyncRequired({ resume_from: "1", oldest_retained: 2 })).toBe(false);
    expect(isResyncRequired({ resume_from: 1 })).toBe(false);
    expect(isResyncRequired(null)).toBe(false);
    expect(isResyncRequired([])).toBe(false);
    expect(isResyncRequired(42)).toBe(false);
  });

  it("accepts only the correct shape for StreamError", () => {
    expect(isStreamErrorShape({ error: "boom" })).toBe(true);
    expect(isStreamErrorShape({ error: 42 })).toBe(false);
    expect(isStreamErrorShape({})).toBe(false);
    expect(isStreamErrorShape(null)).toBe(false);
  });
});
