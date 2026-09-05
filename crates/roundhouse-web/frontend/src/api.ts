// The whole `/api` client surface, against the contract verified directly off
// `crates/roundhouse-web/src/{runs,sse,interaction,lan_auth}.rs` (see
// `.superpowers/sdd/W2/progress.md`'s "Verified backend contract").
//
// Every request is a *relative* path. There is no CORS layer anywhere in the
// crate and no `OPTIONS` route (`lan_auth.rs`), so this client is
// same-origin-or-proxy only and must never call an absolute origin — see
// `vite.config.ts`'s dev proxy for the one place that matters during
// development.

import { getToken } from "./token";

// ── Wire types ──────────────────────────────────────────────────────────

export type Severity = "low" | "med" | "high";

export type Outcome = "nothing" | "changed" | "findings" | "failed" | "needs_human";

export interface Cost {
  usd: number;
  tokens: number;
}

/**
 * `roundhouse_flow::report::Finding`. `#[serde(flatten)]` on the Rust side
 * puts a job's own fields directly on this object, so this stays an open
 * shape rather than a closed interface.
 */
export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  location: string;
  [extra: string]: unknown;
}

export type FindingStatus = "new" | "persisting" | "resolved";

export interface DiffedFinding {
  finding: Finding;
  status: FindingStatus;
}

/** `roundhouse_flow::report::Report`, §8.6's core+extension report schema. */
export interface Report {
  outcome: Outcome;
  severity: Severity;
  headline: string;
  needs_human: boolean;
  cost: Cost;
  findings: Finding[];
  artifacts: unknown[];
  next_actions: string[];
  [extra: string]: unknown;
}

/** One row of `GET /api/runs` — `roundhouse_web::runs::RunSummaryJson`. */
export interface RunSummary {
  run_id: string;
  binding_id: string | null;
  report: Report;
  diffed_findings: DiffedFinding[];
}

// ── `GET /api/runs` ─────────────────────────────────────────────────────

export type RunsResult =
  | { kind: "ok"; runs: RunSummary[] }
  /** No store attached, or the API pool is at its concurrency bound. */
  | { kind: "unavailable"; reason: string }
  | { kind: "error"; status: number; reason: string };

/**
 * `GET /api/runs` — already sorted by the server's `sort_for_triage`
 * (`(needs_human, severity, outcome != nothing)`, `runs.rs`). **Never
 * re-sort the result**: doing so silently diverges from that order the
 * moment either side changes independently of the other.
 *
 * `503` (no store attached / at the concurrency bound) and any other
 * non-2xx are distinct outcomes from `{ kind: "ok", runs: [] }` — an empty
 * inbox is a real, reassuring answer ("nothing needs you") and must never
 * be indistinguishable from "this daemon has no database".
 */
export async function fetchRuns(): Promise<RunsResult> {
  const response = await apiFetch("/api/runs");

  if (response.status === 503) {
    return { kind: "unavailable", reason: await errorReason(response) };
  }
  if (!response.ok) {
    return { kind: "error", status: response.status, reason: await errorReason(response) };
  }

  const runs = (await response.json()) as RunSummary[];
  return { kind: "ok", runs };
}

// ── `POST /api/sessions/{session_id}/interactions` ─────────────────────

/**
 * §11.4's four inputs, exactly as `interaction.rs::parse_interaction`
 * accepts them. Unknown fields are refused with `400`, so this sends
 * precisely these keys and no others.
 */
export type InteractionInput =
  | { kind: "soft_interrupt" }
  | { kind: "hard_cancel" }
  | { kind: "queue"; text: string }
  | { kind: "steer"; text: string };

export type InteractionResult =
  /**
   * Every non-`501` status used to fall through to the error arm below,
   * including a `2xx` — harmless while the handler only ever answers `501`,
   * but the moment another lane wires a real sink this would silently report
   * success as failure. So a `2xx` is its own first-class outcome, checked
   * before `501`.
   */
  | { kind: "ok" }
  /**
   * The handler parses every interaction correctly but has no
   * session-actor sink to dispatch to (ruling R6). A first-class, expected
   * outcome today — not an error to swallow, and not one to retry past.
   */
  | { kind: "not_implemented"; reason: string }
  | { kind: "error"; status: number; reason: string };

export async function postInteraction(
  sessionId: string,
  input: InteractionInput,
): Promise<InteractionResult> {
  const response = await apiFetch(`/api/sessions/${encodeURIComponent(sessionId)}/interactions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });

  if (response.ok) {
    return { kind: "ok" };
  }
  if (response.status === 501) {
    return { kind: "not_implemented", reason: await errorReason(response) };
  }
  return { kind: "error", status: response.status, reason: await errorReason(response) };
}

// ── `GET /api/sessions/{session_id}/events` (SSE) ──────────────────────

/**
 * `roundhouse_proto::ClientEvent` and `roundhouse_core::EventPayload` are
 * externally-tagged Rust enums serialised with their PascalCase variant
 * names verbatim (e.g. `{"TaskEvent":{...}}`), and are grown without notice
 * — a client that switched on a closed set of keys would break the moment a
 * variant it does not know about arrives. So these are left as open records;
 * `asTaskEvent`/`asAck`/`asTaskDelta`/`asTextDelta` below are the
 * discriminating accessors, and each tolerates an unrecognised top-level key
 * by returning `undefined` rather than throwing.
 */
export type ClientEvent = Record<string, unknown>;
export type EventPayload = Record<string, unknown>;
export type Delta = Record<string, unknown>;

export interface TaskEventEnvelope {
  session_id: string;
  task_id: string | null;
  payload: EventPayload;
}

export interface AckEnvelope {
  api_version: number;
}

export function asTaskEvent(event: ClientEvent): TaskEventEnvelope | undefined {
  return asRecord(event["TaskEvent"]) as TaskEventEnvelope | undefined;
}

export function asAck(event: ClientEvent): AckEnvelope | undefined {
  return asRecord(event["Ack"]) as AckEnvelope | undefined;
}

export function asTaskDelta(payload: EventPayload): { delta: Delta } | undefined {
  return asRecord(payload["TaskDelta"]) as { delta: Delta } | undefined;
}

/** `Delta::Text { text }`. */
export function asTextDelta(delta: Delta): { text: string } | undefined {
  const value = delta["Text"];
  return isRecord(value) && typeof value.text === "string"
    ? (value as { text: string })
    : undefined;
}

/**
 * `Delta::Stdout`/`Delta::Stderr` serialise as a JSON array of byte numbers
 * (not base64, not a UTF-8 string), decoded here with `TextDecoder` rather
 * than left to the caller — every consumer needs the same decode, and
 * getting it wrong (treating the array as already-text) is the obvious
 * mistake.
 */
export function asStdoutDelta(delta: Delta): { text: string } | undefined {
  return decodeByteArrayDelta(delta, "Stdout");
}

/** See {@link asStdoutDelta}. */
export function asStderrDelta(delta: Delta): { text: string } | undefined {
  return decodeByteArrayDelta(delta, "Stderr");
}

function decodeByteArrayDelta(delta: Delta, key: "Stdout" | "Stderr"): { text: string } | undefined {
  const value = delta[key];
  if (!Array.isArray(value) || !value.every((byte) => typeof byte === "number")) {
    return undefined;
  }
  return { text: new TextDecoder().decode(new Uint8Array(value as number[])) };
}

export interface ResyncRequired {
  resume_from: number;
  oldest_retained: number;
}

export interface StreamError {
  error: string;
}

export interface SessionStreamHandlers {
  onEvent: (event: ClientEvent, lastEventId: string | null) => void;
  /**
   * Terminal (ruling R13): there is no snapshot route to refetch from, so
   * this is where a caller renders "the server dropped events this client
   * never received; reload to resume" with a manual reload control. The
   * `EventSource` is already `close()`d by the time this fires — never let a
   * stock one reconnect on its own here, or it resumes into the same tail
   * miss forever.
   */
  onResyncRequired: (info: ResyncRequired) => void;
  /** Also terminal, also already `close()`d. */
  onStreamError: (info: StreamError) => void;
  /**
   * The connection itself failed to open or dropped — distinct from
   * `onResyncRequired`/`onStreamError`, which are named frames the server
   * sent over an already-open stream. There is no response body to read
   * here: a native `EventSource` exposes no status or body on failure, only
   * `readyState` (per the Fetch/EventSource specs, a non-2xx response or the
   * wrong content type fails the connection outright — the `400`s
   * `sse::stream_session_events` answers for a bad session id or cursor, or
   * a `401`/`403` from the LAN gate, all land here, never on `onmessage`).
   *
   * `terminal` is `true` when `readyState === EventSource.CLOSED` — the
   * browser has given up and will not retry on its own (a refused open, or a
   * `403`/`401` that will refuse again identically). It is `false` while
   * `readyState === EventSource.CONNECTING`, a transient drop the browser is
   * already retrying by itself.
   */
  onError: (terminal: boolean) => void;
}

/**
 * `GET /api/sessions/{session_id}/events` via the browser's native
 * `EventSource` (ruling R4) — not a fetch-based reader. The server puts
 * `id: <session-uuid>:<seq>` on every data frame and reads the resume
 * cursor from the `last-event-id` *request header only*, which is precisely
 * the header a native `EventSource` replays on its own automatic
 * reconnect; a hand-rolled reader would have to reimplement that.
 *
 * The held token, if any, travels as `?access_token=`, built with
 * `URLSearchParams` — `EventSource` cannot set request headers at all,
 * which is exactly why the server also accepts the token this way
 * (`lan_auth.rs`'s `QUERY_PARAM_PREFIX`).
 *
 * There is no durable resume across a page reload (ruling R14): a fresh
 * `EventSource` carries no cursor, so a reload always starts at
 * `resume_from = 0` — a full replay, since seq 0 is a real event and not a
 * sentinel. `lastEventId` is surfaced to `onEvent` for display only.
 */
export function connectSessionEvents(
  sessionId: string,
  handlers: SessionStreamHandlers,
): EventSource {
  const params = new URLSearchParams();
  const token = getToken();
  if (token !== null) {
    params.set("access_token", token);
  }
  const query = params.toString();
  const path = `/api/sessions/${encodeURIComponent(sessionId)}/events${query ? `?${query}` : ""}`;

  const source = new EventSource(path);

  source.onmessage = (message: MessageEvent<string>) => {
    // Fix round 1 (M5): a malformed body used to throw straight out of this
    // handler. The stream is not being closed here — unlike the two
    // listeners below — so there is a next frame to keep listening for;
    // dropping this one and continuing is strictly better than crashing the
    // whole connection over one bad frame.
    let parsed: ClientEvent;
    try {
      parsed = JSON.parse(message.data) as ClientEvent;
    } catch {
      return;
    }
    handlers.onEvent(parsed, message.lastEventId || null);
  };

  source.addEventListener("resync_required", (message) => {
    source.close();
    // Fix round 1 (M5, ruling R13): a malformed body used to throw here,
    // straight past the whole handler — with `source` already `close()`d,
    // that left the UI's stream state stuck wherever it last was
    // (`open`/`connecting`), which looks like a live connection on what is
    // actually a permanently dead one. That is strictly worse than the
    // "reload to resume" terminal state this frame exists to produce, so a
    // parse failure now falls back to that terminal state via
    // `onStreamError` — `onResyncRequired`'s own fields (`resume_from`,
    // `oldest_retained`) have no sensible fallback value to invent, while
    // `onStreamError` only needs a human-readable string.
    //
    // **The `try` covers only the parse, not the handler call.** Wrapping
    // `handlers.onResyncRequired(...)` itself would also swallow a genuine
    // bug inside that handler (e.g. a consumer's `setStream` throwing) and
    // misreport it as "malformed resync_required frame" — a wrong
    // diagnosis for a real error. Parsing and dispatching are kept as two
    // separate steps so only an actual parse failure takes the fallback
    // path.
    let parsed: ResyncRequired;
    try {
      parsed = JSON.parse((message as MessageEvent<string>).data) as ResyncRequired;
    } catch {
      handlers.onStreamError({ error: "received a malformed resync_required frame" });
      return;
    }
    handlers.onResyncRequired(parsed);
  });

  source.addEventListener("stream_error", (message) => {
    source.close();
    // See the `resync_required` listener above for why this falls back to
    // the same terminal state on a parse failure, and why only the parse
    // itself (not the `onStreamError` call) is inside the `try`.
    let parsed: StreamError;
    try {
      parsed = JSON.parse((message as MessageEvent<string>).data) as StreamError;
    } catch {
      handlers.onStreamError({ error: "received a malformed stream_error frame" });
      return;
    }
    handlers.onStreamError(parsed);
  });

  source.onerror = () => {
    handlers.onError(source.readyState === EventSource.CLOSED);
  };

  return source;
}

// ── Shared plumbing ─────────────────────────────────────────────────────

/**
 * `fetch`, with `Authorization: Bearer <token>` attached when a token is
 * held and no `Authorization` header at all when one is not — a loopback
 * bind is ungated and must still work with no token in play.
 */
function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken();
  if (token === null) {
    return fetch(path, init);
  }

  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return fetch(path, { ...init, headers });
}

/**
 * Every `/api` error body `apiFetch` can produce is `{"error": "<sentence>"}`
 * — `fetchRuns` and `postInteraction` are the only callers, and neither
 * calls the SSE route. (The SSE route's own three `400`s are `text/plain`,
 * an open residual in `sse.rs` — but they are never fetched: `EventSource`
 * cannot be read as a `Response` at all, so `connectSessionEvents`'s
 * `onerror` is the actual analog of this function for that route, not this
 * one.) The `catch` below is for whatever else can still show up in front of
 * `apiFetch` — a proxy or gateway error page — falling back to a generic
 * sentence naming the status instead of propagating the parse error.
 */
async function errorReason(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: unknown };
    if (typeof body.error === "string") {
      return body.error;
    }
  } catch {
    // Not JSON — a proxy or gateway error page in front of `apiFetch`, most
    // plausibly. Fall through to the generic sentence below.
  }
  return `request failed with status ${response.status}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}
