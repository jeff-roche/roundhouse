// §11.1/§11.4's session detail view over `GET /api/sessions/{id}/events`
// (SSE, streaming) and `POST /api/sessions/{id}/interactions` (the four
// interaction inputs).
//
// **No durable resume across a page reload (ruling R14).** `Last-Event-ID`
// is a request-header-only mechanism a fresh `EventSource` cannot set, so a
// reload always restarts at `resume_from = 0` — a full replay, since seq 0
// is a real event, not a sentinel. This view says that plainly rather than
// implying otherwise.
//
// **`resync_required`/`stream_error` are terminal (ruling R13).** There is
// no snapshot route to refetch from — `connectSessionEvents` already
// `close()`s the `EventSource` before either handler fires — so this never
// tries to silently reconnect into the same tail miss.

import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";

import {
  asAck,
  asStderrDelta,
  asStdoutDelta,
  asTaskDelta,
  asTaskEvent,
  asTextDelta,
  connectSessionEvents,
  postInteraction,
  type ClientEvent,
  type InteractionInput,
  type ResyncRequired,
  type StreamError,
} from "./api";
import { isUuidShaped } from "./router";

type LogLine =
  | { kind: "text"; text: string }
  | { kind: "stdout"; text: string }
  | { kind: "stderr"; text: string }
  | { kind: "ack" }
  /** A `ClientEvent`/`EventPayload`/`Delta` shape this client does not (yet)
   * recognise — `roundhouse_proto::ClientEvent` and friends are grown
   * without notice, so this is tolerated and shown, never thrown on. */
  | { kind: "unrecognised"; raw: string };

type StreamState =
  | { kind: "connecting" }
  | { kind: "open" }
  | { kind: "resync_required"; info: ResyncRequired }
  | { kind: "stream_error"; info: StreamError }
  | { kind: "connection_error"; terminal: boolean };

type InteractionStatus =
  | { kind: "idle" }
  | { kind: "sent" }
  | { kind: "not_implemented"; reason: string }
  | { kind: "error"; status: number; reason: string };

export interface SessionViewProps {
  sessionId: string;
  /**
   * Overridable only so a test can observe "the view asked for a reload"
   * without touching `window.location` — jsdom's `location.reload` is
   * non-configurable and cannot be stubbed directly. Defaults to the real
   * thing.
   */
  reload?: () => void;
}

/** Turns one `ClientEvent` into a renderable {@link LogLine}, never throwing. */
function toLogLine(event: ClientEvent): LogLine {
  if (asAck(event) !== undefined) {
    return { kind: "ack" };
  }

  const taskEvent = asTaskEvent(event);
  if (taskEvent !== undefined) {
    const taskDelta = asTaskDelta(taskEvent.payload);
    if (taskDelta !== undefined) {
      const text = asTextDelta(taskDelta.delta);
      if (text !== undefined) {
        return { kind: "text", text: text.text };
      }
      const stdout = asStdoutDelta(taskDelta.delta);
      if (stdout !== undefined) {
        return { kind: "stdout", text: stdout.text };
      }
      const stderr = asStderrDelta(taskDelta.delta);
      if (stderr !== undefined) {
        return { kind: "stderr", text: stderr.text };
      }
    }
  }

  return { kind: "unrecognised", raw: JSON.stringify(event) };
}

export function SessionView(props: SessionViewProps) {
  const [lines, setLines] = createSignal<LogLine[]>([]);
  const [stream, setStream] = createSignal<StreamState>({ kind: "connecting" });
  const [interaction, setInteraction] = createSignal<InteractionStatus>({ kind: "idle" });
  const [composeText, setComposeText] = createSignal("");

  /**
   * Fix round 1 (M4): hoisted to a memo gating the WHOLE interactive
   * surface below, not just the `connectSessionEvents` call the
   * `createEffect` guards. `router.ts`'s `matchRoute` already only ever
   * produces a `session` route for a UUID-shaped id, so this should be
   * unreachable through normal navigation — it is defence in depth against
   * this component being reused somewhere that skips the router. Before
   * this fix, that insurance covered the connection attempt but not the
   * four interaction buttons, which rendered (and could be clicked) even
   * after the effect below had already bailed to `connection_error`.
   */
  const sessionIdValid = createMemo(() => isUuidShaped(props.sessionId));

  const canSend = () => composeText().trim().length > 0;
  const reload = () => (props.reload ?? (() => window.location.reload()))();

  // Reconnects whenever `props.sessionId` changes, and tears the previous
  // connection down first — `onCleanup` inside a `createEffect` runs both
  // between re-runs and on unmount.
  createEffect(() => {
    const sessionId = props.sessionId;

    if (!isUuidShaped(sessionId)) {
      setStream({ kind: "connection_error", terminal: true });
      return;
    }

    setLines([]);
    setStream({ kind: "connecting" });

    const source = connectSessionEvents(sessionId, {
      onEvent: (event) => {
        setStream({ kind: "open" });
        setLines((prev) => [...prev, toLogLine(event)]);
      },
      onResyncRequired: (info) => setStream({ kind: "resync_required", info }),
      onStreamError: (info) => setStream({ kind: "stream_error", info }),
      onError: (terminal) => setStream({ kind: "connection_error", terminal }),
    });

    onCleanup(() => source.close());
  });

  async function sendInteraction(input: InteractionInput): Promise<void> {
    // Same defence in depth as `sessionIdValid` above: never post to a
    // non-UUID-shaped id, even if something renders these controls anyway.
    if (!isUuidShaped(props.sessionId)) {
      return;
    }
    const result = await postInteraction(props.sessionId, input);
    setInteraction(result.kind === "ok" ? { kind: "sent" } : result);
  }

  return (
    <section class="session-view" aria-label="Session">
      <h2>Session {props.sessionId}</h2>

      <Show
        when={sessionIdValid()}
        fallback={
          <p class="session-invalid-id">
            That is not a valid session id (expected a UUID) — this view cannot connect to a
            session or send it an interaction.
          </p>
        }
      >
        <p class="resume-note">
          Reloading this page replays the whole session from the start — there is no way to
          resume from where a previous page left off (no snapshot route exists yet).
        </p>

        <Show when={stream().kind === "connecting"}>
          <p class="stream-connecting">Connecting…</p>
        </Show>

        <Show when={stream().kind === "resync_required" || stream().kind === "stream_error"}>
          <div class="stream-terminal">
            <p>
              The server dropped events this client never received, and there is no snapshot to
              resync from. Reloading replays the session from the start.
            </p>
            <button type="button" onClick={reload}>
              Reload
            </button>
          </div>
        </Show>

        <Show when={stream().kind === "connection_error"}>
          {(() => {
            const state = stream() as { kind: "connection_error"; terminal: boolean };
            return state.terminal ? (
              <p class="stream-connection-refused">
                The connection to this session could not be opened — a bad session id, or this
                device is not authorised. The browser will not retry on its own; reload to try
                again.
              </p>
            ) : (
              <p class="stream-reconnecting">Connection dropped — the browser is reconnecting…</p>
            );
          })()}
        </Show>

        <div class="transcript" role="log">
          <For each={lines()}>
            {(line) => {
              switch (line.kind) {
                case "text":
                  return <span class="line-text">{line.text}</span>;
                case "stdout":
                  return <div class="line-stdout">{line.text}</div>;
                case "stderr":
                  return <div class="line-stderr">{line.text}</div>;
                case "ack":
                  return <div class="line-ack">connected</div>;
                default:
                  return <div class="line-unrecognised">unrecognised event: {line.raw}</div>;
              }
            }}
          </For>
        </div>

        <div class="interactions">
          <button type="button" onClick={() => void sendInteraction({ kind: "soft_interrupt" })}>
            Soft interrupt
          </button>
          <button type="button" onClick={() => void sendInteraction({ kind: "hard_cancel" })}>
            Hard cancel
          </button>

          <textarea
            value={composeText()}
            onInput={(event) => setComposeText(event.currentTarget.value)}
            placeholder="Message to queue (delivered next turn) or steer with (injected now)"
          />
          <button
            type="button"
            disabled={!canSend()}
            onClick={() => void sendInteraction({ kind: "queue", text: composeText() })}
          >
            Queue
          </button>
          <button
            type="button"
            disabled={!canSend()}
            onClick={() => void sendInteraction({ kind: "steer", text: composeText() })}
          >
            Steer
          </button>

          <Show when={interaction().kind === "not_implemented"}>
            <p class="interaction-not-implemented">
              This daemon parses interactions but cannot yet deliver one:{" "}
              {(interaction() as { reason: string }).reason}
            </p>
          </Show>
          <Show when={interaction().kind === "error"}>
            <p class="interaction-error">
              Sending that interaction failed: {(interaction() as { reason: string }).reason}
            </p>
          </Show>
          <Show when={interaction().kind === "sent"}>
            <p class="interaction-sent">Sent.</p>
          </Show>
        </div>
      </Show>
    </section>
  );
}
