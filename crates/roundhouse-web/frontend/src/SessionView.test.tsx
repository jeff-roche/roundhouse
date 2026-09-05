import { render } from "solid-js/web";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SessionView } from "./SessionView";

const SESSION = "550e8400-e29b-41d4-a716-446655440000";

// A minimal stand-in for the browser's `EventSource`, extending
// `api.test.ts`'s `FakeEventSource` with listener capture so a test can
// fire `resync_required`/`stream_error` by name, the way `connectSessionEvents`
// itself listens for them.
class FakeEventSource {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;

  readyState = FakeEventSource.CONNECTING;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  url: string;
  private listeners = new Map<string, Array<(event: MessageEvent) => void>>();

  constructor(url: string) {
    this.url = url;
    instances.push(this);
  }

  addEventListener(name: string, callback: (event: MessageEvent) => void): void {
    const existing = this.listeners.get(name) ?? [];
    existing.push(callback);
    this.listeners.set(name, existing);
  }

  close(): void {
    this.readyState = FakeEventSource.CLOSED;
  }

  emitMessage(data: unknown, lastEventId = ""): void {
    this.onmessage?.({ data: JSON.stringify(data), lastEventId } as MessageEvent);
  }

  emitNamed(name: string, data: unknown): void {
    for (const callback of this.listeners.get(name) ?? []) {
      callback({ data: JSON.stringify(data) } as MessageEvent);
    }
  }

  fireError(): void {
    this.onerror?.();
  }
}

let instances: FakeEventSource[] = [];

function latestSource(): FakeEventSource {
  const source = instances.at(-1);
  if (source === undefined) throw new Error("no EventSource constructed");
  return source;
}

function mount(sessionId: string, reload?: () => void): HTMLDivElement {
  const container = document.createElement("div");
  document.body.appendChild(container);
  render(() => <SessionView sessionId={sessionId} reload={reload} />, container);
  return container;
}

beforeEach(() => {
  instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  vi.stubGlobal("fetch", vi.fn());
});

describe("SessionView streaming", () => {
  it("appends streaming text as TaskDelta/Text frames arrive", async () => {
    const container = mount(SESSION);
    const source = latestSource();

    source.emitMessage({
      TaskEvent: {
        session_id: SESSION,
        task_id: "t1",
        payload: { TaskDelta: { delta: { Text: { text: "hello " } } } },
      },
    });
    source.emitMessage({
      TaskEvent: {
        session_id: SESSION,
        task_id: "t1",
        payload: { TaskDelta: { delta: { Text: { text: "world" } } } },
      },
    });

    await vi.waitFor(() => expect(container.querySelectorAll(".line-text").length).toBe(2));
    expect(container.textContent).toContain("hello ");
    expect(container.textContent).toContain("world");
  });

  it("decodes Delta::Stdout/Stderr byte arrays as text, not raw numbers", async () => {
    const container = mount(SESSION);
    const source = latestSource();
    const bytes = Array.from(new TextEncoder().encode("built ok\n"));

    source.emitMessage({
      TaskEvent: { session_id: SESSION, task_id: "t1", payload: { TaskDelta: { delta: { Stdout: bytes } } } },
    });

    await vi.waitFor(() => expect(container.querySelector(".line-stdout")).not.toBeNull());
    expect(container.textContent).toContain("built ok");
  });

  it("tolerates an unrecognised top-level variant and renders it, never throwing", async () => {
    const container = mount(SESSION);
    const source = latestSource();

    expect(() => source.emitMessage({ SomeFutureVariant: { anything: 1 } })).not.toThrow();

    await vi.waitFor(() => expect(container.querySelector(".line-unrecognised")).not.toBeNull());
  });

  it("renders resync_required as a terminal state with a manual reload control, no auto-reconnect", async () => {
    const reload = vi.fn();
    const container = mount(SESSION, reload);
    const source = latestSource();

    source.emitNamed("resync_required", { resume_from: 10, oldest_retained: 20 });

    await vi.waitFor(() => expect(container.querySelector(".stream-terminal")).not.toBeNull());
    expect(container.textContent).toContain("Reloading replays the session from the start");

    const button = container.querySelector(".stream-terminal button") as HTMLButtonElement;
    button.click();
    expect(reload).toHaveBeenCalledOnce();
  });

  it("renders stream_error the same way as resync_required — both terminal", async () => {
    const container = mount(SESSION);
    const source = latestSource();

    source.emitNamed("stream_error", { error: "something went wrong upstream" });

    await vi.waitFor(() => expect(container.querySelector(".stream-terminal")).not.toBeNull());
  });

  it("distinguishes a terminal connection refusal (401/403/bad id) from a transient drop", async () => {
    const container = mount(SESSION);
    const source = latestSource();

    source.readyState = FakeEventSource.CLOSED;
    source.fireError();
    await vi.waitFor(() => expect(container.querySelector(".stream-connection-refused")).not.toBeNull());
    expect(container.textContent).not.toContain("reconnecting");

    const container2 = mount(SESSION);
    const source2 = latestSource();
    source2.readyState = FakeEventSource.CONNECTING;
    source2.fireError();
    await vi.waitFor(() => expect(container2.querySelector(".stream-reconnecting")).not.toBeNull());
  });
});

describe("SessionView interactions", () => {
  function mockPostOk(body: unknown, status: number, ok: boolean): void {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok, status, json: async () => body }),
    );
  }

  it("disables Queue/Steer when the compose box is empty, sends when non-empty", async () => {
    const container = mount(SESSION);
    const queueButton = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent === "Queue",
    ) as HTMLButtonElement;
    const steerButton = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent === "Steer",
    ) as HTMLButtonElement;

    expect(queueButton.disabled).toBe(true);
    expect(steerButton.disabled).toBe(true);

    const textarea = container.querySelector("textarea") as HTMLTextAreaElement;
    textarea.value = "do the thing";
    textarea.dispatchEvent(new Event("input", { bubbles: true }));

    await vi.waitFor(() => expect(queueButton.disabled).toBe(false));
    expect(steerButton.disabled).toBe(false);
  });

  it("renders the 501 as an explicit not-yet-delivered state, not success and not a generic error", async () => {
    mockPostOk({ error: "this daemon parses interactions but cannot yet deliver one" }, 501, false);
    const container = mount(SESSION);

    const softInterrupt = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent === "Soft interrupt",
    ) as HTMLButtonElement;
    softInterrupt.click();

    await vi.waitFor(() => expect(container.querySelector(".interaction-not-implemented")).not.toBeNull());
    expect(container.querySelector(".interaction-sent")).toBeNull();
    expect(container.querySelector(".interaction-error")).toBeNull();
  });

  it("renders a 2xx as sent, distinct from not-implemented", async () => {
    mockPostOk({}, 200, true);
    const container = mount(SESSION);

    const hardCancel = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent === "Hard cancel",
    ) as HTMLButtonElement;
    hardCancel.click();

    await vi.waitFor(() => expect(container.querySelector(".interaction-sent")).not.toBeNull());
  });
});
