import { render } from "solid-js/web";
import { beforeEach, describe, expect, it, vi } from "vitest";

const SESSION = "550e8400-e29b-41d4-a716-446655440000";

function navigateRaw(path: string): void {
  window.history.replaceState(null, "", path);
}

/**
 * `router.ts` keeps its `currentPath` signal as a module-level singleton,
 * initialised once from `window.location.pathname` at import time — correct
 * for a real page load (the module loads exactly once, at whatever URL the
 * browser already shows), but it means two "cold load at a different URL"
 * scenarios in one test file need two fresh module instances, not one
 * import reused across tests. `vi.resetModules()` plus a dynamic import is
 * what actually reproduces a fresh page load, rather than relying on a
 * synthetic `popstate` as a stand-in for it.
 */
async function mountAppAt(path: string): Promise<HTMLDivElement> {
  navigateRaw(path);
  vi.resetModules();
  const { App } = await import("./App");

  const container = document.createElement("div");
  document.body.appendChild(container);
  render(() => <App />, container);
  return container;
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => [] }));
  class NoopEventSource {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 2;
    readyState = NoopEventSource.CONNECTING;
    onmessage: unknown = null;
    onerror: unknown = null;
    addEventListener(): void {}
    close(): void {}
  }
  vi.stubGlobal("EventSource", NoopEventSource);
});

describe("App routing", () => {
  it("renders the inbox at the site root", async () => {
    const container = await mountAppAt("/");
    await vi.waitFor(() => expect(container.querySelector(".runs-inbox")).not.toBeNull());
  });

  it("renders the session view when the URL is /w/:ws/s/:session on load", async () => {
    const container = await mountAppAt(`/w/acme/s/${SESSION}`);
    await vi.waitFor(() => expect(container.querySelector(".session-view")).not.toBeNull());
    expect(container.textContent).toContain(SESSION);
  });

  it("renders the not-found state for a path outside this client's route table", async () => {
    const container = await mountAppAt("/w/acme/tree");
    await vi.waitFor(() => expect(container.querySelector(".not-found")).not.toBeNull());
  });

  it("navigates to the session view via the 'open session by id' form, without a full page load", async () => {
    const container = await mountAppAt("/");
    await vi.waitFor(() => expect(container.querySelector(".runs-inbox")).not.toBeNull());

    const input = container.querySelector(".open-session-form input") as HTMLInputElement;
    input.value = SESSION;
    input.dispatchEvent(new Event("input", { bubbles: true }));

    const form = container.querySelector(".open-session-form") as HTMLFormElement;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(container.querySelector(".session-view")).not.toBeNull());
    expect(window.location.pathname).toBe(`/w/default/s/${SESSION}`);
  });

  it("rejects a non-UUID value in the open-session-by-id form without navigating", async () => {
    const container = await mountAppAt("/");
    await vi.waitFor(() => expect(container.querySelector(".runs-inbox")).not.toBeNull());

    const input = container.querySelector(".open-session-form input") as HTMLInputElement;
    input.value = "not-a-uuid";
    input.dispatchEvent(new Event("input", { bubbles: true }));

    const form = container.querySelector(".open-session-form") as HTMLFormElement;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(container.querySelector(".open-session-error")).not.toBeNull());
    expect(container.querySelector(".session-view")).toBeNull();
    expect(window.location.pathname).toBe("/");
  });
});
