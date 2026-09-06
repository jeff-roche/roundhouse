import { beforeEach, describe, expect, it } from "vitest";

import {
  currentPath,
  DEFAULT_WORKSPACE,
  inboxPath,
  isUuidShaped,
  matchRoute,
  navigate,
  sessionPath,
} from "./router";

const SESSION = "550e8400-e29b-41d4-a716-446655440000";

function navigateRaw(path: string): void {
  window.history.replaceState(null, "", path);
}

beforeEach(() => {
  navigateRaw("/");
});

describe("matchRoute", () => {
  it("matches the site root as the inbox at the neutral placeholder workspace", () => {
    expect(matchRoute("/")).toEqual({ kind: "inbox", workspace: DEFAULT_WORKSPACE });
  });

  it("matches /w/:ws/inbox and /w/:ws/runs as the inbox, capturing :ws", () => {
    expect(matchRoute("/w/acme/inbox")).toEqual({ kind: "inbox", workspace: "acme" });
    expect(matchRoute("/w/acme/runs")).toEqual({ kind: "inbox", workspace: "acme" });
  });

  it("matches /w/:ws/s/:session as the session view when :session is UUID-shaped", () => {
    expect(matchRoute(`/w/acme/s/${SESSION}`)).toEqual({
      kind: "session",
      workspace: "acme",
      sessionId: SESSION,
    });
  });

  it("percent-decodes the :ws capture", () => {
    expect(matchRoute("/w/my%20team/inbox")).toEqual({ kind: "inbox", workspace: "my team" });
  });

  it("rejects a :session segment that is not UUID-shaped, even if it looks close", () => {
    expect(matchRoute("/w/acme/s/not-a-uuid")).toEqual({ kind: "not-found" });
    expect(matchRoute("/w/acme/s/550e8400e29b41d4a716446655440000")).toEqual({ kind: "not-found" });
  });

  it("rejects the path-traversal shape a bare '..' segment would produce", () => {
    // Exactly the residual `encodeURIComponent` cannot close on its own:
    // `..` is not touched by percent-encoding, so this must be rejected by
    // shape (failing the UUID check) rather than relying on encoding.
    expect(matchRoute("/w/acme/s/..")).toEqual({ kind: "not-found" });
  });

  it("rejects every path outside this client's four routes, even ones the server tolerates", () => {
    // In `is_client_route` (the server would serve the shell, not 404) but
    // not one of this client's own four routes — a real "no such view"
    // state here, not a broken link.
    expect(matchRoute("/w/acme")).toEqual({ kind: "not-found" });
    expect(matchRoute("/settings")).toEqual({ kind: "not-found" });
    expect(matchRoute("/settings/general")).toEqual({ kind: "not-found" });

    // Outside `is_client_route` entirely — the server would 404 these on a
    // hard refresh, so a router that matched them would work only until
    // the page reloaded.
    expect(matchRoute("/w/a/b/c")).toEqual({ kind: "not-found" });
    expect(matchRoute("/settings/a/b")).toEqual({ kind: "not-found" });
    expect(matchRoute(`/w/a/s/${SESSION}/t/task1`)).toEqual({ kind: "not-found" });
  });

  it("rejects a trailing slash, which yields an empty segment the server also rejects", () => {
    expect(matchRoute("/w/a/inbox/")).toEqual({ kind: "not-found" });
  });

  it("rejects a doubled slash for the same reason", () => {
    expect(matchRoute("/w//inbox")).toEqual({ kind: "not-found" });
  });

  it("rejects a path with no leading slash", () => {
    expect(matchRoute("w/acme/inbox")).toEqual({ kind: "not-found" });
  });
});

describe("isUuidShaped", () => {
  it("accepts the canonical hyphenated form only", () => {
    expect(isUuidShaped(SESSION)).toBe(true);
    expect(isUuidShaped(SESSION.toUpperCase())).toBe(true);
    expect(isUuidShaped(SESSION.replaceAll("-", ""))).toBe(false);
    expect(isUuidShaped("..")).toBe(false);
    expect(isUuidShaped("")).toBe(false);
  });
});

describe("inboxPath / sessionPath", () => {
  it("URL-encodes every interpolated segment", () => {
    expect(inboxPath("my team")).toBe("/w/my%20team/inbox");
    expect(sessionPath("my team", SESSION)).toBe(`/w/my%20team/s/${SESSION}`);
  });
});

describe("currentPath / navigate", () => {
  it("reflects the pathname navigate() pushes, and history actually changed", () => {
    navigate("/w/acme/inbox");

    expect(currentPath()).toBe("/w/acme/inbox");
    expect(window.location.pathname).toBe("/w/acme/inbox");
  });

  it("updates on a popstate event (browser back/forward), not just navigate()", () => {
    navigate("/w/acme/inbox");
    navigate(`/w/acme/s/${SESSION}`);

    // Simulate the browser restoring the previous entry on `back()`: jsdom's
    // `history.back()` does not synchronously update `location`, so this
    // drives it the same way a real back-navigation would — a location
    // change followed by a `popstate` event.
    navigateRaw("/w/acme/inbox");
    window.dispatchEvent(new PopStateEvent("popstate"));

    expect(currentPath()).toBe("/w/acme/inbox");
  });
});
