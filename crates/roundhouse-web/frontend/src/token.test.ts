import { beforeEach, describe, expect, it, vi } from "vitest";

import { connectSessionEvents, fetchRuns } from "./api";
import { bootToken, getToken, TOKEN_STORAGE_KEY } from "./token";

// A syntactically valid token: 64 lowercase hex characters, matching
// `lan_auth.rs`'s `TOKEN_BYTES = 32` hex-encoded. Not a real one.
const TOKEN = "a".repeat(64);

function navigateTo(url: string): void {
  window.history.replaceState(null, "", url);
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.localStorage.clear();
  navigateTo("http://localhost/w/default/inbox?keep=1#frag");
});

describe("bootToken", () => {
  // Clause 1 + 2: read `access_token` from `location.search`, store it in
  // `sessionStorage`.
  it("stores a presented access_token in sessionStorage", () => {
    navigateTo(`http://localhost/?access_token=${TOKEN}`);

    bootToken();

    expect(window.sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBe(TOKEN);
  });

  // Clause 2, the negative half: never the browser's persistent store — it
  // should not outlive the tab.
  it("never writes the token to the browser's persistent store", () => {
    navigateTo(`http://localhost/?access_token=${TOKEN}`);

    bootToken();

    expect(window.localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.length).toBe(0);
  });

  // Clause 3: the parameter is stripped immediately, and nothing else about
  // the URL moves.
  it("strips access_token from the URL while preserving other params and the hash", () => {
    navigateTo(`http://localhost/w/default/inbox?access_token=${TOKEN}&keep=1#frag`);

    bootToken();

    expect(window.location.search).not.toContain("access_token");
    expect(window.location.search).toBe("?keep=1");
    expect(window.location.pathname).toBe("/w/default/inbox");
    expect(window.location.hash).toBe("#frag");
  });

  // Clause 4: no `access_token` in the URL falls back to whatever is
  // already held, so a client-side navigation does not lose it.
  it("falls back to a previously held token when the URL carries none", () => {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, TOKEN);
    navigateTo("http://localhost/w/default/inbox");

    const token = bootToken();

    expect(token).toBe(TOKEN);
    expect(getToken()).toBe(TOKEN);
  });
});

describe("the token reaching fetch and EventSource", () => {
  // Clause 5: every fetch sends `Authorization: Bearer <token>` when one is
  // held.
  it("sends the held token as a Bearer header on fetch", async () => {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, TOKEN);
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => [],
    });
    vi.stubGlobal("fetch", fetchMock);

    await fetchRuns();

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
  });

  // Clause 5, the negative half: no token held, no Authorization header at
  // all — a loopback bind is ungated and must still work.
  it("sends no Authorization header at all when no token is held", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => [],
    });
    vi.stubGlobal("fetch", fetchMock);

    await fetchRuns();

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit | undefined];
    // `new Headers(undefined)` is empty, so this covers both "no `init`",
    // "`init` with no `headers`" and "`init.headers` present but empty".
    // `.has()`, not the `in` operator: `Headers` exposes no own property
    // named after a header, so `"Authorization" in headers` is always
    // `false` regardless of what was actually set and would not fail if
    // `apiFetch` sent the header unconditionally.
    expect(new Headers(init?.headers).has("Authorization")).toBe(false);
  });

  // Clause 6: the EventSource URL carries `?access_token=` when a token is
  // held, since EventSource cannot set request headers at all.
  it("carries access_token on the EventSource URL when a token is held", () => {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, TOKEN);
    const urls: string[] = [];
    class FakeEventSource {
      constructor(url: string) {
        urls.push(url);
      }
      close() {}
      addEventListener() {}
    }
    vi.stubGlobal("EventSource", FakeEventSource);

    connectSessionEvents("11111111-1111-4111-8111-111111111111", {
      onEvent: () => {},
      onResyncRequired: () => {},
      onStreamError: () => {},
      onError: () => {},
    });

    expect(urls).toHaveLength(1);
    const url = new URL(urls[0], "http://localhost");
    expect(url.searchParams.get("access_token")).toBe(TOKEN);
  });

  // Clause 6, the negative half: no token held, no query parameter at all.
  it("carries no access_token parameter when no token is held", () => {
    const urls: string[] = [];
    class FakeEventSource {
      constructor(url: string) {
        urls.push(url);
      }
      close() {}
      addEventListener() {}
    }
    vi.stubGlobal("EventSource", FakeEventSource);

    connectSessionEvents("11111111-1111-4111-8111-111111111111", {
      onEvent: () => {},
      onResyncRequired: () => {},
      onStreamError: () => {},
      onError: () => {},
    });

    expect(urls).toHaveLength(1);
    expect(urls[0]).not.toContain("access_token");
  });
});
