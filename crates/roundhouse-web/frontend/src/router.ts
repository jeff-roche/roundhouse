// A hand-rolled client router (ruling R17 — not `@solidjs/router`). The
// route table on the server side, `crates/roundhouse-web/src/assets.rs`'s
// `is_client_route`, is closed and already tested: any path outside it 404s
// on a hard refresh or a pasted deep link. This router's routes are a
// **strict subset** of that table (four of its entries), which is what
// keeps every path this client can navigate to also servable by a fresh
// page load.
//
// Three pieces, as asked for: a `createSignal` over `location.pathname`
// updated on `popstate`, a `navigate(path)` that `pushState`s and updates
// that signal, and a pure `matchRoute` doing the actual parsing — kept
// separate from the signal machinery so it is trivially unit-testable with
// no DOM at all.

import { createSignal } from "solid-js";

/**
 * Canonical hyphenated form only (`8-4-4-4-12` hex digits) — the shape
 * `roundhouse-core`'s ids take on the wire. Deliberately not the more
 * permissive set `Uuid::parse_str` accepts server-side (braced, urn,
 * unhyphenated): this is a client-side gate, not a parser, and a narrower
 * accept-list is the safer default for something that ends up in a URL path
 * segment. It also load-bears a security property, not just a UX one: a
 * segment like `..` fails this pattern and is therefore never matched into
 * a `Route`, so it can never reach `connectSessionEvents` or
 * `postInteraction` as a session id — see this module's `matchRoute` and
 * `api.ts`'s callers, none of which get a chance to build
 * `/api/sessions/../...` from a route-derived value.
 */
export const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export function isUuidShaped(value: string): boolean {
  return UUID_PATTERN.test(value);
}

/**
 * Ruling R18: `/api/runs` takes no workspace parameter and nothing
 * enumerates workspaces, so `:ws` is route shape only. This is the neutral
 * segment used for onward links when the app is opened at `/` with no
 * workspace in the URL — a **constant**, identical in every install
 * (criterion 1 forbids a *per-install* value here, not every string
 * literal; this one is never derived from the machine, the config, or the
 * build environment).
 */
export const DEFAULT_WORKSPACE = "default";

export type Route =
  | { kind: "inbox"; workspace: string }
  | { kind: "session"; workspace: string; sessionId: string }
  | { kind: "not-found" };

/** `decodeURIComponent`, tolerating a malformed percent-escape rather than throwing. */
function decodeSegment(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * Parses a `location.pathname`-shaped string into a {@link Route}. Pure —
 * no DOM, no history — so every shape below is a direct unit test with no
 * navigation involved.
 *
 * Mirrors `assets.rs::split_request_path`'s validity rule on purpose: a
 * path with an empty segment (a trailing slash, a doubled `/`) is invalid
 * there too, and the server would 404 it. Matching that here is what keeps
 * this router's accepted paths a genuine subset of what a hard refresh
 * would actually serve, rather than a client-only illusion that a reload
 * breaks.
 *
 * Only three shapes match, deliberately narrower than
 * `is_client_route`'s own subset used elsewhere in the crate — this is the
 * *client's* route list, not a restatement of every server-tolerated path:
 *
 * - `/` -> the inbox, at the neutral {@link DEFAULT_WORKSPACE} placeholder;
 * - `/w/:ws/inbox` and `/w/:ws/runs` -> the inbox, at `:ws`;
 * - `/w/:ws/s/:session` -> the session view, when `:session` is UUID-shaped
 *   (see {@link UUID_PATTERN}'s doc comment for why that check lives here
 *   rather than only where the id is used).
 *
 * Everything else — including every other entry in `is_client_route`, such
 * as bare `/w/:ws` or `/settings` — is `{ kind: "not-found" }`: a real,
 * renderable "no such view" state in this client, not a 404, since the
 * table is closed and none of those views exist here (ruling R10).
 */
export function matchRoute(pathname: string): Route {
  if (!pathname.startsWith("/")) {
    return { kind: "not-found" };
  }

  const rest = pathname.slice(1);
  if (rest === "") {
    return { kind: "inbox", workspace: DEFAULT_WORKSPACE };
  }

  const segments = rest.split("/");
  if (segments.some((segment) => segment.length === 0)) {
    // A trailing or doubled slash — an empty segment 404s server-side.
    return { kind: "not-found" };
  }

  if (segments.length === 3 && segments[0] === "w" && (segments[2] === "inbox" || segments[2] === "runs")) {
    const workspace = decodeSegment(segments[1]);
    if (workspace === null) return { kind: "not-found" };
    return { kind: "inbox", workspace };
  }

  if (segments.length === 4 && segments[0] === "w" && segments[2] === "s") {
    const workspace = decodeSegment(segments[1]);
    const sessionId = decodeSegment(segments[3]);
    if (workspace === null || sessionId === null || !isUuidShaped(sessionId)) {
      return { kind: "not-found" };
    }
    return { kind: "session", workspace, sessionId };
  }

  return { kind: "not-found" };
}

/** `/w/:ws/inbox`, both segments encoded — for building a link, never for parsing one. */
export function inboxPath(workspace: string): string {
  return `/w/${encodeURIComponent(workspace)}/inbox`;
}

/** `/w/:ws/s/:session`, both segments encoded. */
export function sessionPath(workspace: string, sessionId: string): string {
  return `/w/${encodeURIComponent(workspace)}/s/${encodeURIComponent(sessionId)}`;
}

const [pathname, setPathname] = createSignal(window.location.pathname);

window.addEventListener("popstate", () => setPathname(window.location.pathname));

/** The current `location.pathname`, reactive on Solid's signal graph. */
export function currentPath(): string {
  return pathname();
}

/**
 * Pushes a new history entry and updates {@link currentPath} to match — the
 * one write path a component should use instead of touching
 * `window.history` directly, so the signal never drifts from what the
 * address bar shows.
 */
export function navigate(path: string): void {
  window.history.pushState(null, "", path);
  setPathname(window.location.pathname);
}
