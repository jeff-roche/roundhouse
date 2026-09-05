// The LAN token boot path — binding acceptance criterion 2 of
// `crates/roundhouse-web/assets/dist/index.html` and `src/lan_auth.rs`'s "The
// client contract" section.
//
// Pairing a device means opening `http://host:port/?access_token=<64 hex>` —
// a top-level navigation has no other way to carry a credential. On boot the
// client must:
//
//   1. read `access_token` from `location.search`;
//   2. if present, hold it for the lifetime of the tab only (never storage
//      that survives the tab closing — it should not outlive it);
//   3. immediately strip the parameter out of the URL with
//      `history.replaceState`. This is the whole mitigation against browser
//      history, browser account sync, and URL-bar autocomplete retention,
//      none of which any server-side code can reach;
//   4. if no `access_token` is in the URL, fall back to whatever is already
//      held, so a client-side navigation does not lose it.
//
// `src/api.ts` is the other half of the contract: every `fetch` sends the
// held token as `Authorization: Bearer`, and every `EventSource` URL carries
// it as `?access_token=`, because `EventSource` cannot set request headers.

const QUERY_PARAM = "access_token";

/**
 * The key the held token is kept under. Exported only so tests can assert
 * against it directly rather than hardcoding the string a second time.
 */
export const TOKEN_STORAGE_KEY = "roundhouse.access_token";

/**
 * Runs synchronously, before Solid's `render()`, in `src/index.tsx`.
 *
 * Returns the token now held, or `null` if none was ever presented.
 */
export function bootToken(): string | null {
  const url = new URL(window.location.href);
  const presented = url.searchParams.get(QUERY_PARAM);

  if (presented === null) {
    return getToken();
  }

  // Cleared when the tab closes — `sessionStorage` is per-tab and does not
  // survive it, unlike the browser's persistent key-value store, which this
  // deliberately does not use.
  window.sessionStorage.setItem(TOKEN_STORAGE_KEY, presented);

  url.searchParams.delete(QUERY_PARAM);
  window.history.replaceState(null, "", url.pathname + remainingSuffix(url) + url.hash);

  return presented;
}

/** The token currently held, if `bootToken` has ever stored one. */
export function getToken(): string | null {
  return window.sessionStorage.getItem(TOKEN_STORAGE_KEY);
}

/** `?a=b&c=d`, or `""` if nothing is left to carry. */
function remainingSuffix(url: URL): string {
  const remaining = url.searchParams.toString();
  return remaining ? `?${remaining}` : "";
}
