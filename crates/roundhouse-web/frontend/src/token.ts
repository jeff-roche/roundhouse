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

  const remaining = removeQueryParam(window.location.search, QUERY_PARAM);
  window.history.replaceState(null, "", url.pathname + remaining + url.hash);

  return presented;
}

/** The token currently held, if `bootToken` has ever stored one. */
export function getToken(): string | null {
  return window.sessionStorage.getItem(TOKEN_STORAGE_KEY);
}

/**
 * Removes `key` from a raw query string by splitting on `&` and rejoining —
 * deliberately not `url.searchParams.delete(key)` followed by
 * `url.searchParams.toString()`. That round-trip re-serialises every
 * *remaining* pair under `application/x-www-form-urlencoded` rules (a space
 * becomes `+`, not `%20`; a valueless `?debug` becomes `?debug=`), which is
 * semantically equivalent for anything reading the query through
 * `URLSearchParams` but not byte-identical for anything reading
 * `location.search` raw. Splitting the original string on `&` and dropping
 * only the matched segments leaves every other pair exactly as the browser
 * presented it.
 *
 * Known rough edge, accepted rather than fixed: this compares each segment
 * against `key` literally, so a percent-encoded key (`%61ccess_token=...`)
 * is not recognised as `access_token` and survives in the URL. `bootToken`
 * itself only ever writes this parameter unencoded, so the edge is reachable
 * only by a caller deliberately obfuscating it — not a normal pairing link.
 */
function removeQueryParam(rawSearch: string, key: string): string {
  const withoutLeadingQuestion = rawSearch.startsWith("?") ? rawSearch.slice(1) : rawSearch;
  if (withoutLeadingQuestion === "") {
    return "";
  }

  const kept = withoutLeadingQuestion
    .split("&")
    .filter((pair) => pair !== key && !pair.startsWith(`${key}=`));

  return kept.length > 0 ? `?${kept.join("&")}` : "";
}
