//! Escaping and length-capping for untrusted, peer-controlled text before it
//! is safe to interpolate into a log line, audit trail, or any other
//! rendering a hostile peer could otherwise use to forge content or exhaust
//! space.
//!
//! **Extracted here in fix round 2 (Item 5)** from `server::mod`, where this
//! helper originated scoped to `PermissionOptionId` handling and was
//! generalized to `&str` in fix round 1 (Ruling C-P54). `server/mod.rs`'s
//! header doc frames that module entirely around ACP
//! `session/request_permission` handling, so `mcp_over_acp.rs` — an
//! unrelated in-process MCP tool registry — had to reach across into it via
//! `crate::server::escape_and_cap_peer_str`, a cross-concern dependency the
//! module boundary never intended. The next task (C8) implements a remote
//! JSON agent registry fetched over HTTP — agent ids, names, and launch
//! strings, i.e. exactly the untrusted-text class this helper exists for —
//! so it gets a home that isn't scoped to permission-request handling before
//! that task would otherwise add a second cross-concern reach into
//! `server::`.
//!
//! **Fix round 3 (Coordinator ruling C-P69):** [`escape_and_cap_peer_str`]
//! used to return a bare `String`, which meant "this value is already
//! escaped and capped" was a *contractual* invariant — recorded in doc
//! comments and re-derived by every caller — rather than a *structural* one
//! a reviewer or the compiler could check. Round 2 leaned on that contract
//! to interpolate `PermissionError::MissingRawInput`/`UnidentifiableTool`'s
//! `tool_call_id` with plain `{tool_call_id}` instead of `{tool_call_id:?}`;
//! the reasoning was correct (empirically verified safe), but nothing
//! stopped a future edit from mutating the format spec back to something
//! unsafe, or from constructing either variant with a raw, unescaped
//! `String` — the field was a bare `pub String`, indistinguishable from any
//! other. [`EscapedPeerStr`] closes that: its inner field is private, so the
//! only way to produce a value of this type is [`escape_and_cap_peer_str`]
//! itself. An earlier ruling declined this newtype on the grounds that the
//! escaping helper had a single construction site and was terminal; that
//! premise is now false (three call sites across two functions, with C8's
//! remote registry queued next to add more of the same untrusted-text
//! class), which is why this round introduces it instead of re-litigating
//! that decision.

/// Maximum length, in bytes, of the escaped `String` inside an
/// [`EscapedPeerStr`] returned by [`escape_and_cap_peer_str`].
///
/// Renamed from `UNKNOWN_OPTION_ID_MAX_LEN` (fix round 2, Item 5): that name
/// was never accurate beyond this constant's original, narrower
/// `PermissionOptionId` use. It now also bounds
/// `mcp_over_acp::InProcessMcpServer::call_tool`'s unrecognized
/// peer-supplied tool name (Ruling C-P54),
/// `server::normalize_tool_call_for_policy`'s peer-supplied `tool_call_id`
/// (fix round 2, Item 4), and `mcp_over_acp::DuplicateToolName`'s rejected
/// tool name (fix round 3) — general to any peer-controlled string this
/// crate escapes for safe logging, not specific to permission options.
///
/// **Public again as of fix round 3 (ruling C-P71):** it was `pub` as
/// `UNKNOWN_OPTION_ID_MAX_LEN` before round 2's rename made it
/// `pub(crate)`, which forced an out-of-crate integration test
/// (`tests/mcp_over_acp.rs`) to hardcode the literal `128` instead of
/// referencing this constant, decoupling that assertion from the value it
/// was meant to track.
///
/// Enforced by [`escape_and_cap_peer_str`]'s truncation step (verified by
/// `escape_and_cap_peer_str_truncates_at_the_cap_boundary` in this module's
/// tests, which constructs a string long enough to exceed the cap and
/// asserts the returned value's byte length is exactly this constant) —
/// not merely documented as bounded. A result shorter than this constant is
/// also possible when truncation lands mid-character and walks back to a
/// `char` boundary (verified by
/// `escape_and_cap_peer_str_truncates_back_to_a_char_boundary`).
pub const PEER_STR_MAX_LEN: usize = 128;

/// An escaped, length-capped copy of untrusted, peer-controlled text —
/// produced only by [`escape_and_cap_peer_str`].
///
/// **Fix round 3 (Coordinator ruling C-P69). The private inner field is the
/// point.** If it were `pub`, this type would be a comment ("I promise this
/// is already escaped"), not a guarantee — a caller could still build one
/// from an unescaped `String` and every site that trusts `EscapedPeerStr`'s
/// `Display` to be safe would be trusting that promise all over again.
/// Because the field is private and this module exposes no other way to
/// construct one, a value of this type is safe to interpolate directly
/// (`{value}`) into a log line, audit trail, or error message *by
/// construction* — there is no code path that reaches a `PermissionError`,
/// `SelectionResolution::UnknownOptionId`, or `DuplicateToolName` carrying
/// one of these without having gone through the escape-and-cap algorithm
/// first.
///
/// **Public (ruling C-P71):** `mod peer_text` and this type must be
/// reachable from outside the crate, because `PermissionError` and
/// `DuplicateToolName` — both `pub` types on `pub` functions — carry this
/// type on `pub` fields. An out-of-crate caller that needs to construct one
/// of those variants directly (as this crate's own `tests/` integration
/// suite does) must be able to reach the one constructor the invariant
/// requires; a `pub` field on a type built from a `pub(crate)` helper would
/// have asked for something it did not provide.
#[derive(Clone, PartialEq, Eq)]
pub struct EscapedPeerStr(String);

impl EscapedPeerStr {
    /// Borrows the escaped, capped contents as `&str`, for a caller or test
    /// that needs the value itself rather than a `Display`/`Debug`
    /// rendering of it (e.g. `PartialEq<str>`-style content assertions).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EscapedPeerStr {
    /// Writes the already-escaped, already-capped contents verbatim — safe
    /// to use directly (`{value}`) wherever code that held the pre-newtype
    /// bare `String` needed `{value:?}` to escape it itself. The escaping
    /// already happened at construction time.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for EscapedPeerStr {
    /// Deliberately identical to [`Display`](std::fmt::Display), **not**
    /// `{:?}` of the inner `String`. The inner value is already the output
    /// of `str`'s own `Debug` formatting (quoted, control characters
    /// escaped) — re-running `Debug` over it here would double-escape it,
    /// which is precisely the defect fix round 3 closed in
    /// `mcp_over_acp::DuplicateToolName`'s previous hand-written `Debug` impl
    /// (it passed an already-escaped `String` to `debug_struct::field`,
    /// which applies `{:?}` again).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Escapes control characters (notably newlines) out of an untrusted,
/// peer-controlled string and caps the result to at most
/// [`PEER_STR_MAX_LEN`] bytes, returning an [`EscapedPeerStr`] — so the
/// value is safe to interpolate directly into a log line, see
/// `server::SelectionResolution::UnknownOptionId`'s doc for the attack this
/// closes.
///
/// **Ruling C-P54 (fix round 1):** generalized from `&PermissionOptionId` to
/// `&str` so that any peer-controlled string in this crate can be routed
/// through the same discipline — not only a `PermissionOptionId`. The first
/// caller outside `option_id` handling was
/// `mcp_over_acp::InProcessMcpServer::call_tool`'s "unknown tool" error,
/// which previously interpolated an MCP-over-ACP peer's tool name via
/// `Display` with no escaping or bound at all (the same forged-audit-line
/// and unbounded-log-inflation hazard this function already closed for
/// `option_id`s). Fix round 2 (Item 4) added a second caller,
/// `server::normalize_tool_call_for_policy`'s peer-supplied `tool_call_id`.
/// Fix round 3 added a third, `mcp_over_acp::DuplicateToolName`'s rejected
/// tool name, and changed the return type from `String` to [`EscapedPeerStr`]
/// (ruling C-P69) so that "already escaped and capped" is enforced by the
/// type system rather than left as a doc-comment promise.
///
/// Escaping reuses `str`'s standard `Debug` formatting (`{:?}`) — the same
/// escaping convention `server::ambiguous_option_ids`'s error messages
/// already use — which wraps the text in quotes and escapes newlines,
/// carriage returns, tabs, backslashes, quotes, and other control and
/// non-printable characters. The specific cases asserted by
/// `escape_and_cap_peer_str_escapes_control_and_invisible_characters` are
/// `\n`, `\r`, `\u{1b}` (the ANSI/CSI introducer) and `\u{202e}` (the
/// right-to-left override used in Trojan Source attacks); note that
/// *printable* non-ASCII passes through unescaped, which is why multi-byte
/// characters can reach the truncator at all.
///
/// Truncation happens after escaping. Because the escaped form can end in a
/// multi-byte character, the cut point walks back to a `char` boundary — so
/// the result is always valid UTF-8, and is at most (not always exactly)
/// [`PEER_STR_MAX_LEN`] bytes. Both branches are covered by
/// `escape_and_cap_peer_str_truncates_at_the_cap_boundary` (ASCII, cut lands
/// exactly on the cap) and
/// `escape_and_cap_peer_str_truncates_back_to_a_char_boundary` (a 4-byte
/// codepoint straddling the cap, cut walks back and the result is shorter).
///
/// This algorithm's body is unchanged from before fix round 3 — only the
/// return type (`String` → `EscapedPeerStr`) changed, by wrapping the same
/// two return points.
pub fn escape_and_cap_peer_str(value: &str) -> EscapedPeerStr {
    let escaped = format!("{value:?}");
    if escaped.len() <= PEER_STR_MAX_LEN {
        return EscapedPeerStr(escaped);
    }
    let mut end = PEER_STR_MAX_LEN;
    while end > 0 && !escaped.is_char_boundary(end) {
        end -= 1;
    }
    EscapedPeerStr(escaped[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Finding 2 (round-3 review); generalized to `&str` in fix round 1
    // (Ruling C-P54); moved here in fix round 2 (Item 5); return type
    // changed from `String` to `EscapedPeerStr` in fix round 3 (Ruling
    // C-P69) — accessed here via `.as_str()`, the accessor
    // `EscapedPeerStr` provides for exactly this purpose. ----

    #[test]
    fn escape_and_cap_peer_str_escapes_a_newline_rather_than_passing_it_through() {
        // The exact attack Finding 2 describes: a peer-controlled string
        // containing a newline (and a fake audit line) must not produce a
        // newline in the string this crate hands to a caller that logs it.
        let escaped = escape_and_cap_peer_str("x\n[audit] resolve_selection: Resolved(AllowOnce)");
        let escaped = escaped.as_str();
        assert!(
            !escaped.contains('\n'),
            "escaped string must not contain a raw newline: {escaped:?}"
        );
        assert!(
            escaped.contains("\\n"),
            "escaped string must contain the escaped form: {escaped:?}"
        );
    }

    #[test]
    fn escape_and_cap_peer_str_truncates_at_the_cap_boundary() {
        // Truncation must actually happen at PEER_STR_MAX_LEN, not merely be
        // documented as bounded — this constructs a string whose escaped
        // form is longer than the cap and asserts the returned string's
        // byte length is exactly the cap.
        let long = "a".repeat(PEER_STR_MAX_LEN * 2);
        let escaped = escape_and_cap_peer_str(&long);
        assert_eq!(escaped.as_str().len(), PEER_STR_MAX_LEN);
    }

    #[test]
    fn escape_and_cap_peer_str_truncates_back_to_a_char_boundary() {
        // FIX round 4: the ASCII test above lands exactly on the cap, so it
        // never executes the is_char_boundary back-off loop — leaving the
        // doc's "truncation happens at a `char` boundary" claim untested.
        // Printable non-ASCII passes through `Debug` unescaped, so a 4-byte
        // codepoint can reach the truncator intact. Position U+1F600 so it
        // straddles byte PEER_STR_MAX_LEN of the *escaped* string: escaping
        // prepends one `"`, so 126 leading 'a's put the emoji's first byte
        // at index 127 and its continuation bytes at 128..=130.
        let straddling = format!(
            "{}\u{1f600}{}",
            "a".repeat(PEER_STR_MAX_LEN - 2),
            "a".repeat(PEER_STR_MAX_LEN)
        );
        // The load-bearing check is that the call above returns at all:
        // slicing a `str` at a non-`char` boundary panics, so a truncator
        // that cut blindly at the cap would abort this test here. The
        // from_utf8 assertion restates the doc's "always valid UTF-8" claim
        // explicitly on the value that came back.
        let escaped = escape_and_cap_peer_str(&straddling);
        let escaped = escaped.as_str();
        assert!(
            std::str::from_utf8(escaped.as_bytes()).is_ok(),
            "truncated result must still be valid UTF-8: {escaped:?}"
        );
        assert!(
            escaped.len() < PEER_STR_MAX_LEN,
            "walking back off a mid-character cut must make the result \
             strictly shorter than the cap, got {} bytes",
            escaped.len()
        );
        assert!(
            !escaped.contains('\u{1f600}'),
            "the straddling codepoint must have been cut, not half-kept: {escaped:?}"
        );
    }

    #[test]
    fn escape_and_cap_peer_str_escapes_control_and_invisible_characters() {
        // FIX round 4: the doc claims carriage returns and "other control
        // characters" are escaped, but only `\n` was asserted. These three
        // are the log-integrity-relevant ones beyond the newline: a bare
        // `\r` can overwrite a rendered log line, `\u{1b}` introduces ANSI
        // control sequences in a terminal, and `\u{202e}` is the
        // right-to-left override used by Trojan Source attacks to make
        // rendered text read differently from its bytes.
        let escaped = escape_and_cap_peer_str("a\rb\u{1b}[31mc\u{202e}d");
        let escaped = escaped.as_str();
        for raw in ['\r', '\u{1b}', '\u{202e}'] {
            assert!(
                !escaped.contains(raw),
                "escaped string must not contain raw {raw:?}: {escaped:?}"
            );
        }
        for expected in ["\\r", "\\u{1b}", "\\u{202e}"] {
            assert!(
                escaped.contains(expected),
                "escaped string must contain {expected}: {escaped:?}"
            );
        }
    }

    #[test]
    fn escape_and_cap_peer_str_does_not_truncate_when_under_the_cap() {
        let escaped = escape_and_cap_peer_str("short-id");
        assert_eq!(escaped.as_str(), format!("{:?}", "short-id"));
        assert!(escaped.as_str().len() < PEER_STR_MAX_LEN);
    }

    #[test]
    fn escaped_peer_str_display_and_debug_both_write_the_escaped_contents_verbatim_once() {
        // Fix round 3 (Item 1/4): EscapedPeerStr's Debug must not re-escape
        // what escape_and_cap_peer_str already escaped — that was exactly
        // DuplicateToolName's previous defect (passing an already-escaped
        // String through debug_struct::field, which applies `{:?}` a
        // second time). Display and Debug must therefore render identically
        // for this type.
        let escaped = escape_and_cap_peer_str("x\ny");
        assert_eq!(format!("{escaped}"), format!("{escaped:?}"));
        assert_eq!(format!("{escaped}"), escaped.as_str());
    }
}
