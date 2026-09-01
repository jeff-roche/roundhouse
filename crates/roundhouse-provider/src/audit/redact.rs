//! §9.9: "a final redaction pass regexes every persisted error body for
//! API-key-shaped strings, bearer tokens, and JWTs, because providers echo
//! request bodies in 400s more often than you'd like."
//!
//! **This is deliberately a second, complementary mechanism, not a
//! duplicate of Phase 2's redactor** (`roundhouse_store::redact::Redactor`).
//! Phase 2's is a known-literal Aho-Corasick matcher: it scrubs secret
//! *values Phase 2 already resolved and holds a reference to* out of
//! arbitrary log lines, at the persistence boundary, before an
//! `EventPayload` is ever serialized. This one has no literal to look for —
//! it runs on provider error-body text specifically, which can echo back a
//! key that was never resolved through Phase 2's path at all (e.g. a stale
//! or mistyped key rejected before credential resolution completes), so it
//! matches by *shape* instead of by known value. `roundhouse-provider`
//! cannot depend on `roundhouse-store` (that dependency runs the other
//! direction), so this genuinely has to be a separate layer, not a shared
//! helper.

use regex::Regex;
use std::sync::LazyLock;

static API_KEY_SHAPED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(sk|pk|rk)-[A-Za-z0-9_-]{16,}\b").unwrap());
static BEARER_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Bearer\s+[A-Za-z0-9._-]{8,}").unwrap());
static JWT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap());

pub fn redact_error_body(body: &str) -> String {
    let redacted = JWT.replace_all(body, "[REDACTED-JWT]");
    let redacted = BEARER_TOKEN.replace_all(&redacted, "Bearer [REDACTED]");
    let redacted = API_KEY_SHAPED.replace_all(&redacted, "[REDACTED-KEY]");
    redacted.into_owned()
}
