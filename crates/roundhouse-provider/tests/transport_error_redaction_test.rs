//! Audit L3: `src/audit/redact.rs`'s doc comment used to hand-maintain a
//! prose enumeration of every `ProviderError::Transport` construction site
//! in this crate, plus a running count. That count has been wrong three
//! audit rounds running (16, then still wrong, then 18 when the real number
//! had already moved again as new codecs/shims landed) -- the mechanism was
//! wrong, not the arithmetic: a human recount of a fact this cheap to check
//! mechanically will drift every time a new codec or transport shim adds (or
//! forgets to add) a sink.
//!
//! This test replaces the prose count with a mechanical one: it greps every
//! `.rs` file under `src/` for the literal `ProviderError::Transport(`
//! construction/pattern and requires each occurrence to be either
//! self-evidently safe (`redact_transport_error_text` called on the same
//! line) or listed in [`ALLOWLIST`] below, with a reason. An unlisted,
//! unredacted occurrence fails the build; so does a stale allowlist entry
//! that no longer matches anything (the same "wrong for three rounds"
//! failure mode, just the opposite direction -- an entry nobody re-audits
//! because it always vacuously passes).

use std::path::Path;

/// One exempted `ProviderError::Transport(` occurrence that does not (and
/// should not) call `redact_transport_error_text` on its own line, with why.
struct AllowlistEntry {
    /// Path relative to this crate's `src/`, using `/` separators.
    file: &'static str,
    /// A substring unique to the exempted line, used to match it precisely
    /// rather than by line number (which drifts on any unrelated edit above
    /// it in the same file).
    line_contains: &'static str,
    /// Why this occurrence needs no redaction.
    reason: &'static str,
}

/// Verified by hand against the current source (audit L3); each entry's
/// `reason` is the actual justification, not a placeholder, and any change
/// to why an entry is exempt should update the reason along with the code.
const ALLOWLIST: &[AllowlistEntry] = &[
    AllowlistEntry {
        file: "anthropic_provider.rs",
        line_contains: "_ => ProviderError::Transport(format!(",
        reason: "status-only: the message is a fixed \
                 `format!(\"...unexpected HTTP {status}\")` carrying a `u16`, \
                 never a URL or credential-bearing error text",
    },
    AllowlistEntry {
        file: "codec/cohere_v2/provider.rs",
        line_contains: "StreamFailureKind::Transport => ProviderError::Transport(failure.message)",
        reason: "already redacted at construction: `failure.message` for the \
                 `Transport` kind is built by `decode.rs` via \
                 `redact_transport_error_text`, not raw here",
    },
    AllowlistEntry {
        file: "codec/openai_chat/provider.rs",
        line_contains: "StreamFailureKind::Transport => ProviderError::Transport(failure.message)",
        reason: "already redacted at construction: `failure.message` for the \
                 `Transport` kind is built by `decode.rs` via \
                 `redact_transport_error_text`, not raw here",
    },
    AllowlistEntry {
        file: "codec/openai_chat/azure_provider.rs",
        line_contains: "StreamFailureKind::Transport => ProviderError::Transport(failure.message)",
        reason: "already redacted at construction: `failure.message` for the \
                 `Transport` kind is built by `decode.rs` via \
                 `redact_transport_error_text`, not raw here",
    },
    AllowlistEntry {
        file: "retry.rs",
        line_contains:
            "ProviderError::Server { .. } | ProviderError::Timeout | ProviderError::Transport(_)",
        reason: "a pattern match on an already-constructed `ProviderError`, \
                 not a construction site -- nothing to redact here",
    },
    AllowlistEntry {
        file: "retry.rs",
        line_contains: "| ProviderError::Transport(_)",
        reason: "a pattern match on an already-constructed `ProviderError`, \
                 not a construction site -- nothing to redact here",
    },
    AllowlistEntry {
        file: "codec/cohere_v2/provider.rs",
        line_contains: "assert!(matches!(err, ProviderError::Transport(m)",
        reason: "a test assertion inspecting an already-redacted message, \
                 not a production construction site",
    },
];

/// Audit L3: every `ProviderError::Transport(` occurrence in `src/` is either
/// self-evidently redacted (the same line also calls
/// `redact_transport_error_text`) or explicitly, individually allowlisted
/// with a stated reason. Verified against a deliberately-introduced
/// unredacted sink in development (see this test's own commit message for
/// the failing run) before being trusted as a real gate.
#[test]
fn every_provider_error_transport_site_is_redacted_or_explicitly_allowlisted() {
    const NEEDLE: &str = "ProviderError::Transport(";
    const REDACTOR: &str = "redact_transport_error_text";

    for entry in ALLOWLIST {
        assert!(
            !entry.reason.is_empty(),
            "ALLOWLIST entry for {} (`{}`) must state why it's exempt",
            entry.file,
            entry.line_contains
        );
    }

    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut used = vec![false; ALLOWLIST.len()];
    let mut violations = Vec::new();

    for entry in walkdir::WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.path().extension().is_some_and(|e| e == "rs") {
            continue;
        }
        let contents = std::fs::read_to_string(entry.path()).unwrap();
        let rel = entry
            .path()
            .strip_prefix(&src_dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");

        for (line_no, line) in contents.lines().enumerate() {
            // A `//`/`///` comment line can legitimately *mention* the
            // literal `ProviderError::Transport(` in prose (e.g. this
            // module's own doc comment, or `redact.rs`'s, explaining what
            // this test checks) without being a real construction site --
            // real sites are always executable code, never comment-only
            // lines, so skip them rather than flag a doc comment as a
            // violation.
            if line.trim_start().starts_with("//") {
                continue;
            }
            if !line.contains(NEEDLE) {
                continue;
            }
            if line.contains(REDACTOR) {
                continue;
            }
            match ALLOWLIST
                .iter()
                .enumerate()
                .find(|(_, a)| a.file == rel && line.contains(a.line_contains))
            {
                Some((idx, _)) => used[idx] = true,
                None => violations.push(format!(
                    "{rel}:{}: `{}` (not redacted on this line, and not in ALLOWLIST)",
                    line_no + 1,
                    line.trim()
                )),
            }
        }
    }

    assert!(
        violations.is_empty(),
        "found `ProviderError::Transport(` site(s) that are neither redacted \
         nor explicitly allowlisted -- route them through \
         `redact_transport_error_text`, or add a justified ALLOWLIST entry:\n{}",
        violations.join("\n")
    );

    let stale: Vec<&str> = ALLOWLIST
        .iter()
        .zip(&used)
        .filter(|(_, used)| !**used)
        .map(|(a, _)| a.file)
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWLIST entries that no longer match anything in src/ (stale -- \
         the code moved, or the exemption no longer applies): {stale:?}"
    );
}
