//! §9.9 hardening triad, parts 2-3: allow-list header capture for the audit
//! log, and a complementary, shape-based redaction pass over persisted
//! provider error bodies. Neither mechanism here handles secret material —
//! header capture actively excludes anything that could carry it, and
//! redaction only ever removes text, never reads or stores a live secret.

pub mod header_capture;
pub mod redact;

pub use header_capture::capture_headers_for_audit;
pub use redact::redact_error_body;
// Fix round 4, R4: crate-internal only (no public surface change) -- shared
// by `cohere_v2` and `openai_chat`'s transport-error sinks.
pub(crate) use redact::redact_transport_error_text;
