/// §9.9: "header capture for the log is allow-list only." Anything not on
/// this list is dropped, unconditionally — including headers that happen to
/// look harmless, because the point is never having to reason about which
/// header names might carry secrets later.
const AUDIT_HEADER_ALLOW_LIST: &[&str] = &[
    "content-type",
    "content-length",
    "x-request-id",
    "x-ratelimit-remaining",
    "x-ratelimit-limit",
    "retry-after",
    "date",
    "server",
];

pub fn capture_headers_for_audit(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| AUDIT_HEADER_ALLOW_LIST.contains(&k.to_lowercase().as_str()))
        .cloned()
        .collect()
}
