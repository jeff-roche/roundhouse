/// §9.9 hardening triad, part 1: "an override is recorded on the task as
/// host only, never a full URL with query string (some gateways put keys in
/// query params)." Called at the same call site that resolves an explicit
/// base-URL override (`base_url::resolve_base_url`), before that URL is
/// ever written to a task record.
pub fn record_base_url_override(overridden_url: &str) -> String {
    match url::Url::parse(overridden_url) {
        Ok(parsed) => parsed
            .host_str()
            .map(|h| match parsed.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
            .unwrap_or_else(|| "<unparseable-host>".to_string()),
        Err(_) => "<unparseable-host>".to_string(),
    }
}
