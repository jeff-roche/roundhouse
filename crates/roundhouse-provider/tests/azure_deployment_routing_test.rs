//! Task 14: the `azure-deployment-routing` transport shim (§9.4's second
//! named shim, alongside Task 7's `sigv4-eventstream`).
//!
//! REALITY-CORRECTIONS §2/§14a: `roundhouse_provider::transport` is a
//! private `mod` (`lib.rs` declares `mod transport;`, not `pub mod
//! transport;`), so the brief's literal
//! `use roundhouse_provider::transport::azure_deployment_routing::...` does
//! not compile from this external integration-test crate. `lib.rs` re-
//! exports the submodule itself at the crate root
//! (`pub use transport::azure_deployment_routing;`), the same "use the
//! crate-root re-export" fix REALITY-CORRECTIONS prescribes for every other
//! type the plan tries to reach through that private module — so the import
//! below is `roundhouse_provider::azure_deployment_routing::*`, not the
//! brief's literal path.
use roundhouse_provider::azure_deployment_routing::{
    azure_deployment_url, resolve_deployment_name,
};

#[test]
fn builds_url_with_deployment_name_as_a_path_segment_and_api_version_as_a_query_param() {
    let url = azure_deployment_url(
        "https://my-resource.openai.azure.com",
        "gpt-5-deployment-prod",
        "2026-06-01",
    )
    .unwrap();
    assert_eq!(
        url.as_str(),
        "https://my-resource.openai.azure.com/openai/deployments/gpt-5-deployment-prod/chat/completions?api-version=2026-06-01",
    );
}

#[test]
fn rejects_a_base_url_that_is_not_a_valid_url() {
    assert!(azure_deployment_url("not a url", "dep", "2026-06-01").is_err());
}

/// A gateway/base URL carrying its own path prefix must keep it (mirrors
/// `openai_chat`'s/`google_genai`'s/`cohere_v2`'s identical
/// `build_endpoint_url` precedent for preserving an existing path prefix).
#[test]
fn preserves_a_base_url_path_prefix() {
    let url =
        azure_deployment_url("https://gateway.example.com/proxy", "dep", "2026-06-01").unwrap();
    assert_eq!(
        url.as_str(),
        "https://gateway.example.com/proxy/openai/deployments/dep/chat/completions?api-version=2026-06-01",
    );
}

/// A "cannot be a base" URL (e.g. `mailto:`, `data:`) silently ignores
/// `Url::set_path` per the `url` crate's own documented behavior, which
/// would otherwise send the deployment-routed request to whatever the
/// original path/opaque-data happened to be instead of failing loudly. Must
/// be rejected before that silent no-op can happen.
#[test]
fn rejects_a_base_url_that_cannot_be_a_base() {
    assert!(azure_deployment_url("mailto:someone@example.com", "dep", "2026-06-01").is_err());
}

#[test]
fn deployment_name_resolves_from_the_profile_model_entry_not_the_model_id() {
    // The model id ("gpt-5.4") is what the REST of the system uses to select
    // this profile in the first place (via match_globs, same as every other
    // provider); the deployment name is a separate, Azure-specific mapping
    // this profile carries per model.
    let profile: roundhouse_provider::profile::ProviderProfile =
        toml::from_str(include_str!("../profiles/azure-openai.toml")).unwrap();
    let model = profile
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "gpt-5.4"))
        .unwrap();
    assert_eq!(model.azure_deployment.as_deref(), Some("gpt-5-4-prod"));
}

#[test]
fn resolve_deployment_name_finds_the_mapping_for_a_matched_model_id() {
    let profile: roundhouse_provider::profile::ProviderProfile =
        toml::from_str(include_str!("../profiles/azure-openai.toml")).unwrap();
    assert_eq!(
        resolve_deployment_name(&profile, "gpt-5.4").unwrap(),
        "gpt-5-4-prod"
    );
}

#[test]
fn resolve_deployment_name_fails_closed_for_an_unmapped_model_id() {
    let profile: roundhouse_provider::profile::ProviderProfile =
        toml::from_str(include_str!("../profiles/azure-openai.toml")).unwrap();
    assert!(resolve_deployment_name(&profile, "some-unmapped-model").is_err());
}

/// Security: `deployment_name` becomes a raw URL PATH SEGMENT, bounded by
/// literal `/` on both sides (`.../deployments/{name}/chat/...`) — unlike
/// `google_genai::build_endpoint_url`'s model id (glued to a `:` suffix so a
/// standalone `..` can never form), an Azure deployment name stands alone
/// between two path separators, so an all-dots value really would be a
/// working `..` traversal segment if allowed through. Mirrors
/// `google_genai::provider::build_endpoint_url`'s exact allowlist-plus-
/// all-dots-guard precedent and its adversarial fixture list (including the
/// `url` crate's own pre-parse normalization bypasses: `\` as a path
/// separator for special schemes, and the parser stripping tab/LF/CR before
/// parsing, which can reassemble `.` + TAB + `.` into a literal `..`
/// segment that never appeared in the pre-check string).
#[test]
fn rejects_a_deployment_name_shaped_as_a_path_traversal_or_containing_url_metacharacters() {
    for bad_deployment in [
        "../admin",
        "foo/bar",
        "%2e%2e",
        "dep/../../admin",
        "foo\\bar",
        ".\t.\\admin",
        "",
        ".",
        "..",
        "...",
        "dep?evil=1",
        "dep#frag",
        "dep%20space",
    ] {
        assert!(
            azure_deployment_url(
                "https://my-resource.openai.azure.com",
                bad_deployment,
                "2026-06-01"
            )
            .is_err(),
            "expected deployment name `{bad_deployment:?}` to be rejected"
        );
    }
}

/// Security (audit L1): `base_url` is operator-supplied and can carry a
/// credential (userinfo, or a `?key=...` query parameter some gateways use).
/// Both of `azure_deployment_url`'s `base_url` error paths interpolate
/// `base_url` into the returned `ProviderError`, so both must be routed
/// through the crate's transport-error redactor rather than leaking it raw
/// into a message that can reach a persisted, physically-immutable `events`
/// row. This fixture triggers the "unparseable URL" branch: a stray leading
/// word (no colon of its own) means the candidate scheme run up to the
/// credential-bearing URL's own first colon contains a space, which is not a
/// legal scheme character, so `Url::parse` rejects the string outright --
/// exactly the "operator pasted a URL wrong" shape -- while the
/// credential-bearing URL embedded inside it is itself well-formed, so the
/// redactor's embedded-URL matcher still finds and reduces it. (Verified
/// against `url` 2.5: `Url::parse("not a url https://...")` returns
/// `Err(RelativeUrlWithoutBase)`, not `Ok`.)
#[test]
fn the_invalid_base_url_rejection_does_not_leak_userinfo_or_a_query_credential() {
    let base_url = "not a url https://user:s3cr3t-p4ss@evil.example.com/proxy?api_key=SECRETVALUEABCDEFGHIJKLMN";
    let err = azure_deployment_url(base_url, "dep", "2026-06-01")
        .expect_err("a base_url with a stray leading word must fail to parse as a URL");
    let rendered = err.to_string();
    assert!(
        !rendered.contains("user:s3cr3t-p4ss"),
        "userinfo must not survive: {rendered}"
    );
    assert!(
        !rendered.contains("SECRETVALUEABCDEFGHIJKLMN"),
        "the query string's credential-shaped value must not survive: {rendered}"
    );
    assert!(
        rendered.contains("evil.example.com"),
        "the host itself is not secret and should stay, for diagnosability: {rendered}"
    );
}

/// Security (audit L1), the second sink: the "cannot be a base" branch fires
/// on a URL that parses fine but has no hierarchical part to route through
/// (e.g. a non-`http(s)` scheme whose remainder isn't `//`-prefixed). An
/// operator-pasted value can still carry a `https://user:pass@host?key=...`
/// credential embedded in it even when the outer string as a whole takes
/// this shape, so this sink needs the same redaction as the parse-failure
/// one.
#[test]
fn the_cannot_be_a_base_rejection_does_not_leak_userinfo_or_a_query_credential() {
    let base_url =
        "gateway:https://user:s3cr3t-p4ss@evil.example.com/proxy?api_key=SECRETVALUEABCDEFGHIJKLMN";
    let err = azure_deployment_url(base_url, "dep", "2026-06-01")
        .expect_err("a non-special, non-`//`-prefixed scheme must be rejected as cannot-be-a-base");
    let rendered = err.to_string();
    assert!(
        !rendered.contains("user:s3cr3t-p4ss"),
        "userinfo must not survive: {rendered}"
    );
    assert!(
        !rendered.contains("SECRETVALUEABCDEFGHIJKLMN"),
        "the query string's credential-shaped value must not survive: {rendered}"
    );
    assert!(
        rendered.contains("evil.example.com"),
        "the host itself is not secret and should stay, for diagnosability: {rendered}"
    );
}

/// The allowlist must not over-reject real deployment names (customer-chosen
/// identifiers, typically alphanumerics/hyphens/underscores/dots).
#[test]
fn legitimate_deployment_names_are_accepted() {
    for good_deployment in [
        "gpt-5-deployment-prod",
        "gpt_4o_prod",
        "gpt.5.4",
        "deployment01",
    ] {
        assert!(
            azure_deployment_url(
                "https://my-resource.openai.azure.com",
                good_deployment,
                "2026-06-01"
            )
            .is_ok(),
            "expected deployment name `{good_deployment}` to be accepted"
        );
    }
}

/// A rejected deployment name may contain newlines or other control bytes
/// smuggled in from config; the rejection message must escape it (`{:?}`),
/// not interpolate it raw, since `ProviderError`'s `Display` can reach a
/// persisted, physically-immutable `events` row (mirrors
/// `google_genai::provider::build_endpoint_url`'s identical close-out
/// guarantee for a rejected model id).
#[test]
fn the_rejection_message_escapes_a_newline_in_the_deployment_name_rather_than_interpolating_it_raw()
{
    let err = azure_deployment_url(
        "https://my-resource.openai.azure.com",
        "dep\nadmin",
        "2026-06-01",
    )
    .expect_err("a deployment name containing a newline must be rejected");
    let rendered = err.to_string();
    assert!(
        !rendered.contains('\n'),
        "the rejection message must not contain a raw, unescaped newline: {rendered:?}"
    );
    assert!(
        rendered.contains("\\n"),
        "expected the newline to appear escaped (via {{:?}}) in the message: {rendered:?}"
    );
}
