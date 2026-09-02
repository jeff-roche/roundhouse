//! Task 13: the OpenAI first-party `openai-chat` profile is the DEGRADED
//! path (§9.2) relative to `openai-responses.toml` (Task 5); this is what
//! makes that fact data via `[[model]].endpoint_preference` +
//! `resolve_endpoint_preference` (Task 4, §9.4, audit finding 3) instead of
//! a hardcoded branch in a `Provider` impl.
use roundhouse_provider::profile::{resolve_endpoint_preference, EndpointKind, ProviderProfile};

fn load_openai_chat_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/openai.toml")).unwrap()
}

#[test]
fn frontier_gpt5_model_prefers_responses_and_marks_chat_degraded() {
    let p = load_openai_chat_profile();
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "gpt-5*"))
        .expect("gpt-5* entry must exist");
    assert_eq!(
        model.endpoint_preference.len(),
        2,
        "§9.4: [responses, chat] with chat marked degraded"
    );
    assert_eq!(
        model.endpoint_preference[0].endpoint,
        EndpointKind::Responses
    );
    assert!(
        !model.endpoint_preference[0].degraded,
        "Responses must be listed first and non-degraded"
    );
    assert_eq!(model.endpoint_preference[1].endpoint, EndpointKind::Chat);
    assert!(
        model.endpoint_preference[1].degraded,
        "§9.2: Chat Completions is degraded for frontier OpenAI models"
    );
}

#[test]
fn legacy_gpt4_model_has_no_endpoint_preference_at_all() {
    // §9.2's degradation is specific to frontier models (GPT-5.4+) — gpt-4/3.5
    // never lost tool-calling on Chat Completions, so there is nothing to
    // prefer around; an empty endpoint_preference is correct, not an omission.
    let p = load_openai_chat_profile();
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "gpt-4*"))
        .expect("gpt-4* entry must exist");
    assert!(model.endpoint_preference.is_empty());
}

#[test]
fn resolving_with_both_endpoints_available_picks_responses() {
    let p = load_openai_chat_profile();
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "gpt-5*"))
        .unwrap();
    let resolution = resolve_endpoint_preference(
        &model.endpoint_preference,
        &[EndpointKind::Responses, EndpointKind::Chat],
    )
    .unwrap();
    assert_eq!(resolution.endpoint, EndpointKind::Responses);
    assert!(!resolution.degraded);
}

#[test]
fn resolving_with_only_chat_available_falls_back_degraded_reportable_as_a_loss_event() {
    // e.g. the Responses adapter is still `experimental` (§9.10) and not yet
    // promoted to `supported` in this deployment — Chat is all that's left.
    let p = load_openai_chat_profile();
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "gpt-5*"))
        .unwrap();
    let resolution =
        resolve_endpoint_preference(&model.endpoint_preference, &[EndpointKind::Chat]).unwrap();
    assert_eq!(resolution.endpoint, EndpointKind::Chat);
    assert!(
        resolution.degraded,
        "falling back to Chat must be reported as degraded so a caller can log a LossEvent"
    );
}
