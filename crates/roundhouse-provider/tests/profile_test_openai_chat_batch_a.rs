//! Profile-deserialization shape tests for the five `openai-chat` batch-A
//! profiles (REALITY-CORRECTIONS §10: `CARGO_MANIFEST_DIR` is already
//! `crates/roundhouse-provider`, so the path has no `../`).
use roundhouse_provider::profile::{AuthKind, ParamsMode, ProviderProfile};

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

#[test]
fn openrouter_profile_shape() {
    let p = load("openrouter");
    assert_eq!(p.codec, "openai-chat");
    assert_eq!(p.defaults.base_url, "https://openrouter.ai/api/v1");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
    assert_eq!(p.defaults.params.mode, ParamsMode::DenyList);
}

#[test]
fn together_profile_shape() {
    let p = load("together");
    assert_eq!(p.codec, "openai-chat");
    assert_eq!(p.defaults.base_url, "https://api.together.xyz/v1");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
}

#[test]
fn fireworks_profile_shape() {
    let p = load("fireworks");
    assert_eq!(p.codec, "openai-chat");
    assert_eq!(p.defaults.base_url, "https://api.fireworks.ai/inference/v1");
}

#[test]
fn groq_profile_denies_logprobs() {
    // Groq's real API restriction: `logprobs` is not supported on chat
    // completions the way OpenAI's is -- this is the "a few quirk-profile
    // fields" case audit finding 1 describes for batched providers.
    let p = load("groq");
    assert_eq!(p.defaults.base_url, "https://api.groq.com/openai/v1");
    assert!(p.defaults.params.fields.iter().any(|f| f == "logprobs"));
}

#[test]
fn cerebras_profile_denies_n() {
    // Cerebras does not support `n` (multiple completions per request).
    let p = load("cerebras");
    assert_eq!(p.defaults.base_url, "https://api.cerebras.ai/v1");
    assert!(p.defaults.params.fields.iter().any(|f| f == "n"));
}
