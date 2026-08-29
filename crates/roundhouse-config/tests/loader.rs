use roundhouse_config::{ConfigLoader, ConfigScope, SecretRef};
use std::fs;
use std::path::PathBuf;

fn temp_dir_for(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "roundhouse-config-test-{name}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

#[test]
fn narrower_scope_overrides_wider_scope_on_conflicting_keys() {
    let dir = temp_dir_for("override");
    let user_path = dir.join("user.toml");
    let project_path = dir.join("project.toml");
    fs::write(&user_path, "[general]\nmode = \"ask\"\n").unwrap();
    fs::write(&project_path, "[general]\nmode = \"auto\"\n").unwrap();

    let loaded = ConfigLoader::new()
        .with_layer(ConfigScope::UserGlobal, &user_path)
        .with_layer(ConfigScope::Project, &project_path)
        .load()
        .expect("load succeeds");

    assert_eq!(
        loaded.get("general").and_then(|t| t.get("mode")).and_then(|v| v.as_str()),
        Some("auto"),
        "Project scope must win over UserGlobal on a conflicting key (§6.2 precedence: narrower wins)"
    );
}

#[test]
fn missing_layer_is_skipped_not_an_error() {
    let dir = temp_dir_for("missing");
    let present_path = dir.join("present.toml");
    let missing_path = dir.join("does-not-exist.toml");
    fs::write(&present_path, "[general]\nmode = \"ask\"\n").unwrap();

    let loaded = ConfigLoader::new()
        .with_layer(ConfigScope::UserGlobal, &present_path)
        .with_layer(ConfigScope::Project, &missing_path)
        .load()
        .expect("a missing layer must not error — it is simply absent");

    assert_eq!(loaded.scopes_present, vec![ConfigScope::UserGlobal]);
}

#[test]
fn nested_tables_deep_merge_rather_than_replace_wholesale() {
    let dir = temp_dir_for("deepmerge");
    let user_path = dir.join("user.toml");
    let project_path = dir.join("project.toml");
    fs::write(
        &user_path,
        "[providers.anthropic]\nbase_url = \"https://api.anthropic.com\"\n",
    )
    .unwrap();
    fs::write(
        &project_path,
        "[providers.anthropic]\ndefault_model = \"claude-opus\"\n",
    )
    .unwrap();

    let loaded = ConfigLoader::new()
        .with_layer(ConfigScope::UserGlobal, &user_path)
        .with_layer(ConfigScope::Project, &project_path)
        .load()
        .expect("load succeeds");

    let anthropic = loaded
        .get("providers")
        .and_then(|p| p.get("anthropic"))
        .expect("providers.anthropic present");
    assert_eq!(
        anthropic.get("base_url").and_then(|v| v.as_str()),
        Some("https://api.anthropic.com"),
        "Project layer must not wholesale-replace the [providers.anthropic] table — \
         base_url from UserGlobal must survive the merge"
    );
    assert_eq!(
        anthropic.get("default_model").and_then(|v| v.as_str()),
        Some("claude-opus")
    );
}

#[test]
fn secret_ref_round_trips_through_toml_without_holding_material() {
    let dir = temp_dir_for("secretref");
    let path = dir.join("secrets.toml");
    fs::write(
        &path,
        "[providers.anthropic]\napi_key = { kind = \"keyring\", service = \"roundhouse\", account = \"anthropic\" }\n",
    )
    .unwrap();

    let loaded = ConfigLoader::new()
        .with_layer(ConfigScope::UserGlobal, &path)
        .load()
        .expect("load succeeds");

    let raw = loaded
        .get("providers")
        .and_then(|p| p.get("anthropic"))
        .and_then(|a| a.get("api_key"))
        .expect("api_key present")
        .clone();
    // NOTE for whoever executes this task: confirm `toml::Value::try_into::<T>()` is
    // the correct conversion call for the pinned `toml` 0.8 — if the real API differs,
    // fix this call site only, the SecretRef type itself does not change.
    let secret: SecretRef = raw
        .try_into()
        .expect("api_key must deserialize into SecretRef");
    assert_eq!(
        secret,
        SecretRef::Keyring {
            service: "roundhouse".into(),
            account: "anthropic".into()
        }
    );
}
