//! Integration-level coverage for `roundhouse_config::network`, exercised
//! through the crate's public API (as an external caller — `roundhouse-
//! daemon`/`roundhouse-engine` — would use it), rather than `network.rs`'s
//! own `#[cfg(test)]` unit tests.
//!
//! The load-bearing case here is the same one `crates/roundhouse-config/
//! src/network.rs`'s unit tests already prove from inside the crate: a
//! project-scoped `[network] allowed_hosts` entry must never be able to
//! widen — or, worse, unilaterally establish — the egress allowlist a real
//! caller ends up with.

use roundhouse_config::network::load_network_config_from_layers;
use roundhouse_config::{ConfigScope, NetworkConfig};

fn write(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn no_configured_layers_default_to_a_fail_closed_empty_allowlist() {
    let cfg = load_network_config_from_layers(vec![]).unwrap();
    assert_eq!(cfg, NetworkConfig::default());
    assert!(cfg.allowed_hosts.is_empty());
}

#[test]
fn a_user_global_allowlist_reaches_the_caller_unmodified() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "config.toml",
        "[network]\nallowed_hosts = [\"api.anthropic.com\"]\n",
    );
    let cfg = load_network_config_from_layers(vec![(ConfigScope::UserGlobal, path)]).unwrap();
    assert_eq!(cfg.allowed_hosts, vec!["api.anthropic.com".to_string()]);
}

/// The attack this task exists to close: cloning a hostile repository and
/// opening a session inside it must not let that repo's own
/// `.roundhouse/config.toml` add its own exfiltration destination to the
/// egress allowlist — regardless of whether the operator's own (wider)
/// scope ever configured an allowlist at all.
#[test]
fn a_project_scoped_config_can_never_add_a_host_the_wider_scope_did_not_already_allow() {
    let dir = tempfile::tempdir().unwrap();
    let user = write(dir.path(), "user-config.toml", "");
    let project = write(
        dir.path(),
        "project-config.toml",
        "[network]\nallowed_hosts = [\"attacker.example.net\"]\n",
    );

    let cfg = load_network_config_from_layers(vec![
        (ConfigScope::UserGlobal, user),
        (ConfigScope::Project, project),
    ])
    .unwrap();

    assert!(
        cfg.allowed_hosts.is_empty(),
        "a project-scoped config widened the egress allowlist to {:?}",
        cfg.allowed_hosts
    );
}

/// A legitimate use of project scope per §6.2: narrowing an already-wider
/// user allowlist down is honored, since it can never expand what the
/// project's own environment can reach.
#[test]
fn a_project_scoped_config_may_legitimately_narrow_the_user_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let user = write(
        dir.path(),
        "user-config.toml",
        "[network]\nallowed_hosts = [\"api.anthropic.com\", \"crates.io\"]\n",
    );
    let project = write(
        dir.path(),
        "project-config.toml",
        "[network]\nallowed_hosts = [\"crates.io\"]\n",
    );

    let cfg = load_network_config_from_layers(vec![
        (ConfigScope::UserGlobal, user),
        (ConfigScope::Project, project),
    ])
    .unwrap();

    assert_eq!(cfg.allowed_hosts, vec!["crates.io".to_string()]);
}
