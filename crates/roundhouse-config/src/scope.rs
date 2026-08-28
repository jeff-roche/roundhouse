/// §6.2's precedence ranking, restricted to the scopes a config *file* can
/// live at — the policy engine's `Grant` scope has no config-file analogue.
/// Derive order matters: variants are listed ascending by precedence, so
/// `ConfigScope::Project > ConfigScope::UserGlobal` holds by derived `Ord`.
///
/// **Known gap — not narrow-only, no trust-decision gating.** `ConfigLoader`
/// (`loader.rs`) merges layers by this ordering alone: a narrower scope's
/// value for a key always overwrites a wider scope's value for that same
/// key, full stop. §6.2 states a stricter rule it calls "the single most
/// important precedence rule" for `.roundhouse/policy.toml` *and*
/// `.roundhouse/config.toml` specifically (both named `Project` scope
/// there): "Project scope may narrow, never widen, unless the user has
/// recorded a trust decision keyed on `(repo_root, blake3(policy_file))`."
/// That narrow-only/widen distinction, and the trust-decision store it
/// depends on, are **not implemented anywhere in this crate**. This
/// generic `ConfigLoader` is plain layered TOML merge for Phase 0's
/// contract (`S-CFG-1`); it must not be assumed — by this crate or by any
/// later phase — to already provide narrow-only trust-gating for
/// security-relevant keys such as `general.mode`
/// (`plan`/`ask`/`accept-edits`/`auto`, §6.3). Real enforcement of §6.2's
/// rule belongs to whichever later phase actually gates autonomy/policy
/// decisions (`roundhouse-policy`'s Phase 2 engine), which has the
/// trust-decision infrastructure this crate deliberately does not build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfigScope {
    Builtin,
    UserGlobal,
    Project,
    /// No default on-disk path yet — a `Workspace` can span multiple project
    /// roots (§3.1), and that resolution isn't designed yet. Included now so
    /// `ConfigScope`'s ranking already matches §6.2's shape; `default_layers`
    /// below does not populate a `Workspace` layer.
    Workspace,
}
