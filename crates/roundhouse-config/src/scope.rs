/// §6.2's precedence ranking, restricted to the scopes a config *file* can
/// live at — the policy engine's `Grant` scope has no config-file analogue.
/// Derive order matters: variants are listed ascending by precedence, so
/// `ConfigScope::Project > ConfigScope::UserGlobal` holds by derived `Ord`.
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
