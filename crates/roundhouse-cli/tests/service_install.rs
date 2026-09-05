//! Integration tests for `round service install`/`round service uninstall`'s
//! pure and file-writing surface.
//!
//! Nothing here touches the real user's `$HOME`, `~/.config`, or
//! `~/Library`: every filesystem-writing test drives `install_to`/
//! `uninstall_from` (the seams `install`/`uninstall` are thin wrappers
//! around) with an explicit `tempfile::tempdir()`, and no test requires
//! `systemctl`/`launchctl` to exist on the host. Nothing here mutates
//! process-wide environment variables either (see
//! `service_install::tests` in the crate itself for the `$HOME`/
//! `$XDG_CONFIG_HOME` policy tests, which take those as plain function
//! arguments instead).

use roundhouse_cli::commands::service_install::{
    check_exec_path_safe, install_dir_unchecked, install_to, render_launchd_plist,
    render_systemd_unit, uninstall_from, OsFamily, ServiceInstallError,
};
use std::path::Path;

#[test]
fn systemd_unit_names_the_actual_installed_binary_and_restarts_always() {
    let unit = render_systemd_unit(Path::new("/home/user/.local/bin/round"));
    // Fix round 1 (security review, H1): the exec path is now quoted so
    // systemd's `ExecStart=` word-splitting can't be fooled by a space in
    // the path — see `systemd_execstart_names_the_exact_verified_path_*`
    // below for the round-trip check this format exists to satisfy.
    assert!(unit.contains("ExecStart=\"/home/user/.local/bin/round\" daemon"));
    assert!(unit.contains("Restart=always"));
    // §8.7: "Persistent=true buys nothing" — we do our own catch-up, so the
    // rendered unit must not rely on systemd's own missed-timer replay.
    assert!(!unit.contains("Persistent=true"));
}

#[test]
fn launchd_plist_names_the_actual_installed_binary_and_keeps_alive() {
    let plist = render_launchd_plist(Path::new("/usr/local/bin/round"));
    assert!(plist.contains("<string>/usr/local/bin/round</string>"));
    assert!(plist.contains("<string>daemon</string>"));
    assert!(plist.contains("<key>KeepAlive</key>"));
}

/// H1 (security review): the path a real systemd would actually execute —
/// after undoing exactly the quoting/escaping `render_systemd_unit` applies
/// — must equal the path that was safety-checked, even when it contains a
/// space. Before this fix, an unquoted `ExecStart=/tmp/rh build/round
/// daemon` would have systemd split it into executable `/tmp/rh` with argv
/// `build/round daemon` — a completely different, attacker-creatable path.
///
/// Example-based (this one input, not a generative property test), but the
/// escaping model it checks against real `systemd-analyze verify --user`
/// behavior has been independently confirmed by security review.
#[test]
fn systemd_execstart_names_the_exact_verified_path_even_with_a_space() {
    let exec_path = Path::new("/tmp/rh build/round");
    let unit = render_systemd_unit(exec_path);
    let line = unit
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .expect("unit must have an ExecStart= line");
    let value = line
        .strip_prefix("ExecStart=")
        .and_then(|v| v.strip_suffix(" daemon"))
        .expect("ExecStart= must end with the daemon subcommand");
    let recovered = unescape_systemd_word(value);
    assert_eq!(recovered, exec_path.to_str().unwrap());
}

#[test]
fn systemd_execstart_doubles_percent_signs_so_systemd_does_not_expand_a_specifier() {
    let exec_path = Path::new("/opt/100%cpu/round");
    let unit = render_systemd_unit(exec_path);
    assert!(unit.contains("ExecStart=\"/opt/100%%cpu/round\" daemon"));
    let line = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
    let value = line
        .strip_prefix("ExecStart=")
        .and_then(|v| v.strip_suffix(" daemon"))
        .unwrap();
    assert_eq!(unescape_systemd_word(value), exec_path.to_str().unwrap());
}

/// Inverse of the escaping `render_systemd_unit` applies to its
/// `ExecStart=` value: strips the wrapping double quotes, un-backslash
/// escapes, then un-doubles `%` — i.e. exactly what systemd's own unit-file
/// parser does before exec'ing. Test-only: demonstrates the round-trip for
/// these specific example inputs rather than just eyeballing the rendered
/// string.
fn unescape_systemd_word(quoted: &str) -> String {
    let inner = quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .expect("ExecStart='s path must be double-quoted");
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
                continue;
            }
        }
        out.push(c);
    }
    out.replace("%%", "%")
}

#[test]
fn launchd_plist_escapes_xml_special_characters_in_the_exec_path() {
    let plist = render_launchd_plist(Path::new("/tmp/a&b<c>/round"));
    assert!(plist.contains("<string>/tmp/a&amp;b&lt;c&gt;/round</string>"));
    assert!(!plist.contains("<string>/tmp/a&b<c>/round</string>"));
}

/// Fix round 2 (code review): the systemd side round-trips through a real
/// unescape; the launchd tests before this one only used `contains`, which
/// would still pass even if a future escaping regression left the raw
/// substring present alongside broken XML elsewhere. This extracts the
/// first `<string>` in `ProgramArguments` and un-escapes it exactly the way
/// an XML parser would, proving the recovered value equals the original
/// path — for a path with XML-special characters, and for one with a space.
#[test]
fn launchd_plist_program_argument_round_trips_xml_special_characters() {
    let exec_path = Path::new("/tmp/a&b<c>/round");
    let plist = render_launchd_plist(exec_path);
    let recovered = unescape_xml_text(&first_program_argument(&plist));
    assert_eq!(recovered, exec_path.to_str().unwrap());
}

#[test]
fn launchd_plist_program_argument_round_trips_a_path_with_a_space() {
    let exec_path = Path::new("/tmp/rh build/round");
    let plist = render_launchd_plist(exec_path);
    let recovered = unescape_xml_text(&first_program_argument(&plist));
    assert_eq!(recovered, exec_path.to_str().unwrap());
}

/// Extracts the text of the first `<string>` element inside
/// `<key>ProgramArguments</key>`'s `<array>` — the binary path
/// `render_launchd_plist` substitutes. Test-only parsing, deliberately
/// simple (no real XML parser dependency) since it only needs to locate one
/// well-known element in output this same test file controls the shape of.
fn first_program_argument(plist: &str) -> String {
    let key = "<key>ProgramArguments</key>";
    let after_key = &plist[plist.find(key).expect("ProgramArguments key present") + key.len()..];
    let array_start = after_key.find("<array>").expect("array present") + "<array>".len();
    let after_array_open = &after_key[array_start..];
    let string_start =
        after_array_open.find("<string>").expect("string present") + "<string>".len();
    let after_string_open = &after_array_open[string_start..];
    let string_end = after_string_open
        .find("</string>")
        .expect("closing string tag present");
    after_string_open[..string_end].to_string()
}

/// Inverse of `escape_xml_text` in the crate under test.
fn unescape_xml_text(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Fix round 1 (security review, H1.4): launchd's log paths use `~`, which
/// launchd does not expand. `render_launchd_plist` must substitute an
/// absolute path there too, not just for the binary.
#[test]
fn launchd_plist_substitutes_absolute_log_paths_not_a_literal_tilde() {
    let plist = render_launchd_plist(Path::new("/usr/local/bin/round"));
    assert!(!plist.contains("~/Library/Logs"));
    assert!(plist.contains("Library/Logs/roundhouse/daemon.log"));
    assert!(plist.contains("Library/Logs/roundhouse/daemon.err"));
}

#[test]
fn install_dir_unchecked_is_the_os_specific_per_user_convention() {
    let linux = install_dir_unchecked(OsFamily::Linux);
    assert!(linux.ends_with("systemd/user"));
    assert!(!linux.starts_with("/etc"));

    let macos = install_dir_unchecked(OsFamily::MacOs);
    assert!(macos.ends_with("Library/LaunchAgents"));
    assert!(!macos.starts_with("/Library"));
}

#[test]
fn install_to_writes_the_unit_under_a_tempdir() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");

    let unit_path = install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap();

    assert_eq!(unit_path, dir.path().join("roundhouse.service"));
    assert!(dir.path().join("roundhouse.service").is_file());
    // Fix round 1 (orchestrator ruling): the paired `.socket` unit was
    // removed as a dead artifact (see packaging/systemd/roundhouse.service's
    // comment) -- no socket file should be written.
    assert!(!dir.path().join("roundhouse.socket").exists());

    let written = std::fs::read_to_string(&unit_path).unwrap();
    assert!(written.contains("ExecStart=\"/home/user/.local/bin/round\" daemon"));
}

#[test]
fn install_to_writes_the_plist_under_a_tempdir_on_macos() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/usr/local/bin/round");

    let plist_path = install_to(dir.path(), OsFamily::MacOs, exec_path, false).unwrap();

    assert_eq!(plist_path, dir.path().join("com.roundhouse.daemon.plist"));
    assert!(plist_path.is_file());
}

#[test]
fn install_to_refuses_to_clobber_an_existing_unit_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");

    install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap();

    // A hand-customised unit the user edited themselves.
    let unit_path = dir.path().join("roundhouse.service");
    std::fs::write(&unit_path, "# hand customised\n").unwrap();

    let err = install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap_err();
    assert!(matches!(err, ServiceInstallError::AlreadyExists { .. }));

    // The hand-customised content must survive the refused install.
    let contents = std::fs::read_to_string(&unit_path).unwrap();
    assert_eq!(contents, "# hand customised\n");
}

#[test]
fn install_to_overwrites_with_force() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");

    install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap();
    std::fs::write(dir.path().join("roundhouse.service"), "# stale\n").unwrap();

    install_to(dir.path(), OsFamily::Linux, exec_path, true).unwrap();

    let contents = std::fs::read_to_string(dir.path().join("roundhouse.service")).unwrap();
    assert!(contents.contains("ExecStart=\"/home/user/.local/bin/round\" daemon"));
}

#[cfg(unix)]
#[test]
fn install_to_writes_files_that_are_not_group_or_world_writable() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");
    let unit_path = install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap();

    let mode = std::fs::metadata(&unit_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode & 0o022,
        0,
        "unit file must not be group/world writable"
    );
}

/// Fix round 2 (code review, M): `--force` must *repair* a unit file that
/// already exists at a permissive mode, not just overwrite its contents.
/// The first cut of `write_unit_file` moved `0o644` from a post-open
/// `set_permissions` to `OpenOptionsExt::mode`, which `open(2)` silently
/// ignores whenever `O_CREAT` doesn't actually create the file — exactly
/// the `--force` overwrite-an-existing-file path.
#[cfg(unix)]
#[test]
fn install_to_with_force_repairs_a_permissive_existing_mode() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");
    let unit_path = dir.path().join("roundhouse.service");
    std::fs::write(&unit_path, "# stale, world-writable\n").unwrap();
    std::fs::set_permissions(&unit_path, std::fs::Permissions::from_mode(0o666)).unwrap();

    install_to(dir.path(), OsFamily::Linux, exec_path, true).unwrap();

    let mode = std::fs::metadata(&unit_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode & 0o022,
        0,
        "--force must repair a pre-existing permissive mode, not just overwrite content"
    );
}

/// Fix round 1 (security review, M1's downstream item): a *pre-existing*
/// install directory that is group/world-writable must be refused, not
/// silently written into -- a writable directory defeats the file's own
/// 0o644 mode (another user can just replace the whole file).
#[cfg(unix)]
#[test]
fn install_to_refuses_a_pre_existing_group_writable_install_dir() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");

    let err = install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap_err();
    assert!(matches!(err, ServiceInstallError::UnsafeInstallDir { .. }));
    assert!(!dir.path().join("roundhouse.service").exists());
}

/// Fix round 2 (code review, L): the install-directory check must walk
/// ancestors just like the exec-path check does -- `$XDG_CONFIG_HOME` at
/// `/srv/shared/cfg` with `/srv/shared` group-writable and `cfg/` itself a
/// safe `0700` must still be refused, because any group member can rename
/// `cfg` out from under the victim and substitute their own tree.
#[cfg(unix)]
#[test]
fn install_to_refuses_an_install_dir_with_a_writable_grandparent() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    let cfg_dir = root.path().join("cfg");
    std::fs::create_dir(&cfg_dir).unwrap();
    std::fs::set_permissions(&cfg_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");

    let err = install_to(&cfg_dir, OsFamily::Linux, exec_path, false).unwrap_err();
    assert!(matches!(err, ServiceInstallError::UnsafeInstallDir { .. }));
    assert!(!cfg_dir.join("roundhouse.service").exists());
}

/// H1.2 (security review): a raw newline in the exec path must be rejected
/// outright rather than written -- quoting alone cannot make an embedded
/// line break safe in a line-based unit file (it would still start a new
/// line, e.g. injecting a new `[Service]` directive).
#[test]
fn install_to_rejects_an_exec_path_containing_a_newline() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round\nRestart=no");

    let err = install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap_err();
    assert!(matches!(err, ServiceInstallError::InvalidExecPath { .. }));
    assert!(!dir.path().join("roundhouse.service").exists());
}

/// H1.4 (security review): a non-UTF-8 exec path must be rejected outright
/// rather than lossily substituted -- `.display()`'s U+FFFD replacement
/// would silently write a unit naming a *different* path than the one that
/// was safety-checked.
#[cfg(unix)]
#[test]
fn install_to_rejects_a_non_utf8_exec_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let bytes = b"/home/user/\xffbin/round";
    let exec_path = Path::new(OsStr::from_bytes(bytes));

    let err = install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap_err();
    assert!(matches!(err, ServiceInstallError::InvalidExecPath { .. }));
}

#[test]
fn uninstall_from_removes_previously_installed_files_and_tolerates_absence() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");
    install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap();

    uninstall_from(dir.path(), OsFamily::Linux).unwrap();

    assert!(!dir.path().join("roundhouse.service").exists());

    // Uninstalling again (nothing left to remove) is not an error.
    uninstall_from(dir.path(), OsFamily::Linux).unwrap();
}

/// Fix round 2 (code review, L): `uninstall_from` must also clean up
/// `roundhouse.socket`, a file an earlier version of this installer wrote
/// (before the orchestrator ruling that removed it from `install_to`) but
/// that current code never writes and therefore, without this, would never
/// remove either -- leaving an upgraded user's enabled, still-loaded socket
/// unit orphaned forever.
#[test]
fn uninstall_from_removes_the_legacy_socket_unit_left_by_an_earlier_version() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");
    install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap();
    // Simulate a leftover from the previous installer version, which wrote
    // this file directly (current `install_to` no longer does).
    std::fs::write(dir.path().join("roundhouse.socket"), "[Socket]\n").unwrap();

    uninstall_from(dir.path(), OsFamily::Linux).unwrap();

    assert!(!dir.path().join("roundhouse.service").exists());
    assert!(!dir.path().join("roundhouse.socket").exists());
}

#[cfg(unix)]
#[test]
fn check_exec_path_safe_rejects_a_world_writable_directory_without_sticky_bit() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let exe = dir.path().join("round");
    std::fs::write(&exe, b"").unwrap();

    let err = check_exec_path_safe(&exe).unwrap_err();
    assert!(matches!(err, ServiceInstallError::UnsafeExecPath { .. }));
}

/// M1 (security review): group-writable, not just world-writable, must be
/// rejected too -- a `0775` directory owned by a shared group is exactly as
/// replaceable by any group member as a `0777` one is by any user.
#[cfg(unix)]
#[test]
fn check_exec_path_safe_rejects_a_group_writable_directory_without_sticky_bit() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    let exe = dir.path().join("round");
    std::fs::write(&exe, b"").unwrap();

    let err = check_exec_path_safe(&exe).unwrap_err();
    assert!(matches!(err, ServiceInstallError::UnsafeExecPath { .. }));
}

/// M1 (security review): the check must walk *every* ancestor, not just the
/// immediate parent -- `/srv/shared/bin/round` must be rejected even though
/// `bin/` itself is a safe `0755`, because `/srv/shared` (the grandparent)
/// is a shared, writable-by-everyone directory.
#[cfg(unix)]
#[test]
fn check_exec_path_safe_walks_ancestors_and_rejects_a_shared_writable_grandparent() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let bin_dir = root.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = bin_dir.join("round");
    std::fs::write(&exe, b"").unwrap();

    let err = check_exec_path_safe(&exe).unwrap_err();
    assert!(matches!(err, ServiceInstallError::UnsafeExecPath { .. }));
}

/// Fix round 2 (code review): the ancestor-directory walk doesn't cover a
/// permissive mode on the exec *file* itself -- a `round` binary at
/// `0666` under perfectly safe `0755` ancestors is still directly
/// overwritable by any local user.
#[cfg(unix)]
#[test]
fn check_exec_path_safe_rejects_a_world_writable_exec_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = dir.path().join("round");
    std::fs::write(&exe, b"").unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o666)).unwrap();

    let err = check_exec_path_safe(&exe).unwrap_err();
    assert!(matches!(
        err,
        ServiceInstallError::UnsafeExecFileMode { .. }
    ));
}

#[cfg(unix)]
#[test]
fn check_exec_path_safe_accepts_a_world_writable_directory_with_sticky_bit() {
    use std::os::unix::fs::PermissionsExt;

    // e.g. /tmp itself: world-writable but sticky, which is the standard,
    // safe shape for a shared scratch directory (only the file's owner can
    // rename/delete it out from under another user).
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
    let exe = dir.path().join("round");
    std::fs::write(&exe, b"").unwrap();

    check_exec_path_safe(&exe).unwrap();
}

#[cfg(unix)]
#[test]
fn check_exec_path_safe_accepts_an_owner_only_directory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let exe = dir.path().join("round");
    std::fs::write(&exe, b"").unwrap();

    check_exec_path_safe(&exe).unwrap();
}
