//! Integration tests for `round service install`/`round service uninstall`'s
//! pure and file-writing surface.
//!
//! Nothing here touches the real user's `$HOME`, `~/.config`, or
//! `~/Library`: every filesystem-writing test drives `install_to`/
//! `uninstall_from` (the seams `install`/`uninstall` are thin wrappers
//! around) with an explicit `tempfile::tempdir()`, and no test requires
//! `systemctl`/`launchctl` to exist on the host.

use roundhouse_cli::commands::service_install::{
    check_exec_path_safe, install_dir, install_to, render_launchd_plist, render_systemd_unit,
    uninstall_from, OsFamily, ServiceInstallError,
};
use std::path::Path;

#[test]
fn systemd_unit_names_the_actual_installed_binary_and_restarts_always() {
    let unit = render_systemd_unit(Path::new("/home/user/.local/bin/round"));
    assert!(unit.contains("ExecStart=/home/user/.local/bin/round daemon"));
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

#[test]
fn install_dir_is_the_os_specific_per_user_convention() {
    let linux = install_dir(OsFamily::Linux);
    assert!(linux.ends_with("systemd/user"));
    assert!(!linux.starts_with("/etc"));

    let macos = install_dir(OsFamily::MacOs);
    assert!(macos.ends_with("Library/LaunchAgents"));
    assert!(!macos.starts_with("/Library"));
}

#[test]
fn install_to_writes_unit_and_socket_under_a_tempdir() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");

    let unit_path = install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap();

    assert_eq!(unit_path, dir.path().join("roundhouse.service"));
    assert!(dir.path().join("roundhouse.service").is_file());
    assert!(dir.path().join("roundhouse.socket").is_file());

    let written = std::fs::read_to_string(&unit_path).unwrap();
    assert!(written.contains("ExecStart=/home/user/.local/bin/round daemon"));
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
    assert!(contents.contains("ExecStart=/home/user/.local/bin/round daemon"));
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

    let socket_unit = dir.path().join("roundhouse.socket");
    let mode = std::fs::metadata(&socket_unit)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode & 0o022,
        0,
        "socket unit must not be group/world writable"
    );
}

#[test]
fn uninstall_from_removes_previously_installed_files_and_tolerates_absence() {
    let dir = tempfile::tempdir().unwrap();
    let exec_path = Path::new("/home/user/.local/bin/round");
    install_to(dir.path(), OsFamily::Linux, exec_path, false).unwrap();

    uninstall_from(dir.path(), OsFamily::Linux).unwrap();

    assert!(!dir.path().join("roundhouse.service").exists());
    assert!(!dir.path().join("roundhouse.socket").exists());

    // Uninstalling again (nothing left to remove) is not an error.
    uninstall_from(dir.path(), OsFamily::Linux).unwrap();
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
