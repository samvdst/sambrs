//! Live SMB integration tests; see the README's Testing section.
#![cfg(windows)]

use sambrs::{
    ConnectOptions, DisconnectOptions, DriveLetter, Error, SmbTarget, cancel_connection, enumerate,
    query, server,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_ASSIGNED, ERROR_BAD_NET_NAME, ERROR_INVALID_PASSWORD,
    ERROR_LOGON_FAILURE, ERROR_NO_NET_OR_BAD_PATH, ERROR_NO_NETWORK, ERROR_OPEN_FILES,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_DuplicateShare as NERR_DUPLICATE_SHARE, NERR_NetNameNotFound as NERR_NET_NAME_NOT_FOUND,
};

const SHARE: &str = "SAMBRS_TEST_SHARE";
const USERNAME: &str = "SAMBRS_TEST_USERNAME";
const PASSWORD: &str = "SAMBRS_TEST_PASSWORD";

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

/// `server::*` tests only make sense against the local machine, with rights
/// to administer it.
fn local_admin() -> bool {
    std::env::var("SAMBRS_TEST_LOCAL").is_ok_and(|v| v == "1")
}

fn target(mount: Option<DriveLetter>) -> SmbTarget {
    let target = SmbTarget::new(required_env(SHARE))
        .credentials(required_env(USERNAME), required_env(PASSWORD));
    mount.into_iter().fold(target, SmbTarget::mount_on)
}

fn drive_exists(letter: DriveLetter) -> bool {
    std::path::Path::new(&format!(r"{letter}\")).is_dir()
}

// ── connect / disconnect ────────────────────────────────────────────────────

// Lovely Windows returns several statuses for a bad password.
#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn wrong_password_fails_without_prompting() {
    let target = SmbTarget::new(required_env(SHARE))
        .credentials(required_env(USERNAME), "definitely-the-wrong-password-1");
    let result = target.connect();
    assert!(
        matches!(
            result,
            Err(Error::Windows(
                ERROR_INVALID_PASSWORD | ERROR_LOGON_FAILURE | ERROR_ACCESS_DENIED
            ))
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn nonexistent_share_fails() {
    let target = SmbTarget::new(r"\\thisisnotashare.local\Share-Name")
        .credentials(required_env(USERNAME), required_env(PASSWORD));
    let result = target.connect();
    // The documented WNetAddConnection2W error list is not exhaustive;
    // unresolvable hosts commonly surface as ERROR_BAD_NETPATH (53) or
    // ERROR_SEM_TIMEOUT (121).
    assert!(
        matches!(
            result,
            Err(Error::Windows(
                ERROR_BAD_NET_NAME | ERROR_NO_NET_OR_BAD_PATH | ERROR_NO_NETWORK | 53 | 121
            ))
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn deviceless_connect_and_reconnect_works() {
    let target = target(None);
    target.connect().unwrap();
    // Reconnecting a deviceless connection is fine.
    target.connect().unwrap();
    assert!(std::path::Path::new(&required_env(SHARE)).is_dir());
    target.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn mounted_reconnect_fails_with_already_assigned() {
    let target = target(Some(DriveLetter::S));
    target.connect().unwrap();
    assert_eq!(
        target.connect(),
        Err(Error::Windows(ERROR_ALREADY_ASSIGNED))
    );
    target.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn two_letters_to_the_same_share_work() {
    let one = target(Some(DriveLetter::S));
    let two = target(Some(DriveLetter::T));
    one.connect().unwrap();
    two.connect().unwrap();
    assert!(drive_exists(DriveLetter::S));
    assert!(drive_exists(DriveLetter::T));
    one.disconnect().unwrap();
    assert!(!drive_exists(DriveLetter::S));
    two.disconnect().unwrap();
    assert!(!drive_exists(DriveLetter::T));
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn force_disconnect_with_open_file_works() {
    let target = target(Some(DriveLetter::U));
    target.connect().unwrap();
    let file = std::fs::File::create(r"U:\sambrs-force-disconnect.txt").unwrap();
    // Non-forced disconnect must refuse while a file is open.
    assert_eq!(target.disconnect(), Err(Error::Windows(ERROR_OPEN_FILES)));
    target
        .disconnect_with(DisconnectOptions::new().force(true))
        .unwrap();
    drop(file);
    assert!(!drive_exists(DriveLetter::U));
    // Clean up the file via a fresh connection.
    let target = self::target(Some(DriveLetter::U));
    target.connect().unwrap();
    let _ = std::fs::remove_file(r"U:\sambrs-force-disconnect.txt");
    target.disconnect().unwrap();
}

// ── RAII guard ──────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn guard_leak_keeps_the_connection() {
    let target = target(Some(DriveLetter::V));
    target
        .connect_guarded(ConnectOptions::new())
        .unwrap()
        .leak();
    assert!(drive_exists(DriveLetter::V));
    target.disconnect().unwrap();
}

// The ownership property behind the guard design: a guard cancels only the
// device it owns, so dropping it must not tear down an independent deviceless
// connection to the same resource.
#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn guard_drop_leaves_other_connections_alone() {
    let deviceless = target(None);
    deviceless.connect().unwrap();
    let mounted = target(Some(DriveLetter::V));
    {
        let _guard = mounted.connect_guarded(ConnectOptions::new()).unwrap();
        assert!(drive_exists(DriveLetter::V));
    }
    assert!(!drive_exists(DriveLetter::V));
    // The deviceless connection must still be alive; disconnecting it now
    // fails with ERROR_NOT_CONNECTED if the guard's drop tore it down.
    deviceless.disconnect().unwrap();
}

// ── auto-assigned drive letter ──────────────────────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn connect_auto_assigns_a_device() {
    let target = target(None);
    let access_name = target.connect_auto(ConnectOptions::new()).unwrap();
    assert!(
        access_name.ends_with(':'),
        "expected a device name, got {access_name:?}"
    );
    assert!(std::path::Path::new(&format!(r"{access_name}\")).is_dir());
    cancel_connection(&access_name, DisconnectOptions::new()).unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn connect_auto_guarded_owns_the_assigned_device() {
    let target = target(None);
    let device;
    {
        let guard = target.connect_auto_guarded(ConnectOptions::new()).unwrap();
        device = guard.device().to_string();
        assert!(
            device.ends_with(':'),
            "expected a device name, got {device:?}"
        );
        assert!(std::path::Path::new(&format!(r"{device}\")).is_dir());
    }
    assert!(!std::path::Path::new(&format!(r"{device}\")).is_dir());
}

// ── query ───────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn get_connection_returns_the_remote_name() {
    let target = target(Some(DriveLetter::W));
    target.connect().unwrap();
    let remote = query::get_connection("W:").unwrap();
    assert!(
        remote.eq_ignore_ascii_case(&required_env(SHARE)),
        "{remote} != {}",
        required_env(SHARE)
    );
    target.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn get_user_returns_a_user() {
    let target = target(Some(DriveLetter::W));
    target.connect().unwrap();
    let user = query::get_user(Some("W:")).unwrap();
    assert!(!user.is_empty());
    target.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn get_universal_name_resolves_a_mounted_path() {
    let target = target(Some(DriveLetter::W));
    target.connect().unwrap();
    let unc = query::get_universal_name(r"W:\").unwrap();
    assert!(
        unc.to_ascii_lowercase()
            .starts_with(&required_env(SHARE).to_ascii_lowercase()),
        "{unc} does not start with {}",
        required_env(SHARE)
    );
    target.disconnect().unwrap();
}

// ── enumerate ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn enumerate_connections_contains_the_share() {
    let target = target(Some(DriveLetter::X));
    target.connect().unwrap();
    let found = enumerate::connections()
        .unwrap()
        .filter_map(Result::ok)
        .any(|r| {
            r.remote_name
                .is_some_and(|n| n.eq_ignore_ascii_case(&required_env(SHARE)))
        });
    target.disconnect().unwrap();
    assert!(found, "active connection to the test share not enumerated");
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn enumerate_server_shares_contains_the_share() {
    // \\server\share -> \\server
    let full = required_env(SHARE);
    let server = full.trim_start_matches('\\').split('\\').next().unwrap();
    let server_root = format!(r"\\{server}");
    // Authenticate first: servers may refuse anonymous enumeration.
    let target = target(None);
    target.connect().unwrap();
    let found = enumerate::server_shares(&server_root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|r| r.remote_name.is_some_and(|n| n.eq_ignore_ascii_case(&full)));
    target.disconnect().unwrap();
    assert!(found, "test share not found in {server_root}'s share list");
}

// ── server administration (local machine only) ──────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn server_shares_lists_the_test_share() {
    if !local_admin() {
        eprintln!("skipped: SAMBRS_TEST_LOCAL != 1");
        return;
    }
    let leaf = required_env(SHARE).rsplit('\\').next().unwrap().to_string();
    let all = server::shares(None).unwrap();
    assert!(
        all.iter().any(|s| s.name.eq_ignore_ascii_case(&leaf)),
        "share {leaf} not in {all:?}"
    );
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn server_add_get_delete_share_roundtrip() {
    if !local_admin() {
        eprintln!("skipped: SAMBRS_TEST_LOCAL != 1");
        return;
    }
    let dir = std::env::temp_dir().join("sambrs-roundtrip-share");
    std::fs::create_dir_all(&dir).unwrap();
    let name = format!("sambrs-tmp-{}", std::process::id());

    server::add_share(
        None,
        &server::NewShare::disk(&name, dir.to_str().unwrap()).remark("sambrs test share"),
    )
    .unwrap();

    let info = server::share_info(None, &name).unwrap();
    assert_eq!(info.name.to_ascii_lowercase(), name.to_ascii_lowercase());
    assert_eq!(info.share_type.kind, server::ShareKind::Disk);
    assert_eq!(info.remark.as_deref(), Some("sambrs test share"));

    // Adding the same name again must fail cleanly.
    let dup = server::add_share(None, &server::NewShare::disk(&name, dir.to_str().unwrap()));
    assert_eq!(dup, Err(Error::Windows(NERR_DUPLICATE_SHARE)));

    server::delete_share(None, &name).unwrap();
    assert_eq!(
        server::share_info(None, &name),
        Err(Error::Windows(NERR_NET_NAME_NOT_FOUND))
    );
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn server_sessions_and_connections_are_listable() {
    if !local_admin() {
        eprintln!("skipped: SAMBRS_TEST_LOCAL != 1");
        return;
    }
    let leaf = required_env(SHARE).rsplit('\\').next().unwrap().to_string();
    let target = target(None);
    target.connect().unwrap();

    // Establishing the connection above means at least one session and one
    // connection must be visible.
    let sessions = server::sessions(None, None, None).unwrap();
    assert!(!sessions.is_empty(), "no SMB sessions listed");

    let connections = server::connections(None, &leaf).unwrap();
    assert!(!connections.is_empty(), "no connections to {leaf} listed");

    target.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn server_open_files_are_listable_and_closable() {
    if !local_admin() {
        eprintln!("skipped: SAMBRS_TEST_LOCAL != 1");
        return;
    }
    let target = target(Some(DriveLetter::Y));
    target.connect().unwrap();
    let path = r"Y:\sambrs-open-file.txt";
    let file = std::fs::File::create(path).unwrap();

    let open = server::open_files(None, None, None).unwrap();
    let ours = open
        .iter()
        .find(|f| f.path.contains("sambrs-open-file"))
        .unwrap_or_else(|| panic!("our open file not listed by NetFileEnum; listed: {open:?}"));
    server::close_file(None, ours.id).unwrap();

    drop(file);
    let _ = std::fs::remove_file(path);
    target
        .disconnect_with(DisconnectOptions::new().force(true))
        .unwrap();
}
