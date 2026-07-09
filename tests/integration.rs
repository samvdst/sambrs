//! Integration tests against a real SMB share.
//!
//! These tests are `#[ignore]`d by default because they need a live share.
//! Provide one via environment variables and run them explicitly:
//!
//! ```text
//! SAMBRS_TEST_SHARE=\\server\share
//! SAMBRS_TEST_USERNAME=DOMAIN\user
//! SAMBRS_TEST_PASSWORD=...
//! SAMBRS_TEST_LOCAL=1   # only if the share is on THIS machine and the test
//!                       # process can administer it (enables server:: tests)
//! RUST_TEST_THREADS=1   # the tests mount real drive letters and enumerate
//!                       # live connections; they must not run concurrently
//!
//! cargo test -- --include-ignored
//! ```
//!
//! CI provisions `\\localhost\sambrs-test` with a dedicated local user and
//! runs the full suite; see `.github/workflows/ci.yml`. Drive letters S-Z are
//! used by these tests and must be free. In a git checkout,
//! `.cargo/config.toml` sets `RUST_TEST_THREADS=1` for you; that file is not
//! part of the packaged crate, so set it yourself when running from a
//! published copy.
#![cfg(windows)]

use sambrs::{
    ConnectOptions, DisconnectOptions, DriveLetter, Error, SmbShare, cancel_connection, enumerate,
    query, server,
};

fn share_name() -> String {
    std::env::var("SAMBRS_TEST_SHARE").expect("SAMBRS_TEST_SHARE must be set")
}

fn username() -> String {
    std::env::var("SAMBRS_TEST_USERNAME").expect("SAMBRS_TEST_USERNAME must be set")
}

fn password() -> String {
    std::env::var("SAMBRS_TEST_PASSWORD").expect("SAMBRS_TEST_PASSWORD must be set")
}

/// `server::*` tests only make sense against the local machine, with rights
/// to administer it.
fn local_admin() -> bool {
    std::env::var("SAMBRS_TEST_LOCAL").is_ok_and(|v| v == "1")
}

fn share(mount: Option<DriveLetter>) -> SmbShare {
    let mut builder = SmbShare::builder(share_name()).credentials(username(), password());
    if let Some(letter) = mount {
        builder = builder.mount_on(letter);
    }
    builder.build().expect("test credentials contain no NUL")
}

fn drive_exists(letter: DriveLetter) -> bool {
    std::path::Path::new(&format!(r"{letter}\")).is_dir()
}

// ── connect / disconnect ────────────────────────────────────────────────────

// Lovely Windows sometimes returns `LogonFailure` and sometimes
// `InvalidPassword` for a bad password.
#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn wrong_password_fails_without_prompting() {
    let share = SmbShare::builder(share_name())
        .credentials(username(), "definitely-the-wrong-password-1")
        .build()
        .unwrap();
    let result = share.connect();
    assert!(
        matches!(
            result,
            Err(Error::InvalidPassword | Error::LogonFailure | Error::AccessDenied)
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn nonexistent_share_fails() {
    let share = SmbShare::builder(r"\\thisisnotashare.local\Share-Name")
        .credentials(username(), password())
        .build()
        .unwrap();
    let result = share.connect();
    // The documented WNetAddConnection2W error list is not exhaustive
    // ("Other: use FormatMessage"): unresolvable hosts commonly surface as
    // ERROR_BAD_NETPATH (53) or ERROR_SEM_TIMEOUT (121), which have no
    // dedicated variant.
    assert!(
        matches!(
            result,
            Err(Error::BadNetName
                | Error::NoNetOrBadPath
                | Error::NoNetwork
                | Error::Other(53 | 121))
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn deviceless_connect_and_reconnect_works() {
    let share = share(None);
    share.connect().unwrap();
    // Reconnecting a deviceless connection is fine.
    share.connect().unwrap();
    assert!(std::path::Path::new(&share_name()).is_dir());
    share.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn mount_on_drive_letter_works_and_does_not_persist() {
    let share = share(Some(DriveLetter::S));
    share.connect().unwrap();
    assert!(drive_exists(DriveLetter::S));
    share.disconnect().unwrap();
    assert!(!drive_exists(DriveLetter::S));
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn mounted_reconnect_fails_with_already_assigned() {
    let share = share(Some(DriveLetter::S));
    share.connect().unwrap();
    assert_eq!(share.connect(), Err(Error::AlreadyAssigned));
    share.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn two_letters_to_the_same_share_work() {
    let one = share(Some(DriveLetter::S));
    let two = share(Some(DriveLetter::T));
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
    let share = share(Some(DriveLetter::U));
    share.connect().unwrap();
    let file = std::fs::File::create(r"U:\sambrs-force-disconnect.txt").unwrap();
    // Non-forced disconnect must refuse while a file is open.
    assert_eq!(share.disconnect(), Err(Error::OpenFiles));
    share
        .disconnect_with(DisconnectOptions::new().force(true))
        .unwrap();
    drop(file);
    assert!(!drive_exists(DriveLetter::U));
    // Clean up the file via a fresh connection.
    let share = self::share(Some(DriveLetter::U));
    share.connect().unwrap();
    let _ = std::fs::remove_file(r"U:\sambrs-force-disconnect.txt");
    share.disconnect().unwrap();
}

// ── RAII guard ──────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn guard_disconnects_on_drop() {
    let share = share(Some(DriveLetter::V));
    {
        let _guard = share.connect_guarded(ConnectOptions::new()).unwrap();
        assert!(drive_exists(DriveLetter::V));
    }
    assert!(!drive_exists(DriveLetter::V));
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn guard_leak_keeps_the_connection() {
    let share = share(Some(DriveLetter::V));
    share.connect_guarded(ConnectOptions::new()).unwrap().leak();
    assert!(drive_exists(DriveLetter::V));
    share.disconnect().unwrap();
}

// ── auto-assigned drive letter ──────────────────────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn connect_auto_assigns_a_device() {
    let share = share(None);
    let access_name = share.connect_auto(ConnectOptions::new()).unwrap();
    assert!(
        access_name.ends_with(':'),
        "expected a device name, got {access_name:?}"
    );
    assert!(std::path::Path::new(&format!(r"{access_name}\")).is_dir());
    cancel_connection(&access_name, DisconnectOptions::new()).unwrap();
}

// ── query ───────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn get_connection_returns_the_remote_name() {
    let share = share(Some(DriveLetter::W));
    share.connect().unwrap();
    let remote = query::get_connection("W:").unwrap();
    assert!(
        remote.eq_ignore_ascii_case(&share_name()),
        "{remote} != {}",
        share_name()
    );
    share.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn get_user_returns_a_user() {
    let share = share(Some(DriveLetter::W));
    share.connect().unwrap();
    let user = query::get_user(Some("W:")).unwrap();
    assert!(!user.is_empty());
    share.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn get_universal_name_resolves_a_mounted_path() {
    let share = share(Some(DriveLetter::W));
    share.connect().unwrap();
    let unc = query::get_universal_name(r"W:\").unwrap();
    assert!(
        unc.to_ascii_lowercase()
            .starts_with(&share_name().to_ascii_lowercase()),
        "{unc} does not start with {}",
        share_name()
    );
    share.disconnect().unwrap();
}

// ── enumerate ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn enumerate_connections_contains_the_share() {
    let share = share(Some(DriveLetter::X));
    share.connect().unwrap();
    let found = enumerate::connections()
        .unwrap()
        .filter_map(Result::ok)
        .any(|r| {
            r.remote_name
                .is_some_and(|n| n.eq_ignore_ascii_case(&share_name()))
        });
    share.disconnect().unwrap();
    assert!(found, "active connection to the test share not enumerated");
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn enumerate_server_shares_contains_the_share() {
    // \\server\share -> \\server
    let full = share_name();
    let server_root = full
        .trim_start_matches('\\')
        .split('\\')
        .next()
        .map(|s| format!(r"\\{s}"))
        .unwrap();
    // Authenticate first: servers may refuse anonymous enumeration.
    let share = share(None);
    share.connect().unwrap();
    let found = enumerate::server_shares(&server_root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|r| r.remote_name.is_some_and(|n| n.eq_ignore_ascii_case(&full)));
    share.disconnect().unwrap();
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
    let leaf = share_name().rsplit('\\').next().unwrap().to_string();
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
    assert_eq!(dup, Err(Error::DuplicateShare));

    server::delete_share(None, &name).unwrap();
    assert_eq!(server::share_info(None, &name), Err(Error::NetNameNotFound));
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn server_sessions_and_connections_are_listable() {
    if !local_admin() {
        eprintln!("skipped: SAMBRS_TEST_LOCAL != 1");
        return;
    }
    let leaf = share_name().rsplit('\\').next().unwrap().to_string();
    let share = share(None);
    share.connect().unwrap();

    // Establishing the connection above means at least one session and one
    // connection must be visible.
    let sessions = server::sessions(None, None, None).unwrap();
    assert!(!sessions.is_empty(), "no SMB sessions listed");

    let connections = server::connections(None, &leaf).unwrap();
    assert!(!connections.is_empty(), "no connections to {leaf} listed");

    share.disconnect().unwrap();
}

#[test]
#[ignore = "requires a live SMB share; set SAMBRS_TEST_* and run with --include-ignored"]
fn server_open_files_are_listable_and_closable() {
    if !local_admin() {
        eprintln!("skipped: SAMBRS_TEST_LOCAL != 1");
        return;
    }
    let share = share(Some(DriveLetter::Y));
    share.connect().unwrap();
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
    share
        .disconnect_with(DisconnectOptions::new().force(true))
        .unwrap();
}
