# Changelog

## 0.2.0 (unreleased)

A ground-up rework: from "a tiny wrapper around two calls" to safe, flexible
bindings for the Windows SMB surface. **Breaking release** — see the
migration table in the README.

### Fixed

- **Unicode correctness**: all calls now use the wide (`W`) API variants with
  UTF-16 strings. 0.1 used the ANSI variants, which mangled non-ASCII share
  names, user names, and passwords (typically surfacing as spurious
  `LogonFailure`).
- `ERROR_EXTENDED_ERROR` no longer swallows the real error: the
  provider-specific code and message are fetched via `WNetGetLastErrorW` and
  carried in `Error::ExtendedError`.
- `disconnect`'s misleading `persist` parameter (which *removed* persistence)
  is now `DisconnectOptions::forget`.

### Added

- Authenticate as the logged-on user by omitting credentials (0.1 always
  passed non-null credentials, making SSO unreachable).
- `SmbShare::builder` with `credentials`, `username`, `password`, `mount_on`
  (type-safe `DriveLetter`), `local_device`, `resource_type` (disk/printer),
  and `provider`.
- `ConnectOptions` covering every documented `CONNECT_*` flag: `persist`,
  `update_recent`, `interactive`, `prompt`, `commandline`, `redirect`,
  `current_media`, `save_credentials`, `reset_credentials`,
  `require_integrity` (SMB signing), `require_privacy` (SMB encryption),
  `write_through` — plus `raw_flags` and `SmbShare::connect_raw` as escape
  hatches.
- `SmbShare::connect_auto`: let Windows pick a free drive letter
  (`WNetUseConnectionW`), returning the assigned name.
- `SmbShare::connect_guarded` / `connect_auto_guarded`: RAII `Connection`
  guard that disconnects on drop, with `leak()` and explicit `disconnect()`.
  A guard always owns a redirected local device and cancels exactly that
  device, so dropping it can never tear down a connection it did not create.
  Deviceless shares are rejected with `InvalidParameter` (Windows does not
  reference-count deviceless connections, so no guard can own one); see the
  `Connection` docs.
- `cancel_connection`: disconnect any connection by device or remote name.
- `query` module: `get_connection`, `get_user`, `get_universal_name`.
- `enumerate` module: iterate active connections, remembered connections, and
  the shares a server exposes (`WNetOpenEnumW` family), plus `resources_raw`.
- `server` module (netapi32): `shares`, `share_info`, `add_share`,
  `delete_share`, `sessions`, `delete_session`, `open_files`, `close_file`,
  `connections` — with automatic fallback to lower information levels when
  not administrator. `delete_session` requires a non-empty client and/or
  user filter (`InvalidParameter` otherwise — netapi32 treats an empty
  string as no filter); ending every session on a server is the separate,
  explicit `delete_all_sessions`.
- `Error::raw_os_error` and `From<Error> for std::io::Error`. Converting an
  `ExtendedError` keeps the error as the `io::Error` payload, so the
  provider's own code, description, and name survive instead of collapsing
  into the generic `ERROR_EXTENDED_ERROR` (1208) message.
- Cargo features: `tracing` (now optional!) and `zeroize` (wipe password
  buffers on drop).
- CI: full integration suite against a real `\\localhost` share on Windows
  runners; clippy/rustfmt/rustdoc gates; MSRV (1.85) build check.
- The `server` enumeration loop fails with `Error::Other(ERROR_MORE_DATA)`
  instead of spinning forever when a malformed server keeps reporting
  `ERROR_MORE_DATA` without delivering entries or terminating.

### Changed

- `Error` is `#[non_exhaustive]` and gained variants for the query/server
  APIs; `Error::CStringConversion` is now `Error::InteriorNul`.
- `windows-sys` 0.52 → 0.60, `thiserror` 1 → 2; dependencies are declared
  Windows-only, and the crate compiles to nothing on other targets.
- docs.rs builds Windows targets; MSRV pinned at 1.85.

## 0.1.2

- Description and examples; edition 2024; initial `WNetAddConnection2A` /
  `WNetCancelConnection2A` wrapper with typed errors.
