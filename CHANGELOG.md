# Changelog

## 0.2.2 (unreleased)

### Changed

- Logging is structured. Every public operation opens a `debug` span named
  after the function, with its inputs (`remote`, `user`, `local`, `flags`,
  `name`, `drive`, `path`, `server`, and so on) as fields, so every event
  inside it carries that context. Usernames therefore appear at debug level;
  passwords are still never logged.
- Every Windows call emits one `debug` event, `"WNet call returned"`, with
  `operation` and the raw `status` as fields, so `status != 0` finds every
  failed call. Flags and results are integers rather than hex strings.
- Enumeration logs each entry at `trace` and a single `debug` summary with the
  number of `entries` when it finishes.
- `connect_auto` logs the access name Windows assigned.
- A `Connection` guard that fails to disconnect on drop now logs a `warn`
  event, since it cannot return the error. A drive that was already
  disconnected stays at `debug`.
- `WNetGetUserW` no longer logs the resolved user name; it is the return value.
- The README documents the span and field names.

## 0.2.1 (2026-11-09)

### Added

- `Error::code()` returns the Windows status code of an `Error::Windows`.
- `Error::is_credential_rejected()` identifies statuses where Windows rejected
  the credential itself: invalid password, logon failure, account restriction,
  expired password, disabled account, expired account, password must change,
  or locked-out account. Callers should not retry these, because each retry
  counts as another failed logon toward account lockout.

## 0.2.0 (2026-07-15)

A breaking rework into a safe, opinionated Windows client for existing SMB
disk shares.

### Added

- Authentication using the logged-on identity, paired credentials, or a
  username or password on its own.
- Typed drive letters and automatically assigned drive mappings.
- `ConnectOptions` for persistence, SMB signing, and SMB encryption, plus
  `DisconnectOptions` for forced disconnection and forgetting mappings.
- RAII `Connection` guards for temporary drive mappings, with explicit
  disconnection when errors need handling.
- Focused queries for mapped-drive targets, connection users, and universal
  UNC paths.
- Disk-focused enumeration of active connections, remembered mappings, and a
  server's existing shares.
- Provider-specific extended errors from `WNetGetLastErrorW`.
- Detailed `tracing` events and zeroization of stored passwords and their
  transient UTF-16 buffers. Usernames and targets may be logged; passwords
  never are.

### Changed

- `SmbShare` and its boolean arguments are replaced by the fluent `SmbTarget`,
  `DriveLetter`, `ConnectOptions`, and `DisconnectOptions` API.
- All Windows calls use Unicode (`W`) APIs.
- Windows statuses are preserved as `Error::Windows(code)` in a non-exhaustive
  error enum; crate validation and provider-specific errors remain typed.
- Persistence requires a drive mapping; guarded connections cannot persist;
  forgetting requires a drive mapping. Invalid combinations fail before a
  Windows call.
- Deviceless connections are kept out of Windows' recent-connections list.
- The crate API and dependencies are Windows-only; cross-platform consumers
  must gate the dependency and usage with `cfg(windows)`.
- `windows-sys` 0.52 → 0.61.

### Removed

- Interactive authentication and password prompts.
- Individual variants for Windows status codes, superseded by
  `Error::Windows(code)`.

## 0.1.2 (2024-07-29)

- Description and examples; edition 2024; initial `WNetAddConnection2A` /
  `WNetCancelConnection2A` wrapper with typed errors.
