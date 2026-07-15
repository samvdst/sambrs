# Changelog

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

## 0.1.2

- Description and examples; edition 2024; initial `WNetAddConnection2A` /
  `WNetCancelConnection2A` wrapper with typed errors.
