# Changelog

## 0.2.0 (unreleased)

A breaking rework into a safe, opinionated Windows client for existing SMB
disk shares.

### Added

- `SmbTarget` connections using the logged-on identity, paired credentials, or
  partial username/password credentials.
- Deviceless, explicit-drive, and automatically assigned connections.
- Persistent drive mappings and explicit `force`/`forget` disconnect options.
- `ConnectOptions::require_integrity` for SMB signing and
  `require_privacy` for SMB encryption.
- RAII `Connection` guards for temporary drive mappings, with explicit
  disconnect and leak operations.
- Focused queries for mapped-drive targets, connection users, and universal
  UNC paths.
- Disk-focused enumeration of active connections, remembered mappings, and a
  server's existing shares.
- Provider-specific extended errors from `WNetGetLastErrorW`.
- Unconditional detailed `tracing` events. Usernames and targets are logged;
  passwords never are.
- Unconditional zeroization of stored and transient UTF-16 password buffers.

### Changed

- All Windows calls use Unicode (`W`) APIs.
- Windows statuses are preserved as `Error::Windows(code)` while
  crate-originated validation and provider-specific errors remain typed.
- Persistence requires a drive mapping; guarded connections cannot persist;
  forgetting requires a drive mapping. Invalid combinations fail before a
  Windows call.
- Deviceless connections are kept out of Windows' recent-connections list.
- Dependencies and API are Windows-only; cross-platform consumers must gate
  the dependency and usage with `cfg(windows)`.
- `windows-sys` 0.52 → 0.60; MSRV is Rust 1.85.

### Removed

- Server administration and share creation.
- Printer resources, arbitrary local devices, and custom provider selection.
- Raw WNet enumeration and metadata.
- Interactive authentication, connection-wide write-through, and other raw
  `CONNECT_*` controls outside persistence, signing, and encryption.
- `Error::raw_os_error` and conversion into `std::io::Error`.

## 0.1.2

- Description and examples; edition 2024; initial `WNetAddConnection2A` /
  `WNetCancelConnection2A` wrapper with typed errors.
