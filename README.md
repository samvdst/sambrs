# sambrs

[![crates.io](https://img.shields.io/crates/v/sambrs.svg)](https://crates.io/crates/sambrs)
[![docs.rs](https://img.shields.io/docsrs/sambrs)](https://docs.rs/sambrs)

Safe and flexible Rust bindings for Windows SMB share operations.

Sam -> SMB -> Rust -> Samba is taken!? -> sambrs

The crate wraps three areas of the Windows API, aiming to expose the full
flexibility of the underlying calls behind a safe, unopinionated interface:

- **Connecting** — `WNetAddConnection2W`, `WNetUseConnectionW`, and
  `WNetCancelConnection2W`: connect to a share deviceless, mounted on a drive
  letter of your choice, or on a letter Windows picks. Every documented
  `CONNECT_*` flag is available through `ConnectOptions`, including
  per-connection SMB signing (`require_integrity`) and encryption
  (`require_privacy`) enforcement, plus a raw-flags escape hatch. An optional
  RAII `Connection` guard disconnects on drop.
- **Querying and enumerating** — `WNetGetConnectionW`, `WNetGetUserW`,
  `WNetGetUniversalNameW`, and the `WNetOpenEnumW` family: inspect existing
  connections, list remembered ones, and enumerate the shares a server
  exposes, as a plain Rust `Iterator`.
- **Administering** — the netapi32 `NetShare*`, `NetSession*`, `NetFile*`,
  and `NetConnectionEnum` functions: create and delete shares, and manage
  sessions and open files, on the local machine or a remote server.

All strings cross the FFI boundary as UTF-16 (the `W` API variants), so share
names, user names, and passwords with any Unicode content work correctly.

## Installation

```toml
[dependencies]
sambrs = "0.2"
```

## Usage

Instantiate an `SmbShare` and establish a connection. Once connected (mounted
or deviceless), `std::fs` works on it like on any local path:

```rust
use sambrs::{ConnectOptions, DriveLetter, SmbShare};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let share = SmbShare::builder(r"\\server.local\share")
        .credentials(r"LOGONDOMAIN\user", "pass")
        .mount_on(DriveLetter::D)
        .build()?;

    share.connect_with(
        ConnectOptions::new()
            .persist(true)          // restore the mapping at logon
            .require_privacy(true), // enforce SMB encryption
    )?;

    // use std::fs as if D:\ was a local directory
    println!("{}", std::fs::metadata(r"D:\")?.is_dir());

    share.disconnect()?;
    Ok(())
}
```

Without credentials, the connection authenticates as the logged-on user:

```rust
let share = sambrs::SmbShare::new(r"\\server.local\share");
share.connect()?;
```

Enumerate what a server offers, or administer shares (see the
[`enumerate`](https://docs.rs/sambrs/latest/sambrs/enumerate/) and
[`server`](https://docs.rs/sambrs/latest/sambrs/server/) module docs for the
full API):

```rust
for resource in sambrs::enumerate::server_shares(r"\\fileserver")? {
    println!("{:?}", resource?.remote_name);
}

sambrs::server::add_share(
    None, // local machine
    &sambrs::server::NewShare::disk("scratch", r"C:\scratch"),
)?;
```

## Cargo features

Both features are off by default — no forced dependencies:

- `tracing` — emit [`tracing`](https://docs.rs/tracing) debug/trace events for
  every Windows API call.
- `zeroize` — wipe password buffers (the stored `String` and the transient
  UTF-16 copies) when they are dropped.

## Platform support

Windows only. On other targets the crate compiles to nothing, so it is safe
to keep in cross-platform dependency trees; gate your usage behind
`#[cfg(windows)]`. MSRV is 1.85 (edition 2024).

## Testing

The integration tests need a real share and are ignored by default. Point
them at one and include them explicitly:

```text
SAMBRS_TEST_SHARE=\\server\share
SAMBRS_TEST_USERNAME=DOMAIN\user
SAMBRS_TEST_PASSWORD=...
SAMBRS_TEST_LOCAL=1   # only if the share is local; enables the server:: tests

cargo test -- --include-ignored
```

CI provisions a local user plus `\\localhost\sambrs-test` on a Windows runner
and runs the whole suite against it on every push.

## Migrating from 0.1

`0.2` is a rework of the whole API; the most important changes:

| 0.1 | 0.2 |
| --- | --- |
| `SmbShare::new(share, user, pass, Some('d'))` | `SmbShare::builder(share).credentials(user, pass).mount_on(DriveLetter::D).build()?` |
| `share.connect(persist, interactive)` | `share.connect_with(ConnectOptions::new().persist(persist).interactive(interactive))` |
| `share.disconnect(persist, force)` | `share.disconnect_with(DisconnectOptions::new().forget(persist).force(force))` — note the rename: the old `persist: true` *removed* the persistence |
| `Error::CStringConversion` | `Error::InteriorNul` |

Under the hood, 0.1 used the ANSI (`A`) API variants, which silently mangled
non-ASCII share names, user names, and passwords; 0.2 uses the wide (`W`)
variants throughout. Empty-string credentials are no longer the way to say
"use my logon credentials" — omit them instead (empty string means a real
empty password now, matching the Windows API).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE)
file for more details.

## Special Thanks

Special thanks to [Christian Visintin](https://github.com/veeso) for his
informative [blog
post](https://blog.veeso.dev/blog/en/how-to-access-an-smb-share-with-rust-on-windows/)
on accessing SMB shares with Rust on Windows. If you need a fully-featured
remote file access solution that works across multiple protocols, you should
definitely check out his project
[remotefs](https://github.com/veeso/remotefs-rs).
