# sambrs

[![crates.io](https://img.shields.io/crates/v/sambrs.svg)](https://crates.io/crates/sambrs)
[![docs.rs](https://img.shields.io/docsrs/sambrs)](https://docs.rs/sambrs)

Safe, opinionated Windows SMB client operations for existing disk shares.

Sam -> SMB -> Rust -> Samba is taken!? -> sambrs

`sambrs` keeps unsafe Windows FFI, UTF-16 conversion, buffer ownership,
validation, cleanup, and `WNet` quirks out of applications. It supports:

- deviceless, explicit-drive, and automatically assigned connections;
- temporary and persistent drive mappings;
- default, paired, and partial credentials;
- SMB signing and encryption requirements;
- guarded temporary mappings that disconnect on drop;
- querying mapped drives, connection users, and universal UNC paths;
- enumerating active connections, remembered mappings, and a server's disk shares.

It deliberately does not create or administer shares, handle printers, expose
raw `WNet` controls, or transfer files. See the [boundary
ADR](https://github.com/samvdst/sambrs/blob/main/docs/adr/0001-opinionated-smb-client-boundary.md).

Passwords and their temporary UTF-16 buffers are wiped on drop. Operations,
targets, usernames, options, and raw Windows statuses are emitted through
`tracing`; passwords are never logged.

## Installation

The crate is Windows-only, so cross-platform applications should make the
dependency conditional:

```toml
[target.'cfg(windows)'.dependencies]
sambrs = "0.2"
```

MSRV is Rust 1.85 (edition 2024).

## Usage

Configure an `SmbTarget` and establish a connection. Once connected,
`std::fs` works on the UNC path or mapped drive like any other filesystem
path:

```no_run
use sambrs::{ConnectOptions, DisconnectOptions, DriveLetter, SmbTarget};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = SmbTarget::new(r"\\server.local\share")
        .credentials(r"LOGONDOMAIN\user", "pass")
        .mount_on(DriveLetter::D);

    target.connect_with(
        ConnectOptions::new()
            .persist(true)
            .require_privacy(true),
    )?;

    println!("{}", std::fs::metadata(r"D:\")?.is_dir());

    target.disconnect_with(DisconnectOptions::new().forget(true))?;
    Ok(())
}
```

Persistence requires an explicit or automatically assigned drive. A
deviceless connection uses the UNC path directly and is never remembered:

```no_run
# fn main() -> Result<(), sambrs::Error> {
let target = sambrs::SmbTarget::new(r"\\server.local\share");
target.connect()?;
# Ok(())
# }
```

Use a guard for an automatically cleaned-up temporary mapping:

```no_run
# fn main() -> Result<(), sambrs::Error> {
let target = sambrs::SmbTarget::new(r"\\server.local\share");
let connection = target.connect_auto_guarded(sambrs::ConnectOptions::new())?;
println!("mapped on {}", connection.device());
# Ok(())
# }
```

Guarded connections cannot be persistent because persistence outlives the
guard.

Inspect existing resources through the focused query and enumeration modules:

```no_run
# fn main() -> Result<(), sambrs::Error> {
for resource in sambrs::enumerate::server_shares(r"\\fileserver")? {
    println!("{:?}", resource?.remote_name);
}

let remote = sambrs::query::get_connection("D:")?;
let user = sambrs::query::get_user(Some("D:"))?;
let unc = sambrs::query::get_universal_name(r"D:\folder\file.txt")?;
# Ok(())
# }
```

## Testing

The integration tests need a real share and are ignored by default. Point
them at one and include them explicitly:

```text
SAMBRS_TEST_SHARE=\\server\share
SAMBRS_TEST_USERNAME=DOMAIN\user
SAMBRS_TEST_PASSWORD=...

cargo test -- --include-ignored --test-threads=1
```

The tests mount real drive letters and must run single-threaded.

## Migrating from 0.1

`0.2` is a breaking rework of the API:

| 0.1 | 0.2 |
| --- | --- |
| `SmbShare::new(share, user, pass, Some('d'))` | `SmbTarget::new(share).credentials(user, pass).mount_on(DriveLetter::D)` |
| `share.connect(persist, interactive)` | `target.connect_with(ConnectOptions::new().persist(persist))` |
| `share.disconnect(persist, force)` | `target.disconnect_with(DisconnectOptions::new().forget(persist).force(force))` |
| `Error::CStringConversion` | `Error::InteriorNul` |

The old `persist: true` disconnect argument removed persistence, hence the
`forget` rename. Version 0.2 uses Unicode Windows APIs throughout and omitting
credentials now means "use the logged-on Windows identity."

## License

This project is licensed under the MIT License. See the
[license](https://github.com/samvdst/sambrs/blob/main/LICENSE).

## Special thanks

Thanks to [Christian Visintin](https://github.com/veeso) for his [article on
accessing SMB shares with Rust on
Windows](https://blog.veeso.dev/blog/en/how-to-access-an-smb-share-with-rust-on-windows/).
For a fully featured, cross-platform remote-file solution, see
[remotefs](https://github.com/veeso/remotefs-rs).
