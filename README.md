# Sambrs

A tiny ergonomic wrapper around `WNetAddConnection2A` and
`WNetCancelConnection2A`. The goal is to offer an easy to use interface to
connect to SMB network shares on Windows.

Sam -> SMB -> Rust -> Samba is taken!? -> sambrs

## Features

- Simple and ergonomic interface to connect to SMB network shares.
- Support for specifying a local Windows mount point.
- Options to persist connections across user login sessions.
- Interactive mode for password prompts.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
sambrs = "0.1"
```

## Usage

Instantiate an `SmbShare` with an optional local Windows mount point and establish
a connection.

When calling the connect method, you have the option to persist the connection
across user login sessions and to enable interactive mode. Interactive mode will
block until the user either provides a correct password or cancels, resulting in
a `Canceled` error.

```rust
use sambrs::SmbShare;

fn main() {
    let share = SmbShare::new(r"\\server\share", "user", "pass", Some('D'));

    match share.connect(false, false) {
        Ok(()) => println!("Connected successfully!"),
        Err(e) => eprintln!("Failed to connect: {}", e),
    }

    // use std::fs as if D:\ was a local directory
    dbg!(std::fs::metadata(r"D:\").unwrap().is_dir());
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file
for more details.

## Special Thanks

Special thanks to [Christian Visintin](https://github.com/veeso) for his
informative [blog
post](https://blog.veeso.dev/blog/en/how-to-access-an-smb-share-with-rust-on-windows/)
on accessing SMB shares with Rust on Windows. If you need a fully-featured
remote file access solution that works across multiple protocols, you should
definitely check out his project
[remotefs](https://github.com/veeso/remotefs-rs).
