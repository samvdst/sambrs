# Sambrs

A tiny wrapper around `WNetAddConnection2A` and `WNetCancelConnection2A`. The goal is to offer an ergonomic interface to connect to an SMB network share on Windows.

Sam -> SMB -> Rust -> Samba is taken!? == sambrs

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

Create an `SmbShare` with an optional local Windows mount point and connect to it.

You can specify if you want to persist the connection across user login sessions and if you want to connect interactively. Interactive mode will prompt the user for a password in case the password is wrong or empty.

```rust
use sambrs::SmbShare;

fn main() {
    let share = SmbShare::new(r"\\server\share", "user", "pass", Some('e'));
    match share.connect(false, false) {
        Ok(_) => println!("Connected successfully!"),
        Err(e) => eprintln!("Failed to connect: {}", e),
    }
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Special Thanks

Special thanks to [Christian Visintin](https://github.com/veeso) for his informative [blog post](https://blog.veeso.dev/blog/en/how-to-access-an-smb-share-with-rust-on-windows/) on accessing SMB shares with Rust on Windows. If you need a fully-featured remote file access solution that works across multiple protocols, you should definitely check out his project [remotefs](https://github.com/veeso/remotefs-rs).
