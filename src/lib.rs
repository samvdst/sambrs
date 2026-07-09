#![cfg(windows)]
#![warn(clippy::pedantic)]

//! Safe and flexible bindings for Windows SMB share operations.
//!
//! Sam -> SMB -> Rust -> Samba is taken!? -> sambrs
//!
//! The crate wraps three areas of the Windows API, aiming to expose the full
//! flexibility of the underlying calls behind a safe interface:
//!
//! - **Connecting** ([`SmbShare`]): `WNetAddConnection2W`,
//!   `WNetUseConnectionW`, and `WNetCancelConnection2W` — connect to a share
//!   (deviceless, mounted on a drive letter of your choice, or a letter
//!   Windows picks), with every documented `CONNECT_*` flag available through
//!   [`ConnectOptions`], including per-connection SMB signing/encryption
//!   enforcement. An optional RAII [`Connection`] guard disconnects on drop.
//! - **Querying and enumerating** ([`query`], [`enumerate`]):
//!   `WNetGetConnectionW`, `WNetGetUserW`, `WNetGetUniversalNameW`, and the
//!   `WNetOpenEnumW` family — inspect existing connections, list remembered
//!   ones, and enumerate the shares a server exposes.
//! - **Administering** ([`server`]): the netapi32 `NetShare*`, `NetSession*`,
//!   `NetFile*`, and `NetConnectionEnum` functions — create and delete
//!   shares, and manage sessions and open files, locally or on a remote
//!   server.
//!
//! All strings cross the FFI boundary as UTF-16 (the `W` API variants), so
//! share names, user names, and passwords with any Unicode content work
//! correctly.
//!
//! # Connecting to a share
//!
//! Instantiate an [`SmbShare`] and establish a connection. Once connected
//! (mounted or deviceless), `std::fs` works on it like on any local path:
//!
//! ```no_run
//! use sambrs::{ConnectOptions, DriveLetter, SmbShare};
//!
//! let share = SmbShare::builder(r"\\server.local\share")
//!     .credentials(r"LOGONDOMAIN\user", "pass")
//!     .mount_on(DriveLetter::D)
//!     .build()?;
//!
//! share.connect_with(
//!     ConnectOptions::new()
//!         .persist(true)          // restore the mapping at logon
//!         .require_privacy(true), // enforce SMB encryption
//! )?;
//!
//! // use std::fs as if D:\ was a local directory
//! println!("{}", std::fs::metadata(r"D:\")?.is_dir());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Without credentials, the connection authenticates as the logged-on user;
//! [`SmbShare::new`] is the shortest path to that:
//!
//! ```no_run
//! use sambrs::SmbShare;
//!
//! let share = SmbShare::new(r"\\server.local\share");
//! share.connect()?;
//! # Ok::<(), sambrs::Error>(())
//! ```
//!
//! # Cargo features
//!
//! - `tracing` — emit [`tracing`](https://docs.rs/tracing) debug/trace events
//!   for every Windows API call.
//! - `zeroize` — wipe password buffers (the stored `String` and the transient
//!   UTF-16 copies) when they are dropped.
//!
//! # Platform support
//!
//! This crate is Windows-only; on other targets it compiles to nothing. Gate
//! usage behind `#[cfg(windows)]` in cross-platform projects.

mod error;
mod options;
mod share;
mod strings;
mod trace;

pub mod enumerate;
pub mod query;
pub mod server;

pub use error::{Error, Result};
pub use options::{ConnectOptions, DisconnectOptions, DriveLetter, ResourceType};
pub use share::{Connection, SmbShare, SmbShareBuilder, cancel_connection};
