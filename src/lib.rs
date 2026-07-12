#![cfg(windows)]
#![warn(clippy::pedantic)]
#![doc = include_str!("../README.md")]

mod error;
mod options;
mod strings;
mod target;
mod trace;

pub mod enumerate;
pub mod query;
pub mod server;

pub use error::{Error, Result};
pub use options::{ConnectOptions, DisconnectOptions, DriveLetter, ResourceType};
pub use target::{Connection, SmbTarget, cancel_connection};
