#![cfg(windows)]
#![warn(clippy::pedantic)]
#![doc = include_str!("../README.md")]

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
pub use share::{Connection, SmbShare, cancel_connection};
