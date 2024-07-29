#![warn(clippy::pedantic)]

//! A tiny wrapper around `WNetAddConnection2A` and `WNetCancelConnection2A`. The goal is to offer an ergonomic interface to connect to an SMB network share on Windows.
//!
//! Sam -> SMB -> Rust -> Samba is taken!? == sambrs
//!
//! # How To
//!
//! Create an `SmbShare` with an optional local Windows mount point.
//!
//! Connect to the share and specify if you want to persist the connection across user login
//! session, and if you want to connect interactively. Interactive mode will prompt the user for a
//! password in case the password is wrong or empty.
//!
//! ```
//! let share = sambrs::SmbShare::new(r"\\server\share", "user", "pass", Some('D'));
//! match share.connect(false, false) {
//!     Ok(_) => println!("Connected successfully!"),
//!     Err(e) => eprintln!("Failed to connect: {}", e),
//! }
//! ```

mod error;

pub use error::{Error, Result};
use std::ffi::CString;
use tracing::{debug, error, trace};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_ASSIGNED, ERROR_BAD_DEVICE, ERROR_BAD_DEV_TYPE,
    ERROR_BAD_NET_NAME, ERROR_BAD_PROFILE, ERROR_BAD_PROVIDER, ERROR_BAD_USERNAME, ERROR_BUSY,
    ERROR_CANCELLED, ERROR_CANNOT_OPEN_PROFILE, ERROR_DEVICE_ALREADY_REMEMBERED,
    ERROR_DEVICE_IN_USE, ERROR_EXTENDED_ERROR, ERROR_INVALID_ADDRESS, ERROR_INVALID_PARAMETER,
    ERROR_INVALID_PASSWORD, ERROR_LOGON_FAILURE, ERROR_NOT_CONNECTED, ERROR_NO_NETWORK,
    ERROR_NO_NET_OR_BAD_PATH, ERROR_OPEN_FILES, FALSE, NO_ERROR, TRUE,
};
use windows_sys::Win32::NetworkManagement::WNet;

pub struct SmbShare {
    share: String,
    username: String,
    password: String,
    mount_on: Option<char>,
}

impl SmbShare {
    /// Create an `SmbShare` representation to connect to.
    ///
    /// Optionally specify `mount_on` to map the SMB share to a local device. Otherwise it will be
    /// a deviceless connection. Case insensitive.
    ///
    /// # Example
    ///
    /// ```
    /// let share = sambrs::SmbShare::new(r"\\server.local\share", r"LOGONDOMAIN\user", "pass", None);
    /// ```
    pub fn new(
        share: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        mount_on: Option<char>,
    ) -> Self {
        Self {
            share: share.into(),
            username: username.into(),
            password: password.into(),
            mount_on,
        }
    }

    /// Connect to the SMB share. Connecting multiple times works fine in deviceless mode but fails
    /// with a local mount point.
    ///
    /// - `persist` will remember the connection and restore when the user logs off and on again. No-op
    ///   if `mount_on` is `None`
    /// - `interactive` will prompt the user for a password instead of failing with `Error::InvalidPassword`
    ///
    /// # Some excerpts from the [Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2a)
    ///
    /// `persist` (`CONNECT_UPDATE_PROFILE`): The network resource connection should be remembered. If this bit
    /// flag is set, the operating system automatically attempts to restore the connection when the
    /// user logs on.
    ///
    /// The operating system remembers only successful connections that redirect local devices. It does
    /// not remember connections that are unsuccessful or deviceless connections. (A deviceless
    /// connection occurs when the `lpLocalName` member is NULL or points to an empty string.)
    ///
    /// If this bit flag is clear, the operating system does not try to restore the connection when the
    /// user logs on.
    ///
    /// `!persist` (`CONNECT_TEMPORARY`): The network resource connection should not be remembered. If this flag is
    /// set, the operating system will not attempt to restore the connection when the user logs on
    /// again.
    ///
    /// `interactive` (`CONNECT_INTERACTIVE`): If this flag is set, the operating system may interact with the user for
    /// authentication purposes.
    ///
    /// # Errors
    /// This method will error if Windows is unable to connect to the SMB share.
    pub fn connect(&self, persist: bool, interactive: bool) -> Result<()> {
        let local_name = self
            .mount_on
            .map(|ln| format!("{ln}:"))
            .map(CString::new)
            .transpose()?;

        let local_name = match local_name {
            Some(ref cstring) => cstring.as_c_str().as_ptr() as *mut u8,
            None => std::ptr::null_mut(),
        };

        let mut flags = 0u32;

        if persist && self.mount_on.is_some() {
            flags |= WNet::CONNECT_UPDATE_PROFILE;
        } else {
            flags |= WNet::CONNECT_TEMPORARY;
        }

        if interactive {
            flags |= WNet::CONNECT_INTERACTIVE;
        }

        debug!("Connection flags: {flags:#?}");

        let share = CString::new(&*self.share)?;
        let username = CString::new(&*self.username)?;
        let password = CString::new(&*self.password)?;

        // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/ns-winnetwk-netresourcea
        let mut netresource = WNet::NETRESOURCEA {
            dwDisplayType: 0, // ignored by WNetAddConnection2A
            dwScope: 0,       // ignored by WNetAddConnection2A
            dwType: WNet::RESOURCETYPE_DISK,
            dwUsage: 0, // ignored by WNetAddConnection2A
            lpLocalName: local_name,
            lpRemoteName: share.as_c_str().as_ptr() as *mut u8,
            lpComment: std::ptr::null_mut(), // ignored by WNetAddConnection2A
            lpProvider: std::ptr::null_mut(), // Microsoft docs: You should set this member only if you know the network provider you want to use.
                                              // Otherwise, let the operating system determine which provider the network name maps to.
        };

        trace!("Trying to connect to {}", self.share);

        // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2a
        let connection_result = unsafe {
            let username = username.as_ref().as_ptr();
            let password = password.as_ref().as_ptr();
            WNet::WNetAddConnection2A(
                std::ptr::from_mut::<WNet::NETRESOURCEA>(&mut netresource),
                password.cast::<u8>(),
                username.cast::<u8>(),
                flags,
            )
        };

        debug!("Connection result: {connection_result:#?}");

        let connection_result = match connection_result {
            NO_ERROR => Ok(()),
            ERROR_ACCESS_DENIED => Err(Error::AccessDenied),
            ERROR_ALREADY_ASSIGNED => Err(Error::AlreadyAssigned),
            ERROR_BAD_DEV_TYPE => Err(Error::BadDevType),
            ERROR_BAD_DEVICE => Err(Error::BadDevice),
            ERROR_BAD_NET_NAME => Err(Error::BadNetName),
            ERROR_BAD_PROFILE => Err(Error::BadProfile),
            ERROR_BAD_PROVIDER => Err(Error::BadProvider),
            ERROR_BAD_USERNAME => Err(Error::BadUsername),
            ERROR_BUSY => Err(Error::Busy),
            ERROR_CANCELLED => Err(Error::Cancelled),
            ERROR_CANNOT_OPEN_PROFILE => Err(Error::CannotOpenProfile),
            ERROR_DEVICE_ALREADY_REMEMBERED => Err(Error::DeviceAlreadyRemembered),
            ERROR_EXTENDED_ERROR => Err(Error::ExtendedError),
            ERROR_INVALID_ADDRESS => Err(Error::InvalidAddress),
            ERROR_INVALID_PARAMETER => Err(Error::InvalidParameter),
            ERROR_INVALID_PASSWORD => Err(Error::InvalidPassword),
            ERROR_LOGON_FAILURE => Err(Error::LogonFailure),
            ERROR_NO_NET_OR_BAD_PATH => Err(Error::NoNetOrBadPath),
            ERROR_NO_NETWORK => Err(Error::NoNetwork),
            _ => Err(Error::Other),
        };

        match connection_result {
            Ok(()) => {
                trace!("Successfully connected");
            }
            Err(ref e) => error!("Connection failed: {e}"),
        };

        connection_result
    }

    /// Disconnect from the SMB share.
    ///
    /// `persist` (`CONNECT_UPDATE_PROFILE`): The system updates the user profile with the
    /// information that the connection is no longer a persistent one. The system will not restore
    /// this connection during subsequent logon operations. (Disconnecting resources using remote
    /// names has no effect on persistent connections.)
    ///
    /// `force`: Specifies whether the disconnection should occur if there are open files or jobs
    /// on the connection. If this parameter is FALSE, the function fails if there are open files
    /// or jobs.
    ///
    /// # Errors
    /// This method will return an error if Windows is unable to disconnect from the smb share.
    pub fn disconnect(&self, persist: bool, force: bool) -> Result<()> {
        let local_name = self
            .mount_on
            .map(|ln| format!("{ln}:"))
            .map(CString::new)
            .transpose()?;

        let resource_to_disconnect = local_name.unwrap_or(CString::new(&*self.share)?);

        let force = if force { TRUE } else { FALSE };

        let persist = if persist && self.mount_on.is_some() {
            WNet::CONNECT_UPDATE_PROFILE
        } else {
            0
        };

        let disconnect_result = unsafe {
            WNet::WNetCancelConnection2A(resource_to_disconnect.as_ptr() as *mut u8, persist, force)
        };

        debug!("Disconnect result: {disconnect_result:#?}");

        let disconnect_result = match disconnect_result {
            NO_ERROR => Ok(()),
            ERROR_BAD_PROFILE => Err(Error::BadProfile),
            ERROR_CANNOT_OPEN_PROFILE => Err(Error::CannotOpenProfile),
            ERROR_DEVICE_IN_USE => Err(Error::DeviceInUse),
            ERROR_EXTENDED_ERROR => Err(Error::ExtendedError),
            ERROR_NOT_CONNECTED => Err(Error::NotConnected),
            ERROR_OPEN_FILES => Err(Error::OpenFiles),
            _ => Err(Error::Other),
        };

        match disconnect_result {
            Ok(()) => trace!("Successfully disconnected"),
            Err(ref e) => error!("Disconnect failed: {e}"),
        }

        disconnect_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: propper integration test setup

    const VALID_SHARE: &str = r"PUTYOURSHARE";
    const CORRECT_USERNAME: &str = r"PUTYOURUSER";
    const CORRECT_PASSWORD: &str = r"PUTYOURPASS";

    const WRONG_SHARE: &str = r"\\thisisnotashare.local\Share-Name";
    const WRONG_PASSWORD: &str = r"pass";

    // I really wanted to assert against a specific error, but lovely Windows sometimes returns
    // `LogonFailure` and sometimes `InvalidPassword`.
    #[test]
    fn sad_non_interactive_does_not_prompt_and_returns_error() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, WRONG_PASSWORD, None);
        let connection = share.connect(false, false);
        assert!(connection.is_err());
        if let Err(e) = connection {
            assert!(e == Error::InvalidPassword || e == Error::LogonFailure);
        }
    }

    #[test]
    fn sad_non_existent_share() {
        let share = SmbShare::new(WRONG_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, None);
        let connection = share.connect(false, false);
        assert!(connection.is_err());
        if let Err(e) = connection {
            assert_eq!(e, Error::BadNetName);
        }
    }

    #[test]
    fn happy_mount_on_works_and_does_not_persist() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, Some('s'));
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        assert!(std::path::Path::new(r"s:\").is_dir());
        let disconnect = share.disconnect(false, false);
        assert!(disconnect.is_ok());
    }

    #[test]
    fn happy_deviceless_works() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, None);
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        assert!(std::path::Path::new(VALID_SHARE).is_dir());
        let disconnect = share.disconnect(false, false);
        assert!(disconnect.is_ok());
    }

    #[test]
    fn happy_deviceless_reconnecting_is_fine() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, None);
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        assert!(std::path::Path::new(VALID_SHARE).is_dir());
        let disconnect = share.disconnect(false, false);
        assert!(disconnect.is_ok());
    }

    #[test]
    fn sad_mounted_reconnecting_returns_already_assigned_error() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, Some('s'));
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        assert!(std::path::Path::new(r"s:\").is_dir());
        let connection = share.connect(false, false);
        assert!(connection.is_err());
        if let Err(e) = connection {
            assert_eq!(e, Error::AlreadyAssigned);
        }
        let disconnect = share.disconnect(false, false);
        assert!(disconnect.is_ok());
    }

    #[test]
    fn happy_connecting_multiple_letters_to_same_share_works() {
        let share_one = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, Some('s'));
        let connection1 = share_one.connect(false, false);
        assert!(connection1.is_ok());
        let share_two = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, Some('t'));
        let connection2 = share_two.connect(false, false);
        assert!(connection2.is_ok());
        assert!(std::path::Path::new(r"s:\").is_dir());
        assert!(std::path::Path::new(r"t:\").is_dir());
        let share_one_disconnect = share_one.disconnect(false, false);
        assert!(share_one_disconnect.is_ok());
        assert!(!std::path::Path::new(r"s:\").is_dir());
        let share_two_disconnect = share_two.disconnect(false, false);
        assert!(share_two_disconnect.is_ok());
        assert!(!std::path::Path::new(r"t:\").is_dir());
    }
}
