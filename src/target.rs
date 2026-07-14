use crate::error::{Error, Result, check_wnet};
use crate::options::{ConnectOptions, DisconnectOptions, DriveLetter};
use crate::strings::{WideSecret, from_wide_buf, len_u32, opt_ptr, secret_ptr, to_wide};
use tracing::{debug, trace};
use windows_sys::Win32::NetworkManagement::WNet;

/// The wide-string buffers for one connect call, converted from an
/// [`SmbTarget`].
///
/// Owning them in one struct pins down the borrow discipline: the struct must
/// outlive the FFI call because every pointer passed to it borrows from the
/// buffers owned here.
struct ConnectArgs {
    remote: Vec<u16>,
    local: Option<Vec<u16>>,
    username: Option<Vec<u16>>,
    password: Option<WideSecret>,
}

impl ConnectArgs {
    fn new(target: &SmbTarget) -> Result<Self> {
        let password = target
            .password
            .as_deref()
            .map(|password| to_wide(password))
            .transpose()?
            .map(WideSecret::from);
        Ok(Self {
            remote: to_wide(&target.remote)?,
            local: target.local.as_deref().map(to_wide).transpose()?,
            username: target.username.as_deref().map(to_wide).transpose()?,
            password,
        })
    }

    /// The `NETRESOURCEW` handed to `WNetAddConnection2W` /
    /// `WNetUseConnectionW`. Its pointers borrow from `self`.
    // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
    fn resource(&self) -> WNet::NETRESOURCEW {
        WNet::NETRESOURCEW {
            dwType: WNet::RESOURCETYPE_DISK,
            lpLocalName: opt_ptr(self.local.as_deref()),
            lpRemoteName: self.remote.as_ptr().cast_mut(),
            ..Default::default()
        }
    }
}

/// A reusable target for SMB connections, optionally mapped to a local drive.
///
/// Construct one with [`SmbTarget::new`], configure it with the fluent setters,
/// then establish the connection with one of the `connect*` methods.
///
/// ```no_run
/// use sambrs::{DriveLetter, SmbTarget};
///
/// let target = SmbTarget::new(r"\\server\share")
///     .credentials("user", "pass")
///     .mount_on(DriveLetter::D);
///
/// target.connect()?;
/// // use std::fs as if D:\ was a local directory
/// assert!(std::fs::metadata(r"D:\")?.is_dir());
/// target.disconnect()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct SmbTarget {
    remote: String,
    username: Option<String>,
    password: Option<zeroize::Zeroizing<String>>,
    local: Option<String>,
}

// Deliberately manual: must never leak the password.
impl std::fmt::Debug for SmbTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmbTarget")
            .field("remote", &self.remote)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("local", &self.local)
            .finish()
    }
}

impl SmbTarget {
    /// An SMB target at `remote` (e.g. `\\server\share`), initially configured
    /// for a deviceless connection using the logged-on user's credentials.
    pub fn new(remote: impl Into<String>) -> Self {
        Self {
            remote: remote.into(),
            username: None,
            password: None,
            local: None,
        }
    }

    /// Authenticate with an explicit user name and password.
    ///
    /// The user name can carry a domain (`DOMAIN\user` or `user@domain`).
    /// Without credentials, the connection uses the logged-on user's
    /// credentials. An empty password string is a real (empty) password, not
    /// "no password".
    #[must_use]
    pub fn credentials(self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username(username).password(password)
    }

    /// Set only the user name; Windows will use the default password
    /// associated with that user.
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set only the password; Windows will use the default user name.
    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(zeroize::Zeroizing::new(password.into()));
        self
    }

    /// Redirect this target to a local drive letter.
    #[must_use]
    pub fn mount_on(mut self, letter: DriveLetter) -> Self {
        self.local = Some(letter.to_string());
        self
    }

    /// Connect with default options: a temporary, non-interactive connection.
    ///
    /// Connecting multiple times works fine in deviceless mode but fails with
    /// `ERROR_ALREADY_ASSIGNED` when a local mount point is set. Windows
    /// does not reference-count connections, though: repeated deviceless
    /// connects share one underlying connection, and a single
    /// [`disconnect`](Self::disconnect) cancels them all.
    ///
    /// # Errors
    /// Returns [`Error`] for invalid options or a failed Windows call.
    pub fn connect(&self) -> Result<()> {
        self.connect_with(ConnectOptions::new())
    }

    /// Connect with explicit [`ConnectOptions`].
    ///
    /// # Errors
    /// [`Error::PersistenceRequiresDrive`] when persistence is requested for
    /// a deviceless target, or another [`Error`] when the Windows call fails.
    pub fn connect_with(&self, options: ConnectOptions) -> Result<()> {
        if options.is_persistent() && self.local.is_none() {
            return Err(Error::PersistenceRequiresDrive);
        }
        let flags = options.flags;
        let args = ConnectArgs::new(self)?;
        let resource = args.resource();

        trace!(
            "connecting to {} as {} with flags {flags:#x}",
            self.remote,
            self.username.as_deref().unwrap_or("<logged-on user>")
        );

        // SAFETY: all pointers in `resource` and the credential pointers stay
        // valid for the duration of the call — they borrow from the buffers
        // owned by `args`, which lives until the end of this function.
        let status = unsafe {
            WNet::WNetAddConnection2W(
                &raw const resource,
                secret_ptr(args.password.as_ref()),
                opt_ptr(args.username.as_deref()),
                flags,
            )
        };

        debug!("WNetAddConnection2W returned {status}");
        check_wnet(status)
    }

    /// Connect and let Windows pick a free drive, via `WNetUseConnectionW`
    /// with `CONNECT_REDIRECT`.
    ///
    /// Returns the drive through which the share is accessible (e.g. `"Z:"`),
    /// or the drive configured on this target if one was set. Pass the returned name to
    /// [`cancel_connection`] to disconnect, or use
    /// [`connect_auto_guarded`](Self::connect_auto_guarded) to have that
    /// happen automatically.
    ///
    /// # Errors
    /// See [`Error`].
    pub fn connect_auto(&self, options: ConnectOptions) -> Result<String> {
        let flags = options.flags | WNet::CONNECT_REDIRECT;
        let args = ConnectArgs::new(self)?;
        let resource = args.resource();

        trace!(
            "auto-connecting to {} as {} with flags {flags:#x}",
            self.remote,
            self.username.as_deref().unwrap_or("<logged-on user>")
        );

        // Sized so any real access name fits on the first call: the name is
        // either a mapped drive ("Z:", nowhere near 1024) or, for
        // a deviceless connection, a provider-adjusted form of the remote
        // name — covered by the `remote.len()` headroom. There is
        // deliberately no grow-and-retry on ERROR_MORE_DATA: Windows does
        // not document whether the failed call left the connection behind,
        // so a retry could establish a second one (with CONNECT_REDIRECT, a
        // second drive letter whose name is never returned to the caller).
        let mut access_name = vec![0u16; 1024 + args.remote.len()];
        let mut size = len_u32(access_name.len());
        let mut result = 0u32;
        // SAFETY: `args` (which every pointer in `resource` and the
        // credential pointers borrow from) and `access_name` outlive the call.
        let status = unsafe {
            WNet::WNetUseConnectionW(
                std::ptr::null_mut(), // no owner window for credential dialogs
                &raw const resource,
                secret_ptr(args.password.as_ref()),
                opt_ptr(args.username.as_deref()),
                flags,
                access_name.as_mut_ptr(),
                &raw mut size,
                &raw mut result,
            )
        };
        debug!("WNetUseConnectionW returned {status}, result {result:#x}");
        check_wnet(status)?;
        Ok(from_wide_buf(&access_name))
    }

    /// Connect and return an RAII [`Connection`] guard that disconnects when
    /// dropped.
    ///
    /// Requires a drive set via [`mount_on`](Self::mount_on): the drive is
    /// the one thing a guard can exclusively own — connecting fails with
    /// `ERROR_ALREADY_ASSIGNED` if it is taken, and canceling it by name on
    /// drop touches no other connection. A deviceless connection offers no
    /// such handle: Windows does not reference-count connections, and
    /// canceling by remote name tears down **every** deviceless connection
    /// to the resource in this logon session, including ones the guard never
    /// made — so deviceless targets are rejected here. Use
    /// [`connect_auto_guarded`](Self::connect_auto_guarded) to have Windows
    /// pick the device instead.
    ///
    /// # Errors
    /// [`Error::GuardRequiresDrive`] when this target has no drive, or
    /// [`Error::PersistentGuard`] when persistence is requested; otherwise
    /// see [`Error`].
    pub fn connect_guarded(&self, options: ConnectOptions) -> Result<Connection> {
        if options.is_persistent() {
            return Err(Error::PersistentGuard);
        }
        let device = self.local.clone().ok_or(Error::GuardRequiresDrive)?;
        self.connect_with(options)?;
        Ok(Connection {
            device,
            armed: true,
        })
    }

    /// [`connect_auto`](Self::connect_auto) with an RAII [`Connection`]
    /// guard: Windows picks a free drive, and the guard cancels
    /// exactly that device when dropped. [`Connection::device`] tells you
    /// where the target is mounted.
    ///
    /// # Errors
    /// [`Error::PersistentGuard`] when persistence is requested; otherwise
    /// see [`connect_auto`](Self::connect_auto).
    pub fn connect_auto_guarded(&self, options: ConnectOptions) -> Result<Connection> {
        if options.is_persistent() {
            return Err(Error::PersistentGuard);
        }
        let device = self.connect_auto(options)?;
        Ok(Connection {
            device,
            armed: true,
        })
    }

    /// Disconnect with default options: non-forced, keeping any persistence.
    ///
    /// Disconnects by drive name when this target has one, otherwise by
    /// remote name. Disconnecting by remote name cancels **all** deviceless
    /// connections to that resource in this logon session — Windows does not
    /// reference-count them, so this undoes every [`connect`](Self::connect)
    /// to the resource at once, not just one.
    ///
    /// # Errors
    /// Returns [`Error`] when the Windows call fails.
    pub fn disconnect(&self) -> Result<()> {
        self.disconnect_with(DisconnectOptions::default())
    }

    /// Disconnect with explicit [`DisconnectOptions`].
    ///
    /// # Errors
    /// See [`Error`].
    pub fn disconnect_with(&self, options: DisconnectOptions) -> Result<()> {
        let name = self.local.as_deref().unwrap_or(&self.remote);
        cancel_connection(name, options)
    }
}

/// Cancel a connection by name: either a mapped drive (e.g. `"Z:"`) or a
/// remote name (`\\server\share`) for deviceless connections.
///
/// This is the direct wrapper around `WNetCancelConnection2W`; use it to
/// disconnect names returned by
/// [`SmbTarget::connect_auto`] or found via [`crate::enumerate`].
///
/// A drive name cancels only that mapping; a remote name cancels
/// **all** deviceless connections to that resource in this logon session
/// (Windows does not reference-count them).
///
/// # Errors
/// See [`Error`].
pub fn cancel_connection(name: &str, options: DisconnectOptions) -> Result<()> {
    if options.forget && !is_drive(name) {
        return Err(Error::ForgetRequiresDrive);
    }
    let wide = to_wide(name)?;
    trace!(
        "disconnecting {name} (force={}, forget={})",
        options.force, options.forget
    );
    // SAFETY: `wide` is a valid nul-terminated string outliving the call.
    let flags = if options.forget {
        WNet::CONNECT_UPDATE_PROFILE
    } else {
        0
    };
    let status =
        unsafe { WNet::WNetCancelConnection2W(wide.as_ptr(), flags, i32::from(options.force)) };
    debug!("WNetCancelConnection2W returned {status}");
    check_wnet(status)
}

fn is_drive(name: &str) -> bool {
    matches!(name.as_bytes(), [letter, b':'] if letter.is_ascii_alphabetic())
}

/// RAII guard returned by [`SmbTarget::connect_guarded`] and
/// [`SmbTarget::connect_auto_guarded`]: cancels the connection when dropped
/// (best effort — a failure on drop is only visible as a `tracing` event).
///
/// A guard always owns a drive mapping ([`Connection::device`]) and cancels
/// exactly that drive, never the remote name. The drive was
/// free when the guard connected it, so a live guard is its sole owner and
/// dropping it cannot tear down a connection made elsewhere. (This is why
/// deviceless connections cannot be guarded — canceling one means canceling
/// by remote name, which takes every deviceless connection to the resource
/// down with it.)
///
/// Use [`Connection::disconnect`] for explicit error handling.
#[derive(Debug)]
#[must_use = "dropping the guard disconnects the connection immediately"]
pub struct Connection {
    /// The mapped drive this guard exclusively owns.
    device: String,
    armed: bool,
}

impl Connection {
    /// The drive this guard owns (e.g. `"Z:"`) — the target is
    /// accessible through it for as long as the guard lives.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Disconnect now, with explicit error handling.
    ///
    /// # Errors
    /// See [`Error`].
    pub fn disconnect(mut self, options: DisconnectOptions) -> Result<()> {
        self.armed = false;
        cancel_connection(&self.device, options)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = cancel_connection(&self.device, DisconnectOptions::default()) {
                debug!("failed to disconnect {} on guard drop: {e}", self.device);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configures_target_fluently() {
        let target = SmbTarget::new(r"\\server\share")
            .username("user")
            .password("secret-value")
            .mount_on(DriveLetter::D);
        assert_eq!(target.username.as_deref(), Some("user"));
        assert_eq!(target.password.as_deref().unwrap().as_str(), "secret-value");
        assert_eq!(target.local.as_deref(), Some("D:"));
        let debug = format!("{target:?}");
        assert!(debug.contains("user"));
        assert!(!debug.contains("secret-value"));
    }

    #[test]
    fn credential_forms_keep_missing_fields_absent() {
        let default = SmbTarget::new(r"\\server\share");
        let args = ConnectArgs::new(&default).unwrap();
        assert!(args.username.is_none());
        assert!(args.password.is_none());

        let username_only = SmbTarget::new(r"\\server\share").username("user");
        let args = ConnectArgs::new(&username_only).unwrap();
        assert!(args.username.is_some());
        assert!(args.password.is_none());

        let password_only = SmbTarget::new(r"\\server\share").password("secret-value");
        let args = ConnectArgs::new(&password_only).unwrap();
        assert!(args.username.is_none());
        assert!(args.password.is_some());
    }

    #[test]
    fn invalid_lifetime_combinations_are_rejected_before_windows_calls() {
        let deviceless = SmbTarget::new(r"\\server\share");
        let persistent = ConnectOptions::new().persist(true);
        assert_eq!(
            deviceless.connect_with(persistent),
            Err(Error::PersistenceRequiresDrive)
        );
        assert_eq!(
            deviceless
                .connect_guarded(ConnectOptions::new())
                .unwrap_err(),
            Error::GuardRequiresDrive
        );
        assert_eq!(
            deviceless.connect_auto_guarded(persistent).unwrap_err(),
            Error::PersistentGuard
        );

        let mapped = SmbTarget::new(r"\\server\share").mount_on(DriveLetter::D);
        assert_eq!(
            mapped.connect_guarded(persistent).unwrap_err(),
            Error::PersistentGuard
        );
        assert_eq!(
            deviceless.disconnect_with(DisconnectOptions::default().forget(true)),
            Err(Error::ForgetRequiresDrive)
        );
    }

    #[test]
    fn drive_names_are_recognized_for_forgetting() {
        assert!(is_drive("D:"));
        assert!(is_drive("z:"));
        assert!(!is_drive(r"\\server\share"));
        assert!(!is_drive("D:\\"));
    }
}
