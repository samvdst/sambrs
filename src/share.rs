use crate::error::{Error, Result, check_wnet};
use crate::options::{ConnectOptions, DisconnectOptions, DriveLetter, ResourceType};
use crate::strings::{WideSecret, from_wide_buf, len_u32, opt_ptr, secret_ptr, to_wide};
use crate::trace::{debug, trace};
use windows_sys::Win32::NetworkManagement::WNet;

/// The wide-string buffers and resource type for one connect call, converted
/// from an [`SmbShare`].
///
/// Owning them in one struct pins down the borrow discipline: the struct must
/// outlive the FFI call because every pointer passed to it borrows from the
/// buffers owned here.
struct ConnectArgs {
    remote: Vec<u16>,
    local: Option<Vec<u16>>,
    provider: Option<Vec<u16>>,
    username: Option<Vec<u16>>,
    password: Option<WideSecret>,
    resource_type: ResourceType,
}

impl ConnectArgs {
    fn new(share: &SmbShare) -> Result<Self> {
        let password = share.password.as_deref().map(to_wide).transpose()?;
        Ok(Self {
            remote: to_wide(&share.remote)?,
            local: share.local.as_deref().map(to_wide).transpose()?,
            provider: share.provider.as_deref().map(to_wide).transpose()?,
            username: share.username.as_deref().map(to_wide).transpose()?,
            password: password.map(WideSecret::from),
            resource_type: share.resource_type,
        })
    }

    /// The `NETRESOURCEW` handed to `WNetAddConnection2W` /
    /// `WNetUseConnectionW`. Its pointers borrow from `self`.
    // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
    fn resource(&self) -> WNet::NETRESOURCEW {
        WNet::NETRESOURCEW {
            dwScope: 0, // ignored by WNetAddConnection2W / WNetUseConnectionW
            dwType: self.resource_type as u32,
            dwDisplayType: 0, // ignored, as dwScope
            dwUsage: 0,       // ignored, as dwScope
            lpLocalName: opt_ptr(self.local.as_deref()),
            lpRemoteName: self.remote.as_ptr().cast_mut(),
            lpComment: std::ptr::null_mut(), // ignored, as dwScope
            lpProvider: opt_ptr(self.provider.as_deref()),
        }
    }
}

/// A remote SMB share, optionally redirected to a local device.
///
/// Construct one with [`SmbShare::new`] (deviceless, current-user
/// credentials) or [`SmbShare::builder`] for full control, then establish the
/// connection with one of the `connect*` methods.
///
/// ```no_run
/// use sambrs::{DriveLetter, SmbShare};
///
/// let share = SmbShare::builder(r"\\server\share")
///     .credentials("user", "pass")
///     .mount_on(DriveLetter::D)
///     .build()?;
///
/// share.connect()?;
/// // use std::fs as if D:\ was a local directory
/// assert!(std::fs::metadata(r"D:\")?.is_dir());
/// share.disconnect()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct SmbShare {
    remote: String,
    username: Option<String>,
    password: Option<String>,
    local: Option<String>,
    resource_type: ResourceType,
    provider: Option<String>,
}

// Deliberately manual: must never leak the password.
impl std::fmt::Debug for SmbShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmbShare")
            .field("remote", &self.remote)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("local", &self.local)
            .field("resource_type", &self.resource_type)
            .field("provider", &self.provider)
            .finish()
    }
}

#[cfg(feature = "zeroize")]
impl Drop for SmbShare {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

impl SmbShare {
    /// A deviceless connection to `remote` (e.g. `\\server\share`) using the
    /// credentials of the currently logged-on user.
    ///
    /// Use [`SmbShare::builder`] to set credentials, a local mount point, a
    /// resource type, or a network provider.
    pub fn new(remote: impl Into<String>) -> Self {
        Self {
            remote: remote.into(),
            username: None,
            password: None,
            local: None,
            resource_type: ResourceType::Disk,
            provider: None,
        }
    }

    /// Start building a share representation with full control over
    /// credentials, mount point, resource type, and provider.
    pub fn builder(remote: impl Into<String>) -> SmbShareBuilder {
        SmbShareBuilder {
            share: Self::new(remote),
        }
    }

    /// The remote name, e.g. `\\server\share`.
    #[must_use]
    pub fn remote(&self) -> &str {
        &self.remote
    }

    /// The local device this share is redirected to (e.g. `"D:"`), if any.
    #[must_use]
    pub fn local_device(&self) -> Option<&str> {
        self.local.as_deref()
    }

    /// The user name used to authenticate; `None` means the credentials of
    /// the currently logged-on user.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Connect with default options: a temporary, non-interactive connection.
    ///
    /// Connecting multiple times works fine in deviceless mode but fails with
    /// [`Error::AlreadyAssigned`] when a local mount point is set. Windows
    /// does not reference-count connections, though: repeated deviceless
    /// connects share one underlying connection, and a single
    /// [`disconnect`](Self::disconnect) cancels them all.
    ///
    /// # Errors
    /// See [`Error`] — every documented `WNetAddConnection2W` failure has a
    /// dedicated variant.
    pub fn connect(&self) -> Result<()> {
        self.connect_with(ConnectOptions::new())
    }

    /// Connect with explicit [`ConnectOptions`].
    ///
    /// # Errors
    /// See [`Error`] — every documented `WNetAddConnection2W` failure has a
    /// dedicated variant.
    pub fn connect_with(&self, options: ConnectOptions) -> Result<()> {
        self.connect_raw(options.to_flags())
    }

    /// Connect passing `dwFlags` verbatim to `WNetAddConnection2W` — an
    /// escape hatch when [`ConnectOptions`] doesn't expose a flag you need.
    ///
    /// # Errors
    /// See [`Error`].
    pub fn connect_raw(&self, flags: u32) -> Result<()> {
        let args = ConnectArgs::new(self)?;
        let resource = args.resource();

        trace!("connecting to {} with flags {flags:#x}", self.remote);

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

    /// Connect and let Windows pick a free local device, via
    /// `WNetUseConnectionW` with `CONNECT_REDIRECT`.
    ///
    /// Returns the name through which the share is accessible — the assigned
    /// device (e.g. `"Z:"`), or the local device configured on this share if
    /// one was set. Pass the returned name to
    /// [`cancel_connection`] to disconnect, or use
    /// [`connect_auto_guarded`](Self::connect_auto_guarded) to have that
    /// happen automatically.
    ///
    /// The share's resource type must be [`ResourceType::Disk`] or
    /// [`ResourceType::Print`]: Windows rejects `RESOURCETYPE_ANY` with
    /// [`Error::InvalidParameter`] when it chooses the device itself.
    ///
    /// # Errors
    /// See [`Error`].
    pub fn connect_auto(&self, options: ConnectOptions) -> Result<String> {
        self.connect_auto_raw(options.to_flags() | WNet::CONNECT_REDIRECT)
    }

    /// [`connect_auto`](Self::connect_auto) with verbatim `dwFlags` (note:
    /// `CONNECT_REDIRECT` is *not* added for you here).
    ///
    /// # Errors
    /// See [`Error`].
    pub fn connect_auto_raw(&self, flags: u32) -> Result<String> {
        let args = ConnectArgs::new(self)?;
        let resource = args.resource();

        trace!("auto-connecting to {} with flags {flags:#x}", self.remote);

        // Sized so any real access name fits on the first call: the name is
        // either a redirected local device ("Z:", nowhere near 1024) or, for
        // a deviceless connection, a provider-adjusted form of the remote
        // name — covered by the `remote.len()` headroom. There is
        // deliberately no grow-and-retry on ERROR_MORE_DATA: Windows does
        // not document whether the failed call left the connection behind,
        // so a retry could establish a second one (with CONNECT_REDIRECT, a
        // second drive letter whose name is never returned to the caller).
        let mut access_name = vec![0u16; 1024 + args.remote.len()];
        let mut size = len_u32(access_name.len());
        let mut result = 0u32;
        // SAFETY: as in `connect_raw` — `args` (which every pointer in
        // `resource` and the credential pointers borrow from) and
        // `access_name` outlive the call.
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
    /// Requires a local device (set via
    /// [`mount_on`](SmbShareBuilder::mount_on) /
    /// [`local_device`](SmbShareBuilder::local_device)): the device is the
    /// one thing a guard can exclusively own — connecting fails with
    /// [`Error::AlreadyAssigned`] if it is taken, and canceling it by name on
    /// drop touches no other connection. A deviceless connection offers no
    /// such handle: Windows does not reference-count connections, and
    /// canceling by remote name tears down **every** deviceless connection
    /// to the resource in this logon session, including ones the guard never
    /// made — so deviceless shares are rejected here. Use
    /// [`connect_auto_guarded`](Self::connect_auto_guarded) to have Windows
    /// pick the device instead.
    ///
    /// # Errors
    /// [`Error::InvalidParameter`] (synthesized without a Windows call) when
    /// this share has no local device; otherwise see [`Error`].
    pub fn connect_guarded(&self, options: ConnectOptions) -> Result<Connection> {
        let Some(device) = self.local.as_deref() else {
            return Err(Error::InvalidParameter);
        };
        let device = device.to_string();
        self.connect_with(options)?;
        Ok(Connection {
            device,
            armed: true,
        })
    }

    /// [`connect_auto`](Self::connect_auto) with an RAII [`Connection`]
    /// guard: Windows picks a free local device, and the guard cancels
    /// exactly that device when dropped. [`Connection::device`] tells you
    /// where the share is mounted.
    ///
    /// # Errors
    /// See [`connect_auto`](Self::connect_auto).
    pub fn connect_auto_guarded(&self, options: ConnectOptions) -> Result<Connection> {
        let device = self.connect_auto(options)?;
        Ok(Connection {
            device,
            armed: true,
        })
    }

    /// Disconnect with default options: non-forced, keeping any persistence.
    ///
    /// Disconnects by local device name when this share has one, otherwise by
    /// remote name. Disconnecting by remote name cancels **all** deviceless
    /// connections to that resource in this logon session — Windows does not
    /// reference-count them, so this undoes every [`connect`](Self::connect)
    /// to the resource at once, not just one.
    ///
    /// # Errors
    /// See [`Error`] — every documented `WNetCancelConnection2W` failure has
    /// a dedicated variant.
    pub fn disconnect(&self) -> Result<()> {
        self.disconnect_with(DisconnectOptions::new())
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

/// Cancel a connection by name: either a redirected local device (e.g.
/// `"Z:"`) or a remote name (`\\server\share`) for deviceless connections.
///
/// This is the direct wrapper around `WNetCancelConnection2W`; use it to
/// disconnect names returned by
/// [`SmbShare::connect_auto`] or found via [`crate::enumerate`].
///
/// A local device name cancels only that redirection; a remote name cancels
/// **all** deviceless connections to that resource in this logon session
/// (Windows does not reference-count them).
///
/// # Errors
/// See [`Error`].
pub fn cancel_connection(name: &str, options: DisconnectOptions) -> Result<()> {
    let wide = to_wide(name)?;
    trace!("disconnecting {name}");
    // SAFETY: `wide` is a valid nul-terminated string outliving the call.
    let status = unsafe {
        WNet::WNetCancelConnection2W(wide.as_ptr(), options.flags(), options.force_bool())
    };
    debug!("WNetCancelConnection2W returned {status}");
    check_wnet(status)
}

/// Builder for [`SmbShare`], created via [`SmbShare::builder`].
#[derive(Debug)]
pub struct SmbShareBuilder {
    share: SmbShare,
}

impl SmbShareBuilder {
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
        self.share.username = Some(username.into());
        self
    }

    /// Set only the password; Windows will use the default user name.
    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        // Wipe any previously set password before the assignment drops it.
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.share.password.zeroize();
        }
        self.share.password = Some(password.into());
        self
    }

    /// Redirect the share to a local drive letter.
    #[must_use]
    pub fn mount_on(mut self, letter: DriveLetter) -> Self {
        self.share.local = Some(letter.to_string());
        self
    }

    /// Redirect to an arbitrary local device name (e.g. `"LPT1"` for a
    /// printer share). Prefer [`mount_on`](Self::mount_on) for drive letters;
    /// this escape hatch is passed to Windows unvalidated.
    #[must_use]
    pub fn local_device(mut self, device: impl Into<String>) -> Self {
        self.share.local = Some(device.into());
        self
    }

    /// The resource type to connect to. Defaults to [`ResourceType::Disk`].
    ///
    /// [`ResourceType::Any`] is only valid for deviceless connections; see
    /// its documentation.
    #[must_use]
    pub fn resource_type(mut self, resource_type: ResourceType) -> Self {
        self.share.resource_type = resource_type;
        self
    }

    /// The network provider to use (`lpProvider`). Microsoft: set this only
    /// if you know the network provider you want; otherwise let the operating
    /// system determine which provider the network name maps to.
    #[must_use]
    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.share.provider = Some(provider.into());
        self
    }

    /// Validate the configuration and build the [`SmbShare`].
    ///
    /// # Errors
    /// [`Error::InteriorNul`] if any string contains a NUL character.
    pub fn build(self) -> Result<SmbShare> {
        let strings = [
            Some(self.share.remote.as_str()),
            self.share.username.as_deref(),
            self.share.password.as_deref(),
            self.share.local.as_deref(),
            self.share.provider.as_deref(),
        ];
        if strings.into_iter().flatten().any(|s| s.contains('\0')) {
            return Err(Error::InteriorNul);
        }
        Ok(self.share)
    }
}

/// RAII guard returned by [`SmbShare::connect_guarded`] and
/// [`SmbShare::connect_auto_guarded`]: cancels the connection when dropped
/// (best effort — a failure on drop is only visible as a `tracing` event,
/// with the `tracing` feature enabled).
///
/// A guard always owns a local device redirection ([`Connection::device`])
/// and cancels exactly that device, never the remote name. The device was
/// free when the guard connected it, so a live guard is its sole owner and
/// dropping it cannot tear down a connection made elsewhere. (This is why
/// deviceless connections cannot be guarded — canceling one means canceling
/// by remote name, which takes every deviceless connection to the resource
/// down with it.)
///
/// Use [`Connection::disconnect`] for explicit error handling, or
/// [`Connection::leak`] to keep the connection open past the guard.
#[derive(Debug)]
#[must_use = "dropping the guard disconnects the share immediately"]
pub struct Connection {
    /// The redirected local device this guard exclusively owns.
    device: String,
    armed: bool,
}

impl Connection {
    /// The local device this guard owns (e.g. `"Z:"`) — the share is
    /// accessible through it for as long as the guard lives.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Consume the guard without disconnecting, keeping the connection open.
    pub fn leak(mut self) {
        self.armed = false;
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
            if let Err(e) = cancel_connection(&self.device, DisconnectOptions::new()) {
                debug!("failed to disconnect {} on guard drop: {e}", self.device);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deviceless_connect_guarded_is_rejected() {
        // Rejected before any Windows call: without a local device there is
        // nothing a guard can exclusively own, and canceling by remote name
        // would tear down deviceless connections the guard never made.
        let share = SmbShare::new(r"\\server\share");
        assert_eq!(
            share.connect_guarded(ConnectOptions::new()).unwrap_err(),
            Error::InvalidParameter
        );
    }
}
