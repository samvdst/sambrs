use crate::error::{Error, Result, check_wnet};
use crate::options::{ConnectOptions, DisconnectOptions, DriveLetter, ResourceType};
use crate::strings::{from_wide_buf, len_u32, opt_ptr, secret_ptr, to_wide, to_wide_secret};
use crate::trace::{debug, trace};
use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::NetworkManagement::WNet;

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
    /// [`Error::AlreadyAssigned`] when a local mount point is set.
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
        let remote = to_wide(&self.remote)?;
        let local = self.local.as_deref().map(to_wide).transpose()?;
        let provider = self.provider.as_deref().map(to_wide).transpose()?;
        let username = self.username.as_deref().map(to_wide).transpose()?;
        let password = self.password.as_deref().map(to_wide_secret).transpose()?;

        // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
        let resource = WNet::NETRESOURCEW {
            dwScope: 0, // ignored by WNetAddConnection2W
            dwType: self.resource_type.to_dword(),
            dwDisplayType: 0, // ignored by WNetAddConnection2W
            dwUsage: 0,       // ignored by WNetAddConnection2W
            lpLocalName: opt_ptr(local.as_deref()),
            lpRemoteName: remote.as_ptr().cast_mut(),
            lpComment: std::ptr::null_mut(), // ignored by WNetAddConnection2W
            lpProvider: opt_ptr(provider.as_deref()),
        };

        trace!("connecting to {} with flags {flags:#x}", self.remote);

        // SAFETY: all pointers in `resource` and the credential pointers stay
        // valid for the duration of the call — they borrow from the wide
        // buffers bound above, which live until the end of this function.
        let status = unsafe {
            WNet::WNetAddConnection2W(
                &raw const resource,
                secret_ptr(password.as_ref()),
                opt_ptr(username.as_deref()),
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
    /// [`cancel_connection`] to disconnect.
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
        let remote = to_wide(&self.remote)?;
        let local = self.local.as_deref().map(to_wide).transpose()?;
        let provider = self.provider.as_deref().map(to_wide).transpose()?;
        let username = self.username.as_deref().map(to_wide).transpose()?;
        let password = self.password.as_deref().map(to_wide_secret).transpose()?;

        let resource = WNet::NETRESOURCEW {
            dwScope: 0,
            dwType: self.resource_type.to_dword(),
            dwDisplayType: 0,
            dwUsage: 0,
            lpLocalName: opt_ptr(local.as_deref()),
            lpRemoteName: remote.as_ptr().cast_mut(),
            lpComment: std::ptr::null_mut(),
            lpProvider: opt_ptr(provider.as_deref()),
        };

        trace!("auto-connecting to {} with flags {flags:#x}", self.remote);

        let mut access_name = vec![0u16; 1024];
        // One retry with the size Windows asked for.
        for _ in 0..2 {
            let mut size = len_u32(access_name.len());
            let mut result = 0u32;
            // SAFETY: as in `connect_raw`; `access_name` outlives the call.
            let status = unsafe {
                WNet::WNetUseConnectionW(
                    std::ptr::null_mut(), // no owner window for credential dialogs
                    &raw const resource,
                    secret_ptr(password.as_ref()),
                    opt_ptr(username.as_deref()),
                    flags,
                    access_name.as_mut_ptr(),
                    &raw mut size,
                    &raw mut result,
                )
            };
            debug!("WNetUseConnectionW returned {status}, result {result:#x}");
            if status == ERROR_MORE_DATA {
                access_name = vec![0u16; size as usize];
                continue;
            }
            check_wnet(status)?;
            return Ok(from_wide_buf(&access_name));
        }
        Err(Error::Other(ERROR_MORE_DATA))
    }

    /// Connect and return an RAII [`Connection`] guard that disconnects when
    /// dropped.
    ///
    /// # Errors
    /// See [`Error`].
    pub fn connect_guarded(&self, options: ConnectOptions) -> Result<Connection<'_>> {
        self.connect_with(options)?;
        Ok(Connection {
            share: self,
            on_drop: DisconnectOptions::new(),
            armed: true,
        })
    }

    /// Disconnect with default options: non-forced, keeping any persistence.
    ///
    /// Disconnects by local device name when this share has one, otherwise by
    /// remote name.
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
        self.share.local = Some(letter.device());
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
        fn validate(s: Option<&str>) -> Result<()> {
            if s.is_some_and(|s| s.contains('\0')) {
                Err(Error::InteriorNul)
            } else {
                Ok(())
            }
        }
        validate(Some(&self.share.remote))?;
        validate(self.share.username.as_deref())?;
        validate(self.share.password.as_deref())?;
        validate(self.share.local.as_deref())?;
        validate(self.share.provider.as_deref())?;
        Ok(self.share)
    }
}

/// RAII guard returned by [`SmbShare::connect_guarded`]: disconnects the
/// share when dropped (best effort — a failure on drop is only visible as a
/// `tracing` event, with the `tracing` feature enabled).
///
/// Use [`Connection::disconnect`] for explicit error handling, or
/// [`Connection::leak`] to keep the connection open past the guard.
#[derive(Debug)]
#[must_use = "dropping the guard disconnects the share immediately"]
pub struct Connection<'a> {
    share: &'a SmbShare,
    on_drop: DisconnectOptions,
    armed: bool,
}

impl<'a> Connection<'a> {
    /// Configure the [`DisconnectOptions`] used when this guard drops (e.g.
    /// force-close open files).
    pub fn on_drop(mut self, options: DisconnectOptions) -> Self {
        self.on_drop = options;
        self
    }

    /// The share this guard belongs to.
    #[must_use]
    pub fn share(&self) -> &'a SmbShare {
        self.share
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
        self.share.disconnect_with(options)
    }
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = self.share.disconnect_with(self.on_drop) {
                debug!(
                    "failed to disconnect {} on guard drop: {e}",
                    self.share.remote()
                );
            }
        }
    }
}
