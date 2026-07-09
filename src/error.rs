use thiserror::Error;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_ASSIGNED, ERROR_BAD_DEV_TYPE, ERROR_BAD_DEVICE,
    ERROR_BAD_NET_NAME, ERROR_BAD_PROFILE, ERROR_BAD_PROVIDER, ERROR_BAD_USERNAME, ERROR_BUSY,
    ERROR_CANCELLED, ERROR_CANNOT_OPEN_PROFILE, ERROR_CONNECTION_UNAVAIL, ERROR_DEV_NOT_EXIST,
    ERROR_DEVICE_ALREADY_REMEMBERED, ERROR_DEVICE_IN_USE, ERROR_EXTENDED_ERROR,
    ERROR_INVALID_ADDRESS, ERROR_INVALID_LEVEL, ERROR_INVALID_PARAMETER, ERROR_INVALID_PASSWORD,
    ERROR_LOGON_FAILURE, ERROR_NO_NET_OR_BAD_PATH, ERROR_NO_NETWORK, ERROR_NOT_CONNECTED,
    ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_SUPPORTED, ERROR_OPEN_FILES,
    ERROR_SESSION_CREDENTIAL_CONFLICT, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_ClientNameNotFound as NERR_CLIENT_NAME_NOT_FOUND,
    NERR_DuplicateShare as NERR_DUPLICATE_SHARE, NERR_FileIdNotFound as NERR_FILE_ID_NOT_FOUND,
    NERR_NetNameNotFound as NERR_NET_NAME_NOT_FOUND, NERR_Success as NERR_SUCCESS,
    NERR_UnknownDevDir as NERR_UNKNOWN_DEV_DIR, NERR_UserNotFound as NERR_USER_NOT_FOUND,
};
use windows_sys::Win32::NetworkManagement::WNet;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by sambrs operations.
///
/// Most variants map 1:1 to a documented Windows error code;
/// [`Error::raw_os_error`] returns the underlying code. The enum is
/// `#[non_exhaustive]` so new variants can be added as more of the Windows
/// API surface is wrapped.
#[non_exhaustive]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // ── input validation (no OS error code) ────────────────────────────────
    #[error("input string contains an interior NUL, which cannot be passed to the Windows API")]
    InteriorNul,
    #[error("'{0}' is not a valid drive letter (expected A-Z)")]
    InvalidDriveLetter(char),

    // ── WNet connect/disconnect ────────────────────────────────────────────
    /// The caller does not have access to the network resource.
    #[error("access to the network resource was denied")]
    AccessDenied,
    /// The local device is already connected to a network resource.
    #[error("the local device is already connected to a network resource")]
    AlreadyAssigned,
    /// The type of the local device and the type of the network resource do
    /// not match (e.g. mounting a printer share on a drive letter).
    #[error("the local device type and the network resource type do not match")]
    BadDevType,
    /// Returned when the local device name names a device that cannot be
    /// redirected to a network resource.
    #[error("the specified device name is not valid")]
    BadDevice,
    /// Returned when no network resource provider accepts the remote name:
    /// it is empty, malformed, or names a resource that cannot be located.
    #[error("the network name cannot be found")]
    BadNetName,
    /// The user profile is in an incorrect format.
    #[error("the user profile is in an incorrect format")]
    BadProfile,
    /// Returned when the configured provider name does not match any network
    /// provider installed on the system.
    #[error("the specified network provider name is not valid")]
    BadProvider,
    /// The specified user name is not valid.
    #[error("the specified user name is not valid")]
    BadUsername,
    /// The router or provider is busy, possibly still initializing. The
    /// caller should retry.
    #[error("the router or provider is busy; retry the operation")]
    Busy,
    /// The connection attempt was canceled by the user through a provider
    /// dialog box, or by a called resource.
    #[error("the connection attempt was canceled")]
    Cancelled,
    /// The system is unable to open the user profile to process persistent
    /// connections.
    #[error("the user profile cannot be opened to process persistent connections")]
    CannotOpenProfile,
    /// Returned when the user profile already remembers a connection for this
    /// local device name that points to a different network resource.
    #[error("the local device name has a remembered connection to another network resource")]
    DeviceAlreadyRemembered,
    /// Returned when connecting with redirection (`CONNECT_REDIRECT`, see
    /// [`ConnectOptions::redirect`](crate::ConnectOptions::redirect)) without
    /// a local device name to redirect to.
    #[error("an attempt was made to access an invalid address")]
    InvalidAddress,
    /// A parameter is incorrect — for `WNet` connections, a resource type
    /// other than disk, print, or any, or an incorrect or unknown flag value.
    /// Also synthesized without a Windows call by
    /// [`server::delete_session`](crate::server::delete_session) when neither
    /// a client nor a user filter is given.
    #[error("a parameter is incorrect")]
    InvalidParameter,
    /// The specified password is invalid (and, for connects, the interactive
    /// flag is not set, so Windows could not prompt for a correct one).
    #[error("the specified password is invalid")]
    InvalidPassword,
    /// Logon failure because of an unknown user name or a bad password.
    #[error("logon failed: unknown user name or bad password")]
    LogonFailure,
    /// No network provider accepted the given network path — none of them
    /// recognized the remote name.
    #[error("no network provider accepted the given network path")]
    NoNetOrBadPath,
    /// The network is unavailable.
    #[error("the network is unavailable")]
    NoNetwork,
    /// Windows does not allow the same user to hold connections to one server
    /// or share under more than one user name. Disconnect all previous
    /// connections to the server or share and try again.
    #[error("a connection to the server or share already exists under different credentials")]
    SessionCredentialConflict,
    /// The device is in use by an active process and cannot be disconnected.
    #[error("the device is in use by an active process and cannot be disconnected")]
    DeviceInUse,
    /// The name is not a redirected device, or the system is not currently
    /// connected to it.
    #[error("the name is not a redirected device or a currently connected resource")]
    NotConnected,
    /// There are open files on the connection and the disconnect was not
    /// forced (see
    /// [`DisconnectOptions::force`](crate::DisconnectOptions::force)).
    #[error("there are open files and the disconnect was not forced")]
    OpenFiles,
    /// A network-specific error reported by the network provider, resolved via
    /// `WNetGetLastErrorW`. `code` is the provider's own error code.
    #[error(
        "a network-specific error occurred (code {code}): {description} [provider: {provider}]"
    )]
    ExtendedError {
        code: u32,
        description: String,
        provider: String,
    },

    // ── introspection ──────────────────────────────────────────────────────
    /// The device is not currently connected, but it is a remembered
    /// (persistent) connection.
    #[error("the device is not connected, but it is a remembered connection")]
    ConnectionUnavailable,
    /// The request is not supported for this resource.
    #[error("the request is not supported for this resource")]
    NotSupported,
    /// The specified device does not exist.
    #[error("the specified device does not exist")]
    DeviceNotFound,

    // ── netapi32 share/session/file administration ─────────────────────────
    /// The share name does not exist on the target server.
    #[error("the share name does not exist on this server")]
    NetNameNotFound,
    /// The share name is already in use on the target server.
    #[error("the share name is already in use on this server")]
    DuplicateShare,
    /// The device or directory backing the share does not exist.
    #[error("the device or directory does not exist")]
    UnknownDeviceOrDirectory,
    /// No session exists with the given computer name.
    #[error("no session exists with that computer name")]
    ClientNameNotFound,
    /// The user name could not be found.
    #[error("the user name could not be found")]
    UserNotFound,
    /// No open file with the given identification number exists.
    #[error("no open file with that identification number exists")]
    FileIdNotFound,
    /// The system call level is not correct — the requested information level
    /// is not supported.
    #[error("the requested information level is not supported")]
    InvalidLevel,
    /// Not enough memory is available to complete the operation.
    #[error("not enough memory is available to complete the operation")]
    NotEnoughMemory,

    /// Any status code without a dedicated variant. The message is resolved
    /// through the system message table where possible.
    #[error("Windows error {code}: {msg}", code = .0, msg = os_message(*.0))]
    Other(u32),
}

fn os_message(code: u32) -> String {
    #[allow(clippy::cast_possible_wrap)]
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

impl Error {
    /// Map a raw Windows / `NERR_*` status code to an [`Error`].
    ///
    /// `ERROR_EXTENDED_ERROR` is intentionally *not* resolved here — `WNet` call
    /// sites intercept it and fetch the provider details via
    /// [`wnet_extended_error`].
    pub(crate) fn from_status(code: u32) -> Self {
        match code {
            ERROR_ACCESS_DENIED => Self::AccessDenied,
            ERROR_ALREADY_ASSIGNED => Self::AlreadyAssigned,
            ERROR_BAD_DEV_TYPE => Self::BadDevType,
            ERROR_BAD_DEVICE => Self::BadDevice,
            ERROR_BAD_NET_NAME => Self::BadNetName,
            ERROR_BAD_PROFILE => Self::BadProfile,
            ERROR_BAD_PROVIDER => Self::BadProvider,
            ERROR_BAD_USERNAME => Self::BadUsername,
            ERROR_BUSY => Self::Busy,
            ERROR_CANCELLED => Self::Cancelled,
            ERROR_CANNOT_OPEN_PROFILE => Self::CannotOpenProfile,
            ERROR_CONNECTION_UNAVAIL => Self::ConnectionUnavailable,
            ERROR_DEV_NOT_EXIST => Self::DeviceNotFound,
            ERROR_DEVICE_ALREADY_REMEMBERED => Self::DeviceAlreadyRemembered,
            ERROR_DEVICE_IN_USE => Self::DeviceInUse,
            ERROR_INVALID_ADDRESS => Self::InvalidAddress,
            ERROR_INVALID_LEVEL => Self::InvalidLevel,
            ERROR_INVALID_PARAMETER => Self::InvalidParameter,
            ERROR_INVALID_PASSWORD => Self::InvalidPassword,
            ERROR_LOGON_FAILURE => Self::LogonFailure,
            ERROR_NOT_CONNECTED => Self::NotConnected,
            ERROR_NOT_ENOUGH_MEMORY => Self::NotEnoughMemory,
            ERROR_NOT_SUPPORTED => Self::NotSupported,
            ERROR_NO_NET_OR_BAD_PATH => Self::NoNetOrBadPath,
            ERROR_NO_NETWORK => Self::NoNetwork,
            ERROR_OPEN_FILES => Self::OpenFiles,
            ERROR_SESSION_CREDENTIAL_CONFLICT => Self::SessionCredentialConflict,
            NERR_CLIENT_NAME_NOT_FOUND => Self::ClientNameNotFound,
            NERR_DUPLICATE_SHARE => Self::DuplicateShare,
            NERR_FILE_ID_NOT_FOUND => Self::FileIdNotFound,
            NERR_NET_NAME_NOT_FOUND => Self::NetNameNotFound,
            NERR_UNKNOWN_DEV_DIR => Self::UnknownDeviceOrDirectory,
            NERR_USER_NOT_FOUND => Self::UserNotFound,
            other => Self::Other(other),
        }
    }

    /// The Windows error code this error corresponds to.
    ///
    /// Returns `None` for input-validation errors that have no Windows code
    /// ([`Error::InteriorNul`], [`Error::InvalidDriveLetter`]). The code
    /// usually comes from a failed Windows API call, but sambrs synthesizes
    /// [`Error::InvalidParameter`] for some rejected inputs (see
    /// [`server::delete_session`](crate::server::delete_session)); it still
    /// reports the matching `ERROR_INVALID_PARAMETER`. For
    /// [`Error::ExtendedError`] this is `ERROR_EXTENDED_ERROR` (1208); the
    /// provider-specific code is in the variant itself.
    #[must_use]
    pub fn raw_os_error(&self) -> Option<u32> {
        match self {
            Self::InteriorNul | Self::InvalidDriveLetter(_) => None,
            Self::AccessDenied => Some(ERROR_ACCESS_DENIED),
            Self::AlreadyAssigned => Some(ERROR_ALREADY_ASSIGNED),
            Self::BadDevType => Some(ERROR_BAD_DEV_TYPE),
            Self::BadDevice => Some(ERROR_BAD_DEVICE),
            Self::BadNetName => Some(ERROR_BAD_NET_NAME),
            Self::BadProfile => Some(ERROR_BAD_PROFILE),
            Self::BadProvider => Some(ERROR_BAD_PROVIDER),
            Self::BadUsername => Some(ERROR_BAD_USERNAME),
            Self::Busy => Some(ERROR_BUSY),
            Self::Cancelled => Some(ERROR_CANCELLED),
            Self::CannotOpenProfile => Some(ERROR_CANNOT_OPEN_PROFILE),
            Self::ConnectionUnavailable => Some(ERROR_CONNECTION_UNAVAIL),
            Self::DeviceNotFound => Some(ERROR_DEV_NOT_EXIST),
            Self::DeviceAlreadyRemembered => Some(ERROR_DEVICE_ALREADY_REMEMBERED),
            Self::DeviceInUse => Some(ERROR_DEVICE_IN_USE),
            Self::ExtendedError { .. } => Some(ERROR_EXTENDED_ERROR),
            Self::InvalidAddress => Some(ERROR_INVALID_ADDRESS),
            Self::InvalidLevel => Some(ERROR_INVALID_LEVEL),
            Self::InvalidParameter => Some(ERROR_INVALID_PARAMETER),
            Self::InvalidPassword => Some(ERROR_INVALID_PASSWORD),
            Self::LogonFailure => Some(ERROR_LOGON_FAILURE),
            Self::NotConnected => Some(ERROR_NOT_CONNECTED),
            Self::NotEnoughMemory => Some(ERROR_NOT_ENOUGH_MEMORY),
            Self::NotSupported => Some(ERROR_NOT_SUPPORTED),
            Self::NoNetOrBadPath => Some(ERROR_NO_NET_OR_BAD_PATH),
            Self::NoNetwork => Some(ERROR_NO_NETWORK),
            Self::OpenFiles => Some(ERROR_OPEN_FILES),
            Self::SessionCredentialConflict => Some(ERROR_SESSION_CREDENTIAL_CONFLICT),
            Self::ClientNameNotFound => Some(NERR_CLIENT_NAME_NOT_FOUND),
            Self::DuplicateShare => Some(NERR_DUPLICATE_SHARE),
            Self::FileIdNotFound => Some(NERR_FILE_ID_NOT_FOUND),
            Self::NetNameNotFound => Some(NERR_NET_NAME_NOT_FOUND),
            Self::UnknownDeviceOrDirectory => Some(NERR_UNKNOWN_DEV_DIR),
            Self::UserNotFound => Some(NERR_USER_NOT_FOUND),
            Self::Other(code) => Some(*code),
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e.raw_os_error() {
            #[allow(clippy::cast_possible_wrap)]
            Some(code) => Self::from_raw_os_error(code as i32),
            None => Self::new(std::io::ErrorKind::InvalidInput, e),
        }
    }
}

/// Turn a `WNet` status code into a `Result`, resolving `ERROR_EXTENDED_ERROR`
/// into the provider-specific error details.
pub(crate) fn check_wnet(status: u32) -> Result<()> {
    match status {
        NO_ERROR => Ok(()),
        ERROR_EXTENDED_ERROR => Err(wnet_extended_error()),
        code => Err(Error::from_status(code)),
    }
}

/// Turn a netapi32 status code into a `Result`.
pub(crate) fn check_net(status: u32) -> Result<()> {
    if status == NERR_SUCCESS {
        Ok(())
    } else {
        Err(Error::from_status(status))
    }
}

/// Fetch the provider-specific error behind `ERROR_EXTENDED_ERROR` via
/// `WNetGetLastErrorW`. Must be called on the same thread that received the
/// failing status, before any other `WNet` call.
pub(crate) fn wnet_extended_error() -> Error {
    let mut code = 0u32;
    let mut description = [0u16; 512];
    let mut provider = [0u16; 256];
    let status = unsafe {
        WNet::WNetGetLastErrorW(
            &raw mut code,
            description.as_mut_ptr(),
            crate::strings::len_u32(description.len()),
            provider.as_mut_ptr(),
            crate::strings::len_u32(provider.len()),
        )
    };
    if status == NO_ERROR {
        Error::ExtendedError {
            code,
            description: crate::strings::from_wide_buf(&description),
            provider: crate::strings::from_wide_buf(&provider),
        }
    } else {
        Error::ExtendedError {
            code: 0,
            description: String::from("<provider error details unavailable>"),
            provider: String::new(),
        }
    }
}
