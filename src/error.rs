use std::ffi::NulError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Failed to convert share to CString")]
    CStringConversion(#[from] NulError),

    #[error("The caller does not have access to the network resource.")]
    AccessDenied,
    #[error(
        "The local device specified by the lpLocalName member is already connected to a network resource."
    )]
    AlreadyAssigned,
    #[error("The type of local device and the type of network resource do not match.")]
    BadDevType,
    #[error(
        "The specified device name is not valid. This error is returned if the lpLocalName member of the NETRESOURCE structure pointed to by the lpNetResource parameter specifies a device that is not redirectable."
    )]
    BadDevice,
    #[error(
        "The network name cannot be found. This value is returned if the lpRemoteName member of the NETRESOURCE structure pointed to by the lpNetResource parameter specifies a resource that is not acceptable to any network resource provider, either because the resource name is empty, not valid, or because the named resource cannot be located."
    )]
    BadNetName,
    #[error("The user profile is in an incorrect format.")]
    BadProfile,
    #[error(
        "The specified network provider name is not valid. This error is returned if the lpProvider member of the NETRESOURCE structure pointed to by the lpNetResource parameter specifies a value that does not match any network provider."
    )]
    BadProvider,
    #[error("The specified user name is not valid.")]
    BadUsername,
    #[error("The router or provider is busy, possibly initializing. The caller should retry.")]
    Busy,
    #[error(
        "The attempt to make the connection was canceled by the user through a dialog box from one of the network resource providers, or by a called resource."
    )]
    Cancelled,
    #[error("The system is unable to open the user profile to process persistent connections.")]
    CannotOpenProfile,
    #[error(
        "The local device name has a remembered connection to another network resource. This error is returned if an entry for the device specified by lpLocalName member of the NETRESOURCE structure pointed to by the lpNetResource parameter specifies a value that is already in the user profile for a different connection than that specified in the lpNetResource parameter."
    )]
    DeviceAlreadyRemembered,
    #[error(
        "A network-specific error occurred. Call the WNetGetLastError function to obtain a description of the error."
    )]
    ExtendedError,
    #[error(
        "An attempt was made to access an invalid address. This error is returned if the dwFlags parameter specifies a value of CONNECT_REDIRECT, but the lpLocalName member of the NETRESOURCE structure pointed to by the lpNetResource parameter was unspecified."
    )]
    InvalidAddress,
    #[error(
        "A parameter is incorrect. This error is returned if the dwType member of the NETRESOURCE structure pointed to by the lpNetResource parameter specifies a value other than RESOURCETYPE_DISK, RESOURCETYPE_PRINT, or RESOURCETYPE_ANY. This error is also returned if the dwFlags parameter specifies an incorrect or unknown value."
    )]
    InvalidParameter,
    #[error("The specified password is invalid and the CONNECT_INTERACTIVE flag is not set.")]
    InvalidPassword,
    #[error("A logon failure because of an unknown user name or a bad password.")]
    LogonFailure,
    #[error(
        "No network provider accepted the given network path. This error is returned if no network provider recognized the lpRemoteName member of the NETRESOURCE structure pointed to by the lpNetResource parameter."
    )]
    NoNetOrBadPath,
    #[error("The network is unavailable.")]
    NoNetwork,
    #[error("The device is in use by an active process and cannot be disconnected.")]
    DeviceInUse,
    #[error(
        "The name specified by the lpName parameter is not a redirected device, or the system is not currently connected to the device specified by the parameter."
    )]
    NotConnected,
    #[error("There are open files, and the fForce parameter is FALSE.")]
    OpenFiles,
    #[error("Unknown error.")]
    Other,
}
