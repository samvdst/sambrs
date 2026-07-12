use windows_sys::Win32::Foundation::{ERROR_EXTENDED_ERROR, NO_ERROR};
use windows_sys::Win32::NetworkManagement::WNet;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by sambrs operations.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input contains an interior NUL and cannot cross the Windows API boundary.
    InteriorNul,
    /// The character is not an ASCII drive letter.
    InvalidDriveLetter(char),
    /// Persistence was requested without a local drive mapping.
    PersistenceRequiresDrive,
    /// A guarded connection was requested without a local drive mapping.
    GuardRequiresDrive,
    /// A guarded connection was configured to persist beyond the guard's lifetime.
    PersistentGuard,
    /// Forgetting was requested for a connection without a local drive mapping.
    ForgetRequiresDrive,
    /// A Windows status code.
    Windows(u32),
    /// A provider-specific error resolved through `WNetGetLastErrorW`.
    ExtendedError {
        code: u32,
        description: String,
        provider: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InteriorNul => f.write_str(
                "input string contains an interior NUL, which cannot be passed to the Windows API",
            ),
            Self::InvalidDriveLetter(c) => {
                write!(f, "'{c}' is not a valid drive letter (expected A-Z)")
            }
            Self::PersistenceRequiresDrive => {
                f.write_str("persistent SMB connections require a drive mapping")
            }
            Self::GuardRequiresDrive => {
                f.write_str("a guarded SMB connection requires a drive mapping")
            }
            Self::PersistentGuard => f.write_str("a guarded SMB connection cannot be persistent"),
            Self::ForgetRequiresDrive => f.write_str("only a drive mapping can be forgotten"),
            Self::Windows(code) => write!(f, "Windows error {code}: {}", os_message(*code)),
            Self::ExtendedError {
                code,
                description,
                provider,
            } => write!(
                f,
                "a network-specific error occurred (code {code}): {description} [provider: {provider}]"
            ),
        }
    }
}

impl std::error::Error for Error {}

fn os_message(code: u32) -> String {
    #[allow(clippy::cast_possible_wrap)]
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

/// Turn a `WNet` status code into a `Result`, resolving `ERROR_EXTENDED_ERROR`
/// into the provider-specific error details.
pub(crate) fn check_wnet(status: u32) -> Result<()> {
    match status {
        NO_ERROR => Ok(()),
        ERROR_EXTENDED_ERROR => Err(wnet_extended_error()),
        code => Err(Error::Windows(code)),
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
    tracing::debug!("WNetGetLastErrorW returned {status} (provider status {code})");
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
