use windows_sys::Win32::Foundation::{
    ERROR_ACCOUNT_DISABLED, ERROR_ACCOUNT_EXPIRED, ERROR_ACCOUNT_LOCKED_OUT,
    ERROR_ACCOUNT_RESTRICTION, ERROR_EXTENDED_ERROR, ERROR_INVALID_PASSWORD, ERROR_LOGON_FAILURE,
    ERROR_PASSWORD_EXPIRED, ERROR_PASSWORD_MUST_CHANGE, NO_ERROR,
};
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

impl Error {
    /// The Windows status code behind an [`Error::Windows`], or `None` for
    /// every other variant. Provider-specific codes stay on
    /// [`Error::ExtendedError`].
    #[must_use]
    pub fn code(&self) -> Option<u32> {
        match self {
            Self::Windows(code) => Some(*code),
            _ => None,
        }
    }

    /// Whether Windows rejected the credentials themselves: a wrong password,
    /// or an account that is locked out, disabled, expired, restricted, or
    /// whose password has expired or must change.
    ///
    /// Do not retry a rejected credential. Each attempt counts as another
    /// failed logon and can lock the account out. Wait for the credential to
    /// change instead. Transient failures (unreachable server, session
    /// conflicts, and so on) return `false`.
    #[must_use]
    pub fn is_credential_rejected(&self) -> bool {
        matches!(
            self.code(),
            Some(
                ERROR_INVALID_PASSWORD
                    | ERROR_LOGON_FAILURE
                    | ERROR_ACCOUNT_RESTRICTION
                    | ERROR_PASSWORD_EXPIRED
                    | ERROR_ACCOUNT_DISABLED
                    | ERROR_ACCOUNT_EXPIRED
                    | ERROR_PASSWORD_MUST_CHANGE
                    | ERROR_ACCOUNT_LOCKED_OUT
            )
        )
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
    tracing::debug!(
        operation = "WNetGetLastErrorW",
        status,
        provider_code = code,
        "WNet call returned"
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_keep_their_code_and_classify_credential_rejection() {
        assert_eq!(check_wnet(NO_ERROR), Ok(()));
        for (code, rejected) in [
            (86, true),    // invalid password
            (1326, true),  // logon failure
            (1327, true),  // account restriction
            (1330, true),  // password expired
            (1331, true),  // account disabled
            (1793, true),  // account expired
            (1907, true),  // password must change
            (1909, true),  // account locked out
            (53, false),   // bad net path
            (1219, false), // session credential conflict
            (2250, false), // not connected
            (1234, false), // unlisted
        ] {
            let error = check_wnet(code).unwrap_err();
            assert_eq!(error, Error::Windows(code));
            assert_eq!(error.code(), Some(code));
            assert_eq!(error.is_credential_rejected(), rejected, "code {code}");
            assert!(error.to_string().contains(&code.to_string()));
        }
        assert_eq!(Error::InteriorNul.code(), None);
        assert!(!Error::InteriorNul.is_credential_rejected());
    }
}
