use windows_sys::Win32::Foundation::{ERROR_EXTENDED_ERROR, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::NERR_Success as NERR_SUCCESS;
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
    /// A Windows or `NERR_*` status code.
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
    use windows_sys::Win32::NetworkManagement::NetManagement::{MAX_NERR, NERR_BASE};

    // NERR_* messages live in netmsg.dll's message table, which the system
    // table behind `from_raw_os_error` cannot see (it would show an
    // unknown-error placeholder for them).
    if (NERR_BASE..=MAX_NERR).contains(&code) {
        if let Some(msg) = netmsg_message(code) {
            return msg;
        }
    }
    #[allow(clippy::cast_possible_wrap)]
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

/// Look up a message in netmsg.dll's message table; `None` when the module
/// or the message is unavailable (the caller then falls back to the system
/// message table).
fn netmsg_message(code: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
    };
    use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_AS_DATAFILE, LoadLibraryExW};

    let netmsg = crate::strings::to_wide("netmsg.dll").ok()?;
    // SAFETY: `netmsg` is a valid nul-terminated string; the returned module
    // handle is freed below, after the message has been copied out of it.
    let module = unsafe {
        LoadLibraryExW(
            netmsg.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_AS_DATAFILE,
        )
    };
    if module.is_null() {
        return None;
    }
    let mut buf = [0u16; 512];
    // SAFETY: `module` stays valid and `buf` outlives the call;
    // IGNORE_INSERTS guarantees the null `arguments` is never read.
    let len = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
            module,
            code,
            0, // default language search order
            buf.as_mut_ptr(),
            crate::strings::len_u32(buf.len()),
            std::ptr::null(),
        )
    };
    // SAFETY: `module` came from LoadLibraryExW and is freed exactly once.
    unsafe {
        FreeLibrary(module);
    }
    // Messages end with "\r\n"; io::Error's Display doesn't have trailing
    // whitespace either.
    (len > 0).then(|| crate::strings::from_wide_buf(&buf).trim_end().to_string())
}

impl Error {
    pub(crate) fn from_status(code: u32) -> Self {
        Self::Windows(code)
    }

    /// The underlying Windows status code, if this error has one.
    #[must_use]
    pub fn raw_os_error(&self) -> Option<u32> {
        match self {
            Self::Windows(code) => Some(*code),
            Self::ExtendedError { .. } => Some(ERROR_EXTENDED_ERROR),
            Self::InteriorNul | Self::InvalidDriveLetter(_) => None,
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        match error {
            #[allow(clippy::cast_possible_wrap)]
            Error::Windows(code) => Self::from_raw_os_error(code as i32),
            Error::ExtendedError { .. } => Self::other(error),
            Error::InteriorNul | Error::InvalidDriveLetter(_) => {
                Self::new(std::io::ErrorKind::InvalidInput, error)
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    #[test]
    fn io_error_conversion_keeps_extended_error_details() {
        let e = Error::ExtendedError {
            code: 59,
            description: String::from("the provider says no"),
            provider: String::from("Test Provider"),
        };
        let io: std::io::Error = e.into();
        assert_eq!(io.raw_os_error(), None);
        let msg = io.to_string();
        assert!(msg.contains("59"), "provider code lost: {msg}");
        assert!(
            msg.contains("the provider says no"),
            "description lost: {msg}"
        );
        assert!(msg.contains("Test Provider"), "provider name lost: {msg}");
    }

    #[test]
    fn io_error_conversion_maps_windows_codes() {
        let io: std::io::Error = Error::Windows(ERROR_ACCESS_DENIED).into();
        #[allow(clippy::cast_possible_wrap)]
        {
            assert_eq!(io.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
        }
    }

    #[test]
    fn io_error_conversion_flags_input_validation_errors() {
        let io: std::io::Error = Error::InteriorNul.into();
        assert_eq!(io.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn windows_error_resolves_nerr_messages_from_netmsg_dll() {
        // NERR_NetNotStarted (2102) has no system-table message; it must
        // come from netmsg.dll. The text is locale-dependent, so assert only
        // that a message was found and that Error's Display uses it.
        let msg = netmsg_message(2102).expect("netmsg.dll must resolve NERR codes");
        assert!(!msg.is_empty());
        assert!(Error::Windows(2102).to_string().contains(&msg));
    }
}
