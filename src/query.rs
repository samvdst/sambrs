//! Query information about existing connections: which remote a device is
//! mapped to, which user a connection runs as, and UNC paths for local paths
//! on redirected drives.

use crate::error::{Error, Result, wnet_extended_error};
use crate::strings::{from_pwstr, len_u32, opt_ptr, to_wide};
use crate::trace::{debug, trace};
use windows_sys::Win32::Foundation::{ERROR_EXTENDED_ERROR, ERROR_MORE_DATA, NO_ERROR};
use windows_sys::Win32::NetworkManagement::WNet;

/// Call a `WNet` function that fills a wide-string output buffer, growing the
/// buffer when Windows reports `ERROR_MORE_DATA`.
fn wide_out(operation: &str, mut call: impl FnMut(*mut u16, *mut u32) -> u32) -> Result<String> {
    let mut buf = vec![0u16; 256];
    for _ in 0..4 {
        let mut len = len_u32(buf.len());
        let status = call(buf.as_mut_ptr(), &raw mut len);
        debug!("{operation} returned {status}");
        match status {
            NO_ERROR => return Ok(crate::strings::from_wide_buf(&buf)),
            // `len` now holds the required size in characters.
            ERROR_MORE_DATA => buf = vec![0u16; len as usize + 1],
            ERROR_EXTENDED_ERROR => return Err(wnet_extended_error()),
            code => return Err(Error::Windows(code)),
        }
    }
    Err(Error::Windows(ERROR_MORE_DATA))
}

/// The remote name a mapped drive is connected to, via `WNetGetConnectionW`.
///
/// ```no_run
/// let remote = sambrs::query::get_connection("Z:")?;
/// assert_eq!(remote, r"\\server\share");
/// # Ok::<(), sambrs::Error>(())
/// ```
///
/// # Errors
/// `ERROR_NOT_CONNECTED` if the device is not redirected,
/// `ERROR_CONNECTION_UNAVAIL` if it is remembered but not currently
/// connected, or `ERROR_BAD_DEVICE` for an invalid device name.
pub fn get_connection(drive: &str) -> Result<String> {
    trace!("querying remote share mapped to {drive}");
    let device = to_wide(drive)?;
    // SAFETY: `device` outlives the call; the buffer is sized via `len`.
    wide_out("WNetGetConnectionW", |buf, len| unsafe {
        WNet::WNetGetConnectionW(device.as_ptr(), buf, len)
    })
}

/// The user name used to establish a connection, via `WNetGetUserW`.
///
/// `connection` is a local device (`"Z:"`) or a remote name; `None` returns
/// the name of the current user of the process.
///
/// # Errors
/// `ERROR_NOT_CONNECTED` if the name is not a connected resource.
pub fn get_user(connection: Option<&str>) -> Result<String> {
    trace!(
        "querying user for {}",
        connection.unwrap_or("<current process>")
    );
    let name = connection.map(to_wide).transpose()?;
    // SAFETY: `name` (when present) outlives the call.
    let user = wide_out("WNetGetUserW", |buf, len| unsafe {
        WNet::WNetGetUserW(opt_ptr(name.as_deref()), buf, len)
    })?;
    debug!("WNetGetUserW resolved user {user}");
    Ok(user)
}

/// The UNC path for a local path on a redirected drive, via
/// `WNetGetUniversalNameW`. For example `Z:\dir\file.txt` becomes
/// `\\server\share\dir\file.txt`.
///
/// # Errors
/// `ERROR_NOT_SUPPORTED` or `ERROR_NOT_CONNECTED` when the path is not on a
/// network-redirected device.
pub fn get_universal_name(local_path: &str) -> Result<String> {
    trace!("resolving universal name for mapped path");
    let path = to_wide(local_path)?;
    // u64 elements keep the buffer aligned for UNIVERSAL_NAME_INFOW.
    let mut buf = vec![0u64; 128];
    for _ in 0..4 {
        let mut size = len_u32(buf.len() * size_of::<u64>());
        // SAFETY: `path` and `buf` outlive the call; `size` tells Windows the
        // buffer size in bytes.
        let status = unsafe {
            WNet::WNetGetUniversalNameW(
                path.as_ptr(),
                WNet::UNIVERSAL_NAME_INFO_LEVEL,
                buf.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        debug!("WNetGetUniversalNameW returned {status}");
        match status {
            NO_ERROR => {
                // SAFETY: on success the buffer starts with a
                // UNIVERSAL_NAME_INFOW whose string pointer points into `buf`.
                let name = unsafe {
                    let info = &*buf.as_ptr().cast::<WNet::UNIVERSAL_NAME_INFOW>();
                    from_pwstr(info.lpUniversalName)
                };
                return Ok(name.unwrap_or_default());
            }
            // `size` now holds the required size in bytes.
            ERROR_MORE_DATA => buf = vec![0u64; (size as usize).div_ceil(size_of::<u64>())],
            ERROR_EXTENDED_ERROR => return Err(wnet_extended_error()),
            code => return Err(Error::Windows(code)),
        }
    }
    Err(Error::Windows(ERROR_MORE_DATA))
}
