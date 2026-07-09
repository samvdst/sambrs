//! Internal UTF-16 string helpers shared by every module that talks to the
//! wide (`W`) variants of the Windows API.

use crate::{Error, Result};

/// Encode a `&str` as a nul-terminated UTF-16 buffer.
///
/// The buffer is allocated with its final capacity up front so no intermediate
/// heap copy of the data is left behind (relevant for the `zeroize` feature).
/// The interior-NUL check runs on the `&str` before any allocation — a non-NUL
/// char never encodes to a 0 UTF-16 unit, so it is equivalent to scanning the
/// encoded buffer — which keeps the error path free of transient copies too.
pub(crate) fn to_wide(s: &str) -> Result<Vec<u16>> {
    if s.contains('\0') {
        return Err(Error::InteriorNul);
    }
    // A UTF-16 encoding never has more code units than the UTF-8 encoding has
    // bytes, so this capacity guarantees a single allocation.
    let mut wide: Vec<u16> = Vec::with_capacity(s.len() + 1);
    wide.extend(s.encode_utf16());
    wide.push(0);
    Ok(wide)
}

/// A nul-terminated UTF-16 buffer that is wiped on drop when the `zeroize`
/// feature is enabled.
#[cfg(feature = "zeroize")]
pub(crate) type WideSecret = zeroize::Zeroizing<Vec<u16>>;
#[cfg(not(feature = "zeroize"))]
pub(crate) type WideSecret = Vec<u16>;

/// Encode a secret (password) as a nul-terminated UTF-16 buffer.
pub(crate) fn to_wide_secret(s: &str) -> Result<WideSecret> {
    #[cfg(feature = "zeroize")]
    {
        to_wide(s).map(zeroize::Zeroizing::new)
    }
    #[cfg(not(feature = "zeroize"))]
    {
        to_wide(s)
    }
}

/// Pointer to an optional wide string, or null when absent.
///
/// The caller must keep the owning buffer alive for as long as the returned
/// pointer is in use.
pub(crate) fn opt_ptr(buf: Option<&[u16]>) -> *mut u16 {
    buf.map_or(std::ptr::null_mut(), |b| b.as_ptr().cast_mut())
}

/// Owned `String` from a wide buffer, up to the first nul (or the full buffer
/// if it contains none).
pub(crate) fn from_wide_buf(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Owned `String` from a nul-terminated wide pointer; `None` when null.
///
/// # Safety
/// `ptr` must either be null or point to a valid nul-terminated UTF-16 string.
pub(crate) unsafe fn from_pwstr(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: the caller guarantees a valid nul-terminated string.
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(
            ptr, len,
        )))
    }
}

/// Pointer to an optional secret wide string, or null when absent.
///
/// The caller must keep the owning buffer alive for as long as the returned
/// pointer is in use. (A `match` rather than a closure so the body works for
/// both `Vec<u16>` and `Zeroizing<Vec<u16>>` via auto-deref.)
pub(crate) fn secret_ptr(buf: Option<&WideSecret>) -> *const u16 {
    match buf {
        Some(b) => b.as_ptr(),
        None => std::ptr::null(),
    }
}

/// Buffer length as `u32` for Windows APIs; saturates instead of panicking.
pub(crate) fn len_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_wide_appends_nul() {
        assert_eq!(to_wide("ab").unwrap(), vec![97, 98, 0]);
    }

    #[test]
    fn to_wide_handles_non_ascii() {
        // 'ü' is a single UTF-16 code unit but two UTF-8 bytes.
        assert_eq!(to_wide("ü").unwrap(), vec![0xFC, 0]);
    }

    #[test]
    fn to_wide_rejects_interior_nul() {
        assert_eq!(to_wide("a\0b").unwrap_err(), Error::InteriorNul);
    }

    #[test]
    fn from_wide_buf_stops_at_nul() {
        assert_eq!(from_wide_buf(&[97, 98, 0, 99]), "ab");
        assert_eq!(from_wide_buf(&[97, 98]), "ab");
    }

    #[test]
    fn from_pwstr_roundtrip() {
        let wide = to_wide("hello").unwrap();
        assert_eq!(
            unsafe { from_pwstr(wide.as_ptr()) }.as_deref(),
            Some("hello")
        );
        assert_eq!(unsafe { from_pwstr(std::ptr::null()) }, None);
    }
}
