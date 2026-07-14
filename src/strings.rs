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

/// A nul-terminated UTF-16 buffer that is wiped on drop.
pub(crate) type WideSecret = zeroize::Zeroizing<Vec<u16>>;

/// Pointer to an optional wide string, or null when absent.
///
/// The caller must keep the owning buffer alive for as long as the returned
/// pointer is in use.
pub(crate) fn opt_ptr(buf: Option<&[u16]>) -> *const u16 {
    buf.map_or(std::ptr::null(), <[u16]>::as_ptr)
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

/// Buffer length as `u32` for Windows APIs; saturates instead of panicking.
pub(crate) fn len_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_wide_converts_and_validates() {
        assert_eq!(to_wide("ab").unwrap(), vec![97, 98, 0]);
        assert_eq!(to_wide("ü").unwrap(), vec![0xFC, 0]);
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
