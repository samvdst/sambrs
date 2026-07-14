//! Enumerate network resources via `WNetOpenEnumW` / `WNetEnumResourceW`:
//! active connections, remembered (persistent) connections, and the shares a
//! server exposes.
//!
//! ```no_run
//! // Everything \\fileserver offers:
//! for resource in sambrs::enumerate::server_shares(r"\\fileserver")? {
//!     println!("{:?}", resource?.remote_name);
//! }
//! # Ok::<(), sambrs::Error>(())
//! ```

use crate::error::{Error, Result, check_wnet, wnet_extended_error};
use crate::strings::{from_pwstr, len_u32, to_wide};
use tracing::{debug, trace};
use windows_sys::Win32::Foundation::{
    ERROR_EXTENDED_ERROR, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, HANDLE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::WNet;

/// An owned snapshot of one disk-share resource.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetResource {
    /// Local drive when this entry is a mapped connection, e.g. `"Z:"`.
    pub local_name: Option<String>,
    /// Remote name, e.g. `\\server\share`.
    pub remote_name: Option<String>,
}

/// Iterator over enumerated [`NetResource`] entries. Closes the enumeration
/// handle on drop.
#[derive(Debug)]
pub struct Resources {
    handle: HANDLE,
    /// Enumeration buffer, reused with any growth between resources; `u64`
    /// elements keep it `NETRESOURCEW`-aligned.
    buf: Vec<u64>,
    finished: bool,
}

impl Iterator for Resources {
    type Item = Result<NetResource>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        // Bounded retries as a defensive measure against a misbehaving
        // provider that keeps demanding a bigger buffer (mirrors the cap in
        // `query::wide_out`).
        for _ in 0..4 {
            let mut count = 1u32;
            let mut size = len_u32(self.buf.len() * size_of::<u64>());
            // SAFETY: `self.buf` outlives the call; `size` is its size in
            // bytes.
            let status = unsafe {
                WNet::WNetEnumResourceW(
                    self.handle,
                    &raw mut count,
                    self.buf.as_mut_ptr().cast(),
                    &raw mut size,
                )
            };
            debug!("WNetEnumResourceW returned {status} (entries={count}, bytes={size})");
            match status {
                NO_ERROR if count == 0 => {
                    trace!("zero-entry success; treating as end of enumeration");
                    self.finished = true;
                    return None;
                }
                NO_ERROR => {
                    // SAFETY: on success the buffer starts with one
                    // NETRESOURCEW; its strings live in `self.buf` and are
                    // copied before the buffer is reused.
                    let resource = unsafe {
                        let raw = &*self.buf.as_ptr().cast::<WNet::NETRESOURCEW>();
                        NetResource {
                            local_name: from_pwstr(raw.lpLocalName),
                            remote_name: from_pwstr(raw.lpRemoteName),
                        }
                    };
                    return Some(Ok(resource));
                }
                ERROR_NO_MORE_ITEMS => {
                    self.finished = true;
                    return None;
                }
                // Buffer too small for a single entry; `size` holds the
                // required size in bytes.
                ERROR_MORE_DATA => {
                    self.buf = vec![0u64; (size as usize).div_ceil(size_of::<u64>())];
                }
                ERROR_EXTENDED_ERROR => {
                    self.finished = true;
                    return Some(Err(wnet_extended_error()));
                }
                code => {
                    self.finished = true;
                    return Some(Err(Error::Windows(code)));
                }
            }
        }
        self.finished = true;
        Some(Err(Error::Windows(ERROR_MORE_DATA)))
    }
}

impl Drop for Resources {
    fn drop(&mut self) {
        // SAFETY: the handle came from WNetOpenEnumW and is closed only here.
        let status = unsafe { WNet::WNetCloseEnum(self.handle) };
        debug!("WNetCloseEnum returned {status}");
    }
}

fn open(scope: u32, root_remote: Option<&str>) -> Result<Resources> {
    let remote = root_remote.map(to_wide).transpose()?;
    let root = remote.as_ref().map(|remote| WNet::NETRESOURCEW {
        dwUsage: WNet::RESOURCEUSAGE_CONTAINER,
        lpRemoteName: remote.as_ptr().cast_mut(),
        ..Default::default()
    });

    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: `root` (when present) and its string live until after the call.
    let status = unsafe {
        WNet::WNetOpenEnumW(
            scope,
            WNet::RESOURCETYPE_DISK,
            0,
            root.as_ref().map_or(std::ptr::null(), std::ptr::from_ref),
            &raw mut handle,
        )
    };
    debug!("WNetOpenEnumW returned {status}");
    check_wnet(status)?;
    Ok(Resources {
        handle,
        buf: vec![0u64; 2048], // 16 KiB to start; grows on demand
        finished: false,
    })
}

/// Currently connected resources (`RESOURCE_CONNECTED`) — every active
/// redirection and deviceless connection of the calling user.
///
/// # Errors
/// See [`Error`].
pub fn connections() -> Result<Resources> {
    trace!("enumerating active disk-share connections");
    open(WNet::RESOURCE_CONNECTED, None)
}

/// Remembered (persistent) connections (`RESOURCE_REMEMBERED`) — restored at
/// logon whether or not they are currently connected.
///
/// # Errors
/// See [`Error`].
pub fn remembered() -> Result<Resources> {
    trace!("enumerating remembered disk-share mappings");
    open(WNet::RESOURCE_REMEMBERED, None)
}

/// The disk shares a server exposes (`RESOURCE_GLOBALNET` rooted at `server`,
/// e.g. `r"\\fileserver"`).
///
/// The server may require an authenticated connection (e.g. to `IPC$`)
/// before it lets you enumerate.
///
/// # Errors
/// `ERROR_BAD_NET_NAME` / `ERROR_NO_NET_OR_BAD_PATH` when the server cannot
/// be found, or `ERROR_ACCESS_DENIED` when it refuses anonymous enumeration.
pub fn server_shares(server: &str) -> Result<Resources> {
    trace!("enumerating disk shares on {server}");
    open(WNet::RESOURCE_GLOBALNET, Some(server))
}
