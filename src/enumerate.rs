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

use crate::error::{Error, Result, wnet_extended_error};
use crate::strings::{from_pwstr, len_u32, to_wide};
use crate::trace::trace;
use std::collections::VecDeque;
use windows_sys::Win32::Foundation::{
    ERROR_EXTENDED_ERROR, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, HANDLE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::WNet;

/// An owned snapshot of one `NETRESOURCEW` entry.
///
/// The `scope`, `resource_type`, `display_type`, and `usage` fields carry the
/// raw `RESOURCE_*`, `RESOURCETYPE_*`, `RESOURCEDISPLAYTYPE_*`, and
/// `RESOURCEUSAGE_*` values from `winnetwk.h` (available as constants in
/// `windows_sys::Win32::NetworkManagement::WNet`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetResource {
    pub scope: u32,
    pub resource_type: u32,
    pub display_type: u32,
    pub usage: u32,
    /// Local device when this entry is a redirected connection, e.g. `"Z:"`.
    pub local_name: Option<String>,
    /// Remote name, e.g. `\\server\share`.
    pub remote_name: Option<String>,
    pub comment: Option<String>,
    pub provider: Option<String>,
}

impl NetResource {
    /// Whether this resource is a container (server, domain) that can itself
    /// be enumerated.
    #[must_use]
    pub fn is_container(&self) -> bool {
        self.usage & WNet::RESOURCEUSAGE_CONTAINER != 0
    }

    /// Whether this resource can be connected to.
    #[must_use]
    pub fn is_connectable(&self) -> bool {
        self.usage & WNet::RESOURCEUSAGE_CONNECTABLE != 0
    }

    fn from_raw(raw: &WNet::NETRESOURCEW) -> Self {
        // SAFETY: the pointers in a NETRESOURCEW returned by
        // WNetEnumResourceW are either null or valid nul-terminated strings
        // within the enumeration buffer, which is alive for this call.
        unsafe {
            Self {
                scope: raw.dwScope,
                resource_type: raw.dwType,
                display_type: raw.dwDisplayType,
                usage: raw.dwUsage,
                local_name: from_pwstr(raw.lpLocalName),
                remote_name: from_pwstr(raw.lpRemoteName),
                comment: from_pwstr(raw.lpComment),
                provider: from_pwstr(raw.lpProvider),
            }
        }
    }
}

/// Iterator over enumerated [`NetResource`] entries. Closes the enumeration
/// handle on drop.
#[derive(Debug)]
pub struct Resources {
    handle: HANDLE,
    batch: VecDeque<NetResource>,
    finished: bool,
}

impl Iterator for Resources {
    type Item = Result<NetResource>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(resource) = self.batch.pop_front() {
                return Some(Ok(resource));
            }
            if self.finished {
                return None;
            }
            if let Err(e) = self.fill() {
                self.finished = true;
                return Some(Err(e));
            }
        }
    }
}

impl Resources {
    fn fill(&mut self) -> Result<()> {
        // 16 KiB, u64 elements to keep NETRESOURCEW-aligned.
        let mut buf = vec![0u64; 2048];
        // Bounded retries as a defensive measure against a misbehaving
        // provider that keeps demanding a bigger buffer (mirrors the cap in
        // `query::wide_out`).
        for _ in 0..4 {
            let mut count = u32::MAX; // as many entries as fit
            let mut size = len_u32(buf.len() * size_of::<u64>());
            // SAFETY: `buf` outlives the call; `size` is its size in bytes.
            let status = unsafe {
                WNet::WNetEnumResourceW(
                    self.handle,
                    &raw mut count,
                    buf.as_mut_ptr().cast(),
                    &raw mut size,
                )
            };
            match status {
                NO_ERROR => {
                    trace!("WNetEnumResourceW returned {count} entries");
                    // A zero-entry success is out of contract (the API
                    // reports the end via ERROR_NO_MORE_ITEMS); treat it as
                    // the end of the enumeration rather than re-asking a
                    // misbehaving provider forever.
                    if count == 0 {
                        trace!("zero-entry success; treating as end of enumeration");
                        self.finished = true;
                        return Ok(());
                    }
                    // SAFETY: on success the buffer starts with `count`
                    // NETRESOURCEW entries; the strings they point to live in
                    // `buf` and are copied out immediately by `from_raw`.
                    let entries = unsafe {
                        std::slice::from_raw_parts(
                            buf.as_ptr().cast::<WNet::NETRESOURCEW>(),
                            count as usize,
                        )
                    };
                    self.batch.extend(entries.iter().map(NetResource::from_raw));
                    return Ok(());
                }
                ERROR_NO_MORE_ITEMS => {
                    self.finished = true;
                    return Ok(());
                }
                // Buffer too small for a single entry; `size` holds the
                // required size in bytes.
                ERROR_MORE_DATA => {
                    buf = vec![0u64; (size as usize).div_ceil(size_of::<u64>())];
                }
                ERROR_EXTENDED_ERROR => return Err(wnet_extended_error()),
                code => return Err(Error::from_status(code)),
            }
        }
        Err(Error::Other(ERROR_MORE_DATA))
    }
}

impl Drop for Resources {
    fn drop(&mut self) {
        // SAFETY: the handle came from WNetOpenEnumW and is closed only here.
        unsafe {
            WNet::WNetCloseEnum(self.handle);
        }
    }
}

fn open(
    scope: u32,
    resource_type: u32,
    usage: u32,
    root_remote: Option<&str>,
) -> Result<Resources> {
    let remote = root_remote.map(to_wide).transpose()?;
    let root = remote.as_ref().map(|remote| WNet::NETRESOURCEW {
        dwScope: 0,
        dwType: 0,
        dwDisplayType: 0,
        dwUsage: WNet::RESOURCEUSAGE_CONTAINER,
        lpLocalName: std::ptr::null_mut(),
        lpRemoteName: remote.as_ptr().cast_mut(),
        lpComment: std::ptr::null_mut(),
        lpProvider: std::ptr::null_mut(),
    });

    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: `root` (when present) and its string live until after the call.
    let status = unsafe {
        WNet::WNetOpenEnumW(
            scope,
            resource_type,
            usage,
            root.as_ref().map_or(std::ptr::null(), std::ptr::from_ref),
            &raw mut handle,
        )
    };
    match status {
        NO_ERROR => Ok(Resources {
            handle,
            batch: VecDeque::new(),
            finished: false,
        }),
        ERROR_EXTENDED_ERROR => Err(wnet_extended_error()),
        code => Err(Error::from_status(code)),
    }
}

/// Currently connected resources (`RESOURCE_CONNECTED`) — every active
/// redirection and deviceless connection of the calling user.
///
/// # Errors
/// See [`Error`].
pub fn connections() -> Result<Resources> {
    open(WNet::RESOURCE_CONNECTED, WNet::RESOURCETYPE_ANY, 0, None)
}

/// Remembered (persistent) connections (`RESOURCE_REMEMBERED`) — restored at
/// logon whether or not they are currently connected.
///
/// # Errors
/// See [`Error`].
pub fn remembered() -> Result<Resources> {
    open(WNet::RESOURCE_REMEMBERED, WNet::RESOURCETYPE_ANY, 0, None)
}

/// The resources a server exposes (`RESOURCE_GLOBALNET` rooted at `server`,
/// e.g. `r"\\fileserver"`): its shares, including shared printers.
///
/// The server may require an authenticated connection (e.g. to `IPC$`)
/// before it lets you enumerate.
///
/// # Errors
/// [`Error::BadNetName`] / [`Error::NoNetOrBadPath`] when the server cannot
/// be found, [`Error::AccessDenied`] when it refuses anonymous enumeration.
pub fn server_shares(server: &str) -> Result<Resources> {
    open(
        WNet::RESOURCE_GLOBALNET,
        WNet::RESOURCETYPE_ANY,
        0,
        Some(server),
    )
}

/// Fully general enumeration — pass raw `RESOURCE_*` scope, `RESOURCETYPE_*`
/// type, and `RESOURCEUSAGE_*` usage values, and optionally the remote name
/// of a container to enumerate (as in [`server_shares`]).
///
/// # Errors
/// See [`Error`].
pub fn resources_raw(
    scope: u32,
    resource_type: u32,
    usage: u32,
    root_remote: Option<&str>,
) -> Result<Resources> {
    open(scope, resource_type, usage, root_remote)
}
