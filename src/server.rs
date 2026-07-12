//! Server-side SMB administration via netapi32: enumerate, inspect, create,
//! and delete shares; list and end sessions; list and close open files; and
//! list the connections made to a share.
//!
//! Every function takes the target server as `Option<&str>` — `None` means
//! the local machine, `Some(r"\\fileserver")` administers a remote one. Most
//! of these calls require administrative rights on the target; the
//! enumeration functions fall back to a lower information level (fewer
//! fields, see the struct docs) when access is denied.
//!
//! ```no_run
//! use sambrs::server;
//!
//! // Create a share on the local machine, list everything, delete it again.
//! server::add_share(None, &server::NewShare::disk("scratch", r"C:\scratch"))?;
//! for share in server::shares(None)? {
//!     println!("{} -> {:?}", share.name, share.path);
//! }
//! server::delete_share(None, "scratch")?;
//! # Ok::<(), sambrs::Error>(())
//! ```

use crate::error::{Error, Result, check_net};
use crate::strings::{from_pwstr, opt_ptr, to_wide};
use crate::trace::debug;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    MAX_PREFERRED_LENGTH, NERR_Success as NERR_SUCCESS, NetApiBufferFree,
};
use windows_sys::Win32::Storage::FileSystem::{
    CONNECTION_INFO_1, FILE_INFO_3, NetConnectionEnum, NetFileClose, NetFileEnum, NetSessionDel,
    NetSessionEnum, NetShareAdd, NetShareDel, NetShareEnum, NetShareGetInfo, PERM_FILE_CREATE,
    PERM_FILE_READ, PERM_FILE_WRITE, SESS_GUEST, SESSION_INFO_1, SESSION_INFO_10, SHARE_INFO_1,
    SHARE_INFO_2, SHI_USES_UNLIMITED, STYPE_DEVICE, STYPE_DISKTREE, STYPE_IPC, STYPE_MASK,
    STYPE_PRINTQ, STYPE_SPECIAL, STYPE_TEMPORARY,
};

/// Frees a netapi32-allocated buffer on drop.
struct NetBuffer(*mut u8);

impl Drop for NetBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was allocated by netapi32 and is freed once.
            unsafe {
                NetApiBufferFree(self.0.cast());
            }
        }
    }
}

/// Run a `Net*Enum` call to completion, handling the resume/`ERROR_MORE_DATA`
/// protocol and buffer ownership. `call` receives the out-buffer pointer and
/// the entries-read / total-entries out-params; `map` converts each returned
/// entry while the buffer is still alive.
///
/// The protocol contract says every `ERROR_MORE_DATA` batch delivers entries
/// and advances the resume handle; a malformed or malicious server can
/// violate that, so the loop fails with `Error::Windows(ERROR_MORE_DATA)`
/// instead of spinning forever: immediately when a batch delivers nothing
/// (the next call would repeat the identical request), and after
/// `MAX_BATCHES` batches as a backstop against a resume handle that yields
/// entries but never terminates.
fn net_enum<T, U>(
    mut call: impl FnMut(*mut *mut u8, *mut u32, *mut u32) -> u32,
    mut map: impl FnMut(&T) -> U,
) -> Result<Vec<U>> {
    // Batches are MAX_PREFERRED_LENGTH-sized (remotely still tens of KB), so
    // thousands of batches are far beyond any real enumeration.
    const MAX_BATCHES: u32 = 4096;
    let mut out = Vec::new();
    for _ in 0..MAX_BATCHES {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let status = call(&raw mut buf, &raw mut read, &raw mut total);
        let _guard = NetBuffer(buf);
        match status {
            NERR_SUCCESS | ERROR_MORE_DATA => {
                if !buf.is_null() {
                    // SAFETY: netapi32 returned `read` entries of type T in a
                    // properly aligned buffer owned by `_guard`.
                    let entries =
                        unsafe { std::slice::from_raw_parts(buf.cast::<T>(), read as usize) };
                    out.extend(entries.iter().map(&mut map));
                }
                if status == NERR_SUCCESS {
                    return Ok(out);
                }
                if buf.is_null() || read == 0 {
                    // ERROR_MORE_DATA with an empty batch: no progress was
                    // made, so looping would repeat the identical call.
                    return Err(Error::Windows(ERROR_MORE_DATA));
                }
                // ERROR_MORE_DATA: loop again, the resume handle captured by
                // `call` continues where this batch ended.
            }
            code => return Err(Error::from_status(code)),
        }
    }
    Err(Error::Windows(ERROR_MORE_DATA))
}

/// Owned `String` from a nul-terminated wide pointer; `None` when the pointer
/// is null **or** the string is empty. netapi32 uses null and empty
/// interchangeably for "no value", so every optional string field of the
/// structs below normalizes both to `None`.
///
/// # Safety
/// As [`from_pwstr`]: `ptr` must either be null or point to a valid
/// nul-terminated UTF-16 string.
unsafe fn from_pwstr_nonempty(ptr: *const u16) -> Option<String> {
    // SAFETY: guaranteed by caller.
    unsafe { from_pwstr(ptr) }.filter(|s| !s.is_empty())
}

/// The type of a share, unpacked from the raw `STYPE_*` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShareType {
    pub kind: ShareKind,
    /// `STYPE_SPECIAL`: an administrative share (`C$`, `ADMIN$`, `IPC$`, …).
    pub special: bool,
    /// `STYPE_TEMPORARY`: not persistent across server restarts.
    pub temporary: bool,
}

/// The base kind of a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ShareKind {
    /// A disk share (`STYPE_DISKTREE`).
    #[default]
    Disk,
    /// A print queue (`STYPE_PRINTQ`).
    PrintQueue,
    /// A communication device (`STYPE_DEVICE`).
    Device,
    /// Interprocess communication, i.e. `IPC$` (`STYPE_IPC`).
    Ipc,
    /// Any other raw `STYPE_*` base value.
    Other(u32),
}

impl ShareType {
    fn from_raw(raw: u32) -> Self {
        let kind = match raw & STYPE_MASK {
            STYPE_DISKTREE => ShareKind::Disk,
            STYPE_PRINTQ => ShareKind::PrintQueue,
            STYPE_DEVICE => ShareKind::Device,
            STYPE_IPC => ShareKind::Ipc,
            other => ShareKind::Other(other),
        };
        Self {
            kind,
            special: raw & STYPE_SPECIAL != 0,
            temporary: raw & STYPE_TEMPORARY != 0,
        }
    }
}

impl ShareKind {
    fn to_raw(self) -> u32 {
        match self {
            Self::Disk => STYPE_DISKTREE,
            Self::PrintQueue => STYPE_PRINTQ,
            Self::Device => STYPE_DEVICE,
            Self::Ipc => STYPE_IPC,
            Self::Other(raw) => raw,
        }
    }
}

/// A share on a server, from `NetShareEnum` / `NetShareGetInfo`.
///
/// The `path`, `permissions`, `max_uses`, and `current_uses` fields come from
/// information level 2, which requires administrative rights on the target
/// server; they are `None` when the call had to fall back to level 1.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShareInfo {
    pub name: String,
    pub share_type: ShareType,
    /// Comment shown next to the share; `None` when absent or empty.
    pub remark: Option<String>,
    /// Local path backing the share, e.g. `C:\data` (level 2 only); `None`
    /// when absent or empty (`IPC$` has no path).
    pub path: Option<String>,
    /// Share-level permission bits, `ACCESS_*` (level 2 only).
    pub permissions: Option<u32>,
    /// Concurrent-user limit; `u32::MAX` means unlimited (level 2 only).
    pub max_uses: Option<u32>,
    /// Current number of connections to the share (level 2 only).
    pub current_uses: Option<u32>,
}

impl ShareInfo {
    /// # Safety
    /// `info` must come from a live netapi32 level-2 buffer.
    unsafe fn from_level2(info: &SHARE_INFO_2) -> Self {
        // SAFETY: guaranteed by caller.
        unsafe {
            Self {
                name: from_pwstr(info.shi2_netname).unwrap_or_default(),
                share_type: ShareType::from_raw(info.shi2_type),
                remark: from_pwstr_nonempty(info.shi2_remark),
                path: from_pwstr_nonempty(info.shi2_path),
                permissions: Some(info.shi2_permissions),
                max_uses: Some(info.shi2_max_uses),
                current_uses: Some(info.shi2_current_uses),
            }
        }
    }

    /// # Safety
    /// `info` must come from a live netapi32 level-1 buffer.
    unsafe fn from_level1(info: &SHARE_INFO_1) -> Self {
        // SAFETY: guaranteed by caller.
        unsafe {
            Self {
                name: from_pwstr(info.shi1_netname).unwrap_or_default(),
                share_type: ShareType::from_raw(info.shi1_type),
                remark: from_pwstr_nonempty(info.shi1_remark),
                path: None,
                permissions: None,
                max_uses: None,
                current_uses: None,
            }
        }
    }
}

/// List the shares on a server via `NetShareEnum`.
///
/// Tries information level 2 (full detail, administrative rights) first and
/// transparently falls back to level 1 on `ERROR_ACCESS_DENIED`.
///
/// # Errors
/// See [`Error`].
pub fn shares(server: Option<&str>) -> Result<Vec<ShareInfo>> {
    let server_w = server.map(to_wide).transpose()?;
    let server_ptr = opt_ptr(server_w.as_deref());

    let mut resume = 0u32;
    match net_enum::<SHARE_INFO_2, _>(
        |buf, read, total| unsafe {
            NetShareEnum(
                server_ptr,
                2,
                buf,
                MAX_PREFERRED_LENGTH,
                read,
                total,
                &raw mut resume,
            )
        },
        |info| unsafe { ShareInfo::from_level2(info) },
    ) {
        Ok(out) => Ok(out),
        Err(Error::Windows(ERROR_ACCESS_DENIED)) => {
            debug!("NetShareEnum level 2 denied, falling back to level 1");
            let mut resume = 0u32;
            net_enum::<SHARE_INFO_1, _>(
                |buf, read, total| unsafe {
                    NetShareEnum(
                        server_ptr,
                        1,
                        buf,
                        MAX_PREFERRED_LENGTH,
                        read,
                        total,
                        &raw mut resume,
                    )
                },
                |info| unsafe { ShareInfo::from_level1(info) },
            )
        }
        Err(e) => Err(e),
    }
}

/// Details of a single share via `NetShareGetInfo`, with the same level-2 →
/// level-1 fallback as [`shares`].
///
/// # Errors
/// `NERR_NetNameNotFound` when the share does not exist.
// netapi32 allocates its info buffers with alignment suitable for any of its
// info structures, so the u8 -> SHARE_INFO_* casts below are sound.
#[allow(clippy::cast_ptr_alignment)]
pub fn share_info(server: Option<&str>, name: &str) -> Result<ShareInfo> {
    let server_w = server.map(to_wide).transpose()?;
    let name_w = to_wide(name)?;

    let get = |level: u32| -> Result<NetBuffer> {
        let mut buf: *mut u8 = std::ptr::null_mut();
        // SAFETY: pointers outlive the call; `buf` receives an allocation
        // owned by the returned NetBuffer.
        let status = unsafe {
            NetShareGetInfo(
                opt_ptr(server_w.as_deref()),
                name_w.as_ptr(),
                level,
                &raw mut buf,
            )
        };
        let guard = NetBuffer(buf);
        check_net(status)?;
        Ok(guard)
    };

    match get(2) {
        Ok(buf) => {
            // SAFETY: level-2 success means `buf` holds one SHARE_INFO_2.
            Ok(unsafe { ShareInfo::from_level2(&*buf.0.cast::<SHARE_INFO_2>()) })
        }
        Err(Error::Windows(ERROR_ACCESS_DENIED)) => {
            let buf = get(1)?;
            // SAFETY: level-1 success means `buf` holds one SHARE_INFO_1.
            Ok(unsafe { ShareInfo::from_level1(&*buf.0.cast::<SHARE_INFO_1>()) })
        }
        Err(e) => Err(e),
    }
}

/// Definition of a share to create with [`add_share`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewShare {
    name: String,
    path: String,
    kind: ShareKind,
    remark: Option<String>,
    permissions: u32,
    max_uses: u32,
}

impl NewShare {
    /// A disk share exposing the local directory `path` (e.g. `C:\data`) as
    /// `name`, with default share-level permissions (`ACCESS_ALL`) and no
    /// user limit.
    ///
    /// Note that share-level permissions are largely historical — access is
    /// normally governed by the NTFS ACLs of the backing directory.
    pub fn disk(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            kind: ShareKind::Disk,
            remark: None,
            permissions: windows_sys::Win32::Storage::FileSystem::ACCESS_ALL,
            max_uses: SHI_USES_UNLIMITED,
        }
    }

    /// An optional comment shown next to the share.
    #[must_use]
    pub fn remark(mut self, remark: impl Into<String>) -> Self {
        self.remark = Some(remark.into());
        self
    }

    /// Override the share kind (e.g. [`ShareKind::PrintQueue`]).
    #[must_use]
    pub fn kind(mut self, kind: ShareKind) -> Self {
        self.kind = kind;
        self
    }

    /// Override the share-level permission bits (`ACCESS_*`).
    #[must_use]
    pub fn permissions(mut self, permissions: u32) -> Self {
        self.permissions = permissions;
        self
    }

    /// Limit the number of concurrent users.
    #[must_use]
    pub fn max_uses(mut self, max_uses: u32) -> Self {
        self.max_uses = max_uses;
        self
    }
}

/// Create a share via `NetShareAdd` (information level 2). Requires
/// administrative rights on the target server.
///
/// # Errors
/// `NERR_DuplicateShare` when the name is taken,
/// `NERR_UnknownDevDir` when the backing path does not exist,
/// `ERROR_ACCESS_DENIED` without administrative rights.
pub fn add_share(server: Option<&str>, share: &NewShare) -> Result<()> {
    let server_w = server.map(to_wide).transpose()?;
    let name_w = to_wide(&share.name)?;
    let path_w = to_wide(&share.path)?;
    let remark_w = share.remark.as_deref().map(to_wide).transpose()?;

    let info = SHARE_INFO_2 {
        shi2_netname: name_w.as_ptr().cast_mut(),
        shi2_type: share.kind.to_raw(),
        shi2_remark: opt_ptr(remark_w.as_deref()),
        shi2_permissions: share.permissions,
        shi2_max_uses: share.max_uses,
        shi2_current_uses: 0,
        shi2_path: path_w.as_ptr().cast_mut(),
        shi2_passwd: std::ptr::null_mut(),
    };

    let mut parm_err = 0u32;
    // SAFETY: `info` and all buffers it points into outlive the call.
    let status = unsafe {
        NetShareAdd(
            opt_ptr(server_w.as_deref()),
            2,
            std::ptr::from_ref(&info).cast(),
            &raw mut parm_err,
        )
    };
    if status != NERR_SUCCESS {
        debug!("NetShareAdd failed with {status} (parameter index {parm_err})");
    }
    check_net(status)
}

/// Delete a share via `NetShareDel`. Requires administrative rights on the
/// target server.
///
/// # Errors
/// `NERR_NetNameNotFound` when the share does not exist.
pub fn delete_share(server: Option<&str>, name: &str) -> Result<()> {
    let server_w = server.map(to_wide).transpose()?;
    let name_w = to_wide(name)?;
    // SAFETY: both strings outlive the call.
    let status = unsafe { NetShareDel(opt_ptr(server_w.as_deref()), name_w.as_ptr(), 0) };
    check_net(status)
}

/// An SMB session established with a server, from `NetSessionEnum`.
///
/// The `open_files` and `is_guest` fields come from information level 1,
/// which requires administrative rights; they are `None` when the call had
/// to fall back to level 10.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionInfo {
    /// Name of the computer that established the session.
    pub client: String,
    /// Name of the user who established the session; `None` when absent or
    /// empty.
    pub username: Option<String>,
    /// Number of files, devices, and pipes opened during the session
    /// (level 1 only).
    pub open_files: Option<u32>,
    /// How long the session has been active.
    pub active: Duration,
    /// How long the session has been idle.
    pub idle: Duration,
    /// Whether the client connected as a guest (level 1 only).
    pub is_guest: Option<bool>,
}

impl SessionInfo {
    /// # Safety
    /// `info` must come from a live netapi32 level-1 buffer.
    unsafe fn from_level1(info: &SESSION_INFO_1) -> Self {
        // SAFETY: guaranteed by caller.
        unsafe {
            Self {
                client: from_pwstr(info.sesi1_cname).unwrap_or_default(),
                username: from_pwstr_nonempty(info.sesi1_username),
                open_files: Some(info.sesi1_num_opens),
                active: Duration::from_secs(u64::from(info.sesi1_time)),
                idle: Duration::from_secs(u64::from(info.sesi1_idle_time)),
                is_guest: Some(info.sesi1_user_flags & SESS_GUEST != 0),
            }
        }
    }

    /// # Safety
    /// `info` must come from a live netapi32 level-10 buffer.
    unsafe fn from_level10(info: &SESSION_INFO_10) -> Self {
        // SAFETY: guaranteed by caller.
        unsafe {
            Self {
                client: from_pwstr(info.sesi10_cname).unwrap_or_default(),
                username: from_pwstr_nonempty(info.sesi10_username),
                open_files: None,
                active: Duration::from_secs(u64::from(info.sesi10_time)),
                idle: Duration::from_secs(u64::from(info.sesi10_idle_time)),
                is_guest: None,
            }
        }
    }
}

/// List the SMB sessions on a server via `NetSessionEnum`, optionally
/// filtered by client computer name and/or user name.
///
/// The `client` filter is the API's `UncClientName` parameter and must be in
/// UNC form with the leading backslashes (`r"\\workstation"`); note that
/// [`SessionInfo::client`] may report the bare name without them.
///
/// Tries information level 1 (full detail, administrative rights) first and
/// transparently falls back to level 10 on `ERROR_ACCESS_DENIED`.
///
/// # Errors
/// `NERR_ClientNameNotFound` / `NERR_UserNotFound` when a filter matches
/// nothing.
pub fn sessions(
    server: Option<&str>,
    client: Option<&str>,
    username: Option<&str>,
) -> Result<Vec<SessionInfo>> {
    let server_w = server.map(to_wide).transpose()?;
    let client_w = client.map(to_wide).transpose()?;
    let user_w = username.map(to_wide).transpose()?;
    let (server_ptr, client_ptr, user_ptr) = (
        opt_ptr(server_w.as_deref()),
        opt_ptr(client_w.as_deref()),
        opt_ptr(user_w.as_deref()),
    );

    let mut resume = 0u32;
    match net_enum::<SESSION_INFO_1, _>(
        |buf, read, total| unsafe {
            NetSessionEnum(
                server_ptr,
                client_ptr,
                user_ptr,
                1,
                buf,
                MAX_PREFERRED_LENGTH,
                read,
                total,
                &raw mut resume,
            )
        },
        |info| unsafe { SessionInfo::from_level1(info) },
    ) {
        Ok(out) => Ok(out),
        Err(Error::Windows(ERROR_ACCESS_DENIED)) => {
            debug!("NetSessionEnum level 1 denied, falling back to level 10");
            let mut resume = 0u32;
            net_enum::<SESSION_INFO_10, _>(
                |buf, read, total| unsafe {
                    NetSessionEnum(
                        server_ptr,
                        client_ptr,
                        user_ptr,
                        10,
                        buf,
                        MAX_PREFERRED_LENGTH,
                        read,
                        total,
                        &raw mut resume,
                    )
                },
                |info| unsafe { SessionInfo::from_level10(info) },
            )
        }
        Err(e) => Err(e),
    }
}

/// End SMB sessions on a server via `NetSessionDel`. Requires administrative
/// rights on the target server.
///
/// `client` and `username` scope what is deleted: sessions from that
/// computer (in UNC form, `r"\\workstation"` — see [`sessions`]), sessions
/// of that user, or their intersection. At least one of the two is required,
/// and an empty string does not count — netapi32 treats it like a missing
/// filter. Ending every session on the server is deliberately a separate
/// function, [`delete_all_sessions`].
///
/// # Errors
/// `ERROR_INVALID_PARAMETER` when both `client` and `username` are `None` or
/// empty (use [`delete_all_sessions`] to end every session),
/// `NERR_ClientNameNotFound` / `NERR_UserNotFound` when nothing matches.
pub fn delete_session(
    server: Option<&str>,
    client: Option<&str>,
    username: Option<&str>,
) -> Result<()> {
    // netapi32 treats an empty filter string like a null one, so empty
    // strings must not slip past the all-sessions guard below.
    let client = client.filter(|c| !c.is_empty());
    let username = username.filter(|u| !u.is_empty());
    if client.is_none() && username.is_none() {
        return Err(Error::Windows(ERROR_INVALID_PARAMETER));
    }
    session_del(server, client, username)
}

/// End **every** SMB session on a server via `NetSessionDel` with no client
/// or user filter. Requires administrative rights on the target server.
///
/// **This disconnects all clients of the server at once**, without notifying
/// them — open files may lose data. For anything more targeted, use
/// [`delete_session`].
///
/// # Errors
/// `ERROR_ACCESS_DENIED` without administrative rights.
pub fn delete_all_sessions(server: Option<&str>) -> Result<()> {
    session_del(server, None, None)
}

fn session_del(server: Option<&str>, client: Option<&str>, username: Option<&str>) -> Result<()> {
    let server_w = server.map(to_wide).transpose()?;
    let client_w = client.map(to_wide).transpose()?;
    let user_w = username.map(to_wide).transpose()?;
    // SAFETY: all strings outlive the call.
    let status = unsafe {
        NetSessionDel(
            opt_ptr(server_w.as_deref()),
            opt_ptr(client_w.as_deref()),
            opt_ptr(user_w.as_deref()),
        )
    };
    check_net(status)
}

/// A file, device, or pipe opened through SMB on a server, from
/// `NetFileEnum` (information level 3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenFile {
    /// Server-assigned identifier; pass to [`close_file`].
    pub id: u32,
    pub path: String,
    /// The user (or computer, for null sessions) that opened it; `None` when
    /// absent or empty.
    pub username: Option<String>,
    /// Number of locks held on the file.
    pub locks: u32,
    /// Raw `PERM_FILE_*` access bits; see the `can_*` methods.
    pub permissions: u32,
}

impl OpenFile {
    #[must_use]
    pub fn can_read(&self) -> bool {
        self.permissions & PERM_FILE_READ != 0
    }

    #[must_use]
    pub fn can_write(&self) -> bool {
        self.permissions & PERM_FILE_WRITE != 0
    }

    #[must_use]
    pub fn can_create(&self) -> bool {
        self.permissions & PERM_FILE_CREATE != 0
    }
}

/// List the open files/devices/pipes on a server via `NetFileEnum`,
/// optionally filtered to a base path prefix and/or user name. Requires
/// administrative rights on the target server.
///
/// # Errors
/// `ERROR_ACCESS_DENIED` without administrative rights.
pub fn open_files(
    server: Option<&str>,
    base_path: Option<&str>,
    username: Option<&str>,
) -> Result<Vec<OpenFile>> {
    let server_w = server.map(to_wide).transpose()?;
    let path_w = base_path.map(to_wide).transpose()?;
    let user_w = username.map(to_wide).transpose()?;

    let mut resume = 0usize; // NetFileEnum's resume handle is pointer-sized
    net_enum::<FILE_INFO_3, _>(
        |buf, read, total| unsafe {
            NetFileEnum(
                opt_ptr(server_w.as_deref()),
                opt_ptr(path_w.as_deref()),
                opt_ptr(user_w.as_deref()),
                3,
                buf,
                MAX_PREFERRED_LENGTH,
                read,
                total,
                &raw mut resume,
            )
        },
        |info| {
            // SAFETY: strings live in the enumeration buffer held by net_enum.
            unsafe {
                OpenFile {
                    id: info.fi3_id,
                    path: from_pwstr(info.fi3_pathname).unwrap_or_default(),
                    username: from_pwstr_nonempty(info.fi3_username),
                    locks: info.fi3_num_locks,
                    permissions: info.fi3_permissions,
                }
            }
        },
    )
}

/// Force-close an open file/device/pipe by its [`OpenFile::id`] via
/// `NetFileClose`. Requires administrative rights on the target server.
///
/// The client is not notified — use with care, this can cause data loss on
/// the client side.
///
/// # Errors
/// `NERR_FileIdNotFound` when the id does not exist.
pub fn close_file(server: Option<&str>, id: u32) -> Result<()> {
    let server_w = server.map(to_wide).transpose()?;
    // SAFETY: the string outlives the call.
    let status = unsafe { NetFileClose(opt_ptr(server_w.as_deref()), id) };
    check_net(status)
}

/// A connection made to a shared resource, from `NetConnectionEnum`
/// (information level 1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShareConnection {
    /// Server-assigned connection identifier.
    pub id: u32,
    pub share_type: ShareType,
    /// Number of files currently open through this connection.
    pub open_files: u32,
    /// Number of users on this connection.
    pub users: u32,
    /// How long the connection has been established.
    pub active: Duration,
    /// User on this connection; `None` when absent or empty.
    pub username: Option<String>,
    /// Depending on the qualifier passed to [`connections`]: the share name
    /// or the client computer name. `None` when absent or empty.
    pub name: Option<String>,
}

/// List the connections to a share, or from a client computer, via
/// `NetConnectionEnum`. Requires administrative rights on the target server.
///
/// `qualifier` is either a share name (`"data"`) — listing the connections
/// made to that share — or a computer name (`r"\\workstation"`) — listing
/// the connections made from that computer.
///
/// # Errors
/// `NERR_NetNameNotFound` when the qualifier matches no share.
pub fn connections(server: Option<&str>, qualifier: &str) -> Result<Vec<ShareConnection>> {
    let server_w = server.map(to_wide).transpose()?;
    let qualifier_w = to_wide(qualifier)?;

    let mut resume = 0u32;
    net_enum::<CONNECTION_INFO_1, _>(
        |buf, read, total| unsafe {
            NetConnectionEnum(
                opt_ptr(server_w.as_deref()),
                qualifier_w.as_ptr(),
                1,
                buf,
                MAX_PREFERRED_LENGTH,
                read,
                total,
                &raw mut resume,
            )
        },
        |info| {
            // SAFETY: strings live in the enumeration buffer held by net_enum.
            unsafe {
                ShareConnection {
                    id: info.coni1_id,
                    share_type: ShareType::from_raw(info.coni1_type),
                    open_files: info.coni1_num_opens,
                    users: info.coni1_num_users,
                    active: Duration::from_secs(u64::from(info.coni1_time)),
                    username: from_pwstr_nonempty(info.coni1_username),
                    name: from_pwstr_nonempty(info.coni1_netname),
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_type_unpacks_flags() {
        let t = ShareType::from_raw(STYPE_DISKTREE | STYPE_SPECIAL);
        assert_eq!(t.kind, ShareKind::Disk);
        assert!(t.special);
        assert!(!t.temporary);

        let t = ShareType::from_raw(STYPE_PRINTQ | STYPE_TEMPORARY);
        assert_eq!(t.kind, ShareKind::PrintQueue);
        assert!(!t.special);
        assert!(t.temporary);
    }

    #[test]
    fn delete_session_requires_a_nonempty_filter() {
        // Rejected before the FFI call, so this cannot touch real sessions.
        for (client, username) in [
            (None, None),
            (Some(""), None),
            (None, Some("")),
            (Some(""), Some("")),
        ] {
            assert_eq!(
                delete_session(None, client, username).unwrap_err(),
                Error::Windows(ERROR_INVALID_PARAMETER)
            );
        }
    }

    #[test]
    fn net_enum_fails_on_an_empty_more_data_batch() {
        // ERROR_MORE_DATA with no entries delivered means the next call
        // would repeat the identical request; net_enum must error out
        // instead of looping forever.
        let mut calls = 0;
        let result = net_enum::<u32, _>(
            |_, _, _| {
                calls += 1;
                ERROR_MORE_DATA
            },
            |_| panic!("no entries were delivered"),
        );
        assert_eq!(result, Err(Error::Windows(ERROR_MORE_DATA)));
        assert_eq!(calls, 1);
    }

    #[test]
    // netapi32 allocates with alignment suitable for any of its info
    // structures, so the u8 -> u32 cast below is sound.
    #[allow(clippy::cast_ptr_alignment)]
    fn net_enum_gives_up_on_a_never_ending_enumeration() {
        use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferAllocate;

        // A resume handle that keeps yielding entries without ever reaching
        // NERR_SUCCESS must hit the batch backstop, not run unbounded.
        let mut entries = 0u32;
        let result = net_enum::<u32, _>(
            |buf, read, _| {
                // SAFETY: `buf` receives a real netapi32 allocation (freed
                // by net_enum's NetBuffer guard) holding the one u32 entry
                // that `read` reports.
                unsafe {
                    NetApiBufferAllocate(4, buf.cast());
                    (*buf).cast::<u32>().write(7);
                    read.write(1);
                }
                ERROR_MORE_DATA
            },
            |&n| {
                assert_eq!(n, 7);
                entries += 1;
            },
        );
        assert_eq!(result, Err(Error::Windows(ERROR_MORE_DATA)));
        assert!(entries > 0, "delivered entries must still be consumed");
    }

    #[test]
    fn share_kind_roundtrips() {
        for kind in [
            ShareKind::Disk,
            ShareKind::PrintQueue,
            ShareKind::Device,
            ShareKind::Ipc,
        ] {
            assert_eq!(ShareType::from_raw(kind.to_raw()).kind, kind);
        }
    }
}
