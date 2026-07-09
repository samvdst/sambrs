use crate::error::Error;
use windows_sys::Win32::Foundation::{FALSE, TRUE};
use windows_sys::Win32::NetworkManagement::WNet;

/// A local Windows drive letter (`A:` – `Z:`).
///
/// Guarantees at compile time that a mount point is a valid device letter,
/// instead of failing at connect time with a confusing [`Error::BadDevice`].
///
/// ```
/// use sambrs::DriveLetter;
///
/// let letter = DriveLetter::try_from('d').unwrap();
/// assert_eq!(letter, DriveLetter::D);
/// assert_eq!(letter.to_string(), "D:");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[rustfmt::skip]
pub enum DriveLetter {
    A, B, C, D, E, F, G, H, I, J, K, L, M,
    N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
}

impl DriveLetter {
    /// The letter as an uppercase `char`.
    #[must_use]
    pub const fn as_char(self) -> char {
        (b'A' + self as u8) as char
    }

    /// The device name Windows expects, e.g. `"D:"`.
    pub(crate) fn device(self) -> String {
        format!("{}:", self.as_char())
    }
}

impl TryFrom<char> for DriveLetter {
    type Error = Error;

    /// Case insensitive; anything outside `A-Z` returns
    /// [`Error::InvalidDriveLetter`].
    fn try_from(c: char) -> Result<Self, Error> {
        #[rustfmt::skip]
        const LETTERS: [DriveLetter; 26] = [
            DriveLetter::A, DriveLetter::B, DriveLetter::C, DriveLetter::D, DriveLetter::E,
            DriveLetter::F, DriveLetter::G, DriveLetter::H, DriveLetter::I, DriveLetter::J,
            DriveLetter::K, DriveLetter::L, DriveLetter::M, DriveLetter::N, DriveLetter::O,
            DriveLetter::P, DriveLetter::Q, DriveLetter::R, DriveLetter::S, DriveLetter::T,
            DriveLetter::U, DriveLetter::V, DriveLetter::W, DriveLetter::X, DriveLetter::Y,
            DriveLetter::Z,
        ];
        let upper = c.to_ascii_uppercase();
        if upper.is_ascii_uppercase() {
            Ok(LETTERS[(upper as u8 - b'A') as usize])
        } else {
            Err(Error::InvalidDriveLetter(c))
        }
    }
}

impl std::fmt::Display for DriveLetter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.as_char())
    }
}

/// The type of network resource to connect to (`dwType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ResourceType {
    /// A disk share (`RESOURCETYPE_DISK`). The default.
    #[default]
    Disk,
    /// A shared printer (`RESOURCETYPE_PRINT`).
    Print,
    /// Any resource type (`RESOURCETYPE_ANY`).
    ///
    /// Only valid for deviceless connections: Windows rejects it with
    /// [`Error::InvalidParameter`] when a local device is redirected —
    /// whether configured explicitly or chosen automatically by
    /// [`SmbShare::connect_auto`](crate::SmbShare::connect_auto).
    Any,
}

impl ResourceType {
    pub(crate) fn to_dword(self) -> u32 {
        match self {
            Self::Disk => WNet::RESOURCETYPE_DISK,
            Self::Print => WNet::RESOURCETYPE_PRINT,
            Self::Any => WNet::RESOURCETYPE_ANY,
        }
    }
}

/// Options for [`SmbShare::connect_with`](crate::SmbShare::connect_with),
/// covering every documented `CONNECT_*` flag of `WNetAddConnection2W` /
/// `WNetUseConnectionW`.
///
/// The default (`ConnectOptions::new()`) is a temporary, non-interactive
/// connection — the same behavior as
/// [`SmbShare::connect`](crate::SmbShare::connect).
///
/// ```
/// use sambrs::ConnectOptions;
///
/// let opts = ConnectOptions::new()
///     .persist(true)
///     .require_privacy(true); // enforce SMB encryption
/// ```
// One independent boolean per CONNECT_* flag is exactly the shape of the
// underlying API; a state machine would misrepresent it.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
pub struct ConnectOptions {
    persist: bool,
    update_recent: bool,
    interactive: bool,
    prompt: bool,
    commandline: bool,
    redirect: bool,
    current_media: bool,
    save_credentials: bool,
    reset_credentials: bool,
    require_integrity: bool,
    require_privacy: bool,
    write_through: bool,
    raw_flags: u32,
}

impl ConnectOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// `CONNECT_UPDATE_PROFILE`: remember the connection and restore it when
    /// the user logs on again.
    ///
    /// From the [Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w):
    /// the operating system remembers only successful connections that
    /// redirect local devices; deviceless connections are not remembered.
    /// When this is `false` (the default), `CONNECT_TEMPORARY` is passed
    /// instead.
    pub fn persist(mut self, yes: bool) -> Self {
        self.persist = yes;
        self
    }

    /// `CONNECT_UPDATE_RECENT`: keep the connection out of the recent
    /// connection list unless it has a redirected local device associated
    /// with it.
    pub fn update_recent(mut self, yes: bool) -> Self {
        self.update_recent = yes;
        self
    }

    /// `CONNECT_INTERACTIVE`: the operating system may interact with the user
    /// for authentication purposes, e.g. by showing a password prompt instead
    /// of failing with [`Error::InvalidPassword`].
    pub fn interactive(mut self, yes: bool) -> Self {
        self.interactive = yes;
        self
    }

    /// `CONNECT_PROMPT`: always prompt for the user name and password instead
    /// of first trying supplied or remembered credentials. Only valid
    /// together with [`interactive`](Self::interactive).
    pub fn prompt(mut self, yes: bool) -> Self {
        self.prompt = yes;
        self
    }

    /// `CONNECT_COMMANDLINE`: prompt for authentication on the command line
    /// instead of with a GUI dialog. Only valid together with
    /// [`interactive`](Self::interactive); also a prerequisite for
    /// [`save_credentials`](Self::save_credentials) and
    /// [`reset_credentials`](Self::reset_credentials) to take effect.
    pub fn commandline(mut self, yes: bool) -> Self {
        self.commandline = yes;
        self
    }

    /// `CONNECT_REDIRECT`: force the redirection of a local device even if a
    /// local device name was not specified.
    pub fn redirect(mut self, yes: bool) -> Self {
        self.redirect = yes;
        self
    }

    /// `CONNECT_CURRENT_MEDIA`: do not start a new media to establish the
    /// connection (e.g. do not initiate a new dial-up connection).
    pub fn current_media(mut self, yes: bool) -> Self {
        self.current_media = yes;
        self
    }

    /// `CONNECT_CMD_SAVECRED`: if the operating system prompts for a
    /// credential, it is saved by the credential manager.
    ///
    /// Windows ignores this flag unless [`interactive`](Self::interactive)
    /// and [`commandline`](Self::commandline) are also set.
    pub fn save_credentials(mut self, yes: bool) -> Self {
        self.save_credentials = yes;
        self
    }

    /// `CONNECT_CRED_RESET`: reset the credentials for this connection that
    /// are saved by the credential manager.
    ///
    /// Windows ignores this flag unless [`commandline`](Self::commandline)
    /// is also set.
    pub fn reset_credentials(mut self, yes: bool) -> Self {
        self.reset_credentials = yes;
        self
    }

    /// `CONNECT_REQUIRE_INTEGRITY`: fail the connection if SMB signing cannot
    /// be enforced.
    pub fn require_integrity(mut self, yes: bool) -> Self {
        self.require_integrity = yes;
        self
    }

    /// `CONNECT_REQUIRE_PRIVACY`: fail the connection if SMB encryption
    /// cannot be enforced.
    pub fn require_privacy(mut self, yes: bool) -> Self {
        self.require_privacy = yes;
        self
    }

    /// `CONNECT_WRITE_THROUGH_SEMANTICS`: writes go through to the server
    /// before the operation completes (no write caching).
    pub fn write_through(mut self, yes: bool) -> Self {
        self.write_through = yes;
        self
    }

    /// OR arbitrary raw `CONNECT_*` bits into the final flag value — an
    /// escape hatch for flags this crate has no named setter for. The bits
    /// are passed through verbatim; when they already contain
    /// `CONNECT_UPDATE_PROFILE` or `CONNECT_TEMPORARY`, the automatic
    /// `CONNECT_TEMPORARY` default is suppressed.
    pub fn raw_flags(mut self, flags: u32) -> Self {
        self.raw_flags = flags;
        self
    }

    pub(crate) fn to_flags(self) -> u32 {
        let mut flags = self.raw_flags;
        if self.persist {
            flags |= WNet::CONNECT_UPDATE_PROFILE;
        } else if flags & (WNet::CONNECT_UPDATE_PROFILE | WNet::CONNECT_TEMPORARY) == 0 {
            flags |= WNet::CONNECT_TEMPORARY;
        }
        if self.update_recent {
            flags |= WNet::CONNECT_UPDATE_RECENT;
        }
        if self.interactive {
            flags |= WNet::CONNECT_INTERACTIVE;
        }
        if self.prompt {
            flags |= WNet::CONNECT_PROMPT;
        }
        if self.commandline {
            flags |= WNet::CONNECT_COMMANDLINE;
        }
        if self.redirect {
            flags |= WNet::CONNECT_REDIRECT;
        }
        if self.current_media {
            flags |= WNet::CONNECT_CURRENT_MEDIA;
        }
        if self.save_credentials {
            flags |= WNet::CONNECT_CMD_SAVECRED;
        }
        if self.reset_credentials {
            flags |= WNet::CONNECT_CRED_RESET;
        }
        if self.require_integrity {
            flags |= WNet::CONNECT_REQUIRE_INTEGRITY;
        }
        if self.require_privacy {
            flags |= WNet::CONNECT_REQUIRE_PRIVACY;
        }
        if self.write_through {
            flags |= WNet::CONNECT_WRITE_THROUGH_SEMANTICS;
        }
        flags
    }
}

/// Options for [`SmbShare::disconnect_with`](crate::SmbShare::disconnect_with)
/// and [`cancel_connection`](crate::cancel_connection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
pub struct DisconnectOptions {
    force: bool,
    forget: bool,
}

impl DisconnectOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Disconnect even if there are open files or jobs on the connection.
    /// When `false` (the default), disconnecting fails with
    /// [`Error::OpenFiles`] if anything is still open.
    pub fn force(mut self, yes: bool) -> Self {
        self.force = yes;
        self
    }

    /// `CONNECT_UPDATE_PROFILE`: update the user profile so this connection
    /// is no longer persistent — the system will not restore it on the next
    /// logon. Disconnecting by remote name (deviceless) has no effect on
    /// persistent connections.
    ///
    /// Note: this was called `persist` in sambrs 0.1, which suggested the
    /// opposite of what the flag does.
    pub fn forget(mut self, yes: bool) -> Self {
        self.forget = yes;
        self
    }

    pub(crate) fn flags(self) -> u32 {
        if self.forget {
            WNet::CONNECT_UPDATE_PROFILE
        } else {
            0
        }
    }

    pub(crate) fn force_bool(self) -> i32 {
        if self.force { TRUE } else { FALSE }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_letter_from_char_is_case_insensitive() {
        assert_eq!(DriveLetter::try_from('d').unwrap(), DriveLetter::D);
        assert_eq!(DriveLetter::try_from('Z').unwrap(), DriveLetter::Z);
        assert_eq!(
            DriveLetter::try_from('é').unwrap_err(),
            Error::InvalidDriveLetter('é')
        );
        assert_eq!(
            DriveLetter::try_from('1').unwrap_err(),
            Error::InvalidDriveLetter('1')
        );
    }

    #[test]
    fn drive_letter_formats_as_device() {
        assert_eq!(DriveLetter::A.device(), "A:");
        assert_eq!(DriveLetter::Z.to_string(), "Z:");
    }

    #[test]
    fn default_options_are_temporary() {
        assert_eq!(ConnectOptions::new().to_flags(), WNet::CONNECT_TEMPORARY);
    }

    #[test]
    fn persist_replaces_temporary() {
        let flags = ConnectOptions::new().persist(true).to_flags();
        assert_eq!(flags, WNet::CONNECT_UPDATE_PROFILE);
    }

    #[test]
    fn all_flags_map() {
        let flags = ConnectOptions::new()
            .update_recent(true)
            .interactive(true)
            .prompt(true)
            .commandline(true)
            .redirect(true)
            .current_media(true)
            .save_credentials(true)
            .reset_credentials(true)
            .require_integrity(true)
            .require_privacy(true)
            .write_through(true)
            .to_flags();
        assert_eq!(
            flags,
            WNet::CONNECT_TEMPORARY
                | WNet::CONNECT_UPDATE_RECENT
                | WNet::CONNECT_INTERACTIVE
                | WNet::CONNECT_PROMPT
                | WNet::CONNECT_COMMANDLINE
                | WNet::CONNECT_REDIRECT
                | WNet::CONNECT_CURRENT_MEDIA
                | WNet::CONNECT_CMD_SAVECRED
                | WNet::CONNECT_CRED_RESET
                | WNet::CONNECT_REQUIRE_INTEGRITY
                | WNet::CONNECT_REQUIRE_PRIVACY
                | WNet::CONNECT_WRITE_THROUGH_SEMANTICS
        );
    }

    #[test]
    fn raw_flags_suppress_automatic_temporary() {
        let flags = ConnectOptions::new()
            .raw_flags(WNet::CONNECT_UPDATE_PROFILE)
            .to_flags();
        assert_eq!(flags, WNet::CONNECT_UPDATE_PROFILE);
    }

    #[test]
    fn disconnect_options_map() {
        assert_eq!(DisconnectOptions::new().flags(), 0);
        assert_eq!(DisconnectOptions::new().force_bool(), FALSE);
        assert_eq!(
            DisconnectOptions::new().forget(true).flags(),
            WNet::CONNECT_UPDATE_PROFILE
        );
        assert_eq!(DisconnectOptions::new().force(true).force_bool(), TRUE);
    }
}
