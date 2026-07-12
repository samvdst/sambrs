use crate::error::Error;
use windows_sys::Win32::NetworkManagement::WNet;

/// A local Windows drive letter (`A:` – `Z:`).
///
/// Guarantees at compile time that a mount point is a valid device letter,
/// instead of failing at connect time with a confusing `ERROR_BAD_DEVICE`.
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
#[repr(u32)]
pub enum ResourceType {
    /// A disk share (`RESOURCETYPE_DISK`). The default.
    #[default]
    Disk = WNet::RESOURCETYPE_DISK,
    /// A shared printer (`RESOURCETYPE_PRINT`).
    Print = WNet::RESOURCETYPE_PRINT,
    /// Any resource type (`RESOURCETYPE_ANY`).
    ///
    /// Only valid for deviceless connections: Windows rejects it with
    /// `ERROR_INVALID_PARAMETER` when a local device is redirected —
    /// whether configured explicitly or chosen automatically by
    /// [`SmbTarget::connect_auto`](crate::SmbTarget::connect_auto).
    Any = WNet::RESOURCETYPE_ANY,
}

/// Options for [`SmbTarget::connect_with`](crate::SmbTarget::connect_with),
/// covering every documented `CONNECT_*` flag of `WNetAddConnection2W` /
/// `WNetUseConnectionW`.
///
/// The default (`ConnectOptions::new()`) is a temporary, non-interactive
/// connection — the same behavior as
/// [`SmbTarget::connect`](crate::SmbTarget::connect).
///
/// ```
/// use sambrs::ConnectOptions;
///
/// let opts = ConnectOptions::new()
///     .persist(true)
///     .require_privacy(true); // enforce SMB encryption
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ConnectOptions {
    flags: u32,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectOptions {
    pub const fn new() -> Self {
        Self {
            flags: WNet::CONNECT_TEMPORARY,
        }
    }

    fn flag(mut self, flag: u32, yes: bool) -> Self {
        if yes {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
        self
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
        self.flags &= !(WNet::CONNECT_UPDATE_PROFILE | WNet::CONNECT_TEMPORARY);
        self.flags |= if yes {
            WNet::CONNECT_UPDATE_PROFILE
        } else {
            WNet::CONNECT_TEMPORARY
        };
        self
    }

    /// `CONNECT_UPDATE_RECENT`: keep the connection out of the recent
    /// connection list unless it has a redirected local device associated
    /// with it.
    pub fn update_recent(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_UPDATE_RECENT, yes)
    }

    /// `CONNECT_INTERACTIVE`: the operating system may interact with the user
    /// for authentication purposes, e.g. by showing a password prompt instead
    /// of failing with `ERROR_INVALID_PASSWORD`.
    pub fn interactive(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_INTERACTIVE, yes)
    }

    /// `CONNECT_PROMPT`: always prompt for the user name and password instead
    /// of first trying supplied or remembered credentials. Only valid
    /// together with [`interactive`](Self::interactive).
    pub fn prompt(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_PROMPT, yes)
    }

    /// `CONNECT_COMMANDLINE`: prompt for authentication on the command line
    /// instead of with a GUI dialog. Only valid together with
    /// [`interactive`](Self::interactive); also a prerequisite for
    /// [`save_credentials`](Self::save_credentials) and
    /// [`reset_credentials`](Self::reset_credentials) to take effect.
    pub fn commandline(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_COMMANDLINE, yes)
    }

    /// `CONNECT_REDIRECT`: force the redirection of a local device even if a
    /// local device name was not specified.
    pub fn redirect(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_REDIRECT, yes)
    }

    /// `CONNECT_CURRENT_MEDIA`: do not start a new media to establish the
    /// connection (e.g. do not initiate a new dial-up connection).
    pub fn current_media(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_CURRENT_MEDIA, yes)
    }

    /// `CONNECT_CMD_SAVECRED`: if the operating system prompts for a
    /// credential, it is saved by the credential manager.
    ///
    /// Windows ignores this flag unless [`interactive`](Self::interactive)
    /// and [`commandline`](Self::commandline) are also set.
    pub fn save_credentials(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_CMD_SAVECRED, yes)
    }

    /// `CONNECT_CRED_RESET`: reset the credentials for this connection that
    /// are saved by the credential manager.
    ///
    /// Windows ignores this flag unless [`commandline`](Self::commandline)
    /// is also set.
    pub fn reset_credentials(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_CRED_RESET, yes)
    }

    /// `CONNECT_REQUIRE_INTEGRITY`: fail the connection if SMB signing cannot
    /// be enforced.
    pub fn require_integrity(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_REQUIRE_INTEGRITY, yes)
    }

    /// `CONNECT_REQUIRE_PRIVACY`: fail the connection if SMB encryption
    /// cannot be enforced.
    pub fn require_privacy(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_REQUIRE_PRIVACY, yes)
    }

    /// `CONNECT_WRITE_THROUGH_SEMANTICS`: writes go through to the server
    /// before the operation completes (no write caching).
    pub fn write_through(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_WRITE_THROUGH_SEMANTICS, yes)
    }

    pub(crate) fn to_flags(self) -> u32 {
        self.flags
    }
}

/// Options for [`SmbTarget::disconnect_with`](crate::SmbTarget::disconnect_with)
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
    /// `ERROR_OPEN_FILES` if anything is still open.
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
        i32::from(self.force)
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
        assert_eq!(DriveLetter::A.to_string(), "A:");
        assert_eq!(DriveLetter::Z.to_string(), "Z:");
    }

    #[test]
    fn default_options_are_temporary() {
        assert_eq!(ConnectOptions::new().to_flags(), WNet::CONNECT_TEMPORARY);
        assert_eq!(
            ConnectOptions::new()
                .interactive(true)
                .interactive(false)
                .to_flags(),
            WNet::CONNECT_TEMPORARY
        );
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
    fn disconnect_options_map() {
        assert_eq!(DisconnectOptions::new().flags(), 0);
        assert_eq!(DisconnectOptions::new().force_bool(), 0);
        assert_eq!(
            DisconnectOptions::new().forget(true).flags(),
            WNet::CONNECT_UPDATE_PROFILE
        );
        assert_eq!(DisconnectOptions::new().force(true).force_bool(), 1);
    }
}
