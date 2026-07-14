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
        write!(f, "{}:", char::from(b'A' + *self as u8))
    }
}

/// Options for [`SmbTarget::connect_with`](crate::SmbTarget::connect_with).
///
/// The default is a temporary, non-interactive connection. Deviceless
/// connections are kept out of Windows' recent-connections list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ConnectOptions {
    pub(crate) flags: u32,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectOptions {
    pub const fn new() -> Self {
        Self {
            flags: WNet::CONNECT_TEMPORARY | WNet::CONNECT_UPDATE_RECENT,
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

    pub(crate) fn is_persistent(self) -> bool {
        self.flags & WNet::CONNECT_UPDATE_PROFILE != 0
    }

    /// Remember this drive mapping and restore it when the user logs on.
    /// Persistence requires an explicit or automatically assigned drive.
    pub fn persist(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_UPDATE_PROFILE, yes)
            .flag(WNet::CONNECT_TEMPORARY, !yes)
    }

    /// Fail if SMB signing cannot be enforced.
    pub fn require_integrity(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_REQUIRE_INTEGRITY, yes)
    }

    /// Fail if SMB encryption cannot be enforced.
    pub fn require_privacy(self, yes: bool) -> Self {
        self.flag(WNet::CONNECT_REQUIRE_PRIVACY, yes)
    }
}

/// Options for [`SmbTarget::disconnect_with`](crate::SmbTarget::disconnect_with)
/// and [`cancel_connection`](crate::cancel_connection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
pub struct DisconnectOptions {
    pub(crate) force: bool,
    pub(crate) forget: bool,
}

impl DisconnectOptions {
    /// Disconnect even if files or jobs remain open on the mapping.
    pub fn force(mut self, yes: bool) -> Self {
        self.force = yes;
        self
    }

    /// Remove this drive mapping from the user profile so Windows will not
    /// restore it at the next logon.
    pub fn forget(mut self, yes: bool) -> Self {
        self.forget = yes;
        self
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
    fn default_options_are_temporary_and_suppress_recent_deviceless_connections() {
        assert_eq!(
            ConnectOptions::new().flags,
            WNet::CONNECT_TEMPORARY | WNet::CONNECT_UPDATE_RECENT
        );
    }

    #[test]
    fn persist_replaces_temporary() {
        assert_eq!(
            ConnectOptions::new().persist(true).flags,
            WNet::CONNECT_UPDATE_PROFILE | WNet::CONNECT_UPDATE_RECENT
        );
    }

    #[test]
    fn security_options_map() {
        assert_eq!(
            ConnectOptions::new()
                .require_integrity(true)
                .require_privacy(true)
                .flags,
            WNet::CONNECT_TEMPORARY
                | WNet::CONNECT_UPDATE_RECENT
                | WNet::CONNECT_REQUIRE_INTEGRITY
                | WNet::CONNECT_REQUIRE_PRIVACY
        );
    }
}
