//! Security Identifiers (SID)
//
//! A SID is a variable-length structure that uniquely identifies
//! a security principal (user, group, logon session).
//
//! Layout (Windows SDK):
//!   BYTE  Revision
//!   BYTE  SubAuthorityCount
//!   CHAR  IdentifierAuthority[6]
//!   DWORD SubAuthority[SubAuthorityCount]
//
//! Well-known SIDs:
//!   S-1-0-0        Nobody
//!   S-1-1-0        Everyone
//!   S-1-3-0        Creator Owner
//!   S-1-3-1        Creator Group
//!   S-1-5-1        Dialup
//!   S-1-5-2        Network
//!   S-1-5-3        Batch
//!   S-1-5-4        Interactive
//!   S-1-5-6        Service
//!   S-1-5-7        AnonymousLogon
//!   S-1-5-9        SChannel
//!   S-1-5-10       Self (self-relative SID)
//!   S-1-5-11       Authenticated Users
//!   S-1-5-12       Restricted Code
//!   S-1-5-13       Terminal Server
//!   S-1-5-14       Remote Interactive Logon
//!   S-1-5-18       LocalSystem (NT AUTHORITY\\SYSTEM)
//!   S-1-5-19       NT Authority (Local Service)
//!   S-1-5-20       Network Service
//!   S-1-5-21-X     Relative Identifier (domain-relative)
//!   S-1-5-32-544   Administrators
//!   S-1-5-32-545   Users
//!   S-1-5-32-546   Guests
//!   S-1-5-32-547   Power Users
//!   S-1-5-32-548   Account Operators
//!   S-1-5-32-549   Server Operators
//!   S-1-5-32-550   Print Operators
//!   S-1-5-32-551   Backup Operators
//!   S-1-5-32-552   Replicator

use core::fmt;
use core::slice;

/// SID revision.
pub const SID_REVISION: u8 = 1;
/// Maximum number of subauthorities.
pub const SID_MAX_SUB_AUTHORITIES: usize = 8;

/// Maximum length of a SID string (e.g. "S-1-5-32-544")
pub const SID_STRING_MAX: usize = 30;

/// A SID structure. Follows the Windows SDK layout exactly.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Sid {
    pub revision: u8,
    pub sub_authority_count: u8,
    pub identifier_authority: [u8; 6],
    /// Subauthorities (variable length, up to SID_MAX_SUB_AUTHORITIES)
    pub sub_authority: [u32; SID_MAX_SUB_AUTHORITIES],
}

impl Sid {
    /// Create a Sid with the given revision and no subauthorities.
    pub const fn new() -> Self {
        Self {
            revision: SID_REVISION,
            sub_authority_count: 0,
            identifier_authority: [0; 6],
            sub_authority: [0; SID_MAX_SUB_AUTHORITIES],
        }
    }

    /// Create a Sid from an identifier authority and subauthorities.
    pub const fn with_subs(
        authority: [u8; 6],
        sub0: u32, sub1: u32, sub2: u32, sub3: u32,
        sub4: u32, sub5: u32, sub6: u32, sub7: u32,
    ) -> Self {
        Self {
            revision: SID_REVISION,
            sub_authority_count: 1,
            identifier_authority: authority,
            sub_authority: [sub0, sub1, sub2, sub3, sub4, sub5, sub6, sub7],
        }
    }

    /// Create a Sid from an identifier authority and 2 subauthorities.
    pub const fn with_2subs(
        authority: [u8; 6],
        sub0: u32, sub1: u32,
    ) -> Self {
        Self {
            revision: SID_REVISION,
            sub_authority_count: 2,
            identifier_authority: authority,
            sub_authority: [sub0, sub1, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Create a Sid from an identifier authority and subauthorities array.
    pub const fn with_authority_and_subs_arr(
        authority: [u8; 6],
        count: u8,
        sub0: u32, sub1: u32, sub2: u32, sub3: u32,
        sub4: u32, sub5: u32, sub6: u32, sub7: u32,
    ) -> Self {
        Self {
            revision: SID_REVISION,
            sub_authority_count: count,
            identifier_authority: authority,
            sub_authority: [sub0, sub1, sub2, sub3, sub4, sub5, sub6, sub7],
        }
    }

    /// Create a well-known SID by name.
    pub const fn well_known(name: WellKnownSid) -> Self {
        match name {
            WellKnownSid::Null => {
                // S-1-0-0
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,0],
                    sub_authority: [0, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::World => {
                // S-1-1-0
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,1],
                    sub_authority: [0, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::Local => {
                // S-1-2-0
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,2],
                    sub_authority: [0, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::CreatorOwner => {
                // S-1-3-0
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,3],
                    sub_authority: [0, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::CreatorGroup => {
                // S-1-3-1
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,3],
                    sub_authority: [1, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::Dialup => {
                // S-1-5-1
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [1, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::Network => {
                // S-1-5-2
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [2, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::Batch => {
                // S-1-5-3
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [3, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::Interactive => {
                // S-1-5-4
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [4, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::Service => {
                // S-1-5-6
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [6, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::AnonymousLogon => {
                // S-1-5-7
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [7, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::AuthenticatedUser => {
                // S-1-5-11
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [11, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::LocalSystem => {
                // S-1-5-18
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [18, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::LocalService => {
                // S-1-5-19
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [19, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::NetworkService => {
                // S-1-5-20
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [20, 0,0,0,0,0,0,0] }
            }
            WellKnownSid::Administrators => {
                // S-1-5-32-544
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 544, 0,0,0,0,0,0] }
            }
            WellKnownSid::Users => {
                // S-1-5-32-545
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 545, 0,0,0,0,0,0] }
            }
            WellKnownSid::Guests => {
                // S-1-5-32-546
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 546, 0,0,0,0,0,0] }
            }
            WellKnownSid::PowerUsers => {
                // S-1-5-32-547
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 547, 0,0,0,0,0,0] }
            }
            WellKnownSid::AccountOperators => {
                // S-1-5-32-548
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 548, 0,0,0,0,0,0] }
            }
            WellKnownSid::ServerOperators => {
                // S-1-5-32-549
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 549, 0,0,0,0,0,0] }
            }
            WellKnownSid::PrintOperators => {
                // S-1-5-32-550
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 550, 0,0,0,0,0,0] }
            }
            WellKnownSid::BackupOperators => {
                // S-1-5-32-551
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 551, 0,0,0,0,0,0] }
            }
            WellKnownSid::Replicator => {
                // S-1-5-32-552
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 552, 0,0,0,0,0,0] }
            }
            WellKnownSid::NtVersion => {
                // S-1-5-32-554
                Self { revision: SID_REVISION, sub_authority_count: 2,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [32, 554, 0,0,0,0,0,0] }
            }
            WellKnownSid::RestrictedCode => {
                // S-1-5-12
                Self { revision: SID_REVISION, sub_authority_count: 1,
                    identifier_authority: [0,0,0,0,0,5],
                    sub_authority: [12, 0,0,0,0,0,0,0] }
            }
        }
    }

    /// Return the subauthority count.
    pub fn subauthority_count(&self) -> usize {
        self.sub_authority_count as usize
    }

    /// Return the subauthority at index i.
    pub fn subauthority(&self, i: usize) -> u32 {
        if i < SID_MAX_SUB_AUTHORITIES {
            self.sub_authority[i]
        } else {
            0
        }
    }

    /// Get the identifier authority as a u48 value.
    pub fn identifier_authority(&self) -> u64 {
        let b = &self.identifier_authority;
        ((b[0] as u64) << 40)
            | ((b[1] as u64) << 32)
            | ((b[2] as u64) << 24)
            | ((b[3] as u64) << 16)
            | ((b[4] as u64) << 8)
            | (b[5] as u64)
    }

    /// Compare two SIDs for equality.
    pub fn equals(&self, other: &Sid) -> bool {
        if self.sub_authority_count != other.sub_authority_count {
            return false;
        }
        if self.identifier_authority() != other.identifier_authority() {
            return false;
        }
        for i in 0..self.sub_authority_count as usize {
            if self.sub_authority[i] != other.sub_authority[i] {
                return false;
            }
        }
        true
    }

    /// Convert a SID to its string representation "S-R-X-Y-Z...".
    pub fn to_string(&self) -> [u16; SID_STRING_MAX] {
        let mut buf = [0u16; SID_STRING_MAX];
        let mut pos = 0;

        // "S-"
        if pos < SID_STRING_MAX { buf[pos] = 'S' as u16; pos += 1; }
        if pos < SID_STRING_MAX { buf[pos] = '-' as u16; pos += 1; }

        // Revision
        pos += write_u64(&mut buf[pos..], self.revision as u64);

        // Identifier authority (6 bytes as big-endian u48)
        let ia = self.identifier_authority();
        if pos < SID_STRING_MAX { buf[pos] = '-' as u16; pos += 1; }
        pos += write_u64(&mut buf[pos..], ia);

        // Subauthorities
        for i in 0..self.sub_authority_count as usize {
            if pos < SID_STRING_MAX { buf[pos] = '-' as u16; pos += 1; }
            pos += write_u64(&mut buf[pos..], self.sub_authority[i] as u64);
        }

        buf
    }

    /// Return the byte size of this SID (8 header + 4 * subauthority_count).
    pub fn size(&self) -> usize {
        8 + (self.sub_authority_count as usize) * 4
    }
}

fn write_u64(buf: &mut [u16], mut val: u64) -> usize {
    if val == 0 {
        if !buf.is_empty() { buf[0] = '0' as u16; }
        return 1;
    }
    let mut digits = [0u16; 20];
    let mut n = 0;
    while val > 0 && n < 20 {
        digits[n] = (b'0' as u16) + (val % 10) as u16;
        val /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[i] = digits[n - 1 - i];
    }
    n
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid(S-")?;
        write!(f, "{}", self.revision)?;
        write!(f, "-{}", self.identifier_authority())?;
        for i in 0..self.subauthority_count() {
            write!(f, "-{}", self.sub_authority[i])?;
        }
        write!(f, ")")
    }
}

/// Well-known SID types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WellKnownSid {
    Null,
    World,
    Local,
    CreatorOwner,
    CreatorGroup,
    Dialup,
    Network,
    Batch,
    Interactive,
    Service,
    AnonymousLogon,
    AuthenticatedUser,
    LocalSystem,
    LocalService,
    NetworkService,
    Administrators,
    Users,
    Guests,
    PowerUsers,
    AccountOperators,
    ServerOperators,
    PrintOperators,
    BackupOperators,
    Replicator,
    NtVersion,
    RestrictedCode,
}

/// Pre-allocated well-known SIDs for kernel use.
pub static SID_NULL: Sid = Sid::well_known(WellKnownSid::Null);
pub static SID_EVERYONE: Sid = Sid::well_known(WellKnownSid::World);
pub static SID_AUTHENTICATED_USER: Sid = Sid::well_known(WellKnownSid::AuthenticatedUser);
pub static SID_LOCAL_SYSTEM: Sid = Sid::well_known(WellKnownSid::LocalSystem);
pub static SID_ADMINISTRATORS: Sid = Sid::well_known(WellKnownSid::Administrators);
pub static SID_USERS: Sid = Sid::well_known(WellKnownSid::Users);
pub static SID_INTERACTIVE: Sid = Sid::well_known(WellKnownSid::Interactive);

pub fn init() {
    // crate::kprintln!("    SE/SID: initialized (well-known SIDs loaded)")  // kprintln disabled (memcpy crash workaround);
}
