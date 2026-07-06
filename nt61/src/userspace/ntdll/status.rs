//! NTSTATUS values (subset).
//!
//! Only the codes most commonly used by the userspace subsystem
//! are listed — Phase 2 will extend as needed. Values from
//! `ntstatus.h` (Windows 7 SDK).

#![allow(dead_code, non_snake_case)]

pub const STATUS_SUCCESS: i32                    = 0x0000_0000;
pub const STATUS_WAIT_0: i32                     = 0x0000_0000;
pub const STATUS_WAIT_1: i32                     = 0x0000_0001;
pub const STATUS_WAIT_2: i32                     = 0x0000_0002;
pub const STATUS_WAIT_3: i32                     = 0x0000_0003;
pub const STATUS_WAIT_63: i32                    = 0x0000_003F;
pub const STATUS_TIMEOUT: i32                    = 0x0000_0102;
pub const STATUS_PENDING: i32                    = 0x0000_0103;
pub const STATUS_REPARSE: i32                    = 0x0000_0104;
pub const STATUS_MORE_ENTRIES: i32               = 0x0000_0105;
pub const STATUS_NOT_ALL_ASSIGNED: i32           = 0x0000_0106;
pub const STATUS_SOME_NOT_MAPPED: i32            = 0x0000_0107;
pub const STATUS_OPLOCK_BREAK_IN_PROGRESS: i32   = 0x0000_0108;
pub const STATUS_VOLUME_DISMOUNTED: i32          = 0x0000_0109;
pub const STATUS_RXACT_COMMITTED: i32            = 0x0000_010A;
pub const STATUS_CHECKING_FILE_SYSTEM: i32       = 0x0000_010B;

pub const STATUS_UNSUCCESSFUL: i32               = 0xC0000001_u32 as i32;
pub const STATUS_NOT_IMPLEMENTED: i32            = 0xC0000002_u32 as i32;
pub const STATUS_INVALID_INFO_CLASS: i32         = 0xC0000003_u32 as i32;
pub const STATUS_INFO_LENGTH_MISMATCH: i32       = 0xC0000004_u32 as i32;

pub const STATUS_NO_SUCH_DEVICE: i32             = 0xC000000E_u32 as i32;

pub const STATUS_INVALID_DEVICE_REQUEST: i32     = 0xC0000010_u32 as i32;
pub const STATUS_END_OF_FILE: i32                = 0xC0000011_u32 as i32;
pub const STATUS_WRONG_VOLUME: i32               = 0xC0000012_u32 as i32;
pub const STATUS_NO_MEDIA_IN_DEVICE: i32         = 0xC0000013_u32 as i32;

pub const STATUS_NO_MEMORY: i32                  = 0xC0000017_u32 as i32;
pub const STATUS_ALREADY_COMMITTED: i32          = 0xC0000018_u32 as i32;
pub const STATUS_ACCESS_DENIED: i32              = 0xC0000022_u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: i32           = 0xC0000023_u32 as i32;

pub const STATUS_OBJECT_NAME_INVALID: i32        = 0xC0000033_u32 as i32;
pub const STATUS_OBJECT_NAME_NOT_FOUND: i32      = 0xC0000034_u32 as i32;
pub const STATUS_OBJECT_NAME_COLLISION: i32      = 0xC0000035_u32 as i32;
pub const STATUS_OBJECT_PATH_INVALID: i32        = 0xC000003A_u32 as i32;
pub const STATUS_OBJECT_PATH_NOT_FOUND: i32      = 0xC000003B_u32 as i32;
pub const STATUS_OBJECT_PATH_SYNTAX_BAD: i32     = 0xC000003C_u32 as i32;

pub const STATUS_IO_DEVICE_ERROR: i32            = 0xC000009C_u32 as i32;
pub const STATUS_DEVICE_BUSY: i32                = 0x8000000A_u32 as i32;

pub const STATUS_INVALID_PARAMETER: i32          = 0xC000000D_u32 as i32;
pub const STATUS_INVALID_PARAMETER_1: i32        = 0xC00000EF_u32 as i32;
pub const STATUS_INVALID_PARAMETER_2: i32        = 0xC00000F0_u32 as i32;

pub const STATUS_INVALID_HANDLE: i32             = 0xC0000008_u32 as i32;
pub const STATUS_HANDLE_NOT_CLOSABLE: i32        = 0xC0000026_u32 as i32;

pub const STATUS_INVALID_IMAGE_FORMAT: i32       = 0xC000007B_u32 as i32;
pub const STATUS_NO_TOKEN: i32                   = 0xC000007C_u32 as i32;
pub const STATUS_BAD_IMPERSONATION_LEVEL: i32    = 0xC00000A5_u32 as i32;
pub const STATUS_BAD_TOKEN_TYPE: i32             = 0xC00000A6_u32 as i32;

pub const STATUS_PROCESS_IS_TERMINATING: i32     = 0xC000010A_u32 as i32;

pub const STATUS_NOT_FOUND: i32                  = 0xC0000225_u32 as i32;
pub const STATUS_NOT_A_DIRECTORY: i32            = 0xC0000103_u32 as i32;

pub const STATUS_DIRECTORY_NOT_EMPTY: i32        = 0xC0000101_u32 as i32;

pub const STATUS_PRIVILEGE_NOT_HELD: i32         = 0xC0000061_u32 as i32;

/// Convert NTSTATUS to Result<()>.
pub fn status_check(s: i32) -> Result<(), ()> {
    if s >= 0 { Ok(()) } else { Err(()) }
}

/// Severity bits.
pub const fn nt_success(s: i32) -> bool { s >= 0 }
pub const fn nt_information(s: i32) -> bool { (s >> 30) == 1 }
pub const fn nt_warning(s: i32) -> bool { (s >> 30) == 2 }
pub const fn nt_error(s: i32) -> bool { (s >> 30) == 3 }
