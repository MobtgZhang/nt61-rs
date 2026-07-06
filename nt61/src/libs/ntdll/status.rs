//! ntdll — NTSTATUS codes & error translation
//
//! Public NTSTATUS values used by the ntdll stubs. We only
//! enumerate the codes that the stubs actually return; the full
//! table in the NT DDK has ~7000 entries but only ~30 are
//! required for the public Native API surface we expose.
//
//! `nt_status_to_dos_error` implements the RtlNtStatusToDosError
//! mapping defined by the NT 6.1 SDK (a fixed table with ~400
//! rows). The DLL stubs use this when they need to convert
//! NTSTATUS → Win32 `GetLastError` value for the kernel32 layer.

use super::types::NTSTATUS;

// We don't re-export NTSTATUS here because it's already `pub`
// in `super::types`. Downstream modules import it from
// `super::types` directly.

// ---------------------------------------------------------------------------
// Severity bits (the top two bits of NTSTATUS)
// ---------------------------------------------------------------------------

pub const STATUS_SEVERITY_SUCCESS: u32 = 0x0;
pub const STATUS_SEVERITY_INFORMATIONAL: u32 = 0x1;
pub const STATUS_SEVERITY_WARNING: u32 = 0x2;
pub const STATUS_SEVERITY_ERROR: u32 = 0x3;

pub fn status_severity(s: NTSTATUS) -> u32 {
    ((s as u32) >> 30) & 0x3
}

pub fn status_is_success(s: NTSTATUS) -> bool {
    s >= 0
}

pub fn status_is_error(s: NTSTATUS) -> bool {
    s < 0
}

// ---------------------------------------------------------------------------
// Public NTSTATUS codes (the subset we use)
// ---------------------------------------------------------------------------

pub const STATUS_SUCCESS: NTSTATUS                 = 0x00000000;
pub const STATUS_PENDING: NTSTATUS                 = 0x00000103;
pub const STATUS_TIMEOUT: NTSTATUS                 = 0x00000102;
pub const STATUS_WAIT_0: NTSTATUS                  = 0x00000000;
pub const STATUS_WAIT_1: NTSTATUS                  = 0x00000001;
pub const STATUS_WAIT_2: NTSTATUS                  = 0x00000002;
pub const STATUS_WAIT_63: NTSTATUS                 = 0x0000003F;
pub const STATUS_ABANDONED: NTSTATUS               = 0x00000080;
pub const STATUS_ABANDONED_WAIT_0: NTSTATUS        = 0x00000080;
pub const STATUS_ABANDONED_WAIT_63: NTSTATUS       = 0x000000BF;
pub const STATUS_USER_APC: NTSTATUS                = 0x000000C0;
pub const STATUS_KERNEL_APC: NTSTATUS              = 0x00000100;
pub const STATUS_ALERTED: NTSTATUS                 = 0x00000101;

pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS    = 0xC0000004_u32 as i32;
pub const STATUS_ACCESS_VIOLATION: NTSTATUS        = 0xC0000005_u32 as i32;
pub const STATUS_UNSUCCESSFUL: NTSTATUS        = 0xC0000001_u32 as i32;  // 0xC0000001
pub const STATUS_NOT_IMPLEMENTED: NTSTATUS         = 0xC0000002_u32 as i32;
pub const STATUS_INVALID_HANDLE: NTSTATUS          = 0xC0000008_u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS       = 0xC000000D_u32 as i32;
pub const STATUS_NO_SUCH_DEVICE: NTSTATUS          = 0xC000000E_u32 as i32;
pub const STATUS_NO_SUCH_FILE: NTSTATUS            = 0xC000000F_u32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: NTSTATUS  = 0xC0000010_u32 as i32;
pub const STATUS_END_OF_FILE: NTSTATUS             = 0xC0000011_u32 as i32;
pub const STATUS_MORE_PROCESSING_REQUIRED: NTSTATUS= 0xC0000016_u32 as i32;
pub const STATUS_NO_MEMORY: NTSTATUS               = 0xC0000017_u32 as i32;
pub const STATUS_CONFLICTING_ADDRESSES: NTSTATUS   = 0xC0000018_u32 as i32;
pub const STATUS_NOT_MAPPED_VIEW: NTSTATUS         = 0xC0000019_u32 as i32;
pub const STATUS_UNABLE_TO_FREE_VM: NTSTATUS       = 0xC000001A_u32 as i32;
pub const STATUS_UNABLE_TO_DELETE_SECTION: NTSTATUS= 0xC000001B_u32 as i32;
pub const STATUS_INVALID_SYSTEM_SERVICE: NTSTATUS  = 0xC000001C_u32 as i32;
pub const STATUS_ILLEGAL_INSTRUCTION: NTSTATUS     = 0xC000001D_u32 as i32;
pub const STATUS_INVALID_LOCK_SEQUENCE: NTSTATUS   = 0xC000001E_u32 as i32;
pub const STATUS_INVALID_VIEW_SIZE: NTSTATUS       = 0xC000001F_u32 as i32;
pub const STATUS_INVALID_FILE_FOR_SECTION: NTSTATUS= 0xC0000020_u32 as i32;
pub const STATUS_ALREADY_COMMITTED: NTSTATUS       = 0xC0000021_u32 as i32;
pub const STATUS_ACCESS_DENIED: NTSTATUS           = 0xC0000022_u32 as i32;
pub const STATUS_BUFFER_OVERFLOW: NTSTATUS         = 0xC0000034_u32 as i32;
pub const STATUS_NO_MORE_ENTRIES: NTSTATUS        = 0x8000001F_u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS        = 0xC0000023_u32 as i32;
pub const STATUS_OBJECT_TYPE_MISMATCH: NTSTATUS    = 0xC0000024_u32 as i32;
pub const STATUS_NONCONTINUABLE_EXCEPTION: NTSTATUS= 0xC0000025_u32 as i32;
pub const STATUS_INVALID_DISPOSITION: NTSTATUS     = 0xC0000026_u32 as i32;
pub const STATUS_UNWIND: NTSTATUS                  = 0xC0000027_u32 as i32;
pub const STATUS_BAD_STACK: NTSTATUS               = 0xC0000028_u32 as i32;
pub const STATUS_INVALID_UNWIND_TARGET: NTSTATUS   = 0xC0000029_u32 as i32;
pub const STATUS_NOT_LOCKED: NTSTATUS              = 0xC000002A_u32 as i32;
pub const STATUS_PARITY_ERROR: NTSTATUS            = 0xC000002B_u32 as i32;
pub const STATUS_UNABLE_TO_DECOMMIT_VM: NTSTATUS   = 0xC000002C_u32 as i32;
pub const STATUS_NOT_COMMITTED: NTSTATUS           = 0xC000002D_u32 as i32;
pub const STATUS_INVALID_PORT_ATTRIBUTES: NTSTATUS = 0xC000002E_u32 as i32;
pub const STATUS_PORT_DISCONNECTED: NTSTATUS       = 0xC0000037_u32 as i32;
pub const STATUS_DEVICE_ALREADY_ATTACHED: NTSTATUS = 0xC0000038_u32 as i32;
pub const STATUS_OBJECT_NAME_INVALID: NTSTATUS     = 0xC0000033_u32 as i32;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS   = 0xC0000034_u32 as i32;
pub const STATUS_OBJECT_NAME_COLLISION: NTSTATUS   = 0xC0000035_u32 as i32;
pub const STATUS_OBJECT_PATH_INVALID: NTSTATUS     = 0xC0000039_u32 as i32;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NTSTATUS   = 0xC000003A_u32 as i32;
pub const STATUS_OBJECT_PATH_SYNTAX_BAD: NTSTATUS  = 0xC000003B_u32 as i32;
pub const STATUS_NAME_TOO_LONG: NTSTATUS           = 0xC0000102_u32 as i32;
pub const STATUS_IO_DEVICE_ERROR: NTSTATUS         = 0xC0000185_u32 as i32;
pub const STATUS_DEVICE_NOT_READY: NTSTATUS        = 0xC00000A3_u32 as i32;
pub const STATUS_PRIVILEGE_NOT_HELD: NTSTATUS     = 0xC0000061_u32 as i32;
pub const STATUS_PROCESS_IS_TERMINATING: NTSTATUS  = 0xC0000005_u32 as i32;
pub const STATUS_INVALID_IMAGE_FORMAT: NTSTATUS    = 0xC000007B_u32 as i32;
pub const STATUS_DRIVER_ENTRYPOINT_NOT_FOUND: NTSTATUS = 0xC000003C_u32 as i32;
pub const STATUS_RESOURCE_NOT_OWNED: NTSTATUS      = 0xC0000264_u32 as i32;
pub const STATUS_INVALID_LOCK_STATE: NTSTATUS      = 0xC000001E_u32 as i32;
pub const STATUS_DELETE_PENDING: NTSTATUS          = 0xC0000056_u32 as i32;
pub const STATUS_FILE_LOCK_CONFLICT: NTSTATUS      = 0xC0000054_u32 as i32;
pub const STATUS_NOT_A_DIRECTORY: NTSTATUS         = 0xC0000103_u32 as i32;
pub const STATUS_DIRECTORY_NOT_EMPTY: NTSTATUS     = 0xC0000101_u32 as i32;
pub const STATUS_SHARING_VIOLATION: NTSTATUS       = 0xC0000043_u32 as i32;
pub const STATUS_HANDLE_NOT_CLOSABLE: NTSTATUS     = 0xC0000235_u32 as i32;
pub const STATUS_DLL_NOT_FOUND: NTSTATUS           = 0xC0000135_u32 as i32;
pub const STATUS_NOT_FOUND: NTSTATUS               = 0xC0000225_u32 as i32;
pub const STATUS_INVALID_INFO_CLASS: NTSTATUS      = 0xC0000003_u32 as i32;
pub const STATUS_MUTEX_NOT_OWNED: NTSTATUS         = 0xC0000055_u32 as i32;
pub const STATUS_FILE_IS_A_DIRECTORY: NTSTATUS   = 0xC00000BA_u32 as i32;
pub const STATUS_CANNOT_DELETE: NTSTATUS        = 0xC0000139_u32 as i32;

// ---------------------------------------------------------------------------
// Win32 error codes (subset; same values as error.rs in kernel32)
// ---------------------------------------------------------------------------

pub const ERROR_SUCCESS: u32                = 0;
pub const ERROR_INVALID_FUNCTION: u32       = 1;
pub const ERROR_FILE_NOT_FOUND: u32         = 2;
pub const ERROR_PATH_NOT_FOUND: u32         = 3;
pub const ERROR_TOO_MANY_OPEN_FILES: u32    = 4;
pub const ERROR_ACCESS_DENIED: u32          = 5;
pub const ERROR_INVALID_HANDLE: u32         = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32      = 8;
pub const ERROR_INVALID_DATA: u32           = 13;
pub const ERROR_INVALID_PARAMETER: u32      = 87;
pub const ERROR_INVALID_NAME: u32           = 123;
pub const ERROR_DIR_NOT_EMPTY: u32          = 145;
pub const ERROR_ALREADY_EXISTS: u32         = 183;
pub const ERROR_SHARING_VIOLATION: u32      = 32;
pub const ERROR_LOCK_VIOLATION: u32         = 33;
pub const ERROR_HANDLE_DISK_FULL: u32       = 39;
pub const ERROR_FILE_EXISTS: u32            = 80;
pub const ERROR_DISK_FULL: u32              = 112;
pub const ERROR_INVALID_ADDRESS: u32        = 487;
pub const ERROR_IO_DEVICE: u32              = 1117;
pub const ERROR_NOT_READY: u32              = 21;
pub const ERROR_PARTIAL_COPY: u32           = 299;
pub const ERROR_NOACCESS: u32               = 998;
pub const ERROR_NOT_IMPLEMENTED: u32        = 50;
pub const ERROR_INSUFFICIENT_BUFFER: u32    = 122;
pub const ERROR_NO_MORE_FILES: u32          = 18;
pub const ERROR_MOD_NOT_FOUND: u32          = 126;
pub const ERROR_PROC_NOT_FOUND: u32         = 127;
pub const ERROR_BAD_EXE_FORMAT: u32         = 193;
pub const ERROR_TIMEOUT: u32                = 1460;
pub const ERROR_PIPE_BUSY: u32              = 231;
pub const ERROR_MORE_DATA: u32              = 234;
pub const ERROR_NO_DATA: u32                = 232;
pub const ERROR_INVALID_CATEGORY: u32       = 669;
pub const ERROR_INVALID_USER_BUFFER: u32    = 1784;
pub const ERROR_NOT_LOCKED: u32              = 158;

// ---------------------------------------------------------------------------
// RtlNtStatusToDosError — NT 6.1 SDK mapping table (subset)
// ---------------------------------------------------------------------------

/// Map an NTSTATUS to a Win32 error code. Returns the closest
/// Win32 code as defined by the NT 6.1 SDK
/// `RtlNtStatusToDosError` table. Codes that are not in the
/// table fall through to a default mapping based on the
/// `STATUS_SEVERITY` bits.
pub fn nt_status_to_dos_error(s: NTSTATUS) -> u32 {
    let s = s as u32;
    match s {
        0x00000000 => ERROR_SUCCESS,
        0x00000103 => ERROR_IO_PENDING,
        0x00000102 => ERROR_TIMEOUT,
        0xC0000002 => ERROR_INVALID_FUNCTION,
        0xC0000005 => ERROR_ACCESS_DENIED,
        0xC0000008 => ERROR_INVALID_HANDLE,
        0xC000000D => ERROR_INVALID_PARAMETER,
        0xC000000E => ERROR_NOT_READY,
        0xC000000F => ERROR_FILE_NOT_FOUND,
        0xC0000010 => ERROR_INVALID_FUNCTION,
        0xC0000011 => ERROR_HANDLE_EOF,
        0xC0000017 => ERROR_NOT_ENOUGH_MEMORY,
        0xC0000018 => ERROR_INVALID_ADDRESS,
        0xC0000019 => ERROR_INVALID_ADDRESS,
        0xC000001A => ERROR_INVALID_ADDRESS,
        0xC0000021 => ERROR_FILE_NOT_FOUND,
        0xC0000022 => ERROR_ACCESS_DENIED,
        0xC0000023 => ERROR_INSUFFICIENT_BUFFER,
        0xC0000024 => ERROR_INVALID_FUNCTION,
        0xC0000025 => ERROR_INVALID_ADDRESS,
        0xC0000026 => ERROR_INVALID_PARAMETER,
        0xC0000027 => ERROR_INVALID_PARAMETER,
        0xC0000033 => ERROR_INVALID_NAME,
        0xC0000034 => ERROR_FILE_NOT_FOUND,
        0xC0000035 => ERROR_FILE_EXISTS,
        0xC0000037 => ERROR_INVALID_HANDLE,
        0xC0000038 => ERROR_INVALID_FUNCTION,
        0xC0000039 => ERROR_INVALID_NAME,
        0xC000003A => ERROR_PATH_NOT_FOUND,
        0xC000003B => ERROR_INVALID_NAME,
        0xC0000043 => ERROR_SHARING_VIOLATION,
        0xC0000054 => ERROR_LOCK_VIOLATION,
        0xC0000056 => ERROR_ACCESS_DENIED,
        0xC000007B => ERROR_BAD_EXE_FORMAT,
        0xC0000101 => ERROR_DIR_NOT_EMPTY,
        0xC0000102 => ERROR_INVALID_NAME,
        0xC0000103 => ERROR_INVALID_NAME,
        0xC0000185 => ERROR_IO_DEVICE,
        0xC0000235 => ERROR_INVALID_HANDLE,
        0xC0000264 => ERROR_NOT_LOCKED,
        _ => {
            // Default: error → generic access denied
            if (s >> 30) & 0x3 == STATUS_SEVERITY_WARNING {
                ERROR_IO_PENDING
            } else {
                ERROR_INVALID_FUNCTION
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Additional Win32 error codes
// ---------------------------------------------------------------------------

pub const ERROR_IO_PENDING: u32          = 997;
pub const ERROR_HANDLE_EOF: u32          = 38;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_round_trip() {
        assert!(status_is_success(STATUS_SUCCESS));
        assert!(!status_is_error(STATUS_SUCCESS));
        assert_eq!(nt_status_to_dos_error(STATUS_SUCCESS), ERROR_SUCCESS);
    }

    #[test]
    fn error_severity() {
        assert_eq!(status_severity(STATUS_SUCCESS), STATUS_SEVERITY_SUCCESS);
        assert_eq!(status_severity(STATUS_PENDING), STATUS_SEVERITY_SUCCESS);
        assert_eq!(status_severity(STATUS_INVALID_HANDLE), STATUS_SEVERITY_ERROR);
    }

    #[test]
    fn known_translations() {
        assert_eq!(nt_status_to_dos_error(STATUS_INVALID_HANDLE), ERROR_INVALID_HANDLE);
        assert_eq!(nt_status_to_dos_error(STATUS_NO_MEMORY), ERROR_NOT_ENOUGH_MEMORY);
        assert_eq!(nt_status_to_dos_error(STATUS_BUFFER_TOO_SMALL), ERROR_INSUFFICIENT_BUFFER);
        assert_eq!(nt_status_to_dos_error(STATUS_OBJECT_NAME_NOT_FOUND), ERROR_FILE_NOT_FOUND);
        assert_eq!(nt_status_to_dos_error(STATUS_OBJECT_PATH_NOT_FOUND), ERROR_PATH_NOT_FOUND);
        assert_eq!(nt_status_to_dos_error(STATUS_NOT_IMPLEMENTED), ERROR_INVALID_FUNCTION);
        assert_eq!(nt_status_to_dos_error(STATUS_SHARING_VIOLATION), ERROR_SHARING_VIOLATION);
    }
}
