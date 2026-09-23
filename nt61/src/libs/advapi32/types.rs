//! advapi32 — Windows Types and Constants
//
//! Common types, constants, and structures used throughout advapi32.dll.
//! Provides Win32 API types for registry, security, services, and credentials.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::libs::ntdll::types::WCHAR;

// Re-export basic types from ntdll for public use
pub use crate::libs::ntdll::types::{DWORD, LONG, BYTE, WORD, HANDLE, PVOID, ULONG, PWSTR, PCWSTR};

pub type LPVOID = PVOID;


pub type BOOL = i32;

pub const TRUE: BOOL = 1;

pub const FALSE: BOOL = 0;


pub const ERROR_SUCCESS: DWORD = 0;
pub const ERROR_INVALID_FUNCTION: DWORD = 1;
pub const ERROR_FILE_NOT_FOUND: DWORD = 2;
pub const ERROR_PATH_NOT_FOUND: DWORD = 3;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_INVALID_HANDLE: DWORD = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: DWORD = 8;
pub const ERROR_INVALID_PARAMETER: DWORD = 87;
pub const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;
pub const ERROR_MORE_DATA: DWORD = 234;
pub const ERROR_NO_MORE_ITEMS: DWORD = 259;
pub const ERROR_SERVICE_DOES_NOT_EXIST: DWORD = 1060;
pub const ERROR_SERVICE_ALREADY_RUNNING: DWORD = 1056;
pub const ERROR_SERVICE_NOT_ACTIVE: DWORD = 1062;
pub const ERROR_BADKEY: DWORD = 1010;
pub const ERROR_CANTOPEN: DWORD = 1011;
pub const ERROR_CANTREAD: DWORD = 1012;
pub const ERROR_CANTWRITE: DWORD = 1013;
pub const ERROR_REGISTRY_CORRUPT: DWORD = 1015;
pub const ERROR_KEY_DELETED: DWORD = 1018;
pub const ERROR_NONE_MAPPED: DWORD = 1332;


pub const REG_NONE: DWORD = 0;
pub const REG_SZ: DWORD = 1;
pub const REG_EXPAND_SZ: DWORD = 2;
pub const REG_BINARY: DWORD = 3;
pub const REG_DWORD: DWORD = 4;
pub const REG_DWORD_LITTLE_ENDIAN: DWORD = 4;
pub const REG_DWORD_BIG_ENDIAN: DWORD = 5;
pub const REG_LINK: DWORD = 6;
pub const REG_MULTI_SZ: DWORD = 7;
pub const REG_RESOURCE_LIST: DWORD = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: DWORD = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: DWORD = 10;
pub const REG_QWORD: DWORD = 11;
pub const REG_QWORD_LITTLE_ENDIAN: DWORD = 11;

pub const KEY_QUERY_VALUE: DWORD = 0x0001;
pub const KEY_SET_VALUE: DWORD = 0x0002;
pub const KEY_CREATE_SUB_KEY: DWORD = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: DWORD = 0x0008;
pub const KEY_NOTIFY: DWORD = 0x0010;
pub const KEY_CREATE_LINK: DWORD = 0x0020;
pub const KEY_WOW64_64KEY: DWORD = 0x0100;
pub const KEY_WOW64_32KEY: DWORD = 0x0200;
pub const KEY_READ: DWORD = 0x20019;
pub const KEY_WRITE: DWORD = 0x20006;
pub const KEY_EXECUTE: DWORD = 0x20019;
pub const KEY_ALL_ACCESS: DWORD = 0xF003F;

pub const REG_OPTION_NON_VOLATILE: DWORD = 0;
pub const REG_OPTION_VOLATILE: DWORD = 1;
pub const REG_OPTION_CREATE_LINK: DWORD = 2;
pub const REG_OPTION_BACKUP_RESTORE: DWORD = 4;

pub const REG_CREATED_NEW_KEY: DWORD = 1;
pub const REG_OPENED_EXISTING_KEY: DWORD = 2;

pub type HKEY = HANDLE;

pub type REGSAM = DWORD;

pub type LPCWSTR = PCWSTR;
pub type LPWSTR = PWSTR;
pub type LPDWORD = *mut DWORD;
pub type LPBYTE = *mut BYTE;
pub type LPCBYTE = *const BYTE;

pub const HKEY_CLASSES_ROOT: HKEY = 0x80000000 as HKEY;
pub const HKEY_CURRENT_USER: HKEY = 0x80000001 as HKEY;
pub const HKEY_LOCAL_MACHINE: HKEY = 0x80000002 as HKEY;
pub const HKEY_USERS: HKEY = 0x80000003 as HKEY;
pub const HKEY_PERFORMANCE_DATA: HKEY = 0x80000004 as HKEY;
pub const HKEY_CURRENT_CONFIG: HKEY = 0x80000005 as HKEY;
pub const HKEY_DYN_DATA: HKEY = 0x80000006 as HKEY;


pub type PSID = PVOID;
pub type PSID_NAME_USE = *mut SID_NAME_USE;

/// SID name use enumeration
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SID_NAME_USE {
    SidTypeUser = 1,
    SidTypeGroup = 2,
    SidTypeDomain = 3,
    SidTypeAlias = 4,
    SidTypeWellKnownGroup = 5,
    SidTypeDeletedAccount = 6,
    SidTypeInvalid = 7,
    SidTypeUnknown = 8,
    SidTypeComputer = 9,
}

#[repr(C)]
pub struct ACL {
    pub AclRevision: BYTE,
    pub Sbz1: BYTE,
    pub AclSize: WORD,
    pub AceCount: WORD,
    pub Sbz2: WORD,
}

#[repr(C)]
pub struct SECURITY_DESCRIPTOR {
    pub Revision: BYTE,
    pub Sbz1: BYTE,
    pub Control: WORD,
    pub Owner: PSID,
    pub Group: PSID,
    pub Sacl: *mut ACL,
    pub Dacl: *mut ACL,
}

pub type PSECURITY_DESCRIPTOR = *mut SECURITY_DESCRIPTOR;

pub const OWNER_SECURITY_INFORMATION: DWORD = 0x00000001;
pub const GROUP_SECURITY_INFORMATION: DWORD = 0x00000002;
pub const DACL_SECURITY_INFORMATION: DWORD = 0x00000004;
pub const SACL_SECURITY_INFORMATION: DWORD = 0x00000008;
pub const LABEL_SECURITY_INFORMATION: DWORD = 0x00000010;
pub const PROTECTED_DACL_SECURITY_INFORMATION: DWORD = 0x80000000;
pub const PROTECTED_SACL_SECURITY_INFORMATION: DWORD = 0x40000000;
pub const UNPROTECTED_DACL_SECURITY_INFORMATION: DWORD = 0x20000000;
pub const UNPROTECTED_SACL_SECURITY_INFORMATION: DWORD = 0x10000000;


pub type SC_HANDLE = HANDLE;

pub const SERVICE_KERNEL_DRIVER: DWORD = 0x00000001;
pub const SERVICE_FILE_SYSTEM_DRIVER: DWORD = 0x00000002;
pub const SERVICE_ADAPTER: DWORD = 0x00000004;
pub const SERVICE_RECOGNIZER_DRIVER: DWORD = 0x00000008;
pub const SERVICE_WIN32_OWN_PROCESS: DWORD = 0x00000010;
pub const SERVICE_WIN32_SHARE_PROCESS: DWORD = 0x00000020;
pub const SERVICE_INTERACTIVE_PROCESS: DWORD = 0x00000100;

pub const SERVICE_BOOT_START: DWORD = 0x00000000;
pub const SERVICE_SYSTEM_START: DWORD = 0x00000001;
pub const SERVICE_AUTO_START: DWORD = 0x00000002;
pub const SERVICE_DEMAND_START: DWORD = 0x00000003;
pub const SERVICE_DISABLED: DWORD = 0x00000004;

pub const SERVICE_ERROR_IGNORE: DWORD = 0x00000000;
pub const SERVICE_ERROR_NORMAL: DWORD = 0x00000001;
pub const SERVICE_ERROR_SEVERE: DWORD = 0x00000002;
pub const SERVICE_ERROR_CRITICAL: DWORD = 0x00000003;

pub const SERVICE_STOPPED: DWORD = 0x00000001;
pub const SERVICE_START_PENDING: DWORD = 0x00000002;
pub const SERVICE_STOP_PENDING: DWORD = 0x00000003;
pub const SERVICE_RUNNING: DWORD = 0x00000004;
pub const SERVICE_CONTINUE_PENDING: DWORD = 0x00000005;
pub const SERVICE_PAUSE_PENDING: DWORD = 0x00000006;
pub const SERVICE_PAUSED: DWORD = 0x00000007;

pub const SERVICE_CONTROL_STOP: DWORD = 0x00000001;
pub const SERVICE_CONTROL_PAUSE: DWORD = 0x00000002;
pub const SERVICE_CONTROL_CONTINUE: DWORD = 0x00000003;
pub const SERVICE_CONTROL_INTERROGATE: DWORD = 0x00000004;
pub const SERVICE_CONTROL_SHUTDOWN: DWORD = 0x00000005;

pub const SERVICE_ALL_ACCESS: DWORD = 0xF01FF;
pub const SERVICE_QUERY_CONFIG: DWORD = 0x0001;
pub const SERVICE_CHANGE_CONFIG: DWORD = 0x0002;
pub const SERVICE_QUERY_STATUS: DWORD = 0x0004;
pub const SERVICE_ENUMERATE_DEPENDENTS: DWORD = 0x0008;
pub const SERVICE_START: DWORD = 0x0010;
pub const SERVICE_STOP: DWORD = 0x0020;
pub const SERVICE_PAUSE_CONTINUE: DWORD = 0x0040;
pub const SERVICE_INTERROGATE: DWORD = 0x0080;
pub const SERVICE_USER_DEFINED_CONTROL: DWORD = 0x0100;

pub const SC_MANAGER_ALL_ACCESS: DWORD = 0xF003F;
pub const SC_MANAGER_CONNECT: DWORD = 0x0001;
pub const SC_MANAGER_CREATE_SERVICE: DWORD = 0x0002;
pub const SC_MANAGER_ENUMERATE_SERVICE: DWORD = 0x0004;
pub const SC_MANAGER_LOCK: DWORD = 0x0008;
pub const SC_MANAGER_QUERY_LOCK_STATUS: DWORD = 0x0010;
pub const SC_MANAGER_MODIFY_BOOT_CONFIG: DWORD = 0x0020;

#[repr(C)]
pub struct SERVICE_STATUS {
    pub dwServiceType: DWORD,
    pub dwCurrentState: DWORD,
    pub dwControlsAccepted: DWORD,
    pub dwWin32ExitCode: DWORD,
    pub dwServiceSpecificExitCode: DWORD,
    pub dwCheckPoint: DWORD,
    pub dwWaitHint: DWORD,
}

pub type LPSERVICE_STATUS = *mut SERVICE_STATUS;


pub type HANDLE_EVENTLOG = HANDLE;

pub const EVENTLOG_SUCCESS: WORD = 0x0000;
pub const EVENTLOG_ERROR_TYPE: WORD = 0x0001;
pub const EVENTLOG_WARNING_TYPE: WORD = 0x0002;
pub const EVENTLOG_INFORMATION_TYPE: WORD = 0x0004;
pub const EVENTLOG_AUDIT_SUCCESS: WORD = 0x0008;
pub const EVENTLOG_AUDIT_FAILURE: WORD = 0x0010;


pub const CRED_TYPE_GENERIC: DWORD = 1;
pub const CRED_TYPE_DOMAIN_PASSWORD: DWORD = 2;
pub const CRED_TYPE_DOMAIN_CERTIFICATE: DWORD = 3;
pub const CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: DWORD = 4;
pub const CRED_TYPE_GENERIC_CERTIFICATE: DWORD = 5;
pub const CRED_TYPE_DOMAIN_EXTENDED: DWORD = 6;

pub const CRED_PERSIST_SESSION: DWORD = 1;
pub const CRED_PERSIST_LOCAL_MACHINE: DWORD = 2;
pub const CRED_PERSIST_ENTERPRISE: DWORD = 3;

#[repr(C)]
pub struct CREDENTIALW {
    pub Flags: DWORD,
    pub Type: DWORD,
    pub TargetName: PWSTR,
    pub Comment: PWSTR,
    pub LastWritten: FILETIME,
    pub CredentialBlobSize: DWORD,
    pub CredentialBlob: *mut BYTE,
    pub Persist: DWORD,
    pub AttributeCount: DWORD,
    pub Attributes: PVOID,
    pub TargetAlias: PWSTR,
    pub UserName: PWSTR,
}

pub type PCREDENTIALW = *mut CREDENTIALW;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}


#[repr(C)]
#[derive(Clone, Copy)]
pub struct LUID {
    pub LowPart: DWORD,
    pub HighPart: LONG,
}

#[repr(C)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: DWORD,
}

pub const TOKEN_QUERY: DWORD = 0x0008;
pub const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
pub const TOKEN_ADJUST_GROUPS: DWORD = 0x0040;
pub const TOKEN_ADJUST_DEFAULT: DWORD = 0x0080;

pub const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: DWORD = 0x00000001;
pub const SE_PRIVILEGE_REMOVED: DWORD = 0x00000004;


pub fn nt_status_to_win32(status: i32) -> DWORD {
    use crate::libs::ntdll::status::*;

    match status {
        STATUS_SUCCESS => ERROR_SUCCESS,
        STATUS_ACCESS_DENIED => ERROR_ACCESS_DENIED,
        STATUS_INVALID_HANDLE => ERROR_INVALID_HANDLE,
        STATUS_INVALID_PARAMETER => ERROR_INVALID_PARAMETER,
        STATUS_NO_MEMORY => ERROR_NOT_ENOUGH_MEMORY,
        STATUS_BUFFER_TOO_SMALL => ERROR_INSUFFICIENT_BUFFER,
        STATUS_BUFFER_OVERFLOW => ERROR_FILE_NOT_FOUND,  // Also covers STATUS_OBJECT_NAME_NOT_FOUND (same value)
        STATUS_NO_MORE_ENTRIES => ERROR_NO_MORE_ITEMS,
        _ => {
            if status >= 0 {
                ERROR_SUCCESS
            } else {
                ERROR_INVALID_FUNCTION
            }
        }
    }
}

pub fn is_predefined_key(key: HKEY) -> bool {
    let addr = key as usize;
    addr >= 0x80000000 && addr <= 0x80000006
}
