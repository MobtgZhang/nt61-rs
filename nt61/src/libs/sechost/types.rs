//! sechost.dll — Windows 7 Security Types
//
//! Types specific to sechost.dll security operations, service control,
//! and event logging introduced in Windows 7 (NT 6.1).
//
//! References:
//!   * Microsoft Windows 7 SDK winsvc.h, winbase.h
//!   * Windows Internals 6th Edition
//!   * ReactOS 0.3.x winsvc.h

use crate::libs::kernel32::types::{BOOL, DWORD, HANDLE, LPWSTR};
use crate::libs::ntdll::types::{BYTE, PVOID, WORD};

// Re-export types for public use
pub use crate::libs::kernel32::types::INVALID_HANDLE_VALUE;
pub use crate::libs::kernel32::types::LPVOID as LPVOID_RE;

pub type ScEnumType = DWORD;
pub const SC_ENUM_PROCESS_INFO: ScEnumType = 0;

pub const SC_MANAGER_ALL_ACCESS: DWORD = 0xF003F;
pub const SC_MANAGER_CONNECT: DWORD = 0x0001;
pub const SC_MANAGER_CREATE_SERVICE: DWORD = 0x0002;
pub const SC_MANAGER_ENUMERATE_SERVICE: DWORD = 0x0004;

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

pub const SERVICE_CONFIG_DESCRIPTION: DWORD = 1;
pub const SERVICE_CONFIG_FAILURE_ACTIONS: DWORD = 2;
pub const SERVICE_CONFIG_DELAYED_AUTO_START_INFO: DWORD = 3;
pub const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: DWORD = 4;
pub const SERVICE_CONFIG_SERVICE_SID_INFO: DWORD = 5;
pub const SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO: DWORD = 6;
pub const SERVICE_CONFIG_PRESHUTDOWN_INFO: DWORD = 7;
pub const SERVICE_CONFIG_TRIGGER_INFO: DWORD = 8;
pub const SERVICE_CONFIG_PREFERRED_NODE: DWORD = 9;

pub const SERVICE_CONTROL_STOP: DWORD = 0x00000001;
pub const SERVICE_CONTROL_PAUSE: DWORD = 0x00000002;
pub const SERVICE_CONTROL_CONTINUE: DWORD = 0x00000003;
pub const SERVICE_CONTROL_INTERROGATE: DWORD = 0x00000004;
pub const SERVICE_CONTROL_SHUTDOWN: DWORD = 0x00000005;
pub const SERVICE_CONTROL_PARAMCHANGE: DWORD = 0x00000006;
pub const SERVICE_CONTROL_NETBINDADD: DWORD = 0x00000007;
pub const SERVICE_CONTROL_NETBINDREMOVE: DWORD = 0x00000008;
pub const SERVICE_CONTROL_NETBINDENABLE: DWORD = 0x00000009;
pub const SERVICE_CONTROL_NETBINDDISABLE: DWORD = 0x0000000A;

pub const SERVICE_CONTROL_PAUSE_CONTINUE: DWORD = 0x00000002;

pub const SERVICE_STOPPED: DWORD = 0x00000001;
pub const SERVICE_START_PENDING: DWORD = 0x00000002;
pub const SERVICE_STOP_PENDING: DWORD = 0x00000003;
pub const SERVICE_RUNNING: DWORD = 0x00000004;
pub const SERVICE_CONTINUE_PENDING: DWORD = 0x00000005;
pub const SERVICE_PAUSE_PENDING: DWORD = 0x00000006;
pub const SERVICE_PAUSED: DWORD = 0x00000007;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SERVICE_STATUS_PROCESS {
    pub dw_service_type: DWORD,
    pub dw_current_state: DWORD,
    pub dw_controls_accepted: DWORD,
    pub dw_win32_exit_code: DWORD,
    pub dw_service_specific_exit_code: DWORD,
    pub dw_check_point: DWORD,
    pub dw_wait_hint: DWORD,
    pub dw_process_id: DWORD,
    pub dw_service_flags: DWORD,
}

#[repr(C)]
pub struct SERVICE_DESCRIPTIONW {
    pub lp_description: LPWSTR,
}

#[repr(C)]
pub struct SERVICE_DELAYED_AUTO_START_INFO {
    pub f_delayed_autostart: BOOL,
}

pub type SeObjectType = DWORD;
pub const SE_UNKNOWN_OBJECT_TYPE: SeObjectType = 0;
pub const SE_FILE_OBJECT: SeObjectType = 1;
pub const SE_SERVICE: SeObjectType = 2;
pub const SE_PRINTER: SeObjectType = 3;
pub const SE_REGISTRY_KEY: SeObjectType = 4;
pub const SE_LMSHARE: SeObjectType = 5;
pub const SE_KERNEL_OBJECT: SeObjectType = 6;
pub const SE_WINDOW_OBJECT: SeObjectType = 7;
pub const SE_DS_OBJECT: SeObjectType = 8;
pub const SE_DS_OBJECT_ALL: SeObjectType = 9;
pub const SE_PROVIDER_DEFINED_OBJECT: SeObjectType = 10;
pub const SE_WMIGUID_OBJECT: SeObjectType = 11;
pub const SE_REGISTRY_WOW64_32KEY: SeObjectType = 12;

pub type SecurityInformation = DWORD;
pub const OWNER_SECURITY_INFORMATION: SecurityInformation = 0x00000001;
pub const GROUP_SECURITY_INFORMATION: SecurityInformation = 0x00000002;
pub const DACL_SECURITY_INFORMATION: SecurityInformation = 0x00000004;
pub const SACL_SECURITY_INFORMATION: SecurityInformation = 0x00000008;
pub const LABEL_SECURITY_INFORMATION: SecurityInformation = 0x00000010;
pub const PROTECTED_DACL_SECURITY_INFORMATION: SecurityInformation = 0x80000000;
pub const PROTECTED_SACL_SECURITY_INFORMATION: SecurityInformation = 0x40000000;
pub const UNPROTECTED_DACL_SECURITY_INFORMATION: SecurityInformation = 0x20000000;
pub const UNPROTECTED_SACL_SECURITY_INFORMATION: SecurityInformation = 0x10000000;

#[repr(C)]
pub struct TRUSTEE_W {
    pub p_multiple_trustee: *mut TRUSTEE_W,
    pub multiple_trustee_operation: DWORD,
    pub trustee_form: DWORD,
    pub trustee_type: DWORD,
    pub ptstr_name: LPWSTR,
}

pub const TRUSTEE_IS_SID: DWORD = 0;
pub const TRUSTEE_IS_NAME: DWORD = 1;
pub const TRUSTEE_BAD_FORM: DWORD = 2;
pub const TRUSTEE_IS_OBJECTS_AND_SID: DWORD = 3;
pub const TRUSTEE_IS_OBJECTS_AND_NAME: DWORD = 4;

pub const TRUSTEE_IS_UNKNOWN: DWORD = 0;
pub const TRUSTEE_IS_USER: DWORD = 1;
pub const TRUSTEE_IS_GROUP: DWORD = 2;
pub const TRUSTEE_IS_DOMAIN: DWORD = 3;
pub const TRUSTEE_IS_ALIAS: DWORD = 4;
pub const TRUSTEE_IS_WELL_KNOWN_GROUP: DWORD = 5;
pub const TRUSTEE_IS_DELETED: DWORD = 6;
pub const TRUSTEE_IS_INVALID: DWORD = 7;
pub const TRUSTEE_IS_COMPUTER: DWORD = 8;

#[repr(C)]
pub struct EXPLICIT_ACCESS_W {
    pub grf_access_permissions: DWORD,
    pub grf_access_mode: DWORD,
    pub grf_inheritance: DWORD,
    pub trustee: TRUSTEE_W,
}

pub const NOT_USED_ACCESS: DWORD = 0;
pub const GRANT_ACCESS: DWORD = 1;
pub const SET_ACCESS: DWORD = 2;
pub const DENY_ACCESS: DWORD = 3;
pub const REVOKE_ACCESS: DWORD = 4;
pub const SET_AUDIT_SUCCESS: DWORD = 5;
pub const SET_AUDIT_FAILURE: DWORD = 6;

pub type PACL = *mut ACL;

#[repr(C)]
pub struct ACL {
    pub acl_revision: BYTE,
    pub sbz1: BYTE,
    pub acl_size: WORD,
    pub ace_count: WORD,
    pub sbz2: WORD,
}

pub type PSID = PVOID;

pub const EVENTLOG_SUCCESS: WORD = 0x0000;
pub const EVENTLOG_ERROR_TYPE: WORD = 0x0001;
pub const EVENTLOG_WARNING_TYPE: WORD = 0x0002;
pub const EVENTLOG_INFORMATION_TYPE: WORD = 0x0004;
pub const EVENTLOG_AUDIT_SUCCESS: WORD = 0x0008;
pub const EVENTLOG_AUDIT_FAILURE: WORD = 0x0010;

pub type EventSourceHandle = HANDLE;

pub const ERROR_SUCCESS: DWORD = 0;
pub const ERROR_INVALID_HANDLE: DWORD = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: DWORD = 8;
pub const ERROR_INVALID_PARAMETER: DWORD = 87;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;
pub const ERROR_SERVICE_DOES_NOT_EXIST: DWORD = 1060;
pub const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: DWORD = 1061;
pub const ERROR_INVALID_SERVICE_CONTROL: DWORD = 1052;
