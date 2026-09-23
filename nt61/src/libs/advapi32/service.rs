//! advapi32 — Service Control Manager APIs
//
//! Implements Windows Service Control Manager (SCM) functions:
//! - OpenSCManagerW — Connect to the SCM
//! - CreateServiceW — Create a new service
//! - OpenServiceW — Open an existing service
//! - StartServiceW — Start a service
//! - ControlService — Send control codes to a service
//! - DeleteService — Delete a service
//! - QueryServiceStatus — Query service status
//! - ChangeServiceConfigW — Modify service configuration
//! - EnumServicesStatusW — Enumerate services

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case, non_upper_case_globals, dead_code)]

use super::types::*;
use crate::libs::ntdll::types::{HANDLE, PVOID, DWORD, PWSTR, PCWSTR};
use core::ptr::{null_mut, null};
use alloc::vec::Vec;
use alloc::string::String;


const MAX_SERVICES: usize = 128;

#[derive(Copy, Clone)]
struct ServiceEntry {
    name: [u16; 64],
    display_name: [u16; 128],
    service_type: DWORD,
    start_type: DWORD,
    error_control: DWORD,
    binary_path: [u16; 260],
    current_state: DWORD,
    controls_accepted: DWORD,
    win32_exit_code: DWORD,
    service_exit_code: DWORD,
    checkpoint: DWORD,
    wait_hint: DWORD,
    in_use: bool,
}

impl ServiceEntry {
    const fn new() -> Self {
        Self {
            name: [0; 64],
            display_name: [0; 128],
            service_type: SERVICE_WIN32_OWN_PROCESS,
            start_type: SERVICE_DEMAND_START,
            error_control: SERVICE_ERROR_NORMAL,
            binary_path: [0; 260],
            current_state: SERVICE_STOPPED,
            controls_accepted: 0,
            win32_exit_code: 0,
            service_exit_code: 0,
            checkpoint: 0,
            wait_hint: 0,
            in_use: false,
        }
    }
}

static mut SERVICE_TABLE: [ServiceEntry; MAX_SERVICES] = [ServiceEntry::new(); MAX_SERVICES];

#[derive(Copy, Clone)]
struct ScmHandle {
    access: DWORD,
    service_index: Option<usize>,
    in_use: bool,
}

const MAX_SCM_HANDLES: usize = 64;

static mut SCM_HANDLES: [ScmHandle; MAX_SCM_HANDLES] = [ScmHandle {
    access: 0,
    service_index: None,
    in_use: false,
}; MAX_SCM_HANDLES];

fn alloc_scm_handle(access: DWORD, service_index: Option<usize>) -> Option<SC_HANDLE> {
    unsafe {
        for (i, entry) in SCM_HANDLES.iter_mut().enumerate() {
            if !entry.in_use {
                entry.access = access;
                entry.service_index = service_index;
                entry.in_use = true;
                return Some((0x2000 + i * 4) as SC_HANDLE);
            }
        }
    }
    None
}

fn free_scm_handle(handle: SC_HANDLE) -> bool {
    let index = ((handle as usize) - 0x2000) / 4;
    unsafe {
        if index < MAX_SCM_HANDLES && SCM_HANDLES[index].in_use {
            SCM_HANDLES[index].in_use = false;
            return true;
        }
    }
    false
}

fn get_scm_handle(handle: SC_HANDLE) -> Option<&'static ScmHandle> {
    let index = ((handle as usize) - 0x2000) / 4;
    unsafe {
        if index < MAX_SCM_HANDLES && SCM_HANDLES[index].in_use {
            return Some(&SCM_HANDLES[index]);
        }
    }
    None
}

unsafe fn find_service(name: PCWSTR) -> Option<usize> {
    if name.is_null() {
        return None;
    }

    for (i, service) in SERVICE_TABLE.iter().enumerate() {
        if !service.in_use {
            continue;
        }

        let mut match_found = true;
        let mut j = 0;
        let mut p = name;
        while j < service.name.len() && !p.is_null() && *p != 0 && service.name[j] != 0 {
            if service.name[j] != *p {
                match_found = false;
                break;
            }
            j += 1;
            p = p.offset(1);
        }

        if match_found && (j >= service.name.len() || service.name[j] == 0) && (p.is_null() || *p == 0) {
            return Some(i);
        }
    }

    None
}

unsafe fn alloc_service() -> Option<usize> {
    for (i, service) in SERVICE_TABLE.iter_mut().enumerate() {
        if !service.in_use {
            service.in_use = true;
            return Some(i);
        }
    }
    None
}

unsafe fn copy_to_buffer(dest: &mut [u16], src: PCWSTR) {
    if src.is_null() {
        dest[0] = 0;
        return;
    }

    let mut i = 0;
    let mut p = src;
    while i < dest.len() - 1 && !p.is_null() && *p != 0 {
        dest[i] = *p;
        i += 1;
        p = p.offset(1);
    }
    dest[i] = 0;
}


#[no_mangle]
pub unsafe extern "C" fn OpenSCManagerW(
    lpMachineName: PCWSTR,
    lpDatabaseName: PCWSTR,
    dwDesiredAccess: DWORD,
) -> SC_HANDLE {
    match alloc_scm_handle(dwDesiredAccess, None) {
        Some(handle) => handle,
        None => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn CloseServiceHandle(hSCObject: SC_HANDLE) -> LONG {
    if free_scm_handle(hSCObject) {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

#[no_mangle]
pub unsafe extern "C" fn CreateServiceW(
    hSCManager: SC_HANDLE,
    lpServiceName: PCWSTR,
    lpDisplayName: PCWSTR,
    dwDesiredAccess: DWORD,
    dwServiceType: DWORD,
    dwStartType: DWORD,
    dwErrorControl: DWORD,
    lpBinaryPathName: PCWSTR,
    lpLoadOrderGroup: PCWSTR,
    lpdwTagId: *mut DWORD,
    lpDependencies: PCWSTR,
    lpServiceStartName: PCWSTR,
    lpPassword: PCWSTR,
) -> SC_HANDLE {
    if get_scm_handle(hSCManager).is_none() {
        return null_mut();
    }

    if lpServiceName.is_null() || lpBinaryPathName.is_null() {
        return null_mut();
    }

    if find_service(lpServiceName).is_some() {
        return null_mut();
    }

    let service_index = match alloc_service() {
        Some(idx) => idx,
        None => return null_mut(),
    };

    let service = &mut SERVICE_TABLE[service_index];
    copy_to_buffer(&mut service.name, lpServiceName);
    copy_to_buffer(&mut service.display_name, if lpDisplayName.is_null() { lpServiceName } else { lpDisplayName });
    copy_to_buffer(&mut service.binary_path, lpBinaryPathName);
    service.service_type = dwServiceType;
    service.start_type = dwStartType;
    service.error_control = dwErrorControl;
    service.current_state = SERVICE_STOPPED;
    service.controls_accepted = SERVICE_CONTROL_STOP;

    match alloc_scm_handle(dwDesiredAccess, Some(service_index)) {
        Some(handle) => handle,
        None => {
            service.in_use = false;
            null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn OpenServiceW(
    hSCManager: SC_HANDLE,
    lpServiceName: PCWSTR,
    dwDesiredAccess: DWORD,
) -> SC_HANDLE {
    if get_scm_handle(hSCManager).is_none() {
        return null_mut();
    }

    let service_index = match find_service(lpServiceName) {
        Some(idx) => idx,
        None => return null_mut(),
    };

    match alloc_scm_handle(dwDesiredAccess, Some(service_index)) {
        Some(handle) => handle,
        None => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn StartServiceW(
    hService: SC_HANDLE,
    dwNumServiceArgs: DWORD,
    lpServiceArgVectors: *mut PCWSTR,
) -> LONG {
    let handle_entry = match get_scm_handle(hService) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0, // Not a service handle
    };

    let service = &mut SERVICE_TABLE[service_index];
    service.current_state = SERVICE_START_PENDING;
    service.checkpoint = 0;
    service.wait_hint = 2000;

    service.current_state = SERVICE_RUNNING;
    service.controls_accepted = SERVICE_CONTROL_STOP | SERVICE_CONTROL_PAUSE | SERVICE_CONTROL_CONTINUE;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ControlService(
    hService: SC_HANDLE,
    dwControl: DWORD,
    lpServiceStatus: LPSERVICE_STATUS,
) -> LONG {
    let handle_entry = match get_scm_handle(hService) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    let service = &mut SERVICE_TABLE[service_index];

    match dwControl {
        SERVICE_CONTROL_STOP => {
            service.current_state = SERVICE_STOP_PENDING;
            service.checkpoint = 0;
            service.wait_hint = 2000;
            service.current_state = SERVICE_STOPPED;
        }
        SERVICE_CONTROL_PAUSE => {
            if service.current_state == SERVICE_RUNNING {
                service.current_state = SERVICE_PAUSE_PENDING;
                service.current_state = SERVICE_PAUSED;
            }
        }
        SERVICE_CONTROL_CONTINUE => {
            if service.current_state == SERVICE_PAUSED {
                service.current_state = SERVICE_CONTINUE_PENDING;
                service.current_state = SERVICE_RUNNING;
            }
        }
        SERVICE_CONTROL_INTERROGATE => {
        }
        _ => {}
    }

    if !lpServiceStatus.is_null() {
        (*lpServiceStatus).dwServiceType = service.service_type;
        (*lpServiceStatus).dwCurrentState = service.current_state;
        (*lpServiceStatus).dwControlsAccepted = service.controls_accepted;
        (*lpServiceStatus).dwWin32ExitCode = service.win32_exit_code;
        (*lpServiceStatus).dwServiceSpecificExitCode = service.service_exit_code;
        (*lpServiceStatus).dwCheckPoint = service.checkpoint;
        (*lpServiceStatus).dwWaitHint = service.wait_hint;
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn QueryServiceStatus(
    hService: SC_HANDLE,
    lpServiceStatus: LPSERVICE_STATUS,
) -> LONG {
    if lpServiceStatus.is_null() {
        return 0; // FALSE
    }

    let handle_entry = match get_scm_handle(hService) {
        Some(h) => h,
        None => return 0,
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    let service = &SERVICE_TABLE[service_index];
    (*lpServiceStatus).dwServiceType = service.service_type;
    (*lpServiceStatus).dwCurrentState = service.current_state;
    (*lpServiceStatus).dwControlsAccepted = service.controls_accepted;
    (*lpServiceStatus).dwWin32ExitCode = service.win32_exit_code;
    (*lpServiceStatus).dwServiceSpecificExitCode = service.service_exit_code;
    (*lpServiceStatus).dwCheckPoint = service.checkpoint;
    (*lpServiceStatus).dwWaitHint = service.wait_hint;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn DeleteService(hService: SC_HANDLE) -> LONG {
    let handle_entry = match get_scm_handle(hService) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    let service = &mut SERVICE_TABLE[service_index];
    if service.current_state != SERVICE_STOPPED {
        return 0; // Cannot delete running service
    }

    service.in_use = false;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ChangeServiceConfigW(
    hService: SC_HANDLE,
    dwServiceType: DWORD,
    dwStartType: DWORD,
    dwErrorControl: DWORD,
    lpBinaryPathName: PCWSTR,
    lpLoadOrderGroup: PCWSTR,
    lpdwTagId: *mut DWORD,
    lpDependencies: PCWSTR,
    lpServiceStartName: PCWSTR,
    lpPassword: PCWSTR,
    lpDisplayName: PCWSTR,
) -> LONG {
    let handle_entry = match get_scm_handle(hService) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    let service = &mut SERVICE_TABLE[service_index];

    if dwServiceType != 0xFFFFFFFF {
        service.service_type = dwServiceType;
    }
    if dwStartType != 0xFFFFFFFF {
        service.start_type = dwStartType;
    }
    if dwErrorControl != 0xFFFFFFFF {
        service.error_control = dwErrorControl;
    }
    if !lpBinaryPathName.is_null() {
        copy_to_buffer(&mut service.binary_path, lpBinaryPathName);
    }
    if !lpDisplayName.is_null() {
        copy_to_buffer(&mut service.display_name, lpDisplayName);
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn EnumServicesStatusW(
    hSCManager: SC_HANDLE,
    dwServiceType: DWORD,
    dwServiceState: DWORD,
    lpServices: PVOID,
    cbBufSize: DWORD,
    pcbBytesNeeded: *mut DWORD,
    lpServicesReturned: *mut DWORD,
    lpResumeHandle: *mut DWORD,
) -> LONG {
    if get_scm_handle(hSCManager).is_none() {
        return 0; // FALSE
    }

    let mut count = 0;
    for service in SERVICE_TABLE.iter() {
        if !service.in_use {
            continue;
        }

        if dwServiceType != 0 && (service.service_type & dwServiceType) == 0 {
            continue;
        }

        match dwServiceState {
            1 => if service.current_state != SERVICE_STOPPED { continue; },
            2 => if service.current_state == SERVICE_STOPPED { continue; },
            _ => {}
        }

        count += 1;
    }

    if !lpServicesReturned.is_null() {
        *lpServicesReturned = count;
    }

    if !pcbBytesNeeded.is_null() {
        *pcbBytesNeeded = count * 256; // Approximate size
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn QueryServiceConfigW(
    hService: SC_HANDLE,
    lpServiceConfig: PVOID,
    cbBufSize: DWORD,
    pcbBytesNeeded: *mut DWORD,
) -> LONG {
    let handle_entry = match get_scm_handle(hService) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    if !pcbBytesNeeded.is_null() {
        *pcbBytesNeeded = 512; // Approximate size
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn StartServiceCtrlDispatcherW(
    lpServiceStartTable: PVOID,
) -> LONG {
    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn RegisterServiceCtrlHandlerW(
    lpServiceName: PCWSTR,
    lpHandlerProc: PVOID,
) -> SC_HANDLE {
    0x3000 as SC_HANDLE
}

#[no_mangle]
pub unsafe extern "C" fn SetServiceStatus(
    hServiceStatus: SC_HANDLE,
    lpServiceStatus: LPSERVICE_STATUS,
) -> LONG {
    if lpServiceStatus.is_null() {
        return 0; // FALSE
    }

    1 // TRUE
}
