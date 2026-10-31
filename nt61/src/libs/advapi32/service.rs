//! advapi32 — Service control Manager APIs
//
//! Implements Windows Service control Manager (SCM) functions:
//! - OpenSCManagerW — Connect to the SCM
//! - CreateServiceW — create a new service
//! - OpenServiceW — Open an existing service
//! - StartServiceW — Start a service
//! - ControlService — Send control codes to a service
//! - DeleteService — Delete a service
//! - QueryServiceStatus — Query service status
//! - ChangeServiceConfigW — Modify service configuration
//! - EnumServicesStatusW — Enumerate services

use super::types::*;
use crate::libs::ntdll::types::{DWORD, PCWSTR, PVOID};
use core::ptr::null_mut;

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

fn alloc_scm_handle(access: DWORD, service_index: Option<usize>) -> Option<ScHandle> {
    unsafe {
        for (i, entry) in (*core::ptr::addr_of_mut!(SCM_HANDLES))
            .iter_mut()
            .enumerate()
        {
            if !entry.in_use {
                entry.access = access;
                entry.service_index = service_index;
                entry.in_use = true;
                return Some((0x2000 + i * 4) as ScHandle);
            }
        }
    }
    None
}

fn free_scm_handle(handle: ScHandle) -> bool {
    let index = ((handle as usize) - 0x2000) / 4;
    unsafe {
        if index < MAX_SCM_HANDLES && SCM_HANDLES[index].in_use {
            SCM_HANDLES[index].in_use = false;
            return true;
        }
    }
    false
}

fn get_scm_handle(handle: ScHandle) -> Option<&'static ScmHandle> {
    let index = ((handle as usize) - 0x2000) / 4;
    unsafe {
        if index < MAX_SCM_HANDLES && SCM_HANDLES[index].in_use {
            return Some(&SCM_HANDLES[index]);
        }
    }
    None
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn find_service(name: PCWSTR) -> Option<usize> {
    if name.is_null() {
        return None;
    }

    for (i, service) in (*core::ptr::addr_of!(SERVICE_TABLE)).iter().enumerate() {
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

        if match_found
            && (j >= service.name.len() || service.name[j] == 0)
            && (p.is_null() || *p == 0)
        {
            return Some(i);
        }
    }

    None
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn alloc_service() -> Option<usize> {
    for (i, service) in (*core::ptr::addr_of_mut!(SERVICE_TABLE))
        .iter_mut()
        .enumerate()
    {
        if !service.in_use {
            service.in_use = true;
            return Some(i);
        }
    }
    None
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn OpenSCManagerW(
    _lp_machine_name: PCWSTR,
    _lp_database_name: PCWSTR,
    dw_desired_access: DWORD,
) -> ScHandle {
    match alloc_scm_handle(dw_desired_access, None) {
        Some(handle) => handle,
        None => null_mut(),
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CloseServiceHandle(h_scobject: ScHandle) -> LONG {
    if free_scm_handle(h_scobject) {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CreateServiceW(
    h_scmanager: ScHandle,
    lp_service_name: PCWSTR,
    lp_display_name: PCWSTR,
    dw_desired_access: DWORD,
    dw_service_type: DWORD,
    dw_start_type: DWORD,
    dw_error_control: DWORD,
    lp_binary_path_name: PCWSTR,
    _lp_load_order_group: PCWSTR,
    _lpdw_tag_id: *mut DWORD,
    _lp_dependencies: PCWSTR,
    _lp_service_start_name: PCWSTR,
    _lp_password: PCWSTR,
) -> ScHandle {
    if get_scm_handle(h_scmanager).is_none() {
        return null_mut();
    }

    if lp_service_name.is_null() || lp_binary_path_name.is_null() {
        return null_mut();
    }

    if find_service(lp_service_name).is_some() {
        return null_mut();
    }

    let service_index = match alloc_service() {
        Some(idx) => idx,
        None => return null_mut(),
    };

    let service = &mut SERVICE_TABLE[service_index];
    copy_to_buffer(&mut service.name, lp_service_name);
    copy_to_buffer(
        &mut service.display_name,
        if lp_display_name.is_null() {
            lp_service_name
        } else {
            lp_display_name
        },
    );
    copy_to_buffer(&mut service.binary_path, lp_binary_path_name);
    service.service_type = dw_service_type;
    service.start_type = dw_start_type;
    service.error_control = dw_error_control;
    service.current_state = SERVICE_STOPPED;
    service.controls_accepted = SERVICE_CONTROL_STOP;

    match alloc_scm_handle(dw_desired_access, Some(service_index)) {
        Some(handle) => handle,
        None => {
            service.in_use = false;
            null_mut()
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn OpenServiceW(
    h_scmanager: ScHandle,
    lp_service_name: PCWSTR,
    dw_desired_access: DWORD,
) -> ScHandle {
    if get_scm_handle(h_scmanager).is_none() {
        return null_mut();
    }

    let service_index = match find_service(lp_service_name) {
        Some(idx) => idx,
        None => return null_mut(),
    };

    match alloc_scm_handle(dw_desired_access, Some(service_index)) {
        Some(handle) => handle,
        None => null_mut(),
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn StartServiceW(
    h_service: ScHandle,
    _dw_num_service_args: DWORD,
    _lp_service_arg_vectors: *mut PCWSTR,
) -> LONG {
    let handle_entry = match get_scm_handle(h_service) {
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
    service.controls_accepted =
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_PAUSE | SERVICE_CONTROL_CONTINUE;

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn ControlService(
    h_service: ScHandle,
    dw_control: DWORD,
    lp_service_status: LpserviceStatus,
) -> LONG {
    let handle_entry = match get_scm_handle(h_service) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    let service = &mut SERVICE_TABLE[service_index];

    match dw_control {
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
        SERVICE_CONTROL_INTERROGATE => {}
        _ => {}
    }

    if !lp_service_status.is_null() {
        (*lp_service_status).dw_service_type = service.service_type;
        (*lp_service_status).dw_current_state = service.current_state;
        (*lp_service_status).dw_controls_accepted = service.controls_accepted;
        (*lp_service_status).dw_win32_exit_code = service.win32_exit_code;
        (*lp_service_status).dw_service_specific_exit_code = service.service_exit_code;
        (*lp_service_status).dw_check_point = service.checkpoint;
        (*lp_service_status).dw_wait_hint = service.wait_hint;
    }

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn QueryServiceStatus(
    h_service: ScHandle,
    lp_service_status: LpserviceStatus,
) -> LONG {
    if lp_service_status.is_null() {
        return 0; // FALSE
    }

    let handle_entry = match get_scm_handle(h_service) {
        Some(h) => h,
        None => return 0,
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    let service = &SERVICE_TABLE[service_index];
    (*lp_service_status).dw_service_type = service.service_type;
    (*lp_service_status).dw_current_state = service.current_state;
    (*lp_service_status).dw_controls_accepted = service.controls_accepted;
    (*lp_service_status).dw_win32_exit_code = service.win32_exit_code;
    (*lp_service_status).dw_service_specific_exit_code = service.service_exit_code;
    (*lp_service_status).dw_check_point = service.checkpoint;
    (*lp_service_status).dw_wait_hint = service.wait_hint;

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn DeleteService(h_service: ScHandle) -> LONG {
    let handle_entry = match get_scm_handle(h_service) {
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn ChangeServiceConfigW(
    h_service: ScHandle,
    dw_service_type: DWORD,
    dw_start_type: DWORD,
    dw_error_control: DWORD,
    lp_binary_path_name: PCWSTR,
    _lp_load_order_group: PCWSTR,
    _lpdw_tag_id: *mut DWORD,
    _lp_dependencies: PCWSTR,
    _lp_service_start_name: PCWSTR,
    _lp_password: PCWSTR,
    lp_display_name: PCWSTR,
) -> LONG {
    let handle_entry = match get_scm_handle(h_service) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    let service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    let service = &mut SERVICE_TABLE[service_index];

    if dw_service_type != 0xFFFFFFFF {
        service.service_type = dw_service_type;
    }
    if dw_start_type != 0xFFFFFFFF {
        service.start_type = dw_start_type;
    }
    if dw_error_control != 0xFFFFFFFF {
        service.error_control = dw_error_control;
    }
    if !lp_binary_path_name.is_null() {
        copy_to_buffer(&mut service.binary_path, lp_binary_path_name);
    }
    if !lp_display_name.is_null() {
        copy_to_buffer(&mut service.display_name, lp_display_name);
    }

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn EnumServicesStatusW(
    h_scmanager: ScHandle,
    dw_service_type: DWORD,
    dw_service_state: DWORD,
    _lp_services: PVOID,
    _cb_buf_size: DWORD,
    pcb_bytes_needed: *mut DWORD,
    lp_services_returned: *mut DWORD,
    _lp_resume_handle: *mut DWORD,
) -> LONG {
    if get_scm_handle(h_scmanager).is_none() {
        return 0; // FALSE
    }

    let mut count = 0;
    for service in (*core::ptr::addr_of!(SERVICE_TABLE)).iter() {
        if !service.in_use {
            continue;
        }

        if dw_service_type != 0 && (service.service_type & dw_service_type) == 0 {
            continue;
        }

        match dw_service_state {
            1 => {
                if service.current_state != SERVICE_STOPPED {
                    continue;
                }
            }
            2 if service.current_state == SERVICE_STOPPED => {
                continue;
            }
            _ => {}
        }

        count += 1;
    }

    if !lp_services_returned.is_null() {
        *lp_services_returned = count;
    }

    if !pcb_bytes_needed.is_null() {
        *pcb_bytes_needed = count * 256; // Approximate size
    }

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn QueryServiceConfigW(
    h_service: ScHandle,
    _lp_service_config: PVOID,
    _cb_buf_size: DWORD,
    pcb_bytes_needed: *mut DWORD,
) -> LONG {
    let handle_entry = match get_scm_handle(h_service) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    let _service_index = match handle_entry.service_index {
        Some(idx) => idx,
        None => return 0,
    };

    if !pcb_bytes_needed.is_null() {
        *pcb_bytes_needed = 512; // Approximate size
    }

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn StartServiceCtrlDispatcherW(_lp_service_start_table: PVOID) -> LONG {
    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn RegisterServiceCtrlHandlerW(
    _lp_service_name: PCWSTR,
    _lp_handler_proc: PVOID,
) -> ScHandle {
    0x3000 as ScHandle
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn SetServiceStatus(
    _h_service_status: ScHandle,
    lp_service_status: LpserviceStatus,
) -> LONG {
    if lp_service_status.is_null() {
        return 0; // FALSE
    }

    1 // TRUE
}
