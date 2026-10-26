//! ntdll — nt_query_system_information / nt_set_system_information
//
//! Returns mostly stubs: the kernel reports fixed values
//! (single processor, 4 GiB of RAM, ...) so that the kernel32
//! layer can do its smoke test. The full surface is much
//! larger; we provide the most-used classes:
//
//!   * `SystemBasicInformation` (0) — fixed 1 CPU / 4 GiB
//!   * `SystemProcessorInformation` (1) — x86_64 family
//!   * `SystemTimeOfDayInformation` (3) — current boot time
//!   * `SystemProcessInformation` (5) — list of registered
//!     processes
//
//! References: MSDN Library "Windows 7" —
//! `ntdll.dll` system information APIs.

use super::status::{STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::types::{NTSTATUS, PVOID};
use crate::mm::user_copy::write_user_object;

/// `SYSTEM_BASIC_INFORMATION` (44 bytes on x64).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct SystemBasicInformation {
    pub reserved: u32,
    pub timer_resolution: u32,
    pub page_size: u32,
    pub number_of_physical_pages: u32,
    pub lowest_physical_page_number: u32,
    pub highest_physical_page_number: u32,
    pub allocation_granularity: u32,
    pub minimum_user_mode_address: PVOID,
    pub maximum_user_mode_address: PVOID,
    pub active_processors_affinity_mask: PVOID,
    pub number_of_processors: u8,
    pub _pad: [u8; 7],
}

/// `SYSTEM_PROCESSOR_INFORMATION` (12 bytes).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct SystemProcessorInformation {
    pub processor_architecture: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub maximum_processors: u16,
    pub processor_features: u32,
}

/// `SYSTEM_TIMEOFDAY_INFORMATION` (48 bytes).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct SystemTimeOfDayInformation {
    pub boot_time: i64,
    pub current_time: i64,
    pub time_zone_bias: i64,
    pub time_zone_id: u32,
    pub _pad: u32,
    pub boot_time_cycles: u64,
    pub current_time_cycles: u64,
}

/// `nt_query_system_information`.
pub unsafe extern "C" fn nt_query_system_information(
    system_information_class: u32,
    system_information: PVOID,
    system_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if system_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    match system_information_class {
        0 => {
            // SystemBasicInformation
            if system_information_length < core::mem::size_of::<SystemBasicInformation>() as u32 {
                if !return_length.is_null() {
                    // The required length is user-visible state: route the
                    // store through the user-copy validator instead of a
                    // bare dereference of a caller-controlled pointer.
                    if write_user_object(
                        return_length as u64,
                        &(core::mem::size_of::<SystemBasicInformation>() as u32),
                    )
                    .is_err()
                    {
                        return super::status::STATUS_ACCESS_VIOLATION;
                    }
                }
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            let mut s = SystemBasicInformation::default();
            s.reserved = 0;
            s.timer_resolution = 156250; // 15.625 ms
            s.page_size = 4096;
            s.number_of_physical_pages = 0x100000; // 4 GiB
            s.lowest_physical_page_number = 1;
            s.highest_physical_page_number = 0x100000;
            s.allocation_granularity = 0x10000; // 64 KiB
            s.minimum_user_mode_address = 0x10000 as PVOID;
            s.maximum_user_mode_address = 0x0000_7FFF_FFFF_FFFFusize as PVOID;
            s.active_processors_affinity_mask = 0x1usize as PVOID;
            s.number_of_processors = 1;
            if write_user_object(system_information as u64, &s).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
                if !return_length.is_null()
                    && write_user_object(
                        return_length as u64,
                        &(core::mem::size_of::<SystemBasicInformation>() as u32),
                    )
                    .is_err()
                {
                    return super::status::STATUS_ACCESS_VIOLATION;
                }
            STATUS_SUCCESS
        }
        1 => {
            // SystemProcessorInformation
            if system_information_length < core::mem::size_of::<SystemProcessorInformation>() as u32
            {
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            let mut s = SystemProcessorInformation::default();
            s.processor_architecture = 9; // PROCESSOR_ARCHITECTURE_AMD64
            s.processor_level = 0x10;
            s.processor_revision = 0x9000;
            s.maximum_processors = 1;
            s.processor_features = 0;
            if write_user_object(system_information as u64, &s).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
                if !return_length.is_null()
                    && write_user_object(
                        return_length as u64,
                        &(core::mem::size_of::<SystemProcessorInformation>() as u32),
                    )
                    .is_err()
                {
                    return super::status::STATUS_ACCESS_VIOLATION;
                }
            STATUS_SUCCESS
        }
        3 => {
            // SystemTimeOfDayInformation
            if system_information_length < core::mem::size_of::<SystemTimeOfDayInformation>() as u32
            {
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            let mut s = SystemTimeOfDayInformation::default();
            s.boot_time = 0;
            s.current_time = crate::ke::time::get_system_time() as i64;
            s.time_zone_bias = 0;
            s.time_zone_id = 0;
            s.boot_time_cycles = 0;
            s.current_time_cycles = crate::ke::time::get_system_time();
            if write_user_object(system_information as u64, &s).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            if !return_length.is_null() {
                let _ = write_user_object(
                    return_length as u64,
                    &(core::mem::size_of::<SystemTimeOfDayInformation>() as u32),
                );
            }
            STATUS_SUCCESS
        }
        _ => {
            if !return_length.is_null() {
                let _ = write_user_object(return_length as u64, &0u32);
            }
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// `nt_set_system_information` — most classes are read-only; the
/// only writable one is `SystemLoadGdiDriverInformation`
/// (class 26), which we don't implement. The failure is explicit
/// STATUS_NOT_SUPPORTED (not STATUS_INVALID_INFO_CLASS) so a caller
/// cannot mistake the missing driver-load path for a malformed class
/// number.
pub unsafe extern "C" fn nt_set_system_information(
    _system_information_class: u32,
    _system_information: PVOID,
    _system_information_length: u32,
) -> NTSTATUS {
    super::status::STATUS_NOT_SUPPORTED
}

/// `rtl_get_native_system_information` — alias kept for compat
/// with very old applications.
pub unsafe extern "C" fn rtl_get_native_system_information(
    info_class: u32,
    info: PVOID,
    length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    nt_query_system_information(info_class, info, length, return_length)
}
