//! ntdll — PEB / TEB data structures
//
//! The Process Environment Block (PEB) and Thread Environment
//! Block (TEB) are user-mode data structures created by the
//! kernel at process / thread creation. The Windows 7 layout
//! is the reference; the structures here mirror the SDK
//! `peb.h` / `teb.h` definitions.
//
//! In this kernel the structures are never actually used by
//! user-mode code (no ring 3), so the implementation only
//! stores the layout and provides the access helpers
//! (`NtCurrentTeb`, `RtlGetCurrentPeb`, ...).
//
//! References: MSDN Library "Windows 7" — PEB and TEB.

use super::types::{HANDLE, NTSTATUS, PVOID};

/// `PEB` (Process Environment Block), 64-bit Windows 7 layout.
#[repr(C)]
#[derive(Default)]
pub struct Peb {
    pub inherited_address_space: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    pub _pad0: u8,
    pub mutant: PVOID,
    pub image_base_address: PVOID,
    pub ldr: PVOID,
    pub process_parameters: PVOID,
    pub sub_system_data: PVOID,
    pub process_heap: PVOID,
    pub fast_peb_lock: PVOID,
    pub _pad1: [PVOID; 2],
    pub read_only_shared_memory_base: PVOID,
    pub _pad2: [PVOID; 5],
    pub read_only_static_server_data: PVOID,
    pub _pad3: PVOID,
    pub nt_global_flag: u32,
    pub _pad4: u32,
    pub critical_section_timeout: i64,
    pub heap_segment_commit: u32,
    pub heap_segment_reserve: u32,
    pub heap_decommit_total_free_threshold: u32,
    pub heap_decommit_free_block_threshold: u32,
    pub number_of_heaps: u32,
    pub max_number_of_heaps: u32,
    pub process_heaps: PVOID,
    pub gdi_shared_handle_table: PVOID,
    pub process_starter_helper: PVOID,
    pub gdi_dc_attribute_list: PVOID,
    pub loader_lock: PVOID,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_csd_version: u16,
    pub os_platform_id: u32,
    pub image_subsystem: u32,
    pub image_subsystem_major_version: u32,
    pub image_subsystem_minor_version: u32,
    pub _pad5: [PVOID; 30],
    pub session_id: u32,
}

/// `NT_TIB` (Thread Information Block) — the first field of the
/// TEB on x64.
#[repr(C)]
#[derive(Default)]
pub struct NtTib {
    pub exception_list: PVOID,
    pub stack_base: PVOID,
    pub stack_limit: PVOID,
    pub sub_system_tib: PVOID,
    pub fiber_data: PVOID,
    pub arbitrary_user_pointer: PVOID,
    pub self_: PVOID,
}

/// `TEB` (Thread Environment Block).
#[repr(C)]
#[derive(Default)]
pub struct Teb {
    pub nt_tib: NtTib,
    pub environment_pointer: PVOID,
    pub client_id: [PVOID; 2],
    pub active_rpc_handle: PVOID,
    pub thread_local_storage_pointer: PVOID,
    pub peb: *mut Peb,
    pub last_error_value: u32,
    pub count_of_owned_critical_sections: u32,
    pub csr_client_thread: PVOID,
    pub win32_thread_info: PVOID,
    pub user32_reserved: [u32; 26],
    pub user_reserved: [u32; 5],
    pub wow64_reserved: PVOID,
    pub current_locale: u32,
    pub fp_software_status_register: u32,
    pub _pad0: [PVOID; 3],
    pub system_reserved1: [u32; 11],
    pub placeholder_compatibility_mode: u8,
    pub _pad1: [u8; 3],
    pub placeholder_compatibility_mode2: u8,
    pub _pad2: [u8; 3],
    pub _pad3: [u8; 4],
    pub nt_user_thunk_info_ptr: PVOID,
    pub _pad4: [PVOID; 9],
    pub nt_maximum_stack_depth: usize,
    pub nt_stack_committed: PVOID,
    pub nt_stack_reserve: PVOID,
    pub _pad5: [PVOID; 8],
}

/// `RtlGetCurrentPeb` — return the PEB pointer of the current
/// process. In a real kernel this reads the `gs` segment. The
/// bootstrap returns NULL.
pub unsafe extern "C" fn RtlGetCurrentPeb() -> *mut Peb {
    core::ptr::null_mut()
}

/// `RtlGetThreadErrorMode` / `RtlSetThreadErrorMode` — return 0
/// (default error mode).
pub unsafe extern "C" fn RtlGetThreadErrorMode() -> u32 { 0 }
pub unsafe extern "C" fn RtlSetThreadErrorMode(_mode: u32, _old_mode: *mut u32) -> i32 { 0 }

/// `PebGetVersion` — return the OS version. We report
/// `6.1.7601` (Windows 7 SP1 build 7601).
pub unsafe extern "C" fn PebGetVersion(major: *mut u32, minor: *mut u32, build: *mut u32) -> u32 {
    if !major.is_null() { *major = 6; }
    if !minor.is_null() { *minor = 1; }
    if !build.is_null() { *build = 7601; }
    0
}

/// `RtlExitUserThread` — exit the current thread. Maps to
/// `NtTerminateThread` with the supplied status.
pub unsafe extern "C" fn RtlExitUserThread(exit_status: u32) -> ! {
    super::thread::NtTerminateThread(-1isize as HANDLE, exit_status);
    loop { core::hint::spin_loop(); }
}
