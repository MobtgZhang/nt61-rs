//! System Service Descriptor Table (SSDT) Implementation
//
//! This module implements the Windows NT System Service Dispatch Table,
//! which is the core mechanism for routing system calls from user mode
//! to kernel handlers.
//
//! ## Background
//
//! In Windows NT, user-mode code (via ntdll.dll) invokes system services
//! using the `syscall` instruction with a service number in EAX. The CPU
//! transfers control to the kernel's SYSCALL entry point, which then
//! dispatches to the appropriate handler using the SSDT.
//
//! The SSDT is an array of `KSERVICE_TABLE_DESCRIPTOR` structures:
//! - `KiServiceTable`: Main system service table (Win32k, GDI, User)
//! - `KeServiceDescriptorTable`: Base table for native services
//! - `KeServiceDescriptorTableShadow`: Includes win32k services
//
//! ## Service Number Encoding
//
//! System service numbers are 32-bit values encoded as:
//!   bits [31:16]: parameter count (number of bytes of arguments)
//!   bits [15:12]: service table index (0 = win32k, 1 = native)
//!   bits [11:0]: service offset in the table
//
//! On x64, the parameter count is encoded in bits 16-31, not 0-15.
//
//! ## Windows 7 x64 SSDT
//
//! On Windows 7 x64, the SSDT contains approximately 400+ native
//! system services. The table is indexed by the low 12 bits of the
//! service number.
//
//! Reference: ReactOS/WRK, Geoff Chappell, Vergilius Project

/// Maximum number of services in the SSDT
pub const SSDT_MAX_SERVICES: usize = 512;

/// Maximum argument size (in bytes) for a single service call. The argument
/// size decoded by `get_argument_size()` is a byte count taken from a single
/// byte of the service number, so 255 is both the architecture limit and the
/// actual value checked by the syscall entry.
pub const SSDT_MAX_ARGUMENT_SIZE: usize = u8::MAX as usize;

/// Service table descriptor - describes a service table
#[repr(C)]
pub struct KeServiceDescriptor {
    /// Base address of the service table (array of function pointers)
    pub service_table: *const (),
    /// Counter table (optional, for performance)
    pub counter_table: *const (),
    /// Number of services in the table
    pub service_count: u32,
    /// Argument count table base
    pub argument_table: *const u8,
}

/// Service table descriptor entry (what's pointed to by KeServiceDescriptorTable)
#[repr(C)]
pub struct KeServiceDescriptorTable {
    /// Base service table
    pub base: KeServiceDescriptor,
    /// Shadow service table (includes win32k services)
    pub shadow: KeServiceDescriptor,
    /// Reserved
    pub reserved: [u64; 2],
}

impl Default for KeServiceDescriptorTable {
    fn default() -> Self {
        Self {
            base: KeServiceDescriptor {
                service_table: core::ptr::null(),
                counter_table: core::ptr::null(),
                service_count: 0,
                argument_table: core::ptr::null(),
            },
            shadow: KeServiceDescriptor {
                service_table: core::ptr::null(),
                counter_table: core::ptr::null(),
                service_count: 0,
                argument_table: core::ptr::null(),
            },
            reserved: [0; 2],
        }
    }
}

/// Global KeServiceDescriptorTable (Windows-compatible)
/// This is the official NT service descriptor table that can be exported
/// for debugging and compatibility purposes.
static mut KE_SERVICE_DESCRIPTOR_TABLE: KeServiceDescriptorTable = KeServiceDescriptorTable {
    base: KeServiceDescriptor {
        service_table: core::ptr::null(),
        counter_table: core::ptr::null(),
        service_count: 0,
        argument_table: core::ptr::null(),
    },
    shadow: KeServiceDescriptor {
        service_table: core::ptr::null(),
        counter_table: core::ptr::null(),
        service_count: 0,
        argument_table: core::ptr::null(),
    },
    reserved: [0; 2],
};

/// Get a reference to the global KeServiceDescriptorTable
///
/// This table is populated during init() and contains pointers to
/// both the native and shadow (win32k) service tables.
pub fn get_service_descriptor_table() -> &'static KeServiceDescriptorTable {
    unsafe { &*core::ptr::addr_of!(KE_SERVICE_DESCRIPTOR_TABLE) }
}

/// Service argument count encoding
/// On x64: bits 16-31 of the service number encode the argument size
#[inline(always)]
pub fn get_argument_size(service_number: u32) -> u32 {
    (service_number >> 16) & 0xFF
}

/// Argument byte count for a Shadow SSDT (win32k) service.
///
/// Win32k service numbers (0x1000..0x1FFF) carry no argument size in
/// bits 16-31, so the per-service table populated by
/// `register_shadow_service` is the only source of truth.
pub fn get_shadow_argument_size(service_number: u32) -> u8 {
    // Delegate to the authoritative shadow SSDT (shadow_ssdt.rs),
    // which has the full 0x1000-entry table populated by
    // init_shadow_services(). The old 512-entry local table was a
    // disconnected duplicate (P0-2).
    let index = service_number & 0xFFF;
    crate::ke::shadow_ssdt::get_argument_size(index)
}

/// Get the actual service index (offset within the table)
#[inline(always)]
pub fn get_service_index(service_number: u32) -> u32 {
    service_number & 0xFFF
}

/// Get the service table index (0 = native, 1 = win32k)
#[inline(always)]
pub fn get_table_index(service_number: u32) -> u32 {
    (service_number >> 12) & 0xF
}

// =====================================================================
// Native service dispatch
// =====================================================================
//
// There is intentionally NO native KiServiceTable in this module. The
// previous local `KI_SERVICE_TABLE` / `KI_SERVICE_TABLE_ENCODED` /
// `KI_ARGUMENT_TABLE` arrays were never populated by any caller and
// the native dispatch path never routed through them (ke_exc P0-3).
// Native syscalls are dispatched by the architecture trap layer
// (`arch/x86_64/syscall.rs`) via `ssdt_common` and its per-arch
// fallback match; the win32k (shadow) services live in
// `ke::shadow_ssdt` and are exposed through the descriptor table's
// `shadow` member below.

// =====================================================================
// SSDT Dispatch Functions
// =====================================================================

/// Initialize the SSDT with service handlers
/// This function should be called during kernel initialization
pub fn init() {
    crate::hal::serial::write_string("[ke.ssdt] enter\r\n");
    // The native `base` member is left empty on purpose: this Phase-0
    // kernel has no NT-compatible native function-pointer table (native
    // syscalls dispatch through `ssdt_common` plus the architecture
    // trap layer). Exporting a fake populated table was worse than
    // exporting an honestly empty one (ke_exc P0-3). The shadow member
    // points at the real win32k tables.
    unsafe {
        KE_SERVICE_DESCRIPTOR_TABLE.shadow = KeServiceDescriptor {
            service_table: crate::ke::shadow_ssdt::service_table_ptr(),
            counter_table: core::ptr::null(),
            service_count: crate::ke::shadow_ssdt::SHADOW_MAX_SERVICES as u32,
            argument_table: crate::ke::shadow_ssdt::argument_table_ptr(),
        };
    }
}

// =====================================================================
// Shadow SSDT (Win32k)
// =====================================================================
//
// The Shadow SSDT contains services provided by win32k.sys for
// graphics and window management. When a win32k service is called
// from user mode, the service number is in the range 0x1000-0x1FFF.

/// Get a shadow (win32k) service handler
pub fn get_shadow_service_handler(service_number: u32) -> Option<*const ()> {
    // Delegate to the authoritative shadow SSDT table (P0-2).
    let index = service_number & 0xFFF;
    crate::ke::shadow_ssdt::get_shadow_service(index)
}

/// Register a shadow (win32k) service handler
///
/// # Safety
/// This function modifies a static mutable array. It should only be
/// called during initialization.
pub unsafe fn register_shadow_service(service_number: u32, handler: *const (), arg_size: u8) {
    // Delegate to the authoritative shadow SSDT table (P0-2).
    let index = service_number & 0xFFF;
    crate::ke::shadow_ssdt::register_shadow_service(index, handler, arg_size);

    // // kprintln!("[SSDT] Registered shadow service #{:04x} at index {} (args={})",
    // //              service_number, index, arg_size);
}

// =====================================================================
// Smoke Test
// =====================================================================

/// Run SSDT smoke test
pub fn smoke_test() -> bool {
    // The descriptor table's shadow member must point at the real
    // win32k tables (ke_exc P0-2/P0-3); the native member is honestly
    // empty because native dispatch lives in ssdt_common + the arch
    // trap layer.
    let table = get_service_descriptor_table();

    !table.shadow.service_table.is_null() && !table.shadow.argument_table.is_null()
}
