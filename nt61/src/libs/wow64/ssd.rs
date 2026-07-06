//
//! In Windows, the WoW64 layer intercepts 32-bit system calls made via
//! `sysenter`/`int 2e` and routes them through `wow64.dll`. The SSD
//! (Service Selector Table) maps 32-bit service numbers to 64-bit handlers.
//
//! This module implements:
//!   * SSD table management (KiSystemServiceStart, KiSystemServiceSelect)
//!   * 32-bit service number to handler mapping
//!   * Argument extraction from 32-bit stack
//
//! References:
//!   * geoffchappell.com — wow64 system service dispatching
//!   * ReactOS `win32ss/gdi/gdi32/objects/thunk.c`

#![allow(dead_code)]

use crate::libs::wow64::types::*;

// 32-bit NTSTATUS (Win32 unsigned representation). The ntdll status
// module exposes the canonical signed `NTSTATUS` (i32); in the WoW64
// surface we re-export the same numeric value as `u32` so it can be
// returned from `extern "C"` thunks whose ABI is unsigned 32-bit
// (`ULONG32` / `NTSTATUS32`).
const STATUS_SUCCESS_32: ULONG32           = 0x00000000;
const STATUS_NOT_IMPLEMENTED_32: ULONG32   = 0xC0000002;
const STATUS_INVALID_PARAMETER_32: ULONG32 = 0xC000000D;
const STATUS_NO_MEMORY_32: ULONG32         = 0xC0000017;
const STATUS_INVALID_HANDLE_32: ULONG32    = 0xC0000008;
const STATUS_UNSUCCESSFUL_32: ULONG32      = 0xC0000001;
const STATUS_ACCESS_DENIED_32: ULONG32     = 0xC0000022;

// =============================================================================
// Service Number Constants
// =============================================================================

/// System service numbers used by 32-bit ntdll.dll.
/// These are the Wow64 service table indices.
pub mod service_numbers {
    use super::ULONG32;

    // Memory Management Services
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: ULONG32 = 0x0011;
    pub const NT_FREE_VIRTUAL_MEMORY: ULONG32 = 0x0012;
    pub const NT_QUERY_VIRTUAL_MEMORY: ULONG32 = 0x0023;
    pub const NT_PROTECT_VIRTUAL_MEMORY: ULONG32 = 0x0047;
    pub const NT_READ_PROCESS_MEMORY: ULONG32 = 0x0050;
    pub const NT_WRITE_PROCESS_MEMORY: ULONG32 = 0x0051;
    pub const NT_QUERY_SECURITY_DOMAIN: ULONG32 = 0x0053;

    // Process Services
    pub const NT_CREATE_PROCESS: ULONG32 = 0x0030;
    pub const NT_OPEN_PROCESS: ULONG32 = 0x0024;
    pub const NT_TERMINATE_PROCESS: ULONG32 = 0x0029;
    pub const NT_QUERY_INFORMATION_PROCESS: ULONG32 = 0x0019;
    pub const NT_SET_INFORMATION_PROCESS: ULONG32 = 0x0015;
    pub const NT_QUERY_DEFAULT_LOCALE: ULONG32 = 0x1005;

    // Thread Services
    pub const NT_CREATE_THREAD: ULONG32 = 0x0031;
    pub const NT_OPEN_THREAD: ULONG32 = 0x003F;
    pub const NT_TERMINATE_THREAD: ULONG32 = 0x002D;
    pub const NT_GET_CONTEXT_THREAD: ULONG32 = 0x0013;
    pub const NT_SET_CONTEXT_THREAD: ULONG32 = 0x0014;
    pub const NT_QUERY_INFORMATION_THREAD: ULONG32 = 0x0026;
    pub const NT_SET_INFORMATION_THREAD: ULONG32 = 0x0010;
    pub const NT_SUSPEND_THREAD: ULONG32 = 0x0041;
    pub const NT_RESUME_THREAD: ULONG32 = 0x0042;
    pub const NT_QUEUE_APC_THREAD: ULONG32 = 0x001C;

    // Object Services
    pub const NT_OPEN_PROCESS_TOKEN: ULONG32 = 0x003A;
    pub const NT_OPEN_THREAD_TOKEN: ULONG32 = 0x003B;
    pub const NT_DUPLICATE_OBJECT: ULONG32 = 0x002A;
    pub const NT_CLOSE: ULONG32 = 0x0030;
    pub const NT_QUERY_OBJECT: ULONG32 = 0x0018;

    // Section/Memory Object Services
    pub const NT_CREATE_SECTION: ULONG32 = 0x0038;
    pub const NT_MAP_VIEW_OF_SECTION: ULONG32 = 0x002E;
    pub const NT_UNMAP_VIEW_OF_SECTION: ULONG32 = 0x002F;
    pub const NT_SHARE_OBJECT: ULONG32 = 0x003D;

    // Synchronization
    pub const NT_WAIT_FOR_SINGLE_OBJECT: ULONG32 = 0x0024;
    pub const NT_SET_EVENT: ULONG32 = 0x0025;
    pub const NT_CLEAR_EVENT: ULONG32 = 0x0026;
    pub const NT_CREATE_MUTANT: ULONG32 = 0x0027;
    pub const NT_RELEASE_MUTANT: ULONG32 = 0x0028;

    // Time Services
    pub const NT_QUERY_SYSTEM_TIME: ULONG32 = 0x0037;
    pub const NT_SET_SYSTEM_TIME: ULONG32 = 0x0038;
    pub const NT_QUERY_PERFORMANCE_COUNTER: ULONG32 = 0x0040;

    // Exception/APC Services
    pub const NT_RAISE_EXCEPTION: ULONG32 = 0x004D;
    pub const NT_DISPATCH_EXCEPTION: ULONG32 = 0x004E;
    pub const NT_ADD_VECTORED_EXCEPTION_HANDLER: ULONG32 = 0x004B;

    // Debug Services
    pub const NT_DEBUG_ACTIVE_PROCESS: ULONG32 = 0x0038;
    pub const NT_DEBUG_PROCESS: ULONG32 = 0x0039;
    pub const NT_REMOVE_PROCESS_DEBUG: ULONG32 = 0x003A;

    // Info Services
    pub const NT_QUERY_INFORMATION_FILE: ULONG32 = 0x0020;
    pub const NT_SET_INFORMATION_FILE: ULONG32 = 0x0021;
    pub const NT_FLUSH_BUFFERS_FILE: ULONG32 = 0x0022;

    // ALPC Services
    pub const NT_CREATE_PORT: ULONG32 = 0x005A;
    pub const NT_CONNECT_PORT: ULONG32 = 0x005B;

    // Registry Services
    pub const NT_OPEN_KEY: ULONG32 = 0x0035;
    pub const NT_QUERY_KEY: ULONG32 = 0x0036;
    pub const NT_ENUMERATE_KEY: ULONG32 = 0x0037;
    pub const NT_SET_VALUE_KEY: ULONG32 = 0x0038;
    pub const NT_QUERY_VALUE_KEY: ULONG32 = 0x0039;
    pub const NT_DELETE_KEY: ULONG32 = 0x003A;

    // Maximum service number in the base table
    pub const MAX_BASE_SERVICE: ULONG32 = 0x0FFF;
}

// =============================================================================
// Service Table Descriptor
// =============================================================================

/// Descriptor for a 32-bit system service table.
/// This describes where the service table lives in 32-bit address space.
#[repr(C)]
#[derive(Default)]
pub struct Wow64ServiceDescriptor {
    /// Pointer to 32-bit service table (array of service addresses).
    pub service_table: ULONG32,
    /// Pointer to service counter table (optional).
    pub counter_table: ULONG32,
    /// Number of services in this table.
    pub service_limit: ULONG32,
    /// Pointer to argument table (byte count for each service).
    pub arguments_table: ULONG32,
}

impl Wow64ServiceDescriptor {
    /// Create a new service descriptor.
    pub fn new(
        service_table: ULONG32,
        service_limit: ULONG32,
        arguments_table: ULONG32,
    ) -> Self {
        Self {
            service_table,
            counter_table: 0,
            service_limit,
            arguments_table,
        }
    }

    /// Check if a service number is within range.
    pub fn is_valid_service(&self, number: ULONG32) -> bool {
        number < self.service_limit
    }
}

/// KeServiceDescriptorTable - The ntdll 32-bit service table.
/// Located at a fixed address in 32-bit address space.
pub const WIN32K_SYSCALL_SERVICE_TABLE: usize = 0x0001;

/// Shadow KeServiceDescriptorTable for win32k.sys services.
/// In 64-bit Windows, win32k.sys has its own service table.
pub const WIN32K_SERVICE_TABLE_INDEX: usize = 1;

// Service call signature - takes 32-bit args pointer, returns NTSTATUS32
type ServiceHandler = unsafe extern "C" fn(args: *const u32) -> ULONG32;

// =============================================================================
// Service Dispatch Entry
// =============================================================================

/// A single service dispatch entry in the service table.
#[derive(Clone, Copy)]
pub struct ServiceEntry {
    /// Service routine handler (raw function pointer).
    handler: Option<ServiceHandler>,
    /// Argument size in bytes.
    pub arg_size: u8,
}

impl ServiceEntry {
    /// Create a new service entry.
    pub const fn new(handler: Option<ServiceHandler>, arg_size: u8) -> Self {
        Self { handler, arg_size }
    }

    /// Create an empty service entry.
    pub const fn empty() -> Self {
        Self { handler: None, arg_size: 0 }
    }

    /// Get argument size as u32.
    pub fn arg_size_u32(&self) -> ULONG32 {
        self.arg_size as ULONG32
    }

    /// Get handler for dispatch.
    pub fn get_handler(&self) -> Option<ServiceHandler> {
        self.handler
    }
}

// =============================================================================
// Service Table Implementation
// =============================================================================

/// Number of entries in the base service table.
pub const BASE_SERVICE_TABLE_SIZE: usize = 2048;

/// The base (ntdll) service table.
/// This would be populated at init time from the actual ntdll.dll export table.
static mut BASE_SERVICE_TABLE: [ServiceEntry; BASE_SERVICE_TABLE_SIZE] =
    [ServiceEntry::empty(); BASE_SERVICE_TABLE_SIZE];

/// Shadow service table for win32k.sys calls.
/// This is indexed by (table_index - 1).
static mut SHADOW_SERVICE_TABLE: [ServiceEntry; BASE_SERVICE_TABLE_SIZE] =
    [ServiceEntry::empty(); BASE_SERVICE_TABLE_SIZE];

// =============================================================================
// Service Number Decoding
// =============================================================================

/// Extract the service table index from a 32-bit service number.
/// Format: [table_index:4][service_number:12]
#[inline]
pub fn get_table_index(service_number: ULONG32) -> usize {
    ((service_number >> 12) & 0xF) as usize
}

/// Extract the service index within the table.
#[inline]
pub fn get_service_index(service_number: ULONG32) -> ULONG32 {
    service_number & 0x0FFF
}

/// Check if this is a shadow (win32k) service.
#[inline]
pub fn is_shadow_service(service_number: ULONG32) -> bool {
    get_table_index(service_number) == WIN32K_SERVICE_TABLE_INDEX
}

// =============================================================================
// Argument Extraction
// =============================================================================

/// Get a 32-bit argument from the stack at the given index.
/// Arguments are passed on the 32-bit stack in reverse order (cdecl-like).
///
/// # Arguments
/// * `args` - Pointer to first argument on stack
/// * `index` - Argument index (0-based)
/// * `size` - Size of argument (4 or 8 bytes)
///
/// # Safety
/// The caller must ensure that the stack pointer and index are valid.
#[inline]
pub unsafe fn get_argument_32(
    args: *const u32,
    index: u32,
    size: u32,
) -> u64 {
    match size {
        4 => *args.add(index as usize) as u64,
        8 => {
            // 64-bit argument: low 32 bits at index, high 32 bits at index+1
            let low = *args.add(index as usize) as u64;
            let high = *args.add(index as usize + 1) as u64;
            low | (high << 32)
        }
        _ => 0,
    }
}

/// Get argument size from the service table entry.
pub fn get_argument_size(service_number: ULONG32) -> u8 {
    let table_idx = get_table_index(service_number);
    let svc_idx = get_service_index(service_number) as usize;

    match table_idx {
        0 if svc_idx < BASE_SERVICE_TABLE_SIZE => {
            // Safety: Reading from static mutable table during read-only operation
            unsafe { BASE_SERVICE_TABLE[svc_idx].arg_size }
        }
        1 if svc_idx < SHADOW_SERVICE_TABLE_SIZE => {
            // Safety: Reading from static mutable table during read-only operation
            unsafe { SHADOW_SERVICE_TABLE[svc_idx].arg_size }
        }
        _ => 0,
    }
}

const SHADOW_SERVICE_TABLE_SIZE: usize = 2048;

// =============================================================================
// Service Lookup
// =============================================================================

/// Look up a service handler from the service tables.
///
/// # Arguments
/// * `service_number` - The 32-bit service number
///
/// # Returns
/// * `Some(handler)` on success
/// * `None` if service not found
pub fn lookup_service(service_number: ULONG32) -> Option<ServiceHandler> {
    let table_idx = get_table_index(service_number);
    let svc_idx = get_service_index(service_number);

    if svc_idx >= BASE_SERVICE_TABLE_SIZE as u32 {
        return None;
    }

    match table_idx {
        0 => {
            let entry = unsafe { &BASE_SERVICE_TABLE[svc_idx as usize] };
            entry.get_handler()
        }
        1 => {
            let entry = unsafe { &SHADOW_SERVICE_TABLE[svc_idx as usize] };
            entry.get_handler()
        }
        _ => None,
    }
}

// =============================================================================
// Service Table Initialization
// =============================================================================

/// Initialize the service table with stub entries.
/// In a real implementation, this would parse ntdll.dll exports.
pub fn init_service_table() {

    // Register memory management services
    register_base_service(
        service_numbers::NT_ALLOCATE_VIRTUAL_MEMORY,
        stub_handler,
        24, // 6 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_FREE_VIRTUAL_MEMORY,
        stub_handler,
        16, // 4 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_QUERY_VIRTUAL_MEMORY,
        stub_handler,
        20, // 5 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_PROTECT_VIRTUAL_MEMORY,
        stub_handler,
        20, // 5 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_READ_PROCESS_MEMORY,
        stub_handler,
        20, // 5 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_WRITE_PROCESS_MEMORY,
        stub_handler,
        20, // 5 args * 4 bytes
    );

    // Register process services
    register_base_service(
        service_numbers::NT_CREATE_PROCESS,
        stub_handler,
        32, // 8 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_OPEN_PROCESS,
        stub_handler,
        16, // 4 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_QUERY_INFORMATION_PROCESS,
        stub_handler,
        20, // 5 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_SET_INFORMATION_PROCESS,
        stub_handler,
        16, // 4 args * 4 bytes
    );

    // Register thread services
    register_base_service(
        service_numbers::NT_CREATE_THREAD,
        stub_handler,
        28, // 7 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_OPEN_THREAD,
        stub_handler,
        16, // 4 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_GET_CONTEXT_THREAD,
        stub_handler,
        12, // 3 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_SET_CONTEXT_THREAD,
        stub_handler,
        12, // 3 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_QUERY_INFORMATION_THREAD,
        stub_handler,
        20, // 5 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_SET_INFORMATION_THREAD,
        stub_handler,
        16, // 4 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_SUSPEND_THREAD,
        stub_handler,
        8, // 2 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_RESUME_THREAD,
        stub_handler,
        8, // 2 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_QUEUE_APC_THREAD,
        stub_handler,
        16, // 4 args * 4 bytes
    );

    // Register exception services
    register_base_service(
        service_numbers::NT_RAISE_EXCEPTION,
        stub_handler,
        16, // 4 args * 4 bytes
    );
    register_base_service(
        service_numbers::NT_DISPATCH_EXCEPTION,
        stub_handler,
        12, // 3 args * 4 bytes
    );

}

/// Register a base (ntdll) service.
fn register_base_service(
    service_number: ULONG32,
    handler: ServiceHandler,
    arg_size: u8,
) {
    let idx = get_service_index(service_number) as usize;
    if idx < BASE_SERVICE_TABLE_SIZE {
        // Safety: Writing to static mutable storage during init
        unsafe {
            BASE_SERVICE_TABLE[idx] = ServiceEntry::new(Some(handler), arg_size);
        }
    }
}

/// Register a shadow (win32k) service.
fn register_shadow_service(
    service_number: ULONG32,
    handler: ServiceHandler,
    arg_size: u8,
) {
    let idx = get_service_index(service_number) as usize;
    if idx < SHADOW_SERVICE_TABLE_SIZE {
        unsafe {
            SHADOW_SERVICE_TABLE[idx] = ServiceEntry::new(Some(handler), arg_size);
        }
    }
}

/// Update an existing service handler in the base table.
/// This allows external modules (like syscall_thunk) to replace
/// stub handlers with real implementations after init.
pub fn update_service_handler(
    service_number: ULONG32,
    handler: ServiceHandler,
) {
    register_base_service(service_number, handler, 0);
}

/// Update an existing shadow service handler.
pub fn update_shadow_service_handler(
    service_number: ULONG32,
    handler: ServiceHandler,
) {
    register_shadow_service(service_number, handler, 0);
}

/// Stub handler for unregistered services.
unsafe extern "C" fn stub_handler(_args: *const u32) -> ULONG32 {
    STATUS_NOT_IMPLEMENTED_32
}

// =============================================================================
// Service Dispatch
// =============================================================================

/// Dispatch a 32-bit system call.
/// This is called from the syscall thunk when a 32-bit app makes a syscall.
///
/// # Arguments
/// * `service_number` - The decoded 32-bit service number
/// * `args` - Pointer to 32-bit argument stack
///
/// # Returns
/// * NTSTATUS from the service
pub unsafe fn dispatch_service(
    service_number: ULONG32,
    args: *const u32,
) -> ULONG32 {
    let table_idx = get_table_index(service_number);
    let svc_idx = get_service_index(service_number);

    match table_idx {
        0 => {
            if svc_idx as usize >= BASE_SERVICE_TABLE_SIZE {
                crate::wow64_klog!(
                    "[SSD] Invalid base svc idx 0x{:03x}", svc_idx
                );
                return STATUS_INVALID_PARAMETER_32;
            }
            let entry = &BASE_SERVICE_TABLE[svc_idx as usize];
            match entry.get_handler() {
                Some(handler) => handler(args),
                None => {
                    crate::wow64_klog!(
                        "[SSD] Unregistered base svc 0x{:03x}", svc_idx
                    );
                    STATUS_NOT_IMPLEMENTED_32
                }
            }
        }
        1 => {
            if svc_idx as usize >= SHADOW_SERVICE_TABLE_SIZE {
                crate::wow64_klog!(
                    "[SSD] Invalid shadow svc idx 0x{:03x}", svc_idx
                );
                return STATUS_INVALID_PARAMETER_32;
            }
            let entry = &SHADOW_SERVICE_TABLE[svc_idx as usize];
            match entry.get_handler() {
                Some(handler) => handler(args),
                None => {
                    crate::wow64_klog!(
                        "[SSD] Unregistered shadow svc 0x{:03x}", svc_idx
                    );
                    STATUS_NOT_IMPLEMENTED_32
                }
            }
        }
        _ => {
            crate::wow64_klog!(
                "[SSD] Unknown table index {} for svc 0x{:08x}",
                table_idx, service_number
            );
            STATUS_INVALID_PARAMETER_32
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_number_decoding() {
        // Normal service: table 0, index 0x011
        let svc = 0x0011u32;
        assert_eq!(get_table_index(svc), 0);
        assert_eq!(get_service_index(svc), 0x011);

        // Shadow service: table 1, index 0x100
        let svc = 0x1001u32;
        assert_eq!(get_table_index(svc), 1);
        assert_eq!(get_service_index(svc), 0x001);

        // Table 1, higher index
        let svc = 0x1123u32;
        assert_eq!(get_table_index(svc), 1);
        assert_eq!(get_service_index(svc), 0x123);
    }

    #[test]
    fn test_is_shadow_service() {
        assert!(!is_shadow_service(0x0011));
        assert!(is_shadow_service(0x1001));
        assert!(!is_shadow_service(0x2001));
        assert!(is_shadow_service(0x1234));
    }

    #[test]
    fn test_service_descriptor() {
        let desc = Wow64ServiceDescriptor::new(0x10000, 2048, 0x11000);
        assert!(desc.is_valid_service(100));
        assert!(!desc.is_valid_service(2048));
        assert!(!desc.is_valid_service(0xFFFFFFFF));
    }
}
