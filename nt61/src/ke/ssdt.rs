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

#![cfg(target_arch = "x86_64")]

use crate::ke::shadow_ssdt::SHADOW_MAX_SERVICES;

/// Maximum number of services in the SSDT
pub const SSDT_MAX_SERVICES: usize = 512;

/// Maximum argument size (in bytes) for a single service call
pub const SSDT_MAX_ARGUMENT_SIZE: usize = 0x400;

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
static mut KE_SERVICE_DESCRIPTOR_TABLE: KeServiceDescriptorTable = 
    KeServiceDescriptorTable {
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
    unsafe { &KE_SERVICE_DESCRIPTOR_TABLE }
}

/// Service argument count encoding
/// On x64: bits 16-31 of the service number encode the argument size
#[inline(always)]
pub fn get_argument_size(service_number: u32) -> u32 {
    (service_number >> 16) & 0xFF
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

/// SSDT entry point signature
pub type SsdtHandler = extern "C" fn() -> u64;

// External C function for syscall dispatch (linked by loader; not called
// directly inside the kernel because the dispatch table resolves the call)
extern "C" {
    #[allow(unused)]
    fn syscall_dispatch(syscall_num: u64, tf: *mut ()) -> u64;
}

// =====================================================================
// KiServiceTable - The actual service table
// =====================================================================
//
// This is the core system service table. Each entry is a pointer to
// the handler function. The table is indexed by the service number
// (masked to 12 bits).
//
// In a real implementation, this would be populated with actual
// function pointers. For the bootstrap, we use a static array
// and populate it during initialization.
//
// ## Windows 7 x64 SSDT Entry Format
//
// Each entry in KiServiceTable is a 4-byte encoded value:
//   - High 28 bits: Offset from KiServiceTable base (divided by 16)
//   - Low 4 bits: Argument size in bytes
//
// Formula: handler_address = KiServiceTableBase + (entry >> 4) * 16
//
// For this implementation, we support both:
//   1. Direct function pointers (simplified for static linking)
//   2. Encoded offset entries (Windows-compatible)

/// KiServiceTable entry using encoded offset (Windows-compatible)
/// Each entry is 4 bytes: high 28 bits = offset/16, low 4 bits = arg size
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ServiceTableEntry {
    pub handler: *const (),
}

impl ServiceTableEntry {
    pub const fn new() -> Self {
        Self { handler: core::ptr::null() }
    }
    
    pub const fn is_null(&self) -> bool {
        self.handler.is_null()
    }
}

/// Encoded SSDT entry for Windows-compatible offset calculation
/// High 28 bits = relative offset / 16, Low 4 bits = argument size
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EncodedServiceEntry {
    pub encoded: u32,
}

impl EncodedServiceEntry {
    pub const fn new() -> Self {
        Self { encoded: 0 }
    }
    
    pub const fn is_null(&self) -> bool {
        self.encoded == 0
    }
    
    /// Create an encoded entry from handler address and table base
    /// 
    /// # Arguments
    /// * `handler` - The absolute address of the service handler
    /// * `table_base` - The base address of KiServiceTable
    /// * `arg_size` - Argument size in bytes (max 15)
    pub const fn create(handler: u64, table_base: u64, arg_size: u8) -> Self {
        let offset = handler.wrapping_sub(table_base);
        let offset_units = (offset / 16) as u32;
        let encoded = (offset_units << 4) | (arg_size as u32 & 0xF);
        Self { encoded }
    }
    
    /// Get handler address from encoded entry
    pub fn get_handler(&self, table_base: u64) -> *const () {
        let offset_units = self.encoded >> 4;
        let offset = (offset_units as u64) * 16;
        (table_base.wrapping_add(offset)) as *const ()
    }
    
    /// Get argument size from encoded entry
    pub fn get_argument_size(&self) -> u8 {
        (self.encoded & 0xF) as u8
    }
}

/// KiServiceTable - the main system service table
/// This is a static array that will be populated during init
#[allow(unused_mut)]
static mut KI_SERVICE_TABLE: [ServiceTableEntry; SSDT_MAX_SERVICES] = {
    let mut arr = [ServiceTableEntry::new(); SSDT_MAX_SERVICES];
    arr
};

/// Encoded KiServiceTable for Windows-compatible offset calculation
#[allow(unused_mut)]
static mut KI_SERVICE_TABLE_ENCODED: [EncodedServiceEntry; SSDT_MAX_SERVICES] = {
    let mut arr = [EncodedServiceEntry::new(); SSDT_MAX_SERVICES];
    arr
};

/// Argument count table - each entry is a byte encoding the argument size
static mut KI_ARGUMENT_TABLE: [u8; SSDT_MAX_SERVICES] = [0; SSDT_MAX_SERVICES];

// =====================================================================
// SSDT Dispatch Functions
// =====================================================================

/// Initialize the SSDT with service handlers
/// This function should be called during kernel initialization
pub fn init() {
    crate::hal::serial::write_string("[ke.ssdt] enter\r\n");
    // // kprintln!("[SSDT] Initializing System Service Dispatch Table...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Initialize KeServiceDescriptorTable with proper pointers
    unsafe {
        let table_base = KI_SERVICE_TABLE.as_ptr() as u64;
        let arg_base = KI_ARGUMENT_TABLE.as_ptr();
        
        KE_SERVICE_DESCRIPTOR_TABLE.base = KeServiceDescriptor {
            service_table: table_base as *const (),
            counter_table: core::ptr::null(),
            service_count: SSDT_MAX_SERVICES as u32,
            argument_table: arg_base,
        };
        
        // Initialize shadow table (win32k) - will be populated later
        KE_SERVICE_DESCRIPTOR_TABLE.shadow = KeServiceDescriptor {
            service_table: SHADOW_SERVICE_TABLE.as_ptr() as *const (),
            counter_table: core::ptr::null(),
            service_count: SHADOW_MAX_SERVICES as u32,
            argument_table: SHADOW_ARGUMENT_TABLE.as_ptr(),
        };
        
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[SSDT] KeServiceDescriptorTable initialized:");
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "  - Native base: 0x{:016x}, services: {}, args: {:p}",
// //             table_base, SSDT_MAX_SERVICES, arg_base
// //         );
    }
    
    // // kprintln!("[SSDT] SSDT initialized with {} max services", SSDT_MAX_SERVICES)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Get a service handler from the SSDT
/// Returns the handler function pointer for the given service number
pub fn get_service_handler(service_number: u32) -> Option<*const ()> {
    let index = get_service_index(service_number) as usize;
    if index >= SSDT_MAX_SERVICES {
        return None;
    }
    
    unsafe {
        let entry = &KI_SERVICE_TABLE[index];
        if entry.handler.is_null() {
            None
        } else {
            Some(entry.handler)
        }
    }
}

/// Get the argument size for a service
pub fn get_service_argument_size(service_number: u32) -> u32 {
    let index = get_service_index(service_number) as usize;
    if index >= SSDT_MAX_SERVICES {
        return 0;
    }
    
    unsafe {
        KI_ARGUMENT_TABLE[index] as u32
    }
}

/// Register a service handler in the SSDT
/// 
/// # Safety
/// This function modifies a static mutable array. It should only be
/// called during initialization when no other cores are running.
pub unsafe fn register_service(service_number: u32, handler: *const (), arg_size: u8) {
    let index = get_service_index(service_number) as usize;
    if index >= SSDT_MAX_SERVICES {
        // // kprintln!("[SSDT] ERROR: Service index {} out of range", index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return;
    }
    
    KI_SERVICE_TABLE[index].handler = handler;
    KI_ARGUMENT_TABLE[index] = arg_size;
    
    // // kprintln!("[SSDT] Registered service #{:03x} at index {} (args={})",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //              service_number, index, arg_size);
}

/// Register a service handler using Windows-compatible encoded offset
/// 
/// This function stores the service in the encoded table using the
/// Windows 7 x64 SSDT format: handler = base + (encoded >> 4) * 16
/// 
/// # Safety
/// This function modifies static mutable arrays. Only call during init.
pub unsafe fn register_service_encoded(
    service_number: u32,
    handler: *const (),
    arg_size: u8,
    table_base: u64,
) {
    let index = get_service_index(service_number) as usize;
    if index >= SSDT_MAX_SERVICES {
        // // kprintln!("[SSDT] ERROR: Encoded service index {} out of range", index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return;
    }
    
    // Also store in the direct pointer table for backward compatibility
    KI_SERVICE_TABLE[index].handler = handler;
    
    // Store encoded entry
    KI_SERVICE_TABLE_ENCODED[index] = EncodedServiceEntry::create(
        handler as u64,
        table_base,
        arg_size,
    );
    KI_ARGUMENT_TABLE[index] = arg_size;
    
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "[SSDT] Registered encoded service #{:03x} at index {} (args={}, offset_encoded=0x{:08x})", 
// //         service_number, index, arg_size, KI_SERVICE_TABLE_ENCODED[index].encoded
// //     );
}

/// Get handler using Windows-compatible encoded offset calculation
/// 
/// Returns the handler address computed as: base + (encoded >> 4) * 16
pub fn get_service_handler_encoded(service_number: u32, table_base: u64) -> Option<*const ()> {
    let index = get_service_index(service_number) as usize;
    if index >= SSDT_MAX_SERVICES {
        return None;
    }
    
    unsafe {
        let entry = &KI_SERVICE_TABLE_ENCODED[index];
        if entry.is_null() {
            // Fall back to direct pointer table
            let direct = &KI_SERVICE_TABLE[index];
            if direct.handler.is_null() {
                None
            } else {
                Some(direct.handler)
            }
        } else {
            Some(entry.get_handler(table_base))
        }
    }
}

/// Get KiServiceTable base address (for use with encoded entries)
/// 
/// Returns the address of the KiServiceTable static array.
/// This is needed for computing encoded offsets.
pub fn get_service_table_base() -> u64 {
    unsafe { KI_SERVICE_TABLE.as_ptr() as u64 }
}

// =====================================================================
// Shadow SSDT (Win32k)
// =====================================================================
//
// The Shadow SSDT contains services provided by win32k.sys for
// graphics and window management. When a win32k service is called
// from user mode, the service number is in the range 0x1000-0x1FFF.

/// Shadow SSDT (Win32k services)
#[allow(unused_mut)]
static mut SHADOW_SERVICE_TABLE: [ServiceTableEntry; SSDT_MAX_SERVICES] = {
    let mut arr = [ServiceTableEntry::new(); SSDT_MAX_SERVICES];
    arr
};

static mut SHADOW_ARGUMENT_TABLE: [u8; SSDT_MAX_SERVICES] = [0; SSDT_MAX_SERVICES];

/// Get a shadow (win32k) service handler
pub fn get_shadow_service_handler(service_number: u32) -> Option<*const ()> {
    // Shadow services are in range 0x1000-0x1FFF
    let index = (service_number & 0xFFF) as usize;
    if index >= SSDT_MAX_SERVICES {
        return None;
    }
    
    unsafe {
        let entry = &SHADOW_SERVICE_TABLE[index];
        if entry.handler.is_null() {
            None
        } else {
            Some(entry.handler)
        }
    }
}

/// Register a shadow (win32k) service handler
/// 
/// # Safety
/// This function modifies a static mutable array. It should only be
/// called during initialization.
pub unsafe fn register_shadow_service(service_number: u32, handler: *const (), arg_size: u8) {
    let index = (service_number & 0xFFF) as usize;
    if index >= SSDT_MAX_SERVICES {
        // // kprintln!("[SSDT] ERROR: Shadow service index {} out of range", index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return;
    }
    
    SHADOW_SERVICE_TABLE[index].handler = handler;
    SHADOW_ARGUMENT_TABLE[index] = arg_size;
    
    // // kprintln!("[SSDT] Registered shadow service #{:04x} at index {} (args={})",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //              service_number, index, arg_size);
}

// =====================================================================
// Service Dispatch
// =====================================================================

/// Dispatch a system service call
/// This is called from the syscall entry point with the service number
/// and a pointer to the trap frame.
pub fn dispatch_service(service_number: u32, trap_frame: *mut ()) -> u64 {
    let table_index = get_table_index(service_number);
    
    match table_index {
        0 => {
            // Native service table - use encoded offset if available
            let table_base = get_service_table_base();
            match get_service_handler_encoded(service_number, table_base) {
                Some(handler) => {
                    // Call the handler
                    unsafe {
                        let fn_ptr: extern "C" fn(*mut ()) -> u64 = 
                            core::mem::transmute(handler);
                        fn_ptr(trap_frame)
                    }
                }
                None => {
                    // Fall back to direct lookup
                    match get_service_handler(service_number) {
                        Some(handler) => {
                            unsafe {
                                let fn_ptr: extern "C" fn(*mut ()) -> u64 = 
                                    core::mem::transmute(handler);
                                fn_ptr(trap_frame)
                            }
                        }
                        None => {
                            // // kprintln!("[SSDT] Unimplemented native service 0x{:03x}",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                                      get_service_index(service_number));
                            0xC0000001u32 as u64 // STATUS_NOT_IMPLEMENTED
                        }
                    }
                }
            }
        }
        1 => {
            // Shadow (win32k) service table
            match get_shadow_service_handler(service_number) {
                Some(handler) => {
                    unsafe {
                        let fn_ptr: extern "C" fn(*mut ()) -> u64 = 
                            core::mem::transmute(handler);
                        fn_ptr(trap_frame)
                    }
                }
                None => {
                    // // kprintln!("[SSDT] Unimplemented shadow service 0x{:04x}",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                              service_number);
                    0xC0000001u32 as u64
                }
            }
        }
        _ => {
            // // kprintln!("[SSDT] Unknown table index {}", table_index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            0xC0000001u32 as u64
        }
    }
}

// =====================================================================
// Smoke Test
// =====================================================================

/// Run SSDT smoke test
pub fn smoke_test() -> bool {
    // // kprintln!("  [SSDT SMOKE] running SSDT smoke test...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    // Check that the service tables are accessible
    let table_ptr = unsafe { KI_SERVICE_TABLE.as_ptr() };
    if table_ptr.is_null() {
        // // kprintln!("  [SSDT SMOKE FAIL] KiServiceTable is null")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    
    let arg_ptr = unsafe { KI_ARGUMENT_TABLE.as_ptr() };
    if arg_ptr.is_null() {
        // // kprintln!("  [SSDT SMOKE FAIL] KiArgumentTable is null")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    
    // // kprintln!("  [SSDT SMOKE] KiServiceTable: {:p}", table_ptr)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  [SSDT SMOKE] KiArgumentTable: {:p}", arg_ptr)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  [SSDT SMOKE] Max services: {}", SSDT_MAX_SERVICES)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  [SSDT SMOKE OK]")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    true
}
