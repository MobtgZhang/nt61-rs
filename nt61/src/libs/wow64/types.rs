//! In NT 6.1 the WoW64 layer translates 32-bit structures
//! into their 64-bit counterparts before calling into the
//! kernel. This module provides comprehensive type definitions
//! for Wow64 compatibility including CONTEXT32, PEB32, TEB32,
//! and various Wow64-specific structures.
//
//! References:
//!   * geoffchappell.com - Windows 7 x86 structure layouts
//!   * Vergilius Project - Windows kernel structure references
//!   * ReactOS 0.3.x WoW64 implementation

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use core::ptr::null_mut;

// =============================================================================
// Basic 32-bit Types
// =============================================================================

/// 32-bit USHORT.
pub type USHORT16 = u16;
/// 32-bit ULONG.
pub type ULONG32 = u32;
/// 32-bit pointer (just an address).
pub type ULONG32_PTR = u32;
/// 32-bit DWORD.
pub type DWORD = u32;
/// 32-bit WORD.
pub type WORD = u16;
/// 32-bit BOOL.
pub type BOOL = i32;
/// 32-bit HANDLE (still 32-bit in WoW64 processes).
pub type HANDLE32 = u32;

// =============================================================================
// Wow64 Address Space Constants
// =============================================================================

/// Wow64 user space start (leave NULL pointer guard page).
pub const WOW64_USER_SPACE_START: ULONG32 = 0x00010000;
/// Wow64 user space end (exclusive, compatible zone end).
pub const WOW64_USER_SPACE_END: ULONG32 = 0x7FFEFFFF;
/// Wow64 System DLL base (wow64.dll, ntdll.dll, etc).
pub const WOW64_SYSTEM_DLL_BASE: ULONG32 = 0x7FFE0000;
/// Wow64 System DLL region size (256MB).
pub const WOW64_SYSTEM_DLL_SIZE: ULONG32 = 0x01000000;
/// Maximum user-mode address in Wow64 (exclusive).
pub const WOW64_MAX_USER_ADDRESS: ULONG32 = 0x7FFEFFFF;

/// PEB32 virtual address in Windows 7 x86 processes on x64 Windows.
/// This is the address where the 32-bit PEB is mapped in the Wow64 process.
pub const PEB32_VIRTUAL_ADDRESS: ULONG32 = 0x7FFDE000;

/// TEB32 base address in Windows 7 x86.
/// The first thread's TEB32 is at this address; subsequent TEBs are
/// spaced at TEB32_SIZE (0x1000) intervals.
pub const TEB32_BASE_ADDRESS: ULONG32 = 0x7FFDE000;

/// TEB32 size (one page).
pub const TEB32_SIZE: u32 = 0x1000;

// =============================================================================
// NTSTATUS Constants
// =============================================================================

pub const STATUS_SUCCESS: ULONG32 = 0x00000000;
pub const STATUS_INVALID_PARAMETER: ULONG32 = 0xC000000D;
pub const STATUS_ACCESS_DENIED: ULONG32 = 0xC0000022;
pub const STATUS_NO_MEMORY: ULONG32 = 0xC0000017;
pub const STATUS_INVALID_HANDLE: ULONG32 = 0xC0000008;
pub const STATUS_UNSUCCESSFUL: ULONG32 = 0xC0000001;
pub const STATUS_BUFFER_TOO_SMALL: ULONG32 = 0xC0000023;
pub const STATUS_INFO_LENGTH_MISMATCH: ULONG32 = 0xC0000004;
pub const STATUS_NOT_IMPLEMENTED: ULONG32 = 0xC0000002;

// =============================================================================
// 32-bit List Entry (LIST_ENTRY32)
// =============================================================================

/// LIST_ENTRY32 - 32-bit intrusive doubly-linked list entry.
/// Used in PEB32 and TEB32 for loader data structures.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct ListEntry32 {
    /// Forward link to next entry.
    pub flink: ULONG32,
    /// Backward link to previous entry.
    pub blink: ULONG32,
}

impl ListEntry32 {
    /// Create a new empty (self-anchored) list entry.
    pub fn new() -> Self {
        Self { flink: 0, blink: 0 }
    }

    /// Initialize as a self-anchored empty list (fling == blink == self).
    pub fn init(&mut self) {
        let me = self as *mut ListEntry32 as ULONG32;
        self.flink = me;
        self.blink = me;
    }

    /// Check if this list entry is self-anchored (empty list).
    pub fn is_empty(&self) -> bool {
        let me = self as *const ListEntry32 as ULONG32;
        self.flink == me && self.blink == me
    }
}

// =============================================================================
// 32-bit Client ID (CLIENT_ID32)
// =============================================================================

/// CLIENT_ID32 - 32-bit unique process/thread identifier.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct ClientId32 {
    /// Unique process ID.
    pub unique_process: ULONG32,
    /// Unique thread ID.
    pub unique_thread: ULONG32,
}

impl ClientId32 {
    pub fn new() -> Self {
        Self { unique_process: 0, unique_thread: 0 }
    }

    pub fn set(&mut self, pid: u32, tid: u32) {
        self.unique_process = pid;
        self.unique_thread = tid;
    }
}

// =============================================================================
// 32-bit Unicode String (UNICODE_STRING32)
// =============================================================================

/// UNICODE_STRING32 - 32-bit counted unicode string.
/// Used in PEB32 for DLL names and command line.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct UnicodeString32 {
    /// Length in bytes (not characters).
    pub Length: u16,
    /// Maximum length in bytes.
    pub MaximumLength: u16,
    /// Pointer to buffer (32-bit).
    pub Buffer: ULONG32,
}

impl UnicodeString32 {
    pub fn new() -> Self {
        Self { Length: 0, MaximumLength: 0, Buffer: 0 }
    }

    /// Get length as usize.
    pub fn len(&self) -> usize {
        self.Length as usize
    }

    /// Check if string is empty.
    pub fn is_empty(&self) -> bool {
        self.Length == 0
    }
}

// =============================================================================
// CONTEXT32 (x86 32-bit Thread Context)
// =============================================================================

/// CONTEXT32 - x86 32-bit thread context structure.
/// Size: 0x2CC bytes (716 bytes)
/// Reference: geoffchappell.com studies/windows/km/ntoskrnl/inc/ntos/mm/ctx/lite.htm
///
/// The CONTEXT structure contains processor-specific register data.
/// On x86, this includes general purpose registers, segment registers,
/// debug registers, and floating point state.
#[repr(C)]
pub struct Context32 {
    // === Context Header ===
    /// Context flags indicating which registers are valid.
    pub context_flags: ULONG32,

    // === Debug Registers ===
    pub dr0: ULONG32,  // 0x04
    pub dr1: ULONG32,  // 0x08
    pub dr2: ULONG32,  // 0x0C
    pub dr3: ULONG32,  // 0x10
    pub dr6: ULONG32,  // 0x14
    pub dr7: ULONG32,  // 0x18

    // === Floating Point State (FPU_SAVE_AREA, 112 bytes) ===
    pub float_save: FpuSaveArea32,  // 0x1C

    // === Segment Registers ===
    pub gs: ULONG32,  // 0x8C
    pub fs: ULONG32,  // 0x90
    pub es: ULONG32,  // 0x94
    pub ds: ULONG32,  // 0x98

    // === General Purpose Registers ===
    pub edi: ULONG32,  // 0x9C
    pub esi: ULONG32,  // 0xA0
    pub ebx: ULONG32,  // 0xA4
    pub edx: ULONG32,  // 0xA8
    pub ecx: ULONG32,  // 0xAC
    pub eax: ULONG32,  // 0xB0

    // === Frame Pointer & Program Counter ===
    pub ebp: ULONG32,  // 0xB4
    pub eip: ULONG32,  // 0xB8 (instruction pointer)
    pub cs: ULONG32,   // 0xBC (code segment)
    pub eflags: ULONG32,  // 0xC0
    pub esp: ULONG32,  // 0xC4 (stack pointer)
    pub ss: ULONG32,   // 0xC8 (stack segment)

    // === Extended Registers (from FPU/FP stack) ===
    // The extended register state follows, typically 512 bytes for SSE/XMM
    // but on basic x86 without SSE this area contains the FP register stack.
    pub extended_registers: [u8; 512],  // 0xCC
}

impl Default for Context32 {
    fn default() -> Self {
        Self {
            context_flags: 0,
            dr0: 0, dr1: 0, dr2: 0, dr3: 0, dr6: 0, dr7: 0,
            float_save: FpuSaveArea32::default(),
            gs: 0, fs: 0, es: 0, ds: 0,
            edi: 0, esi: 0, ebx: 0, edx: 0, ecx: 0, eax: 0,
            ebp: 0, eip: 0, cs: 0, eflags: 0, esp: 0, ss: 0,
            extended_registers: [0; 512],
        }
    }
}

impl Context32 {
    pub fn new() -> Self {
        Self {
            context_flags: 0,
            dr0: 0, dr1: 0, dr2: 0, dr3: 0, dr6: 0, dr7: 0,
            float_save: FpuSaveArea32::default(),
            gs: 0, fs: 0, es: 0, ds: 0,
            edi: 0, esi: 0, ebx: 0, edx: 0, ecx: 0, eax: 0,
            ebp: 0, eip: 0, cs: 0, eflags: 0, esp: 0, ss: 0,
            extended_registers: [0; 512],
        }
    }

    /// Context flag: full context.
    pub const CONTEXT_FULL: ULONG32 = 0x00010007;
    /// Context flag: integer registers only.
    pub const CONTEXT_INTEGER: ULONG32 = 0x00010002;
    /// Context flag: control registers (EIP, EBP, ESP, CS, SS, EFLAGS).
    pub const CONTEXT_CONTROL: ULONG32 = 0x00010005;
    /// Context flag: segment registers.
    pub const CONTEXT_SEGMENTS: ULONG32 = 0x00010004;
    /// Context flag: floating point registers.
    pub const CONTEXT_FLOATING_POINT: ULONG32 = 0x00010008;
    /// Context flag: debug registers.
    pub const CONTEXT_DEBUG_REGISTERS: ULONG32 = 0x00010010;
}

// Context32 size assertion
const _: () = assert!(
    core::mem::size_of::<Context32>() == 0x2CC,
    "Context32 must be 0x2CC bytes"
);

// =============================================================================
// FPU Save Area (FPU_SAVE_AREA32)
// =============================================================================
// Context32 size assertion (temporarily disabled - needs field alignment fix)
// const _: () = assert!(
//     core::mem::size_of::<Context32>() == 0x2CC,
//     "Context32 must be 0x2CC bytes"
// );

/// FPU_SAVE_AREA32 - x86 FPU floating point register save area.
/// Size: 112 bytes (0x70)
#[repr(C)]
pub struct FpuSaveArea32 {
    /// Control word.
    pub control_word: u32,     // 0x00
    /// Status word.
    pub status_word: u32,     // 0x04
    /// Tag word.
    pub tag_word: u32,        // 0x08
    /// Error offset.
    pub error_offset: u32,    // 0x0C
    /// Error selector.
    pub error_selector: u32,  // 0x10
    /// Data offset.
    pub data_offset: u32,     // 0x14
    /// Data selector.
    pub data_selector: u32,   // 0x18
    /// Register area (8 registers * 10 bytes each = 80 bytes).
    pub register_area: [u8; 80],  // 0x1C
    /// Reserved padding to make total size 112 bytes (0x70).
    pub _reserved: u32,  // 0x6C - padding to reach 112 bytes total
}

impl Default for FpuSaveArea32 {
    fn default() -> Self {
        Self {
            control_word: 0,
            status_word: 0,
            tag_word: 0,
            error_offset: 0,
            error_selector: 0,
            data_offset: 0,
            data_selector: 0,
            register_area: [0; 80],
            _reserved: 0,
        }
    }
}

// =============================================================================
// WOW64_PROCESS_INFORMATION
// =============================================================================

/// WOW64_PROCESS_INFORMATION - Information about a Wow64 process.
/// This structure is used by Wow64AllocateVirtualMemory and related functions
/// to describe the Wow64 process context.
#[repr(C)]
#[derive(Default)]
pub struct Wow64ProcessInformation {
    /// 32-bit PEB address.
    pub peb_32: ULONG32,
    /// Pointer to shared PEB (kernel-mode address of PEB64).
    pub shared_peb: ULONG32,
    /// User-mode shared data pointer.
    pub user_shared_data: ULONG32,
    /// Target ETHREAD address (kernel-mode).
    pub target_ethread: ULONG32,
    /// Target EPROCESS address (kernel-mode).
    pub target_eprocess: ULONG32,
}

// =============================================================================
// WOW64_MEMORY_BASIC_INFORMATION32
// =============================================================================

/// WOW64_MEMORY_BASIC_INFORMATION32 - Memory region information in 32-bit terms.
/// Used by Wow64QueryVirtualMemory.
#[repr(C)]
#[derive(Default)]
pub struct Wow64MemoryBasicInformation32 {
    /// Base address of region.
    pub base_address: ULONG32,
    /// Allocation base address.
    pub allocation_base: ULONG32,
    /// Allocation protect value.
    pub allocation_protect: ULONG32,
    /// Region size.
    pub region_size: ULONG32,
    /// State (MEM_COMMIT, MEM_FREE, MEM_RESERVE).
    pub state: ULONG32,
    /// Protect (PAGE_READ, PAGE_WRITE, etc).
    pub protect: ULONG32,
    /// Type (MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE).
    pub memory_type: ULONG32,
}

// Memory allocation types
pub mod memory_allocation_type {
    use super::ULONG32;
    pub const MEM_COMMIT: ULONG32 = 0x1000;
    pub const MEM_RESERVE: ULONG32 = 0x2000;
    pub const MEM_DECOMMIT: ULONG32 = 0x4000;
    pub const MEM_RELEASE: ULONG32 = 0x8000;
    pub const MEM_FREE: ULONG32 = 0x10000;
}

// Memory states
pub mod memory_state {
    use super::ULONG32;
    pub const MEM_COMMIT: ULONG32 = 0x1000;
    pub const MEM_RESERVE: ULONG32 = 0x2000;
    pub const MEM_FREE: ULONG32 = 0x10000;
}

// Memory protection constants
pub mod memory_protect {
    use super::ULONG32;
    pub const PAGE_NOACCESS: ULONG32 = 0x01;
    pub const PAGE_READONLY: ULONG32 = 0x02;
    pub const PAGE_READWRITE: ULONG32 = 0x04;
    pub const PAGE_WRITECOPY: ULONG32 = 0x08;
    pub const PAGE_EXECUTE: ULONG32 = 0x10;
    pub const PAGE_EXECUTE_READ: ULONG32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: ULONG32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: ULONG32 = 0x80;
    pub const PAGE_GUARD: ULONG32 = 0x100;
    pub const PAGE_NOCACHE: ULONG32 = 0x200;
    pub const PAGE_WRITECOMBINE: ULONG32 = 0x400;
}

// =============================================================================
// 32-bit LDR Data Table Entry (LDR_DATA_TABLE_ENTRY32)
// =============================================================================

/// LDR_DATA_TABLE_ENTRY32 - 32-bit module (DLL) entry in the PEB loader data.
/// Size: 0x58 bytes
/// Reference: geoffchappell.com
#[repr(C)]
#[derive(Default)]
pub struct LdrDataTableEntry32 {
    /// In-memory order links (LIST_ENTRY32).
    pub in_load_order_links: ListEntry32,       // +0x00
    /// Memory order links.
    pub in_memory_order_links: ListEntry32,    // +0x08
    /// Initialization order links.
    pub in_initialization_order_links: ListEntry32,  // +0x10
    /// DLL base address.
    pub dll_base: ULONG32,                    // +0x18
    /// Entry point RVA.
    pub entry_point: ULONG32,                  // +0x1C
    /// Size of image.
    pub size_of_image: ULONG32,               // +0x20
    /// Full DLL path name (UNICODE_STRING32).
    pub full_dll_name: UnicodeString32,       // +0x24
    /// Base DLL name (UNICODE_STRING32).
    pub base_dll_name: UnicodeString32,      // +0x2C
    /// Flags (LDRP_*).
    pub flags: ULONG32,                       // +0x34
    /// Load count (obsolete but still used).
    pub load_count: u16,                     // +0x38
    /// TLS index.
    pub tls_index: u16,                      // +0x3A
    /// Hash table entry (for fast module lookup).
    pub hash_table_entry: [u8; 12],          // +0x3C
    /// Section info (for cross-session DLL unloading).
    pub section_info: SectionInfo32,          // +0x48
    /// Check sum.
    pub check_sum: ULONG32,                   // +0x50
    /// Module load time (for ordering).
    pub module_load_time: u64,               // +0x54
}

// LDR Data Table Entry flags
pub mod ldr_flags {
    use super::ULONG32;
    pub const LDRP_STATIC_LINK: ULONG32 = 0x00000002;
    pub const LDRP_IMAGE_DLL: ULONG32 = 0x00000004;
    pub const LDRP_LOAD_IN_PROGRESS: ULONG32 = 0x00001000;
    pub const LDRP_UNLOAD_IN_PROGRESS: ULONG32 = 0x00002000;
    pub const LDRP_ENTRY_INSERTED: ULONG32 = 0x00004000;
    pub const LDRP_ENTRY_PROCESSED: ULONG32 = 0x00008000;
    pub const LDRP_COMPONENTS_DETACHED: ULONG32 = 0x00010000;
    pub const LDRP_DONT_CALL_FOR_THREADS: ULONG32 = 0x00040000;
    pub const LDRP_WOW64_DLL: ULONG32 = 0x00020000;
}

/// Section info for cross-session DLL unloading.
#[repr(C)]
#[derive(Default)]
pub struct SectionInfo32 {
    /// Section handle.
    pub section_handle: ULONG32,
    /// Remote section pointer.
    pub remote_section_pointer: ULONG32,
    /// Section handle reference count.
    pub section_handle_reference_count: ULONG32,
    /// Pointer to section.
    pub section_pointer: ULONG32,
}

// =============================================================================
// 32-bit PEB (PEB32)
// =============================================================================

/// PEB32 - Process Environment Block for 32-bit process on x64 Windows.
/// Size: 0x1E8 bytes (488 bytes)
/// Reference: geoffchappell.com, Vergilius Project
///
/// The PEB is created by the kernel at process creation and contains
/// information about the loaded modules, process parameters, and various
/// process-level settings.
#[repr(C)]
#[derive(Default)]
pub struct Peb32 {
    // === Inherited from NT_TIB ===
    /// Inherited from NT_TIB - pointer to environment.
    pub environment_pointer: ULONG32,      // +0x00
    /// Inherited from NT_TIB - client ID (overlaps with below).
    pub _tib_client_id_1: [u8; 8],     // +0x04

    // === PEB Header ===
    /// BeingDebugged flag.
    pub being_debugged: u8,               // +0x002
    /// Bit field (SpareBool, ImageBaseAddress, etc).
    pub bit_field: u8,                   // +0x003
    /// Spare byte.
    pub spare0: u8,                      // +0x004
    /// Spare byte.
    pub spare1: u8,                      // +0x005
    /// Spare byte.
    pub spare2: u8,                      // +0x006
    /// Spare byte.
    pub spare3: u8,                      // +0x007

    // === Loader Data ===
    /// DLL base address.
    pub image_base_address: ULONG32,       // +0x008
    /// Pointer to PPEB_LDR_DATA32.
    pub ldr: ULONG32,                     // +0x00C
    /// Process parameters block pointer.
    pub process_parameters: ULONG32,       // +0x010

    // === SubSystem & Heap ===
    /// Sub system type.
    pub sub_system_data: ULONG32,         // +0x014
    /// Process heap.
    pub process_heap: ULONG32,            // +0x018
    /// Fast PEB lock (RTL_CRITICAL_SECTION).
    pub fast_peb_lock: ULONG32,          // +0x01C

    // === More PEB fields ===
    /// Spare/alternative heap handle.
    pub sparc: ULONG32,                   // +0x020
    /// TEB address (for compatibility).
    pub teb: ULONG32,                    // +0x024 (actually at 0x030)
    /// Spare.
    pub spare_u32_1: ULONG32,            // +0x028
    /// Spare.
    pub spare_u32_2: ULONG32,            // +0x02C

    // === Extended PEB fields ===
    /// Spare PEB lock.
    pub spare_2: ULONG32,                // +0x030
    /// Spare.
    pub spare_u32_3: ULONG32,            // +0x034
    /// Spare.
    pub spare_u32_4: ULONG32,            // +0x038
    /// Spare.
    pub spare_u32_5: ULONG32,            // +0x03C
    /// Spare.
    pub spare_u32_6: ULONG32,            // +0x040
    /// Spare.
    pub spare_u32_7: ULONG32,            // +0x044
    /// Spare.
    pub spare_u32_8: ULONG32,            // +0x048
    /// Spare.
    pub spare_u32_9: ULONG32,            // +0x04C
    /// Spare.
    pub spare_u32_10: ULONG32,           // +0x050
    /// Spare.
    pub spare_u32_11: ULONG32,           // +0x054
    /// Spare.
    pub spare_u32_12: ULONG32,           // +0x058
    /// Spare.
    pub spare_u32_13: ULONG32,           // +0x05C
    /// Spare.
    pub spare_u32_14: ULONG32,           // +0x060
    /// Spare.
    pub spare_u32_15: ULONG32,           // +0x064

    // === GDI/USER Handles ===
    /// GDI handle table.
    pub gdi_shared_handle_table: ULONG32,  // +0x068
    /// Process styles / Spare.
    pub sparc_2: ULONG32,                // +0x06C
    /// Spare.
    pub spare_u32_16: ULONG32,           // +0x070

    // === TEB & Locale ===
    /// TEB32 pointer (for Wow64).
    pub teb32: ULONG32,                  // +0x074 (wow64teb)
    /// GDI DC attribute list.
    pub gdi_dc_attribute_list: ULONG32, // +0x078
    /// Loader lock (critical section).
    pub loader_lock: ULONG32,            // +0x07C
    /// OS major version.
    pub os_major_version: u8,           // +0x080
    /// OS minor version.
    pub os_minor_version: u8,           // +0x081
    /// OS build number.
    pub os_build_number: u16,            // +0x082
    /// OS platform ID.
    pub os_platform_id: u8,             // +0x084
    /// Spare.
    pub spare_byte: u8,                  // +0x085
    /// Spare.
    pub spare_word: u16,                 // +0x086
    /// Reserved / Kernel callback version.
    pub kernel_callback_version: ULONG32, // +0x088
    /// Spare.
    pub spare_u32_17: ULONG32,           // +0x08C

    // === Subsystem & Session ===
    /// Image subsystem type.
    pub image_sub_system: ULONG32,      // +0x090
    /// Image subsystem major version.
    pub image_sub_system_major_version: u16,  // +0x094
    /// Image subsystem minor version.
    pub image_sub_system_minor_version: u16,  // +0x096
    /// Spare.
    pub spare_u32_18: ULONG32,           // +0x098
    /// Spare.
    pub spare_u32_19: ULONG32,           // +0x09C

    // === Image Base & Features ===
    /// Image base value (original preferred base).
    pub image_base_value: ULONG32,        // +0x0A0
    /// Spare.
    pub spare_u32_20: ULONG32,           // +0x0A4
    /// Heap affinity / Spare.
    pub heap_affinity_mask: ULONG32,     // +0x0A8
    /// Heap affinity mask (high part).
    pub heap_affinity_mask_high: ULONG32, // +0x0AC
    /// Spare.
    pub spare_u32_21: ULONG32,           // +0x0B0

    // === Heap Information ===
    /// Number of process heaps.
    pub number_of_heaps: ULONG32,         // +0x0B4
    /// Maximum number of heaps.
    pub maximum_number_of_heaps: ULONG32, // +0x0B8
    /// Process heaps array pointer.
    pub process_heaps: ULONG32,          // +0x0BC

    // === GDI/USER More ===
    /// GDI batch.
    pub gdi_batch: ULONG32,             // +0x0C0
    /// Spare.
    pub spare_u32_22: ULONG32,           // +0x0C4
    /// Spare.
    pub spare_u32_23: ULONG32,           // +0x0C8
    /// Spare.
    pub spare_u32_24: ULONG32,           // +0x0CC
    /// Spare.
    pub spare_u32_25: ULONG32,           // +0x0D0
    /// Spare.
    pub spare_u32_26: ULONG32,           // +0x0D4
    /// Spare.
    pub spare_u32_27: ULONG32,           // +0x0D8
    /// Spare.
    pub spare_u32_28: ULONG32,           // +0x0DC

    // === RTL User Process Parameters ===
    /// RTL user process parameters.
    pub rtl_user_process_params: ULONG32,  // +0x0E0

    // === More PEB fields ===
    pub spare_u32_29: ULONG32,           // +0x0E4
    pub spare_u32_30: ULONG32,           // +0x0E8
    pub spare_u32_31: ULONG32,           // +0x0EC
    pub spare_u32_32: ULONG32,           // +0x0F0
    pub spare_u32_33: ULONG32,           // +0x0F4
    pub spare_u32_34: ULONG32,           // +0x0F8
    pub spare_u32_35: ULONG32,           // +0x0FC
    pub spare_u32_36: ULONG32,           // +0x100
    pub spare_u32_37: ULONG32,           // +0x104
    pub spare_u32_38: ULONG32,           // +0x108
    pub spare_u32_39: ULONG32,           // +0x10C
    pub spare_u32_40: ULONG32,           // +0x110
    pub spare_u32_41: ULONG32,           // +0x114
    pub spare_u32_42: ULONG32,           // +0x118
    pub spare_u32_43: ULONG32,           // +0x11C
    pub spare_u32_44: ULONG32,           // +0x120

    // === Session & GDI More ===
    /// Session ID.
    pub session_id: ULONG32,             // +0x124
    /// Spare.
    pub spare_u32_45: ULONG32,           // +0x128
    pub spare_u32_46: ULONG32,           // +0x12C
    pub spare_u32_47: ULONG32,           // +0x130
    pub spare_u32_48: ULONG32,           // +0x134
    pub spare_u32_49: ULONG32,           // +0x138

    // === Instrumentation ===
    /// Spare.
    pub spare_u32_50: ULONG32,           // +0x13C
    /// Spare.
    pub spare_u32_51: ULONG32,           // +0x140
    /// Spare.
    pub spare_u32_52: ULONG32,           // +0x144
    /// Spare.
    pub spare_u32_53: ULONG32,           // +0x148
    pub spare_u32_54: ULONG32,           // +0x14C
    pub spare_u32_55: ULONG32,           // +0x150
    pub spare_u32_56: ULONG32,           // +0x154
    pub spare_u32_57: ULONG32,           // +0x158
    pub spare_u32_58: ULONG32,           // +0x15C
    pub spare_u32_59: ULONG32,           // +0x160
    pub spare_u32_60: ULONG32,           // +0x164
    pub spare_u32_61: ULONG32,           // +0x168
    pub spare_u32_62: ULONG32,           // +0x16C
    pub spare_u32_63: ULONG32,           // +0x170
    pub spare_u32_64: ULONG32,           // +0x174
    pub spare_u32_65: ULONG32,           // +0x178
    pub spare_u32_66: ULONG32,           // +0x17C

    // === Post Process/Heap ===
    pub spare_u32_67: ULONG32,           // +0x180
    pub spare_u32_68: ULONG32,           // +0x184
    pub spare_u32_69: ULONG32,           // +0x188
    pub spare_u32_70: ULONG32,           // +0x18C
    pub spare_u32_71: ULONG32,           // +0x190
    pub spare_u32_72: ULONG32,           // +0x194
    pub spare_u32_73: ULONG32,           // +0x198
    pub spare_u32_74: ULONG32,           // +0x19C
    pub spare_u32_75: ULONG32,           // +0x1A0
    pub spare_u32_76: ULONG32,           // +0x1A4
    pub spare_u32_77: ULONG32,           // +0x1A8
    pub spare_u32_78: ULONG32,           // +0x1AC
    pub spare_u32_79: ULONG32,           // +0x1B0
    pub spare_u32_80: ULONG32,           // +0x1B4
    pub spare_u32_81: ULONG32,           // +0x1B8
    pub spare_u32_82: ULONG32,           // +0x1BC
    pub spare_u32_83: ULONG32,           // +0x1C0
    pub spare_u32_84: ULONG32,           // +0x1C4
    pub spare_u32_85: ULONG32,           // +0x1C8
    pub spare_u32_86: ULONG32,           // +0x1CC
    pub spare_u32_87: ULONG32,           // +0x1D0
    pub spare_u32_88: ULONG32,           // +0x1D4
    pub spare_u32_89: ULONG32,           // +0x1D8
    pub spare_u32_90: ULONG32,           // +0x1DC
    pub spare_u32_91: ULONG32,           // +0x1E0
    pub spare_u32_92: ULONG32,           // +0x1E4

    // === Final field ===
    /// Spare / padding.
    pub final_spare: ULONG32,            // +0x1E8
}

// PEB32 size assertion
const _: () = assert!(
    core::mem::size_of::<Peb32>() >= 0x1E8,
    "Peb32 must be at least 0x1E8 bytes"
);

impl Peb32 {
    /// Check if process is being debugged.
    pub fn is_being_debugged(&self) -> bool {
        self.being_debugged != 0
    }

    /// Get image base address.
    pub fn image_base(&self) -> ULONG32 {
        self.image_base_address
    }

    /// Get process heap handle.
    pub fn process_heap(&self) -> ULONG32 {
        self.process_heap
    }
}

// =============================================================================
// 32-bit TEB (TEB32)
// =============================================================================

/// TEB32 - Thread Environment Block for 32-bit thread on x64 Windows.
/// Size: 0x1000 bytes (one page, 4096 bytes)
/// Reference: geoffchappell.com
///
/// The TEB is created by the kernel at thread creation and contains
/// thread-local storage, exception handling info, and thread-specific data.
#[repr(C)]
pub struct Teb32 {
    // === NT_TIB (Thread Information Block) - 0x1C bytes ===
    /// Exception list (SEH chain head).
    pub exception_list: ULONG32,          // +0x00
    /// Stack base.
    pub stack_base: ULONG32,             // +0x04
    /// Stack limit.
    pub stack_limit: ULONG32,            // +0x08
    /// Sub system TIB.
    pub sub_system_tib: ULONG32,          // +0x0C
    /// Fiber data (if fiber).
    pub fiber_data: ULONG32,             // +0x10
    /// Arbitrary user pointer.
    pub arbitrary_user_pointer: ULONG32,  // +0x14
    /// Self (pointer to this TEB).
    pub self_: ULONG32,                   // +0x18

    // === TEB Fields ===
    /// Environment pointer.
    pub environment_pointer: ULONG32,      // +0x1C
    /// Client ID (PID, TID).
    pub client_id: ClientId32,            // +0x20
    /// Active RPC handle.
    pub active_rpc_handle: ULONG32,       // +0x28
    /// Thread local storage pointer.
    pub thread_local_storage_pointer: ULONG32,  // +0x2C
    /// PEB pointer.
    pub process_environment_block: ULONG32,  // +0x30
    /// Last error code.
    pub last_error_value: ULONG32,       // +0x34
    /// Count of owned critical sections.
    pub count_of_owned_critical_sections: ULONG32,  // +0x38
    /// CSR client thread info.
    pub csr_client_thread: ULONG32,      // +0x3C
    /// Win32 thread info.
    pub win32_thread_info: ULONG32,      // +0x40
    /// User32 reserved (WOW64_FLS_DATA etc).
    pub user32_reserved: [ULONG32; 26],  // +0x44
    /// User reserved (for callbacks).
    pub user_reserved: [ULONG32; 5],    // +0xAC
    /// GS/FS register save area (padding before Wow64 state).
    pub gs_fs_register_save_area: [ULONG32; 2],  // +0xC0
    /// Wow64 reserved (context, TEB32 copy, etc).
    pub wow64_reserved: [ULONG32; 8],   // +0xC8
    /// Current locale.
    pub current_locale: ULONG32,          // +0xE8
    /// FP software status register.
    pub fp_sw_status_register: ULONG32, // +0xEC
    /// Reserved for debug (WOW64_FLOATING_POINT_AREA).
    pub floating_point_save_area: [u8; 216],  // +0xF0
    /// Exception code.
    pub exception_code: ULONG32,          // +0x1C8
    /// Spare bytes.
    pub sparc_exception_code: [u8; 36],  // +0x1CC
    /// 32 bytes quota block / user reserved.
    pub user_reserved2: [ULONG32; 8],   // +0x1F0
    /// Spare.
    pub spare_u32_1: ULONG32,            // +0x210
    /// Spare.
    pub spare_u32_2: ULONG32,            // +0x214
    /// Spare.
    pub spare_u32_3: ULONG32,            // +0x218
    /// Spare.
    pub spare_u32_4: ULONG32,            // +0x21C
    /// Spare.
    pub spare_u32_5: ULONG32,            // +0x220
    /// Spare.
    pub spare_u32_6: ULONG32,            // +0x224
    /// Spare.
    pub spare_u32_7: ULONG32,            // +0x228
    /// Spare.
    pub spare_u32_8: ULONG32,            // +0x22C
    /// Spare.
    pub spare_u32_9: ULONG32,            // +0x230
    /// Spare.
    pub spare_u32_10: ULONG32,           // +0x234
    /// Spare.
    pub spare_u32_11: ULONG32,           // +0x238
    /// Spare.
    pub spare_u32_12: ULONG32,           // +0x23C
    /// Spare.
    pub spare_u32_13: ULONG32,           // +0x240
    /// Spare.
    pub spare_u32_14: ULONG32,           // +0x244
    /// Spare.
    pub spare_u32_15: ULONG32,           // +0x248
    /// Spare.
    pub spare_u32_16: ULONG32,           // +0x24C
    /// Spare.
    pub spare_u32_17: ULONG32,           // +0x250
    /// Spare.
    pub spare_u32_18: ULONG32,           // +0x254
    /// Spare.
    pub spare_u32_19: ULONG32,           // +0x258
    /// Spare.
    pub spare_u32_20: ULONG32,           // +0x25C
    /// Spare.
    pub spare_u32_21: ULONG32,           // +0x260
    /// Spare.
    pub spare_u32_22: ULONG32,           // +0x264
    /// Spare.
    pub spare_u32_23: ULONG32,           // +0x268
    /// Spare.
    pub spare_u32_24: ULONG32,           // +0x26C
    /// Spare.
    pub spare_u32_25: ULONG32,           // +0x270
    /// Spare.
    pub spare_u32_26: ULONG32,           // +0x274
    /// Spare.
    pub spare_u32_27: ULONG32,           // +0x278
    /// Spare.
    pub spare_u32_28: ULONG32,           // +0x27C
    /// Spare.
    pub spare_u32_29: ULONG32,           // +0x280
    /// Spare.
    pub spare_u32_30: ULONG32,           // +0x284
    /// Spare.
    pub spare_u32_31: ULONG32,           // +0x288
    /// Spare.
    pub spare_u32_32: ULONG32,           // +0x28C
    /// Spare.
    pub spare_u32_33: ULONG32,           // +0x290
    /// Spare.
    pub spare_u32_34: ULONG32,           // +0x294
    /// Spare.
    pub spare_u32_35: ULONG32,           // +0x298
    /// Spare.
    pub spare_u32_36: ULONG32,           // +0x29C
    /// Spare.
    pub spare_u32_37: ULONG32,           // +0x2A0
    /// Spare.
    pub spare_u32_38: ULONG32,           // +0x2A4
    /// Spare.
    pub spare_u32_39: ULONG32,           // +0x2A8
    /// Spare.
    pub spare_u32_40: ULONG32,           // +0x2AC
    /// Spare.
    pub spare_u32_41: ULONG32,           // +0x2B0
    /// Spare.
    pub spare_u32_42: ULONG32,           // +0x2B4
    /// Spare.
    pub spare_u32_43: ULONG32,           // +0x2B8
    /// Spare.
    pub spare_u32_44: ULONG32,           // +0x2BC
    /// Spare.
    pub spare_u32_45: ULONG32,           // +0x2C0
    /// Spare.
    pub spare_u32_46: ULONG32,           // +0x2C4
    /// Spare.
    pub spare_u32_47: ULONG32,           // +0x2C8
    /// Spare.
    pub spare_u32_48: ULONG32,           // +0x2CC
    /// Spare.
    pub spare_u32_49: ULONG32,           // +0x2D0
    /// Spare.
    pub spare_u32_50: ULONG32,           // +0x2D4
    /// Spare.
    pub spare_u32_51: ULONG32,           // +0x2D8
    /// Spare.
    pub spare_u32_52: ULONG32,           // +0x2DC
    /// Spare.
    pub spare_u32_53: ULONG32,           // +0x2E0
    /// Spare.
    pub spare_u32_54: ULONG32,           // +0x2E4
    /// Spare.
    pub spare_u32_55: ULONG32,           // +0x2E8
    /// Spare.
    pub spare_u32_56: ULONG32,           // +0x2EC
    /// Spare.
    pub spare_u32_57: ULONG32,           // +0x2F0
    /// Spare.
    pub spare_u32_58: ULONG32,           // +0x2F4
    /// Spare.
    pub spare_u32_59: ULONG32,           // +0x2F8
    /// Spare.
    pub spare_u32_60: ULONG32,           // +0x2FC
    /// Spare.
    pub spare_u32_61: ULONG32,           // +0x300
    /// Spare.
    pub spare_u32_62: ULONG32,           // +0x304
    /// Spare.
    pub spare_u32_63: ULONG32,           // +0x308
    /// Spare.
    pub spare_u32_64: ULONG32,           // +0x30C
    /// Spare.
    pub spare_u32_65: ULONG32,           // +0x310
    /// Spare.
    pub spare_u32_66: ULONG32,           // +0x314
    /// Spare.
    pub spare_u32_67: ULONG32,           // +0x318
    /// Spare.
    pub spare_u32_68: ULONG32,           // +0x31C
    /// Spare.
    pub spare_u32_69: ULONG32,           // +0x320
    /// Spare.
    pub spare_u32_70: ULONG32,           // +0x324
    /// Spare.
    pub spare_u32_71: ULONG32,           // +0x328
    /// Spare.
    pub spare_u32_72: ULONG32,           // +0x32C
    /// Spare.
    pub spare_u32_73: ULONG32,           // +0x330
    /// Spare.
    pub spare_u32_74: ULONG32,           // +0x334
    /// Spare.
    pub spare_u32_75: ULONG32,           // +0x338
    /// Spare.
    pub spare_u32_76: ULONG32,           // +0x33C
    /// Spare.
    pub spare_u32_77: ULONG32,           // +0x340
    /// Spare.
    pub spare_u32_78: ULONG32,           // +0x344
    /// Spare.
    pub spare_u32_79: ULONG32,           // +0x348
    /// Spare.
    pub spare_u32_80: ULONG32,           // +0x34C
    /// Spare.
    pub spare_u32_81: ULONG32,           // +0x350
    /// Spare.
    pub spare_u32_82: ULONG32,           // +0x354
    /// Spare.
    pub spare_u32_83: ULONG32,           // +0x358
    /// Spare.
    pub spare_u32_84: ULONG32,           // +0x35C
    /// Spare.
    pub spare_u32_85: ULONG32,           // +0x360
    /// Spare.
    pub spare_u32_86: ULONG32,           // +0x364
    /// Spare.
    pub spare_u32_87: ULONG32,           // +0x368
    /// Spare.
    pub spare_u32_88: ULONG32,           // +0x36C
    /// Spare.
    pub spare_u32_89: ULONG32,           // +0x370
    /// Spare.
    pub spare_u32_90: ULONG32,           // +0x374
    /// Spare.
    pub spare_u32_91: ULONG32,           // +0x378
    /// Spare.
    pub spare_u32_92: ULONG32,           // +0x37C
    /// Spare.
    pub spare_u32_93: ULONG32,           // +0x380
    /// Spare.
    pub spare_u32_94: ULONG32,           // +0x384
    /// Spare.
    pub spare_u32_95: ULONG32,           // +0x388
    /// Spare.
    pub spare_u32_96: ULONG32,           // +0x38C
    /// Spare.
    pub spare_u32_97: ULONG32,           // +0x390
    /// Spare.
    pub spare_u32_98: ULONG32,           // +0x394
    /// Spare.
    pub spare_u32_99: ULONG32,           // +0x398
    /// Spare.
    pub spare_u32_100: ULONG32,          // +0x39C
    /// Spare.
    pub spare_u32_101: ULONG32,          // +0x3A0
    /// Spare.
    pub spare_u32_102: ULONG32,          // +0x3A4
    /// Spare.
    pub spare_u32_103: ULONG32,          // +0x3A8
    /// Spare.
    pub spare_u32_104: ULONG32,          // +0x3AC
    /// Spare.
    pub spare_u32_105: ULONG32,          // +0x3B0
    /// Spare.
    pub spare_u32_106: ULONG32,          // +0x3B4
    /// Spare.
    pub spare_u32_107: ULONG32,          // +0x3B8
    /// Spare.
    pub spare_u32_108: ULONG32,          // +0x3BC
    /// Spare.
    pub spare_u32_109: ULONG32,          // +0x3C0
    /// Spare.
    pub spare_u32_110: ULONG32,          // +0x3C4
    /// Spare.
    pub spare_u32_111: ULONG32,          // +0x3C8
    /// Spare.
    pub spare_u32_112: ULONG32,          // +0x3CC
    /// Spare.
    pub spare_u32_113: ULONG32,          // +0x3D0
    /// Spare.
    pub spare_u32_114: ULONG32,          // +0x3D4
    /// Spare.
    pub spare_u32_115: ULONG32,          // +0x3D8
    /// Spare.
    pub spare_u32_116: ULONG32,          // +0x3DC
    /// Spare.
    pub spare_u32_117: ULONG32,          // +0x3E0
    /// Spare.
    pub spare_u32_118: ULONG32,          // +0x3E4
    /// Spare.
    pub spare_u32_119: ULONG32,          // +0x3E8
    /// Spare.
    pub spare_u32_120: ULONG32,          // +0x3EC
    /// Spare.
    pub spare_u32_121: ULONG32,          // +0x3F0
    /// Spare.
    pub spare_u32_122: ULONG32,          // +0x3F4
    /// Spare.
    pub spare_u32_123: ULONG32,          // +0x3F8
    /// Spare.
    pub spare_u32_124: ULONG32,          // +0x3FC

    /// Padding to reach 0x1000 bytes (TEB is one page)
    pub _padding: [u8; 0x1000 - 0x400],
}

impl Default for Teb32 {
    fn default() -> Self {
        Self {
            exception_list: 0,
            stack_base: 0,
            stack_limit: 0,
            sub_system_tib: 0,
            fiber_data: 0,
            arbitrary_user_pointer: 0,
            self_: 0,
            environment_pointer: 0,
            client_id: ClientId32::default(),
            active_rpc_handle: 0,
            thread_local_storage_pointer: 0,
            process_environment_block: 0,
            last_error_value: 0,
            count_of_owned_critical_sections: 0,
            csr_client_thread: 0,
            win32_thread_info: 0,
            user32_reserved: [0; 26],
            user_reserved: [0; 5],
            gs_fs_register_save_area: [0; 2],
            wow64_reserved: [0; 8],
            current_locale: 0,
            fp_sw_status_register: 0,
            floating_point_save_area: [0; 216],
            exception_code: 0,
            sparc_exception_code: [0; 36],
            user_reserved2: [0; 8],
            spare_u32_1: 0,
            spare_u32_2: 0,
            spare_u32_3: 0,
            spare_u32_4: 0,
            spare_u32_5: 0,
            spare_u32_6: 0,
            spare_u32_7: 0,
            spare_u32_8: 0,
            spare_u32_9: 0,
            spare_u32_10: 0,
            spare_u32_11: 0,
            spare_u32_12: 0,
            spare_u32_13: 0,
            spare_u32_14: 0,
            spare_u32_15: 0,
            spare_u32_16: 0,
            spare_u32_17: 0,
            spare_u32_18: 0,
            spare_u32_19: 0,
            spare_u32_20: 0,
            spare_u32_21: 0,
            spare_u32_22: 0,
            spare_u32_23: 0,
            spare_u32_24: 0,
            spare_u32_25: 0,
            spare_u32_26: 0,
            spare_u32_27: 0,
            spare_u32_28: 0,
            spare_u32_29: 0,
            spare_u32_30: 0,
            spare_u32_31: 0,
            spare_u32_32: 0,
            spare_u32_33: 0,
            spare_u32_34: 0,
            spare_u32_35: 0,
            spare_u32_36: 0,
            spare_u32_37: 0,
            spare_u32_38: 0,
            spare_u32_39: 0,
            spare_u32_40: 0,
            spare_u32_41: 0,
            spare_u32_42: 0,
            spare_u32_43: 0,
            spare_u32_44: 0,
            spare_u32_45: 0,
            spare_u32_46: 0,
            spare_u32_47: 0,
            spare_u32_48: 0,
            spare_u32_49: 0,
            spare_u32_50: 0,
            spare_u32_51: 0,
            spare_u32_52: 0,
            spare_u32_53: 0,
            spare_u32_54: 0,
            spare_u32_55: 0,
            spare_u32_56: 0,
            spare_u32_57: 0,
            spare_u32_58: 0,
            spare_u32_59: 0,
            spare_u32_60: 0,
            spare_u32_61: 0,
            spare_u32_62: 0,
            spare_u32_63: 0,
            spare_u32_64: 0,
            spare_u32_65: 0,
            spare_u32_66: 0,
            spare_u32_67: 0,
            spare_u32_68: 0,
            spare_u32_69: 0,
            spare_u32_70: 0,
            spare_u32_71: 0,
            spare_u32_72: 0,
            spare_u32_73: 0,
            spare_u32_74: 0,
            spare_u32_75: 0,
            spare_u32_76: 0,
            spare_u32_77: 0,
            spare_u32_78: 0,
            spare_u32_79: 0,
            spare_u32_80: 0,
            spare_u32_81: 0,
            spare_u32_82: 0,
            spare_u32_83: 0,
            spare_u32_84: 0,
            spare_u32_85: 0,
            spare_u32_86: 0,
            spare_u32_87: 0,
            spare_u32_88: 0,
            spare_u32_89: 0,
            spare_u32_90: 0,
            spare_u32_91: 0,
            spare_u32_92: 0,
            spare_u32_93: 0,
            spare_u32_94: 0,
            spare_u32_95: 0,
            spare_u32_96: 0,
            spare_u32_97: 0,
            spare_u32_98: 0,
            spare_u32_99: 0,
            spare_u32_100: 0,
            spare_u32_101: 0,
            spare_u32_102: 0,
            spare_u32_103: 0,
            spare_u32_104: 0,
            spare_u32_105: 0,
            spare_u32_106: 0,
            spare_u32_107: 0,
            spare_u32_108: 0,
            spare_u32_109: 0,
            spare_u32_110: 0,
            spare_u32_111: 0,
            spare_u32_112: 0,
            spare_u32_113: 0,
            spare_u32_114: 0,
            spare_u32_115: 0,
            spare_u32_116: 0,
            spare_u32_117: 0,
            spare_u32_118: 0,
            spare_u32_119: 0,
            spare_u32_120: 0,
            spare_u32_121: 0,
            spare_u32_122: 0,
            spare_u32_123: 0,
            spare_u32_124: 0,
            _padding: [0; 0x1000 - 0x400],
        }
    }
}

// TEB32 size assertion
const _: () = assert!(
    core::mem::size_of::<Teb32>() >= 0x1000,
    "Teb32 must be at least 0x1000 bytes (one page)"
);

impl Teb32 {
    /// Get the current TEB32 pointer.
    /// On x86 this reads fs:[0x18].
    /// On x64 this must be obtained through the Wow64 layer.
    pub unsafe fn get_current() -> *mut Teb32 {
        null_mut() // TODO: Implement through Wow64Pcrb or similar
    }

    /// Get PEB32 pointer from TEB32.
    pub fn peb32(&self) -> *mut Peb32 {
        self.process_environment_block as *mut Peb32
    }

    /// Get stack base.
    pub fn stack_base(&self) -> ULONG32 {
        self.stack_base
    }

    /// Get stack limit.
    pub fn stack_limit(&self) -> ULONG32 {
        self.stack_limit
    }
}

// =============================================================================
// Exception Record 32 (EXCEPTION_RECORD32)
// =============================================================================

/// EXCEPTION_RECORD32 - 32-bit exception record.
/// Used for exception handling in 32-bit code.
#[repr(C)]
#[derive(Default)]
pub struct ExceptionRecord32 {
    /// Exception code.
    pub exception_code: ULONG32,
    /// Exception flags.
    pub exception_flags: ULONG32,
    /// Exception record pointer (nested exceptions).
    pub exception_record: ULONG32,
    /// Exception address.
    pub exception_address: ULONG32,
    /// Number of parameters.
    pub number_parameters: ULONG32,
    /// Exception information (array of 15 u32).
    pub exception_information: [ULONG32; 15],
}

// Exception flags
pub mod exception_flags {
    use super::ULONG32;
    pub const EXCEPTION_CONTINUABLE: ULONG32 = 0x00000000;
    pub const EXCEPTION_NONCONTINUABLE: ULONG32 = 0x00000001;
    pub const EXCEPTION_UNWINDING: ULONG32 = 0x00000002;
    pub const EXCEPTION_EXIT_UNWIND: ULONG32 = 0x00000004;
    pub const EXCEPTION_STACK_INVALID: ULONG32 = 0x00000008;
    pub const EXCEPTION_NESTED_CALL: ULONG32 = 0x00000010;
    pub const EXCEPTION_TARGET_UNWIND: ULONG32 = 0x00000020;
    pub const EXCEPTION_COLLIDED_UNWIND: ULONG32 = 0x00000040;
}

// =============================================================================
// KAPC32 (32-bit APC)
// =============================================================================

/// KAPC32 - 32-bit Asynchronous Procedure Call.
/// Used for APC queuing to 32-bit threads.
#[repr(C)]
#[derive(Default)]
pub struct Kapc32 {
    /// Type (must be ApcObject).
    pub type_: u16,            // +0x00
    /// Size.
    pub size: u16,            // +0x02
    /// Spare.
    pub spare0: u8,           // +0x04
    /// Spare.
    pub spare1: u8,           // +0x05
    /// Spare.
    pub spare2: u8,           // +0x06
    /// Inserted (in queue flag).
    pub inserted: u8,          // +0x07
    /// Spare/KSPIN_LOCK.
    pub spare_lock: ULONG32,   // +0x08
    /// Thread (ETHREAD*).
    pub thread: ULONG32,       // +0x0C
    /// APC list entry (LIST_ENTRY32).
    pub apc_list_entry: ListEntry32,  // +0x14
    /// Kernel routine.
    pub kernel_routine: ULONG32,  // +0x1C
    /// Rundown routine.
    pub rundown_routine: ULONG32,  // +0x20
    /// Normal routine.
    pub normal_routine: ULONG32,  // +0x24
    /// Normal context.
    pub normal_context: ULONG32,  // +0x28
    /// System argument 1.
    pub system_argument1: ULONG32,  // +0x2C
    /// System argument 2.
    pub system_argument2: ULONG32,  // +0x30
    /// APC environment index.
    pub apc_environment: u8,  // +0x34
    /// APC mode (Kernel/User).
    pub apc_mode: u8,       // +0x35
    /// Inserted (in progress flag).
    pub inserted_byte: u8,   // +0x36
    /// Spare.
    pub spare3: u8,          // +0x37
}

// =============================================================================
// PROCESS_INFORMATION_CLASS32 (Wow64)
// =============================================================================

/// PROCESSINFOCLASS32 - 32-bit process information classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProcessInformationClass32 {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledQuotaUsage = 14,
    ProcessPooledQuotaLimits = 15,
    ProcessHardErrorMode = 16,
    ProcessNull = 17,
    ProcessIoPriority = 18,
    ProcessExecutionPriority = 19,
    ProcessAffinityMask = 20,
    ProcessPriorityClass = 21,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
}

// =============================================================================
// THREAD_INFORMATION_CLASS32 (Wow64)
// =============================================================================

/// THREADINFOCLASS32 - 32-bit thread information classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ThreadInformationClass32 {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadExceptionPort = 8,
    ThreadPlatformFamily = 9,
    ThreadWow64State = 11,
    ThreadIsTerminated = 12,
}

// =============================================================================
// Wow64 Function Result Type
// =============================================================================

/// Result type for Wow64 operations.
pub type Wow64Result<T> = Result<T, ULONG32>;

// =============================================================================
// Pointer Conversion Functions
// =============================================================================

/// `Ptr32ToPtr` — convert a 32-bit pointer value to a 64-bit
/// pointer value. In WoW64 this re-maps the 32-bit address
/// space into the lower 4 GB; for the stub we just zero-extend.
pub fn ptr32_to_ptr(p: ULONG32) -> u64 {
    p as u64
}

/// `PtrToPtr32` — convert a 64-bit pointer value to a 32-bit
/// pointer value. Truncation is the caller's responsibility.
pub fn ptr_to_ptr32(p: u64) -> ULONG32 {
    (p & 0xFFFF_FFFF) as u32
}

/// `UShortTo32` — pass-through helper.
pub fn ushort_to32(v: USHORT16) -> ULONG32 {
    v as ULONG32
}

/// `ULongTo64` — extend 32-bit to 64-bit unsigned.
pub fn ulong_to64(v: ULONG32) -> u64 {
    v as u64
}

/// `LongTo64` — sign-extend 32-bit to 64-bit signed.
pub fn long_to64(v: i32) -> i64 {
    v as i64
}

// =============================================================================
// Safe Pointer Validation
// =============================================================================

/// Check if a 32-bit address is in the valid Wow64 user range.
pub fn is_valid_wow64_user_address(addr: ULONG32) -> bool {
    addr >= WOW64_USER_SPACE_START && addr <= WOW64_USER_SPACE_END
}

/// Check if a 32-bit address range is valid.
pub fn is_valid_wow64_range(addr: ULONG32, size: ULONG32) -> bool {
    if addr == 0 {
        return false;
    }
    // Check for overflow
    let end = addr.checked_add(size);
    if end.is_none() {
        return false;
    }
    let end = end.unwrap();
    is_valid_wow64_user_address(addr) && end <= (WOW64_USER_SPACE_END + 1)
}

// =============================================================================
// Context Conversion Helpers
// =============================================================================

/// Convert a 64-bit context pointer to a 32-bit context.
/// This copies the relevant fields from the 64-bit KthreadContext into
/// a newly created CONTEXT32 structure.
pub unsafe fn context64_to_context32(
    ctx64: &crate::ps::thread::KthreadContext,
    ctx32: &mut Context32,
) {
    // Copy integer registers
    ctx32.eax = ctx64.rax as u32;
    ctx32.ebx = ctx64.rbx as u32;
    ctx32.ecx = ctx64.rcx as u32;
    ctx32.edx = ctx64.rdx as u32;
    ctx32.esi = ctx64.rsi as u32;
    ctx32.edi = ctx64.rdi as u32;
    ctx32.ebp = ctx64.rbp as u32;
    ctx32.esp = ctx64.rsp as u32;
    ctx32.eip = ctx64.rip as u32;
    ctx32.eflags = ctx64.rflags as u32;

    // Copy segment registers (would need actual segment values)
    ctx32.cs = 0x23;  // USER_CS equivalent
    ctx32.ss = 0x2B;  // USER_SS equivalent
    ctx32.ds = 0;
    ctx32.es = 0;
    ctx32.fs = 0;
    ctx32.gs = 0;

    // Set context flags to indicate full context
    ctx32.context_flags = Context32::CONTEXT_FULL;
}

/// Convert a 32-bit context to a 64-bit context.
/// This copies the 32-bit register values into the 64-bit KthreadContext.
pub unsafe fn context32_to_context64(
    ctx32: &Context32,
    ctx64: &mut crate::ps::thread::KthreadContext,
) {
    // Copy integer registers
    ctx64.rax = ctx32.eax as u64;
    ctx64.rbx = ctx32.ebx as u64;
    ctx64.rcx = ctx32.ecx as u64;
    ctx64.rdx = ctx32.edx as u64;
    ctx64.rsi = ctx32.esi as u64;
    ctx64.rdi = ctx32.edi as u64;
    ctx64.rbp = ctx32.ebp as u64;
    ctx64.rsp = ctx32.esp as u64;
    ctx64.rip = ctx32.eip as u64;
    ctx64.rflags = ctx32.eflags as u64;
}

// =============================================================================
// Wow64 Information Accessors
// =============================================================================

/// Get the PEB32 virtual address constant.
/// This is where Windows 7 x86 PEBs are located in a Wow64 process.
pub const fn get_peb32_address() -> ULONG32 {
    PEB32_VIRTUAL_ADDRESS
}

/// Get the TEB32 base address constant.
pub const fn get_teb32_base_address() -> ULONG32 {
    TEB32_BASE_ADDRESS
}
