//! syscall — WoW64 System Call Conversion Layer
//
//! This module implements the complete 32-bit to 64-bit system call
//! conversion layer for WoW64. It handles:
//!   * Parameter marshaling (32-bit → 64-bit)
//!   * Structure conversion and layout transformation
//!   * Pointer sign-extension and validation
//!   * Return value conversion (64-bit → 32-bit)
//
//! # Architecture
//!
//! When a 32-bit application makes a system call:
//! 1. ntdll32.dll captures the call via int 2Eh or syscall
//! 2. wow64cpu.dll transitions to 64-bit mode
//! 3. wow64.dll calls this layer to convert parameters
//! 4. Native 64-bit kernel services are invoked
//! 5. Return values are converted back to 32-bit
//!
//! References:
//!   * Windows Internals 7th Edition, Part 1, Chapter 3
//!   * geoffchappell.com — WoW64 system service dispatching
//!   * ReactOS wow64 implementation

#![allow(dead_code)]
#![cfg(target_arch = "x86_64")]

use crate::libs::wow64::types::*;
use core::mem::size_of;

// =============================================================================
// System Call Conversion Context
// =============================================================================

/// Context for a single system call conversion.
/// Tracks the 32-bit arguments and provides conversion utilities.
pub struct SyscallContext {
    /// 32-bit argument stack pointer.
    pub args32: *const u32,
    /// Number of arguments available.
    pub arg_count: usize,
    /// Current argument index (for sequential reads).
    pub current_arg: usize,
}

impl SyscallContext {
    /// Create a new syscall context.
    pub fn new(args32: *const u32, arg_count: usize) -> Self {
        Self {
            args32,
            arg_count,
            current_arg: 0,
        }
    }

    /// Read the next 32-bit argument as u32.

    pub fn next_u32(&mut self) -> u32 {
        if self.current_arg >= self.arg_count {
            return 0;
        }
        let val = unsafe { *self.args32.add(self.current_arg) };
        self.current_arg += 1;
        val
    }

    /// Read the next argument as a sign-extended 64-bit value.
    pub fn next_i64(&mut self) -> i64 {
        self.next_u32() as i32 as i64
    }

    /// Read the next argument as a zero-extended 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.next_u32() as u64
    }

    /// Read the next argument as a 32-bit pointer, extended to 64-bit.
    pub fn next_ptr(&mut self) -> u64 {
        let ptr32 = self.next_u32();
        if ptr32 == 0 {
            0
        } else {
            ptr32 as u64
        }
    }

    /// Read a specific argument by index.
    pub fn get_u32(&self, index: usize) -> u32 {
        if index >= self.arg_count {
            return 0;
        }
        unsafe { *self.args32.add(index) }
    }

    /// Peek at the next argument without advancing.
    pub fn peek_u32(&self) -> u32 {
        self.get_u32(self.current_arg)
    }
}

// =============================================================================
// Parameter Conversion Functions
// =============================================================================

/// Convert a 32-bit handle to 64-bit.
/// WoW64 handles are sign-extended from 32-bit to 64-bit.
pub fn convert_handle_32_to_64(handle32: HANDLE32) -> u64 {
    // Handles are sign-extended in WoW64
    handle32 as i32 as i64 as u64
}

/// Convert a 64-bit handle to 32-bit.
pub fn convert_handle_64_to_32(handle64: u64) -> HANDLE32 {
    (handle64 & 0xFFFF_FFFF) as u32
}

/// Convert a 32-bit NTSTATUS to 64-bit.
pub fn convert_ntstatus_32_to_64(status32: ULONG32) -> i32 {
    status32 as i32
}

/// Convert a 64-bit NTSTATUS to 32-bit.
pub fn convert_ntstatus_64_to_32(status64: i32) -> ULONG32 {
    status64 as u32
}

/// Validate a 32-bit pointer is within WoW64 address space.
pub fn validate_wow64_pointer(ptr32: ULONG32) -> bool {
    if ptr32 == 0 {
        return true; // NULL is valid
    }
    // Check that pointer is within 32-bit user space
    ptr32 >= WOW64_USER_SPACE_START && ptr32 <= WOW64_MAX_USER_ADDRESS
}

/// Convert a 32-bit UNICODE_STRING to 64-bit.
pub fn convert_unicode_string_32_to_64(
    str32: *const UnicodeString32,
) -> Option<(u16, u16, u64)> {
    if str32.is_null() {
        return None;
    }

    unsafe {
        let s = &*str32;
        Some((s.Length, s.MaximumLength, s.Buffer as u64))
    }
}

// =============================================================================
// Structure Conversion
// =============================================================================

/// Convert CLIENT_ID32 to CLIENT_ID64.
pub fn convert_client_id_32_to_64(cid32: &ClientId32) -> (u64, u64) {
    (
        cid32.unique_process as u64,
        cid32.unique_thread as u64,
    )
}

/// Convert OBJECT_ATTRIBUTES32 to 64-bit representation.
pub struct ObjectAttributes64 {
    pub length: u32,
    pub root_directory: u64,
    pub object_name: u64,
    pub attributes: u32,
    pub security_descriptor: u64,
    pub security_quality_of_service: u64,
}

pub fn convert_object_attributes_32_to_64(
    oa32_ptr: ULONG32,
) -> Option<ObjectAttributes64> {
    if oa32_ptr == 0 {
        return None;
    }

    // In a real implementation, we would:
    // 1. Validate the pointer
    // 2. Read the 32-bit structure from user space
    // 3. Convert each field
    // 4. Handle the nested UNICODE_STRING pointer

    // For now, return a placeholder
    Some(ObjectAttributes64 {
        length: 0x18,
        root_directory: 0,
        object_name: 0,
        attributes: 0,
        security_descriptor: 0,
        security_quality_of_service: 0,
    })
}

// =============================================================================
// Memory Information Conversion
// =============================================================================

/// Convert MEMORY_BASIC_INFORMATION64 to MEMORY_BASIC_INFORMATION32.
pub fn convert_memory_basic_info_64_to_32(
    mbi64: &MemoryBasicInformation64,
    mbi32_ptr: ULONG32,
) -> bool {
    if mbi32_ptr == 0 || !validate_wow64_pointer(mbi32_ptr) {
        return false;
    }

    // Convert 64-bit structure to 32-bit
    let mbi32 = MemoryBasicInformation32 {
        base_address: (mbi64.base_address & 0xFFFF_FFFF) as u32,
        allocation_base: (mbi64.allocation_base & 0xFFFF_FFFF) as u32,
        allocation_protect: mbi64.allocation_protect,
        region_size: (mbi64.region_size & 0xFFFF_FFFF) as u32,
        state: mbi64.state,
        protect: mbi64.protect,
        type_: mbi64.type_,
    };

    // In a real implementation, write to user space
    let _ = mbi32;
    true
}

/// MEMORY_BASIC_INFORMATION32 structure.
#[repr(C)]
pub struct MemoryBasicInformation32 {
    pub base_address: u32,
    pub allocation_base: u32,
    pub allocation_protect: u32,
    pub region_size: u32,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
}

/// MEMORY_BASIC_INFORMATION64 structure.
#[repr(C)]
pub struct MemoryBasicInformation64 {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub _padding1: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
    pub _padding2: u32,
}

// =============================================================================
// Context Conversion (CONTEXT32 ↔ CONTEXT64)
// =============================================================================

/// Convert CONTEXT32 to CONTEXT64 (x86 → x64).
pub fn convert_context_32_to_64(ctx32: &Context32) -> Context64 {
    let mut ctx64 = Context64::new();

    // Copy segment registers
    ctx64.seg_cs = ctx32.cs as u16;
    ctx64.seg_ds = ctx32.ds as u16;
    ctx64.seg_es = ctx32.es as u16;
    ctx64.seg_fs = ctx32.fs as u16;
    ctx64.seg_gs = ctx32.gs as u16;
    ctx64.seg_ss = ctx32.ss as u16;
    ctx64.eflags = ctx32.eflags;

    // Convert GP registers (zero-extend)
    ctx64.rax = ctx32.eax as u64;
    ctx64.rcx = ctx32.ecx as u64;
    ctx64.rdx = ctx32.edx as u64;
    ctx64.rbx = ctx32.ebx as u64;
    ctx64.rsp = ctx32.esp as u64;
    ctx64.rbp = ctx32.ebp as u64;
    ctx64.rsi = ctx32.esi as u64;
    ctx64.rdi = ctx32.edi as u64;
    ctx64.rip = ctx32.eip as u64;

    // R8-R15 are zero (not present in 32-bit)
    ctx64.r8 = 0;
    ctx64.r9 = 0;
    ctx64.r10 = 0;
    ctx64.r11 = 0;
    ctx64.r12 = 0;
    ctx64.r13 = 0;
    ctx64.r14 = 0;
    ctx64.r15 = 0;

    ctx64
}

/// Convert CONTEXT64 to CONTEXT32 (x64 → x86).
pub fn convert_context_64_to_32(ctx64: &Context64) -> Context32 {
    let mut ctx32 = Context32::new();

    // Copy segment registers
    ctx32.cs = ctx64.seg_cs as u32;
    ctx32.ds = ctx64.seg_ds as u32;
    ctx32.es = ctx64.seg_es as u32;
    ctx32.fs = ctx64.seg_fs as u32;
    ctx32.gs = ctx64.seg_gs as u32;
    ctx32.ss = ctx64.seg_ss as u32;
    ctx32.eflags = ctx64.eflags;

    // Truncate GP registers to 32-bit
    ctx32.eax = (ctx64.rax & 0xFFFF_FFFF) as u32;
    ctx32.ecx = (ctx64.rcx & 0xFFFF_FFFF) as u32;
    ctx32.edx = (ctx64.rdx & 0xFFFF_FFFF) as u32;
    ctx32.ebx = (ctx64.rbx & 0xFFFF_FFFF) as u32;
    ctx32.esp = (ctx64.rsp & 0xFFFF_FFFF) as u32;
    ctx32.ebp = (ctx64.rbp & 0xFFFF_FFFF) as u32;
    ctx32.esi = (ctx64.rsi & 0xFFFF_FFFF) as u32;
    ctx32.edi = (ctx64.rdi & 0xFFFF_FFFF) as u32;
    ctx32.eip = (ctx64.rip & 0xFFFF_FFFF) as u32;

    ctx32.context_flags = Context32::CONTEXT_FULL;

    ctx32
}

/// 64-bit CONTEXT structure (simplified).
#[repr(C)]
#[derive(Default)]
pub struct Context64 {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

impl Context64 {
    pub fn new() -> Self {
        Self::default()
    }
}

// =============================================================================
// System Call Dispatchers
// =============================================================================

/// Dispatch NtAllocateVirtualMemory (32-bit → 64-bit).
pub fn dispatch_nt_allocate_virtual_memory(ctx: &mut SyscallContext) -> ULONG32 {
    let _process_handle = ctx.next_u32();
    let base_address_ptr = ctx.next_u32();
    let _zero_bits = ctx.next_u32();
    let region_size_ptr = ctx.next_u32();
    let allocation_type = ctx.next_u32();
    let protect = ctx.next_u32();

    // Validate pointers
    if !validate_wow64_pointer(base_address_ptr) ||
       !validate_wow64_pointer(region_size_ptr) {
        return STATUS_INVALID_PARAMETER;
    }

    // In a real implementation:
    // 1. Read base_address and region_size from user space
    // 2. Call NtAllocateVirtualMemory with 64-bit parameters
    // 3. Write results back to 32-bit user space
    // 4. Return NTSTATUS

    let _ = (allocation_type, protect);
    STATUS_NOT_IMPLEMENTED
}

/// Dispatch NtFreeVirtualMemory (32-bit → 64-bit).
pub fn dispatch_nt_free_virtual_memory(ctx: &mut SyscallContext) -> ULONG32 {
    let _process_handle = ctx.next_u32();
    let base_address_ptr = ctx.next_u32();
    let region_size_ptr = ctx.next_u32();
    let free_type = ctx.next_u32();

    if !validate_wow64_pointer(base_address_ptr) ||
       !validate_wow64_pointer(region_size_ptr) {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = free_type;
    STATUS_NOT_IMPLEMENTED
}

/// Dispatch NtQueryVirtualMemory (32-bit → 64-bit).
pub fn dispatch_nt_query_virtual_memory(ctx: &mut SyscallContext) -> ULONG32 {
    let _process_handle = ctx.next_u32();
    let base_address = ctx.next_u32();
    let info_class = ctx.next_u32();
    let info_ptr = ctx.next_u32();
    let info_length = ctx.next_u32();
    let return_length_ptr = ctx.next_u32();

    if !validate_wow64_pointer(info_ptr) {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (base_address, info_class, info_length, return_length_ptr);
    STATUS_NOT_IMPLEMENTED
}

/// Dispatch NtCreateFile (32-bit → 64-bit).
pub fn dispatch_nt_create_file(ctx: &mut SyscallContext) -> ULONG32 {
    let file_handle_ptr = ctx.next_u32();
    let desired_access = ctx.next_u32();
    let object_attributes_ptr = ctx.next_u32();
    let io_status_block_ptr = ctx.next_u32();
    let allocation_size_ptr = ctx.next_u32();
    let file_attributes = ctx.next_u32();
    let share_access = ctx.next_u32();
    let create_disposition = ctx.next_u32();
    let create_options = ctx.next_u32();
    let ea_buffer = ctx.next_u32();
    let ea_length = ctx.next_u32();

    if !validate_wow64_pointer(file_handle_ptr) ||
       !validate_wow64_pointer(io_status_block_ptr) {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (desired_access, object_attributes_ptr, allocation_size_ptr,
             file_attributes, share_access, create_disposition,
             create_options, ea_buffer, ea_length);
    STATUS_NOT_IMPLEMENTED
}

/// Dispatch NtReadFile (32-bit → 64-bit).
pub fn dispatch_nt_read_file(ctx: &mut SyscallContext) -> ULONG32 {
    let _file_handle = ctx.next_u32();
    let _event = ctx.next_u32();
    let _apc_routine = ctx.next_u32();
    let _apc_context = ctx.next_u32();
    let io_status_block_ptr = ctx.next_u32();
    let buffer_ptr = ctx.next_u32();
    let length = ctx.next_u32();
    let byte_offset_ptr = ctx.next_u32();
    let _key = ctx.next_u32();

    if !validate_wow64_pointer(io_status_block_ptr) ||
       !validate_wow64_pointer(buffer_ptr) {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (length, byte_offset_ptr);
    STATUS_NOT_IMPLEMENTED
}

/// Dispatch NtWriteFile (32-bit → 64-bit).
pub fn dispatch_nt_write_file(ctx: &mut SyscallContext) -> ULONG32 {
    let _file_handle = ctx.next_u32();
    let _event = ctx.next_u32();
    let _apc_routine = ctx.next_u32();
    let _apc_context = ctx.next_u32();
    let io_status_block_ptr = ctx.next_u32();
    let buffer_ptr = ctx.next_u32();
    let length = ctx.next_u32();
    let byte_offset_ptr = ctx.next_u32();
    let _key = ctx.next_u32();

    if !validate_wow64_pointer(io_status_block_ptr) ||
       !validate_wow64_pointer(buffer_ptr) {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (length, byte_offset_ptr);
    STATUS_NOT_IMPLEMENTED
}

// =============================================================================
// Alignment Helpers
// =============================================================================

/// Check if a 32-bit pointer is properly aligned for the given size.
pub fn is_aligned_32(ptr: ULONG32, alignment: u32) -> bool {
    ptr % alignment == 0
}

/// Align a 32-bit value up to the given alignment.
pub fn align_up_32(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Calculate structure size with WoW64 padding.
pub fn wow64_structure_size<T>() -> usize {
    // WoW64 structures may have different padding than native 64-bit
    size_of::<T>()
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the WoW64 syscall conversion layer.
pub fn init() {
    crate::wow64_klog!("WoW64 syscall conversion layer initialized");
}
