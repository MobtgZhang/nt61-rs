//! mem_thunk — Wow64 Memory Management Thunks
//
//! This module implements the memory management thunks that translate
//! 32-bit virtual memory operations to their 64-bit equivalents.
//
//! The key functions are:
//!   * Wow64AllocateVirtualMemory32
//!   * Wow64FreeVirtualMemory32
//!   * Wow64ProtectVirtualMemory32
//!   * Wow64QueryVirtualMemory32
//!   * Wow64ReadVirtualMemory32
//!   * Wow64WriteVirtualMemory32
//
//! References:
//!   * geoffchappell.com — wow64 memory management

use crate::libs::wow64::types::*;
use crate::libs::wow64::wow64vas;

// =============================================================================
// Wow64AllocateVirtualMemory32
// =============================================================================

/// Allocate virtual memory in a 32-bit process.
///
/// This is the Wow64 equivalent of NtAllocateVirtualMemory for 32-bit
/// processes. It allocates memory in the lower 4GB address space.
///
/// # Arguments
/// * `process_handle` - Handle to the target process (can be NtCurrentProcess)
/// * `base_address` - Pointer to base address (input/output)
/// * `zero_bits` - Zero bits for address hint
/// * `region_size` - Pointer to region size (input/output)
/// * `allocation_type` - MEM_COMMIT, MEM_RESERVE, etc.
/// * `protect` - Page protection (PAGE_READWRITE, etc.)
///
/// # Returns
/// * NTSTATUS
///
/// # Safety
/// This function manipulates process address spaces.
pub unsafe extern "C" fn Wow64AllocateVirtualMemory32(
    process_handle: HANDLE32,
    base_address: ULONG32_PTR,
    zero_bits: ULONG32,
    region_size: ULONG32,
    allocation_type: ULONG32,
    protect: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64AllocateVirtualMemory32 handle=0x{:08x} base_ptr=0x{:08x} \
         size=0x{:08x} type=0x{:08x} prot=0x{:02x} zb={:#x}",
        process_handle, base_address, region_size,
        allocation_type, protect, zero_bits
    );
    let _ = zero_bits;

    // Get the requested base address (if any)
    let requested_base = if base_address != 0 {
        // Would read from base_address pointer in real implementation
        0
    } else {
        0 // Let the allocator choose
    };

    // Validate allocation type
    if allocation_type == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate protection
    if !is_valid_protection(protect) {
        crate::wow64_klog!("Invalid protection 0x{:02x}", protect);
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate through the Wow64 VAS
    match wow64vas::allocate(
        region_size,
        wow64vas::WOW64_ALLOCATION_GRANULARITY,
        requested_base,
        allocation_type,
        protect,
    ) {
        Some((allocated_base, allocated_size)) => {
            crate::wow64_klog!(
                "Allocated base=0x{:08x} size=0x{:08x}",
                allocated_base, allocated_size
            );

            // Write results back
            // In real implementation: write to base_address and region_size pointers
            let _ = (allocated_base, allocated_size);
            STATUS_SUCCESS
        }
        None => {
            STATUS_NO_MEMORY
        }
    }
}

// =============================================================================
// Wow64FreeVirtualMemory32
// =============================================================================

/// Free virtual memory in a 32-bit process.
///
/// # Arguments
/// * `process_handle` - Handle to the target process
/// * `base_address` - Base address to free
/// * `region_size` - Pointer to region size (output)
/// * `free_type` - MEM_DECOMMIT or MEM_RELEASE
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64FreeVirtualMemory32(
    process_handle: HANDLE32,
    base_address: ULONG32,
    region_size: ULONG32_PTR,
    free_type: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64FreeVirtualMemory32 handle=0x{:08x} addr=0x{:08x} \
         size_ptr=0x{:08x} type=0x{:08x}",
        process_handle, base_address, region_size, free_type
    );

    // Validate free type
    match free_type {
        memory_allocation_type::MEM_RELEASE | memory_allocation_type::MEM_DECOMMIT => {}
        _ => {
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Validate address
    if !wow64vas::is_valid_user_range(base_address, region_size) {
        return STATUS_ACCESS_DENIED;
    }

    // Free through the Wow64 VAS
    if wow64vas::free(base_address, region_size) {
        // Write actual freed size back
        // In real implementation: write to region_size pointer
        STATUS_SUCCESS
    } else {
        STATUS_UNSUCCESSFUL
    }
}

// =============================================================================
// Wow64ProtectVirtualMemory32
// =============================================================================

/// Change the protection on a region of memory.
///
/// # Arguments
/// * `process_handle` - Handle to the target process
/// * `base_address` - Pointer to base address (input/output)
/// * `region_size` - Pointer to region size (input/output)
/// * `new_protect` - New protection value
/// * `old_protect` - Pointer to old protection (output)
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64ProtectVirtualMemory32(
    process_handle: HANDLE32,
    base_address: ULONG32_PTR,
    region_size: ULONG32_PTR,
    new_protect: ULONG32,
    old_protect: ULONG32_PTR,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64ProtectVirtualMemory32 handle=0x{:08x} base_ptr=0x{:08x} \
         size_ptr=0x{:08x} prot=0x{:02x} old_ptr=0x{:08x}",
        process_handle, base_address, region_size, new_protect, old_protect
    );

    // Get base address and size
    // In real implementation: read from base_address and region_size pointers
    let base = 0;
    let size = 0;

    // Validate protection
    if !is_valid_protection(new_protect) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate range
    if !wow64vas::is_valid_user_range(base, size) {
        return STATUS_INVALID_PARAMETER;
    }

    // In real implementation: call 64-bit NtProtectVirtualMemory
    // and translate the result

    STATUS_SUCCESS
}

// =============================================================================
// Wow64QueryVirtualMemory32
// =============================================================================

/// Query information about a region of virtual memory.
///
/// # Arguments
/// * `process_handle` - Handle to the target process
/// * `base_address` - Base address to query
/// * `memory_info_class` - Type of information to query
/// * `buffer` - Output buffer
/// * `buffer_size` - Size of output buffer
/// * `return_length` - Actual size needed (output)
///
/// # Returns
/// * NTSTATUS
///
/// # Info Classes
/// * 0 - MemoryBasicInformation
/// * 1 - MemoryWorkingSetList
/// * 2 - MemorySectionName
/// * etc.
pub unsafe extern "C" fn Wow64QueryVirtualMemory32(
    process_handle: HANDLE32,
    base_address: ULONG32,
    memory_info_class: ULONG32,
    buffer: ULONG32,
    buffer_size: ULONG32,
    return_length: ULONG32_PTR,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64QueryVirtualMemory32 handle=0x{:08x} addr=0x{:08x} \
         class={} buf=0x{:08x} sz={} retlen_ptr=0x{:08x}",
        process_handle, base_address, memory_info_class,
        buffer, buffer_size, return_length
    );

    // Validate buffer
    if buffer == 0
        || buffer_size < core::mem::size_of::<Wow64MemoryBasicInformation32>() as u32
    {
        if return_length != 0 {
            // Would write required size
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Validate address
    if !wow64vas::is_valid_user_address(base_address) {
        return STATUS_INVALID_PARAMETER;
    }

    match memory_info_class {
        0 => {
            // MemoryBasicInformation
            if let Some(info) = wow64vas::query(base_address) {
                // Copy to 32-bit buffer
                crate::wow64_klog!(
                    "MemoryBasicInformation base=0x{:08x} \
                     size=0x{:08x} state=0x{:08x}",
                    info.base_address, info.region_size, info.state
                );
                // In real implementation: copy info to buffer
                STATUS_SUCCESS
            } else {
                STATUS_UNSUCCESSFUL
            }
        }
        _ => {
            crate::wow64_klog!("Unsupported memory info class {}", memory_info_class);
            STATUS_INVALID_PARAMETER
        }
    }
}

// =============================================================================
// Wow64ReadVirtualMemory32
// =============================================================================

/// Read memory from another process.
///
/// # Arguments
/// * `process_handle` - Handle to the source process
/// * `base_address` - Address to read from
/// * `buffer` - Local buffer to read into (32-bit address)
/// * `size` - Number of bytes to read
/// * `number_of_bytes_read` - Number of bytes actually read (output)
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64ReadVirtualMemory32(
    process_handle: HANDLE32,
    base_address: ULONG32,
    buffer: ULONG32,
    size: ULONG32,
    number_of_bytes_read: ULONG32_PTR,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64ReadVirtualMemory32 handle=0x{:08x} from=0x{:08x} \
         to=0x{:08x} size=0x{:08x} bytes_read_ptr=0x{:08x}",
        process_handle, base_address, buffer, size, number_of_bytes_read
    );

    // Validate ranges
    if !wow64vas::is_valid_user_range(base_address, size) {
        return STATUS_ACCESS_DENIED;
    }
    if !wow64vas::is_valid_user_range(buffer, size) {
        return STATUS_ACCESS_DENIED;
    }

    // Use the VAS read function
    match wow64vas::read_memory(process_handle, base_address, buffer, size) {
        Ok(bytes_read) => {
            if number_of_bytes_read != 0 {
                // Would write to number_of_bytes_read
            }
            let _ = bytes_read;
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

// =============================================================================
// Wow64WriteVirtualMemory32
// =============================================================================

/// Write memory to another process.
///
/// # Arguments
/// * `process_handle` - Handle to the target process
/// * `base_address` - Address to write to
/// * `buffer` - Local buffer to write from (32-bit address)
/// * `size` - Number of bytes to write
/// * `number_of_bytes_written` - Number of bytes actually written (output)
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64WriteVirtualMemory32(
    process_handle: HANDLE32,
    base_address: ULONG32,
    buffer: ULONG32,
    size: ULONG32,
    number_of_bytes_written: ULONG32_PTR,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64WriteVirtualMemory32 handle=0x{:08x} to=0x{:08x} \
         from=0x{:08x} size=0x{:08x} bytes_written_ptr=0x{:08x}",
        process_handle, base_address, buffer, size, number_of_bytes_written
    );

    // Validate ranges
    if !wow64vas::is_valid_user_range(base_address, size) {
        return STATUS_ACCESS_DENIED;
    }
    if !wow64vas::is_valid_user_range(buffer, size) {
        return STATUS_ACCESS_DENIED;
    }

    // Use the VAS write function
    match wow64vas::write_memory(process_handle, base_address, buffer, size) {
        Ok(bytes_written) => {
            if number_of_bytes_written != 0 {
                // Would write to number_of_bytes_written
            }
            let _ = bytes_written;
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Validate a memory protection value.
fn is_valid_protection(protect: ULONG32) -> bool {
    match protect {
        memory_protect::PAGE_NOACCESS
        | memory_protect::PAGE_READONLY
        | memory_protect::PAGE_READWRITE
        | memory_protect::PAGE_WRITECOPY
        | memory_protect::PAGE_EXECUTE
        | memory_protect::PAGE_EXECUTE_READ
        | memory_protect::PAGE_EXECUTE_READWRITE
        | memory_protect::PAGE_EXECUTE_WRITECOPY
        | memory_protect::PAGE_GUARD
        | memory_protect::PAGE_NOCACHE
        | memory_protect::PAGE_WRITECOMBINE => true,
        _ => false,
    }
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the memory thunk layer.
pub fn init() {
    crate::wow64_klog!("Initializing memory thunk layer");
    crate::wow64_klog!("Memory thunk layer initialized");
}

// =============================================================================
// Public Entry Points (for thunk.rs forwarding)
// =============================================================================

/// `wow64_allocate_virtual_memory` — wrapper for Wow64AllocateVirtualMemory32.
pub unsafe extern "C" fn wow64_allocate_virtual_memory(
    process_handle: u32,
    base_address: u32,
    zero_bits: u32,
    region_size: u32,
    allocation_type: u32,
    protect: u32,
) -> u32 {
    crate::wow64_klog!(
        "wow64_allocate_virtual_memory proc={:#x} base={:#x} zb={:#x} size={:#x} type={:#x} prot={:#x}",
        process_handle, base_address, zero_bits, region_size,
        allocation_type, protect
    );
    // Forward to the actual implementation
    Wow64AllocateVirtualMemory32(
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect
    )
}

/// `wow64_free_virtual_memory` — wrapper for Wow64FreeVirtualMemory32.
pub unsafe extern "C" fn wow64_free_virtual_memory(
    process_handle: u32,
    base_address: u32,
    region_size: u32,
    free_type: u32,
) -> u32 {
    crate::wow64_klog!(
        "wow64_free_virtual_memory proc={:#x} base={:#x} size={:#x} type={:#x}",
        process_handle, base_address, region_size, free_type
    );
    // Forward to the actual implementation
    Wow64FreeVirtualMemory32(
        process_handle,
        base_address,
        region_size,
        free_type
    )
}

/// `wow64_read_virtual_memory` — wrapper for Wow64ReadVirtualMemory32.
pub unsafe extern "C" fn wow64_read_virtual_memory(
    process_handle: u32,
    base_address: u32,
    buffer: u32,
    size: u32,
) -> u32 {
    crate::wow64_klog!(
        "wow64_read_virtual_memory proc={:#x} src={:#x} dst={:#x} size={}",
        process_handle, base_address, buffer, size
    );
    // Forward to the actual implementation
    Wow64ReadVirtualMemory32(
        process_handle,
        base_address,
        buffer,
        size,
        0 // number_of_bytes_read_ptr
    )
}

/// `wow64_write_virtual_memory` — wrapper for Wow64WriteVirtualMemory32.
pub unsafe extern "C" fn wow64_write_virtual_memory(
    process_handle: u32,
    base_address: u32,
    buffer: u32,
    size: u32,
) -> u32 {
    crate::wow64_klog!(
        "wow64_write_virtual_memory proc={:#x} dst={:#x} src={:#x} size={}",
        process_handle, base_address, buffer, size
    );
    // Forward to the actual implementation
    Wow64WriteVirtualMemory32(
        process_handle,
        base_address,
        buffer,
        size,
        0 // number_of_bytes_written_ptr
    )
}
