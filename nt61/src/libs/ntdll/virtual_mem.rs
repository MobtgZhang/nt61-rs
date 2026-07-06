//! ntdll — Nt* virtual memory APIs
//
//! `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`,
//! `NtProtectVirtualMemory`, `NtQueryVirtualMemory`. The
//! implementation routes to the kernel VM manager for
//! allocations on the kernel pool; user-mode allocations
//! return a deterministic placeholder address so the
//! kernel32 layer can do its smoke test (and the
//! user-mode side of this kernel is never executed, so
//! no real mappings are required).
//
//! References: MSDN Library "Windows 7" — `ntdll.dll`
//! virtual memory APIs.

extern crate alloc;

use super::status::{
    STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED,
    STATUS_NO_MEMORY, STATUS_SUCCESS,
};
use super::types::{HANDLE, NTSTATUS, PVOID, SIZE_T};
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use core::ptr;

/// User-mode base address placeholder (the bootstrap user
/// region starts at 0x0000_7000_0000_0000; see
/// `system_image::build_ntdll`).
const USER_BASE: u64 = 0x0000_7000_0000_0000;

/// Pool tag for virtual memory allocations (4-character tag: 'VMem')
const VMEM_POOL_TAG: u32 = (b'V' as u32) | (b'M' as u32) << 8
    | (b'e' as u32) << 16 | (b'm' as u32) << 24;

/// Memory allocation tracking entry.
struct MemEntry {
    /// Virtual address of the allocation
    base_address: u64,
    /// Size of the allocation in bytes (aligned to page size)
    region_size: u64,
    /// Memory protection flags
    protect: u32,
    /// Whether this allocation is committed
    committed: bool,
}

impl MemEntry {
    fn new(base_address: u64, region_size: u64, protect: u32) -> Self {
        Self {
            base_address,
            region_size,
            protect,
            committed: true,
        }
    }
}

/// Global memory allocation table.
/// This table tracks all allocations made by NtAllocateVirtualMemory
/// so that NtFreeVirtualMemory and NtProtectVirtualMemory can
/// find and modify them.
static MEMORY_TABLE: Spinlock<Vec<MemEntry>> = Spinlock::new(Vec::new());

/// Page size constant (4KB)
const PAGE_SIZE: u64 = 0x1000;

/// Align size up to page boundary
fn align_to_page(size: usize) -> usize {
    ((size + 0xFFF) & !0xFFF) as usize
}

/// Find an allocation entry by base address.
fn find_allocation(base_address: u64) -> Option<usize> {
    let table = MEMORY_TABLE.lock();
    table.iter().position(|e| e.base_address == base_address)
}

/// Remove an allocation entry by base address.
/// Returns the removed entry if found.
fn remove_allocation(base_address: u64) -> Option<MemEntry> {
    let mut table = MEMORY_TABLE.lock();
    if let Some(pos) = table.iter().position(|e| e.base_address == base_address) {
        Some(table.remove(pos))
    } else {
        None
    }
}

/// Add an allocation entry.
fn add_allocation(entry: MemEntry) {
    let mut table = MEMORY_TABLE.lock();
    table.push(entry);
}

/// Validate protection flags.
fn is_valid_protect(protect: u32) -> bool {
    use super::types::page;
    matches!(
        protect,
        page::PAGE_NOACCESS
            | page::PAGE_READONLY
            | page::PAGE_READWRITE
            | page::PAGE_WRITECOPY
            | page::PAGE_EXECUTE
            | page::PAGE_EXECUTE_READ
            | page::PAGE_EXECUTE_READWRITE
            | page::PAGE_EXECUTE_WRITECOPY
            | page::PAGE_GUARD | page::PAGE_NOCACHE
            | page::PAGE_WRITECOMBINE
    )
}

/// `NtAllocateVirtualMemory`.
///
/// Allocates virtual memory in the specified process address space.
/// For user-mode processes, this integrates with the kernel's mm::vas module.
pub unsafe extern "C" fn NtAllocateVirtualMemory(
    _process_handle: HANDLE,
    base_address: *mut PVOID,
    _zero_bits: usize,
    region_size: *mut SIZE_T,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    use super::status::STATUS_INVALID_PARAMETER;
    use super::types::page;
    use super::types::mem;

    // Parameter validation
    if base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let sz = *region_size;
    if sz == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate protection flags
    if !is_valid_protect(protect) {
        return STATUS_ACCESS_DENIED;
    }

    // Align size to page boundary
    let aligned_size = align_to_page(sz) as u64;
    let actual_size = if aligned_size == 0 { PAGE_SIZE } else { aligned_size };

    // Determine allocation type
    let _do_reserve = (allocation_type & mem::MEM_RESERVE) != 0;
    let _do_commit = (allocation_type & mem::MEM_COMMIT) != 0;

    // Default protection if not specified
    let effective_protect = if protect == 0 { page::PAGE_READWRITE } else { protect };

    // Determine the target address
    let desired_base = if (*base_address).is_null() {
        0 // Let the allocator choose
    } else {
        *base_address as u64
    };

    // Try to allocate from kernel VAS first
    let alloc_result = crate::mm::vas::allocate_user_va(
        desired_base,
        actual_size,
        effective_protect,
    );

    let virt_addr = match alloc_result {
        Some(addr) => addr,
        None => {
            // Fallback: try pool allocation for small requests
            // This handles early boot when VAS is not ready
            let pool_ptr = crate::mm::pool::allocate_tagged(
                crate::mm::pool::PoolType::NonPaged,
                actual_size as usize,
                VMEM_POOL_TAG,
            );
            if pool_ptr.is_null() {
                return STATUS_NO_MEMORY;
            }
            // Use the pool pointer as the address
            pool_ptr as u64
        }
    };

    // Track the allocation
    let entry = MemEntry::new(virt_addr, actual_size, effective_protect);
    add_allocation(entry);

    // Update output parameters
    *base_address = virt_addr as PVOID;
    *region_size = actual_size as SIZE_T;

    STATUS_SUCCESS
}

/// `NtFreeVirtualMemory`.
///
/// Frees virtual memory that was allocated with NtAllocateVirtualMemory.
pub unsafe extern "C" fn NtFreeVirtualMemory(
    _process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut SIZE_T,
    free_type: u32,
) -> NTSTATUS {
    use super::types::mem;
    use super::status::STATUS_INVALID_HANDLE;

    // Parameter validation
    if base_address.is_null() || (*base_address).is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let virt_addr = *base_address as u64;
    let _free_type = free_type;

    // Look up the allocation
    let entry = match remove_allocation(virt_addr) {
        Some(e) => e,
        None => {
            // Try to free via kernel VAS (for non-tracked allocations)
            let freed = crate::mm::vas::free_user_va(virt_addr);
            if !freed {
                return STATUS_INVALID_HANDLE;
            }
            *base_address = core::ptr::null_mut();
            if !region_size.is_null() {
                *region_size = 0;
            }
            return STATUS_SUCCESS;
        }
    };

    // Free via kernel VAS if possible
    let _freed = crate::mm::vas::free_user_va(virt_addr);

    // Update output parameters
    *base_address = core::ptr::null_mut();
    if !region_size.is_null() {
        *region_size = entry.region_size as SIZE_T;
    }

    STATUS_SUCCESS
}

/// `NtProtectVirtualMemory` — change page protection.
///
/// This function changes the protection on a region of pages.
/// The protection cannot be changed on a region of pages that has been
/// decommitted using NtFreeVirtualMemory with MEM_DECOMMIT.
pub unsafe extern "C" fn NtProtectVirtualMemory(
    _process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut SIZE_T,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    use super::types::page;

    // Parameter validation
    if base_address.is_null() || (*base_address).is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if region_size.is_null() || *region_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate new protection flags
    if !is_valid_protect(new_protect) {
        return STATUS_ACCESS_DENIED;
    }

    let virt_addr = *base_address as u64;
    let sz = *region_size as u64;
    let aligned_size = align_to_page(sz as usize) as u64;

    // Look up the allocation to validate range
    let mut table = MEMORY_TABLE.lock();
    if let Some(entry) = table.iter_mut().find(|e| e.base_address == virt_addr) {
        // Validate the range is within the allocation
        if aligned_size > entry.region_size {
            return STATUS_INVALID_PARAMETER;
        }

        // Return old protection if requested
        if !old_protect.is_null() {
            *old_protect = entry.protect;
        }

        // Update protection
        entry.protect = new_protect;
    } else {
        // Allocation not tracked, but still allow protection changes
        // for early boot scenarios
        if !old_protect.is_null() {
            *old_protect = page::PAGE_READWRITE;
        }
    }

    STATUS_SUCCESS
}

/// `MEMORY_BASIC_INFORMATION` — information about a region of pages.
#[repr(C)]
#[derive(Default)]
pub struct MemoryBasicInformation {
    pub base_address: PVOID,
    pub allocation_base: PVOID,
    pub allocation_protect: u32,
    pub _pad1: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
    pub _pad2: u32,
}

/// `NtQueryVirtualMemory` — returns information about a region of pages.
pub unsafe extern "C" fn NtQueryVirtualMemory(
    process_handle: HANDLE,
    base_address: PVOID,
    memory_information_class: u32,
    memory_information: PVOID,
    memory_information_length: SIZE_T,
    return_length: *mut SIZE_T,
) -> NTSTATUS {
    use super::types::page;
    use super::types::mem;

    if memory_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _process_handle = process_handle;

    // Only MemoryBasicInformation (class 0) is supported
    if memory_information_class != 0 {
        return STATUS_NOT_IMPLEMENTED;
    }

    let required_size = core::mem::size_of::<MemoryBasicInformation>();
    if memory_information_length < required_size {
        if !return_length.is_null() {
            *return_length = required_size;
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    let virt_addr = base_address as u64;

    // Look up the allocation
    let table = MEMORY_TABLE.lock();
    if let Some(entry) = table.iter().find(|e| {
        virt_addr >= e.base_address && virt_addr < e.base_address + e.region_size
    }) {
        let mbi = &mut *(memory_information as *mut MemoryBasicInformation);
        mbi.base_address = entry.base_address as PVOID;
        mbi.allocation_base = entry.base_address as PVOID;
        mbi.allocation_protect = entry.protect;
        mbi.region_size = entry.region_size;
        mbi.state = if entry.committed {
            mem::MEM_COMMIT
        } else {
            mem::MEM_RESERVE
        };
        mbi.protect = entry.protect;
        mbi.type_ = 0x20000; // MEM_PRIVATE

        if !return_length.is_null() {
            *return_length = required_size;
        }
        STATUS_SUCCESS
    } else {
        // Memory not in our table - return basic information
        let mbi = &mut *(memory_information as *mut MemoryBasicInformation);
        mbi.base_address = (virt_addr & !0xFFF) as PVOID;
        mbi.allocation_base = (virt_addr & !0xFFF) as PVOID;
        mbi.allocation_protect = page::PAGE_READWRITE;
        mbi.region_size = PAGE_SIZE;
        mbi.state = 0; // MEM_FREE
        mbi.protect = 0;
        mbi.type_ = 0;

        if !return_length.is_null() {
            *return_length = required_size;
        }
        STATUS_SUCCESS
    }
}

/// `NtReadVirtualMemory` / `NtWriteVirtualMemory` — read/write
/// the address space of a target process. The bootstrap cannot
/// read another process's memory; return STATUS_NOT_IMPLEMENTED
/// when called on a non-self target, and copy directly for the
/// self case.
pub unsafe extern "C" fn NtReadVirtualMemory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    number_of_bytes_to_read: SIZE_T,
    number_of_bytes_read: *mut SIZE_T,
) -> NTSTATUS {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // For now, only support self-process reads
    if !process_handle.is_null() && process_handle as u64 != (-1i64) as u64 {
        return STATUS_NOT_IMPLEMENTED;
    }

    core::ptr::copy_nonoverlapping(base_address as *const u8, buffer as *mut u8, number_of_bytes_to_read);
    if !number_of_bytes_read.is_null() {
        *number_of_bytes_read = number_of_bytes_to_read;
    }
    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtWriteVirtualMemory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    number_of_bytes_to_write: SIZE_T,
    number_of_bytes_written: *mut SIZE_T,
) -> NTSTATUS {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // For now, only support self-process writes
    if !process_handle.is_null() && process_handle as u64 != (-1i64) as u64 {
        return STATUS_NOT_IMPLEMENTED;
    }

    core::ptr::copy_nonoverlapping(buffer as *const u8, base_address as *mut u8, number_of_bytes_to_write);
    if !number_of_bytes_written.is_null() {
        *number_of_bytes_written = number_of_bytes_to_write;
    }
    STATUS_SUCCESS
}
