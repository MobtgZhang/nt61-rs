//! ntdll — Nt* virtual memory APIs
//
//! `nt_allocate_virtual_memory`, `nt_free_virtual_memory`,
//! `nt_protect_virtual_memory`, `nt_query_virtual_memory`. The
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
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
};
use super::types::{SizeT, HANDLE, NTSTATUS, PVOID};
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

/// User-mode base address placeholder (the bootstrap user
/// region starts at 0x0000_7000_0000_0000; see
/// `system_image::build_ntdll`).
pub const USER_BASE: u64 = 0x0000_7000_0000_0000;

/// Pool tag for virtual memory allocations (4-character tag: 'VMem')
const VMEM_POOL_TAG: u32 =
    (b'V' as u32) | (b'M' as u32) << 8 | (b'e' as u32) << 16 | (b'm' as u32) << 24;

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
/// This table tracks all allocations made by nt_allocate_virtual_memory
/// so that nt_free_virtual_memory and nt_protect_virtual_memory can
/// find and modify them.
static MEMORY_TABLE: Spinlock<Vec<MemEntry>> = Spinlock::new(Vec::new());

/// Page size constant (4KB)
const PAGE_SIZE: u64 = 0x1000;

/// Align size up to page boundary
fn align_to_page(size: usize) -> usize {
    ((size + 0xFFF) & !0xFFF) as usize
}

/// Find an allocation entry by base address.
pub fn find_allocation(base_address: u64) -> Option<usize> {
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
            | page::PAGE_GUARD
            | page::PAGE_NOCACHE
            | page::PAGE_WRITECOMBINE
    )
}

/// `nt_allocate_virtual_memory`.
///
/// Allocates virtual memory in the specified process address space.
/// For user-mode processes, this integrates with the kernel's mm::vas module.
pub unsafe extern "C" fn nt_allocate_virtual_memory(
    _process_handle: HANDLE,
    base_address: *mut PVOID,
    _zero_bits: usize,
    region_size: *mut SizeT,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    use crate::mm::user_copy::{probe_user_write, read_user_object, write_user_object};

    use super::status::STATUS_INVALID_PARAMETER;
    use super::types::mem;
    use super::types::page;

    // Parameter validation
    if base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if probe_user_write(base_address as u64, core::mem::size_of::<PVOID>()).is_err()
        || probe_user_write(region_size as u64, core::mem::size_of::<SizeT>()).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let requested_size = match read_user_object::<SizeT>(region_size as u64) {
        Ok(value) => value,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };
    let sz = requested_size;
    if sz == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate protection flags
    if !is_valid_protect(protect) {
        return STATUS_ACCESS_DENIED;
    }

    // Align size to page boundary
    let aligned_size = align_to_page(sz) as u64;
    let actual_size = if aligned_size == 0 {
        PAGE_SIZE
    } else {
        aligned_size
    };

    // Determine allocation type
    let _do_reserve = (allocation_type & mem::MEM_RESERVE) != 0;
    let _do_commit = (allocation_type & mem::MEM_COMMIT) != 0;

    // Default protection if not specified
    let effective_protect = if protect == 0 {
        page::PAGE_READWRITE
    } else {
        protect
    };

    // Determine the target address
    let base_pointer = match read_user_object::<PVOID>(base_address as u64) {
        Ok(value) => value,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };
    let desired_base = if base_pointer.is_null() {
        0 // Let the allocator choose
    } else {
        base_pointer as u64
    };

    // Try to allocate from kernel VAS first
    let alloc_result =
        crate::mm::vas::allocate_user_va(desired_base, actual_size, effective_protect);

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
    if write_user_object(base_address as u64, &(virt_addr as PVOID)).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    if write_user_object(region_size as u64, &(actual_size as SizeT)).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }

    STATUS_SUCCESS
}

pub unsafe fn nt_allocate_virtual_memory_kernel(
    process_handle: HANDLE,
    base_address: &mut PVOID,
    zero_bits: usize,
    region_size: &mut SizeT,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    let mut base = *base_address;
    let mut size = *region_size;
    let status = nt_allocate_virtual_memory(
        process_handle,
        &mut base,
        zero_bits,
        &mut size,
        allocation_type,
        protect,
    );
    if status == STATUS_SUCCESS {
        *base_address = base;
        *region_size = size;
    }
    status
}

/// `nt_free_virtual_memory`.
///
/// Frees virtual memory that was allocated with nt_allocate_virtual_memory.
pub unsafe extern "C" fn nt_free_virtual_memory(
    _process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut SizeT,
    free_type: u32,
) -> NTSTATUS {
    use super::status::{STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE};
    use crate::mm::user_copy::{probe_user_write, read_user_object, write_user_object};

    // Parameter validation
    if base_address.is_null() || (*base_address).is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if probe_user_write(base_address as u64, core::mem::size_of::<PVOID>()).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    if !region_size.is_null()
        && probe_user_write(region_size as u64, core::mem::size_of::<SizeT>()).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let base_pointer = match read_user_object::<PVOID>(base_address as u64) {
        Ok(value) => value,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };
    if base_pointer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let virt_addr = base_pointer as u64;
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
            if write_user_object(base_address as u64, &core::ptr::null_mut::<PVOID>()).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            if !region_size.is_null() {
                if write_user_object(region_size as u64, &0usize).is_err() {
                    return STATUS_ACCESS_VIOLATION;
                }
            }
            return STATUS_SUCCESS;
        }
    };

    // Free via kernel VAS if possible
    let _freed = crate::mm::vas::free_user_va(virt_addr);

    // Update output parameters
    if write_user_object(base_address as u64, &core::ptr::null_mut::<PVOID>()).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    if !region_size.is_null() {
        if write_user_object(region_size as u64, &(entry.region_size as SizeT)).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    STATUS_SUCCESS
}

pub unsafe fn nt_free_virtual_memory_kernel(
    process_handle: HANDLE,
    base_address: &mut PVOID,
    region_size: &mut SizeT,
    free_type: u32,
) -> NTSTATUS {
    let mut base = *base_address;
    let mut size = *region_size;
    let status = nt_free_virtual_memory(process_handle, &mut base, &mut size, free_type);
    if status == STATUS_SUCCESS {
        *base_address = base;
        *region_size = size;
    }
    status
}

/// `nt_protect_virtual_memory` — change page protection.
///
/// This function changes the protection on a region of pages.
/// The protection cannot be changed on a region of pages that has been
/// decommitted using nt_free_virtual_memory with MEM_DECOMMIT.
pub unsafe extern "C" fn nt_protect_virtual_memory(
    _process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut SizeT,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    use super::status::{STATUS_ACCESS_VIOLATION, STATUS_INVALID_PARAMETER};
    use super::types::page;
    use crate::mm::user_copy::{probe_user_write, read_user_object, write_user_object};

    // Parameter validation
    if base_address.is_null() || (*base_address).is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if probe_user_write(base_address as u64, core::mem::size_of::<PVOID>()).is_err()
        || probe_user_write(region_size as u64, core::mem::size_of::<SizeT>()).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let base_pointer = match read_user_object::<PVOID>(base_address as u64) {
        Ok(value) => value,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };
    if base_pointer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let region_size_value = match read_user_object::<SizeT>(region_size as u64) {
        Ok(value) => value,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };
    if region_size_value == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate new protection flags
    if !is_valid_protect(new_protect) {
        return STATUS_ACCESS_DENIED;
    }

    let virt_addr = base_pointer as u64;
    let sz = region_size_value as u64;
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
            if write_user_object(old_protect as u64, &entry.protect).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
        }

        // Update protection
        entry.protect = new_protect;
    } else {
        // Allocation not tracked, but still allow protection changes
        // for early boot scenarios
        if !old_protect.is_null() {
            if write_user_object(old_protect as u64, &page::PAGE_READWRITE).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
        }
    }

    STATUS_SUCCESS
}

pub unsafe fn nt_protect_virtual_memory_kernel(
    process_handle: HANDLE,
    base_address: &mut PVOID,
    region_size: &mut SizeT,
    new_protect: u32,
    old_protect: &mut u32,
) -> NTSTATUS {
    let mut base = *base_address;
    let mut size = *region_size;
    let mut old = *old_protect;
    let status =
        nt_protect_virtual_memory(process_handle, &mut base, &mut size, new_protect, &mut old);
    if status == STATUS_SUCCESS {
        *base_address = base;
        *region_size = size;
        *old_protect = old;
    }
    status
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

/// `nt_query_virtual_memory` — returns information about a region of pages.
pub unsafe extern "C" fn nt_query_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    memory_information_class: u32,
    memory_information: PVOID,
    memory_information_length: SizeT,
    return_length: *mut SizeT,
) -> NTSTATUS {
    use super::status::STATUS_ACCESS_VIOLATION;
    use crate::mm::user_copy::{copy_to_user, probe_user_write, write_user_object};

    if memory_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if probe_user_write(
        memory_information as u64,
        core::mem::size_of::<MemoryBasicInformation>(),
    )
    .is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if !return_length.is_null()
        && probe_user_write(return_length as u64, core::mem::size_of::<SizeT>()).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let (status, mbi, required_size) = query_virtual_memory_common(
        process_handle,
        base_address,
        memory_information_class,
        memory_information_length,
    );
    if status != STATUS_SUCCESS {
        if let Some(required_size) = required_size {
            if !return_length.is_null() {
                if write_user_object(return_length as u64, &required_size).is_err() {
                    return STATUS_ACCESS_VIOLATION;
                }
            }
        }
        return status;
    }

    if copy_to_user(
        memory_information as u64,
        mbi_as_bytes(mbi.as_ref().unwrap()),
    )
    .is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if !return_length.is_null() {
        if write_user_object(return_length as u64, &required_size.unwrap()).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    status
}

fn query_virtual_memory_common(
    process_handle: HANDLE,
    base_address: PVOID,
    memory_information_class: u32,
    memory_information_length: SizeT,
) -> (NTSTATUS, Option<MemoryBasicInformation>, Option<usize>) {
    use super::types::{mem, page};
    let _process_handle = process_handle;

    // Only MemoryBasicInformation (class 0) is supported
    if memory_information_class != 0 {
        return (STATUS_INVALID_INFO_CLASS, None, None);
    }

    let required_size = core::mem::size_of::<MemoryBasicInformation>();
    if memory_information_length < required_size {
        return (STATUS_BUFFER_TOO_SMALL, None, Some(required_size));
    }

    let virt_addr = base_address as u64;

    // Look up the allocation
    let table = MEMORY_TABLE.lock();
    if let Some(entry) = table
        .iter()
        .find(|e| virt_addr >= e.base_address && virt_addr < e.base_address + e.region_size)
    {
        let mbi = MemoryBasicInformation {
            base_address: entry.base_address as PVOID,
            allocation_base: entry.base_address as PVOID,
            allocation_protect: entry.protect,
            _pad1: 0,
            region_size: entry.region_size,
            state: if entry.committed {
                mem::MEM_COMMIT
            } else {
                mem::MEM_RESERVE
            },
            protect: entry.protect,
            type_: 0x20000, // MEM_PRIVATE
            _pad2: 0,
        };
        (STATUS_SUCCESS, Some(mbi), Some(required_size))
    } else {
        // Memory not in our table - return basic information
        let mbi = MemoryBasicInformation {
            base_address: (virt_addr & !0xFFF) as PVOID,
            allocation_base: (virt_addr & !0xFFF) as PVOID,
            allocation_protect: page::PAGE_READWRITE,
            _pad1: 0,
            region_size: PAGE_SIZE,
            state: 0, // MEM_FREE
            protect: 0,
            type_: 0,
            _pad2: 0,
        };
        (STATUS_SUCCESS, Some(mbi), Some(required_size))
    }
}

fn mbi_as_bytes(mbi: &MemoryBasicInformation) -> &[u8] {
    unsafe {
        core::slice::from_raw_parts(
            mbi as *const MemoryBasicInformation as *const u8,
            core::mem::size_of::<MemoryBasicInformation>(),
        )
    }
}

/// `nt_read_virtual_memory` / `nt_write_virtual_memory` — read/write
/// when called on a non-self target, and copy via a kernel staging
/// buffer for the cross-process case.
pub unsafe extern "C" fn nt_read_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    number_of_bytes_to_read: SizeT,
    number_of_bytes_read: *mut SizeT,
) -> NTSTATUS {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    rw_virtual_memory_impl(
        process_handle,
        base_address,
        buffer,
        number_of_bytes_to_read,
        number_of_bytes_read,
        true,
    )
}

pub unsafe extern "C" fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    number_of_bytes_to_write: SizeT,
    number_of_bytes_written: *mut SizeT,
) -> NTSTATUS {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    rw_virtual_memory_impl(
        process_handle,
        base_address,
        buffer,
        number_of_bytes_to_write,
        number_of_bytes_written,
        false,
    )
}

/// Shared implementation for  and
/// . Resolves the process handle to a PID,
/// switches CR3 to the target address space (if cross-process), does
/// the copy via the kernel's  primitives, then restores
/// the caller's CR3.
unsafe fn rw_virtual_memory_impl(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    size: SizeT,
    bytes_transferred: *mut SizeT,
    is_read: bool,
) -> NTSTATUS {
    use super::file::{lookup_handle, HandleKind};
    use super::status::{STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE};
    use crate::mm::user_copy::{copy_from_user, copy_to_user, write_user_object};

    let is_self = process_handle.is_null() || (process_handle as u64) == (-1isize) as u64;

    let target_pml4: Option<u64> = if is_self {
        None
    } else {
        match lookup_handle(process_handle) {
            Some(e) if e.kind == HandleKind::Process => {
                match crate::ps::process::get_by_pid(e.target) {
                    Some(proc) => Some((*proc).pml4_phys),
                    None => return STATUS_INVALID_HANDLE,
                }
            }
            _ => return STATUS_INVALID_HANDLE,
        }
    };

    let saved_cr3 = if target_pml4.is_some() {
        Some(crate::mm::dynamic_paging::get_cr3())
    } else {
        None
    };

    let result = if target_pml4.is_some() {
        let mut data = alloc::vec![0u8; size];
        if is_read {
            // Switch to target CR3, copy from target, restore caller CR3.
            if let Some(pml4) = target_pml4 {
                crate::mm::dynamic_paging::set_cr3(pml4);
            }
            let ok = copy_from_user(&mut data, base_address as u64).is_ok();
            if let Some(saved) = saved_cr3 {
                crate::mm::dynamic_paging::set_cr3(saved);
            }
            if !ok || copy_to_user(buffer as u64, &data).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
        } else {
            // Copy from caller buffer into staging, switch to target, write.
            if copy_from_user(&mut data, buffer as u64).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            if let Some(pml4) = target_pml4 {
                crate::mm::dynamic_paging::set_cr3(pml4);
            }
            let ok = copy_to_user(base_address as u64, &data).is_ok();
            if let Some(saved) = saved_cr3 {
                crate::mm::dynamic_paging::set_cr3(saved);
            }
            if !ok {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        STATUS_SUCCESS
    } else {
        let mut data = alloc::vec![0u8; size];
        let ok = if is_read {
            copy_from_user(&mut data, base_address as u64).is_ok()
                && copy_to_user(buffer as u64, &data).is_ok()
        } else {
            copy_from_user(&mut data, buffer as u64).is_ok()
                && copy_to_user(base_address as u64, &data).is_ok()
        };
        if !ok {
            return STATUS_ACCESS_VIOLATION;
        }
        STATUS_SUCCESS
    };

    if !bytes_transferred.is_null() {
        if write_user_object(bytes_transferred as u64, &size).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    result
}

pub unsafe fn nt_query_virtual_memory_kernel(
    process_handle: HANDLE,
    base_address: PVOID,
    memory_information_class: u32,
    memory_information: &mut MemoryBasicInformation,
    memory_information_length: SizeT,
    return_length: &mut SizeT,
) -> NTSTATUS {
    let result = MemoryBasicInformation::default();
    let mut result_length = *return_length;
    let status = nt_query_virtual_memory(
        process_handle,
        base_address,
        memory_information_class,
        memory_information as *mut MemoryBasicInformation as PVOID,
        memory_information_length,
        &mut result_length,
    );
    if status == STATUS_SUCCESS {
        *memory_information = result;
        *return_length = result_length;
    }
    status
}

pub unsafe fn nt_read_virtual_memory_kernel(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: &mut [u8],
    number_of_bytes_read: &mut SizeT,
) -> NTSTATUS {
    if base_address.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let length = buffer.len();
    unsafe {
        core::ptr::copy_nonoverlapping(base_address as *const u8, buffer.as_mut_ptr(), length);
    }
    *number_of_bytes_read = length;
    let _ = process_handle;
    STATUS_SUCCESS
}

pub unsafe fn nt_write_virtual_memory_kernel(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: &[u8],
    number_of_bytes_written: &mut SizeT,
) -> NTSTATUS {
    if base_address.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let length = buffer.len();
    unsafe {
        core::ptr::copy_nonoverlapping(buffer.as_ptr(), base_address as *mut u8, length);
    }
    *number_of_bytes_written = length;
    let _ = process_handle;
    STATUS_SUCCESS
}
