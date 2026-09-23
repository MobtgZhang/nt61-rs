//! I/O Transfer Modes
//!
//! Windows NT supports three I/O transfer modes for communicating data
//! between user mode and kernel mode:
//!
//! 1. **Buffered I/O**: The I/O manager allocates a system buffer and
//!    copies data to/from user space. Safe but slower.
//!
//! 2. **Direct I/O**: The I/O manager locks user pages in memory and
//!    creates an MDL (Memory Descriptor List). Zero-copy but requires
//!    page locking.
//!
//! 3. **Neither I/O**: The driver accesses user buffers directly using
//!    the original virtual addresses. Fast but dangerous (page faults,
//!    security issues). Only for trusted drivers.

use core::ptr::null_mut;
use alloc::vec::Vec;

use crate::mm::pool;
use crate::libs::ntdll::status::*;

pub const DO_BUFFERED_IO: u32 = 0x00000004;
pub const DO_DIRECT_IO: u32 = 0x00000010;

#[repr(C)]
pub struct Mdl {
    pub next: *mut Mdl,
    pub size: u16,
    pub mdl_flags: u16,
    pub process: *mut (),
    pub mapped_system_va: *mut u8,
    pub start_va: *mut u8,
    pub byte_count: u32,
    pub byte_offset: u32,
}

impl Mdl {
    pub const fn new() -> Self {
        Self {
            next: null_mut(),
            size: core::mem::size_of::<Mdl>() as u16,
            mdl_flags: 0,
            process: null_mut(),
            mapped_system_va: null_mut(),
            start_va: null_mut(),
            byte_count: 0,
            byte_offset: 0,
        }
    }
}

pub const MDL_MAPPED_TO_SYSTEM_VA: u16 = 0x0001;
pub const MDL_PAGES_LOCKED: u16 = 0x0002;
pub const MDL_SOURCE_IS_NONPAGED_POOL: u16 = 0x0004;
pub const MDL_ALLOCATED_FIXED_SIZE: u16 = 0x0008;
pub const MDL_PARTIAL: u16 = 0x0010;
pub const MDL_PARTIAL_HAS_BEEN_MAPPED: u16 = 0x0020;
pub const MDL_IO_PAGE_READ: u16 = 0x0040;
pub const MDL_WRITE_OPERATION: u16 = 0x0080;
pub const MDL_PARENT_MAPPED_SYSTEM_VA: u16 = 0x0100;
pub const MDL_LOCK_HELD: u16 = 0x0200;
pub const MDL_SCATTER_GATHER_VA: u16 = 0x0400;
pub const MDL_IO_SPACE: u16 = 0x0800;
pub const MDL_NETWORK_HEADER: u16 = 0x1000;
pub const MDL_MAPPING_CAN_FAIL: u16 = 0x2000;
pub const MDL_ALLOCATED_MUST_SUCCEED: u16 = 0x4000;

/// Allocate an MDL for a user buffer.
pub fn allocate_mdl(
    virtual_address: *mut u8,
    length: u32,
    secondary_buffer: bool,
    charge_quota: bool,
    irp: *mut super::Irp,
) -> *mut Mdl {
    let _ = (secondary_buffer, charge_quota, irp);

    let mdl_size = core::mem::size_of::<Mdl>();
    let mdl = pool::allocate(pool::PoolType::NonPaged, mdl_size) as *mut Mdl;

    if mdl.is_null() {
        return null_mut();
    }

    unsafe {
        core::ptr::write_bytes(mdl as *mut u8, 0, mdl_size);
        (*mdl).size = mdl_size as u16;
        (*mdl).start_va = virtual_address;
        (*mdl).byte_count = length;
        (*mdl).byte_offset = (virtual_address as usize & 0xFFF) as u32;
        (*mdl).mdl_flags = 0;
    }

    mdl
}

pub fn build_mdl_for_non_paged_pool(mdl: *mut Mdl) {
    if !mdl.is_null() {
        unsafe {
            (*mdl).mdl_flags |= MDL_SOURCE_IS_NONPAGED_POOL | MDL_PAGES_LOCKED;
        }
    }
}

pub fn probe_and_lock_pages(
    mdl: *mut Mdl,
    access_mode: u8,
    operation: u32,
) -> u32 {
    let _ = (
        
        
        access_mode, operation);

    if mdl.is_null() {
        return STATUS_INVALID_PARAMETER as u32;
    }

    unsafe {
        (*mdl).mdl_flags |= MDL_PAGES_LOCKED;

    }

    STATUS_SUCCESS as u32
}

pub fn unlock_pages(mdl: *mut Mdl) {
    if mdl.is_null() {
        return;
    }

    unsafe {
        (*mdl).mdl_flags &= !MDL_PAGES_LOCKED;
    }
}

pub fn free_mdl(mdl: *mut Mdl) {
    if mdl.is_null() {
        return;
    }

    unlock_pages(mdl);

    pool::free(mdl as *mut u8);
}

pub fn map_locked_pages(mdl: *mut Mdl, access_mode: u8) -> *mut u8 {
    let _ = access_mode;

    if mdl.is_null() {
        return null_mut();
    }

    unsafe {
        if ((*mdl).mdl_flags & MDL_MAPPED_TO_SYSTEM_VA) != 0 {
            return (*mdl).mapped_system_va;
        }

        let mapped_va = (*mdl).start_va;
        (*mdl).mapped_system_va = mapped_va;
        (*mdl).mdl_flags |= MDL_MAPPED_TO_SYSTEM_VA;

        mapped_va
    }
}

pub fn unmap_locked_pages(mdl: *mut Mdl) {
    if mdl.is_null() {
        return;
    }

    unsafe {
        (*mdl).mapped_system_va = null_mut();
        (*mdl).mdl_flags &= !MDL_MAPPED_TO_SYSTEM_VA;
    }
}

pub fn get_system_address_for_mdl(mdl: *mut Mdl) -> *mut u8 {
    if mdl.is_null() {
        return null_mut();
    }

    unsafe {
        if ((*mdl).mdl_flags & MDL_MAPPED_TO_SYSTEM_VA) != 0 {
            (*mdl).mapped_system_va
        } else {
            map_locked_pages(mdl, 0) // KernelMode
        }
    }
}

/// Buffered I/O: Allocate a system buffer and copy from user space.
pub fn allocate_buffered_io_buffer(
    user_buffer: *const u8,
    length: u32,
    for_write: bool,
) -> *mut u8 {
    if length == 0 {
        return null_mut();
    }

    let sys_buffer = pool::allocate(pool::PoolType::NonPaged, length as usize) as *mut u8;

    if sys_buffer.is_null() {
        return null_mut();
    }

    // Copy from user buffer if this is a write operation
    if for_write && !user_buffer.is_null() {
        unsafe {
            core::ptr::copy_nonoverlapping(user_buffer, sys_buffer, length as usize);
        }
    }

    sys_buffer
}

/// Buffered I/O: Copy from system buffer back to user space and free.
pub fn free_buffered_io_buffer(
    sys_buffer: *mut u8,
    user_buffer: *mut u8,
    length: u32,
    for_read: bool,
) {
    if sys_buffer.is_null() {
        return;
    }

    // Copy to user buffer if this is a read operation
    if for_read && !user_buffer.is_null() && length > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(sys_buffer, user_buffer, length as usize);
        }
    }

    pool::free(sys_buffer);
}

pub fn get_io_buffer(
    device_flags: u32,
    user_buffer: *mut u8,
    length: u32,
    for_write: bool,
    mdl_out: *mut *mut Mdl,
) -> *mut u8 {
    if (device_flags & DO_BUFFERED_IO) != 0 {
        allocate_buffered_io_buffer(user_buffer, length, for_write)
    } else if (device_flags & DO_DIRECT_IO) != 0 {
        let mdl = allocate_mdl(user_buffer, length, false, false, null_mut());
        if mdl.is_null() {
            return null_mut();
        }

        let status = probe_and_lock_pages(mdl, 0, if for_write { 1 } else { 0 });
        if status != STATUS_SUCCESS as u32 {
            free_mdl(mdl);
            return null_mut();
        }

        if !mdl_out.is_null() {
            unsafe {
                *mdl_out = mdl;
            }
        }

        get_system_address_for_mdl(mdl)
    } else {
        // Neither I/O - use user buffer directly
        user_buffer
    }
}

pub fn release_io_buffer(
    device_flags: u32,
    sys_buffer: *mut u8,
    user_buffer: *mut u8,
    length: u32,
    for_read: bool,
    mdl: *mut Mdl,
) {
    if (device_flags & DO_BUFFERED_IO) != 0 {
        free_buffered_io_buffer(sys_buffer, user_buffer, length, for_read);
    } else if (device_flags & DO_DIRECT_IO) != 0 {
        if !mdl.is_null() {
            unmap_locked_pages(mdl);
            unlock_pages(mdl);
            free_mdl(mdl);
        }
    } else {
        // Neither I/O - nothing to free (used user buffer directly)
    }
}
