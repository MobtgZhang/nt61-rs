//! User pointer helpers.
//!
//! Syscalls receive raw pointers from user-mode code. Constructing a Rust
//! reference or slice directly over such a pointer is a privilege-escalation
//! hazard: an attacker can supply an unmapped address (causing a kernel
//! page fault and system-wide crash) or a kernel address (allowing
//! writes into kernel memory through a user-mode call). SMAP/SMEP are
//! enforced by `arch::x86_64::cpu_flags::enable_user_boundary_protection()`
//! (CR4 bit 10 / bit 9), so a missed probe raises #PF instead of silently
//! corrupting user memory. The software probe below is still required:
//! SMAP makes the access fault, it does not validate the range.
//!
//! These helpers wrap `translate_virt` with a stricter policy: they
//! reject pointers outside the canonical user range, reject overflow,
//! reject non-canonical VAs, and require the resolved physical page to
//! be present. They also check the writable bit for output paths and
//! the user bit so kernel-only mappings cannot be touched.
//!
//! They are deliberately conservative: on any failure they return
//! `STATUS_ACCESS_VIOLATION`. The caller is responsible for translating
//! the failure into the appropriate NTSTATUS / Win32 error.

use crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
use crate::libs::ntdll::types::UnicodeString;
use crate::mm::constants::{KERNEL_BASE, USER_BASE, USER_LIMIT};

/// True iff `va..va+len` lies entirely inside the user address range
/// and does not overflow.
pub fn is_user_range(va: u64, len: usize) -> bool {
    if va < USER_BASE || va > USER_LIMIT {
        return false;
    }
    let end = match va.checked_add(len as u64) {
        Some(v) => v,
        None => return false,
    };
    // end is exclusive. If it equals USER_LIMIT+1 it is fine because
    // USER_LIMIT is the largest canonical user VA. If it is in the
    // kernel half it is out of bounds.
    if end > USER_LIMIT.saturating_add(1) {
        return false;
    }
    if end > USER_LIMIT && va <= USER_LIMIT {
        // len crosses the boundary — only allowed if va == USER_LIMIT+1
        // but that can never satisfy va >= USER_BASE, so this is dead.
        return false;
    }
    true
}

/// Check that `[ptr, ptr+len)` is readable user memory.
///
/// Returns `Ok(())` if every page in the range is present and mapped
/// user-readable. Returns `Err(STATUS_ACCESS_VIOLATION)` otherwise.
pub fn probe_user_read(ptr: u64, len: usize) -> Result<(), i32> {
    if !is_user_range(ptr, len) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if len == 0 {
        return Ok(());
    }
    let end = ptr + len as u64;
    let mut va = ptr & !0xFFF;
    while va < end {
        if !page_is_user_accessible(va, false) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        va += 0x1000;
    }
    Ok(())
}

/// Check that `[ptr, ptr+len)` is writable user memory.
///
/// Same rules as `probe_user_read`, plus the writable bit must be set
/// on every leaf PTE we cover.
pub fn probe_user_write(ptr: u64, len: usize) -> Result<(), i32> {
    if !is_user_range(ptr, len) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if len == 0 {
        return Ok(());
    }
    let end = ptr + len as u64;
    let mut va = ptr & !0xFFF;
    while va < end {
        if !page_is_user_accessible(va, true) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        va += 0x1000;
    }
    Ok(())
}

/// Copy `len` bytes from user-space `src` into kernel-owned `dst`.
/// Returns `Ok(())` on success.
pub fn copy_from_user(dst: &mut [u8], src: u64) -> Result<(), i32> {
    let len = dst.len();
    if len == 0 {
        return Ok(());
    }
    probe_user_read(src, len)?;
    let _guard = crate::arch::common::user_memory::SmapGuard::open();
    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u8, dst.as_mut_ptr(), len);
    }
    Ok(())
}

/// Copy `len` bytes from kernel-owned `src` into user-space `dst`.
/// Returns `Ok(())` on success.
pub fn copy_to_user(dst: u64, src: &[u8]) -> Result<(), i32> {
    let len = src.len();
    if len == 0 {
        return Ok(());
    }
    probe_user_write(dst, len)?;
    let _guard = crate::arch::common::user_memory::SmapGuard::open();
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, len);
    }
    Ok(())
}

/// Copy a single `T` from user space into `dst`.
pub fn read_user<T: Copy>(src: u64, dst: &mut T) -> Result<(), i32> {
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(dst as *mut T as *mut u8, core::mem::size_of::<T>())
    };
    copy_from_user(bytes, src)
}

/// write a single `T` from `src` into user space.
pub fn write_user<T: Copy>(dst: u64, src: &T) -> Result<(), i32> {
    let bytes = unsafe {
        core::slice::from_raw_parts(src as *const T as *const u8, core::mem::size_of::<T>())
    };
    copy_to_user(dst, bytes)
}

/// Read one fixed-size `Copy` object from user space.
pub fn read_user_object<T: Copy>(src: u64) -> Result<T, i32> {
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    copy_from_user(bytes, src)?;
    Ok(unsafe { value.assume_init() })
}

/// Write one fixed-size `Copy` object to user space.
pub fn write_user_object<T: Copy>(dst: u64, value: &T) -> Result<(), i32> {
    let bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    copy_to_user(dst, bytes)
}

/// Read a counted UTF-16 string header and its buffer from user space.
///
/// `max_bytes` limits the trusted `length` field before any buffer read.
pub fn read_user_unicode_string(src: u64, max_bytes: usize) -> Result<alloc::vec::Vec<u16>, i32> {
    let header: UnicodeString = read_user_object(src)?;
    if header.length == 0 || header.length % 2 != 0 {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if header.length as usize > max_bytes || header.buffer.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    let chars = header.length as usize / 2;
    let mut value = alloc::vec![0u16; chars];
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, header.length as usize)
    };
    copy_from_user(bytes, header.buffer as u64)?;
    Ok(value)
}

/// Read a counted UTF-16 array directly from user memory.
pub fn read_user_utf16(src: u64, char_count: u64) -> Result<alloc::vec::Vec<u16>, i32> {
    if char_count == 0 {
        return Ok(alloc::vec![]);
    }
    let byte_count = (char_count as usize)
        .checked_mul(2)
        .ok_or(STATUS_ACCESS_VIOLATION)?;
    let mut value = alloc::vec![0u16; char_count as usize];
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, byte_count) };
    copy_from_user(bytes, src)?;
    Ok(value)
}



/// True iff `va` is backed by a present, user-owned mapping.
///
/// Check the actual leaf PTE, not merely whether a translation exists.
/// This rejects kernel-only mappings and enforces write permission for
/// user-space output buffers on all supported ISAs.
#[cfg(test)]
fn page_is_user_accessible(_va: u64, _require_write: bool) -> bool {
    false
}

#[cfg(not(test))]
fn page_is_user_accessible(va: u64, require_write: bool) -> bool {
    #[cfg(test)]
    {
        return false;
    }
    crate::arch::leaf_entry(va)
        .map(|entry| crate::arch::page_user_accessible(entry, require_write))
        .unwrap_or(false)
}

/// Returns true iff `va` is in the kernel virtual address range.
pub fn is_kernel_pointer(va: u64) -> bool {
    va >= KERNEL_BASE
}
