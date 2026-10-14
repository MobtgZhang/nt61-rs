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
use crate::mm::constants::{KERNEL_BASE, USER_BASE, USER_LIMIT};
use crate::mm::vm;

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
    let _guard = crate::arch::x86_64::cpu_flags::SmapGuard::open();
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
    let _guard = crate::arch::x86_64::cpu_flags::SmapGuard::open();
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

/// Write a single `T` from `src` into user space.
pub fn write_user<T: Copy>(dst: u64, src: &T) -> Result<(), i32> {
    let bytes = unsafe {
        core::slice::from_raw_parts(src as *const T as *const u8, core::mem::size_of::<T>())
    };
    copy_to_user(dst, bytes)
}

/// Walk the four-level table and return the leaf entry covering `va`.
fn leaf_entry(va: u64) -> Option<crate::mm::pte::MMPTE> {
    let pml4_phys = crate::mm::vas::current_root();
    if pml4_phys == 0 {
        return None;
    }

    let pml4 = pml4_phys as *const crate::mm::pte::MMPTE;
    let pml4e = unsafe { *pml4.add(((va >> 39) & 0x1FF) as usize) };
    if !pml4e.is_hardware() || pml4e.large() {
        return None;
    }

    let pdpt = pml4e.hardware_page_frame() as *const crate::mm::pte::MMPTE;
    let pdpte = unsafe { *pdpt.add(((va >> 30) & 0x1FF) as usize) };
    if !pdpte.is_hardware() {
        return None;
    }
    if pdpte.large() {
        return Some(pdpte);
    }

    let page_directory = pdpte.hardware_page_frame() as *const crate::mm::pte::MMPTE;
    let pde = unsafe { *page_directory.add(((va >> 21) & 0x1FF) as usize) };
    if !pde.is_hardware() {
        return None;
    }
    if pde.large() {
        return Some(pde);
    }

    let page_table = pde.hardware_page_frame() as *const crate::mm::pte::MMPTE;
    let pte = unsafe { *page_table.add(((va >> 12) & 0x1FF) as usize) };
    if !pte.is_hardware() {
        return None;
    }
    Some(pte)
}

/// True iff `va` is backed by a present, user-owned mapping.
///
/// The U/S bit is the part that matters: a mapping without it is
/// kernel-only, so a "user pointer" that resolves through it is a
/// kernel page reached through a user syscall. With CR4.SMAP set the CPU
/// faults on such an access, but the probe still has to reject it so the
/// caller gets an access violation rather than a fault on its own stack.
fn page_is_user_accessible(va: u64, require_write: bool) -> bool {
    let entry = match leaf_entry(va) {
        Some(e) => e,
        None => return false,
    };
    if !entry.user() {
        return false;
    }
    if require_write && !entry.writable() {
        return false;
    }
    true
}

/// Returns true iff `va` is in the kernel virtual address range.
pub fn is_kernel_pointer(va: u64) -> bool {
    va >= KERNEL_BASE
}
