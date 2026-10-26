//! System call parameter validation
//!
//! This module provides security validation for system call parameters,
//! implementing the ProbeForRead and ProbeForWrite mechanisms from NT kernel.
//!
//! All user-mode pointers must be validated before dereferencing to prevent
//! privilege escalation attacks (Ring 3 → Ring 0).
//!
//! The canonical probe implementation lives in `crate::mm::user_copy`: it
//! walks the page tables, requires every page in the range to be present,
//! rejects kernel aliases, and (for write probes) requires the writable bit.
//! This module is the syscall-facing wrapper around it so both share one
//! policy. A probe that only checks "is this address in the user half" is
//! not a probe — it accepts unmapped memory, and the dereference then faults
//! inside the kernel instead of raising a catchable access violation.

/// In Windows x64, user-mode address space is limited to 0x00007FFF_FFFFFFFF.
/// Single source of truth: pinned to `mm::constants::USER_LIMIT` so the
/// syscall layer and the memory manager can never drift apart. The const
/// assertion turns any drift in `mm` into a compile error.
const USER_MAX_ADDRESS: usize = crate::mm::constants::USER_LIMIT as usize;
const _: () = assert!(
    USER_MAX_ADDRESS as u64 == crate::mm::constants::USER_LIMIT,
    "USER_MAX_ADDRESS must track mm::constants::USER_LIMIT",
);

// NTSTATUS is a signed 32-bit value in the documented ABI, so the probe
// helpers report it as `i32` and callers can return it directly from a
// syscall handler without a lossy cast.
pub const STATUS_SUCCESS: i32 = 0x00000000;
pub const STATUS_ACCESS_VIOLATION: i32 = 0xC0000005u32 as i32;
pub const STATUS_INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;
pub const STATUS_DATATYPE_MISALIGNMENT: i32 = 0x80000002u32 as i32;

/// Verify that a user-mode pointer is safe to read from.
/// 1. The address is within user-mode address space
/// 2. Every page covering the range is present and mapped user-readable
/// 3. The entire range is within user-mode bounds
#[inline]
pub unsafe fn probe_for_read(address: *const u8, length: usize) -> Result<(), i32> {
    if address.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    let addr = address as usize;

    // Check if address is in user-mode space
    if addr >= USER_MAX_ADDRESS {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    if length == 0 {
        return Ok(());
    }

    let end = addr.checked_add(length).ok_or(STATUS_INVALID_PARAMETER)?;

    // Check if entire range is within user-mode bounds
    if end > USER_MAX_ADDRESS {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    if end < addr {
        return Err(STATUS_INVALID_PARAMETER);
    }

    // Page-table level probe: the range must actually be mapped.
    crate::mm::user_copy::probe_user_read(addr as u64, length)?;

    Ok(())
}

/// Verify that a user-mode pointer is safe to write to.
/// 1. The address is within user-mode address space
/// 2. Every page covering the range is present, mapped and writable
/// 3. The entire range is within user-mode bounds
//
// A write probe that forwards to the read probe is not a write probe: it
// accepts read-only mappings and the caller then writes through them. The
// writable bit has to be checked explicitly.

#[inline]
pub unsafe fn probe_for_write(address: *mut u8, length: usize) -> Result<(), i32> {
    if address.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let addr = address as usize;
    if addr >= USER_MAX_ADDRESS {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if length == 0 {
        return Ok(());
    }
    let end = addr.checked_add(length).ok_or(STATUS_INVALID_PARAMETER)?;
    if end > USER_MAX_ADDRESS {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    crate::mm::user_copy::probe_user_write(addr as u64, length)?;

    Ok(())
}

#[inline]
pub unsafe fn probe_for_read_aligned(
    address: *const u8,
    length: usize,
    alignment: usize,
) -> Result<(), i32> {
    // NT orders these checks the other way round from the naive reading of
    // the API: ProbeForRead/ProbeForWrite test alignment first and only
    // then probe the range. Reporting misalignment before probing means a
    // caller never walks page tables for a pointer that is rejected anyway.
    if alignment > 1 && (address as usize) % alignment != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe_for_read(address, length)
}

#[inline]
pub unsafe fn probe_for_write_aligned(
    address: *mut u8,
    length: usize,
    alignment: usize,
) -> Result<(), i32> {
    if alignment > 1 && (address as usize) % alignment != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe_for_write(address, length)
}

/// Validate a user-mode string pointer (null-terminated)
/// Validates that a null-terminated string is entirely within user-mode
pub unsafe fn probe_for_read_string(address: *const u8, max_length: usize) -> Result<usize, i32> {
    if address.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    let addr = address as usize;

    if addr >= USER_MAX_ADDRESS {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    // Scan page by page: probe every page of the stretch once and copy
    // it into a stack buffer, instead of re-walking the page tables for
    // every single byte. The probe covers the whole chunk, so no byte
    // is ever dereferenced unvalidated.
    const PAGE: usize = 4096;
    let mut len = 0;
    while len < max_length {
        let page_remaining = PAGE - ((addr + len) % PAGE);
        let chunk = page_remaining.min(max_length - len);
        probe_for_read(address.add(len), chunk)?;
        let mut buf = [0u8; PAGE];
        crate::mm::user_copy::copy_from_user(&mut buf[..chunk], (addr + len) as u64)?;
        if let Some(pos) = buf[..chunk].iter().position(|&b| b == 0) {
            return Ok(len + pos);
        }
        len += chunk;
    }

    Err(STATUS_INVALID_PARAMETER)
}

/// Validate a user-mode Unicode string pointer (null-terminated UTF-16)
/// user-mode address space, up to max_length characters.
pub unsafe fn probe_for_read_unicode_string(
    address: *const u16,
    max_length: usize,
) -> Result<usize, i32> {
    if address.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    let addr = address as usize;

    if addr >= USER_MAX_ADDRESS || addr % 2 != 0 {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    // Same page-wise scan as `probe_for_read_string`, in UTF-16 code
    // units. The pointer is 2-aligned, so every chunk stays within one
    // page.
    const PAGE: usize = 4096;
    let mut len = 0;
    while len < max_length {
        let page_remaining = PAGE - ((addr + len * 2) % PAGE);
        let chars = (page_remaining / 2).min(max_length - len);
        probe_for_read(address.add(len) as *const u8, chars * 2)?;
        let mut buf = [0u16; PAGE / 2];
        crate::mm::user_copy::copy_from_user(
            core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, chars * 2),
            (addr + len * 2) as u64,
        )?;
        if let Some(pos) = buf[..chars].iter().position(|&c| c == 0) {
            return Ok(len + pos);
        }
        len += chars;
    }

    Err(STATUS_INVALID_PARAMETER)
}

/// Probe a user-mode `UnicodeString`.
///
/// The structure itself is user-controlled, so both the header and the
/// buffer it points at must be probed. `length` is a byte count, so the
/// buffer range is `length` bytes and must not exceed `maximum_length`.
pub unsafe fn probe_unicode_string(address: *const u8) -> Result<(), i32> {
    if address.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    probe_for_read(
        address,
        core::mem::size_of::<crate::libs::ntdll::types::UnicodeString>(),
    )?;

    let mut header: crate::libs::ntdll::types::UnicodeString = unsafe { core::mem::zeroed() };
    crate::mm::user_copy::read_user(address as u64, &mut header)?;
    if header.length > header.maximum_length {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if header.length == 0 {
        return Ok(());
    }
    if header.buffer.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    probe_for_read(header.buffer as *const u8, header.length as usize)
}

/// Copy a user-mode null-terminated byte string into a kernel buffer.
///
/// The whole scan happens inside a probed range, so the caller never
/// dereferences unvalidated user memory. Returns the number of bytes
/// copied (excluding the terminator).
pub unsafe fn capture_user_string(
    address: *const u8,
    max_length: usize,
    dst: &mut [u8],
) -> Result<usize, i32> {
    let len = probe_for_read_string(address, max_length)?;
    if len > dst.len() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    crate::mm::user_copy::copy_from_user(&mut dst[..len], address as u64)?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn test_probe_for_read_null() {
        unsafe {
            assert_eq!(
                probe_for_read(ptr::null(), 100),
                Err(STATUS_ACCESS_VIOLATION)
            );
        }
    }

    #[test]
    fn test_probe_for_read_kernel_address() {
        unsafe {
            // Kernel address (above user-mode limit)
            assert_eq!(
                probe_for_read(0xFFFF_8000_0000_0000 as *const u8, 100),
                Err(STATUS_ACCESS_VIOLATION)
            );
        }
    }

    #[test]
    fn test_probe_for_read_overflow() {
        unsafe {
            assert_eq!(
                probe_for_read(0x7FFF_FFFF_FF00 as *const u8, 0x1000),
                Err(STATUS_ACCESS_VIOLATION)
            );
        }
    }

    #[test]
    fn test_probe_for_read_valid() {
        // A user-half address that is not backed by a mapped page must be
        // rejected: bounds alone are not a probe.
        unsafe {
            let result = probe_for_read(0x1000 as *const u8, 100);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_probe_alignment() {
        unsafe {
            assert_eq!(
                probe_for_read_aligned(0x1001 as *const u8, 8, 8),
                Err(STATUS_DATATYPE_MISALIGNMENT)
            );

            // Aligned but not mapped: a probe that only checks bounds would
            // say "ok" here and the caller would fault on the dereference.
            assert_eq!(
                probe_for_read_aligned(0x1000 as *const u8, 8, 8),
                Err(STATUS_ACCESS_VIOLATION)
            );

            // Alignment is reported before the range is walked, so a
            // misaligned kernel pointer still reports misalignment.
            assert_eq!(
                probe_for_write_aligned(0x1001 as *mut u8, 8, 8),
                Err(STATUS_DATATYPE_MISALIGNMENT)
            );
        }
    }
}
