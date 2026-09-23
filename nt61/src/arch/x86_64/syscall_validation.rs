//! System call parameter validation
//!
//! This module provides security validation for system call parameters,
//! implementing the ProbeForRead and ProbeForWrite mechanisms from NT kernel.
//!
//! All user-mode pointers must be validated before dereferencing to prevent
//! privilege escalation attacks (Ring 3 → Ring 0).

use core::ptr;

/// In Windows x64, user-mode address space is limited to 0x00007FFF_FFFFFFFF
const USER_MAX_ADDRESS: usize = 0x7FFF_FFFF_FFFF;

pub const STATUS_SUCCESS: u32 = 0x00000000;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x80000002;

/// Verify that a user-mode pointer is safe to read from.
/// 1. The address is within user-mode address space
/// 3. The entire range is within user-mode bounds
#[inline]
pub unsafe fn probe_for_read(address: *const u8, length: usize) -> Result<(), u32> {
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

    Ok(())
}

/// Verify that a user-mode pointer is safe to write to.
/// 1. The address is within user-mode address space
/// 3. The entire range is within user-mode bounds

#[inline]
pub unsafe fn probe_for_write(address: *mut u8, length: usize) -> Result<(), u32> {
    // Reuse read validation
    probe_for_read(address as *const u8, length)?;


    Ok(())
}

#[inline]
pub unsafe fn probe_for_read_aligned(
    address: *const u8,
    length: usize,
    alignment: usize,
) -> Result<(), u32> {
    probe_for_read(address, length)?;

    if (address as usize) % alignment != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }

    Ok(())
}

#[inline]
pub unsafe fn probe_for_write_aligned(
    address: *mut u8,
    length: usize,
    alignment: usize,
) -> Result<(), u32> {
    probe_for_write(address, length)?;

    if (address as usize) % alignment != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }

    Ok(())
}

/// Validate a user-mode string pointer (null-terminated)
/// Validates that a null-terminated string is entirely within user-mode
pub unsafe fn probe_for_read_string(
    address: *const u8,
    max_length: usize,
) -> Result<usize, u32> {
    if address.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    let addr = address as usize;

    if addr >= USER_MAX_ADDRESS {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    let mut len = 0;
    while len < max_length {
        // Check if this byte is still in user space
        probe_for_read(address.add(len), 1)?;

        if *address.add(len) == 0 {
            return Ok(len);
        }

        len += 1;
    }

    Err(STATUS_INVALID_PARAMETER)
}

/// Validate a user-mode Unicode string pointer (null-terminated UTF-16)
/// user-mode address space, up to max_length characters.
pub unsafe fn probe_for_read_unicode_string(
    address: *const u16,
    max_length: usize,
) -> Result<usize, u32> {
    if address.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    let addr = address as usize;

    if addr >= USER_MAX_ADDRESS || addr % 2 != 0 {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    let mut len = 0;
    while len < max_length {
        // Check if this character is still in user space
        probe_for_read(address.add(len) as *const u8, 2)?;

        if *address.add(len) == 0 {
            return Ok(len);
        }

        len += 1;
    }

    Err(STATUS_INVALID_PARAMETER)
}

#[macro_export]
macro_rules! probe_read {
    ($ptr:expr, $size:expr) => {
        unsafe {
            $crate::arch::x86_64::syscall_validation::probe_for_read(
                $ptr as *const u8,
                $size,
            )?
        }
    };
}

#[macro_export]
macro_rules! probe_write {
    ($ptr:expr, $size:expr) => {
        unsafe {
            $crate::arch::x86_64::syscall_validation::probe_for_write(
                $ptr as *mut u8,
                $size,
            )?
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

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
        unsafe {
            // Valid user-mode address (we can't actually read it, but validation should pass)
            let result = probe_for_read(0x1000 as *const u8, 100);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_probe_alignment() {
        unsafe {
            assert_eq!(
                probe_for_read_aligned(0x1001 as *const u8, 8, 8),
                Err(STATUS_DATATYPE_MISALIGNMENT)
            );

            let result = probe_for_read_aligned(0x1000 as *const u8, 8, 8);
            assert!(result.is_ok());
        }
    }
}
