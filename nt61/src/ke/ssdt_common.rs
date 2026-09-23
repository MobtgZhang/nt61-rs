//! System Service Descriptor Table (SSDT) - Architecture-Independent Framework
//!
//! This module provides a unified system call dispatch framework that works
//! across all supported architectures (x86_64, aarch64, riscv64, loongarch64).
//!
//! # Architecture-Specific Implementation
//!
//! Each architecture implements:
//! - System call entry mechanism (SYSCALL/SVC/ECALL)
//! - Register saving/restoration
//! - System call number extraction
//! - Argument passing according to ABI
//!
//! # Task 4.1: Architecture-Independent SSDT Framework

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

/// Maximum number of system calls supported
pub const MAX_SYSCALLS: usize = 1024;

/// System call handler function pointer type
///
/// Takes system call arguments and returns a result code (NTSTATUS)
pub type SyscallHandler = unsafe extern "C" fn(
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> u32;

/// System Service Descriptor Table Entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SsdtEntry {
    /// Pointer to the system call handler
    pub handler: SyscallHandler,

    /// Number of arguments this system call expects
    pub arg_count: u8,

    /// System call name (for debugging)
    pub name: [u8; 64],
}

impl SsdtEntry {
    /// Create a new SSDT entry

    pub const fn new(handler: SyscallHandler, arg_count: u8, name: &str) -> Self {
        let mut name_bytes = [0u8; 64];
        let bytes = name.as_bytes();
        let len = if bytes.len() > 63 { 63 } else { bytes.len() };

        let mut i = 0;
        while i < len {
            name_bytes[i] = bytes[i];
            i += 1;
        }

        Self {
            handler,
            arg_count,
            name: name_bytes,
        }
    }

    /// Get the system call name as a string
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.name[..end]).unwrap_or("<invalid>")
    }
}

/// System Service Descriptor Table
pub struct Ssdt {
    /// Table of system call entries
    entries: Spinlock<Vec<Option<SsdtEntry>>>,

    /// Number of registered system calls
    count: AtomicUsize,
}

impl Ssdt {
    /// Create a new SSDT
    pub const fn new() -> Self {
        Self {
            entries: Spinlock::new(Vec::new()),
            count: AtomicUsize::new(0),
        }
    }

    /// Initialize the SSDT with the given capacity
    pub fn init(&self, capacity: usize) {
        let mut entries = self.entries.lock();
        entries.resize(capacity, None);
    }

    /// Register a system call handler
    ///
    /// # Safety
    /// The handler must be a valid function pointer that follows the syscall ABI
    pub unsafe fn register(
        &self,
        syscall_number: usize,
        handler: SyscallHandler,
        arg_count: u8,
        name: &str,
    ) -> Result<(), &'static str> {
        if syscall_number >= MAX_SYSCALLS {
            return Err("System call number out of range");
        }

        let mut entries = self.entries.lock();

        if entries.len() <= syscall_number {
            entries.resize(syscall_number + 1, None);
        }

        let entry = SsdtEntry::new(handler, arg_count, name);
        entries[syscall_number] = Some(entry);
        self.count.fetch_add(1, Ordering::Release);

        Ok(())
    }

    /// Dispatch a system call
    ///
    /// # Safety
    /// This function must be called from a valid system call context with
    /// proper arguments
    pub unsafe fn dispatch(
        &self,
        syscall_number: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> u32 {
        let entries = self.entries.lock();

        if syscall_number >= entries.len() {
            return STATUS_INVALID_SYSTEM_SERVICE;
        }

        if let Some(entry) = &entries[syscall_number] {
            (entry.handler)(arg1, arg2, arg3, arg4, arg5, arg6)
        } else {
            STATUS_INVALID_SYSTEM_SERVICE
        }
    }

    /// Get the number of registered system calls
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Get information about a system call
    pub fn get_info(&self, syscall_number: usize) -> Option<SsdtEntry> {
        let entries = self.entries.lock();
        entries.get(syscall_number).and_then(|e| *e)
    }
}

/// Global SSDT instance
static GLOBAL_SSDT: Ssdt = Ssdt::new();

/// NTSTATUS codes
pub const STATUS_SUCCESS: u32 = 0x00000000;
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000001C;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC0000002;

/// Initialize the architecture-independent SSDT framework
pub fn init() {
    GLOBAL_SSDT.init(MAX_SYSCALLS);
    crate::hal::serial::write_string("[SSDT] Architecture-independent framework initialized\r\n");
}

/// Register a system call in the global SSDT
///
/// # Safety
/// The handler must be a valid function pointer
pub unsafe fn register_syscall(
    number: usize,
    handler: SyscallHandler,
    arg_count: u8,
    name: &str,
) -> Result<(), &'static str> {
    GLOBAL_SSDT.register(number, handler, arg_count, name)
}

/// Dispatch a system call through the global SSDT
///
/// # Safety
/// Must be called from valid syscall context
pub unsafe fn dispatch_syscall(
    number: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> u32 {
    GLOBAL_SSDT.dispatch(number, arg1, arg2, arg3, arg4, arg5, arg6)
}

/// Get SSDT statistics
pub fn get_stats() -> (usize, usize) {
    (GLOBAL_SSDT.count(), MAX_SYSCALLS)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn test_handler(
        _a1: usize, _a2: usize, _a3: usize,
        _a4: usize, _a5: usize, _a6: usize
    ) -> u32 {
        STATUS_SUCCESS
    }

    #[test]
    fn test_ssdt_registration() {
        let ssdt = Ssdt::new();
        ssdt.init(1024);

        unsafe {
            let result = ssdt.register(0, test_handler, 0, "TestSyscall");
            assert!(result.is_ok());
            assert_eq!(ssdt.count(), 1);
        }
    }

    #[test]
    fn test_ssdt_dispatch() {
        let ssdt = Ssdt::new();
        ssdt.init(1024);

        unsafe {
            ssdt.register(42, test_handler, 0, "TestSyscall").unwrap();
            let result = ssdt.dispatch(42, 0, 0, 0, 0, 0, 0);
            assert_eq!(result, STATUS_SUCCESS);
        }
    }
}
