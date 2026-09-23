//! RISC-V64 System Service Descriptor Table
//!
//! # Task 4.3: RISC-V64 SSDT Implementation
//!
//! This module implements the system call dispatch mechanism for RISC-V64
//! architecture using the ECALL instruction.
//!
//! # System Call Convention (RISC-V64)
//! - System call number: A7 register
//! - Arguments: A0-A5 (up to 6 arguments)
//! - Return value: A0
//! - ECALL instruction triggers trap to S-mode

use crate::ke::ssdt_common::{self, STATUS_SUCCESS, STATUS_NOT_IMPLEMENTED};

/// System call entry point for RISC-V64
///
/// This function is called from the ECALL trap handler
///
/// # Safety
/// Must be called with valid register context from ECALL handler
#[no_mangle]
pub unsafe extern "C" fn riscv64_syscall_entry(
    syscall_number: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> u32 {
    ssdt_common::dispatch_syscall(
        syscall_number,
        arg1, arg2, arg3, arg4, arg5, arg6
    )
}

/// Register a system call for RISC-V64
///
/// # Safety
/// Handler must follow RISC-V64 calling convention
pub unsafe fn register_syscall(
    number: usize,
    handler: ssdt_common::SyscallHandler,
    arg_count: u8,
    name: &str,
) -> Result<(), &'static str> {
    ssdt_common::register_syscall(number, handler, arg_count, name)
}

/// Initialize RISC-V64 SSDT
pub fn init() {
    crate::hal::serial::write_string("[SSDT] RISC-V64 system call dispatch initialized\r\n");

    // Register common system calls
    unsafe {
        register_common_syscalls();
    }
}

/// Register common NT system calls
unsafe fn register_common_syscalls() {
    // NtClose
    let _ = register_syscall(0x000F, nt_close, 1, "NtClose");

    // NtQuerySystemInformation
    let _ = register_syscall(0x0036, nt_query_system_information, 4, "NtQuerySystemInformation");

    // NtCreateFile
    let _ = register_syscall(0x0055, nt_create_file, 11, "NtCreateFile");

    // Add more system calls as needed
}

// Placeholder implementations
unsafe extern "C" fn nt_close(_handle: usize, _: usize, _: usize, _: usize, _: usize, _: usize) -> u32 {
    STATUS_SUCCESS
}

unsafe extern "C" fn nt_query_system_information(
    _class: usize, _buffer: usize, _length: usize, _ret_length: usize, _: usize, _: usize
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

unsafe extern "C" fn nt_create_file(
    _handle: usize, _access: usize, _obj_attr: usize, _io_status: usize,
    _alloc_size: usize, _attr: usize, _share: usize, _disposition: usize,
    _options: usize, _ea: usize, _ea_length: usize
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// RISC-V64-specific system call statistics
pub fn get_stats() -> (usize, usize) {
    ssdt_common::get_stats()
}
