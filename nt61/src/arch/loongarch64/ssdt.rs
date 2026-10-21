//! LoongArch64 System Service Descriptor Table
//!
//! # Task 4.4: LoongArch64 SSDT Implementation
//!
//! This module implements the system call dispatch mechanism for LoongArch64
//! architecture using the SYSCALL instruction.
//!
//! # System Call Convention (LoongArch64)
//! - System call number: $a7 register
//! - Arguments: $a0-$a5 (up to 6 arguments)
//! - Return value: $a0
//! - SYSCALL instruction triggers exception

use crate::ke::ssdt_common;

/// System call entry point for LoongArch64
///
/// This function is called from the SYSCALL exception handler
///
/// # Safety
/// Must be called with valid register context from SYSCALL handler
#[no_mangle]
pub unsafe extern "C" fn loongarch64_syscall_entry(
    syscall_number: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    stack_pointer: usize,
) -> u32 {
    ssdt_common::dispatch_syscall_with_stack(
        syscall_number,
        [arg1, arg2, arg3, arg4, arg5, arg6, 0, 0],
        6,
        stack_pointer,
    )
}

/// Register a system call for LoongArch64
///
/// # Safety
/// Handler must follow LoongArch64 calling convention
pub unsafe fn register_syscall(
    number: usize,
    handler: ssdt_common::SyscallHandler,
    arg_count: u8,
    name: &str,
) -> Result<(), &'static str> {
    ssdt_common::register_syscall(number, handler, arg_count, name)
}

/// Initialize LoongArch64 SSDT
pub fn init() {
    crate::hal::serial::write_string("[SSDT] LoongArch64 system call dispatch initialized\r\n");

    ssdt_common::register_common_syscalls();
}

/// LoongArch64-specific system call statistics
pub fn get_stats() -> (usize, usize) {
    ssdt_common::get_stats()
}
