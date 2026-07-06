//! BTL syscall bridge.
//!
//! Maps guest (`x86_64`, `x86_32`, `AArch32`) system calls to the
//! NT 6.1 native API exposed by the AArch64 kernel. Currently a
//! stub. A full implementation covers:
//!
//! 1. Linux x86_64 syscall numbers (e.g. `sys_read`, `sys_write`).
//! 2. Windows x86_64 SSDT entries (`ntdll.dll!NtCreateFile`, etc.).
//! 3. ARMv7 SVC numbers (Linux + Android ABI).
//!
//! ## Calling-convention translation
//!
//! Each guest ABI has a different parameter passing convention.
//! The bridge normalises them to the AArch64 AAPCS64 convention
//! (X0..X7 parameter registers, X8 indirect result location,
//! X16 = syscall number) before forwarding to
//! [`crate::arch::aarch64::syscall::syscall_dispatch_with_tf`].

/// Syscall bridge result.
#[derive(Debug, Clone, Copy)]
pub struct BridgeResult {
    pub result: u64,
    pub errno_or_status: i64,
}

/// Translate an x86_64 syscall into the AArch64 native kernel
/// path.
pub fn bridge_x86_64(_syscall_num: u32, _args: &[u64]) -> BridgeResult {
    BridgeResult { result: 0, errno_or_status: -1 }
}

/// Translate an AArch32 syscall.
pub fn bridge_arm32(_syscall_num: u32, _args: &[u64]) -> BridgeResult {
    BridgeResult { result: 0, errno_or_status: -1 }
}
