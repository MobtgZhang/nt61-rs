//! BTL syscall bridge.
//!
//! Translates guest (`x86_64`, `x86_32`, `AArch32`) system calls to
//! the NT 6.1 native API exposed by the AArch64 kernel. The bridge
//! currently fails closed: Linux and NT system calls share neither
//! their number space nor their argument layout (`read(fd, buf, len)`
//! vs. `NtReadFile(handle, event, apc, apc_ctx, iosb, buf, len, off,
//! key)`), so forwarding guest numbers straight into the NT SSDT
//! would invoke an arbitrary, semantically unrelated handler. A full
//! implementation covers:
//!
//! 1. Linux x86_64 syscall numbers (e.g. `sys_read`, `sys_write`).
//! 2. Windows x86_64 SSDT entries (`ntdll.dll!NT_CREATE_FILE`, etc.).
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

/// Linux x86_64 `errno` for "operation not implemented on this target".
const ENOSYS: i64 = -38;

/// Translate an x86_64 syscall into the AArch64 native kernel path.
///
/// Fails closed with `-ENOSYS`: no Linux-to-NT translation exists yet,
/// and pretending the guest number is an NT SSDT index would dispatch
/// the wrong handler with attacker-controlled arguments.
pub fn bridge_x86_64(_syscall_num: u32, _args: &[u64]) -> BridgeResult {
    BridgeResult { result: 0, errno_or_status: ENOSYS }
}

/// Translate an AArch32 syscall. Fails closed for the same reason as
/// [`bridge_x86_64`].
pub fn bridge_arm32(_syscall_num: u32, _args: &[u64]) -> BridgeResult {
    BridgeResult { result: 0, errno_or_status: ENOSYS }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridges_fail_closed_until_translation_exists() {
        let x64 = bridge_x86_64(0, &[]);
        assert_eq!(x64.result, 0);
        assert_eq!(x64.errno_or_status, ENOSYS);

        let arm32 = bridge_arm32(0, &[]);
        assert_eq!(arm32.result, 0);
        assert_eq!(arm32.errno_or_status, ENOSYS);
    }
}
