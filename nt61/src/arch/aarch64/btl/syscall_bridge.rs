//! BTL syscall bridge.
//!
//! Translates Windows NT 6.1 guest (`x86_64`, `x86_32`, `AArch32`)
//! system calls to the native API exposed by the AArch64 kernel.
//!
//! ## Calling-convention translation
//!
//! Each guest ABI has a different parameter passing convention.
//! The bridge normalises them to the AArch64 AAPCS64 convention
//! (X0..X7 parameter registers) before forwarding to the common
//! NT SSDT used by the AArch64 native dispatcher.

/// Syscall bridge result.
#[derive(Debug, Clone, Copy)]
pub struct BridgeResult {
    /// Raw NTSTATUS returned by the native SSDT handler.
    pub result: u64,
    /// NTSTATUS for a failure before dispatch; zero after dispatch.
    pub status: u32,
}

const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const MAX_BRIDGED_REGISTER_ARGS: usize = 4;

/// Map the x86_64 guest register file to the AArch64 integer argument
/// registers. Windows x64 NT calls pass the first four arguments in
/// R10, RDX, R8, and R9; additional arguments are not yet captured by
/// the shared BTL IR and are therefore not forwarded.
fn normalize_x86_64_args(args: &[u64]) -> [usize; 8] {
    let mut out = [0usize; 8];
    let arg_regs = [
        crate::arch::common::btl::ir::X86Reg::R10,
        crate::arch::common::btl::ir::X86Reg::Rdx,
        crate::arch::common::btl::ir::X86Reg::R8,
        crate::arch::common::btl::ir::X86Reg::R9,
    ];
    for (slot, reg) in arg_regs.iter().enumerate() {
        let index = *reg as usize;
        if let Some(value) = args.get(index) {
            out[slot] = *value as usize;
        }
    }
    out
}

/// Map guest ARM32 R0-R3 to the AArch64 argument registers. Windows
/// ARM32 uses the AAPCS convention for the first four integer args.
fn normalize_arm32_args(args: &[u64]) -> [usize; 8] {
    let mut out = [0usize; 8];
    for (slot, value) in args.iter().take(MAX_BRIDGED_REGISTER_ARGS).enumerate() {
        out[slot] = *value as usize;
    }
    out
}

fn dispatch_to_ssdt(number: u32, args: [usize; 8]) -> BridgeResult {
    match crate::ke::ssdt_common::get_info(number as usize) {
        Some(entry) if entry.arg_count as usize <= MAX_BRIDGED_REGISTER_ARGS => {
            let status = unsafe {
                crate::ke::ssdt_common::dispatch_syscall_with_stack(
                    number as usize,
                    args,
                    crate::ke::ssdt_common::INTEGER_REGISTER_ARGUMENTS,
                    0,
                )
            };
            BridgeResult {
                result: status as u64,
                status: 0,
            }
        }
        Some(_) => BridgeResult {
            result: 0,
            status: STATUS_NOT_IMPLEMENTED,
        },
        None => BridgeResult {
            result: 0,
            status: STATUS_INVALID_SYSTEM_SERVICE,
        },
    }
}

/// Translate an x86_64 syscall into the AArch64 native kernel path.
///
/// `args` is the guest register file indexed by `X86Reg`. Numbers not
/// present in the NT SSDT fail closed with `STATUS_INVALID_SYSTEM_SERVICE`.
pub fn bridge_x86_64(syscall_num: u32, args: &[u64]) -> BridgeResult {
    let normalized = normalize_x86_64_args(args);
    dispatch_to_ssdt(syscall_num, normalized)
}

/// Translate an ARM32 syscall. `args[0..4]` are guest R0-R3.
pub fn bridge_arm32(syscall_num: u32, args: &[u64]) -> BridgeResult {
    let normalized = normalize_arm32_args(args);
    dispatch_to_ssdt(syscall_num, normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_services_fail_closed_with_ntstatus() {
        const UNREGISTERED: u32 = 0xFFFF;
        let x64 = bridge_x86_64(UNREGISTERED, &[0; 16]);
        assert_eq!(x64.result, 0);
        assert_eq!(x64.status, STATUS_INVALID_SYSTEM_SERVICE);

        let arm32 = bridge_arm32(UNREGISTERED, &[0; 8]);
        assert_eq!(arm32.result, 0);
        assert_eq!(arm32.status, STATUS_INVALID_SYSTEM_SERVICE);
    }
}
