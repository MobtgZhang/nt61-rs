//! BTL syscall glue: maps guest x86 NT calls to the native NT
//! service table on the RISC-V host.
//!
//! Architecture (mirrors Windows ARM64 WoW64):
//!
//! 1. Guest raises `syscall` / `sysenter` with the NT service
//!    number in eax/edx. The BTL translator lowers this to an
//!    `IrOp::SyscallGlue` IR instruction that calls
//!    [`btl_syscall_dispatch`] with `a0 = eax`, `a1..a5 = e..edi`.
//! 2. We redirect control to the host's native NT service table;
//!    argument conversion is a no-op for the most common subset
//!    (file paths, kernel handles, MASM-style struct passing).
//! 3. The return value is laid back into `*a0` so the
//!    `RET` instruction from the translated block sees it in eax.
//!
//! Phase 4 scaffolds the call path. Phase 5 adds argument
//! marshalling for `NT_QUERY_INFORMATION_FILE` and friends, and
//! Phase 6 instruments hot services with branch counters.

#![cfg(any(feature = "btl", test))]

use crate::arch::common::btl::abi::GuestAbi;
use crate::arch::common::btl::syscall::{dispatch_nt_syscall, BridgeOutcome};

/// Outcome of a BTL syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtlSyscallResult {
    /// The service was forwarded to the native NT dispatcher.
    Handled { result: u64 },
    /// The service number is unknown to the BTL.
    NotHandled,
}

/// Result shape used by the runtime.
pub type BridgeResult = BtlSyscallResult;

/// Glue dispatcher. The arguments arrive in the same calling
/// convention as the native RV64 NT dispatcher (a0..a5).
pub fn btl_syscall_dispatch(
    num: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    _a4: u64,
) -> BtlSyscallResult {
    if num > u32::MAX as u64 {
        return BtlSyscallResult::NotHandled;
    }

    let mut guest_regs = [0u64; 17];
    guest_regs[crate::arch::common::btl::ir::X86Reg::Rax as usize] = num;
    guest_regs[crate::arch::common::btl::ir::X86Reg::R10 as usize] = a0;
    guest_regs[crate::arch::common::btl::ir::X86Reg::Rdx as usize] = a1;
    guest_regs[crate::arch::common::btl::ir::X86Reg::R8 as usize] = a2;
    guest_regs[crate::arch::common::btl::ir::X86Reg::R9 as usize] = a3;

    let mut memory = super::mem::guest_memory();
    let outcome =
        unsafe { dispatch_nt_syscall(GuestAbi::X86_64, num as u32, &guest_regs, &mut memory) };
    match outcome {
        BridgeOutcome::Dispatched(status) => BtlSyscallResult::Handled {
            result: status as u64,
        },
        BridgeOutcome::InvalidService => BtlSyscallResult::NotHandled,
        failure => BtlSyscallResult::Handled {
            result: failure.status() as u64,
        },
    }
}

pub fn init() {}

pub fn smoke_test() -> bool {
    matches!(
        btl_syscall_dispatch(0, 0, 0, 0, 0, 0),
        BtlSyscallResult::Handled { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ke::ssdt_common::{register_syscall, SyscallArguments, STATUS_SUCCESS};

    const TEST_SERVICE: u64 = 0x3F5;

    unsafe extern "C" fn capture_handler(args: &SyscallArguments) -> u32 {
        assert_eq!(args.register_args[0], 0x2468);
        STATUS_SUCCESS
    }

    #[test]
    fn x86_64_service_dispatches_normalised_arguments() {
        unsafe {
            register_syscall(TEST_SERVICE as usize, capture_handler, 1, "btl_rv64").unwrap();
        }
        let result = btl_syscall_dispatch(TEST_SERVICE, 0x2468, 0, 0, 0, 0);
        assert_eq!(
            result,
            BtlSyscallResult::Handled {
                result: STATUS_SUCCESS as u64
            }
        );
    }

    #[test]
    fn invalid_service_fails_closed() {
        assert_eq!(
            btl_syscall_dispatch(0xFFFF, 0, 0, 0, 0, 0),
            BtlSyscallResult::NotHandled
        );
    }
}
