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
//! marshalling for `NtQueryInformationFile` and friends, and
//! Phase 6 instruments hot services with branch counters.

#![cfg(feature = "btl")]

/// Maximum native NT service number we route.
///
/// Phase 4 accepts the same range as the native RV64 dispatcher
/// (defined in [`crate::arch::riscv64::syscall`]). Phase 5
/// expands to the full NT syscall table.
pub const MAX_SERVICE: u64 = 0x100;

/// Outcome of a BTL syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtlSyscallResult {
    /// The service was forwarded to the native NT dispatcher.
    Handled { result: u64 },
    /// The service number is unknown to the BTL.
    NotHandled,
}

/// Glue dispatcher. The arguments arrive in the same calling
/// convention as the native RV64 NT dispatcher (a0..a5).
pub fn btl_syscall_dispatch(num: u64, a0: u64, a1: u64, a2: u64,
                            a3: u64, a4: u64) -> BtlSyscallResult {
    if num >= MAX_SERVICE {
        return BtlSyscallResult::NotHandled;
    }
    // Phase 4: forward directly to the native RV64 dispatcher. We
    // ignore the upper-range services for now.
    let result = crate::arch::riscv64::syscall::dispatch_syscall_raw(num,
                                                                     [a0, a1, a2, a3, a4]);
    BtlSyscallResult::Handled { result }
}

pub fn init() {}

pub fn smoke_test() -> bool {
    matches!(btl_syscall_dispatch(0, 0, 0, 0, 0, 0), BtlSyscallResult::Handled { .. })
}