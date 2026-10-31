//! Shared BTL guest ABI normalisation.
//!
//! Windows NT 6.1 guest syscalls arrive in different register
//! conventions depending on the guest bitness. This module converts
//! the captured guest register file into the uniform argument layout
//! expected by the architecture-independent SSDT, so every non-x86
//! BTL backend (AArch64, LoongArch, RISC-V) shares one bridge.

/// Guest syscall ABI variants supported by the BTL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestAbi {
    /// 64-bit x86-64 guest (Windows x64 syscall convention).
    X86_64,
    /// 32-bit x86 guest (Windows x86 syscall convention).
    X86_32,
    /// 32-bit ARM guest (AAPCS convention).
    Arm32,
}

/// Number of integer-register arguments the BTL can bridge without
/// falling back to the guest stack. Windows x64 passes at most four
/// in registers; ARM32 passes four in R0-R3.
pub const MAX_BRIDGED_REGISTER_ARGS: usize = 4;

/// Normalised syscall arguments in the architecture-independent SSDT
/// register layout.
#[derive(Clone, Copy, Debug)]
pub struct NormalizedSyscall {
    /// First `integer_register_count` argument values.
    pub register_args: [usize; 8],
    /// Number of valid slots in `register_args`.
    pub integer_register_count: usize,
    /// Guest stack pointer carrying trailing (stack) arguments, or
    /// `None` when the ABI passes everything in registers.
    pub stack_arg_base: Option<u64>,
}

impl NormalizedSyscall {
    pub const fn empty() -> Self {
        Self {
            register_args: [0; 8],
            integer_register_count: 0,
            stack_arg_base: None,
        }
    }
}

use super::ir::X86Reg;

/// Normalise a guest register file into the SSDT argument layout.
///
/// `guest_regs` is indexed by `X86Reg as usize` for x86 guests and by
/// raw register number for ARM32 guests.
pub fn normalize_syscall_args(abi: GuestAbi, guest_regs: &[u64]) -> NormalizedSyscall {
    let mut out = NormalizedSyscall::empty();
    match abi {
        GuestAbi::X86_64 => {
            // Windows x64: syscall number in EAX, first four integer
            // arguments in R10 (replacing RCX), RDX, R8, R9.
            const ARG_REGS: [X86Reg; MAX_BRIDGED_REGISTER_ARGS] =
                [X86Reg::R10, X86Reg::Rdx, X86Reg::R8, X86Reg::R9];
            for (slot, reg) in ARG_REGS.iter().enumerate() {
                if let Some(value) = guest_regs.get(*reg as usize) {
                    out.register_args[slot] = *value as usize;
                }
            }
            out.integer_register_count = MAX_BRIDGED_REGISTER_ARGS;
            out.stack_arg_base = guest_regs.get(X86Reg::Rsp as usize).copied();
        }
        GuestAbi::Arm32 => {
            // AAPCS: first four integer arguments in R0-R3.
            for slot in 0..MAX_BRIDGED_REGISTER_ARGS {
                if let Some(value) = guest_regs.get(slot) {
                    out.register_args[slot] = *value as usize;
                }
            }
            out.integer_register_count = MAX_BRIDGED_REGISTER_ARGS;
            out.stack_arg_base = guest_regs.get(13).copied();
        }
        GuestAbi::X86_32 => {
            // Windows x86: EAX = service index, EDX = pointer to the
            // caller's argument block on the user stack. All integer
            // arguments live in that block; the bridge copies them
            // out through guest memory before dispatch.
            if let Some(edx) = guest_regs.get(X86Reg::Rdx as usize) {
                out.stack_arg_base = Some(*edx);
            }
        }
    }
    out
}

/// Host architectures that consume the normalised argument layout.
///
/// The SSDT register slots are identical across hosts; this enum
/// exists so tests can assert the per-host argument-register names
/// that the arch trap stubs must fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostArch {
    Aarch64,
    LoongArch64,
    RiscV64,
}

impl HostArch {
    /// Number of argument registers in the host AAPCS64 / LA64 /
    /// RV64 calling convention (X0-X7 / A0-A7 / a0-a7).
    pub const fn argument_register_count(self) -> usize {
        8
    }

    /// Human-readable register names, first `count` are argument
    /// registers. Used for diagnostics and tests.
    pub const fn argument_register_names(self) -> [&'static str; 8] {
        match self {
            HostArch::Aarch64 => ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            HostArch::LoongArch64 => ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
            HostArch::RiscV64 => ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use HostArch::*;

    fn x64_regs(r10: u64, rdx: u64, r8: u64, r9: u64) -> alloc::vec::Vec<u64> {
        let mut regs = alloc::vec![0u64; 17];
        regs[X86Reg::R10 as usize] = r10;
        regs[X86Reg::Rdx as usize] = rdx;
        regs[X86Reg::R8 as usize] = r8;
        regs[X86Reg::R9 as usize] = r9;
        regs
    }

    #[test]
    fn x86_64_uses_windows_x64_convention() {
        let mut regs = x64_regs(0xAA, 0xBB, 0xCC, 0xDD);
        regs[X86Reg::Rsp as usize] = 0x1_2000;
        let n = normalize_syscall_args(GuestAbi::X86_64, &regs);
        assert_eq!(n.integer_register_count, 4);
        assert_eq!(n.register_args[0], 0xAA); // r10
        assert_eq!(n.register_args[1], 0xBB); // rdx
        assert_eq!(n.register_args[2], 0xCC); // r8
        assert_eq!(n.register_args[3], 0xDD); // r9
        assert_eq!(n.stack_arg_base, Some(0x1_2000));
    }

    #[test]
    fn arm32_uses_aapcs_convention() {
        let regs = alloc::vec![0x11, 0x22, 0x33, 0x44];
        let n = normalize_syscall_args(GuestAbi::Arm32, &regs);
        assert_eq!(n.integer_register_count, 4);
        assert_eq!(n.register_args[0], 0x11);
        assert_eq!(n.register_args[3], 0x44);
        assert!(n.stack_arg_base.is_none());
    }

    #[test]
    fn arm32_records_stack_pointer_for_trailing_args() {
        let mut regs = alloc::vec![0u64; 16];
        regs[13] = 0x1_3000;
        let n = normalize_syscall_args(GuestAbi::Arm32, &regs);
        assert_eq!(n.stack_arg_base, Some(0x1_3000));
    }

    #[test]
    fn x86_32_records_stack_arg_base_from_edx() {
        let mut regs = alloc::vec![0u64; 17];
        regs[X86Reg::Rdx as usize] = 0x7FF0_1234;
        let n = normalize_syscall_args(GuestAbi::X86_32, &regs);
        assert_eq!(n.integer_register_count, 0);
        assert_eq!(n.stack_arg_base, Some(0x7FF0_1234));
    }

    #[test]
    fn host_argument_register_names() {
        for (arch, first) in [(Aarch64, "x0"), (LoongArch64, "a0"), (RiscV64, "a0")] {
            assert_eq!(arch.argument_register_count(), 8);
            assert_eq!(arch.argument_register_names()[0], first);
        }
    }
}
