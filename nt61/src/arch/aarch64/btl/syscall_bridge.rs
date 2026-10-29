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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeResult {
    /// Raw NTSTATUS returned by the native SSDT handler.
    pub result: u64,
    /// NTSTATUS for a failure before dispatch; zero after dispatch.
    pub status: u32,
}

use crate::arch::common::btl::abi::GuestAbi;
use crate::arch::common::btl::memory::{GuestMemory, NullGuestMemory};
use crate::arch::common::btl::syscall::{dispatch_nt_syscall, BridgeOutcome};

fn bridge_abi(
    abi: GuestAbi,
    syscall_num: u32,
    args: &[u64],
    memory: &mut dyn GuestMemory,
) -> BridgeResult {
    let outcome = unsafe { dispatch_nt_syscall(abi, syscall_num, args, memory) };
    match outcome {
        BridgeOutcome::Dispatched(status) => BridgeResult {
            result: status as u64,
            status: 0,
        },
        failure => BridgeResult {
            result: 0,
            status: failure.status(),
        },
    }
}

/// Translate an x86_64 syscall into the AArch64 native kernel path.
///
/// `args` is the guest register file indexed by `X86Reg`. Numbers not
/// present in the NT SSDT fail closed with `STATUS_INVALID_SYSTEM_SERVICE`.
pub fn bridge_x86_64(syscall_num: u32, args: &[u64]) -> BridgeResult {
    let mut memory = NullGuestMemory;
    bridge_abi(GuestAbi::X86_64, syscall_num, args, &mut memory)
}

/// Translate an x86_64 syscall with access to the guest address space.
pub fn bridge_x86_64_memory(
    syscall_num: u32,
    args: &[u64],
    memory: &mut dyn GuestMemory,
) -> BridgeResult {
    bridge_abi(GuestAbi::X86_64, syscall_num, args, memory)
}

/// Translate an ARM32 syscall. `args[0..4]` are guest R0-R3.
pub fn bridge_arm32(syscall_num: u32, args: &[u64]) -> BridgeResult {
    let mut memory = NullGuestMemory;
    bridge_abi(GuestAbi::Arm32, syscall_num, args, &mut memory)
}

/// Translate an ARM32 syscall with access to the guest address space.
pub fn bridge_arm32_memory(
    syscall_num: u32,
    args: &[u64],
    memory: &mut dyn GuestMemory,
) -> BridgeResult {
    bridge_abi(GuestAbi::Arm32, syscall_num, args, memory)
}

/// Translate an x86_32 syscall. Arguments are read from the guest
/// argument block addressed by guest EDX.
pub fn bridge_x86_32_memory(
    syscall_num: u32,
    args: &[u64],
    memory: &mut dyn GuestMemory,
) -> BridgeResult {
    bridge_abi(GuestAbi::X86_32, syscall_num, args, memory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::common::btl::memory::{FlatPaging, GuestAddressSpace};
    use crate::ke::ssdt_common::{register_syscall, SyscallArguments, STATUS_SUCCESS};
    use core::sync::atomic::{AtomicU64, Ordering};

    static LAST_ARG: AtomicU64 = AtomicU64::new(0);

    unsafe extern "C" fn capture_handler(args: &SyscallArguments) -> u32 {
        LAST_ARG.store(args.register_args[0] as u64, Ordering::SeqCst);
        STATUS_SUCCESS
    }

    const TEST_SERVICE: u32 = 0x3F3;

    #[test]
    fn unregistered_services_fail_closed_with_ntstatus() {
        const UNREGISTERED: u32 = 0xFFFF;
        let invalid = BridgeOutcome::InvalidService.status();
        let x64 = bridge_x86_64(UNREGISTERED, &[0; 16]);
        assert_eq!(x64.result, 0);
        assert_eq!(x64.status, invalid);

        let arm32 = bridge_arm32(UNREGISTERED, &[0; 8]);
        assert_eq!(arm32.result, 0);
        assert_eq!(arm32.status, invalid);
    }

    #[test]
    fn x86_64_service_dispatches_normalised_arguments() {
        unsafe {
            register_syscall(TEST_SERVICE as usize, capture_handler, 1, "btl_a64").unwrap();
        }
        let mut args = alloc::vec![0u64; 17];
        args[crate::arch::common::btl::ir::X86Reg::R10 as usize] = 0xBEEF;
        let mut memory = GuestAddressSpace::new(FlatPaging {
            base: core::ptr::null_mut(),
            len: 0,
        });
        let result = bridge_x86_64_memory(TEST_SERVICE, &args, &mut memory);
        assert_eq!(result, BridgeResult { result: STATUS_SUCCESS as u64, status: 0 });
        assert_eq!(LAST_ARG.load(Ordering::SeqCst), 0xBEEF);
    }

    #[test]
    fn x86_32_memory_fault_fails_closed() {
        let mut args = alloc::vec![0u64; 17];
        args[crate::arch::common::btl::ir::X86Reg::Rdx as usize] = 0x1000;
        let mut memory = GuestAddressSpace::new(FlatPaging {
            base: core::ptr::null_mut(),
            len: 0,
        });
        let result = bridge_x86_32_memory(TEST_SERVICE, &args, &mut memory);
        assert_eq!(result, BridgeResult {
            result: 0,
            status: BridgeOutcome::MemoryFault.status(),
        });
    }
}
