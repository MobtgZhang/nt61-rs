//! BTL — system-call bridge directory.

#![cfg(target_arch = "loongarch64")]

pub mod nt;
pub mod win32;

use crate::arch::common::btl::abi::GuestAbi;
use crate::arch::common::btl::memory::{GuestMemory, NullGuestMemory};
use crate::arch::common::btl::syscall::{dispatch_nt_syscall, BridgeOutcome};

/// Result of a bridged guest syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeResult {
    pub result: u64,
    pub status: u32,
}

fn bridge_abi(
    abi: GuestAbi,
    number: u32,
    args: &[u64],
    memory: &mut dyn GuestMemory,
) -> BridgeResult {
    let outcome = unsafe { dispatch_nt_syscall(abi, number, args, memory) };
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

/// Bridge an x86_64 guest syscall using the common NT SSDT.
pub fn bridge_x86_64(number: u32, args: &[u64]) -> BridgeResult {
    let mut memory = NullGuestMemory;
    bridge_abi(GuestAbi::X86_64, number, args, &mut memory)
}

/// Bridge an x86_64 guest syscall with guest-memory access.
pub fn bridge_x86_64_memory(
    number: u32,
    args: &[u64],
    memory: &mut dyn GuestMemory,
) -> BridgeResult {
    bridge_abi(GuestAbi::X86_64, number, args, memory)
}

/// Bridge an ARM32 guest syscall using the common NT SSDT.
pub fn bridge_arm32(number: u32, args: &[u64]) -> BridgeResult {
    let mut memory = NullGuestMemory;
    bridge_abi(GuestAbi::Arm32, number, args, &mut memory)
}

/// Bridge an x86_32 guest syscall; arguments are read from guest EDX.
pub fn bridge_x86_32_memory(
    number: u32,
    args: &[u64],
    memory: &mut dyn GuestMemory,
) -> BridgeResult {
    bridge_abi(GuestAbi::X86_32, number, args, memory)
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

    const TEST_SERVICE: u32 = 0x3F4;

    #[test]
    fn x86_64_service_dispatches_normalised_arguments() {
        unsafe {
            register_syscall(TEST_SERVICE as usize, capture_handler, 1, "btl_la64").unwrap();
        }
        let mut args = alloc::vec![0u64; 17];
        args[crate::arch::common::btl::ir::X86Reg::R10 as usize] = 0x1357;
        let mut memory = GuestAddressSpace::new(FlatPaging {
            base: core::ptr::null_mut(),
            len: 0,
        });
        let result = bridge_x86_64_memory(TEST_SERVICE, &args, &mut memory);
        assert_eq!(
            result,
            BridgeResult {
                result: STATUS_SUCCESS as u64,
                status: 0
            }
        );
        assert_eq!(LAST_ARG.load(Ordering::SeqCst), 0x1357);
    }

    #[test]
    fn unregistered_service_fails_closed() {
        let result = bridge_x86_64(0xFFFF, &[0u64; 17]);
        assert_eq!(result.status, BridgeOutcome::InvalidService.status());
    }
}

pub fn init() {}
