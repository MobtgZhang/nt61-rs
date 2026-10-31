//! Shared BTL NT syscall bridging.
//!
//! Normalises guest register files via [`super::abi`] and dispatches
//! through the architecture-independent SSDT. Every non-x86 BTL
//! backend (AArch64, LoongArch, RISC-V) re-uses this path so a
//! bridged NT service behaves identically regardless of host ISA.

use super::abi::{normalize_syscall_args, GuestAbi, MAX_BRIDGED_REGISTER_ARGS};
use super::memory::GuestMemory;

/// Result of routing a guest syscall through the NT SSDT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// Handler ran; value is the raw NTSTATUS.
    Dispatched(u32),
    /// Service number not registered in the SSDT.
    InvalidService,
    /// A guest argument block or stack frame could not be read.
    MemoryFault,
}

const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

impl BridgeOutcome {
    /// NTSTATUS to surface when the guest's syscall instruction
    /// returns without a handler-written result.
    pub const fn status(self) -> u32 {
        match self {
            Self::Dispatched(status) => status,
            Self::InvalidService => STATUS_INVALID_SYSTEM_SERVICE,
            Self::MemoryFault => STATUS_ACCESS_VIOLATION,
        }
    }
}

/// Read up to `count` 32-bit guest words into the first `count`
/// architecture-independent SSDT argument slots.
fn read_x86_32_stack_args(
    memory: &mut dyn GuestMemory,
    stack_base: u64,
    count: usize,
) -> Option<[usize; 8]> {
    const WORD_SIZE: usize = core::mem::size_of::<u32>();
    let mut raw = [0u8; 8 * WORD_SIZE];
    let bytes = count * WORD_SIZE;
    let n = memory.read_virt(stack_base, &mut raw[..bytes]);
    if n < bytes {
        return None;
    }

    let mut out = [0usize; 8];
    for (slot, value) in out.iter_mut().take(count).enumerate() {
        let lo = slot * WORD_SIZE;
        *value = u32::from_le_bytes(raw[lo..lo + WORD_SIZE].try_into().unwrap()) as usize;
    }
    Some(out)
}

/// Read up to `count` 64-bit guest words into `out`.
fn read_x86_64_stack_args_into(
    memory: &mut dyn GuestMemory,
    stack_base: u64,
    count: usize,
    out: &mut [usize],
) -> bool {
    if out.is_empty() {
        return true;
    }

    const WORD_SIZE: usize = core::mem::size_of::<u64>();
    let mut raw = [0u8; 4 * WORD_SIZE];
    let bytes = count * WORD_SIZE;
    let n = memory.read_virt(stack_base, &mut raw[..bytes]);
    if n < bytes {
        return false;
    }

    for (slot, value) in out.iter_mut().enumerate().take(count) {
        let lo = slot * WORD_SIZE;
        *value = u64::from_le_bytes(raw[lo..lo + WORD_SIZE].try_into().unwrap()) as usize;
    }
    true
}

/// Bridge one guest syscall to the native NT SSDT.
///
/// # Safety
/// Must be called from a valid BTL syscall context. The SSDT handler
/// is invoked with guest-controlled argument values.
pub unsafe fn dispatch_nt_syscall(
    abi: GuestAbi,
    number: u32,
    guest_regs: &[u64],
    memory: &mut dyn GuestMemory,
) -> BridgeOutcome {
    let Some(entry) = crate::ke::ssdt_common::get_info(number as usize) else {
        return BridgeOutcome::InvalidService;
    };

    let arg_count = entry.arg_count as usize;
    let normalized = normalize_syscall_args(abi, guest_regs);
    let (register_args, register_count, stack_pointer) = match abi {
        GuestAbi::X86_64 => {
            if arg_count <= MAX_BRIDGED_REGISTER_ARGS {
                (normalized.register_args, arg_count, 0usize)
            } else {
                let register_count = arg_count.min(8);
                let stack_count = register_count - MAX_BRIDGED_REGISTER_ARGS;
                let Some(stack_base) = normalized.stack_arg_base else {
                    return BridgeOutcome::MemoryFault;
                };
                let stack_base = stack_base + core::mem::size_of::<u64>() as u64;
                let mut args = normalized.register_args;
                if !read_x86_64_stack_args_into(memory, stack_base, stack_count, &mut args[4..]) {
                    return BridgeOutcome::MemoryFault;
                }
                (
                    args,
                    register_count,
                    (stack_base + stack_count as u64 * 8) as usize,
                )
            }
        }
        GuestAbi::X86_32 => {
            let base = match normalized.stack_arg_base {
                Some(base) => base,
                None => return BridgeOutcome::MemoryFault,
            };
            let register_count = arg_count.min(8);
            match read_x86_32_stack_args(memory, base, register_count) {
                Some(args) => (
                    args,
                    register_count,
                    if arg_count > 8 {
                        (base + 8 * core::mem::size_of::<u32>() as u64) as usize
                    } else {
                        0
                    },
                ),
                None => return BridgeOutcome::MemoryFault,
            }
        }
        GuestAbi::Arm32 => {
            if arg_count <= MAX_BRIDGED_REGISTER_ARGS {
                (normalized.register_args, arg_count, 0usize)
            } else {
                let register_count = arg_count.min(8);
                let stack_count = register_count - MAX_BRIDGED_REGISTER_ARGS;
                let Some(stack_base) = normalized.stack_arg_base else {
                    return BridgeOutcome::MemoryFault;
                };
                let Some(stack_args) = read_x86_32_stack_args(memory, stack_base, stack_count)
                else {
                    return BridgeOutcome::MemoryFault;
                };
                let mut args = normalized.register_args;
                args[4..register_count].copy_from_slice(&stack_args[..stack_count]);
                (
                    args,
                    register_count,
                    (stack_base + stack_count as u64 * 4) as usize,
                )
            }
        }
    };

    let status = crate::ke::ssdt_common::dispatch_syscall_with_stack(
        number as usize,
        register_args,
        register_count,
        stack_pointer,
    );
    BridgeOutcome::Dispatched(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::common::btl::ir::X86Reg;
    use crate::ke::ssdt_common::{register_syscall, SyscallArguments, STATUS_SUCCESS};
    use core::sync::atomic::{AtomicU64, Ordering};

    static LAST_ARGS: AtomicU64 = AtomicU64::new(0);
    static LAST_STACK_ARG: AtomicU64 = AtomicU64::new(0);

    unsafe extern "C" fn capture_handler(args: &SyscallArguments) -> u32 {
        LAST_ARGS.store(args.register_args[0] as u64, Ordering::SeqCst);
        STATUS_SUCCESS
    }

    unsafe extern "C" fn capture_fifth_handler(args: &SyscallArguments) -> u32 {
        LAST_STACK_ARG.store(args.register_args[4] as u64, Ordering::SeqCst);
        STATUS_SUCCESS
    }

    const TEST_SERVICE_X86_64: usize = 0x3F2;
    const TEST_SERVICE_X86_32: usize = 0x3F3;
    const TEST_SERVICE_X86_64_STACK: usize = 0x3F4;
    const TEST_SERVICE_X86_32_WORD: usize = 0x3F5;

    struct NopMemory;
    impl GuestMemory for NopMemory {
        fn read_virt(&mut self, _va: u64, _buf: &mut [u8]) -> usize {
            0
        }

        fn write_virt(&mut self, _va: u64, _data: &[u8]) -> bool {
            false
        }
    }

    fn flat_memory(
        backing: &mut [u8],
    ) -> super::super::memory::GuestAddressSpace<super::super::memory::FlatPaging> {
        let paging = super::super::memory::FlatPaging {
            base: backing.as_mut_ptr(),
            len: backing.len(),
        };
        super::super::memory::GuestAddressSpace::new(paging)
    }

    #[test]
    fn x86_64_bridges_registered_service() {
        unsafe {
            register_syscall(TEST_SERVICE_X86_64, capture_handler, 1, "btl_test").unwrap();
        }
        let mut regs = alloc::vec![0u64; 17];
        regs[X86Reg::R10 as usize] = 0xBEEF;
        let mut mem = NopMemory;
        let out = unsafe {
            dispatch_nt_syscall(
                GuestAbi::X86_64,
                TEST_SERVICE_X86_64 as u32,
                &regs,
                &mut mem,
            )
        };
        assert_eq!(out, BridgeOutcome::Dispatched(STATUS_SUCCESS));
        assert_eq!(LAST_ARGS.load(Ordering::SeqCst), 0xBEEF);
    }

    #[test]
    fn unregistered_service_fails_closed() {
        let regs = alloc::vec![0u64; 17];
        let mut mem = NopMemory;
        let out = unsafe { dispatch_nt_syscall(GuestAbi::X86_64, 0xFFFF, &regs, &mut mem) };
        assert_eq!(out, BridgeOutcome::InvalidService);
    }

    #[test]
    fn x86_32_reads_args_from_guest_stack() {
        unsafe {
            register_syscall(TEST_SERVICE_X86_32, capture_handler, 2, "btl_test32").unwrap();
        }
        let mut backing = [0u8; 0x100];
        let mut mem = flat_memory(&mut backing);
        let arg_block: [u8; 8] = [
            0x42, 0, 0, 0, // arg0 = 0x42
            0x99, 0, 0, 0, // arg1 = 0x99
        ];
        assert!(mem.write_virt(0x40, &arg_block));

        let mut regs = alloc::vec![0u64; 17];
        regs[X86Reg::Rdx as usize] = 0x40;
        let out = unsafe {
            dispatch_nt_syscall(
                GuestAbi::X86_32,
                TEST_SERVICE_X86_32 as u32,
                &regs,
                &mut mem,
            )
        };
        assert_eq!(out, BridgeOutcome::Dispatched(STATUS_SUCCESS));
        assert_eq!(LAST_ARGS.load(Ordering::SeqCst), 0x42);
    }

    #[test]
    fn x86_64_reads_fifth_arg_after_return_address() {
        unsafe {
            register_syscall(
                TEST_SERVICE_X86_64_STACK,
                capture_fifth_handler,
                5,
                "btl_test64x",
            )
            .unwrap();
        }
        let mut backing = [0u8; 0x100];
        let mut mem = flat_memory(&mut backing);
        let stack: [u8; 16] = [
            0xFF, 0, 0, 0, 0, 0, 0, 0, // return address
            0x77, 0, 0, 0, 0, 0, 0, 0, // arg4
        ];
        assert!(mem.write_virt(0x80, &stack));

        let mut regs = alloc::vec![0u64; 17];
        regs[X86Reg::R10 as usize] = 0x11;
        regs[X86Reg::Rsp as usize] = 0x80;
        let out = unsafe {
            dispatch_nt_syscall(
                GuestAbi::X86_64,
                TEST_SERVICE_X86_64_STACK as u32,
                &regs,
                &mut mem,
            )
        };
        assert_eq!(out, BridgeOutcome::Dispatched(STATUS_SUCCESS));
        assert_eq!(LAST_STACK_ARG.load(Ordering::SeqCst), 0x77);
    }

    #[test]
    fn x86_32_argument_block_is_32_bit() {
        unsafe {
            register_syscall(TEST_SERVICE_X86_32_WORD, capture_handler, 1, "btl_test32w").unwrap();
        }
        let mut backing = [0u8; 0x100];
        let mut mem = flat_memory(&mut backing);
        let block: [u8; 8] = [0x77, 0, 0, 0, 0xEE, 0xEE, 0xEE, 0xEE];
        assert!(mem.write_virt(0x40, &block));

        let mut regs = alloc::vec![0u64; 17];
        regs[X86Reg::Rdx as usize] = 0x40;
        let out = unsafe {
            dispatch_nt_syscall(
                GuestAbi::X86_32,
                TEST_SERVICE_X86_32_WORD as u32,
                &regs,
                &mut mem,
            )
        };
        assert_eq!(out, BridgeOutcome::Dispatched(STATUS_SUCCESS));
        assert_eq!(LAST_ARGS.load(Ordering::SeqCst), 0x77);
    }
}
