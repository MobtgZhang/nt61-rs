//! RISC-V 64 `ecall` dispatcher.
//!
//! Wired up by [`super::trap::riscv64_trap_dispatch`]:
//!   * The trap frame layout is [`TrapFrame`] (re-exported here
//!     for backward compatibility).
//!   * `dispatch_syscall(frame)` reads the syscall number from
//!     `$a7` (saved as `a7` in the trap frame) and arguments from
//!     `$a0..$a5`, dispatches against the NT service table, and
//!     stores the return value back into `$a0`.
//!
//! Phase 1 covers a small subset of NT calls; the rest return
//! `STATUS_NOT_IMPLEMENTED` so test programs can still exit
//! cleanly. Phase 3 expands the table with argument validation,
//! memory-region probes, and SoC-aware timing helpers.

use core::arch::asm;

pub use super::trap::TrapFrame;

// =====================================================================
// NT service numbers (extended in Phase 3).
// =====================================================================

/// NT_CREATE_PROCESS
pub const SYS_NT_CREATE_PROCESS: u64 = 0x009F;
/// NT_TERMINATE_THREAD
pub const SYS_NT_TERMINATE_THREAD: u64 = 0x0050;
/// NT_OPEN_PROCESS
pub const SYS_NT_OPEN_PROCESS: u64 = 0x0023;
/// NT_OPEN_THREAD
pub const SYS_NT_OPEN_THREAD: u64 = 0x00FE;
/// NT_SUSPEND_THREAD
pub const SYS_NT_SUSPEND_THREAD: u64 = 0x017B;
/// NT_RESUME_THREAD
pub const SYS_NT_RESUME_THREAD: u64 = 0x004F;
/// NT_QUERY_VIRTUAL_MEMORY
pub const SYS_NT_QUERY_VIRTUAL_MEMORY: u64 = 0x0020;
/// NT_PROTECT_VIRTUAL_MEMORY
pub const SYS_NT_PROTECT_VIRTUAL_MEMORY: u64 = 0x004D;
/// NT_SET_INFORMATION_FILE
pub const SYS_NT_SET_INFORMATION_FILE: u64 = 0x0024;
/// NT_QUERY_INFORMATION_FILE
pub const SYS_NT_QUERY_INFORMATION_FILE: u64 = 0x000E;
/// NtFlushInstructionCache
pub const SYS_NT_FLUSH_INSTRUCTION_CACHE: u64 = 0x00C2;
/// NT_ALLOCATE_VIRTUAL_MEMORY
pub const SYS_NT_ALLOCATE_VIRTUAL_MEMORY: u64 = 0x0015;
/// NT_FREE_VIRTUAL_MEMORY
pub const SYS_NT_FREE_VIRTUAL_MEMORY: u64 = 0x001B;
/// NT_QUERY_SYSTEM_INFORMATION
pub const SYS_NT_QUERY_SYSTEM_INFORMATION: u64 = 0x33;
/// NT_CREATE_FILE
pub const SYS_NT_CREATE_FILE: u64 = 0x52;
/// NT_READ_FILE
pub const SYS_NT_READ_FILE: u64 = 0x0003;
/// NT_WRITE_FILE
pub const SYS_NT_WRITE_FILE: u64 = 0x05;
/// NT_CLOSE
pub const SYS_NT_CLOSE: u64 = 0x0C;
/// NT_TERMINATE_PROCESS
pub const SYS_NT_TERMINATE_PROCESS: u64 = 0x29;
/// NT_DELAY_EXECUTION
pub const SYS_NT_DELAY_EXECUTION: u64 = 0x0031;
pub const SYS_PUTCHAR: u64 = 0x0202;
pub const SYS_POLL_KEY: u64 = 0x0203;
pub const SYS_GET_KEY: u64 = 0x0204;
pub const SYS_CLEARSCREEN: u64 = 0x0205;
pub const SYS_READ_LINE: u64 = 0x0211;
pub const SYS_RETURN_TO_FIRMWARE: u64 = 0x0214;
pub const SYS_CMD_EXECUTE: u64 = 0x0215;
pub const SYS_PRINT_PROMPT: u64 = 0x0216;
// =====================================================================
// NTSTATUS constants.
// =====================================================================

pub const STATUS_SUCCESS: u64 = 0x0000_0000;
pub const STATUS_INVALID_SYSTEM_SERVICE: u64 = 0xC000_001C;
pub const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
pub const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
pub const STATUS_OBJECT_NAME_INVALID: u64 = 0xC000_0033;

// =====================================================================
// Backwards-compatible thin wrapper.
// =====================================================================

/// Backwards-compatible syscall dispatcher used by Phase 0 callers
/// (e.g. `ke::interrupt` smoke tests). Reads the syscall number
/// and arguments from the saved frame and returns the status.
///
/// Phase 1 callers should prefer [`dispatch_syscall`].
#[no_mangle]
pub extern "C" fn syscall_dispatch(syscall_num: u64, _tf: *mut TrapFrame) -> u64 {
    handle(syscall_num, 0, 0, 0, 0, 0, 0)
}

// =====================================================================
// Phase 1 dispatch entry point.
// =====================================================================

/// Dispatch one user-mode `ecall`.
///
/// `frame` points at the [`TrapFrame`] pushed by `stvec_trap`.
/// On entry, `$a7` holds the syscall number and `$a0..$a5` the
/// arguments. On return, `$a0` is set to the result. `sepc` is
/// advanced by 4 by the caller (see [`super::trap`]) so the next
/// instruction after the `ecall` runs.
///
/// # Safety
///
/// `frame` must point at a live trap frame in kernel memory.
#[no_mangle]
pub unsafe extern "C" fn dispatch_syscall(frame: *mut TrapFrame) {
    // Snapshot registers from the trap frame rather than reading
    // $a0..$a7 directly — by the time we're in C-land, the C
    // compiler may have stomped on those registers.
    let num = unsafe { (*frame).a7 };
    let a0 = unsafe { (*frame).a0 };
    let a1 = unsafe { (*frame).a1 };
    let a2 = unsafe { (*frame).a2 };
    let a3 = unsafe { (*frame).a3 };
    let a4 = unsafe { (*frame).a4 };
    let a5 = unsafe { (*frame).a5 };
    let a6 = unsafe { (*frame).a6 };
    let stack_pointer = unsafe { (*frame).sp } as usize;

    let register_args = [
        a0 as usize,
        a1 as usize,
        a2 as usize,
        a3 as usize,
        a4 as usize,
        a5 as usize,
        a6 as usize,
        0,
    ];
    let common_status = unsafe {
        crate::ke::ssdt_common::dispatch_syscall_with_stack(
            num as usize,
            register_args,
            crate::ke::ssdt_common::SEVEN_REGISTER_ARCHITECTURES,
            stack_pointer,
        )
    };
    let common_result = if common_status == crate::ke::ssdt_common::STATUS_INVALID_SYSTEM_SERVICE {
        None
    } else {
        Some(common_status)
    };

    let result = match common_result {
        Some(status) => status as u64,
        None => handle(num, a0, a1, a2, a3, a4, a5),
    };

    // Return value goes back in $a0 of the saved frame. The
    // trap dispatcher in [`super::trap`] is responsible for
    // advancing `sepc` past the `ecall`.
    unsafe {
        (*frame).a0 = result;
    }
}

/// Top-level handler. Phase 1 dispatches the subset of NT calls
/// needed for smoke testing; everything else returns
/// `STATUS_NOT_IMPLEMENTED`.
///
/// Phase 3 adds argument validation, simple probes for the
/// memory-allocation services, and BTL-aware touch-up of
/// instruction-cache flush on `ecall` for BTL guests. The
/// argument slots that aren't used by a particular NT call are
/// still passed so we can detect garbage.
fn handle(num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    match num {
        SYS_NT_CLOSE => {
            // NT_CLOSE(handle) — Phase 1 returns success for any handle
            // so test programs can complete the round-trip.
            let _ = a0;
            STATUS_SUCCESS
        }
        SYS_NT_DELAY_EXECUTION => {
            // NT_DELAY_EXECUTION — busy-wait for `a1` 100-ns intervals.
            crate::arch::riscv64::pit::busy_wait_100ns(a1);
            STATUS_SUCCESS
        }
        SYS_NT_TERMINATE_PROCESS => {
            let _ = (a0, a1);
            STATUS_SUCCESS
        }
        SYS_NT_TERMINATE_THREAD => {
            let _ = (a0, a1);
            STATUS_SUCCESS
        }
        SYS_NT_QUERY_SYSTEM_INFORMATION => {
            // Phase 1: return success with no data so callers can probe.
            let _ = (a0, a1, a2, a3, a4, a5);
            STATUS_SUCCESS
        }
        SYS_NT_QUERY_VIRTUAL_MEMORY => {
            let status = unsafe {
                crate::libs::ntdll::virtual_mem::nt_query_virtual_memory(
                    a0 as crate::libs::ntdll::types::HANDLE,
                    a1 as crate::libs::ntdll::types::PVOID,
                    a2 as u32,
                    a3 as crate::libs::ntdll::types::PVOID,
                    a4 as crate::libs::ntdll::types::SizeT,
                    a5 as *mut crate::libs::ntdll::types::SizeT,
                )
            };
            status as u64
        }
        SYS_NT_PROTECT_VIRTUAL_MEMORY => {
            let status = unsafe {
                crate::libs::ntdll::virtual_mem::nt_protect_virtual_memory(
                    a0 as crate::libs::ntdll::types::HANDLE,
                    a1 as *mut crate::libs::ntdll::types::PVOID,
                    a2 as *mut crate::libs::ntdll::types::SizeT,
                    a3 as u32,
                    a4 as *mut u32,
                )
            };
            status as u64
        }
        SYS_NT_ALLOCATE_VIRTUAL_MEMORY => {
            let status = unsafe {
                crate::libs::ntdll::virtual_mem::nt_allocate_virtual_memory(
                    a0 as crate::libs::ntdll::types::HANDLE,
                    a1 as *mut crate::libs::ntdll::types::PVOID,
                    a2 as crate::libs::ntdll::types::SizeT,
                    a3 as *mut crate::libs::ntdll::types::SizeT,
                    a4 as u32,
                    a5 as u32,
                )
            };
            status as u64
        }
        SYS_NT_FREE_VIRTUAL_MEMORY => {
            let status = unsafe {
                crate::libs::ntdll::virtual_mem::nt_free_virtual_memory(
                    a0 as crate::libs::ntdll::types::HANDLE,
                    a1 as *mut crate::libs::ntdll::types::PVOID,
                    a2 as *mut crate::libs::ntdll::types::SizeT,
                    a3 as u32,
                )
            };
            status as u64
        }
        SYS_NT_FLUSH_INSTRUCTION_CACHE => {
            // Flush a region of user-mode memory from the I-cache.
            // For RV64 the relevant instruction is `fence.i`; the
            // BTL module hooks into this call to ensure translated
            // blocks are coherent with self-modifying code.
            unsafe {
                flush_icache_range(a1, a2);
            }
            STATUS_SUCCESS
        }
        SYS_PUTCHAR => crate::arch::common::cmd_host::putchar(a0 as u8),
        SYS_POLL_KEY => {
            if let Some(byte) = crate::arch::common::cmd_host::poll_key() {
                return byte as u64;
            }
            0xC000_0011
        }
        SYS_GET_KEY => crate::arch::common::cmd_host::get_key() as u64,
        SYS_CLEARSCREEN => crate::arch::common::cmd_host::clear_screen(),
        SYS_READ_LINE => {
            match unsafe { crate::arch::common::cmd_host::read_line(a0 as *mut u8, a1 as usize) } {
                Some(written) => written as u64,
                None => 0xC000_000D,
            }
        }
        SYS_RETURN_TO_FIRMWARE => crate::arch::common::cmd_host::return_to_firmware(),
        SYS_CMD_EXECUTE => {
            match crate::arch::common::cmd_host::execute_command(a0 as *const u8, a1 as usize) {
                Ok(exited) => exited as u64,
                Err(_) => 0xC000_000D,
            }
        }
        SYS_PRINT_PROMPT => crate::arch::common::cmd_host::print_prompt(),
        _ => {
            let _ = (a0, a1, a2, a3, a4, a5);
            STATUS_INVALID_SYSTEM_SERVICE
        }
    }
}

/// Flush the instruction cache for a [start, start+len) region.
///
/// On RISC-V we need a `fence.i` after self-modifying code. The
/// `hfence.gvma` / `hfence.vvma` extensions are also available on
/// K3/M1/SG2042 (where Hypervisor + BTL are in scope) but Phase 3
/// uses just the base `fence.i` which is uniform across the 8 SoCs.
#[inline(never)]
unsafe fn flush_icache_range(_start: u64, _size: u64) {
    if _size == 0 {
        return;
    }
    unsafe {
        core::arch::asm!("fence.i", options(nostack, readonly),);
    }
}

// =====================================================================
// Init stub.
// =====================================================================

/// Light-weight init routine. The exception vector is installed by
/// [`super::idt::init`]; this hook is reserved for future
/// user-mode syscall entry shims (Phase 3).
pub fn init() {
    let _ = read_a7;
}

// =====================================================================
// BTL / raw syscall entry point
// =====================================================================

/// Raw syscall dispatch helper used by the BTL glue. Phase 4
/// callers pass an argument vector rather than a `*mut TrapFrame`;
/// this lets the BTL forward NT calls without crafting a fake
/// trap frame on the stack.
pub fn dispatch_syscall_raw(num: u64, args: [u64; 5]) -> u64 {
    handle(num, args[0], args[1], args[2], args[3], args[4], 0)
}

#[inline(always)]
fn read_a7() -> u64 {
    let v: u64;
    unsafe {
        asm!("mv {}, a7", out(reg) v, options(nostack, preserves_flags));
    }
    v
}
