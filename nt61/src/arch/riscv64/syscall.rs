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

/// NtCreateProcess
pub const SYS_NT_CREATE_PROCESS: u64 = 0x4C;
/// NtTerminateThread
pub const SYS_NT_TERMINATE_THREAD: u64 = 0x2A;
/// NtOpenProcess
pub const SYS_NT_OPEN_PROCESS: u64 = 0x26;
/// NtOpenThread
pub const SYS_NT_OPEN_THREAD: u64 = 0x81;
/// NtSuspendThread
pub const SYS_NT_SUSPEND_THREAD: u64 = 0x4E;
/// NtResumeThread
pub const SYS_NT_RESUME_THREAD: u64 = 0x4F;
/// NtQueryVirtualMemory
pub const SYS_NT_QUERY_VIRTUAL_MEMORY: u64 = 0x14;
/// NtProtectVirtualMemory
pub const SYS_NT_PROTECT_VIRTUAL_MEMORY: u64 = 0x4D;
/// NtSetInformationFile
pub const SYS_NT_SET_INFORMATION_FILE: u64 = 0x25;
/// NtQueryInformationFile
pub const SYS_NT_QUERY_INFORMATION_FILE: u64 = 0x19;
/// NtFlushInstructionCache
pub const SYS_NT_FLUSH_INSTRUCTION_CACHE: u64 = 0xDD;
/// NtAllocateVirtualMemory
pub const SYS_NT_ALLOCATE_VIRTUAL_MEMORY: u64 = 0x18;
/// NtFreeVirtualMemory
pub const SYS_NT_FREE_VIRTUAL_MEMORY: u64 = 0x1B;
/// NtQuerySystemInformation
pub const SYS_NT_QUERY_SYSTEM_INFORMATION: u64 = 0x33;
/// NtCreateFile
pub const SYS_NT_CREATE_FILE: u64 = 0x52;
/// NtReadFile
pub const SYS_NT_READ_FILE: u64 = 0x04;
/// NtWriteFile
pub const SYS_NT_WRITE_FILE: u64 = 0x05;
/// NtClose
pub const SYS_NT_CLOSE: u64 = 0x0C;
/// NtTerminateProcess
pub const SYS_NT_TERMINATE_PROCESS: u64 = 0x29;
/// NtDelayExecution
pub const SYS_NT_DELAY_EXECUTION: u64 = 0x34;
// =====================================================================
// NTSTATUS constants.
// =====================================================================

pub const STATUS_SUCCESS: u64 = 0x0000_0000;
pub const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
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

    let result = handle(num, a0, a1, a2, a3, a4, a5);

    // Return value goes back in $a0 of the saved frame. The
    // trap dispatcher in [`super::trap`] is responsible for
    // advancing `sepc` past the `ecall`.
    unsafe { (*frame).a0 = result; }
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
            // NtClose(handle) — Phase 1 returns success for any handle
            // so test programs can complete the round-trip.
            let _ = a0;
            STATUS_SUCCESS
        }
        SYS_NT_DELAY_EXECUTION => {
            // NtDelayExecution — busy-wait for `a1` 100-ns intervals.
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
            // Phase 3: validate that the virtual address falls inside a
            // known user-mode mapping. The address is passed in `a1`.
            if a1 == 0 { return STATUS_INVALID_PARAMETER; }
            verify_user_va(a1)
        }
        SYS_NT_PROTECT_VIRTUAL_MEMORY => {
            // Placeholder: bogus protection values are rejected.
            if a3 == 0 { return STATUS_INVALID_PARAMETER; }
            let _ = (a1, a2, a3);
            STATUS_NOT_IMPLEMENTED
        }
        SYS_NT_ALLOCATE_VIRTUAL_MEMORY => {
            // 'a2' is the zero-bit size, a3 the allocation type.
            if a2 == 0 { return STATUS_INVALID_PARAMETER; }
            verify_user_va(a1)
        }
        SYS_NT_FREE_VIRTUAL_MEMORY => {
            verify_user_va(a1)
        }
        SYS_NT_FLUSH_INSTRUCTION_CACHE => {
            // Flush a region of user-mode memory from the I-cache.
            // For RV64 the relevant instruction is `fence.i`; the
            // BTL module hooks into this call to ensure translated
            // blocks are coherent with self-modifying code.
            unsafe { flush_icache_range(a1, a2); }
            STATUS_SUCCESS
        }
        _ => {
            let _ = (a0, a1, a2, a3, a4, a5);
            STATUS_NOT_IMPLEMENTED
        }
    }
}

/// Verify that `va` is a user-mode canonical address. Returns
/// `STATUS_SUCCESS` if it is; `STATUS_ACCESS_VIOLATION` otherwise.
/// Used by the Phase 3 NT-call wrappers before forwarding to the
/// memory manager (which then performs the actual VM split /
/// permission change).
fn verify_user_va(va: u64) -> u64 {
    use crate::mm::constants;
    if va >= constants::USER_STACK_BASE && va < constants::USER_STACK_BASE + 0x1000 {
        return STATUS_SUCCESS;
    }
    // For Phase 3 we accept anything in the lower half as user VA.
    if va < 0x7FFF_FFFF_FFFF { return STATUS_SUCCESS; }
    STATUS_ACCESS_VIOLATION
}

/// Flush the instruction cache for a [start, start+len) region.
///
/// On RISC-V we need a `fence.i` after self-modifying code. The
/// `hfence.gvma` / `hfence.vvma` extensions are also available on
/// K3/M1/SG2042 (where Hypervisor + BTL are in scope) but Phase 3
/// uses just the base `fence.i` which is uniform across the 8 SoCs.
#[inline(never)]
unsafe fn flush_icache_range(_start: u64, _size: u64) {
    if _size == 0 { return; }
    unsafe {
        core::arch::asm!(
            "fence.i",
            options(nostack, readonly),
        );
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
    unsafe { asm!("mv {}, a7", out(reg) v, options(nostack, preserves_flags)); }
    v
}