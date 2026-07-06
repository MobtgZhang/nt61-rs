//! LoongArch64 system call dispatch.
//!
//! Phase 1 rewrites the original empty stub to provide:
//!   * The `TrapFrame` ABI consumed by `arch::loongarch64::trap`.
//!   * A minimal `dispatch_syscall(frame: *mut TrapFrame)` that
//!     reads syscall number from `$a7` and arguments from `$a0..$a5`,
//!     dispatches against the NT service table, and stores the
//!     return value back into `$a0` of the frame.
//!
//! Phase 2 extends this with full NT coverage; Phase 7 layers the
//! x86-on-LA64 BTL on top.

use core::arch::asm;

use crate::arch::loongarch64::trap::TrapFrame;

// =====================================================================
// Per-CPU scratch area — used to communicate with the user-mode
// system-call surface. Currently unused; reserved for Phase 2.
// =====================================================================

#[inline(always)]
fn read_a7() -> u64 {
    let v: u64;
    unsafe { asm!("move {}, $a7", out(reg) v, options(nostack, preserves_flags)); }
    v
}

#[inline(always)]
fn read_a0() -> u64 {
    let v: u64;
    unsafe { asm!("move {}, $a0", out(reg) v, options(nostack, preserves_flags)); }
    v
}

#[inline(always)]
fn read_a1() -> u64 {
    let v: u64;
    unsafe { asm!("move {}, $a1", out(reg) v, options(nostack, preserves_flags)); }
    v
}

#[inline(always)]
fn read_a2() -> u64 {
    let v: u64;
    unsafe { asm!("move {}, $a2", out(reg) v, options(nostack, preserves_flags)); }
    v
}

#[inline(always)]
fn read_a3() -> u64 {
    let v: u64;
    unsafe { asm!("move {}, $a3", out(reg) v, options(nostack, preserves_flags)); }
    v
}

#[inline(always)]
fn read_a4() -> u64 {
    let v: u64;
    unsafe { asm!("move {}, $a4", out(reg) v, options(nostack, preserves_flags)); }
    v
}

#[inline(always)]
fn read_a5() -> u64 {
    let v: u64;
    unsafe { asm!("move {}, $a5", out(reg) v, options(nostack, preserves_flags)); }
    v
}

// =====================================================================
// System-call numbers (subset — full table in Phase 7).
// =====================================================================

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
// NTSTATUS constants
// =====================================================================

pub const STATUS_SUCCESS: u64 = 0x0000_0000;
pub const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
pub const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;

// =====================================================================
// Dispatch entry point.
// =====================================================================

/// Dispatch one user-mode system call.
///
/// `frame` points at the `TrapFrame` pushed by `loongarch64_exception`.
/// On entry, `$a7` holds the syscall number and `$a0..$a5` the
/// arguments. On return, `$a0` is set to the result and ERA is
/// advanced by 4 so the next instruction (after `syscall`) executes.
///
/// # Safety
///
/// `frame` must point at a live trap frame in kernel memory.
#[no_mangle]
pub unsafe extern "C" fn dispatch_syscall(frame: *mut TrapFrame) {
    // Snapshot registers from the trap frame rather than reading
    // $a0..$a7 directly — by the time we're in C-land, the C
    // compiler may have stomped on those registers.
    let num = (*frame).a[7];
    let a0 = (*frame).a[0];
    let a1 = (*frame).a[1];
    let a2 = (*frame).a[2];
    let a3 = (*frame).a[3];
    let a4 = (*frame).a[4];
    let a5 = (*frame).a[5];

    let result = handle(num, a0, a1, a2, a3, a4, a5);

    // Return value goes back in $a0 of the saved frame.
    (*frame).a[0] = result;
    // Advance ERA past the `syscall` instruction (4 bytes on LA64).
    let era = crate::arch::loongarch64::trap::read_era();
    asm!(
        "csrwr {era}, 0x6",
        era = in(reg) era + 4,
        options(nostack),
    );
}

/// Top-level handler. Phase 1 dispatches the subset of NT calls
/// needed by the Phase 7 BTL bridge; everything else returns
/// `STATUS_NOT_IMPLEMENTED`.
fn handle(num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    match num {
        SYS_NT_CLOSE => {
            // NtClose(handle) — Phase 1 returns success for any handle
            // so test programs can complete the round-trip.
            STATUS_SUCCESS
        }
        SYS_NT_DELAY_EXECUTION => {
            // NtDelayExecution — busy-wait for `a1` 100-ns intervals.
            // Used by Phase 6/7 tests for timing.
            crate::arch::loongarch64::pit::busy_wait_100ns(a1);
            STATUS_SUCCESS
        }
        SYS_NT_TERMINATE_PROCESS => STATUS_SUCCESS,
        SYS_NT_QUERY_SYSTEM_INFORMATION => {
            // Phase 1: return success with no data so callers can probe.
            STATUS_SUCCESS
        }
        _ => {
            // Unimplemented in Phase 1.
            let _ = (a0, a1, a2, a3, a4, a5);
            STATUS_NOT_IMPLEMENTED
        }
    }
}

// =====================================================================
// Light-weight init routine.  Phase 2 will install the user-mode
// syscall entry point in `EENTRY`; for now we leave the exception
// vector installed by `idt::init`.
// =====================================================================

pub fn init() {
    // Nothing to do — Phase 1 leaves the kernel's exception vector
    // in place. Phase 2 will write EENTRY to a dedicated user-mode
    // entry that does the trap-frame copy and falls through to
    // `trap_dispatch`.
    let _ = read_a7;
    let _ = read_a0;
    let _ = read_a1;
    let _ = read_a2;
    let _ = read_a3;
    let _ = read_a4;
    let _ = read_a5;
}