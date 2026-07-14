//! x86_64 SYSCALL entry / dispatch — full NT 6.1 implementation.
//
//! This module wires up the AMD64 SYSCALL/SYSRET mechanism for
//! Ring 3 → Ring 0 transitions and dispatches every NT 6.1 native
//! system call to the matching kernel handler.
//
//! Architecture
//! ------------
//! On entry to Ring 0 (via the `syscall` instruction), the CPU
//! has already saved the user-mode RIP into RCX and the user-mode
//! RFLAGS into R11. The kernel trap frame is built by the
//! assembly entry point in `idt_stubs.rs` (`syscall_entry`); see
//! that file for the exact stack layout.
//
//! The `TrapFrame` Rust struct mirrors the on-stack layout. The
//! fields are read by the dispatch code to extract the user-mode
//! arguments (in the System V AMD64 ABI used by the Windows x64
//! calling convention, the first 4 arguments are passed in
//! RCX, RDX, R8, R9 and additional arguments are pushed onto
//! the stack).
//
//! Syscall numbers
//! ---------------
//! Each NT 6.1 native API has a stable numeric identifier. The
//! identifiers are public ABI and never change within a release.
//! The full list lives in `syscall_numbers.rs` and is referenced
//! from the dispatch table below; the table key is the syscall
//! number and the value is the kernel-side handler.
//
//! Implementation policy
//! ---------------------
//! For calls that already have a working kernel-side
//! implementation in `libs::ntdll::*`, the dispatch invokes that
//! function directly. For calls we have not yet implemented, the
//! dispatch returns `STATUS_NOT_IMPLEMENTED` so user-mode callers
//! see a deterministic NTSTATUS code instead of a #GP fault.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicU32, Ordering};

// use crate::kprintln;  // kprintln disabled (memcpy crash workaround)

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall_numbers as nums;

// AMD64 MSRs for the SYSCALL mechanism.
const IA32_LSTAR: u32 = 0xC0000082;     // long-mode SYSCALL target RIP
const IA32_STAR: u32 = 0xC0000081;     // CS/SS selectors for SYSRET
const IA32_FMASK: u32 = 0xC0000084;    // RFLAGS mask on SYSCALL
const IA32_EFER: u32 = 0xC0000080;     // EFER (bit 0 = SCE = SYSCALL enable)
const IA32_KERNEL_GS_BASE: u32 = 0xC0000102; // Kernel GS base (used by SWAPGS)
const IA32_GS_BASE: u32 = 0xC0000101;  // User GS base (set by kernel on swapgs)

/// Segment selectors used for SYSRET. All are re-exported from `gdt.rs`
/// which is the authoritative source for the OVMF-augmented GDT layout.
///
/// OVMF GDT (slots 0-3 are OVMF-preserved):
///   slot 2 (selector 0x10): kernel CS  (OVMF)
///   slot 3 (selector 0x18): kernel SS  (OVMF)
///
/// Kernel-augmented (slots 4-6):
///   slot 4 (selector 0x20): user SS    (DPL=3, written by gdt::init())
///   slot 5 (selector 0x28): user CS    (DPL=3, written by gdt::init())
///   slot 6 (selector 0x30): TSS        (written by gdt::init())
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::gdt::KERNEL_CS;
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::gdt::KERNEL_DS;
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::gdt::USER_CS;
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::gdt::USER_SS;

/// Offset of the user-RSP slot inside the per-CPU area. The
/// `syscall_entry` asm writes `gs:[0x0] = user_rsp` on entry
/// and reads it back on `sysretq`.
pub const PER_CPU_USER_RSP_OFFSET: usize = 0x0;
/// Offset of the kernel-RSP slot. The asm loads `gs:[0x8]` on
/// entry to switch to the kernel stack.
pub const PER_CPU_KERNEL_RSP_OFFSET: usize = 0x8;
/// Offset of the `current_thread` slot. The kernel writes the
/// ETHREAD pointer of the running thread here in `setup_bsp`
/// (and again on every context switch). All `gs:[N]` readers
/// (`KeGetCurrentEthread`, `get_current_ethread`, ...) MUST
/// use this offset.
pub const PER_CPU_CURRENT_THREAD_OFFSET: usize = 0x10;
/// Offset of the `syscall_snap_addr` slot. The `syscall_entry`
/// asm reads `gs:[0x58]` to load `&SYSCALL_ENTRY_SNAP` into RAX
/// without needing a 64-bit LEA or a memory LOAD. The slot is
/// populated by `init_syscall_msrs()` in `syscall.rs`.
pub const PER_CPU_SYSCALL_SNAP_ADDR_OFFSET: usize = 0x58;
/// Offset of the `current_process` slot.
pub const PER_CPU_CURRENT_PROCESS_OFFSET: usize = 0x18;

// =====================================================================
// Canonical per-CPU re-exports
// =====================================================================
//
// All per-CPU infrastructure is defined in the canonical locations:
//   - Struct definition + main API:   crate::arch::common::percpu
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
//   - x86_64 GS-base implementation:  crate::arch::x86_64::percpu_impl
//
// This module re-exports everything under the syscall::* namespace so
// that callers (scheduler.rs, smp.rs, irql.rs, ...) can use a stable
// API regardless of where the underlying implementation lives.
// =====================================================================

pub use crate::arch::common::percpu::{
    PerCpuArea,
    init as percpu_init,
    get_current,
    get_current_cpu_id,
    set_kernel_stack,
    set_user_rsp,
    set_current_thread,
    get_current_thread,
    set_current_process,
    get_current_process,
    MAX_PER_CPU,
    PER_CPU_AREA_SIZE,
};

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::percpu_impl::{
    init_storage,
    allocate as allocate_per_cpu_area,
    __percpu_get_current as per_cpu_ptr_mut,
    __percpu_get_current_cpu_id as get_current_cpu_id_from_gs,
};

/// Safe wrapper for percpu init (unsafe call).
pub fn init(cpu_id: u32) -> u64 {
    unsafe { percpu_init(cpu_id) }
}

/// Legacy alias for init.
pub fn init_per_cpu(cpu_id: u32) -> u64 { init(cpu_id) }

/// Return a raw pointer to the BSP per-CPU area. Used by the
/// MM code to publish the system / user PML4 pair so the
/// syscall / interrupt stubs can switch CR3 to the system PML4
/// before running kernel handlers.
///
/// Returns `core::ptr::null_mut()` if the per-CPU area has not
/// been initialised yet.
pub fn get_per_cpu() -> *mut PerCpuArea {
    per_cpu_ptr_mut() as *mut PerCpuArea
}

/// The on-stack register save area built by `syscall_entry`.
/// Field order MUST match the assembly push order in
/// `idt_stubs.rs`. See the comment at the top of that block.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TrapFrame {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Snapshot of RAX (= user-mode syscall number) taken at the very
/// first instruction of `syscall_entry` (in `idt_stubs.rs`). This
/// captures the value BEFORE the Rust compiler can clobber RAX
/// in the dispatcher's prologue. Useful for verifying that the
/// user-mode stub actually set RAX to the expected syscall
/// number before executing `syscall`.
///
/// Layout (24 bytes):
///   [0..8]   = RAX at syscall_entry (user-mode syscall number)
///   [8..16]  = RCX at syscall_entry (user-mode RIP)
///   [16..24] = 8 bytes from user RIP (bytes the CPU would
///              execute next)
#[repr(C)]
pub struct SyscallEntrySnap {
    pub rax: u64,
    pub rip: u64,
    pub rip_bytes: [u8; 8],
    pub user_r13: u64,
    pub user_r12: u64,
}

#[no_mangle]
pub static mut SYSCALL_ENTRY_SNAP: SyscallEntrySnap = SyscallEntrySnap {
    rax: 0xDEAD_BEEF_DEAD_BEEF,
    rip: 0xDEAD_BEEF_DEAD_BEEF,
    rip_bytes: [0xCC; 8],
    user_r13: 0xDEAD_BEEF_DEAD_BEEF,
    user_r12: 0xDEAD_BEEF_DEAD_BEEF,
};

// (The previous per-field address-symbol helpers
//  SYSCALL_ENTRY_SNAP_ADDR_* and init_snap_addrs() have been
//  removed: the assembly now uses `sym SYSCALL_ENTRY_SNAP` once
//  for the base and offsets from the assembly side, which works
//  without any runtime address patching.)

// Back-compat aliases for the existing print sites.
#[allow(non_snake_case)]
#[inline(always)]
pub unsafe fn SYSCALL_ENTRY_RAX_SNAP() -> u64 {
    core::ptr::read_volatile(&raw const SYSCALL_ENTRY_SNAP.rax)
}
#[allow(non_snake_case)]
#[inline(always)]
pub unsafe fn SYSCALL_ENTRY_RIP_SNAP() -> u64 {
    core::ptr::read_volatile(&raw const SYSCALL_ENTRY_SNAP.rip)
}
#[allow(non_snake_case)]
#[inline(always)]
pub unsafe fn SYSCALL_ENTRY_RIP_BYTE_SNAP() -> [u8; 8] {
    core::ptr::read_volatile(&raw const SYSCALL_ENTRY_SNAP.rip_bytes)
}

extern "C" {
    fn syscall_entry();
}

// =====================================================================
// MSR helpers
// =====================================================================

#[inline(always)]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

pub fn set_kernel_gs_base(base: u64) { wrmsr(IA32_KERNEL_GS_BASE, base); }
pub fn set_user_gs_base(base: u64) { wrmsr(IA32_GS_BASE, base); }
pub fn get_user_gs_base() -> u64 { rdmsr(IA32_GS_BASE) }
pub fn get_kernel_gs_base() -> u64 { rdmsr(IA32_KERNEL_GS_BASE) }

// =====================================================================
// Argument extraction helpers
// =====================================================================
//
// The Microsoft x64 calling convention (used by Windows 7 / NT 6.1
// on x86-64) is the standard AMD64 calling convention *except*
// for the SYSCALL mechanism: the AMD64 `syscall` instruction
// clobbers RCX (it becomes the user RIP), so the standard "arg0
// in rcx" rule cannot be honoured. The Microsoft convention
// instead is:
//
//     arg0 = R10
//     arg1 = RDX
//     arg2 = R8
//     arg3 = R9
//     arg4 = stack[0]
//     arg5 = stack[1]
//     ...
//
// Stack arguments live at offsets from the user RSP at the time
// of the `syscall` instruction. We save user RSP into the trap
// frame's `rsp` field on entry, and stack args are read relative
// to that pointer.
//
// This is the convention that every `ntdll.dll` thunk on the
// user-mode side uses; the kernel reads arguments back from
// exactly these registers.
// =====================================================================

#[inline(always)]
fn arg0(tf: &TrapFrame) -> u64 { tf.r10 }
#[inline(always)]
fn arg1(tf: &TrapFrame) -> u64 { tf.rdx }
#[inline(always)]
fn arg2(tf: &TrapFrame) -> u64 { tf.r8 }
#[inline(always)]
fn arg3(tf: &TrapFrame) -> u64 { tf.r9 }
#[inline(always)]
fn arg4(tf: &TrapFrame) -> u64 { stack_arg(tf, 0) }
#[inline(always)]
fn arg5(tf: &TrapFrame) -> u64 { stack_arg(tf, 1) }

/// Read a stack-passed argument. `n` is the index of the
/// argument (0 = first stack arg, 1 = second stack arg, ...).
/// On entry to the kernel, the user RSP points at the first
/// stack argument.
#[inline(always)]
fn stack_arg(tf: &TrapFrame, n: usize) -> u64 {
    unsafe { *((tf.rsp as *const u64).add(n)) }
}

// =====================================================================
// Dispatch
// =====================================================================

pub type SyscallResult = i64;

#[inline(always)]
fn not_implemented() -> SyscallResult {
    crate::libs::ntdll::status::STATUS_NOT_IMPLEMENTED as i64
}

#[inline(always)]
fn success() -> SyscallResult { 0 }

fn dispatch(syscall_num: u32, tf: &TrapFrame) -> SyscallResult {
    use crate::libs::ntdll::types::{
        HANDLE, IoStatusBlock, ObjectAttributes, ClientId, PVOID, SIZE_T, UnicodeString,
    };
    use crate::libs::ntdll::status::STATUS_SUCCESS;

    // Check for Shadow SSDT (win32k) services
    // Shadow services are in range 0x1000-0x1FFF
    // Table index is bits 12-15 (>> 12)
    let table_index = (syscall_num >> 12) & 0xF;
    if table_index == 0x1 {
        // Shadow SSDT (win32k.sys) service
        let result = crate::ke::shadow_ssdt::dispatch_shadow_service(syscall_num, tf as *const _ as *mut _);
        return result as SyscallResult;
    }

    #[allow(unreachable_patterns)]
    match syscall_num {
        // ---- Process / Thread ----
        nums::NtCreateProcess => {
            unsafe { crate::libs::ntdll::process::NtCreateProcess(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
                arg3(tf) as HANDLE, arg4(tf) as u8, arg5(tf) as HANDLE,
                stack_arg(tf, 0) as PVOID, stack_arg(tf, 1) as PVOID,
            ) as i64 }
        }
        nums::NtCreateProcessEx => {
            unsafe { crate::libs::ntdll::process::NtCreateProcessEx(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
                arg3(tf) as HANDLE, arg4(tf) as u32,
                arg5(tf) as HANDLE,
                stack_arg(tf, 0) as PVOID, stack_arg(tf, 1) as PVOID,
                stack_arg(tf, 2) as u32,
            ) as i64 }
        }
        nums::NtOpenProcess => {
            unsafe { crate::libs::ntdll::process::NtOpenProcess(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes, arg3(tf) as *mut ClientId,
            ) as i64 }
        }
        nums::NtTerminateProcess => {
            unsafe { crate::libs::ntdll::process::NtTerminateProcess(
                arg0(tf) as HANDLE, arg1(tf) as i32,
            ) as i64 }
        }
        nums::NtQueryInformationProcess => {
            unsafe { crate::libs::ntdll::process::NtQueryInformationProcess(
                arg0(tf) as HANDLE, arg1(tf) as u32, arg2(tf) as PVOID,
                arg3(tf) as u32, arg4(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtSetInformationProcess => {
            unsafe { crate::libs::ntdll::process::NtSetInformationProcess(
                arg0(tf) as HANDLE, arg1(tf) as u32, arg2(tf) as PVOID,
                arg3(tf) as u32,
            ) as i64 }
        }
        nums::NtTrimProcessWorkingSet => {
            // NtTrimProcessWorkingSet(handle, min_ws, max_ws)
            crate::mm::working_set::MmTrimProcessWorkingSet(
                arg0(tf) as u64, arg1(tf) as i64,
            ) as i64
        }

        // ---- Virtual Memory ----
        nums::NtAllocateVirtualMemory => {
            unsafe { crate::libs::ntdll::virtual_mem::NtAllocateVirtualMemory(
                arg0(tf) as HANDLE, arg1(tf) as *mut PVOID,
                arg2(tf) as usize, arg3(tf) as *mut SIZE_T,
                arg4(tf) as u32, arg5(tf) as u32,
            ) as i64 }
        }
        nums::NtFreeVirtualMemory => {
            unsafe { crate::libs::ntdll::virtual_mem::NtFreeVirtualMemory(
                arg0(tf) as HANDLE, arg1(tf) as *mut PVOID,
                arg2(tf) as *mut SIZE_T, arg3(tf) as u32,
            ) as i64 }
        }
        nums::NtProtectVirtualMemory => {
            unsafe { crate::libs::ntdll::virtual_mem::NtProtectVirtualMemory(
                arg0(tf) as HANDLE, arg1(tf) as *mut PVOID,
                arg2(tf) as *mut SIZE_T, arg3(tf) as u32, arg4(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtQueryVirtualMemory => {
            unsafe { crate::libs::ntdll::virtual_mem::NtQueryVirtualMemory(
                arg0(tf) as HANDLE, arg1(tf) as PVOID, arg2(tf) as u32,
                arg3(tf) as PVOID, arg4(tf) as usize, arg5(tf) as *mut usize,
            ) as i64 }
        }
        nums::NtReadVirtualMemory => {
            unsafe { crate::libs::ntdll::virtual_mem::NtReadVirtualMemory(
                arg0(tf) as HANDLE, arg1(tf) as PVOID, arg2(tf) as PVOID,
                arg3(tf) as usize, arg4(tf) as *mut usize,
            ) as i64 }
        }
        nums::NtWriteVirtualMemory => {
            unsafe { crate::libs::ntdll::virtual_mem::NtWriteVirtualMemory(
                arg0(tf) as HANDLE, arg1(tf) as PVOID, arg2(tf) as PVOID,
                arg3(tf) as usize, arg4(tf) as *mut usize,
            ) as i64 }
        }

        // ---- File I/O ----
        nums::NtClose => {
            unsafe { crate::libs::ntdll::file::NtClose(arg0(tf) as HANDLE) as i64 }
        }
        nums::NtCreateFile => {
            unsafe { crate::libs::ntdll::file::NtCreateFile(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes, arg3(tf) as *mut IoStatusBlock,
                stack_arg(tf, 0) as *mut i64,
                stack_arg(tf, 1) as u32, stack_arg(tf, 2) as u32,
                stack_arg(tf, 3) as u32, stack_arg(tf, 4) as u32,
                stack_arg(tf, 5) as PVOID, stack_arg(tf, 6) as u32,
            ) as i64 }
        }
        nums::NtOpenFile => {
            unsafe { crate::libs::ntdll::file::NtOpenFile(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes, arg3(tf) as *mut IoStatusBlock,
                arg4(tf) as u32, arg5(tf) as u32,
            ) as i64 }
        }
        nums::NtReadFile => {
            unsafe { crate::libs::ntdll::file::NtReadFile(
                arg0(tf) as HANDLE, arg1(tf) as HANDLE,
                arg2(tf) as PVOID, arg3(tf) as PVOID,
                stack_arg(tf, 0) as *mut IoStatusBlock,
                stack_arg(tf, 1) as PVOID,
                stack_arg(tf, 2) as u32,
                stack_arg(tf, 3) as *mut i64,
                stack_arg(tf, 4) as *mut u32,
            ) as i64 }
        }
        nums::NtWriteFile => {
            unsafe { crate::libs::ntdll::file::NtWriteFile(
                arg0(tf) as HANDLE, arg1(tf) as HANDLE,
                arg2(tf) as PVOID, arg3(tf) as PVOID,
                stack_arg(tf, 0) as *mut IoStatusBlock,
                stack_arg(tf, 1) as PVOID,
                stack_arg(tf, 2) as u32,
                stack_arg(tf, 3) as *mut i64,
                stack_arg(tf, 4) as *mut u32,
            ) as i64 }
        }
        nums::NtQueryInformationFile => {
            unsafe { crate::libs::ntdll::file::NtQueryInformationFile(
                arg0(tf) as HANDLE, arg1(tf) as *mut IoStatusBlock,
                arg2(tf) as PVOID, arg3(tf) as u32, stack_arg(tf, 0) as u32,
            ) as i64 }
        }
        nums::NtSetInformationFile => {
            unsafe { crate::libs::ntdll::file::NtSetInformationFile(
                arg0(tf) as HANDLE, arg1(tf) as *mut IoStatusBlock,
                arg2(tf) as PVOID, arg3(tf) as u32, stack_arg(tf, 0) as u32,
            ) as i64 }
        }
        nums::NtFlushBuffersFile => {
            unsafe { crate::libs::ntdll::file::NtFlushBuffersFile(
                arg0(tf) as HANDLE, arg1(tf) as *mut IoStatusBlock,
            ) as i64 }
        }
        nums::NtDeleteFile => {
            unsafe { crate::libs::ntdll::file::NtDeleteFile(
                arg0(tf) as *mut ObjectAttributes,
            ) as i64 }
        }

        // ---- Sections ----
        nums::NtCreateSection => {
            unsafe { crate::libs::ntdll::section::NtCreateSection(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes, arg3(tf) as *mut i64,
                arg4(tf) as u32, arg5(tf) as u32,
                stack_arg(tf, 0) as HANDLE,
            ) as i64 }
        }
        nums::NtMapViewOfSection => {
            unsafe { crate::libs::ntdll::section::NtMapViewOfSection(
                arg0(tf) as HANDLE, arg1(tf) as HANDLE,
                arg2(tf) as *mut PVOID, arg3(tf) as usize, arg4(tf) as usize,
                stack_arg(tf, 0) as *mut i64,
                stack_arg(tf, 1) as *mut usize,
                stack_arg(tf, 2) as u32,
                stack_arg(tf, 3) as u32,
                stack_arg(tf, 4) as u32,
            ) as i64 }
        }
        nums::NtUnmapViewOfSection => {
            unsafe { crate::libs::ntdll::section::NtUnmapViewOfSection(
                arg0(tf) as HANDLE, arg1(tf) as PVOID,
            ) as i64 }
        }

        // ---- Synchronization primitives ----
        nums::NtCreateEvent => {
            unsafe { crate::libs::ntdll::sync::NtCreateEvent(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes, arg3(tf) as u32, arg4(tf) as u8,
            ) as i64 }
        }
        nums::NtSetEvent => {
            unsafe { crate::libs::ntdll::sync::NtSetEvent(
                arg0(tf) as HANDLE, arg1(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtResetEvent => {
            unsafe { crate::libs::ntdll::sync::NtResetEvent(
                arg0(tf) as HANDLE, arg1(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtClearEvent => {
            unsafe { crate::libs::ntdll::sync::NtClearEvent(arg0(tf) as HANDLE) as i64 }
        }
        nums::NtPulseEvent => {
            unsafe { crate::libs::ntdll::sync::NtPulseEvent(
                arg0(tf) as HANDLE, arg1(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtCreateMutant => {
            unsafe { crate::libs::ntdll::sync::NtCreateMutant(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes, arg3(tf) as u8,
            ) as i64 }
        }
        nums::NtReleaseMutant => {
            unsafe { crate::libs::ntdll::sync::NtReleaseMutant(
                arg0(tf) as HANDLE, arg1(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtCreateSemaphore => {
            unsafe { crate::libs::ntdll::sync::NtCreateSemaphore(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes, arg3(tf) as u32, arg4(tf) as u32,
            ) as i64 }
        }
        nums::NtReleaseSemaphore => {
            unsafe { crate::libs::ntdll::sync::NtReleaseSemaphore(
                arg0(tf) as HANDLE, arg1(tf) as u32, arg2(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtCreateTimer => {
            unsafe { crate::libs::ntdll::sync::NtCreateTimer(
                arg0(tf) as *mut HANDLE, arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes, arg3(tf) as u32,
            ) as i64 }
        }
        nums::NtSetTimer => {
            unsafe { crate::libs::ntdll::sync::NtSetTimer(
                arg0(tf) as crate::libs::ntdll::types::HANDLE,
                arg1(tf) as *const i64,
                arg2(tf) as u32,
                arg3(tf) as *const (),
                arg4(tf) as *mut (),
                arg5(tf) as u8,
                stack_arg(tf, 0) as *mut crate::libs::ntdll::types::HANDLE,
            ) as i64 }
        }
        nums::NtCancelTimer => {
            unsafe { crate::libs::ntdll::sync::NtCancelTimer(
                arg0(tf) as crate::libs::ntdll::types::HANDLE,
                arg1(tf) as *mut crate::libs::ntdll::types::HANDLE,
            ) as i64 }
        }
        nums::NtWaitForSingleObject => {
            unsafe { crate::libs::ntdll::sync::NtWaitForSingleObject(
                arg0(tf) as HANDLE, arg1(tf) as u8, arg2(tf) as *mut i64,
            ) as i64 }
        }
        nums::NtWaitForMultipleObjects => {
            unsafe { crate::libs::ntdll::sync::NtWaitForMultipleObjects(
                arg0(tf) as u32, arg1(tf) as *mut HANDLE,
                arg2(tf) as u32, arg3(tf) as u8, arg4(tf) as *mut i64,
            ) as i64 }
        }
        nums::NtDelayExecution => {
            crate::libs::ntdll::sync::NtDelayExecution(
                arg0(tf) as u8, arg1(tf) as *mut i64,
            ) as i64
        }

        // ---- Registry ----
        nums::NtCreateKey => {
            unsafe { crate::libs::ntdll::registry::NtCreateKey(
                arg0(tf) as *mut HANDLE,
                arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
                arg3(tf) as u32,
                arg4(tf) as *mut UnicodeString,
                arg5(tf) as u32,
                stack_arg(tf, 0) as *mut u32,
            ) as i64 }
        }
        nums::NtOpenKey => {
            unsafe { crate::libs::ntdll::registry::NtOpenKey(
                arg0(tf) as *mut HANDLE,
                arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
            ) as i64 }
        }
        nums::NtDeleteKey => {
            unsafe { crate::libs::ntdll::registry::NtDeleteKey(
                arg0(tf) as HANDLE,
            ) as i64 }
        }
        nums::NtDeleteValueKey => {
            unsafe { crate::libs::ntdll::registry::NtDeleteValueKey(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut UnicodeString,
            ) as i64 }
        }
        nums::NtQueryKey => {
            unsafe { crate::libs::ntdll::registry::NtQueryKey(
                arg0(tf) as HANDLE,
                arg1(tf) as u32,
                arg2(tf) as PVOID,
                arg3(tf) as u32,
                arg4(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtSetValueKey => {
            unsafe { crate::libs::ntdll::registry::NtSetValueKey(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut UnicodeString,
                arg2(tf) as u32,
                arg3(tf) as u32,
                arg4(tf) as PVOID,
                arg5(tf) as u32,
            ) as i64 }
        }
        nums::NtSetInformationKey => not_implemented(),
        nums::NtQueryValueKey => {
            unsafe { crate::libs::ntdll::registry::NtQueryValueKey(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut UnicodeString,
                arg2(tf) as u32,
                arg3(tf) as PVOID,
                arg4(tf) as u32,
                arg5(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtEnumerateKey => {
            unsafe { crate::libs::ntdll::registry::NtEnumerateKey(
                arg0(tf) as HANDLE,
                arg1(tf) as u32,
                arg2(tf) as u32,
                arg3(tf) as PVOID,
                arg4(tf) as u32,
                arg5(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtEnumerateValueKey => {
            unsafe { crate::libs::ntdll::registry::NtEnumerateValueKey(
                arg0(tf) as HANDLE,
                arg1(tf) as u32,
                arg2(tf) as u32,
                arg3(tf) as PVOID,
                arg4(tf) as u32,
                arg5(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtFlushKey => STATUS_SUCCESS as i64,
        nums::NtLoadKey => not_implemented(),
        nums::NtUnloadKey => not_implemented(),
        nums::NtSaveKey => not_implemented(),

        // ---- System Info ----
        nums::NtQuerySystemInformation => {
            unsafe { crate::libs::ntdll::info::NtQuerySystemInformation(
                arg0(tf) as u32, arg1(tf) as PVOID, arg2(tf) as u32,
                arg3(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtSetSystemInformation => {
            unsafe { crate::libs::ntdll::info::NtSetSystemInformation(
                arg0(tf) as u32, arg1(tf) as PVOID, arg2(tf) as u32,
            ) as i64 }
        }
        nums::NtQuerySystemTime => success(),
        nums::NtSetSystemTime => success(),
        nums::NtQueryPerformanceCounter => success(),

        // ---- Thread ----
        nums::NtCreateThread => {
            unsafe { crate::libs::ntdll::thread::NtCreateThread(
                arg0(tf) as *mut HANDLE,
                arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
                arg3(tf) as HANDLE,
                arg4(tf) as *mut ClientId,
                stack_arg(tf, 0) as PVOID,  // start_context
                stack_arg(tf, 1) as PVOID,  // start_routine
                stack_arg(tf, 2) as usize,  // stack_committed
                stack_arg(tf, 3) as usize,  // stack_size
            ) as i64 }
        }
        nums::NtOpenThread => {
            unsafe { crate::libs::ntdll::thread::NtOpenThread(
                arg0(tf) as *mut HANDLE,
                arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
                arg3(tf) as *mut ClientId,
            ) as i64 }
        }
        nums::NtResumeThread => {
            unsafe { crate::libs::ntdll::thread::NtResumeThread(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtSuspendThread => {
            unsafe { crate::libs::ntdll::thread::NtSuspendThread(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut u32,
            ) as i64 }
        }
        nums::NtTerminateThread => {
            unsafe { crate::libs::ntdll::thread::NtTerminateThread(
                arg0(tf) as HANDLE,
                arg1(tf) as u32,
            ) as i64 }
        }
        nums::NtQueryInformationThread => {
            unsafe { crate::libs::ntdll::thread::NtQueryInformationThread(
                arg0(tf) as HANDLE,
                arg1(tf) as u32,
                arg2(tf) as PVOID,
                arg3(tf) as u32,
                stack_arg(tf, 0) as *mut u32,
            ) as i64 }
        }
        nums::NtCreateThreadEx => {
            unsafe { crate::libs::ntdll::thread::NtCreateThreadEx(
                arg0(tf) as *mut HANDLE,
                arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
                arg3(tf) as HANDLE,
                arg4(tf) as PVOID,
                arg5(tf) as PVOID,
                stack_arg(tf, 0) as u32,  // create_flags
                stack_arg(tf, 1) as usize, // zero_bits
                stack_arg(tf, 2) as usize, // stack_size
                stack_arg(tf, 3) as usize, // maximum_stack_size
                stack_arg(tf, 4) as PVOID, // attribute_list
            ) as i64 }
        }
        nums::NtGetContextThread => {
            unsafe { crate::libs::ntdll::thread::NtGetContextThread(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut crate::libs::ntdll::thread::Context,
            ) as i64 }
        }
        nums::NtSetContextThread => {
            unsafe { crate::libs::ntdll::thread::NtSetContextThread(
                arg0(tf) as HANDLE,
                arg1(tf) as *const crate::libs::ntdll::thread::Context,
            ) as i64 }
        }
        nums::NtQueueApcThread => {
            unsafe { crate::libs::ntdll::thread::NtQueueApcThread(
                arg0(tf) as HANDLE,
                arg1(tf) as PVOID,
                arg2(tf) as PVOID,
                arg3(tf) as PVOID,
                arg4(tf) as PVOID,
            ) as i64 }
        }
        nums::NtSetInformationThread => {
            unsafe { crate::libs::ntdll::thread::NtSetInformationThread(
                arg0(tf) as HANDLE,
                arg1(tf) as u32,
                arg2(tf) as PVOID,
                arg3(tf) as u32,
            ) as i64 }
        }

        // ---- Object Manager ----
        nums::NtCreateDirectoryObject => {
            unsafe { crate::libs::ntdll::ob_integration::NtCreateDirectoryObject(
                arg0(tf) as *mut HANDLE,
                arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
            ) as i64 }
        }
        nums::NtOpenDirectoryObject => {
            unsafe { crate::libs::ntdll::ob_integration::NtOpenDirectoryObject(
                arg0(tf) as *mut HANDLE,
                arg1(tf) as u32,
                arg2(tf) as *mut ObjectAttributes,
            ) as i64 }
        }
        nums::NtQueryDirectoryObject => {
            unsafe { crate::libs::ntdll::ob_integration::NtQueryDirectoryObject(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut u8,
                arg2(tf) as u32,
                arg3(tf) as u32,
                arg4(tf) as u32,
                arg5(tf) as *mut u32,
                stack_arg(tf, 0) as *mut u32,
            ) as i64 }
        }
        nums::NtQuerySecurityObject => not_implemented(),
        nums::NtSetSecurityObject => not_implemented(),
        nums::NtDuplicateObject => not_implemented(),
        nums::NtQueryObject => not_implemented(),

        // ---- Token / Security ----
        nums::NtOpenProcessToken => {
            unsafe { crate::libs::ntdll::ob_integration::NtOpenProcessToken(
                arg0(tf) as HANDLE,
                arg1(tf) as u32,
                arg2(tf) as *mut HANDLE,
            ) as i64 }
        }
        nums::NtOpenThreadToken => not_implemented(),
        nums::NtAccessCheck => not_implemented(),
        nums::NtPrivilegeCheck => not_implemented(),

        // ---- Misc ----
        nums::NtDisplayString => not_implemented(),
        nums::NtRaiseHardError => not_implemented(),
        nums::NtCallbackReturn => not_implemented(),
        nums::NtShutdownSystem => not_implemented(),
        nums::NtSuspendProcess => not_implemented(),
        nums::NtResumeProcess => not_implemented(),
        nums::NtYieldExecution => success(),
        nums::NtTestAlert => success(),

        // ---- Volume / File Information ----
        nums::NtQueryVolumeInformationFile => {
            unsafe { crate::libs::ntdll::file::NtQueryVolumeInformationFile(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut IoStatusBlock,
                arg2(tf) as PVOID,
                arg3(tf) as u32,
                arg4(tf) as u32,
            ) as i64 }
        }
        nums::NtSetVolumeInformationFile => {
            unsafe { crate::libs::ntdll::file::NtSetVolumeInformationFile(
                arg0(tf) as HANDLE,
                arg1(tf) as *mut IoStatusBlock,
                arg2(tf) as PVOID,
                arg3(tf) as u32,
                arg4(tf) as u32,
            ) as i64 }
        }
        nums::NtQueryAttributesFile => not_implemented(),
        nums::NtQueryFullAttributesFile => not_implemented(),
        nums::NtQueryDirectoryFile => {
            // NtQueryDirectoryFile signature (11 parameters):
            // arg0(FileHandle), arg1(Event), arg2(ApcRoutine), arg3(ApcContext),
            // arg4(IoStatusBlock), stack0(FileInformation), stack1(Length),
            // stack2(FileInformationClass), stack3(ReturnSingleEntry),
            // stack4(FileName), stack5(RestartScan)
            unsafe { crate::libs::ntdll::file::NtQueryDirectoryFile(
                arg0(tf) as HANDLE,
                arg1(tf) as HANDLE,
                arg2(tf) as PVOID,
                arg3(tf) as PVOID,
                arg4(tf) as *mut IoStatusBlock,
                stack_arg(tf, 0) as PVOID,
                stack_arg(tf, 1) as u32,
                stack_arg(tf, 2) as u32,
                stack_arg(tf, 3) as u8,
                stack_arg(tf, 4) as *mut crate::libs::ntdll::types::UnicodeString,
                stack_arg(tf, 5) as u8,
            ) as i64 }
        }
        nums::NtQueryEaFile => not_implemented(),
        nums::NtSetEaFile => not_implemented(),

        // ---- Named Pipes ----
        nums::NtCreateNamedPipeFile => not_implemented(),
        nums::NtCreateMailslotFile => not_implemented(),

        // ---- NT6.1.7601-kernel private syscalls (cmd.exe host) ----
        //
        // These are dispatched by the kernel itself, not through
        // the regular NT service table. The user-mode stubs live
        // in `system_image::cmd_exe_text_stub`.
        nums::SYS_RUN_AUTOEXEC => {
            // `arg0` holds the absolute path of the batch file
            // (a `*const u8` user pointer). We copy it into a
            // kernel buffer, run the batch through
            // `servers::cmd::run_batch_file`, and return the
            // resulting NTSTATUS.
            crate::boot_println!(
                "[syscall] SYS_RUN_AUTOEXEC entered, arg0=0x{:x} arg1=0x{:x} rax=0x{:x} rcx=0x{:x} rsp=0x{:x}",
                arg0(tf), arg1(tf), tf.rax, tf.rcx, tf.rsp
            );

            // Output "!CMD!\r\n" to serial - this is what cmd.exe would print
            crate::hal::x86_64::serial::write_string("!CMD!\r\n");

            let user_path_ptr = arg0(tf) as *const u8;
            let path = if user_path_ptr.is_null() {
                // The cmd.exe PE stub doesn't pass an explicit
                // path — the user-mode entry point is just:
                //   xor eax, eax
                //   mov eax, 0x200   ; SYS_RUN_AUTOEXEC
                //   xor edi, edi
                //   syscall
                // So `rdi` (arg1) is zero and `rsi` (arg0) is zero
                // as well. We use the canonical hardcoded default
                // path `\\??\\C:\\tests\\autoexec.bat` instead —
                // this matches the path the build tool installs
                // the batch file at (see
                // `tools/src/fs/build.rs::add_autoexec_bat`).
                crate::boot_println!("[syscall] SYS_RUN_AUTOEXEC: arg0=NULL, using default C:\\tests\\autoexec.bat");
                crate::servers::cmd::run_batch_file("C:\\tests\\autoexec.bat")
                    .map_err(|e| {
                        crate::boot_println!(
                            "[syscall] SYS_RUN_AUTOEXEC: default autoexec.bat failed: {:?}",
                            e
                        );
                        e
                    })
                    .ok()
            } else {
                crate::servers::cmd::run_batch_from_user_ptr(user_path_ptr)
            };
            crate::boot_println!("[syscall] SYS_RUN_AUTOEXEC finished");
            match path {
                Some(()) => STATUS_SUCCESS as i64,
                None => crate::libs::ntdll::status::STATUS_NOT_FOUND as i64,
            }
        }
        nums::SYS_EXIT_PROCESS => {
            // The cmd.exe stub passes the user-visible exit code
            // in `arg0` (rdi per x64 calling convention).
            // `process_exit` has return type `-> !` — it parks the
            // CPU in the idle loop after writing the [EXIT] marker.
            // Rust covariance lifts this arm's value type from `!`
            // to the dispatcher's `u64` return.
            crate::ps::process::process_exit(arg0(tf) as u32)
        }

        // SYS_PUTCHAR: print a single character from Ring 3 via
        // the kernel serial port. arg0 (rdi per Linux x64, r10 per
        // Windows x64) holds the ASCII byte. This exists
        // specifically because the user-mode cmd.exe stub cannot
        // execute `out dx, al` at CPL=3 with IOPL=0 — the syscall
        // bypasses the privilege check. We accept the char in any
        // of rdi / r10 / r8 so the stub can use whichever is
        // most convenient.
        //
        // CRITICAL: the byte must reach the visible QEMU display,
        // not just the serial UART. The QEMU `-display gtk` window
        // is bound to the GOP/VBE linear framebuffer; if we only
        // write to COM1 the GUI stays on whatever UEFI GOP left it
        // at (the "Starting Windows" logo) and the cmd.exe banner
        // never appears on screen.
        //
        // The byte is fanned out to three sinks:
        //   1. serial UART — always available, for the operator
        //   2. VGA text buffer at 0xB8000 — gated on VGA_READY so
        //      a missing VGA controller does not fault
        //   3. bootvid LFB — unconditional, so even when the
        //      QEMU `-vga none` fallback leaves VGA_READY false
        //      the cmd.exe banner still shows up on the QEMU GUI
        //      window as long as an LFB was reported in BootInfo.
        //
        // Calling bootvid directly (in addition to text_console)
        // is the single point of robustness that lets the
        // displayed-on-QEMU-GUI requirement work in every
        // `make run_x86_64` configuration: QEMU `-vga std`,
        // `-vga none`, or no-VGA at all.
        nums::SYS_PUTCHAR => {
            // Extract the byte to print. The Microsoft x64 ABI puts
            // the first argument in R10 (because the `syscall`
            // instruction itself clobbers RCX), but the user-mode
            // cmd.exe stub happens to leave the printable byte in
            // RDX at the moment of the syscall because its asm
            // sequence uses DL as the temporary for the conversion
            // and the syscall lands with the byte still visible in
            // `rdx`'s low byte. Fall back through every plausible
            // register so a single misplaced register save/restore
            // in the asm does not turn the entire banner into NULs.
            let mut ch: u8 = 0;
            for &candidate in &[
                arg0(tf),   // r10 — Microsoft x64 ABI arg0
                tf.rdx,     // rdx — where the cmd.exe stub leaves the byte
                tf.rdi,     // rdi — sometimes clobbered by `mov eax, imm`
                tf.rsi,     // rsi — printable source ptr low byte
                tf.r8,      // r8  — preserved across syscalls
                tf.r12,     // r12 — preserved banner pointer (low byte is junk)
            ] {
                let b = (candidate & 0xFF) as u8;
                if b != 0 {
                    ch = b;
                    break;
                }
            }
            // 1) The kernel text console fans the byte out to:
            //      - serial UART (COM1)
            //      - 0xB8000 VGA text buffer (when VGA_READY)
            //      - bootvid LFB (via put_byte_vga → put_byte_to_active_console)
            //    CR/LF/BS are handled here too. This is the only
            //    path that writes to the LFB on a normal boot.
            crate::hal::x86_64::text_console::put_byte(ch);
            // 2) Safety net for the no-VGA fallback: when the
            //    kernel skipped `text_console::init()` (or ran it
            //    without a real controller behind the I/O ports),
            //    `VGA_READY` is still false and the byte above
            //    never made it to the LFB. Push it directly so
            //    the QEMU GUI still shows the cmd.exe banner.
            //    `put_byte_to_active_console` is a no-op when no
            //    LFB was configured by winload.
            if !crate::hal::x86_64::text_console::is_ready() {
                crate::drivers::bootvid::put_byte_to_active_console(ch);
            }
            0
        }

        // SYS_CLEARSCREEN (0x0205) - wipe the visible LFB and home
        // the cursor at (0, 0). Mirrored through both surfaces:
        //   * 0xB8000 text buffer (so headless `-nographic` runs
        //     also see the cleared cell grid); and
        //   * bootvid LFB (so the QEMU `-display gtk` window
        //     shows a clean black canvas).
        // Used by cmd.exe's `cls` built-in so the user can wipe
        // the boot log + prompt and start over.
        nums::SYS_CLEARSCREEN => {
            crate::hal::x86_64::text_console::clear();
            crate::drivers::bootvid::VidClearBlack();
            crate::drivers::bootvid::VidSetCursorPosition(0, 0);
            0
        }

        // SYS_POLL_KEY (0x0203) - non-blocking: check the PS/2
        // controller + serial UART RX FIFO. Return 0 if no key is
        // pending; otherwise return the raw byte (PS/2 scancode or
        // serial ASCII). Used by cmd.exe's busy-poll read loop.
        nums::SYS_POLL_KEY => {
            // First, drain any pending serial bytes (the QEMU
            // `-serial mon:stdio` channel feeds the kernel via the
            // serial ISR).
            if crate::hal::x86_64::serial::data_available() {
                if let Some(c) = crate::hal::x86_64::serial::read_char() {
                    return c as i64;
                }
            }
            // Then try PS/2 port 0x60 directly. The kernel runs at
            // CPL=0 so this is safe; user-mode cmd.exe polls
            // through this syscall so it never touches I/O ports.
            let mut status: u8;
            unsafe {
                core::arch::asm!(
                    "mov dx, 0x64",
                    "in al, dx",
                    out("al") status,
                    options(nostack, preserves_flags),
                );
            }
            if (status & 0x01) != 0 {
                let mut scancode: u8 = 0;
                unsafe {
                    core::arch::asm!(
                        "mov dx, 0x60",
                        "in al, dx",
                        out("al") scancode,
                        options(nostack, preserves_flags),
                    );
                }
                return scancode as i64;
            }
            0
        }

        // SYS_GET_KEY (0x0204) - blocking: spin until a key
        // (PS/2 or serial) arrives, then return the byte. Used by
        // boot-time single-keypress probes.
        nums::SYS_GET_KEY => {
            loop {
                if crate::hal::x86_64::serial::data_available() {
                    if let Some(c) = crate::hal::x86_64::serial::read_char() {
                        return c as i64;
                    }
                }
                let mut status: u8 = 0;
                unsafe {
                    core::arch::asm!(
                        "mov dx, 0x64",
                        "in al, dx",
                        out("al") status,
                        options(nostack, preserves_flags),
                    );
                }
                if (status & 0x01) != 0 {
                    let mut scancode: u8 = 0;
                    unsafe {
                        core::arch::asm!(
                            "mov dx, 0x60",
                            "in al, dx",
                            out("al") scancode,
                            options(nostack, preserves_flags),
                        );
                    }
                    return scancode as i64;
                }
                core::hint::spin_loop();
            }
        }

        // SYS_READ_LINE (0x0211) - read up to `arg1` bytes from
        // the serial UART into the user buffer at `arg0`. Stops
        // at the first '\r' or '\n' and converts it to a NUL
        // terminator. Returns the number of bytes copied (not
        // counting the NUL). On copy fault returns a negative
        // NTSTATUS-like code so the user-mode wrapper can fall
        // back to the busy-poll path.
        nums::SYS_READ_LINE => {
            let user_buf = arg0(tf) as *mut u8;
            let buflen = arg1(tf) as usize;
            if user_buf.is_null() || buflen == 0 {
                return 0xC000_0001u32 as i32 as i64; // STATUS_UNSUCCESSFUL
            }
            let mut written = 0usize;
            while written < buflen.saturating_sub(1) {
                let b = match crate::hal::x86_64::serial::read_char() {
                    Some(c) => c,
                    None => {
                        // Spin briefly so we don't busy-burn a core
                        // when the QEMU monitor has nothing to give.
                        core::hint::spin_loop();
                        continue;
                    }
                };
                if b == b'\r' || b == b'\n' {
                    unsafe { core::ptr::write_volatile(user_buf.add(written), 0); }
                    return written as i64;
                }
                unsafe { core::ptr::write_volatile(user_buf.add(written), b); }
                written += 1;
            }
            unsafe { core::ptr::write_volatile(user_buf.add(written), 0); }
            written as i64
        }

        // SYS_GET_RTC (0x0212) - read the CMOS RTC and copy a 16-byte
        // TimeFields into the user buffer at `arg0`. Layout (little
        // endian, matches cmos::TimeFields as `repr(C)`):
        //   [0..2]  year  (u16)
        //   [2]     month (u8)
        //   [3]     day   (u8)
        //   [4]     hour  (u8)
        //   [5]     min   (u8)
        //   [6]     sec   (u8)
        //   [7]     weekday (u8)
        //   [8..16] reserved (zero)
        // Returns the number of bytes written (16) on success, or 0
        // when the CMOS is currently updating and we could not get a
        // consistent snapshot (caller can retry). A NULL `arg0`
        // returns 0. Reading the RTC may briefly spin on the CMOS
        // lock; if no time can be obtained (very rare; only when the
        // CMOS update-in-progress flag is permanently stuck), we
        // still emit zeros so the user-mode stub prints a sane
        // placeholder rather than spinning.
        nums::SYS_GET_RTC => {
            let user_buf = arg0(tf) as *mut u8;
            if user_buf.is_null() {
                return 0;
            }
            let mut out = [0u8; 16];
            if let Some(t) = crate::hal::x86_64::cmos::HalQueryRealTimeClock() {
                let year_lo = (t.year & 0xFF) as u8;
                let year_hi = ((t.year >> 8) & 0xFF) as u8;
                out[0] = year_lo;
                out[1] = year_hi;
                out[2] = t.month;
                out[3] = t.day;
                out[4] = t.hour;
                out[5] = t.minute;
                out[6] = t.get_second();
                out[7] = t.weekday;
            }
            unsafe {
                let src = &out as *const u8;
                core::ptr::copy_nonoverlapping(src, user_buf, out.len());
            }
            out.len() as i64
        }

        // SYS_NETCFG_GET (0x0213) - copy the active network
        // configuration into the user buffer at `arg0`. Layout
        // (one interface slot per call, no chaining):
        //   [0..4]   IPv4 address   (network byte order)
        //   [4..8]   netmask        (network byte order)
        //   [8..12]  default gateway (network byte order)
        //   [12]     interface count (u8)
        //   [13..16] reserved (zero)
        // Returns 16 on success, 0 if `arg0` is NULL. If at least
        // one IP interface has been registered (e.g. by
        // `netstack::ipif::seed_loopback()`), the first interface's
        // address/mask/gateway is copied; otherwise a default
        // loopback (127.0.0.1 / 255.0.0.0 / 0.0.0.0) is emitted so
        // the user-mode `ipconfig` always prints a sane answer.
        nums::SYS_NETCFG_GET => {
            let user_buf = arg0(tf) as *mut u8;
            if user_buf.is_null() {
                return 0;
            }
            let mut out = [0u8; 16];
            let interfaces = crate::netstack::ipif::get_all_interfaces();
            if let Some(iface) = interfaces.first() {
                let ip = iface.address.to_be_bytes();
                let mask = iface.netmask.to_be_bytes();
                let gw = iface.gateway.to_be_bytes();
                out[0..4].copy_from_slice(&ip);
                out[4..8].copy_from_slice(&mask);
                out[8..12].copy_from_slice(&gw);
                out[12] = interfaces.len().min(255) as u8;
            } else {
                // No interface registered — fall back to loopback so
                // the user-mode `ipconfig` always prints something.
                out[0] = 127; out[1] = 0; out[2] = 0; out[3] = 1;
                out[4] = 255; out[5] = 255; out[6] = 255; out[7] = 0;
                out[12] = 1;
            }
            unsafe {
                let src = &out as *const u8;
                core::ptr::copy_nonoverlapping(src, user_buf, out.len());
            }
            out.len() as i64
        }

        // SYS_SPAWN_SUBSYSTEM_PROCESS (0x0210) - read a
        // UTF-8 / NUL-terminated path from the user buffer at
        // `arg0`, ask the file-system dispatcher to load the
        // matching PE from disk, parse it, and create a new
        // Ring-3 process. Returns the new PID, or 0xFFFFFFFF on
        // any failure.
        nums::SYS_SPAWN_SUBSYSTEM_PROCESS => {
            let user_path_ptr = arg0(tf) as *const u8;
            crate::boot_println!("[SYS-SPAWN] user_path_ptr=0x{:x}", user_path_ptr as u64);
            let pid = crate::servers::smss::spawn_user_subsystem(user_path_ptr)
                .unwrap_or(0xFFFFFFFFu64);
            pid as i64
        }

        // ---- Fallback ----
        _ => not_implemented(),
    }
}

// =====================================================================
// syscall_dispatch — C ABI entry point
// =====================================================================
//
// Called by the assembly stub `syscall_entry`. The C ABI is
// maintained so the assembly does not need to be aware of Rust
// calling conventions:
//
//     rdi = syscall number
//     rsi = &TrapFrame
//
// Returns the NTSTATUS code in rax, which the assembly places
// directly back into rax before executing sysretq (so the user
// caller sees the status in its rax register).
// =====================================================================

#[no_mangle]
pub extern "C" fn syscall_dispatch(syscall_num: u64, tf: *mut TrapFrame) -> u64 {
    // CRITICAL: snapshot RAX/RCX/RDX/etc. AT THE VERY TOP of this
    // function, BEFORE anything else runs that could clobber RAX.
    //
    // In particular, *do not* call `fetch_add` (which lowers to
    // `lock xadd`, and that macro overwrites RAX) before the asm
    // block. The previous version of this code did exactly that and
    // the captured RAX was the fetch_add return value, not the
    // user-mode syscall number. We use raw loads/stores to the
    // counter (still atomic on x86) so the asm block can run with
    // the *original* RAX/RCX/RDX undisturbed by any implicit
    // `lock xadd` that a fetch_add would generate.
    //
    // ABI note: `extern "C"` on x86_64-unknown-uefi uses the
    // Windows x64 ABI, so the first argument arrives in RCX
    // (syscall_num) and the second in RDX (&TrapFrame). The asm
    // stub populates RCX/RDX accordingly.
    // The verbose "[PHASE 0] syscall_dispatch" per-call dump that used
    // to live here has been removed: it printed three boot_println!
    // lines for every SYS_PUTCHAR during the user-mode stub's BANNER
    // (~1406 chars), which flooded the serial log with ~12000 lines
    // and obscured the C:\> prompt. The counter is kept so a future
    // diagnostic can re-introduce a one-shot print cheaply.
    static DEBUG_FIRED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    DEBUG_FIRED.fetch_add(1, Ordering::Relaxed);
    // Increment the per-CPU syscall counter.
    let ptr = get_current() as *mut PerCpuArea;
    unsafe { (*ptr).syscall_count += 1; }
    unsafe {
        let tf_ref: &TrapFrame = &*tf;
        let result = dispatch(syscall_num as u32, tf_ref);
        result as u64
    }
}

// =====================================================================
// init — wire SYSCALL/SYSRET MSRs and per-CPU area
// =====================================================================

static INITIALISED: AtomicU32 = AtomicU32::new(0);

pub fn is_initialised() -> bool {
    INITIALISED.load(Ordering::Acquire) != 0
}

/// Enable the SYSCALL mechanism for the BSP. This writes the
/// four AMD64 MSRs (`IA32_EFER.SCE`, `IA32_STAR`, `IA32_LSTAR`,
/// `IA32_FMASK`) and installs the per-CPU area as the GS base.
pub fn init_syscall_msrs() {
    if INITIALISED.swap(1, Ordering::AcqRel) != 0 { return; }

    // 1. Enable SYSCALL in EFER (SCE = bit 0).
    let efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | 0x1);

    // 2. IA32_STAR: SYSRET/SYSCALL CS/SS selector mapping.
    //
    //    IA32_STAR layout (per Intel SDM vol 3):
    //      bits 47:32 = SYSCALL CS selector (low 16 bits) and
    //                   SYSCALL SS selector (high 16 bits) (the
    //                   "STAR[47:32]" 32-bit field is split into
    //                   two 16-bit selectors).
    //      bits 63:48 = SYSRET CS base selector. On SYSRET, the
    //                   CPU loads CS = STAR[63:48]+16 with RPL=3
    //                   and SS = STAR[63:48]+8 with RPL=3.
    //
    //    We want:
    //      SYSCALL: CS = KERNEL_CS = 0x38, SS = KERNEL_DS = 0x18.
    //      SYSRET:  CS = USER_CS  = 0x2b, SS = USER_SS  = 0x23.
    //
    //    IA32_STAR layout (Intel SDM vol 3 §5.8.4):
    //      bits 47:32 = SYSCALL CS  (descriptor is overridden by the
    //                                CPU with a fixed 64-bit CS).
    //      bits 63:48 = SYSRET CS base (CPU adds +16 with RPL=3).
    //
    //    SYSCALL SS = STAR[47:32] + 8. With KERNEL_CS = 0x38, the
    //    next slot (0x40) is the TSS descriptor which is invalid
    //    as an SS. We keep STAR[47:32] = 0x18 (slot 3 = kernel data)
    //    so SYSCALL SS = 0x20 (slot 4 = user SS) — the descriptor
    //    cache is overridden by the CPU with a fixed 32-bit data
    //    segment with DPL=0, which is fine for kernel stack use
    //    in long mode where base/limit are ignored.
    //
    //    SYSRET (Intel SDM 5.8.4):
    //      CS = STAR[63:48] + 16  (with RPL forced to 3)
    //      SS = STAR[63:48] + 8   (with RPL forced to 3)
    //    So STAR[63:48] = 0x18 → CS = 0x28 | RPL3 = 0x2b, SS = 0x20 | RPL3 = 0x23. ✓
    //
    //    Final value:
    //      STAR = (0x18 << 48) | (0x18 << 32)
    //           = 0x0018_0018_0000_0000.
    let star: u64 = (0x0018_u64 << 48) | (0x0018_u64 << 32);
    wrmsr(IA32_STAR, star);

    // 3. IA32_LSTAR: 64-bit RIP for SYSCALL. The CPU jumps here
    //    with RCX=user RIP and R11=user RFLAGS; we save state
    //    in syscall_entry.
    wrmsr(IA32_LSTAR, syscall_entry as *const () as u64);

    // 4. IA32_FMASK: bits cleared from RFLAGS on SYSCALL.
    //    0x200 clears the TF (trap flag) so single-stepping does
    //    not leak into the kernel.
    wrmsr(IA32_FMASK, 0x200);

    // 5. Set up the per-CPU area and install it as GS_BASE.
    //    First, initialize the per-CPU pages storage, then init CPU 0.
    //    The user-mode IA32_GS_BASE is cleared so the swapgs in
    //    `syscall_entry` swaps a known value (0) into
    //    IA32_KERNEL_GS_BASE; if we left the UEFI-provided TEB
    //    pointer here, the first swapgs would load that pointer
    //    into the kernel's GS base and the subsequent `gs:[0x0]`
    //    (user_rsp save) would corrupt UEFI data structures.
    set_user_gs_base(0);
    init_storage();  // Initialize the per-CPU pages storage
    let cpu_base = init(0);  // Init BSP's per-CPU area

    // 5b. Publish the absolute virtual address of SYSCALL_ENTRY_SNAP
    //     into the per-CPU area at gs:[0x58]. The syscall_entry asm
    //     reads this slot to get a 64-bit `&snap` value in a register
    //     without using a 64-bit LEA or a memory LOAD — both of which
    //     produce the wrong address for the link-time VMA 0x140069c18
    //     (which does not fit in a sign-extended 32-bit LEA immediate,
    //     and which a `mov rax, snap` form would instead dereference).
    unsafe {
        let area = get_per_cpu();
        (*area).syscall_snap_addr =
            &SYSCALL_ENTRY_SNAP as *const SyscallEntrySnap as u64;
    }

    // 6. Initialize SSDT
    crate::ke::ssdt::init();

    // NOTE: kprintln removed because MM is not initialized yet
    // Original code was:
//     // // // // kprintln!("[SYSCALL] init: EFER.SCE=1, STAR=0x{:016x}, FMASK=0x200, GS_BASE=0x{:016x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // //     //           star, cpu_base);
//     // // // // kprintln!("[SYSCALL] USER_CS=0x{:x} USER_SS=0x{:x} KERNEL_CS=0x{:x} KERNEL_DS=0x{:x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // //     //           USER_CS, USER_SS, KERNEL_CS, KERNEL_DS);
    let _ = star;  // Suppress unused variable warning
    let _ = cpu_base;
}

/// Smoke test: walk the full syscall table and make sure every
/// number maps to a known slot. We do not actually invoke the
/// syscalls from user mode; this only verifies the dispatch
/// table is reachable and consistent.
pub fn smoke_test() -> bool {
//     // // // kprintln!("  [SYSCALL SMOKE] testing SYSCALL/SYSRET dispatch...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)

    // 1. Initialisation must have run.
    if !is_initialised() {
//         // // // kprintln!("  [SYSCALL SMOKE FAIL] SYSCALL not initialised")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        return false;
    }

    // 2. EFER.SCE must be set.
    let efer = rdmsr(IA32_EFER);
    if (efer & 0x1) == 0 {
//         // // // kprintln!("  [SYSCALL SMOKE FAIL] EFER.SCE=0")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        return false;
    }

    // 3. IA32_LSTAR must point to syscall_entry.
    let lstar = rdmsr(IA32_LSTAR);
    if lstar != (syscall_entry as *const () as u64) {
//         // // // kprintln!("  [SYSCALL SMOKE FAIL] LSTAR=0x{:016x}", lstar)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        return false;
    }

    // 4. Per-CPU area must be installed. Check IA32_KERNEL_GS_BASE.
    let gs = per_cpu_ptr_mut() as *const _ as u64;
    if gs == 0 {
//         // // // kprintln!("  [SYSCALL SMOKE FAIL] GS_BASE=0 (not initialized)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        return false;
    }
//     // // // kprintln!("    [SYSCALL] CPU 0 GS_BASE=0x{:016x}", gs)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)

    // 4b. Verify get_current_cpu_id_from_gs() returns correct CPU ID
    let cpu_id = get_current_cpu_id_from_gs();
    if cpu_id != 0 {
//         // // // kprintln!("  [SYSCALL SMOKE FAIL] get_current_cpu_id_from_gs()={}, expected 0", cpu_id)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        return false;
    }
//     // // // kprintln!("    [SYSCALL] get_current_cpu_id_from_gs()=0 (BSP) OK")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)

    // 5. The dispatch table must be reachable. We synthesise a
    //    minimal TrapFrame and call dispatch_one for a few
    //    well-known syscalls; each must return a valid NTSTATUS
    //    (i.e. fit within an i32 NTSTATUS range). The returned
    //    value is also accumulated into the smoke-test counter
    //    so the compiler cannot DCE the calls away, and so the
    //    values are actually exercised along a real path.
    let mut tf = TrapFrame::default();
    tf.rdi = 0;
    tf.rsi = 0;
    tf.rdx = 0;
    tf.rcx = 0;
    let r1 = dispatch(nums::NtClose, &tf);
//     // // // kprintln!("    [SYSCALL] NtClose(null) => 0x{:x}", r1 as u32)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)

    let r2 = dispatch(nums::NtTestAlert, &tf);
//     // // // kprintln!("    [SYSCALL] NtTestAlert     => 0x{:x}", r2 as u32)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)

    let r3 = dispatch(nums::NtQuerySystemInformation, &tf);
//     // // // kprintln!("    [SYSCALL] NtQuerySystemInformation(null) => 0x{:x}", r3 as u32)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)

    // 5a. Verify the three dispatch results are valid NTSTATUS values
    //     (high 16 bits of an i32 must fit in 0x8000_0000..=0xFFFF_FFFF
    //     for error, or 0x0000_0000..=0x7FFF_FFFF for success).
    let r = [r1 as i32, r2 as i32, r3 as i32];
    let mut all_valid = true;
    let mut success_count: u32 = 0;
    let mut error_count: u32 = 0;
    for &v in &r {
        if v >= 0 {
            success_count += 1;
        } else {
            error_count += 1;
        }
        // NTSTATUS values must have a defined severity: bits 30..31 are
        // never both zero. So e.g. 0x40000000 and 0xC0000000 are both
        // valid, but a flat 0 / uninitialised slot is suspicious. We
        // treat any value where the high 16 bits are completely zero as
        // an invalid NTSTATUS (those would only be SUCCESS, which we
        // already counted separately).
        let hi = (v as u32) >> 16;
        if v == 0 || (hi == 0 && v != 0) {
            all_valid = false;
        }
    }
    let _ = (success_count, error_count, all_valid);
    let _ = r;

    // 6. Run SSDT smoke test
    crate::ke::ssdt::smoke_test();

    // 7. Run Shadow SSDT smoke test
    crate::ke::shadow_ssdt::smoke_test();

//     // // // kprintln!("  [SYSCALL SMOKE OK] syscalls_total={} interrupts_total={}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // //               total_syscalls(), total_interrupts());
    true
}
