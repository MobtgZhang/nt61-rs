//! Canonical per-CPU area structure and architecture trait.
//
//! Each logical CPU has a private `PerCpuArea` that stores per-CPU
//! kernel state: current thread/process, kernel/user stack pointers,
//! IRQL, and instrumentation counters.
//
//! ## Memory layout (first 64 bytes are hot-path, accessed from asm)
//
//! | Offset | Field | Notes |
//! |--------|-------|-------|
//! | 0x00 | `user_rsp` | Saved user stack on syscall/trap entry |
//! | 0x08 | `kernel_rsp` | Kernel stack loaded on trap entry |
//! | 0x0C | `cpu_id` | Logical CPU number (0=BSP, 1+=APs) |
//! | 0x10 | `current_thread` | ETHREAD pointer |
//! | 0x18 | `current_process` | EPROCESS pointer |
//! | 0x20 | `irql` | Current IRQL |
//! | 0x28 | `syscall_count` | Per-CPU syscall counter |
//! | 0x30 | `interrupt_count` | Per-CPU interrupt counter |
//
//! ## Architecture mechanism
//
//! | Architecture | Register / Mechanism |
//! |--------------|---------------------|
//! | x86_64 | IA32_KERNEL_GS_BASE MSR + GS segment |
//! | aarch64 | TPIDR_EL1 (thread pointer register) |
//! | riscv64 | tp (x4) register |
//! | loongarch64 | tp CSR 0x13 |

use crate::ps::process::Eprocess;
use crate::ps::thread::Ethread;

// =====================================================================
// PerCpuArea — canonical structure (4 KiB, cache-line aligned)
// =====================================================================

/// Per-CPU area. One instance exists per logical CPU.
/// The first four fields are the ones most frequently accessed from
/// architecture-specific inline assembly stubs.
#[repr(C)]
#[repr(align(64))]
pub struct PerCpuArea {
    /// Saved user-mode stack pointer. Written by trap entry, restored
    /// by return-from-trap instruction.
    pub user_rsp: u64,
    /// Kernel stack pointer loaded on entry from user mode.
    pub kernel_rsp: u64,
    /// Logical CPU id (0 = BSP, 1+ = APs).
    pub cpu_id: u32,
    /// Padding to 8-byte align the pointer fields.
    pub _pad0: u32,
    /// Currently-running thread pointer.
    pub current_thread: *mut Ethread,
    /// Currently-running process pointer.
    pub current_process: *mut Eprocess,
    /// Current IRQL on this CPU.
    pub irql: u8,
    /// Padding for 8-byte alignment.
    pub _pad1: [u8; 7],
    /// Total number of syscalls handled on this CPU.
    pub syscall_count: u64,
    /// Total number of interrupts taken on this CPU.
    pub interrupt_count: u64,
    /// Architecture-specific pointer (TSS on x86_64, reserved elsewhere).
    pub arch_ptr: u64,
    /// Physical address of the system PML4. Used by the syscall /
    /// interrupt entry stubs to switch CR3 to the system PML4
    /// before running kernel handlers (which assume a W=1
    /// identity map and a stable system PML4). The system PML4 is
    /// always mapped W=1; the per-process user PML4 is normally a
    /// near-copy of it but its identity-map pages may be R/O, so
    /// page-table walks issued from the kernel while the user
    /// PML4 is active can fault on the first write to a
    /// page-table page.
    pub system_pml4: u64,
    /// Physical address of the per-process (user) PML4 active
    /// when the syscall / interrupt was taken. The syscall /
    /// interrupt stubs restore CR3 to this address before
    /// sysretq / iretq.
    pub user_pml4: u64,
    /// Absolute virtual address of the SYSCALL_ENTRY_SNAP static.
    /// The syscall_entry assembly reads this slot (gs:[0x58]) to
    /// get a 64-bit `&snap` pointer in a register without needing
    /// a 64-bit LEA or a memory LOAD — both of which produce the
    /// wrong address for the link-time VMA 0x140069c18 (which
    /// does not fit in a sign-extended 32-bit LEA immediate).
    pub syscall_snap_addr: u64,
    /// Reserved for future use / padding to 4 KiB.
    pub _reserved: [u64; 59],
}

impl PerCpuArea {
    /// Construct a zero-initialised per-CPU area for the given CPU id.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            user_rsp: 0,
            kernel_rsp: 0,
            cpu_id,
            _pad0: 0,
            current_thread: core::ptr::null_mut(),
            current_process: core::ptr::null_mut(),
            irql: 0,
            _pad1: [0; 7],
            syscall_count: 0,
            interrupt_count: 0,
            arch_ptr: 0,
            system_pml4: 0,
            user_pml4: 0,
            syscall_snap_addr: 0,
            _reserved: [0; 59],
        }
    }
}

impl Default for PerCpuArea {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Size of one per-CPU area in bytes. Must be page-aligned for pool allocation.
pub const PER_CPU_AREA_SIZE: usize = 4096;

/// Maximum number of CPUs supported.
pub const MAX_PER_CPU: usize = 64;

// =====================================================================
// Architecture-specific per-CPU implementation
// =====================================================================
//
// The following functions are provided by each architecture's
// `arch/*/percpu_impl.rs`. They must be implemented for every target.
//
// For x86_64 the implementation lives in `arch/x86_64/percpu_impl.rs`.
// The other architectures each provide their own `arch/*/percpu_impl.rs`.

extern "Rust" {
    /// Initialize the per-CPU area for `cpu_id` and install it as the
    /// CPU's per-CPU register/base. Returns the virtual address of the
    /// per-CPU area. Halts on fatal error.
    fn __percpu_init(cpu_id: u32) -> u64;

    /// Return a mutable reference to the current CPU's PerCpuArea.
    fn __percpu_get_current() -> &'static mut PerCpuArea;

    /// Return the CPU id of the currently executing CPU.
    fn __percpu_get_current_cpu_id() -> u32;

    /// Set the kernel stack pointer for the next user→kernel transition.
    fn __percpu_set_kernel_stack(sp: u64);

    /// Set the user-mode stack pointer for the next kernel→user return.
    fn __percpu_set_user_rsp(sp: u64);

    /// Publish the ETHREAD of the currently-running thread.
    fn __percpu_set_current_thread(thread: *mut Ethread);

    /// Read the ETHREAD pointer of the currently-running thread.
    fn __percpu_get_current_thread() -> *mut Ethread;

    /// Publish the EPROCESS of the currently-running process.
    fn __percpu_set_current_process(process: *mut Eprocess);

    /// Read the EPROCESS pointer of the currently-running process.
    fn __percpu_get_current_process() -> *mut Eprocess;
}

// =====================================================================
// Public API — delegates to arch-specific implementations
// =====================================================================

/// Initialize the per-CPU area for the given CPU and install it as
/// the per-CPU register/base for the current CPU.
///
/// For BSP (cpu_id=0), uses a static PerCpuArea.
/// For APs, allocates a new page from the kernel pool.
pub unsafe fn init(cpu_id: u32) -> u64 {
    unsafe { __percpu_init(cpu_id) }
}

/// Return a mutable reference to the current CPU's PerCpuArea.
pub fn get_current() -> &'static mut PerCpuArea {
    unsafe { __percpu_get_current() }
}

/// Return the CPU id of the currently executing CPU.
pub fn get_current_cpu_id() -> u32 {
    unsafe { __percpu_get_current_cpu_id() }
}

/// Set the kernel stack pointer for the next user→kernel transition.
pub fn set_kernel_stack(sp: u64) {
    unsafe { __percpu_set_kernel_stack(sp) }
}

/// Set the user-mode stack pointer for the next kernel→user return.
pub fn set_user_rsp(sp: u64) {
    unsafe { __percpu_set_user_rsp(sp) }
}

/// Publish the ETHREAD of the currently-running thread into the
/// per-CPU area's `current_thread` slot.
pub fn set_current_thread(thread: *mut Ethread) {
    unsafe { __percpu_set_current_thread(thread) }
}

/// Read the ETHREAD pointer of the currently-running thread from
/// the per-CPU area.
pub fn get_current_thread() -> *mut Ethread {
    unsafe { __percpu_get_current_thread() }
}

/// Publish the EPROCESS of the currently-running process into the
/// per-CPU area's `current_process` slot.
pub fn set_current_process(process: *mut Eprocess) {
    unsafe { __percpu_set_current_process(process) }
}

/// Read the EPROCESS pointer of the currently-running process.
pub fn get_current_process() -> *mut Eprocess {
    unsafe { __percpu_get_current_process() }
}
