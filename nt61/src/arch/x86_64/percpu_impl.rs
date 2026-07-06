//! x86_64 per-CPU implementation.
//
//! Uses IA32_KERNEL_GS_BASE MSR + GS segment. Each CPU's per-CPU
//! area is installed as the GS base, and the `swapgs` instruction
//! swaps between the kernel GS base and user GS base on syscall/sysret.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::common::percpu::{PerCpuArea, MAX_PER_CPU, PER_CPU_AREA_SIZE};
use crate::ps::process::Eprocess;
use crate::ps::thread::Ethread;

// =====================================================================
// MSR helpers
// =====================================================================

const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
const IA32_GS_BASE: u32 = 0xC0000101;

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

// =====================================================================
// Per-CPU area storage
// =====================================================================

/// Per-CPU area storage array. Each CPU has its own page.
static PER_CPU_PAGES: [AtomicU64; MAX_PER_CPU] =
    [const { AtomicU64::new(0) }; MAX_PER_CPU];

/// BSP per-CPU area. Static so it can be used during early boot
/// before the pool allocator is ready.
static mut PER_CPU_0: PerCpuArea = PerCpuArea::new(0);

// =====================================================================
// Per-CPU offsets (hot path — referenced from idt_stubs.rs)
// =====================================================================

/// Offset of `user_rsp` inside PerCpuArea.
const OFFSET_USER_RSP: usize = 0;
/// Offset of `kernel_rsp` inside PerCpuArea.
const OFFSET_KERNEL_RSP: usize = 8;
/// Offset of `current_thread` inside PerCpuArea.
const OFFSET_CURRENT_THREAD: usize = 16;
/// Offset of `current_process` inside PerCpuArea.
const OFFSET_CURRENT_PROCESS: usize = 24;

// =====================================================================
// Exported functions (used by arch/common/percpu.rs via extern "Rust")
// =====================================================================

/// Initialize the per-CPU area for `cpu_id` and install it as the GS
/// base. For BSP (cpu_id=0) uses the static `PER_CPU_0`; for APs
/// allocates a new page from the kernel pool.
///
/// CRITICAL: failure is fatal — the kernel cannot run without a GS base.
#[no_mangle]
    pub unsafe extern "Rust" fn __percpu_init(cpu_id: u32) -> u64 {
    let page = if cpu_id == 0 {
        core::ptr::addr_of_mut!(PER_CPU_0) as u64
    } else {
        allocate(cpu_id)
    };

    if page == 0 {
        crate::mm::fatal_alloc::<PerCpuArea>("x86_64 percpu init");
    }

    // Initialize fields
    let area = &mut *(page as *mut PerCpuArea);
    area.cpu_id = cpu_id;
    area.kernel_rsp = 0;
    area.current_thread = core::ptr::null_mut();
    area.current_process = core::ptr::null_mut();
    area.irql = 0;
    area.syscall_count = 0;
    area.interrupt_count = 0;

    // Install as GS base for this CPU.
    //
    // The empirical observation on x86-64 long-mode CPUs is that
    // the `gs:` prefix resolves GS.base to **IA32_GS_BASE**
    // (regardless of CPL, regardless of the GS descriptor's DPL).
    // We therefore install &PER_CPU_0 into BOTH MSRs so that gs:
    // writes always land on the per-CPU area, then rely on
    // `swapgs` in syscall_entry / iretq to swap them in/out as
    // we cross the kernel/user boundary.
    //
    // After init (we are in the kernel): gs:[off] = &PER_CPU_0+off
    // via IA32_GS_BASE.
    //
    // The first_user_enter trampoline performs a `swapgs` immediately
    // before its iretq, so the user-mode gs: will access the
    // (zero) KERNEL_GS_BASE rather than the kernel per-cpu area.
    wrmsr(IA32_GS_BASE, page);
    wrmsr(IA32_KERNEL_GS_BASE, page);

    // Verify the MSR was written correctly
    if rdmsr(IA32_GS_BASE) != page {
        crate::mm::fatal_alloc::<PerCpuArea>("x86_64 GS_BASE mismatch");
    }

    PER_CPU_PAGES[cpu_id as usize].store(page, Ordering::Release);
    page
}

/// Initialize the per-CPU storage (called during BSP boot before
/// the pool is ready). Sets up `PER_CPU_PAGES[0]` pointing to `PER_CPU_0`.
#[no_mangle]
pub fn init_storage() {
    PER_CPU_PAGES[0].store(
        core::ptr::addr_of_mut!(PER_CPU_0) as u64,
        Ordering::Release,
    );
}

/// Allocate and zero a per-CPU area page for the given CPU id.
/// Returns the virtual address of the allocated page, or 0 on failure.
pub unsafe fn allocate(cpu_id: u32) -> u64 {
    if cpu_id as usize >= MAX_PER_CPU {
        return 0;
    }
    let page = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        PER_CPU_AREA_SIZE,
    ) as u64;
    if page == 0 {
        return 0;
    }
    core::ptr::write_bytes(page as *mut u8, 0, PER_CPU_AREA_SIZE);
    let area = &mut *(page as *mut PerCpuArea);
    area.cpu_id = cpu_id;
    PER_CPU_PAGES[cpu_id as usize].store(page, Ordering::Release);
    page
}

/// Return a mutable reference to the current CPU's PerCpuArea.
/// Reads IA32_KERNEL_GS_BASE to find the GS base.
#[no_mangle]
pub fn __percpu_get_current() -> &'static mut PerCpuArea {
    let gs_base = rdmsr(IA32_KERNEL_GS_BASE);
    if gs_base == 0 {
        // Early boot: fall back to BSP area
        unsafe { &mut *core::ptr::addr_of_mut!(PER_CPU_0) }
    } else {
        unsafe { &mut *(gs_base as *mut PerCpuArea) }
    }
}

/// Return the CPU id of the currently executing CPU.
#[no_mangle]
pub fn __percpu_get_current_cpu_id() -> u32 {
    let gs_base = rdmsr(IA32_KERNEL_GS_BASE);
    if gs_base == 0 {
        return 0;
    }
    // cpu_id is at offset 12
    let cpu_id: u32;
    unsafe {
        cpu_id = *(gs_base as *const u32).add(3);
    }
    cpu_id
}

/// Set the kernel stack pointer for the next user→kernel transition.
#[no_mangle]
pub fn __percpu_set_kernel_stack(sp: u64) {
    unsafe {
        core::arch::asm!(
            "mov gs:[{off}], {v}",
            off = const OFFSET_KERNEL_RSP,
            v   = in(reg) sp,
            options(nostack, preserves_flags),
        );
    }
}

/// Set the user-mode stack pointer for the next kernel→user return.
#[no_mangle]
pub fn __percpu_set_user_rsp(sp: u64) {
    unsafe {
        core::arch::asm!(
            "mov gs:[{off}], {v}",
            off = const OFFSET_USER_RSP,
            v   = in(reg) sp,
            options(nostack, preserves_flags),
        );
    }
}

/// Publish the ETHREAD pointer into the per-CPU `current_thread` slot.
#[no_mangle]
pub fn __percpu_set_current_thread(thread: *mut Ethread) {
    unsafe {
        core::arch::asm!(
            "mov gs:[{off}], {v}",
            off = const OFFSET_CURRENT_THREAD,
            v   = in(reg) thread as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Read the ETHREAD pointer from the per-CPU `current_thread` slot.
#[no_mangle]
pub fn __percpu_get_current_thread() -> *mut Ethread {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mov {v}, gs:[{off}]",
            off = const OFFSET_CURRENT_THREAD,
            v   = out(reg) v,
            options(nostack, preserves_flags),
        );
    }
    v as *mut Ethread
}

/// Publish the EPROCESS pointer into the per-CPU `current_process` slot.
#[no_mangle]
pub fn __percpu_set_current_process(process: *mut Eprocess) {
    unsafe {
        core::arch::asm!(
            "mov gs:[{off}], {v}",
            off = const OFFSET_CURRENT_PROCESS,
            v   = in(reg) process as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Read the EPROCESS pointer from the per-CPU `current_process` slot.
#[no_mangle]
pub fn __percpu_get_current_process() -> *mut Eprocess {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mov {v}, gs:[{off}]",
            off = const OFFSET_CURRENT_PROCESS,
            v   = out(reg) v,
            options(nostack, preserves_flags),
        );
    }
    v as *mut Eprocess
}
