//! aarch64 per-CPU implementation.
//
//! Uses TPIDR_EL1 (thread pointer register at EL1). Each CPU's per-CPU
//! area address is stored in TPIDR_EL1, which can be read with `mrs xN, tpidr_el1`.
//
//! ## Memory layout (must match arch::common::percpu::PerCpuArea)
//
//! | Offset | Field |
//! |--------|-------|
//! | 0x00 | `user_sp` (saved user stack pointer) |
//! | 0x08 | `kernel_sp` (kernel stack pointer) |
//! | 0x0C | `cpu_id` |
//! | 0x10 | `current_thread` |
//! | 0x18 | `current_process` |
//! | 0x20 | `irql` |
//! | 0x28 | `syscall_count` |
//! | 0x30 | `interrupt_count` |

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::common::percpu::{PerCpuArea, MAX_PER_CPU, PER_CPU_AREA_SIZE};
use crate::ps::process::Eprocess;
use crate::ps::thread::Ethread;

// =====================================================================
// Per-CPU storage
// =====================================================================

/// Per-CPU area storage. Each CPU has its own page.
static PER_CPU_PAGES: [AtomicU64; MAX_PER_CPU] =
    [const { AtomicU64::new(0) }; MAX_PER_CPU];

/// BSP per-CPU area. Static so it can be used during early boot
/// before the pool allocator is ready.
static mut PER_CPU_0: PerCpuArea = PerCpuArea::new(0);

// =====================================================================
// Exported functions (used by arch/common/percpu.rs via extern "Rust")
// =====================================================================

/// Initialize the per-CPU area for `cpu_id` and install it as TPIDR_EL1.
/// For BSP (cpu_id=0) uses the static `PER_CPU_0`; for APs allocates
/// a new page from the kernel pool.
#[no_mangle]
pub unsafe extern "Rust" fn __percpu_init(cpu_id: u32) -> u64 {
    let page = if cpu_id == 0 {
        core::ptr::addr_of_mut!(PER_CPU_0) as u64
    } else {
        allocate(cpu_id)
    };

    if page == 0 {
        crate::mm::fatal_alloc::<PerCpuArea>("aarch64 percpu init");
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

    // Install as TPIDR_EL1 for this CPU
    set_tpidr_el1(page);

    PER_CPU_PAGES[cpu_id as usize].store(page, Ordering::Release);
    page
}

/// Initialize the per-CPU storage (called during BSP boot before the pool
/// is ready). Sets up `PER_CPU_PAGES[0]` pointing to `PER_CPU_0`.
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

/// Set TPIDR_EL1 to the given value.
#[inline(always)]
fn set_tpidr_el1(val: u64) {
    unsafe {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) val, options(nostack));
    }
}

/// Read TPIDR_EL1.
#[inline(always)]
fn get_tpidr_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) val, options(nostack));
    }
    val
}

/// Return a mutable reference to the current CPU's PerCpuArea.
/// Reads TPIDR_EL1 to find the per-CPU base.
#[no_mangle]
pub fn __percpu_get_current() -> &'static mut PerCpuArea {
    let base = get_tpidr_el1();
    if base == 0 {
        // Early boot: fall back to BSP area
        unsafe { &mut *core::ptr::addr_of_mut!(PER_CPU_0) }
    } else {
        unsafe { &mut *(base as *mut PerCpuArea) }
    }
}

/// Return the CPU id of the currently executing CPU.
#[no_mangle]
pub fn __percpu_get_current_cpu_id() -> u32 {
    let base = get_tpidr_el1();
    if base == 0 {
        return 0;
    }
    let cpu_id: u32;
    unsafe {
        cpu_id = *(base as *const u32).add(3); // offset 0x0C
    }
    cpu_id
}

/// Set the kernel stack pointer for the next user→kernel transition.
/// On aarch64 this writes to `current_thread` offset in the per-CPU area.
///
//  For aarch64, the kernel SP is tracked via SP_EL1. When entering from
//  user mode, we save the user SP in the per-CPU area and set SP_EL1
//  to the kernel stack. The `kernel_sp` field is at offset 0x08.
#[no_mangle]
pub fn __percpu_set_kernel_stack(sp: u64) {
    let base = get_tpidr_el1();
    if base == 0 {
        return;
    }
    unsafe {
        let ptr = (base as *mut u64).add(1); // offset 0x08
        ptr.write(sp);
    }
}

/// Set the user-mode stack pointer for the next kernel→user return.
#[no_mangle]
pub fn __percpu_set_user_rsp(sp: u64) {
    let base = get_tpidr_el1();
    if base == 0 {
        return;
    }
    unsafe {
        let ptr = base as *mut u64; // offset 0x00
        ptr.write(sp);
    }
}

/// Publish the ETHREAD pointer into the per-CPU `current_thread` slot.
#[no_mangle]
pub fn __percpu_set_current_thread(thread: *mut Ethread) {
    let base = get_tpidr_el1();
    if base == 0 {
        return;
    }
    unsafe {
        let ptr = (base as *mut *mut Ethread).add(2); // offset 0x10
        ptr.write(thread);
    }
}

/// Read the ETHREAD pointer from the per-CPU `current_thread` slot.
#[no_mangle]
pub fn __percpu_get_current_thread() -> *mut Ethread {
    let base = get_tpidr_el1();
    if base == 0 {
        return core::ptr::null_mut();
    }
    unsafe {
        let ptr = (base as *const *mut Ethread).add(2); // offset 0x10
        ptr.read()
    }
}

/// Publish the EPROCESS pointer into the per-CPU `current_process` slot.
#[no_mangle]
pub fn __percpu_set_current_process(process: *mut Eprocess) {
    let base = get_tpidr_el1();
    if base == 0 {
        return;
    }
    unsafe {
        let ptr = (base as *mut *mut Eprocess).add(3); // offset 0x18
        ptr.write(process);
    }
}

/// Read the EPROCESS pointer from the per-CPU `current_process` slot.
#[no_mangle]
pub fn __percpu_get_current_process() -> *mut Eprocess {
    let base = get_tpidr_el1();
    if base == 0 {
        return core::ptr::null_mut();
    }
    unsafe {
        let ptr = (base as *const *mut Eprocess).add(3); // offset 0x18
        ptr.read()
    }
}
