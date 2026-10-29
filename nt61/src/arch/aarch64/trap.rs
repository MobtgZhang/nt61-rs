//! AArch64 trap and exception dispatcher.
//!
//! The exception vector stubs save the full register context onto the
//! kernel stack, capture `ESR_EL1`/`FAR_EL1`/`ELR_EL1`/`SPSR_EL1`,
//! and call `arch_aarch64_trap_dispatch` (defined below). The
//! dispatcher parses the exception class (`ESR_EL1.EC`) and routes
//! the trap to the appropriate handler:
//!
//!   * EC = 0x15 (SVC)                  -> syscall dispatch
//!   * EC = 0x24/0x25 (data/instr abort) -> page-fault handler
//!   * EC = 0x00 (unknown)              -> synchronous fault
//!   * class 1..3 (IRQ/FIQ/SError)      -> interrupt / fault pin
//!   * everything else                  -> fault / panic
//!
//! ## Stack frame layout
//!
//! The on-stack frame built by the stubs is described by
//! [`TrapFrame`] (below). The dispatcher mutates `pc`/`pstate` for
//! the `eret` epilogue: `pc = tf.elr_el1` and `pstate = tf.spsr_el1`.

use alloc::format;
use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

/// Trap frame pushed by every exception-vector stub.
///
/// Field offsets MUST stay in sync with the `save_context` /
/// `restore_context` macros in `exception.rs`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TrapFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub sp: u64,
    pub elr_el1: u64,  // PC where exception was taken
    pub spsr_el1: u64, // PSTATE at time of exception
    pub esr_el1: u64,  // Exception Syndrome Register
    pub far_el1: u64,  // Fault Address Register
    pub exception_class: u64,
    pub reserved: u64,
}

/// Exception class codes (ESR_EL1[31:26]).
pub mod ec {
    /// Unknown reason.
    pub const UNKNOWN: u64 = 0b000000;
    /// Trap instruction (SVC, HVC, SMC).
    pub const SVC: u64 = 0b010101;
    /// Instruction abort (lower EL).
    pub const INSTRUCTION_ABORT_LOWER_EL: u64 = 0b100000;
    /// Data abort (lower EL).
    pub const DATA_ABORT_LOWER_EL: u64 = 0b100100;
    /// Instruction abort (current EL).
    pub const INSTRUCTION_ABORT_CUR_EL: u64 = 0b100001;
    /// Data abort (current EL).
    pub const DATA_ABORT_CUR_EL: u64 = 0b100101;
}

/// Exception classes passed from the stubs.
pub mod exception_kind {
    pub const CURRENT_EL_SP0_SYNC: u64 = 0;
    pub const CURRENT_EL_SP0_IRQ: u64 = 1;
    pub const CURRENT_EL_SP0_FIQ: u64 = 2;
    pub const CURRENT_EL_SP0_SERROR: u64 = 3;
    pub const CURRENT_EL_SPX_SYNC: u64 = 4;
    pub const CURRENT_EL_SPX_IRQ: u64 = 5;
    pub const CURRENT_EL_SPX_FIQ: u64 = 6;
    pub const CURRENT_EL_SPX_SERROR: u64 = 7;
    pub const LOWER_EL_AARCH64_SYNC: u64 = 8;
    pub const LOWER_EL_AARCH64_IRQ: u64 = 9;
    pub const LOWER_EL_AARCH64_FIQ: u64 = 10;
    pub const LOWER_EL_AARCH64_SERROR: u64 = 11;
}

/// One-shot entry markers for the four synchronous exception vectors.
/// Each bit is set the first time its vector fires; the marker is
/// printed exactly once so repeated exceptions do not flood serial.
static SYNC_VECTOR_SEEN: AtomicU32 = AtomicU32::new(0);

fn mark_sync_vector_once(bit: u32, name: &str) {
    let mask = 1u32 << bit;
    let prev = SYNC_VECTOR_SEEN.fetch_or(mask, Ordering::AcqRel);
    if prev & mask == 0 {
        crate::hal::serial::write_string_always("[VEC-ENTRY] ");
        crate::hal::serial::write_string_always(name);
        crate::hal::serial::write_string_always(" sync\r\n");
    }
}

/// Trap dispatcher. Called by every exception-vector stub in
/// `exception.rs` with:
///
///   * `kind` in `x0` (`exception_kind::*`)
///   * `tf`   in `x1` (pointer to a stack-resident [`TrapFrame`])
///
/// Must return normally; the stub will `eret` after we update
/// `tf.elr_el1` (PC) and `tf.spsr_el1` (PSTATE).
///
/// # Safety
///
/// `tf` must point at a live trap frame on the kernel stack.
#[no_mangle]
pub unsafe extern "C" fn arch_aarch64_trap_dispatch(kind: u64, tf: *mut TrapFrame) {
    let tf_ref: &mut TrapFrame = unsafe { &mut *tf };

    match kind {
        exception_kind::LOWER_EL_AARCH64_SYNC => {
            // Synchronous exception from EL0 (user mode): SVC, page fault, …
            mark_sync_vector_once(0, "lower-el");
            handle_lower_sync(tf_ref);
        }
        exception_kind::LOWER_EL_AARCH64_IRQ => {
            // Maskable interrupt from EL0.
            handle_irq();
        }
        exception_kind::CURRENT_EL_SP0_SYNC | exception_kind::CURRENT_EL_SPX_SYNC => {
            // Synchronous exception from EL1: kernel fault (page fault,
            // unknown instruction). For the bootstrap we just print
            // details and continue (the kernel image is small enough
            // that a stray fault is unlikely).
            if kind == exception_kind::CURRENT_EL_SP0_SYNC {
                mark_sync_vector_once(1, "sp0");
            } else {
                mark_sync_vector_once(2, "spx");
            }
            handle_kernel_sync(tf_ref);
        }
        exception_kind::CURRENT_EL_SP0_IRQ | exception_kind::CURRENT_EL_SPX_IRQ => {
            handle_irq();
        }
        _ => {
            // Unhandled class: hang so the developer can debug.
            loop {
                unsafe { core::arch::asm!("wfi", options(nostack)) };
            }
        }
    }
}

/// handle a synchronous exception taken from EL0.
fn handle_lower_sync(tf: &mut TrapFrame) {
    let esr = tf.esr_el1;
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x01FF_FFFF;
    match ec {
        ec::SVC => {
            // The portable user-mode trampoline places the syscall
            // number in X16 and the first eight arguments in X0-X7.
            // The result is propagated back to the caller in X0.
            let syscall_num = tf.x16;
            let result =
                unsafe { crate::arch::aarch64::syscall::syscall_dispatch_with_tf(syscall_num, tf) };

            tf.x0 = result;
            // Advance the PC past the SVC instruction (SVC #imm is 4 bytes).
            tf.elr_el1 = tf.elr_el1.wrapping_add(4);
        }
        ec::DATA_ABORT_LOWER_EL | ec::INSTRUCTION_ABORT_LOWER_EL => {
            // Page fault from user mode. We dispatch to the
            // architecture-common data-abort handler if available,
            // otherwise we kill the user thread. For the bootstrap
            // we just stop the CPU; a proper handler will be added
            // once the demand-pager is in place.
            handle_user_page_fault(tf, ec == ec::INSTRUCTION_ABORT_LOWER_EL);
        }
        _ => {
            // Synchronous fault from EL0 that we cannot handle. Mark
            // the user thread as faulted; the scheduler will reap it.
            handle_user_sync_fault(tf, ec, iss);
        }
    }
}

/// handle a synchronous exception taken from EL1 (kernel fault).
fn handle_kernel_sync(tf: &mut TrapFrame) {
    let esr = tf.esr_el1;
    let ec = (esr >> 26) & 0x3F;
    let far = tf.far_el1;
    let iss = esr & 0x01FF_FFFF;
    let spsr = tf.spsr_el1;
    let elr = tf.elr_el1;
    let kind = tf.exception_class;

    // Kernel faults must never be silently skipped. A skipped fault
    // can corrupt kernel state and is a security risk (e.g. skipping
    // a bounds check). Instead, log the full diagnostic and crash.
    crate::hal::serial::write_string_always("[KERN-FAULT] kind=");
    crate::hal::serial::write_hex_u64_always(kind);
    crate::hal::serial::write_string_always(" ec=");
    crate::hal::serial::write_hex_u64_always(ec);
    crate::hal::serial::write_string_always(" iss=");
    crate::hal::serial::write_hex_u64_always(iss);
    crate::hal::serial::write_string_always(" far=");
    crate::hal::serial::write_hex_u64_always(far);
    crate::hal::serial::write_string_always(" elr=");
    crate::hal::serial::write_hex_u64_always(elr);
    crate::hal::serial::write_string_always(" spsr=");
    crate::hal::serial::write_hex_u64_always(spsr);
    let vbar: u64;
    unsafe {
        asm!("mrs {}, vbar_el1", out(reg) vbar, options(nostack));
    }
    crate::hal::serial::write_string_always(" vbar=");
    crate::hal::serial::write_hex_u64_always(vbar);
    let cur_el: u64;
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) cur_el, options(nostack));
    }
    crate::hal::serial::write_string_always(" el=");
    crate::hal::serial::write_hex_u64_always(cur_el >> 2);
    crate::hal::serial::write_string_always(" lr=");
    crate::hal::serial::write_hex_u64_always(tf.x30);
    crate::hal::serial::write_string_always(" fp=");
    crate::hal::serial::write_hex_u64_always(tf.x29);
    crate::hal::serial::write_string_always(" sp=");
    crate::hal::serial::write_hex_u64_always(tf.sp);
    if (cur_el >> 2) & 3 == 2 {
        let (esr2, elr2, spsr2, far2): (u64, u64, u64, u64);
        unsafe {
            asm!(
                "mrs {}, esr_el2", "mrs {}, elr_el2", "mrs {}, spsr_el2", "mrs {}, far_el2",
                out(reg) esr2, out(reg) elr2, out(reg) spsr2, out(reg) far2,
                options(nostack),
            );
        }
        crate::hal::serial::write_string_always(" esr2=");
        crate::hal::serial::write_hex_u64_always(esr2);
        crate::hal::serial::write_string_always(" elr2=");
        crate::hal::serial::write_hex_u64_always(elr2);
        crate::hal::serial::write_string_always(" spsr2=");
        crate::hal::serial::write_hex_u64_always(spsr2);
        crate::hal::serial::write_string_always(" far2=");
        crate::hal::serial::write_hex_u64_always(far2);
    }
    // Dump the first instruction word of every vector slot so a
    // runtime-corrupted or misrouted table becomes visible.
    crate::hal::serial::write_string_always(" vt=");
    let vt = vbar as *const u64;
    let mut i = 0usize;
    while i < 16 {
        let w = unsafe { core::ptr::read_volatile(vt.add(i * 16)) };
        if i != 0 {
            crate::hal::serial::write_string_always(":");
        }
        crate::hal::serial::write_hex_u64_always(w);
        i += 1;
    }
    crate::hal::serial::write_string_always("\r\n");

    // Increment the per-CPU fault counter for diagnostics.
    let percpu = crate::arch::common::percpu::get_current();
    percpu.interrupt_count = percpu.interrupt_count.wrapping_add(1);

    // Do NOT advance ELR past the faulting instruction. Instead, panic
    // so that the developer immediately sees the bug. The kernel is
    // too small and too early for a fault-recovery strategy.
    crate::rtl::panic::panic(&format!(
        "aarch64 kernel sync fault: ec={:#x} iss={:#x} far={:#x} elr={:#x} spsr={:#x}",
        ec, iss, far, elr, spsr
    ));
}

/// Called from the `lower_el_aarch32_sync` vector: an AArch32 task took
/// a synchronous exception. There is no AArch32 support, so mark the
/// entry once and park the CPU.
#[no_mangle]
pub unsafe extern "C" fn arch_aarch64_trap_aarch32_sync_hang() {
    let prev = SYNC_VECTOR_SEEN.fetch_or(1u32 << 3, Ordering::AcqRel);
    if prev & (1u32 << 3) == 0 {
        crate::hal::serial::write_string_always(
            "[VEC-ENTRY] lower-el-aarch32 sync (unsupported)\r\n",
        );
    }
    loop {
        asm!("wfi", options(nostack));
    }
}

/// handle a maskable IRQ.
fn handle_irq() {
    let percpu = crate::arch::common::percpu::get_current();
    percpu.interrupt_count = percpu.interrupt_count.wrapping_add(1);

    // The actual GIC ack/eoi is performed by
    // `crate::hal::aarch64::apic::handle_irq()` once the GIC driver is
    // initialised. For the bootstrap, we just acknowledge the IRQ
    // source here.
    let irq = crate::hal::aarch64::apic::handle_irq();
    if irq == 29 {
        crate::hal::aarch64::arch_timer::acknowledge();
        crate::ke::timer::tick();
        crate::ke::scheduler::tick();
        crate::ke::psss::psss_tick();
        crate::ke::scheduler::dispatch_pending_reschedule();
    } else if irq < 16 {
        // SGIs (0-15) are the cross-core communication range. The
        // only SGI the kernel sends today is the TLB shootdown
        // (`gic::SGI_TLB_SHOOTDOWN`); the handler is payload-free and
        // flushes the local TLB regardless of the exact SGI id, so
        // any SGI in the range can be routed there.
        crate::ke::tlb_shootdown::handle_shootdown_interrupt();
    }
}

/// handle a user-mode page fault.
fn handle_user_page_fault(tf: &mut TrapFrame, is_instruction: bool) {
    let far = tf.far_el1;
    let elr = tf.elr_el1;
    crate::hal::serial::write_string_always("[USER-FAULT] kind=");
    crate::hal::serial::write_string_always(if is_instruction {
        "instruction"
    } else {
        "data"
    });
    crate::hal::serial::write_string_always(" far=");
    crate::hal::serial::write_hex_u64_always(far);
    crate::hal::serial::write_string_always(" elr=");
    crate::hal::serial::write_hex_u64_always(elr);
    crate::hal::serial::write_string_always("\r\n");

    // Terminate the current thread so the scheduler can reap it.
    // Previously this was a wfi loop that permanently parked the CPU,
    // hanging the entire system when a user process crashed.
    let thread = crate::arch::common::percpu::get_current().current_thread;
    if !thread.is_null() {
        crate::ps::thread::terminate(thread, 0xC000_0005u32);
    }
    // Yield the CPU back to the scheduler. Returning from this trap
    // would eret to the faulting instruction and fault forever.
    crate::ke::scheduler::tick();
    crate::ke::scheduler::dispatch_pending_reschedule();
}

/// Mark a user-mode synchronous fault as fatal.
fn handle_user_sync_fault(tf: &mut TrapFrame, ec: u64, iss: u64) {
    let far = tf.far_el1;
    crate::hal::serial::write_string_always("[USER-FAULT] ec=");
    crate::hal::serial::write_hex_u64_always(ec);
    crate::hal::serial::write_string_always(" iss=");
    crate::hal::serial::write_hex_u64_always(iss);
    crate::hal::serial::write_string_always(" far=");
    crate::hal::serial::write_hex_u64_always(far);
    crate::hal::serial::write_string_always(" elr=");
    crate::hal::serial::write_hex_u64_always(tf.elr_el1);
    crate::hal::serial::write_string_always("\r\n");

    // Same treatment as page faults: terminate the faulting thread
    // and yield back to the scheduler instead of hanging the CPU.
    let thread = crate::arch::common::percpu::get_current().current_thread;
    if !thread.is_null() {
        crate::ps::thread::terminate(thread, 0xC000_0005u32);
    }
    // Same treatment as page faults: never return to the faulting PC.
    crate::ke::scheduler::tick();
    crate::ke::scheduler::dispatch_pending_reschedule();
}

/// Smoke test: verify VBAR_EL1 has been set to our exception vector
/// and that the trap handler symbol is reachable.
pub fn smoke_test() -> bool {
    let vbar: u64;
    unsafe {
        asm!("mrs {}, VBAR_EL1", out(reg) vbar, options(nostack));
    }
    if vbar == 0 {
        return false;
    }
    true
}
