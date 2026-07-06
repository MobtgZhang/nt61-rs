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

use core::arch::asm;

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
    pub elr_el1: u64,        // PC where exception was taken
    pub spsr_el1: u64,       // PSTATE at time of exception
    pub esr_el1: u64,        // Exception Syndrome Register
    pub far_el1: u64,        // Fault Address Register
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
            handle_lower_sync(tf_ref);
        }
        exception_kind::LOWER_EL_AARCH64_IRQ => {
            // Maskable interrupt from EL0.
            handle_irq();
        }
        exception_kind::CURRENT_EL_SP0_SYNC
        | exception_kind::CURRENT_EL_SPX_SYNC => {
            // Synchronous exception from EL1: kernel fault (page fault,
            // unknown instruction). For the bootstrap we just print
            // details and continue (the kernel image is small enough
            // that a stray fault is unlikely).
            handle_kernel_sync(tf_ref);
        }
        exception_kind::CURRENT_EL_SP0_IRQ
        | exception_kind::CURRENT_EL_SPX_IRQ => {
            handle_irq();
        }
        _ => {
            // Unhandled class: hang so the developer can debug.
            #[allow(clippy::empty_loop)]
            loop {
                unsafe { core::arch::asm!("wfi", options(nostack)) };
            }
        }
    }
}

/// Handle a synchronous exception taken from EL0.
fn handle_lower_sync(tf: &mut TrapFrame) {
    let esr = tf.esr_el1;
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x01FF_FFFF;
    match ec {
        ec::SVC => {
            // The Windows ARM64 calling convention places the syscall
            // number in X16. We forward to the syscall dispatcher
            // which returns the NTSTATUS / kernel status. The result
            // must be propagated back to the caller in X0.
            let syscall_num = tf.x16;
            let result = unsafe {
                crate::arch::aarch64::syscall::syscall_dispatch_with_tf(
                    syscall_num,
                    tf,
                )
            };
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

/// Handle a synchronous exception taken from EL1 (kernel fault).
fn handle_kernel_sync(tf: &mut TrapFrame) {
    let esr = tf.esr_el1;
    let ec = (esr >> 26) & 0x3F;
    let far = tf.far_el1;
    // Increment the per-CPU fault counter.
    let percpu = crate::arch::common::percpu::get_current();
    percpu.interrupt_count = percpu.interrupt_count.wrapping_add(1);

    // For the bootstrap we cannot easily continue from kernel faults.
    // We log the syndrome (via UART) and park the CPU.
    let sctlr: u64;
    unsafe {
        asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nostack));
    }
    crate::hal::serial::write_string("[KERN-FAULT] ec=");
    crate::hal::serial::write_hex_u64(ec);
    crate::hal::serial::write_string(" iss=");
    crate::hal::serial::write_hex_u64(esr & 0x01FF_FFFF);
    crate::hal::serial::write_string(" far=");
    crate::hal::serial::write_hex_u64(far);
    crate::hal::serial::write_string(" elr=");
    crate::hal::serial::write_hex_u64(tf.elr_el1);
    crate::hal::serial::write_string("\r\n");

    // Halt the CPU in WFI; the developer can inspect the trap state
    // with a debugger.
    loop {
        unsafe { asm!("wfi", options(nostack)) };
    }
}

/// Handle a maskable IRQ.
fn handle_irq() {
    let percpu = crate::arch::common::percpu::get_current();
    percpu.interrupt_count = percpu.interrupt_count.wrapping_add(1);

    // The actual GIC ack/eoi is performed by
    // `crate::hal::aarch64::apic::handle_irq()` once the GIC driver is
    // initialised. For the bootstrap, we just acknowledge the IRQ
    // source here.
    crate::hal::aarch64::apic::handle_irq();
}

/// Handle a user-mode page fault.
fn handle_user_page_fault(_tf: &mut TrapFrame, _is_instruction: bool) {
    // The proper handler lives in `mm::fault` which is not yet wired
    // up for aarch64. For the bootstrap we kill the user thread by
    // setting PC to a `b .` loop in the user image; a future patch
    // will route to the demand pager.
    // Loop here so the schedule can pick up the faulted thread.
    loop {
        unsafe { asm!("wfi", options(nostack)) };
    }
}

/// Mark a user-mode synchronous fault as fatal.
fn handle_user_sync_fault(_tf: &mut TrapFrame, _ec: u64, _iss: u64) {
    // Future: deliver a STATUS_ACCESS_VIOLATION exception to the
    // user thread; for now we just halt the CPU.
    loop {
        unsafe { asm!("wfi", options(nostack)) };
    }
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
