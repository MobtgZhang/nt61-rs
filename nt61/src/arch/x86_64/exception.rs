//! x86_64 hardware exception handlers.

use crate::arch::common::trap_frame::TrapFrame;
use crate::arch::x86_64::debug::{read_dr6, read_dr7};
use crate::ke::exception::{
    rtl_dispatch_exception, ContextFrame, ExceptionDisposition, ExceptionRecord,
    EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT, EXCEPTION_DIVIDE_BY_ZERO,
    EXCEPTION_ILLEGAL_INSTRUCTION, EXCEPTION_PRIVILEGED_INSTRUCTION, EXCEPTION_SINGLE_STEP,
};
use crate::mm::access_fault::{self, AccessFlags, FaultStatus};

const DR6_MASK: u64 = 0x0000_0FFF;
const DR7_MASK: u64 = 0x0000_FFFF;

impl TrapFrame {
    fn to_context_frame(&self) -> ContextFrame {
        let mut context = ContextFrame::new();
        context.rax = self.rax;
        context.rcx = self.rcx;
        context.rdx = self.rdx;
        context.rbx = self.rbx;
        context.rbp = self.rbp;
        context.rsi = self.rsi;
        context.rdi = self.rdi;
        context.r8 = self.r8;
        context.r9 = self.r9;
        context.r10 = self.r10;
        context.r11 = self.r11;
        context.r12 = self.r12;
        context.r13 = self.r13;
        context.r14 = self.r14;
        context.r15 = self.r15;
        context.rip = self.rip;
        context.rsp = self.rsp;
        context.efl = self.rflags as u16;
        context
    }
}

pub fn handle_debug_exception(tf: &mut TrapFrame) -> ExceptionDisposition {
    let dr6 = read_dr6() & DR6_MASK;
    let _dr7 = read_dr7() & DR7_MASK;
    let _ = dr6;

    let mut record = ExceptionRecord::new(EXCEPTION_SINGLE_STEP, tf.rip);
    let mut context = tf.to_context_frame();
    rtl_dispatch_exception(&mut record, &mut context)
}

pub fn handle_breakpoint_exception(tf: &mut TrapFrame) -> ExceptionDisposition {
    tf.rip += 1;
    let mut record = ExceptionRecord::new(EXCEPTION_BREAKPOINT, tf.rip);
    let mut context = tf.to_context_frame();
    rtl_dispatch_exception(&mut record, &mut context)
}

pub fn handle_invalid_opcode(tf: &mut TrapFrame) -> ExceptionDisposition {
    let mut record = ExceptionRecord::new(EXCEPTION_ILLEGAL_INSTRUCTION, tf.rip);
    let mut context = tf.to_context_frame();
    rtl_dispatch_exception(&mut record, &mut context)
}

pub fn handle_privileged_instruction(tf: &mut TrapFrame) -> ExceptionDisposition {
    let mut record = ExceptionRecord::new(EXCEPTION_PRIVILEGED_INSTRUCTION, tf.rip);
    let mut context = tf.to_context_frame();
    rtl_dispatch_exception(&mut record, &mut context)
}

pub fn handle_page_fault(
    address: u64,
    _present: bool,
    write: bool,
    user: bool,
    tf: &mut TrapFrame,
) -> ExceptionDisposition {
    crate::ke::exception::record_exception();
    let info = [u64::from(write), address, u64::from(user)];
    let mut record = ExceptionRecord::with_info(EXCEPTION_ACCESS_VIOLATION, tf.rip, &info);
    let flags = AccessFlags {
        read: true,
        write,
        execute: false,
        user,
        reserved_bit: false,
        instruction_fetch: false,
    };

    if matches!(access_fault::handle(address, flags), FaultStatus::Handled) {
        return ExceptionDisposition::ExceptionHandled;
    }

    let mut context = tf.to_context_frame();
    rtl_dispatch_exception(&mut record, &mut context)
}

pub fn handle_divide_error(tf: &TrapFrame) -> ExceptionDisposition {
    let mut record = ExceptionRecord::new(EXCEPTION_DIVIDE_BY_ZERO, tf.rip);
    let mut context = tf.to_context_frame();
    rtl_dispatch_exception(&mut record, &mut context)
}

pub fn handle_debug(tf: &mut TrapFrame) -> ExceptionDisposition {
    let _dr6 = read_dr6() & DR6_MASK;
    let _dr7 = read_dr7() & DR7_MASK;
    let mut record = ExceptionRecord::new(EXCEPTION_SINGLE_STEP, tf.rip);
    let mut context = tf.to_context_frame();
    rtl_dispatch_exception(&mut record, &mut context)
}

pub fn handle_breakpoint(tf: &mut TrapFrame) -> ExceptionDisposition {
    tf.rip += 1;
    let mut record = ExceptionRecord::new(EXCEPTION_BREAKPOINT, tf.rip);
    let mut context = tf.to_context_frame();
    rtl_dispatch_exception(&mut record, &mut context)
}
