//! Architecture-neutral facade for hardware trap handlers.

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::exception::{
    handle_breakpoint, handle_breakpoint_exception, handle_debug, handle_debug_exception,
    handle_divide_error, handle_invalid_opcode, handle_page_fault, handle_privileged_instruction,
};

#[cfg(not(target_arch = "x86_64"))]
use crate::arch::common::trap_frame::TrapFrame;

#[cfg(not(target_arch = "x86_64"))]
use crate::ke::exception::ExceptionDisposition;

#[cfg(not(target_arch = "x86_64"))]
pub fn handle_breakpoint_exception(_: &mut TrapFrame) -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}

#[cfg(not(target_arch = "x86_64"))]
pub fn handle_debug_exception(_: &mut TrapFrame) -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}

#[cfg(not(target_arch = "x86_64"))]
pub fn handle_invalid_opcode(_: &mut TrapFrame) -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}

#[cfg(not(target_arch = "x86_64"))]
pub fn handle_privileged_instruction(_: &mut TrapFrame) -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}

#[cfg(not(target_arch = "x86_64"))]
pub fn handle_page_fault(
    _address: u64,
    _present: bool,
    _write: bool,
    _user: bool,
    _: &mut TrapFrame,
) -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}

#[cfg(not(target_arch = "x86_64"))]
pub fn handle_divide_error(_: &TrapFrame) -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}

#[cfg(not(target_arch = "x86_64"))]
pub fn handle_debug(_: &mut TrapFrame) -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}

#[cfg(not(target_arch = "x86_64"))]
pub fn handle_breakpoint(_: &mut TrapFrame) -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}
