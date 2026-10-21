//! Architecture-neutral system-call argument frame.

use crate::arch::common::trap_frame::TrapFrame;

/// Maximum number of register and stack arguments retained by dispatch.
pub const SYSCALL_ARGUMENT_COUNT: usize = 12;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SyscallFrame {
    pub args: [u64; SYSCALL_ARGUMENT_COUNT],
}

impl SyscallFrame {
    pub fn from_args<const N: usize>(arguments: [u64; N]) -> Self {
        let mut frame = Self::default();
        for (index, value) in arguments.into_iter().enumerate() {
            frame.args[index] = value;
        }
        frame
    }

    #[cfg(target_arch = "x86_64")]
    pub unsafe fn from_trap_frame(frame: &TrapFrame) -> Self {
        use crate::arch::x86_64::syscall::{arg0, arg1, arg2, arg3, stack_arg};

        let arguments = [
            arg0(frame),
            arg1(frame),
            arg2(frame),
            arg3(frame),
            stack_arg(frame, 0),
            stack_arg(frame, 1),
            stack_arg(frame, 2),
            stack_arg(frame, 3),
            stack_arg(frame, 4),
            stack_arg(frame, 5),
            stack_arg(frame, 6),
            stack_arg(frame, 7),
        ];
        Self::from_args(arguments)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn from_trap_frame(_frame: &TrapFrame) -> Self {
        Self::default()
    }
}
