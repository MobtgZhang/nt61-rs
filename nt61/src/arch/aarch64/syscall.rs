//! aarch64 system call (SVC #0) dispatch.
//!
//! ARMv8-A does not have an equivalent of the AMD64 `syscall`
//! instruction; user-mode programs issue `svc #0` which the CPU
//! traps to the configured `VBAR_EL1`+0x400 vector (lower-EL sync).
//! The lower-EL sync stub in `arch::aarch64::exception` saves the
//! user register context into a stack-resident [`TrapFrame`], reads
//! `ESR_EL1` to identify the trap class, and forwards the trap to
//! [`crate::arch::aarch64::trap::arch_aarch64_trap_dispatch`]. The
//! SVC case in that dispatcher reads the syscall number from `X16`
//! (Windows ARM64 calling convention) and calls
//! [`syscall_dispatch_with_tf`] defined here.
//!
//! The dispatch table currently implements a small but useful subset
//! of the NT 6.1 native API; every unrecognised syscall returns
//! `STATUS_NOT_IMPLEMENTED` (0xC0000002).

use super::trap::TrapFrame;

/// Trap frame for the aarch64 SVC handler (matches the layout saved
/// by the stubs in `exception.rs`).
pub use super::trap::TrapFrame as SvcTrapFrame;

#[cfg(target_arch = "aarch64")]
const STATUS_INVALID_SYSTEM_SERVICE: u64 = 0xC000_001C;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_NO_DATA: u64 = 0xC000_0011;

use crate::arch::common::cmd_host as host;

/// Dispatch a system call whose arguments and result are passed
/// via the `TrapFrame`. Reads the syscall number from `tf.x16`,
/// returns the NTSTATUS (placed back into `tf.x0` by the
/// dispatcher).
///
/// # Safety
///
/// `tf` must point to a valid [`TrapFrame`] captured by the SVC
/// stub.
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn syscall_dispatch_with_tf(syscall_num: u64, tf: *mut TrapFrame) -> u64 {
    // Bump the per-CPU syscall counter for instrumentation.
    let percpu = crate::arch::common::percpu::get_current();
    percpu.syscall_count = percpu.syscall_count.wrapping_add(1);

    let tf_ref: &mut TrapFrame = &mut *tf;
    let register_args = [
        tf_ref.x0 as usize,
        tf_ref.x1 as usize,
        tf_ref.x2 as usize,
        tf_ref.x3 as usize,
        tf_ref.x4 as usize,
        tf_ref.x5 as usize,
        tf_ref.x6 as usize,
        tf_ref.x7 as usize,
    ];
    let common_status = unsafe {
        crate::ke::ssdt_common::dispatch_syscall_with_stack(
            syscall_num as usize,
            register_args,
            crate::ke::ssdt_common::INTEGER_REGISTER_ARGUMENTS,
            tf_ref.sp as usize,
        )
    };
    let common_result = if common_status == crate::ke::ssdt_common::STATUS_INVALID_SYSTEM_SERVICE {
        None
    } else {
        Some(common_status)
    };
    if let Some(status) = common_result {
        return status as u64;
    }

    match syscall_num as u32 {
        // Yield execution.
        4 => 0, // STATUS_SUCCESS
        8 => {
            // NT_YIELD_EXECUTION equivalent: schedule another thread.
            crate::arch::halt();
            0
        }
        0x18 => {
            // Stub: write a byte to serial (debug only).
            let c = (tf_ref.x0 & 0xFF) as u8;
            crate::hal::aarch64::serial::put_char(c);
            0
        }
        0x19 => {
            // Stub: read a byte from serial (debug only).
            let c = crate::hal::aarch64::serial::try_get_char();
            tf_ref.x0 = match c {
                Some(b) => b as u64,
                None => u64::MAX,
            };
            if c.is_some() {
                0
            } else {
                STATUS_NO_DATA
            } // STATUS_NO_DATA
        }
        host::SYS_PUTCHAR => host::putchar((tf_ref.x0 & 0xFF) as u8),
        host::SYS_POLL_KEY => match host::poll_key() {
            Some(byte) => byte as u64,
            None => 0,
        },
        host::SYS_GET_KEY => {
            let byte = host::get_key();
            byte as u64
        }
        host::SYS_CLEARSCREEN => host::clear_screen(),
        host::SYS_READ_LINE => {
            match unsafe { host::read_line(tf_ref.x0 as *mut u8, tf_ref.x1 as usize) } {
                Some(written) => written as u64,
                None => 0,
            }
        }
        host::SYS_RETURN_TO_FIRMWARE => host::return_to_firmware(),
        host::SYS_CMD_EXECUTE => {
            match host::execute_command(tf_ref.x0 as *const u8, tf_ref.x1 as usize) {
                Ok(exited) => exited as u64,
                Err(_) => STATUS_INVALID_PARAMETER,
            }
        }
        host::SYS_PRINT_PROMPT => host::print_prompt(),
        _ => STATUS_INVALID_SYSTEM_SERVICE,
    }
}

/// Legacy entry point used by tests / older callers. Provides a
/// usable surface even when the full trap path is not yet wired up.
#[no_mangle]
pub extern "C" fn syscall_dispatch(syscall_num: u64, _tf: *mut TrapFrame) -> u64 {
    match syscall_num as u32 {
        0x18 => 0,
        0x19 => 0,
        4 | 8 => 0,
        _ => 0xC000001Cu64, // STATUS_INVALID_SYSTEM_SERVICE
    }
}
