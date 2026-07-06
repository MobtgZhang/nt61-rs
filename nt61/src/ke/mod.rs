//! Kernel Executive
//
//! Core kernel services and subsystems. The executive owns the
//! scheduler, the dispatcher, the timer and APC/DPC machinery, the
//! clock and IRQL helpers, the bugcheck path, and the
//! process-structure worker pool (`Mi*` / `Ps*` work items, a.k.a.
//! "PSSS" in this codebase).
//
//! `init()` walks the NT 6.1 bring-up order: scheduler -> interrupt
//! -> IRQL -> time -> timer -> APC -> DPC -> sync -> dispatch ->
//! psss -> bugcheck. The end-to-end smoke test lives in the
//! `smoke` submodule and is called from `kernel_main` after
//! Phase 9.

pub mod scheduler;
pub mod spinlock;
pub mod sync;
pub mod interrupt;
pub mod irql;
pub mod time;
pub mod timer;
pub mod apc;
pub mod dpc;
pub mod bugcheck;
pub mod dispatch;
pub mod psss;
#[cfg(target_arch = "x86_64")]
pub mod smoke;
pub mod exception;
#[cfg(target_arch = "x86_64")]
pub mod ssdt;
#[cfg(target_arch = "x86_64")]
pub mod shadow_ssdt;
pub mod memdiag;
pub mod safe_mode_shell;

/// Initialize the kernel executive.
///
/// Each sub-module prints a status line; the total time is bounded
/// because every step is O(1) (no real thread is created; the
/// scheduler is a single static state).
pub fn init() {
    pre_ke();
    scheduler::init();
    interrupt::init();
    irql::init();
    time::init();
    timer::init();
    apc::init();
    dpc::init();
    sync::init();
    dispatch::init();
    #[cfg(target_arch = "x86_64")]
    {
        ssdt::init();
        shadow_ssdt::init();
    }
    psss::init();
    bugcheck::init();
    exception::init();
    post_ke();
}

/// Sentinel printed *before* `ke::init()` runs. If `PRE_KE`
/// appears in the serial log but the kernel hangs, the failure
/// is inside one of the sub-module `init()` calls; if it doesn't
/// appear at all, the failure is upstream (memory manager, HAL
/// framebuffer handoff, ...). We intentionally use the COM1-only
/// `serial::write_string` here because `kprintln` uses the
/// LFB+memcpy path that can itself #GP during early init.
fn pre_ke() {
    crate::hal::serial::write_string("[KE] PRE_KE\r\n");
}

/// Sentinel printed *after* `ke::init()` completes. Together
/// with `PRE_KE` this brackets the entire executive bring-up.
fn post_ke() {
    crate::hal::serial::write_string("[KE] POST_KE\r\n");
}

/// Re-export of the kernel-executive smoke test aggregator. The
/// full implementation lives in the `smoke` submodule; this
/// re-export keeps the call site readable as `ke::smoke_test()`
/// (matching the `mm::smoke_test()` / `ob::smoke_test()` /
/// `io::smoke_test()` convention used by `kernel_main`).
#[cfg(target_arch = "x86_64")]
pub fn smoke_test() -> bool { smoke::smoke_test() }
#[cfg(not(target_arch = "x86_64"))]
pub fn smoke_test() -> bool { true }
