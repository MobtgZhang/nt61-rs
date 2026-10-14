//! Process Subsystem
//
//! Process and thread management

pub mod cmdline;
pub mod process;
pub mod smoke;
pub mod thread;
#[cfg(target_arch = "x86_64")]
pub mod wow64_process;
#[cfg(target_arch = "x86_64")]
pub mod wow64_thread;

pub use process::{
    Process, PID_CSRSS, PID_IDLE, PID_LSASS, PID_SERVICES, PID_SMSS, PID_SYSTEM, PID_WINLOGON,
};
pub use thread::{Ethread, KThreadState, Kthread, Thread};
#[cfg(target_arch = "x86_64")]
pub use wow64_process::{create_wow64_process, EprocessWow64Extension, Wow64VasState};
#[cfg(target_arch = "x86_64")]
pub use wow64_thread::{create_wow64_thread, EthreadWow64Extension};

/// Initialize process subsystem
pub fn init() {
    process::init();
    thread::init();
    #[cfg(target_arch = "x86_64")]
    {
        wow64_process::init();
        wow64_thread::init();
    }
}

/// Re-export of the process/thread smoke test. The full
/// implementation lives in the `smoke` submodule; this re-export
/// keeps the call site readable as `ps::smoke_test()`.
pub fn smoke_test() -> bool {
    smoke::smoke_test()
}

pub mod address_space;
pub mod create_process;
pub mod job;
pub mod job_extended;
pub mod process_mgmt;
pub mod tests;
