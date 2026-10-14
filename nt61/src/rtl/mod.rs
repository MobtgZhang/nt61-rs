//! RTL (Runtime Library)
//
//! Kernel runtime support functions

pub mod eventlog; // Windows Event Log (.evtx) system
pub mod klog;
pub mod logging; // Legacy logging
pub mod ntbtlog; // Windows Boot Log (ntbtlog.txt) system
pub mod panic;
pub mod sac; // EMS/SAC serial console
pub mod string;
pub mod testing;
pub mod unicode;
pub mod windows_log; // Windows 7 compatible logging // Unified testing framework for smoke tests

pub fn init() {
    string::init();
    unicode::init();
    klog::init();

    // Boot event — written to the System event log channel.
    eventlog::init();
    eventlog::kernel_events::log_boot_start();

    // Boot log entry: kernel started.
    ntbtlog::enable_boot_log();
    ntbtlog::begin_boot_sequence();
    ntbtlog::log_driver_load(b"\\SystemRoot\\System32\\ntoskrnl.exe");

    // SAC stays disabled unless EMS is enabled in BCD; report init status.
    sac::init();
}

pub mod safe_unwrap;
