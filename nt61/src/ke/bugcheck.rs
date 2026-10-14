//! BugCheck
//
//! System crash handling. The bugcheck code is responsible for
//! halting all CPUs, printing a description, and (on a real
//! machine) writing a crash dump. The bootstrap prints a header
//! with the bugcheck code and the four NT-style parameters, then
//! halts the system.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// BugCheck codes (subset).
//
/// Every code and name below is taken from the Windows 7 / NT 6.1 bug
/// check code reference (Microsoft "Bug Check Code Reference", plus the
/// ReactOS `sdk/include/reactos/mc/bugcodes.mc` message table, which is
/// the same NT table). The numeric value is what a crash dump stores as
/// `BugCheckCode`, so it must match the documented table exactly.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum BugCheckCode {
    ApcIndexMismatch = 0x00000001,
    DeviceQueueNotBusy = 0x00000002,
    InvalidAffinitySet = 0x00000003,
    InvalidDataAccessTrap = 0x00000004,
    InvalidProcessAttachAttempt = 0x00000005,
    InvalidProcessDetachAttempt = 0x00000006,
    InvalidSoftwareInterrupt = 0x00000007,
    IrqlNotDispatchLevel = 0x00000008,
    IrqlNotGreaterOrEqual = 0x00000009,
    IrqlNotLessOrEqual = 0x0000000A,
    MemoryManagement = 0x0000001A,
    PfnListCorrupt = 0x0000004E,
    Filesystem = 0x00000022,
    FatFilesystem = 0x00000023,
    NtfsFilesystem = 0x00000024,
    InconsistentIrp = 0x0000002A,
    NoMoreIrpStackLocations = 0x00000035,
    NoMoreSystemPtes = 0x0000003F,
    SystemServiceException = 0x0000003B,
    ProcessInitializationFailed = 0x00000060,
    KernelStackInpageError = 0x00000077,
    KernelDataInpageError = 0x0000007A,
    UnexpectedKernelModeTrap = 0x0000007F,
    KernelModeExceptionNotHandled = 0x0000008E,
    MachineCheckException = 0x0000009C,
    DriverPowerStateFailure = 0x0000009F,
    BadPoolCaller = 0x000000C2,
    IrqlUnexpectedValue = 0x000000C8,
    DriverVerifierIoManagerViolation = 0x000000C9,
    DriverInvalidStackAccess = 0x000000DC,
    WorkerThreadReturnedAtBadIrql = 0x000000E1,
    ManuallyInitiatedCrash = 0x000000E2,
    CriticalProcessDied = 0x000000EF,
    MupFilesystem = 0x00000103,
    AgpInvalidAccess = 0x00000104,
    AppTaggingInitializationFailed = 0x0000010A,
    WdfViolation = 0x0000010D,
    VideoMemoryManagementInternal = 0x0000010E,
    ResourceManagerExceptionNotHandled = 0x0000010F,
    MsrpcStateViolation = 0x00000112,
    KernelSecurityCheckFailure = 0x00000139,
    KernelModeHeapCorruption = 0x0000013A,
}

impl BugCheckCode {
    pub fn as_u32(self) -> u32 {
        self as u32
    }
    pub fn name(self) -> &'static str {
        match self {
            BugCheckCode::ApcIndexMismatch => "APC_INDEX_MISMATCH",
            BugCheckCode::DeviceQueueNotBusy => "DEVICE_QUEUE_NOT_BUSY",
            BugCheckCode::InvalidAffinitySet => "INVALID_AFFINITY_SET",
            BugCheckCode::InvalidDataAccessTrap => "INVALID_DATA_ACCESS_TRAP",
            BugCheckCode::InvalidProcessAttachAttempt => "INVALID_PROCESS_ATTACH_ATTEMPT",
            BugCheckCode::InvalidProcessDetachAttempt => "INVALID_PROCESS_DETACH_ATTEMPT",
            BugCheckCode::InvalidSoftwareInterrupt => "INVALID_SOFTWARE_INTERRUPT",
            BugCheckCode::IrqlNotDispatchLevel => "IRQL_NOT_DISPATCH_LEVEL",
            BugCheckCode::IrqlNotGreaterOrEqual => "IRQL_NOT_GREATER_OR_EQUAL",
            BugCheckCode::IrqlNotLessOrEqual => "IRQL_NOT_LESS_OR_EQUAL",
            BugCheckCode::MemoryManagement => "MEMORY_MANAGEMENT",
            BugCheckCode::PfnListCorrupt => "PFN_LIST_CORRUPT",
            BugCheckCode::Filesystem => "FILE_SYSTEM",
            BugCheckCode::FatFilesystem => "FAT_FILE_SYSTEM",
            BugCheckCode::NtfsFilesystem => "NTFS_FILE_SYSTEM",
            BugCheckCode::InconsistentIrp => "INCONSISTENT_IRP",
            BugCheckCode::NoMoreIrpStackLocations => "NO_MORE_IRP_STACK_LOCATIONS",
            BugCheckCode::NoMoreSystemPtes => "NO_MORE_SYSTEM_PTES",
            BugCheckCode::SystemServiceException => "SYSTEM_SERVICE_EXCEPTION",
            BugCheckCode::ProcessInitializationFailed => "PROCESS_INITIALIZATION_FAILED",
            BugCheckCode::KernelStackInpageError => "KERNEL_STACK_INPAGE_ERROR",
            BugCheckCode::KernelDataInpageError => "KERNEL_DATA_INPAGE_ERROR",
            BugCheckCode::UnexpectedKernelModeTrap => "UNEXPECTED_KERNEL_MODE_TRAP",
            BugCheckCode::KernelModeExceptionNotHandled => "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
            BugCheckCode::MachineCheckException => "MACHINE_CHECK_EXCEPTION",
            BugCheckCode::DriverPowerStateFailure => "DRIVER_POWER_STATE_FAILURE",
            BugCheckCode::BadPoolCaller => "BAD_POOL_CALLER",
            BugCheckCode::IrqlUnexpectedValue => "IRQL_UNEXPECTED_VALUE",
            BugCheckCode::DriverVerifierIoManagerViolation => "DRIVER_VERIFIER_IOMANAGER_VIOLATION",
            BugCheckCode::DriverInvalidStackAccess => "DRIVER_INVALID_STACK_ACCESS",
            BugCheckCode::WorkerThreadReturnedAtBadIrql => "WORKER_THREAD_RETURNED_AT_BAD_IRQL",
            BugCheckCode::ManuallyInitiatedCrash => "MANUALLY_INITIATED_CRASH",
            BugCheckCode::CriticalProcessDied => "CRITICAL_PROCESS_DIED",
            BugCheckCode::MupFilesystem => "MUP_FILE_SYSTEM",
            BugCheckCode::AgpInvalidAccess => "AGP_INVALID_ACCESS",
            BugCheckCode::AppTaggingInitializationFailed => "APP_TAGGING_INITIALIZATION_FAILED",
            BugCheckCode::WdfViolation => "WDF_VIOLATION",
            BugCheckCode::VideoMemoryManagementInternal => "VIDEO_MEMORY_MANAGEMENT_INTERNAL",
            BugCheckCode::ResourceManagerExceptionNotHandled => {
                "RESOURCE_MANAGER_EXCEPTION_NOT_HANDLED"
            }
            BugCheckCode::MsrpcStateViolation => "MSRPC_STATE_VIOLATION",
            BugCheckCode::KernelSecurityCheckFailure => "KERNEL_SECURITY_CHECK_FAILURE",
            BugCheckCode::KernelModeHeapCorruption => "KERNEL_MODE_HEAP_CORRUPTION",
        }
    }
}

static LAST_CODE: AtomicU32 = AtomicU32::new(0);
static LAST_P1: AtomicU64 = AtomicU64::new(0);
static LAST_P2: AtomicU64 = AtomicU64::new(0);
static LAST_P3: AtomicU64 = AtomicU64::new(0);
static LAST_P4: AtomicU64 = AtomicU64::new(0);
static BUGCHECK_COUNT: AtomicU32 = AtomicU32::new(0);

/// Initialize bugcheck subsystem. Resets the counters; the
/// default is to do nothing on boot.
pub fn init() {
    crate::hal::serial::write_string("[ke.bugcheck] enter\r\n");
    LAST_CODE.store(0, Ordering::SeqCst);
    BUGCHECK_COUNT.store(0, Ordering::SeqCst);
    // // kprintln!("    BugCheck: handler installed (code 0x00000000 = no error)");
}

/// Record the last bugcheck that fired. The crash path calls
/// this just before halting. Returns the count after the call.
pub fn record(code: BugCheckCode, p1: u64, p2: u64, p3: u64, p4: u64) -> u32 {
    LAST_CODE.store(code.as_u32(), Ordering::SeqCst);
    LAST_P1.store(p1, Ordering::SeqCst);
    LAST_P2.store(p2, Ordering::SeqCst);
    LAST_P3.store(p3, Ordering::SeqCst);
    LAST_P4.store(p4, Ordering::SeqCst);
    BUGCHECK_COUNT.fetch_add(1, Ordering::SeqCst) + 1
}

/// Read the last recorded bugcheck code (0 if none).
pub fn last_code() -> u32 {
    LAST_CODE.load(Ordering::SeqCst)
}
/// Read the last recorded bugcheck parameter.
pub fn last_param(n: usize) -> u64 {
    match n {
        1 => LAST_P1.load(Ordering::SeqCst),
        2 => LAST_P2.load(Ordering::SeqCst),
        3 => LAST_P3.load(Ordering::SeqCst),
        4 => LAST_P4.load(Ordering::SeqCst),
        _ => 0,
    }
}
/// Number of bugchecks recorded so far.
pub fn bugcheck_count() -> u32 {
    BUGCHECK_COUNT.load(Ordering::SeqCst)
}

/// Trigger bugcheck
#[allow(dead_code)]
pub fn bugcheck(code: BugCheckCode) -> ! {
    bugcheck_with(code, 0, 0, 0, 0)
}

/// Trigger a real bugcheck with parameters. This is the full
/// surface that the kernel uses for fatal errors.
pub fn bugcheck_with(code: BugCheckCode, p1: u64, p2: u64, p3: u64, p4: u64) -> ! {
    record(code, p1, p2, p3, p4);

    // Host unit tests cannot reach the display (the VGA text buffer at
    // 0xB8000 is not mapped in user space) and cannot execute `hlt`, so a
    // bugcheck would fault the libtest binary. Surface it as a panic under
    // `cfg(test)` so the failure path stays observable; the kernel build is
    // unchanged.
    #[cfg(test)]
    panic!(
        "bugcheck 0x{:08X} p1=0x{:x} p2=0x{:x} p3=0x{:x} p4=0x{:x}",
        code.as_u32(),
        p1,
        p2,
        p3,
        p4
    );

    // Paint the Win7-style BSOD via BOOTVID before we halt.
    // The hex representation of the bugcheck code is also the
    // top-line message; parameters are folded into the secondary
    // status line.
    let code_u32 = code.as_u32();
    let mut secondary = [0u8; 64];
    let label = b"KERNEL BUGCHECK";
    let mut i = 0;
    while i < label.len() && i < secondary.len() {
        secondary[i] = label[i];
        i += 1;
    }
    let _ = (p1, p2, p3, p4); // fold into secondary if needed
    let secondary_str = core::str::from_utf8(&secondary[..i]).unwrap_or("KERNEL BUGCHECK");
    crate::drivers::bootvid::bugcheck_screen(code_u32, secondary_str);
    // Stop other CPUs.
    crate::ke::dispatch::set_panic_stop();
    loop {
        crate::arch::halt();
    }
}

/// Smoke test for the bugcheck subsystem. Records a fake
/// bugcheck (counts only — we don't actually halt) and verifies
/// the counters.
pub fn smoke_test() -> bool {
    let before = bugcheck_count();
    let now = record(BugCheckCode::IrqlNotLessOrEqual, 0x11, 0x22, 0x33, 0x44);
    if now != before + 1 {
        // // kprintln!(
        // //             "    [BUGCHECK SMOKE FAIL] record returned {} expected {}",
        // //             now, before + 1
        // //         );
        return false;
    }
    if last_code() != BugCheckCode::IrqlNotLessOrEqual.as_u32() {
        // // kprintln!(
        // //             "    [BUGCHECK SMOKE FAIL] last_code={:x} expected {:x}",
        // //             last_code(),
        // //             BugCheckCode::IrqlNotLessOrEqual.as_u32()
        // //         );
        return false;
    }
    if last_param(1) != 0x11 || last_param(4) != 0x44 {
        // // kprintln!("    [BUGCHECK SMOKE FAIL] parameter roundtrip");
        return false;
    }
    // // kprintln!(
    // //         "    [BUGCHECK SMOKE OK] last_code=0x{:08X} ({}) params=({:#x},{:#x},{:#x},{:#x})",
    // //         last_code(),
    // //         BugCheckCode::IrqlNotLessOrEqual.name(),
    // //         last_param(1),
    // //         last_param(2),
    // //         last_param(3),
    // //         last_param(4)
    // //     );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codes must match the NT 6.1 bug check code reference.
    #[test]
    fn bugcheck_codes_match_documentation() {
        let expected: &[(u32, &str)] = &[
            (0x00000001, "APC_INDEX_MISMATCH"),
            (0x00000002, "DEVICE_QUEUE_NOT_BUSY"),
            (0x00000003, "INVALID_AFFINITY_SET"),
            (0x00000004, "INVALID_DATA_ACCESS_TRAP"),
            (0x00000006, "INVALID_PROCESS_DETACH_ATTEMPT"),
            (0x00000009, "IRQL_NOT_GREATER_OR_EQUAL"),
            (0x0000000A, "IRQL_NOT_LESS_OR_EQUAL"),
            (0x0000001A, "MEMORY_MANAGEMENT"),
            (0x00000022, "FILE_SYSTEM"),
            (0x00000024, "NTFS_FILE_SYSTEM"),
            (0x00000035, "NO_MORE_IRP_STACK_LOCATIONS"),
            (0x0000003B, "SYSTEM_SERVICE_EXCEPTION"),
            (0x0000003F, "NO_MORE_SYSTEM_PTES"),
            (0x0000004E, "PFN_LIST_CORRUPT"),
            (0x00000060, "PROCESS_INITIALIZATION_FAILED"),
            (0x00000077, "KERNEL_STACK_INPAGE_ERROR"),
            (0x0000007A, "KERNEL_DATA_INPAGE_ERROR"),
            (0x0000007F, "UNEXPECTED_KERNEL_MODE_TRAP"),
            (0x0000009C, "MACHINE_CHECK_EXCEPTION"),
            (0x000000C9, "DRIVER_VERIFIER_IOMANAGER_VIOLATION"),
            (0x000000DC, "DRIVER_INVALID_STACK_ACCESS"),
            (0x000000E1, "WORKER_THREAD_RETURNED_AT_BAD_IRQL"),
            (0x000000E2, "MANUALLY_INITIATED_CRASH"),
            (0x00000103, "MUP_FILE_SYSTEM"),
            (0x00000104, "AGP_INVALID_ACCESS"),
            (0x0000010A, "APP_TAGGING_INITIALIZATION_FAILED"),
            (0x0000010D, "WDF_VIOLATION"),
            (0x0000010E, "VIDEO_MEMORY_MANAGEMENT_INTERNAL"),
            (0x0000010F, "RESOURCE_MANAGER_EXCEPTION_NOT_HANDLED"),
            (0x00000112, "MSRPC_STATE_VIOLATION"),
            (0x00000139, "KERNEL_SECURITY_CHECK_FAILURE"),
            (0x0000013A, "KERNEL_MODE_HEAP_CORRUPTION"),
        ];
        for (code, name) in expected {
            let found = match *code {
                0x00000001 => BugCheckCode::ApcIndexMismatch,
                0x00000002 => BugCheckCode::DeviceQueueNotBusy,
                0x00000003 => BugCheckCode::InvalidAffinitySet,
                0x00000004 => BugCheckCode::InvalidDataAccessTrap,
                0x00000006 => BugCheckCode::InvalidProcessDetachAttempt,
                0x00000009 => BugCheckCode::IrqlNotGreaterOrEqual,
                0x0000000A => BugCheckCode::IrqlNotLessOrEqual,
                0x0000001A => BugCheckCode::MemoryManagement,
                0x00000022 => BugCheckCode::Filesystem,
                0x00000024 => BugCheckCode::NtfsFilesystem,
                0x00000035 => BugCheckCode::NoMoreIrpStackLocations,
                0x0000003B => BugCheckCode::SystemServiceException,
                0x0000003F => BugCheckCode::NoMoreSystemPtes,
                0x0000004E => BugCheckCode::PfnListCorrupt,
                0x00000060 => BugCheckCode::ProcessInitializationFailed,
                0x00000077 => BugCheckCode::KernelStackInpageError,
                0x0000007A => BugCheckCode::KernelDataInpageError,
                0x0000007F => BugCheckCode::UnexpectedKernelModeTrap,
                0x0000009C => BugCheckCode::MachineCheckException,
                0x000000C9 => BugCheckCode::DriverVerifierIoManagerViolation,
                0x000000DC => BugCheckCode::DriverInvalidStackAccess,
                0x000000E1 => BugCheckCode::WorkerThreadReturnedAtBadIrql,
                0x000000E2 => BugCheckCode::ManuallyInitiatedCrash,
                0x00000103 => BugCheckCode::MupFilesystem,
                0x00000104 => BugCheckCode::AgpInvalidAccess,
                0x0000010A => BugCheckCode::AppTaggingInitializationFailed,
                0x0000010D => BugCheckCode::WdfViolation,
                0x0000010E => BugCheckCode::VideoMemoryManagementInternal,
                0x0000010F => BugCheckCode::ResourceManagerExceptionNotHandled,
                0x00000112 => BugCheckCode::MsrpcStateViolation,
                0x00000139 => BugCheckCode::KernelSecurityCheckFailure,
                0x0000013A => BugCheckCode::KernelModeHeapCorruption,
                _ => panic!("code {code:#x} is not represented in BugCheckCode"),
            };
            assert_eq!(found.as_u32(), *code, "code value mismatch for {name}");
            assert_eq!(found.name(), *name, "name mismatch for code {code:#x}");
        }
    }

    #[test]
    fn record_roundtrip() {
        let before = bugcheck_count();
        let after = record(BugCheckCode::IrqlNotLessOrEqual, 0x1, 0x2, 0x3, 0x4);
        assert_eq!(after, before + 1);
        assert_eq!(last_code(), BugCheckCode::IrqlNotLessOrEqual.as_u32());
        assert_eq!(last_param(1), 0x1);
        assert_eq!(last_param(4), 0x4);
    }
}
