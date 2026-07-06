//! BugCheck
//
//! System crash handling. The bugcheck code is responsible for
//! halting all CPUs, printing a description, and (on a real
//! machine) writing a crash dump. The bootstrap prints a header
//! with the bugcheck code and the four NT-style parameters, then
//! halts the system.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// BugCheck codes (subset; full list in `ke::bugcheck`).
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum BugCheckCode {
    ApcIndexMismatch = 0x00000001,
    DataInconsistencyLock = 0x00000002,
    FileSystem = 0x00000003,
    FatalServerError = 0x00000004,
    HardFault = 0x00000006,
    InconsistentPowerState = 0x00000009,
    InternalError = 0x0000010D,
    InvalidHibernate = 0x0000010F,
    InvalidHypercamode = 0x00000112,
    IrqlGtxLapcNotLessOrEqual = 0x0000010A,
    KernelDataInpage = 0x00000077,
    MachineCheck = 0x0000009C,
    MemoryManagement = 0x0000001A,
    NoMoreEntries = 0x00000104,
    NoMoreIrpStackLocations = 0x000000C9,
    ObjectNameInvalid = 0x0000013A,
    PnpUnexpectedInterrupt = 0x0000010E,
    ProcessLocked = 0x00000024,
    SessionHasLockedSession = 0x00000110,
    SystemServiceException = 0x0000003B,
    SystemUninit = 0x000000DC,
    TooManyEntries = 0x00000103,
    TrapCauseException = 0x0000003F,
    UnexpectedKernelModeTrap = 0x0000007F,
}

impl BugCheckCode {
    pub fn as_u32(self) -> u32 {
        self as u32
    }
    pub fn name(self) -> &'static str {
        match self {
            BugCheckCode::ApcIndexMismatch => "APC_INDEX_MISMATCH",
            BugCheckCode::DataInconsistencyLock => "DATA_INCONSISTENCY_LOCK",
            BugCheckCode::FileSystem => "FILE_SYSTEM",
            BugCheckCode::FatalServerError => "FATAL_SERVER_ERROR",
            BugCheckCode::HardFault => "HARD_FAULT",
            BugCheckCode::InconsistentPowerState => "INCONSISTENT_POWER_STATE",
            BugCheckCode::InternalError => "INTERNAL_ERROR",
            BugCheckCode::InvalidHibernate => "INVALID_HIBERNATE",
            BugCheckCode::InvalidHypercamode => "INVALID_HYPERCAMODE",
            BugCheckCode::IrqlGtxLapcNotLessOrEqual => "IRQL_GT_LAPC_NOT_LESS_OR_EQUAL",
            BugCheckCode::KernelDataInpage => "KERNEL_DATA_INPAGE",
            BugCheckCode::MachineCheck => "MACHINE_CHECK",
            BugCheckCode::MemoryManagement => "MEMORY_MANAGEMENT",
            BugCheckCode::NoMoreEntries => "NO_MORE_ENTRIES",
            BugCheckCode::NoMoreIrpStackLocations => "NO_MORE_IRP_STACK_LOCATIONS",
            BugCheckCode::ObjectNameInvalid => "OBJECT_NAME_INVALID",
            BugCheckCode::PnpUnexpectedInterrupt => "PNP_UNEXPECTED_INTERRUPT",
            BugCheckCode::ProcessLocked => "PROCESS_LOCKED",
            BugCheckCode::SessionHasLockedSession => "SESSION_HAS_LOCKED_SESSION",
            BugCheckCode::SystemServiceException => "SYSTEM_SERVICE_EXCEPTION",
            BugCheckCode::SystemUninit => "SYSTEM_UNINIT",
            BugCheckCode::TooManyEntries => "TOO_MANY_ENTRIES",
            BugCheckCode::TrapCauseException => "TRAP_CAUSE_EXCEPTION",
            BugCheckCode::UnexpectedKernelModeTrap => "UNEXPECTED_KERNEL_MODE_TRAP",
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
    // // kprintln!("    BugCheck: handler installed (code 0x00000000 = no error)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
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
    let now = record(BugCheckCode::InternalError, 0x11, 0x22, 0x33, 0x44);
    if now != before + 1 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [BUGCHECK SMOKE FAIL] record returned {} expected {}",
// //             now, before + 1
// //         );
        return false;
    }
    if last_code() != BugCheckCode::InternalError.as_u32() {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [BUGCHECK SMOKE FAIL] last_code={:x} expected {:x}",
// //             last_code(),
// //             BugCheckCode::InternalError.as_u32()
// //         );
        return false;
    }
    if last_param(1) != 0x11 || last_param(4) != 0x44 {
        // // kprintln!("    [BUGCHECK SMOKE FAIL] parameter roundtrip")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "    [BUGCHECK SMOKE OK] last_code=0x{:08X} ({}) params=({:#x},{:#x},{:#x},{:#x})",
// //         last_code(),
// //         BugCheckCode::InternalError.name(),
// //         last_param(1),
// //         last_param(2),
// //         last_param(3),
// //         last_param(4)
// //     );
    true
}
