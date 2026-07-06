//! Platform Hardware Error Driver (pshed.dll)
//
//! Implements the platform-specific hardware error handling subsystem.
//! The PSHED intercepts and manages hardware errors (MCE, PCIe AER,
//! CMCI) and coordinates with the Windows Error Manager (WER).
//
//! Key responsibilities:
//!   * `PshedInitialize` — register the PSHED with the kernel
//!   * `PshedQuerySystemErrorMaskData` / `PshedSetSystemErrorMaskData` —
//!     manage MCE mask bits
//!   * `PshedAddErrorSource` / `PshedRemoveErrorSource` —
//!     register hardware error sources
//!   * `PshedEnableErrorSource` / `PshedDisableErrorSource` —
//!     enable/disable error reporting
//!   * `PshedAcquireBugCheckData` / `PshedReleaseBugCheckData` —
//!     claim bugcheck data during crash dump
//
//! On x86_64, the PSHED manages Machine Check Architecture (MCA) registers:
//!   IA32_MCi_CTL, IA32_MCi_STATUS, IA32_MCi_ADDR, IA32_MCi_MISC
//
//! Clean-room implementation. Spec source: Windows Internals 6th ed.,
//! ch.14 (Hardware Error Architecture), WDK pshed.h.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::kprintln;

// ---------------------------------------------------------------------------
// MCA MSR addresses
// ---------------------------------------------------------------------------

/// IA32_MCG_CAP (read-only) — global MCA capability.
const IA32_MCG_CAP: u32 = 0x0179;
/// IA32_MCG_STATUS — global MCA status.
const IA32_MCG_STATUS: u32 = 0x017A;
/// IA32_MCG_CTL — global MCA control (global enable/disable).
const IA32_MCG_CTL: u32 = 0x017B;
/// IA32_MCi_CTL — per-bank control (bank 0..N-1).
/// Addr = 0xC000_0100 + bank * 4 (where N <= 32).
const IA32_MC0_CTL: u32 = 0xC000_0100;
/// IA32_MCi_STATUS — per-bank error status.
const IA32_MC0_STATUS: u32 = 0xC000_0101;
/// IA32_MCi_ADDR — per-bank error address.
const IA32_MC0_ADDR: u32 = 0xC000_0102;
/// IA32_MCi_MISC — per-bank misc info.
const IA32_MC0_MISC: u32 = 0xC000_0103;



/// MCA error status values.
pub const MCG_STATUS_RIPV: u64 = 0x00000001; // restart IP valid
pub const MCG_STATUS_EIPV: u64 = 0x00000002; // error IP valid
pub const MCG_STATUS_MCIP: u64 = 0x00000004; // machine check in progress
pub const MCG_STATUS_EI: u64 = 0x00000080;   // error overflow

/// MCA error status — valid bit.
pub const MCi_STATUS_VAL: u64 = 0x80000000_00000000;

/// MCA error types.
pub const MC_ERROR_TYPE_UC: u64 = 0;  // Uncorrected
pub const MC_ERROR_TYPE_UE: u64 = 1;  // Uncorrected Error
pub const MC_ERROR_TYPE_PCC: u64 = 2;  // Processor Context Corrupt
pub const MC_ERROR_TYPE_S: u64 = 3;    // Semantically Uncorrected

/// Error source types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSource {
    MCE,     // Machine Check Exception
    CMC,     // Corrected Machine Check
    PCIeAER, // PCIe Advanced Error Reporting
    Other,
}

/// One registered hardware error source.
#[derive(Clone, Copy)]
pub struct ErrorSourceEntry {
    pub source_type: ErrorSource,
    pub enabled: bool,
    pub vector: u8,
    pub flags: u32,
}

impl Default for ErrorSourceEntry {
    fn default() -> Self {
        Self {
            source_type: ErrorSource::Other,
            enabled: false,
            vector: 0,
            flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MCA state
// ---------------------------------------------------------------------------

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static MCA_ENABLED: AtomicBool = AtomicBool::new(false);
static NUM_BANKS: AtomicU32 = AtomicU32::new(0);
static ERROR_SOURCES: AtomicU32 = AtomicU32::new(0);
static BUGCHECK_DATA_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Maximum error source entries.
const MAX_ERROR_SOURCES: usize = 8;

/// Get the number of MCA banks from IA32_MCG_CAP.
fn mca_num_banks() -> u32 {
    let mcg_cap = rdmsr(IA32_MCG_CAP);
    (mcg_cap & 0xFF) as u32
}

/// Read an MSR.
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack)); }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write an MSR.
fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    unsafe { core::arch::asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi, options(nostack)); }
}

/// Check if the MCA hardware is present.
fn mca_is_present() -> bool {
    let mcg_cap = rdmsr(IA32_MCG_CAP);
    (mcg_cap >> 8) & 0xFF > 0 // Has at least one bank
}

/// Initialise the MCA hardware.
fn mca_init() {
    if !mca_is_present() {
        // crate::kprintln!("    [PSHED] MCA hardware not present")  // kprintln disabled (memcpy crash workaround);
        return;
    }

    let num_banks = mca_num_banks();
    NUM_BANKS.store(num_banks, Ordering::Release);

    // Clear any pending errors from boot.
    for bank in 0..num_banks.min(32) {
        let status_msr = IA32_MC0_STATUS + bank * 4;
        let status = rdmsr(status_msr);
        if (status & MCi_STATUS_VAL) != 0 {
            // crate::kprintln!("    [PSHED] bank {}: clearing pending error 0x{:016x}", bank, status)  // kprintln disabled (memcpy crash workaround);
            // Write 0 to clear
            wrmsr(status_msr, 0);
        }
    }

    // Enable all MCA banks globally (set CTL to all 1s).
    for bank in 0..num_banks.min(32) {
        let ctl_msr = IA32_MC0_CTL + bank * 4;
        wrmsr(ctl_msr, 0xFFFFFFFFFFFFFFFF);
    }

    MCA_ENABLED.store(true, Ordering::Release);
    // crate::kprintln!("    [PSHED] MCA initialised, {} banks", num_banks)  // kprintln disabled (memcpy crash workaround);
}

/// Query one MCA bank and return the status as a formatted string.
pub fn query_mca_bank(bank: u32) -> (u64, u64, u64) {
    let status = rdmsr(IA32_MC0_STATUS + bank * 4);
    let addr = rdmsr(IA32_MC0_ADDR + bank * 4);
    let misc = rdmsr(IA32_MC0_MISC + bank * 4);
    (status, addr, misc)
}

/// Initialise the PSHED.
pub fn init() {
    if INITIALIZED.load(Ordering::Acquire) { return; }
    INITIALIZED.store(true, Ordering::Release);
    MCA_ENABLED.store(false, Ordering::Release);

    mca_init();
    // crate::kprintln!("    PSHED: initialized")  // kprintln disabled (memcpy crash workaround);
}

/// `PshedAcquireBugCheckData` — claim the bugcheck data structure
/// so the PSHED can fill in hardware error information during crash.
pub fn pshed_acquire_bugcheck_data() -> bool {
    BUGCHECK_DATA_CLAIMED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok()
}

/// `PshedReleaseBugCheckData` — release the bugcheck data back to the system.
pub fn pshed_release_bugcheck_data() {
    BUGCHECK_DATA_CLAIMED.store(false, Ordering::SeqCst);
}

/// `PshedQuerySystemErrorMaskData` — read the system error mask (MCE mask).
pub fn pshed_query_error_mask() -> u64 {
    let mcg_cap = rdmsr(IA32_MCG_CAP);
    mcg_cap // Return the raw MCA capability register as status
}

/// `PshedSetSystemErrorMaskData` — set the system error mask.
/// On x86_64, this enables/disables MCA banks.
pub fn pshed_set_error_mask(mask: u64) {
    let num_banks = NUM_BANKS.load(Ordering::Acquire);
    for bank in 0..num_banks.min(32) {
        let ctl_msr = IA32_MC0_CTL + bank * 4;
        if (mask & (1 << bank)) != 0 {
            wrmsr(ctl_msr, 0xFFFFFFFFFFFFFFFF); // Enable bank
        } else {
            wrmsr(ctl_msr, 0); // Disable bank
        }
    }
}

/// `PshedAddErrorSource` — register a hardware error source.
pub fn pshed_add_error_source(source_type: ErrorSource) -> bool {
    let old = ERROR_SOURCES.load(Ordering::Acquire);
    let new = old + 1;
    if new >= MAX_ERROR_SOURCES as u32 {
        return false;
    }
    ERROR_SOURCES.store(new, Ordering::Release);
    let vec = match source_type {
        ErrorSource::MCE => 18,  // #MC exception vector
        ErrorSource::CMC => 0,   // CMCI uses APIC
        _ => 0,
    };
    let _ = &vec;
    // crate::kprintln!("    [PSHED] registered {:?} (vector={})", source_type, vec)  // kprintln disabled (memcpy crash workaround);
    true
}

/// `PshedRemoveErrorSource` — unregister a hardware error source.
pub fn pshed_remove_error_source(source_type: ErrorSource) {
    let _ = source_type;
    let old = ERROR_SOURCES.load(Ordering::Acquire);
    if old > 0 {
        ERROR_SOURCES.store(old - 1, Ordering::Release);
    }
}

/// `PshedEnableErrorSource` — enable an error source.
pub fn pshed_enable_error_source(source_type: ErrorSource) {
    // crate::kprintln!("    [PSHED] enabling error source: {:?}", source_type)  // kprintln disabled (memcpy crash workaround);
    match source_type {
        ErrorSource::MCE => {
            // Set the MCG_CTL enable bit if present
            let mcg_cap = rdmsr(IA32_MCG_CAP);
            if (mcg_cap & 0x100) != 0 { // MCG_CTL present
                wrmsr(IA32_MCG_CTL, 0xFFFFFFFFFFFFFFFF);
            }
        }
        ErrorSource::CMC => {
            // CMCI enable is per-bank, set in MCi_CTL
            let num_banks = NUM_BANKS.load(Ordering::Acquire);
            for bank in 0..num_banks.min(32) {
                wrmsr(IA32_MC0_CTL + bank * 4, 0xFFFFFFFFFFFFFFFF);
            }
        }
        _ => {}
    }
}

/// `PshedDisableErrorSource` — disable an error source.
pub fn pshed_disable_error_source(source_type: ErrorSource) {
    // crate::kprintln!("    [PSHED] disabling error source: {:?}", source_type)  // kprintln disabled (memcpy crash workaround);
    match source_type {
        ErrorSource::MCE => {
            let mcg_cap = rdmsr(IA32_MCG_CAP);
            if (mcg_cap & 0x100) != 0 {
                wrmsr(IA32_MCG_CTL, 0);
            }
        }
        ErrorSource::CMC => {
            let num_banks = NUM_BANKS.load(Ordering::Acquire);
            for bank in 0..num_banks.min(32) {
                wrmsr(IA32_MC0_CTL + bank * 4, 0);
            }
        }
        _ => {}
    }
}

/// Decode an MCA error status register into a human-readable description.
/// Returns (error_type, valid, uncorrected).
fn decode_mci_status(status: u64) -> (u64, bool, bool) {
    let valid = (status & MCi_STATUS_VAL) != 0;
    let uncorrected = (status & 0x0000_0000_8000_0000_u64) != 0;
    let error_type = (status >> 56) & 0xF;
    (error_type, valid, uncorrected)
}

/// Smoke test for the PSHED.
pub fn smoke_test() -> bool {
    // crate::kprintln!("  [PSHED SMOKE] testing platform hardware error subsystem...")  // kprintln disabled (memcpy crash workaround);

    let mcg_cap = rdmsr(IA32_MCG_CAP);
    let mcg_status = rdmsr(IA32_MCG_STATUS);

    // crate::kprintln!("    [PSHED] IA32_MCG_CAP=0x{:016x}", mcg_cap)  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("    [PSHED] IA32_MCG_STATUS=0x{:016x}", mcg_status)  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("    [PSHED] num_mca_banks={}", mcg_cap & 0xFF)  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("    [PSHED] mcg_ctl_present={}", (mcg_cap >> 8) & 1)  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("    [PSHED] mcg_cmci_present={}", (mcg_cap >> 10) & 1)  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("    [PSHED] mcg_misc_prompt={}", (mcg_cap >> 11) & 1)  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("    [PSHED] mcg_tlb_errors={}", (mcg_cap >> 12) & 1)  // kprintln disabled (memcpy crash workaround);

    // Check MCG_STATUS flags
    if (mcg_status & MCG_STATUS_RIPV) != 0 {
        // crate::kprintln!("    [PSHED] MCG_STATUS: RIPV=1 (restart IP valid)")  // kprintln disabled (memcpy crash workaround);
    }
    if (mcg_status & MCG_STATUS_EIPV) != 0 {
        // crate::kprintln!("    [PSHED] MCG_STATUS: EIPV=1 (error IP valid)")  // kprintln disabled (memcpy crash workaround);
    }
    if (mcg_status & MCG_STATUS_MCIP) != 0 {
        // crate::kprintln!("    [PSHED] MCG_STATUS: MCIP=1 (machine check in progress)")  // kprintln disabled (memcpy crash workaround);
    }

    // Scan each bank
    let num_banks = (mcg_cap & 0xFF) as u32;
    for bank in 0..num_banks.min(8) {
        let status = rdmsr(IA32_MC0_STATUS + bank * 4);
        if (status & MCi_STATUS_VAL) != 0 {
            let (etype, _, uncor) = decode_mci_status(status);
            let _ = &etype;
            let _ = &uncor;
            // crate::kprintln!("    [PSHED] bank {}: status=0x{:016x} type={} uncorrected={}",  // kprintln disabled (memcpy crash workaround)
//                 bank, status, etype, uncor);
        }
    }

    // Test error source registration
    let added = pshed_add_error_source(ErrorSource::MCE);
    if !added {
        // crate::kprintln!("  [PSHED SMOKE FAIL] failed to add error source")  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Test bugcheck data claim
    let acquired = pshed_acquire_bugcheck_data();
    if !acquired {
        // crate::kprintln!("  [PSHED SMOKE FAIL] failed to acquire bugcheck data")  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    pshed_release_bugcheck_data();

    // crate::kprintln!("  [PSHED SMOKE OK] Platform Hardware Error subsystem healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
