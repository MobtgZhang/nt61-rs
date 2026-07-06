//! RISC-V 64 SBI (Supervisor Binary Interface) wrappers.
//!
//! SBI is the firmware-provided interface that S-mode (the kernel)
//! uses to talk to M-mode (the firmware / hypervisor). Phase 1
//! covers:
//!
//! * `BASE`        — extension probing (EID 0x10).
//! * `TIME`        — `SET_TIMER` (FID 0).
//! * `HSM`         — `HART_START` (FID 0).
//! * `IPI`         — `SEND_IPI` (FID 0).
//! * `SRST`        — `SYSTEM_RESET` (FID 0).
//! * `LEGACY_SET_TIMER` — legacy EID 0x00 (used by OpenSBI legacy).
//!
//! References:
//! * RISC-V SBI Specification v2.0 — §5 (Base), §6 (Time),
//!   §7 (HSM), §8 (IPI), §9 (SRST).
//! * RISC-V SBI Specification v0.2 (legacy 0x00).

use core::arch::asm;

// =====================================================================
// SBI return value (a0 / a1).
// =====================================================================

/// SBI call result. `error` is 0 on success and non-zero on
/// failure (SBI error code).
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct SbiRet {
    pub error: i64,
    pub value: i64,
}

impl SbiRet {
    pub const SUCCESS: SbiRet = SbiRet { error: 0, value: 0 };
    pub fn is_ok(&self) -> bool { self.error == 0 }
}

/// Make an SBI call (EID in a7, FID in a6, args in a0..a5).
///
/// # Safety
///
/// Caller is responsible for ensuring the SBI EID is supported by
/// the running firmware; an unsupported EID may produce arbitrary
/// behaviour on legacy firmwares.
#[inline(always)]
pub unsafe fn sbi_call(eid: u64, fid: u64, arg0: u64, arg1: u64, arg2: u64,
                        arg3: u64, arg4: u64, arg5: u64) -> SbiRet {
    let (err, val): (i64, i64);
    asm!(
        "mv    a0, {a0}",
        "mv    a1, {a1}",
        "mv    a2, {a2}",
        "mv    a3, {a3}",
        "mv    a4, {a4}",
        "mv    a5, {a5}",
        "mv    a6, {fid}",
        "mv    a7, {eid}",
        "ecall",
        "mv    {err}, a0",
        "mv    {val}, a1",
        a0 = in(reg) arg0,
        a1 = in(reg) arg1,
        a2 = in(reg) arg2,
        a3 = in(reg) arg3,
        a4 = in(reg) arg4,
        a5 = in(reg) arg5,
        fid = in(reg) fid,
        eid = in(reg) eid,
        err = out(reg) err,
        val = out(reg) val,
        options(nostack),
    );
    SbiRet { error: err, value: val }
}

// =====================================================================
// Extension IDs
// =====================================================================

pub mod eid {
    /// Legacy `set_timer` (OpenSBI v0.2). Deprecated but universally
    /// available on real hardware.
    pub const LEGACY_SET_TIMER: u64 = 0x00;
    /// Base extension probe.
    pub const BASE: u64 = 0x10;
    /// Timer extension (v0.2+).
    pub const TIME: u64 = 0x54494D45; // "TIME"
    /// Hart State Management extension.
    pub const HSM: u64 = 0x48534D; // "HSM"
    /// Inter-Processor Interrupt extension.
    pub const IPI: u64 = 0x735049; // "sPI"
    /// System Reset extension.
    pub const SRST: u64 = 0x53525354; // "SRST"
}

// =====================================================================
// Base extension (0x10)
// =====================================================================

/// SBI specification version returned by `BASE::GET_SPEC_VERSION`.
pub struct SpecVersion {
    pub major: u32,
    pub minor: u32,
}

/// Probe whether the given EID is implemented.
///
/// Returns `true` if the firmware returns SBI_SUCCESS for `BASE::PROBE`.
pub unsafe fn probe(eid: u64) -> bool {
    let r = sbi_call(eid::BASE, 3 /* PROBE */, 0, 0, 0, 0, 0, 0);
    r.error == 0
}

/// Get the SBI specification version.
pub unsafe fn spec_version() -> SpecVersion {
    let r = sbi_call(eid::BASE, 0 /* GET_SPEC_VERSION */, 0, 0, 0, 0, 0, 0);
    let major = ((r.value >> 24) & 0x7F) as u32;
    let minor = (r.value & 0xFF_FFFF) as u32;
    SpecVersion { major, minor }
}

/// Return the firmware's vendor ID string encoded as a u64.
pub unsafe fn impl_id() -> u64 {
    sbi_call(eid::BASE, 1 /* GET_IMP_ID */, 0, 0, 0, 0, 0, 0).value as u64
}

// =====================================================================
// Time extension (TIME)
// =====================================================================

/// Program the next timer interrupt (stime_value).
///
/// Uses the legacy EID 0x00 by default because it is universally
/// available; switch to the v0.2 TIME extension if the firmware
/// supports it.
pub unsafe fn set_timer(stime_value: u64) -> SbiRet {
    if probe(eid::TIME) {
        sbi_call(eid::TIME, 0 /* SET_TIMER */, stime_value, 0, 0, 0, 0, 0)
    } else {
        sbi_call(eid::LEGACY_SET_TIMER, 0, stime_value, 0, 0, 0, 0, 0)
    }
}

// =====================================================================
// HSM extension — HART_START
// =====================================================================

/// Start the secondary hart identified by `hartid` at the physical
/// address `start_addr`, passing `opaque` in `a1` to the entry
/// function.
///
/// # Safety
///
/// `start_addr` must point at a valid, executable physical address
/// of a trampoline that knows how to bootstrap the hart (the SBI
/// spec defines a custom calling convention — the entry must
/// immediately switch to the kernel's per-CPU trampoline).
pub unsafe fn hsm_hart_start(hartid: u64, start_addr: u64, opaque: u64) -> SbiRet {
    sbi_call(eid::HSM, 0 /* HART_START */, hartid, start_addr, opaque, 0, 0, 0)
}

/// Stop the calling hart. Used for shutdown sequences where the
/// firmware will power off the hart.
pub unsafe fn hsm_hart_stop() -> SbiRet {
    sbi_call(eid::HSM, 1 /* HART_STOP */, 0, 0, 0, 0, 0, 0)
}

/// Get the hart's status (started / stopped).
pub unsafe fn hsm_hart_status(hartid: u64) -> SbiRet {
    sbi_call(eid::HSM, 2 /* HART_GET_STATUS */, hartid, 0, 0, 0, 0, 0)
}

// =====================================================================
// IPI extension
// =====================================================================

/// Send a software IPI to the harts listed in `hart_mask` (one bit
/// per hart, hart 0 = bit 0).
pub unsafe fn ipi_send(hart_mask: u64) -> SbiRet {
    sbi_call(eid::IPI, 0 /* SEND_IPI */, hart_mask, 0, 0, 0, 0, 0)
}

// =====================================================================
// SRST extension
// =====================================================================

/// Reset the system.
pub enum ResetType {
    Shutdown = 0,
    ColdReboot = 1,
    WarmReboot = 2,
}

pub unsafe fn system_reset(ty: ResetType) -> SbiRet {
    sbi_call(eid::SRST, 0 /* SYSTEM_RESET */, ty as u64, 0, 0, 0, 0, 0)
}

// =====================================================================
// Convenience: shutdown
// =====================================================================

/// Convenience wrapper — request a clean shutdown via SBI SRST.
pub unsafe fn shutdown() -> ! {
    let _ = system_reset(ResetType::Shutdown);
    // If SRST is unimplemented we fall back to wfi / halt.
    loop {
        core::arch::asm!("wfi", options(nostack));
    }
}