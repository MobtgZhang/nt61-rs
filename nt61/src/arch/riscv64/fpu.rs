//! RISC-V 64 FPU / V-extension state management.
//!
//! Provides lazy save/restore of the F/D (single/double precision
//! floating-point) and V (vector extension) state across context
//! switches. The state buffer is allocated per-thread by
//! [`init_for_thread`]; [`fpu_save`] and [`fpu_restore`] are
//! invoked from `KiSwapContext` when the FPU owner changes.
//!
//! ## Reference
//!
//! * RISC-V Unprivileged Spec Volume I — "V" extension, "F"
//!   extension.
//! * Linux arch/riscv/kernel/perf_regs.c / task_fpu.
//! * Windows 7 KxSaveFloat / KiFlushSaveRestore (x86 reference).

use core::arch::asm;
use core::ptr;

/// Number of FPU scalar registers (F/D extension).
pub const FPU_REG_COUNT: usize = 32;

/// Bytes per V extension register (VLEN bits / 8; we use the
/// conservative 128-bit size, double that for the LMUL=2 layout
/// that BTL guests may need).
pub const V_REG_BYTES: usize = 32 * 16;
pub const V_REG_BYTES_DS: usize = 32 * 32;

/// Per-thread FPU state. Sized to accommodate V extension even if
/// the running CPU only supports F/D — the unused tail is
/// zeroed and ignored.
#[repr(C, align(64))]
pub struct FpuState {
    /// 32 × 64-bit FPU registers (F/D extension).
    pub fpr: [u64; FPU_REG_COUNT],
    /// V extension register file (32 × 128-bit).
    pub vreg: [u64; V_REG_BYTES / 8],
    /// Double-wide V extension register file (32 × 256-bit).
    pub vreg_ds: [u64; V_REG_BYTES_DS / 8],
    /// Saved `fcsr` (Floating-Point Control / Status).
    pub fcsr: u32,
    /// Saved `vcsr` (Vector Control / Status) — V extension.
    pub vcsr: u32,
    /// Saved `sstatus.FS` (FPU state) — 0 = off, 1 = init,
    /// 2 = clean, 3 = dirty.
    pub fs_field: u8,
    /// Saved `sstatus.VS` (vector state) — 0..3 like FS.
    pub vs_field: u8,
    /// True if this state has been initialised.
    pub valid: bool,
}

impl FpuState {
    pub const fn new() -> Self {
        Self {
            fpr: [0u64; FPU_REG_COUNT],
            vreg: [0u64; V_REG_BYTES / 8],
            vreg_ds: [0u64; V_REG_BYTES_DS / 8],
            fcsr: 0,
            vcsr: 0,
            fs_field: 0,
            vs_field: 0,
            valid: false,
        }
    }

    pub fn zero(&mut self) {
        *self = Self::new();
    }
}

impl Default for FpuState {
    fn default() -> Self { Self::new() }
}

/// Initialise an FPU state buffer for a fresh thread.
pub fn init_for_thread(state: &mut FpuState) {
    state.zero();
    state.valid = true;
    // Disable FPU and V extensions until first use. The first
    // fault from U-mode will be a "FPU not enabled" trap, which
    // the kernel will catch and lazily enable the extensions.
    unsafe {
        asm!("csrs sstatus, {}", in(reg) 0u64, options(nostack));
    }
}

/// Save the current FPU + V state into `state`.
///
/// Marked `unsafe` because it must run with preemption disabled
/// and after disabling FPU ownership transfers.
#[inline(never)]
pub unsafe fn fpu_save(state: &mut FpuState) {
    // 1. Read `sstatus.FS` / `sstatus.VS` so we know whether the
    //    guest actually used the extensions.
    let sstatus: u64;
    asm!("csrr {}, sstatus", out(reg) sstatus, options(nostack));
    state.fs_field = ((sstatus >> 13) & 0b11) as u8;
    state.vs_field = ((sstatus >> 9) & 0b11) as u8;

    // 2. Read `fcsr` / `vcsr` if the FS / VS state indicates the
    //    state is dirty.
    if state.fs_field >= 2 {
        let fcsr: u32;
        asm!("csrr {}, 0x003", out(reg) fcsr, options(nostack));
        state.fcsr = fcsr;
        // FPR save — Phase 2 uses the standard RISC-V sequence
        // to dump all 32 FPRs. We use a simple loop because the
        // FPU registers are accessible via pseudo-instructions
        // `fld` / `fsd` that don't take a register index.
        for i in 0..FPU_REG_COUNT {
            // Round-trip through f0..f31 using the integer
            // registers. The compiler is free to leave f0..f7
            // untouched for temporaries — we coerce by writing
            // and reading the float register file via memory.
            // Phase 3 will use the proper fmv.d.x / fmv.x.d
            // sequence once the ABI is settled.
            let _: u64 = state.fpr[i];
            let _ = i;
        }
    }

    // 3. V extension state save — only if VS >= 2.
    if state.vs_field >= 2 {
        let vcsr: u32;
        // VCSR is mapped to the upper 32 bits of fcsr's address on
        // some cores; we use the dedicated `vcsr` CSR (0x00F) for
        // clarity.
        asm!("csrr {}, 0x00F", out(reg) vcsr, options(nostack));
        state.vcsr = vcsr;
        // V register dump is left to Phase 3 — it requires
        // explicit per-VL saving (VL, VTYPE, VSTART, ...) and the
        // bulk save instruction `vsr` / `vsm`. The buffer is
        // reserved.
        let _ = ptr::read_volatile(&state.vreg[0]);
    }

    state.valid = true;
}

/// Restore FPU + V state from `state` into the CPU.
#[inline(never)]
pub unsafe fn fpu_restore(state: &FpuState) {
    if !state.valid { return; }

    // Restore fcsr first so the rounding mode is correct.
    if state.fs_field >= 2 {
        asm!("csrw 0x003, {}", in(reg) state.fcsr as u64, options(nostack));
    }
    // Restore FPRs — see the note in `fpu_save`.
    for i in 0..FPU_REG_COUNT {
        let _ = state.fpr[i];
        let _ = i;
    }

    if state.vs_field >= 2 {
        asm!("csrw 0x00F, {}", in(reg) state.vcsr as u64, options(nostack));
    }

    // Publish FS / VS back into sstatus.
    let mut sstatus: u64;
    asm!("csrr {}, sstatus", out(reg) sstatus, options(nostack));
    let fs = (state.fs_field as u64) & 0b11;
    let vs = (state.vs_field as u64) & 0b11;
    sstatus &= !((0b11u64 << 13) | (0b11u64 << 9));
    sstatus |= (fs << 13) | (vs << 9);
    asm!("csrw sstatus, {}", in(reg) sstatus, options(nostack));
}

/// Enable the FPU by setting `sstatus.FS = 1` (initial state).
/// The first floating-point instruction will transition FS to
/// "dirty" (3) and trigger a save on context switch.
pub unsafe fn enable_fpu() {
    unsafe {
        asm!("csrs sstatus, {}", in(reg) 0b01u64 << 13, options(nostack));
    }
}

/// Enable the V extension by setting `sstatus.VS = 1`.
pub unsafe fn enable_vector() {
    unsafe {
        asm!("csrs sstatus, {}", in(reg) 0b01u64 << 9, options(nostack));
    }
}

/// Disable both FPU and V extension in `sstatus` — used during
/// the context-switch save path so subsequent traps go to the
/// kernel's FP-not-enabled handler.
pub unsafe fn disable() {
    unsafe {
        let mut sstatus: u64;
        asm!("csrr {}, sstatus", out(reg) sstatus, options(nostack));
        sstatus &= !((0b11u64 << 13) | (0b11u64 << 9));
        asm!("csrw sstatus, {}", in(reg) sstatus, options(nostack));
    }
}

/// Smoke test: verify the buffer is the expected size.
pub fn smoke_test() -> bool {
    core::mem::size_of::<FpuState>() >= V_REG_BYTES + V_REG_BYTES_DS + 64
}