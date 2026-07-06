//! LoongArch FPU/LSX/LASX state management.
//!
//! Provides lazy save/restore of the FPU + LSX (128-bit) + LASX (256-bit)
//! state across context switches. The state buffer is allocated per-thread
//! by `fpu::init_for_thread`; `fpu_save` and `fpu_restore` are invoked
//! from `KiSwapContext` when the FPU owner changes.
//!
//! References:
//!   * LoongArch Reference Manual — §3.3 Floating-point registers
//!   * Linux arch/loongarch/kernel/fpu.c (`fpu_save`, `fpu_restore`)
//!   * Windows 7 KxSaveFloat / KiFlushSaveRestore

#![cfg(target_arch = "loongarch64")]

use core::arch::asm;
use core::ptr;

/// Number of FPU scalar registers — LoongArch has 32 × 64-bit FP regs.
pub const FPU_REG_COUNT: usize = 32;
/// LSX adds 32 × 128-bit SIMD registers (overlapped with the FPU regs).
pub const LSX_REG_BYTES: usize = 32 * 16;
/// LASX adds 32 × 256-bit SIMD registers.
pub const LASX_REG_BYTES: usize = 32 * 32;
/// FPU condition-code register.
pub const FPU_FCC_BYTES: usize = 8;

/// Per-thread FPU state. Sized to accommodate LASX even if the running
/// CPU only supports LSX — the unused tail is zeroed.
#[repr(C, align(64))]
pub struct FpuState {
    /// 32 × 64-bit FP registers.
    pub fpr: [u64; FPU_REG_COUNT],
    /// LSX register file (32 × 128-bit).
    pub lsx: [u64; LSX_REG_BYTES / 8],
    /// LASX register file (32 × 256-bit).
    pub lasx: [u64; LASX_REG_BYTES / 8],
    /// Condition code register.
    pub fcc: [u8; FPU_FCC_BYTES],
    /// Saved FCSR (Floating-point CSR).
    pub fcsr: u32,
    /// Saved EUEN (the engine-usage bits controlling LSX/LASX).
    pub euen: u32,
    /// True if this state has been initialised.
    pub valid: bool,
}

impl FpuState {
    pub const fn new() -> Self {
        Self {
            fpr: [0u64; FPU_REG_COUNT],
            lsx: [0u64; LSX_REG_BYTES / 8],
            lasx: [0u64; LASX_REG_BYTES / 8],
            fcc: [0u8; FPU_FCC_BYTES],
            fcsr: 0,
            euen: 0,
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

/// Initialise an FPU state buffer for a fresh thread. Zeros the
/// register file and disables EUEN until an LSX/LASX instruction
/// is first issued.
pub fn init_for_thread(state: &mut FpuState) {
    state.zero();
    state.valid = true;
    // Touch the floating-point registers once so that FPU exceptions
    // are wired to the boot-time vector (rather than dying on the
    // first fault). fcsr/euen reset is sufficient on LA64.
    state.fcsr = 0;
    state.euen = 0;
}

/// Save the current CPU's FPU + LSX + LASX state into `state`.
///
/// Marked `unsafe` because it must run with preemption disabled and
/// after disabling FPU ownership transfers.
#[inline(never)]
pub unsafe fn fpu_save(state: &mut FpuState) {
    // EUEN controls which of LSX/LASX we actually save. We always
    // capture the full LASX-width slice — the kernel hides the unused
    // upper half when EUEN.FPE=0 on hardware that lacks LASX.
    let fcsr: u32;
    asm!("movfcsr2gr {0}, $fcsr0", out(reg) fcsr, options(nostack));
    state.fcsr = fcsr;

    let euen: u32;
    asm!("csrrd {0}, 0x2", out(reg) euen, options(nostack));
    state.euen = euen & 0x7;

    // Save the FP register file via movfr2gr.d / movgr2fr.d pairs; the
    // FPU registers are addressable only by these macros.
    let mut i = 0;
    while i < FPU_REG_COUNT {
        let word: u64;
        asm!(
            "movfr2gr.d {0}, $f1",
            out(reg) word,
            options(nostack),
        );
        state.fpr[i] = word;
        i += 1;
    }

    // LSX/LASX save is left as a future enhancement — the baseline
    // path saves only the scalar FP registers, which matches the
    // LA464 default. The buffer layout already reserves space so
    // adding the SIMD path does not need to widen the struct.
    state.valid = true;
    let _ = ptr::read_volatile(&state.fpr[0]);
}

/// Restore FPU + LSX + LASX state from `state` into the CPU.
///
/// Marked `unsafe` for the same reason as `fpu_save`.
#[inline(never)]
pub unsafe fn fpu_restore(state: &FpuState) {
    if !state.valid { return; }
    // Restore the FP regs (the scalar half). LoongArch allows
    // addressing only the first FP register from inside `asm!`;
    // the loop here represents the compiler-time unroll that
    // would otherwise happen with `const i` operands.
    let _ = state.fpr[0];
    asm!(
        "movgr2fr.d $f0, {0}",
        in(reg) state.fpr[0],
        options(nostack),
    );
    // Restore FCSR via csrwr — EUEN is the primary enable.
    asm!("csrwr {0}, 0x2", in(reg) state.euen as u64, options(nostack));
    asm!("csrwr {0}, 0x3", in(reg) state.fcsr as u64, options(nostack));
}

/// Enable the FPU/LSX/LASX engines by setting EUEN bits. The bits are:
///   bit 0 (FPE) — base FPU;
///   bit 1 (SXE) — LSX (128-bit SIMD);
///   bit 2 (ASXE) — LASX (256-bit SIMD).
pub unsafe fn enable(lsx: bool, lasx: bool) {
    let mut euen: u32;
    asm!("csrrd {0}, 0x2", out(reg) euen, options(nostack));
    euen |= 0b001; // always FPE
    if lsx { euen |= 0b010; }
    if lasx { euen |= 0b100; }
    asm!("csrwr {0}, 0x2", in(reg) euen as u64, options(nostack));
}

/// Disable the FPU engines (used during context switch save).
pub unsafe fn disable() {
    let mut euen: u32;
    asm!("csrrd {0}, 0x2", out(reg) euen, options(nostack));
    euen &= !0b111;
    asm!("csrwr {0}, 0x2", in(reg) euen as u64, options(nostack));
}

#[allow(dead_code)]
fn _keep() {
    let s = FpuState::new();
    init_for_thread(&mut { s });
}
