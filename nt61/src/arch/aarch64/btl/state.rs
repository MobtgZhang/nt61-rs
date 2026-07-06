//! BTL translated-state management.
//!
//! Currently a stub. Provides:
//!
//! * The translated register file (mapping x86_64/AArch32 registers
//!   to AArch64 host registers).
//! * A shadow memory view for guest-visible segment registers
//!   (FS/GS on x86_64).
//! * Saving/restoring the translated state on every host context
//!   switch.
//!
//! A real implementation will define a `TranslatedState` struct
//! stored in the per-thread `KTHREAD.btl_state` slot.

#[derive(Debug, Clone, Copy)]
pub struct TranslatedState {
    /// Mapped register file (x86_64 / AArch32 view).
    pub regs: [u64; 32],
    /// Saved rflags (x86 guest).
    pub rflags: u64,
    /// FS base (x86_64 guest).
    pub fs_base: u64,
    /// GS base (x86_64 guest).
    pub gs_base: u64,
}

impl TranslatedState {
    pub const fn empty() -> Self {
        Self {
            regs: [0; 32],
            rflags: 0,
            fs_base: 0,
            gs_base: 0,
        }
    }
}
