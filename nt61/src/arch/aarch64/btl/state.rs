//! BTL translated-state management.
//!
//! Provides:
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

use crate::arch::common::btl::ir::X86Reg;

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

    /// Read one x86_64 general-purpose register from the translated
    /// register file. Guest RIP is kept in slot 16.
    pub fn reg(&self, reg: X86Reg) -> u64 {
        self.regs[reg as usize]
    }

    /// Write one x86_64 general-purpose register to the translated
    /// register file.
    pub fn set_reg(&mut self, reg: X86Reg, value: u64) {
        self.regs[reg as usize] = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_accessors_use_x86_slot_mapping() {
        let mut state = TranslatedState::empty();
        state.set_reg(X86Reg::R10, 0x1234);
        state.set_reg(X86Reg::Rip, 0x1000);
        assert_eq!(state.reg(X86Reg::R10), 0x1234);
        assert_eq!(state.regs[X86Reg::R10 as usize], 0x1234);
        assert_eq!(state.reg(X86Reg::Rip), 0x1000);
    }
}
