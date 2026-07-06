//! BTL — x86 CPU state (registers, flags, control registers).
//!
//! Mirrors what the host kernel sees when an x86 thread is being
//! emulated. The structs are pure data; access goes through safe
//! accessors in `regs32.rs` / `regs64.rs`.

#![cfg(target_arch = "loongarch64")]

pub mod regs32;
pub mod regs64;
pub mod flags;

pub use regs32::GuestRegs32;
pub use regs64::GuestRegs64;

/// EFLAGS / RFLAGS layout. The high 32 bits are reserved on x86
/// but kept here to make `pushf` / `popf` symmetric.
#[derive(Copy, Clone, Default)]
pub struct GuestFlags(pub u64);

impl GuestFlags {
    pub fn cf(self) -> bool { (self.0 & 0x0001) != 0 }
    pub fn pf(self) -> bool { (self.0 & 0x0004) != 0 }
    pub fn af(self) -> bool { (self.0 & 0x0010) != 0 }
    pub fn zf(self) -> bool { (self.0 & 0x0040) != 0 }
    pub fn sf(self) -> bool { (self.0 & 0x0080) != 0 }
    pub fn of(self) -> bool { (self.0 & 0x0800) != 0 }
    pub fn df(self) -> bool { (self.0 & 0x0400) != 0 }
    pub fn raw(self) -> u64 { self.0 }
    pub fn set_raw(&mut self, v: u64) { self.0 = v; }
    pub fn set_cf(&mut self, v: bool) { self.0 = (self.0 & !0x0001) | (v as u64); }
    pub fn set_zf(&mut self, v: bool) { self.0 = (self.0 & !0x0040) | ((v as u64) << 6); }
    pub fn set_sf(&mut self, v: bool) { self.0 = (self.0 & !0x0080) | ((v as u64) << 7); }
    pub fn set_of(&mut self, v: bool) { self.0 = (self.0 & !0x0800) | ((v as u64) << 11); }
    pub fn set_pf(&mut self, v: bool) { self.0 = (self.0 & !0x0004) | ((v as u64) << 2); }
    pub fn set_af(&mut self, v: bool) { self.0 = (self.0 & !0x0010) | ((v as u64) << 4); }
}

/// Discriminated view of a guest register file. The concrete layout
/// depends on the binary's bitness; this enum disambiguates the two
/// without paying for a generic parameter on the dispatch hot path.
pub enum GuestRegs<'a> {
    Mode32(&'a mut GuestRegs32),
    Mode64(&'a mut GuestRegs64),
}
