//! 32-bit x86 guest register file.

#![cfg(target_arch = "loongarch64")]

#[derive(Default)]
#[repr(C)]
pub struct GuestRegs32 {
    pub eax: u32, pub ecx: u32, pub edx: u32, pub ebx: u32,
    pub esp: u32, pub ebp: u32, pub esi: u32, pub edi: u32,
    pub eip: u32,
    /// Segment selectors (CS/DS/ES/SS/FS/GS).
    pub cs: u16, pub ds: u16, pub es: u16, pub ss: u16, pub fs: u16, pub gs: u16,
}
