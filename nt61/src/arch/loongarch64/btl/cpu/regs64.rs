//! 64-bit x86-64 guest register file.

#![cfg(target_arch = "loongarch64")]

#[derive(Default)]
#[repr(C)]
pub struct GuestRegs64 {
    pub rax: u64, pub rcx: u64, pub rdx: u64, pub rbx: u64,
    pub rsp: u64, pub rbp: u64, pub rsi: u64, pub rdi: u64,
    pub r8:  u64, pub r9:  u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64,
    pub cs: u16, pub ds: u16, pub es: u16, pub ss: u16, pub fs: u16, pub gs: u16,
}
