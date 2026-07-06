//! ntdll.dll — syscall macros.
//!
//! Provides the inline-asm `syscall` instruction following the
//! Microsoft x64 calling convention: arguments in RCX, RDX, R8, R9,
//! with stack arguments at RSP + 0x28 ...
//!
//! **This module is x86_64 only.** The actual `syscall` instruction
//! and Microsoft x64 ABI are architecture-specific; on LoongArch64 /
//! ARM64 / RISC-V64 the ntdll user-mode syscall stubs are provided by
//! per-architecture code under `userspace/<arch>/ntdll/`.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code, non_snake_case)]

use core::arch::asm;

/// Issue a syscall with one return value. The arguments follow the
/// Microsoft x64 ABI: r10, rdx, r8, r9 (then stack).
#[inline(always)]
pub unsafe fn syscall0(num: u32) -> i64 {
    let r: i64;
    asm!(
        "syscall",
        in("rax") num as u64,
        in("r10") 0u64,
        in("rdx") 0u64,
        in("r8")  0u64,
        in("r9")  0u64,
        out("rcx") _,
        out("r11") _,
        lateout("rax") r,
        options(nostack),
    );
    r
}

#[inline(always)]
pub unsafe fn syscall1(num: u32, a0: u64) -> i64 {
    let r: i64;
    asm!(
        "syscall",
        in("rax") num as u64,
        in("r10") a0,
        in("rdx") 0u64,
        in("r8")  0u64,
        in("r9")  0u64,
        out("rcx") _,
        out("r11") _,
        lateout("rax") r,
        options(nostack),
    );
    r
}

#[inline(always)]
pub unsafe fn syscall2(num: u32, a0: u64, a1: u64) -> i64 {
    let r: i64;
    asm!(
        "syscall",
        in("rax") num as u64,
        in("r10") a0,
        in("rdx") a1,
        in("r8")  0u64,
        in("r9")  0u64,
        out("rcx") _,
        out("r11") _,
        lateout("rax") r,
        options(nostack),
    );
    r
}

#[inline(always)]
pub unsafe fn syscall3(num: u32, a0: u64, a1: u64, a2: u64) -> i64 {
    let r: i64;
    asm!(
        "syscall",
        in("rax") num as u64,
        in("r10") a0,
        in("rdx") a1,
        in("r8")  a2,
        in("r9")  0u64,
        out("rcx") _,
        out("r11") _,
        lateout("rax") r,
        options(nostack),
    );
    r
}

#[inline(always)]
pub unsafe fn syscall4(num: u32, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let r: i64;
    asm!(
        "syscall",
        in("rax") num as u64,
        in("r10") a0,
        in("rdx") a1,
        in("r8")  a2,
        in("r9")  a3,
        out("rcx") _,
        out("r11") _,
        lateout("rax") r,
        options(nostack),
    );
    r
}

/// Variable-arg syscall used by APIs with five or more parameters.
#[inline(always)]
pub unsafe fn syscall_varargs(num: u32, args: &[u64]) -> i64 {
    // First 4 args go in r10, rdx, r8, r9 (per MS-x64 ABI).
    let a0 = *args.get(0).unwrap_or(&0);
    let a1 = *args.get(1).unwrap_or(&0);
    let a2 = *args.get(2).unwrap_or(&0);
    let a3 = *args.get(3).unwrap_or(&0);
    let r: i64;
    asm!(
        "syscall",
        in("rax") num as u64,
        in("r10") a0,
        in("rdx") a1,
        in("r8")  a2,
        in("r9")  a3,
        out("rcx") _,
        out("r11") _,
        lateout("rax") r,
        options(nostack),
    );
    r
}
