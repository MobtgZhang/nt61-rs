//! User-mode native system-call trampoline.

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::user_syscall::*;

#[cfg(not(target_arch = "x86_64"))]
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub unsafe fn syscall_varargs(num: u32, args: &[u64]) -> i64 {
    let result: i64;
    core::arch::asm!(
        "ecall",
        in("a7") num as u64,
        in("a0") args.get(0).copied().unwrap_or(0),
        in("a1") args.get(1).copied().unwrap_or(0),
        in("a2") args.get(2).copied().unwrap_or(0),
        in("a3") args.get(3).copied().unwrap_or(0),
        in("a4") args.get(4).copied().unwrap_or(0),
        in("a5") args.get(5).copied().unwrap_or(0),
        lateout("a0") result,
        options(nostack),
    );
    result
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub unsafe fn syscall_varargs(num: u32, args: &[u64]) -> i64 {
    let result: i64;
    core::arch::asm!(
        "mov x16, x8",
        "svc #0",
        in("x8") num as u64,
        in("x0") args.get(0).copied().unwrap_or(0),
        in("x1") args.get(1).copied().unwrap_or(0),
        in("x2") args.get(2).copied().unwrap_or(0),
        in("x3") args.get(3).copied().unwrap_or(0),
        in("x4") args.get(4).copied().unwrap_or(0),
        in("x5") args.get(5).copied().unwrap_or(0),
        lateout("x0") result,
        options(nostack),
    );
    result
}

#[cfg(target_arch = "loongarch64")]
#[inline(always)]
pub unsafe fn syscall_varargs(num: u32, args: &[u64]) -> i64 {
    let result: i64;
    core::arch::asm!(
        "syscall 0",
        in("$r11") num as u64,
        in("$r4") args.get(0).copied().unwrap_or(0),
        in("$r5") args.get(1).copied().unwrap_or(0),
        in("$r6") args.get(2).copied().unwrap_or(0),
        in("$r7") args.get(3).copied().unwrap_or(0),
        lateout("$r4") result,
        options(nostack),
    );
    result
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64", target_arch = "aarch64", target_arch = "loongarch64")))]
#[inline(always)]
pub unsafe fn syscall_varargs(num: u32, args: &[u64]) -> i64 {
    let result: i64;
    core::arch::asm!(
        "syscall 0",
        in("a7") num as u64,
        in("a0") args.get(0).copied().unwrap_or(0),
        in("a1") args.get(1).copied().unwrap_or(0),
        in("a2") args.get(2).copied().unwrap_or(0),
        in("a3") args.get(3).copied().unwrap_or(0),
        in("a4") args.get(4).copied().unwrap_or(0),
        in("a5") args.get(5).copied().unwrap_or(0),
        lateout("a0") result,
        options(nostack),
    );
    result
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall0(num: u32) -> i64 {
    syscall_varargs(num, &[])
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall1(num: u32, arg0: u64) -> i64 {
    syscall_varargs(num, &[arg0])
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall2(num: u32, arg0: u64, arg1: u64) -> i64 {
    syscall_varargs(num, &[arg0, arg1])
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall3(num: u32, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    syscall_varargs(num, &[arg0, arg1, arg2])
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall4(num: u32, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    syscall_varargs(num, &[arg0, arg1, arg2, arg3])
}
