//! User-mode native system-call trampoline.

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::user_syscall::*;

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall0(_num: u32) -> i64 {
    unimplemented!("user-mode syscall trampoline")
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall1(_num: u32, _arg0: u64) -> i64 {
    unimplemented!("user-mode syscall trampoline")
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall2(_num: u32, _arg0: u64, _arg1: u64) -> i64 {
    unimplemented!("user-mode syscall trampoline")
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall3(_num: u32, _arg0: u64, _arg1: u64, _arg2: u64) -> i64 {
    unimplemented!("user-mode syscall trampoline")
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall4(_num: u32, _arg0: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unimplemented!("user-mode syscall trampoline")
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn syscall_varargs(_num: u32, _args: &[u64]) -> i64 {
    unimplemented!("user-mode syscall trampoline")
}
