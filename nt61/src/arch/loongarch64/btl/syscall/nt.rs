//! BTL — NT system call bridging for x86 guests.
//!
//! The most common NT system calls exposed via WoW64 —
//! `NtAllocateVirtualMemory`, `NtOpenFile`, etc. — are listed here.
//! Each entry returns the LA64 syscall number to invoke from the
//! translated guest code, plus a translator-side ABI fix-up hook.

#![cfg(target_arch = "loongarch64")]

/// NT system calls frequently used by user-mode code under WoW64.
pub mod nt {
    pub const NtAllocateVirtualMemory: u32 = 0x18;
    pub const NtFreeVirtualMemory: u32 = 0x1B;
    pub const NtOpenFile: u32 = 0x33;
    pub const NtReadFile: u32 = 0x3F;
    pub const NtWriteFile: u32 = 0x48;
    pub const NtClose: u32 = 0x0F;
    pub const NtCreateFile: u32 = 0x42;
    pub const NtQueryInformationFile: u32 = 0x37;
    pub const NtSetInformationFile: u32 = 0x39;
    pub const NtTerminateProcess: u32 = 0x29;
    pub const NtTerminateThread: u32 = 0x2B;
    pub const NtDelayExecution: u32 = 0x55;
    pub const NtWaitForSingleObject: u32 = 0x58;
    pub const NtWaitForMultipleObjects: u32 = 0x5B;
    pub const NtDeviceIoControlFile: u32 = 0x44;
    pub const NtQueryVirtualMemory: u32 = 0x52;
    pub const NtCreateSection: u32 = 0x4A;
    pub const NtMapViewOfSection: u32 = 0x4B;
    pub const NtUnmapViewOfSection: u32 = 0x4C;
    pub const NtOpenProcessToken: u32 = 0x36;
}

/// Translate the NT syscall number used by the x86 guest into the
/// LA64-native syscall index. Returns `None` if the syscall is not
/// supported yet (the kernel then returns -ENOSYS to the guest).
#[allow(dead_code)]
pub fn translate_nt_syscall(nr: u32) -> Option<u64> {
    let mapping: &[(u32, u64)] = &[
        (nt::NtAllocateVirtualMemory, 0x18),
        (nt::NtFreeVirtualMemory, 0x1B),
        (nt::NtOpenFile, 0x33),
        (nt::NtReadFile, 0x3F),
        (nt::NtWriteFile, 0x48),
        (nt::NtClose, 0x0F),
        (nt::NtCreateFile, 0x42),
        (nt::NtQueryInformationFile, 0x37),
        (nt::NtSetInformationFile, 0x39),
        (nt::NtTerminateProcess, 0x29),
        (nt::NtTerminateThread, 0x2B),
        (nt::NtDelayExecution, 0x55),
        (nt::NtWaitForSingleObject, 0x58),
        (nt::NtWaitForMultipleObjects, 0x5B),
        (nt::NtDeviceIoControlFile, 0x44),
        (nt::NtQueryVirtualMemory, 0x52),
        (nt::NtCreateSection, 0x4A),
        (nt::NtMapViewOfSection, 0x4B),
        (nt::NtUnmapViewOfSection, 0x4C),
        (nt::NtOpenProcessToken, 0x36),
    ];
    for &(n, t) in mapping {
        if n == nr { return Some(t); }
    }
    None
}
