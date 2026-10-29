//! BTL — NT system call bridging for x86 guests.
//!
//! The most common NT system calls exposed via WoW64 —
//! `NT_ALLOCATE_VIRTUAL_MEMORY`, `NT_OPEN_FILE`, etc. — are listed here.
//! Each entry returns the LA64 syscall number to invoke from the
//! translated guest code, plus a translator-side ABI fix-up hook.

#![cfg(target_arch = "loongarch64")]

/// NT system calls frequently used by user-mode code under WoW64.
pub mod nt {
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
    pub const NT_FREE_VIRTUAL_MEMORY: u32 = 0x1B;
    pub const NT_OPEN_FILE: u32 = 0x33;
    pub const NT_READ_FILE: u32 = 0x3F;
    pub const NT_WRITE_FILE: u32 = 0x48;
    pub const NT_CLOSE: u32 = 0x0F;
    pub const NT_CREATE_FILE: u32 = 0x42;
    pub const NT_QUERY_INFORMATION_FILE: u32 = 0x37;
    pub const NT_SET_INFORMATION_FILE: u32 = 0x39;
    pub const NT_TERMINATE_PROCESS: u32 = 0x29;
    pub const NT_TERMINATE_THREAD: u32 = 0x2B;
    pub const NT_DELAY_EXECUTION: u32 = 0x55;
    pub const NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x58;
    pub const NT_WAIT_FOR_MULTIPLE_OBJECTS: u32 = 0x5B;
    pub const NT_DEVICE_IO_CONTROL_FILE: u32 = 0x44;
    pub const NT_QUERY_VIRTUAL_MEMORY: u32 = 0x52;
    pub const NT_CREATE_SECTION: u32 = 0x4A;
    pub const NT_MAP_VIEW_OF_SECTION: u32 = 0x4B;
    pub const NT_UNMAP_VIEW_OF_SECTION: u32 = 0x4C;
    pub const NT_OPEN_PROCESS_TOKEN: u32 = 0x36;
}

/// Translate the NT syscall number used by the x86 guest into the
/// LA64-native syscall index. Returns `None` if the syscall is not
/// supported yet (the kernel then returns -ENOSYS to the guest).
pub fn translate_nt_syscall(nr: u32) -> Option<u64> {
    if crate::ke::ssdt_common::has_entry(nr as usize) {
        Some(nr as u64)
    } else {
        None
    }
}
