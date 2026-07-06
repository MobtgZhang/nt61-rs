//! BTL — Win32 API thunk layer for x86 guests.

#![cfg(target_arch = "loongarch64")]

/// Win32 API service table index used to dispatch into win32k.sys.
pub const WIN32K_SERVICE_TABLE: usize = 1;

/// Translate a user32.dll / gdi32.dll call into the corresponding
/// win32k.sys syscall. `idx` is the user32 syscall index on the
/// guest side; we add the SERVICE_TABLE index once and return the
/// win32k-side number to invoke.
#[allow(dead_code)]
pub fn translate_win32(idx: u32) -> Option<u32> {
    if idx >= 0x1000 { return None; }
    Some(WIN32K_SERVICE_TABLE as u32 * 0x10000 + idx)
}
