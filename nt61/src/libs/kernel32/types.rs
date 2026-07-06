//! kernel32.dll — public types
//
//! Win32 handle / module / instance newtypes and the
//! `ERROR_*` constant set. These are the things user-mode
//! code touches directly; everything else in kernel32
//! (process management, file I/O, ...) wraps an underlying
//! ntdll call.
//
//! References (for layout / signatures only):
//!   * Microsoft Windows 7 SDK winbase.h / winnt.h
//!   * ReactOS 0.3.x winbase.h

use crate::libs::ntdll::types as ntd_types;

/// `HANDLE` — opaque Win32 handle. Same layout as the NT
/// handle; we re-use the ntdll type.
pub type HANDLE = ntd_types::HANDLE;

/// `DWORD` — 32-bit unsigned.
pub type DWORD = u32;

/// `WORD` — 16-bit unsigned.
pub type WORD = u16;

/// `BYTE` — 8-bit unsigned.
pub type BYTE = u8;

/// Pseudo-handles that are not really allocated by the
/// handle table. `GetCurrentProcess()` and `GetCurrentThread()`
/// return these.
pub const HANDLE_CURRENT_PROCESS: HANDLE = -1isize as HANDLE;
pub const HANDLE_CURRENT_THREAD: HANDLE = -2isize as HANDLE;

/// Invalid handle value.
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

/// `HMODULE` / `HINSTANCE` — both are the base address of a
/// loaded module cast to a pointer.
pub type HMODULE = *mut u8;
pub type HINSTANCE = *mut u8;

/// `LPCSTR` / `LPCWSTR` / `LPSTR` / `LPWSTR` — null-terminated
/// string pointers.
pub type LPCSTR = *const i8;
pub type LPCWSTR = *const u16;
pub type LPSTR = *mut i8;
pub type LPWSTR = *mut u16;

/// `BOOL` — `int` in the SDK. The Win32 API uses the values 0
/// (false) and 1 (true); we follow the convention.
pub type BOOL = i32;
pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

/// `FARPROC` / `PROC` — function pointer.
pub type FARPROC = unsafe extern "C" fn() -> isize;
pub type PROC = FARPROC;

/// `UINT_PTR` / `ULONG_PTR` / `LONG_PTR` — pointer-sized
/// integers.
pub type UINT_PTR = usize;
pub type ULONG_PTR = usize;
pub type LONG_PTR = isize;
pub type DWORD_PTR = usize;

/// `ATOM` — atom (used by `GlobalAddAtom` / ...).
pub type ATOM = u16;

/// `LCID` / `LCID` — locale identifier.
pub type LCID = u32;

/// `LANGID` — language identifier.
pub type LANGID = u16;

/// `LPCVOID` / `LPVOID` — const and mutable pointer to
/// void.
pub type LPCVOID = *const core::ffi::c_void;
pub type LPVOID = *mut core::ffi::c_void;
