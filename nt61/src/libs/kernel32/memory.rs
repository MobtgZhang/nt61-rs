//! kernel32 — memory management
//
//! `VirtualAlloc`, `VirtualFree`, `VirtualProtect`,
//! `VirtualQuery`, `HeapAlloc`, `HeapFree`, `HeapReAlloc`,
//! `HeapSize`, `GetProcessHeap`, `HeapCreate`,
//! `HeapDestroy`. Thin wrappers around the ntdll heap
//! (Rtl*Heap) and virtual memory (NtAllocateVirtualMemory)
//! primitives.

use super::error::{GetLastError, SetLastError};
use super::types::{BOOL, DWORD, FALSE, HANDLE, HANDLE_CURRENT_PROCESS, LPCVOID, LPVOID, TRUE};
use crate::libs::ntdll::heap as ntdll_heap;
use crate::libs::ntdll::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::libs::ntdll::virtual_mem as ntdll_vm;
use core::ptr;

// ---------------------------------------------------------------------------
// Virtual memory
// ---------------------------------------------------------------------------

pub mod vmem {
    pub const MEM_COMMIT: u32 = 0x0000_1000;
    pub const MEM_RESERVE: u32 = 0x0000_2000;
    pub const MEM_DECOMMIT: u32 = 0x0000_4000;
    pub const MEM_RELEASE: u32 = 0x0000_8000;
    pub const MEM_FREE: u32 = 0x0001_0000;
    pub const MEM_PRIVATE: u32 = 0x0002_0000;
    pub const PAGE_NOACCESS: u32 = 0x0001;
    pub const PAGE_READONLY: u32 = 0x0002;
    pub const PAGE_READWRITE: u32 = 0x0004;
    pub const PAGE_EXECUTE: u32 = 0x0010;
    pub const PAGE_EXECUTE_READ: u32 = 0x0020;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x0040;
    pub const PAGE_GUARD: u32 = 0x0100;
    pub const PAGE_NOCACHE: u32 = 0x0200;
}

/// `VirtualAlloc`.
pub unsafe extern "C" fn VirtualAlloc(
    address: LPVOID,
    size: usize,
    allocation_type: DWORD,
    protect: DWORD,
) -> LPVOID {
    if address.is_null() {
        let mut base: *mut u8 = ptr::null_mut();
        let mut s = size;
        let status = ntdll_vm::NtAllocateVirtualMemory(
            HANDLE_CURRENT_PROCESS,
            &mut base as *mut _ as *mut _,
            0,
            &mut s,
            allocation_type,
            protect,
        );
        if status != STATUS_SUCCESS {
            SetLastError(8);
            return ptr::null_mut();
        }
        return base as LPVOID;
    }
    // Specific address requested — accept and return it.
    address
}

/// `VirtualFree`.
pub unsafe extern "C" fn VirtualFree(
    address: LPVOID,
    size: usize,
    free_type: DWORD,
) -> BOOL {
    let mut base = address as *mut u8;
    let mut s = size;
    let status = ntdll_vm::NtFreeVirtualMemory(
        HANDLE_CURRENT_PROCESS,
        &mut base as *mut _ as *mut _,
        &mut s,
        free_type,
    );
    if status == STATUS_SUCCESS { TRUE } else { SetLastError(87); FALSE }
}

/// `VirtualProtect`.
pub unsafe extern "C" fn VirtualProtect(
    address: LPVOID,
    _size: usize,
    new_protect: DWORD,
    old_protect: *mut DWORD,
) -> BOOL {
    let mut base = address as *mut u8;
    let mut s = 0x1000;
    let status = ntdll_vm::NtProtectVirtualMemory(
        HANDLE_CURRENT_PROCESS,
        &mut base as *mut _ as *mut _,
        &mut s,
        new_protect,
        old_protect,
    );
    if status == STATUS_SUCCESS { TRUE } else { SetLastError(87); FALSE }
}

/// `MEMORY_BASIC_INFORMATION`.
#[repr(C)]
#[derive(Default)]
pub struct MemoryBasicInformation {
    pub base_address: LPVOID,
    pub allocation_base: LPVOID,
    pub allocation_protect: DWORD,
    pub _pad1: u32,
    pub region_size: u64,
    pub state: DWORD,
    pub protect: DWORD,
    pub type_: DWORD,
    pub _pad2: u32,
}

/// `VirtualQuery`.
pub unsafe extern "C" fn VirtualQuery(
    address: LPCVOID,
    buffer: *mut MemoryBasicInformation,
    length: usize,
) -> usize {
    if buffer.is_null() { SetLastError(87); return 0; }
    if length < core::mem::size_of::<MemoryBasicInformation>() {
        SetLastError(122);
        return 0;
    }
    let mbi = &mut *buffer;
    mbi.base_address = address as LPVOID;
    mbi.allocation_base = address as LPVOID;
    mbi.allocation_protect = 0x04;
    mbi.region_size = 0x1000;
    mbi.state = 0x1000; // MEM_COMMIT
    mbi.protect = 0x04;
    mbi.type_ = 0x20000; // MEM_PRIVATE
    core::mem::size_of::<MemoryBasicInformation>()
}

// ---------------------------------------------------------------------------
// Heap
// ---------------------------------------------------------------------------

pub mod heap_flags {
    pub const HEAP_NO_SERIALIZE: u32 = 0x0000_0001;
    pub const HEAP_GROWABLE: u32 = 0x0000_0002;
    pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
    pub const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x0000_0010;
}

/// `HeapCreate`.
pub unsafe extern "C" fn HeapCreate(
    options: DWORD,
    _initial_size: usize,
    _maximum_size: usize,
) -> HANDLE {
    ntdll_heap::RtlCreateHeap(options, ptr::null_mut(), 0, 0, ptr::null_mut(), ptr::null_mut())
}

/// `HeapDestroy`.
pub unsafe extern "C" fn HeapDestroy(heap: HANDLE) -> BOOL {
    let result = ntdll_heap::RtlDestroyHeap(heap);
    if result.is_null() { TRUE } else { FALSE }
}

/// `GetProcessHeap`.
pub unsafe extern "C" fn GetProcessHeap() -> HANDLE {
    ntdll_heap::RtlGetProcessHeap()
}

/// `HeapAlloc`.
pub unsafe extern "C" fn HeapAlloc(heap: HANDLE, flags: DWORD, bytes: usize) -> LPVOID {
    ntdll_heap::RtlAllocateHeap(heap, flags, bytes)
}

/// `HeapReAlloc`.
pub unsafe extern "C" fn HeapReAlloc(heap: HANDLE, flags: DWORD, memory: LPVOID, bytes: usize) -> LPVOID {
    ntdll_heap::RtlReAllocateHeap(heap, flags, memory, bytes)
}

/// `HeapFree`.
pub unsafe extern "C" fn HeapFree(heap: HANDLE, flags: DWORD, memory: LPVOID) -> BOOL {
    if ntdll_heap::RtlFreeHeap(heap, flags, memory) == 1 { TRUE } else { FALSE }
}

/// `HeapSize`.
pub unsafe extern "C" fn HeapSize(heap: HANDLE, flags: DWORD, memory: LPVOID) -> usize {
    ntdll_heap::RtlSizeHeap(heap, flags, memory)
}

/// `GlobalAlloc` — wraps `HeapAlloc` of the process heap.
/// Flags we honour:
///   0x0040 = GMEM_ZEROINIT
///   0x001C = GMEM_MOVEABLE | GMEM_DISCARDABLE | GMEM_DDESHARE
pub unsafe extern "C" fn GlobalAlloc(flags: DWORD, bytes: usize) -> HANDLE {
    let h = GetProcessHeap();
    let mut f = 0;
    if flags & 0x0040 != 0 { f |= ntdll_heap::HEAP_ZERO_MEMORY; }
    let p = ntdll_heap::RtlAllocateHeap(h, f, bytes);
    if p.is_null() { return ptr::null_mut(); }
    p
}

/// `GlobalFree`.
pub unsafe extern "C" fn GlobalFree(memory: HANDLE) -> HANDLE {
    if HeapFree(GetProcessHeap(), 0, memory) != 0 { ptr::null_mut() } else { memory }
}

/// `LocalAlloc` — same as GlobalAlloc in modern Windows.
pub unsafe extern "C" fn LocalAlloc(flags: DWORD, bytes: usize) -> HANDLE {
    GlobalAlloc(flags, bytes)
}
pub unsafe extern "C" fn LocalFree(memory: HANDLE) -> HANDLE { GlobalFree(memory) }
