//! kernel32 — memory management
//
//! `virtual_alloc`, `virtual_free`, `virtual_protect`,
//! `virtual_query`, `heap_alloc`, `heap_free`, `heap_re_alloc`,
//! `heap_size`, `get_process_heap`, `heap_create`,
//! `heap_destroy`. Thin wrappers around the ntdll heap
//! (Rtl*Heap) and virtual memory (NT_ALLOCATE_VIRTUAL_MEMORY)
//! primitives.

use super::error::set_last_error;
use super::types::{BOOL, DWORD, FALSE, HANDLE, HANDLE_CURRENT_PROCESS, LPCVOID, LPVOID, TRUE};
use crate::libs::ntdll::heap as ntdll_heap;
use crate::libs::ntdll::status::STATUS_SUCCESS;
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `virtual_alloc`.
pub unsafe extern "C" fn virtual_alloc(
    address: LPVOID,
    size: usize,
    allocation_type: DWORD,
    protect: DWORD,
) -> LPVOID {
    if address.is_null() {
        let mut base: *mut u8 = ptr::null_mut();
        let mut s = size;
        let status = ntdll_vm::nt_allocate_virtual_memory(
            HANDLE_CURRENT_PROCESS,
            &mut base as *mut _ as *mut _,
            0,
            &mut s,
            allocation_type,
            protect,
        );
        if status != STATUS_SUCCESS {
            set_last_error(8);
            return ptr::null_mut();
        }
        return base as LPVOID;
    }
    // Specific address requested — accept and return it.
    address
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `virtual_free`.
pub unsafe extern "C" fn virtual_free(address: LPVOID, size: usize, free_type: DWORD) -> BOOL {
    let mut base = address as *mut u8;
    let mut s = size;
    let status = ntdll_vm::nt_free_virtual_memory(
        HANDLE_CURRENT_PROCESS,
        &mut base as *mut _ as *mut _,
        &mut s,
        free_type,
    );
    if status == STATUS_SUCCESS {
        TRUE
    } else {
        set_last_error(87);
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `virtual_protect`.
pub unsafe extern "C" fn virtual_protect(
    address: LPVOID,
    _size: usize,
    new_protect: DWORD,
    old_protect: *mut DWORD,
) -> BOOL {
    let mut base = address as *mut u8;
    let mut s = 0x1000;
    let status = ntdll_vm::nt_protect_virtual_memory(
        HANDLE_CURRENT_PROCESS,
        &mut base as *mut _ as *mut _,
        &mut s,
        new_protect,
        old_protect,
    );
    if status == STATUS_SUCCESS {
        TRUE
    } else {
        set_last_error(87);
        FALSE
    }
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `virtual_query`.
pub unsafe extern "C" fn virtual_query(
    address: LPCVOID,
    buffer: *mut MemoryBasicInformation,
    length: usize,
) -> usize {
    if buffer.is_null() {
        set_last_error(87);
        return 0;
    }
    if length < core::mem::size_of::<MemoryBasicInformation>() {
        set_last_error(122);
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `heap_create`.
pub unsafe extern "C" fn heap_create(
    options: DWORD,
    _initial_size: usize,
    _maximum_size: usize,
) -> HANDLE {
    ntdll_heap::rtl_create_heap(
        options,
        ptr::null_mut(),
        0,
        0,
        ptr::null_mut(),
        ptr::null_mut(),
    )
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `heap_destroy`.
pub unsafe extern "C" fn heap_destroy(heap: HANDLE) -> BOOL {
    let result = ntdll_heap::rtl_destroy_heap(heap);
    if result.is_null() {
        TRUE
    } else {
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `get_process_heap`.
pub unsafe extern "C" fn get_process_heap() -> HANDLE {
    ntdll_heap::rtl_get_process_heap()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `heap_alloc`.
pub unsafe extern "C" fn heap_alloc(heap: HANDLE, flags: DWORD, bytes: usize) -> LPVOID {
    ntdll_heap::rtl_allocate_heap(heap, flags, bytes)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `heap_re_alloc`.
pub unsafe extern "C" fn heap_re_alloc(
    heap: HANDLE,
    flags: DWORD,
    memory: LPVOID,
    bytes: usize,
) -> LPVOID {
    ntdll_heap::rtl_re_allocate_heap(heap, flags, memory, bytes)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `heap_free`.
pub unsafe extern "C" fn heap_free(heap: HANDLE, flags: DWORD, memory: LPVOID) -> BOOL {
    if ntdll_heap::rtl_free_heap(heap, flags, memory) == 1 {
        TRUE
    } else {
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `heap_size`.
pub unsafe extern "C" fn heap_size(heap: HANDLE, flags: DWORD, memory: LPVOID) -> usize {
    ntdll_heap::rtl_size_heap(heap, flags, memory)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `global_alloc` — wraps `heap_alloc` of the process heap.
/// flags we honour:
///   0x0040 = GMEM_ZEROINIT
///   0x001C = GMEM_MOVEABLE | GMEM_DISCARDABLE | GMEM_DDESHARE
pub unsafe extern "C" fn global_alloc(flags: DWORD, bytes: usize) -> HANDLE {
    let h = get_process_heap();
    let mut f = 0;
    if flags & 0x0040 != 0 {
        f |= ntdll_heap::HEAP_ZERO_MEMORY;
    }
    let p = ntdll_heap::rtl_allocate_heap(h, f, bytes);
    if p.is_null() {
        return ptr::null_mut();
    }
    p
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `global_free`.
pub unsafe extern "C" fn global_free(memory: HANDLE) -> HANDLE {
    if heap_free(get_process_heap(), 0, memory) != 0 {
        ptr::null_mut()
    } else {
        memory
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `local_alloc` — same as global_alloc in modern Windows.
pub unsafe extern "C" fn local_alloc(flags: DWORD, bytes: usize) -> HANDLE {
    global_alloc(flags, bytes)
}
/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn local_free(memory: HANDLE) -> HANDLE {
    global_free(memory)
}
