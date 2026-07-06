//! System PTE pool (`MiReserveSystemPtes` / `MiReleaseSystemPtes`)
//!
//! Non-x86_64 stub. x86_64 has the full implementation in
//! `arch::x86_64::paging`. Other architectures get no-op / pass-through
//! versions of the public API so kernel code can compile cleanly.
//!
//! Most MMIO callers do:
//!   `let va = mm::syspte::map_io_space(paddr, n).unwrap_or(paddr);`
//! which on non-x86_64 just degrades to using the physical address
//! directly (works on platforms with identity-mapped MMIO).

/// Reserve system PTEs. Non-x86_64 stub: returns None.
pub fn reserve_system_ptes(_count: u64) -> Option<u64> {
    None
}

/// Release system PTEs. Non-x86_64 stub: no-op.
pub fn release_system_ptes(_va: u64) {
}

/// Map I/O space. Non-x86_64 stub: returns None.
pub fn map_io_space(_pa: u64, _count: u64) -> Option<u64> {
    None
}

/// Unmap I/O space. Non-x86_64 stub: no-op.
pub fn unmap_io_space(_va: u64, _count: u64) {
}

/// Initialise the system PTE pool. Non-x86_64 stub: no-op.
pub fn init() {
}