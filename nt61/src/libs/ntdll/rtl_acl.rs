//! ntdll — Rtl* ACL (access control list) APIs
//
//! The full ACL layout is the NT security descriptor / ACL /
//! ACE triple documented in `[MS-DTYP]`. We implement the
//! user-mode entry points in their SDK form and accept the
//! calls. No real access checks are performed — the kernel's
//! security reference monitor (in `se::`) will be the source
//! of truth once it lands.
//
//! References: MSDN Library "Windows 7" — Rtl* ACL.

use super::status::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::types::{NTSTATUS, PVOID};
use core::ptr;

/// `ACL` — fixed structure size. The actual data follows
/// immediately in memory.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Acl {
    pub acl_revision: u8,
    pub acl_size: u16,
    pub ace_count: u16,
    pub _pad: u16,
}

/// `RtlCreateAcl` — initialise an existing buffer as an empty
/// ACL. The caller must have allocated at least
/// `sizeof(ACL)` bytes at `Acl`.
pub unsafe extern "C" fn RtlCreateAcl(
    acl: *mut Acl,
    acl_length: u32,
    acl_revision: u32,
) -> NTSTATUS {
    if acl.is_null() { return STATUS_INVALID_PARAMETER; }
    if (acl_length as usize) < core::mem::size_of::<Acl>() {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let _ = acl_revision;
    (*acl).acl_revision = 2; // ACL_REVISION
    (*acl).acl_size = core::mem::size_of::<Acl>() as u16;
    (*acl).ace_count = 0;
    STATUS_SUCCESS
}

/// `RtlAddAccessAllowedAce` — append an access-allowed ACE
/// to the ACL. The buffer must have enough room.
pub unsafe extern "C" fn RtlAddAccessAllowedAce(
    acl: *mut Acl,
    acl_revision: u32,
    access_mask: u32,
    sid: PVOID,
) -> NTSTATUS {
    if acl.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (acl_revision, access_mask, sid);
    (*acl).ace_count = (*acl).ace_count.saturating_add(1);
    (*acl).acl_size = (*acl).acl_size.saturating_add(12);
    STATUS_SUCCESS
}

/// `RtlAddAccessDeniedAce`.
pub unsafe extern "C" fn RtlAddAccessDeniedAce(
    acl: *mut Acl,
    acl_revision: u32,
    access_mask: u32,
    sid: PVOID,
) -> NTSTATUS {
    if acl.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (acl_revision, access_mask, sid);
    (*acl).ace_count = (*acl).ace_count.saturating_add(1);
    (*acl).acl_size = (*acl).acl_size.saturating_add(12);
    STATUS_SUCCESS
}

/// `RtlValidAcl` — returns TRUE if the ACL is well-formed.
/// The bootstrap always returns TRUE.
pub unsafe extern "C" fn RtlValidAcl(acl: *mut Acl) -> u32 {
    if acl.is_null() { return 0; }
    1
}

/// `RtlFirstFreeAce` — pointer to the first free byte in the
/// ACL. We return a fixed offset past the header.
pub unsafe extern "C" fn RtlFirstFreeAce(acl: *mut Acl) -> PVOID {
    if acl.is_null() { return ptr::null_mut(); }
    let off = (*acl).acl_size as usize;
    (acl as *mut u8).add(off) as PVOID
}
