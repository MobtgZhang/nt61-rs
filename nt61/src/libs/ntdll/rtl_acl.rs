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

/// `rtl_create_acl` — initialise an existing buffer as an empty
/// ACL. The caller must have allocated at least
/// `sizeof(ACL)` bytes at `Acl`.
pub unsafe extern "C" fn rtl_create_acl(
    acl: *mut Acl,
    acl_length: u32,
    acl_revision: u32,
) -> NTSTATUS {
    if acl.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if (acl_length as usize) < core::mem::size_of::<Acl>() {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let _ = acl_revision;
    (*acl).acl_revision = 2; // ACL_REVISION
    (*acl).acl_size = core::mem::size_of::<Acl>() as u16;
    (*acl).ace_count = 0;
    STATUS_SUCCESS
}

/// `rtl_add_access_allowed_ace` — append an access-allowed ACE
/// to the ACL. The buffer must have enough room.
pub unsafe extern "C" fn rtl_add_access_allowed_ace(
    acl: *mut Acl,
    acl_revision: u32,
    access_mask: u32,
    sid: PVOID,
) -> NTSTATUS {
    if acl.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (acl_revision, access_mask, sid);
    (*acl).ace_count = (*acl).ace_count.saturating_add(1);
    (*acl).acl_size = (*acl).acl_size.saturating_add(12);
    STATUS_SUCCESS
}

/// `rtl_add_access_denied_ace`.
pub unsafe extern "C" fn rtl_add_access_denied_ace(
    acl: *mut Acl,
    acl_revision: u32,
    access_mask: u32,
    sid: PVOID,
) -> NTSTATUS {
    if acl.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (acl_revision, access_mask, sid);
    (*acl).ace_count = (*acl).ace_count.saturating_add(1);
    (*acl).acl_size = (*acl).acl_size.saturating_add(12);
    STATUS_SUCCESS
}

/// `rtl_valid_acl` — returns TRUE if the ACL is well-formed.
/// The bootstrap always returns TRUE.
pub unsafe extern "C" fn rtl_valid_acl(acl: *mut Acl) -> u32 {
    if acl.is_null() {
        return 0;
    }
    1
}

/// `rtl_first_free_ace` — pointer to the first free byte in the
/// ACL. We return a fixed offset past the header.
pub unsafe extern "C" fn rtl_first_free_ace(acl: *mut Acl) -> PVOID {
    if acl.is_null() {
        return ptr::null_mut();
    }
    let off = (*acl).acl_size as usize;
    (acl as *mut u8).add(off) as PVOID
}
