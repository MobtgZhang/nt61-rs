//! ntdll — Rtl* ACL APIs

use super::status::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::types::{NTSTATUS, PVOID};
use core::ptr;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Acl {
    pub acl_revision: u8,
    pub acl_size: u16,
    pub ace_count: u16,
    pub _pad: u16,
}

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
    (*acl).acl_revision = 2;
    (*acl).acl_size = core::mem::size_of::<Acl>() as u16;
    (*acl).ace_count = 0;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn rtl_add_access_allowed_ace(
    acl: *mut Acl,
    acl_revision: u32,
    access_mask: u32,
    sid: PVOID,
) -> NTSTATUS {
    write_ace(acl, 0x00, acl_revision, access_mask, sid)
}

pub unsafe extern "C" fn rtl_add_access_denied_ace(
    acl: *mut Acl,
    acl_revision: u32,
    access_mask: u32,
    sid: PVOID,
) -> NTSTATUS {
    write_ace(acl, 0x01, acl_revision, access_mask, sid)
}

unsafe fn write_ace(
    acl: *mut Acl,
    ace_type: u8,
    acl_revision: u32,
    access_mask: u32,
    sid: PVOID,
) -> NTSTATUS {
    if acl.is_null() || sid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = acl_revision;
    if ((sid as *mut u8).add(0) as *const u8).read_unaligned() != 1 {
        return STATUS_INVALID_PARAMETER;
    }
    let sub_authority_count = ((sid as *mut u8).add(7) as *const u8).read_unaligned() as usize;
    if sub_authority_count > 15 {
        return STATUS_INVALID_PARAMETER;
    }
    let sid_size = 8 + sub_authority_count * 4;
    let ace_size = 8 + sid_size;
    let acl_offset = (*acl).acl_size as usize;
    if acl_offset < core::mem::size_of::<Acl>() {
        return STATUS_INVALID_PARAMETER;
    }
    match acl_offset.checked_add(ace_size) {
        Some(end) if end <= 4096 => {}
        _ => return STATUS_BUFFER_TOO_SMALL,
    }

    let ace = (acl as *mut u8).add(acl_offset);
    ptr::write_unaligned(ace, ace_type);
    ptr::write_unaligned(ace.add(1), 0u8);
    ptr::write_unaligned(ace.add(2) as *mut u16, ace_size as u16);
    ptr::write_unaligned(ace.add(4) as *mut u32, access_mask);
    ptr::copy_nonoverlapping(sid as *const u8, ace.add(8), sid_size);

    (*acl).ace_count = (*acl).ace_count.saturating_add(1);
    (*acl).acl_size = (acl_offset + ace_size) as u16;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn rtl_valid_acl(acl: *mut Acl) -> u32 {
    if acl.is_null() {
        return 0;
    }
    if (*acl).acl_revision != 2
        || (*acl).ace_count == 0 && (*acl).acl_size as usize != core::mem::size_of::<Acl>()
    {
        return 0;
    }
    1
}

pub unsafe extern "C" fn rtl_first_free_ace(acl: *mut Acl) -> PVOID {
    if acl.is_null() {
        return ptr::null_mut();
    }
    (acl as *mut u8).add((*acl).acl_size as usize) as PVOID
}
