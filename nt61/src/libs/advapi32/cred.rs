//! advapi32 — credential Management APIs
//
//! Implements Windows credential Manager functions:
//! - CredWriteW — write a credential to storage
//! - CredReadW — read a credential from storage
//! - CredDeleteW — Delete a credential
//! - CredEnumerateW — Enumerate stored credentials
//! - CredFree — Free credential memory
//! - CredGetSessionTypes — Get session credential types

use core::sync::atomic::{AtomicU64, Ordering};

use super::types::*;
use crate::libs::ntdll::types::{DWORD, PCWSTR, PVOID, PWSTR};
use core::ptr::null_mut;

const MAX_CREDENTIALS: usize = 256;

#[derive(Copy, Clone)]
struct StoredCredential {
    flags: DWORD,
    cred_type: DWORD,
    target_name: [u16; 256],
    comment: [u16; 256],
    last_written: FILETIME,
    credential_blob: [u8; 512],
    credential_blob_size: DWORD,
    persist: DWORD,
    target_alias: [u16; 256],
    user_name: [u16; 256],
    in_use: bool,
}

impl StoredCredential {
    const fn new() -> Self {
        Self {
            flags: 0,
            cred_type: 0,
            target_name: [0; 256],
            comment: [0; 256],
            last_written: FILETIME {
                dw_low_date_time: 0,
                dw_high_date_time: 0,
            },
            credential_blob: [0; 512],
            credential_blob_size: 0,
            persist: 0,
            target_alias: [0; 256],
            user_name: [0; 256],
            in_use: false,
        }
    }
}

static mut CREDENTIAL_STORE: [StoredCredential; MAX_CREDENTIALS] =
    [StoredCredential::new(); MAX_CREDENTIALS];

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn copy_wide_to_buffer(dest: &mut [u16], src: PCWSTR) {
    if src.is_null() {
        dest[0] = 0;
        return;
    }

    let mut i = 0;
    let mut p = src;
    while i < dest.len() - 1 && !p.is_null() && *p != 0 {
        dest[i] = *p;
        i += 1;
        p = p.offset(1);
    }
    dest[i] = 0;
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn wide_str_equal(s1: &[u16], s2: PCWSTR) -> bool {
    if s2.is_null() {
        return s1[0] == 0;
    }

    let mut i = 0;
    let mut p = s2;
    while i < s1.len() && s1[i] != 0 && !p.is_null() && *p != 0 {
        if s1[i] != *p {
            return false;
        }
        i += 1;
        p = p.offset(1);
    }

    (i >= s1.len() || s1[i] == 0) && (p.is_null() || *p == 0)
}

fn get_current_filetime() -> FILETIME {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    FILETIME {
        dw_low_date_time: (counter & 0xFFFFFFFF) as DWORD,
        dw_high_date_time: (counter >> 32) as DWORD,
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredWriteW(credential: PCREDENTIALW, _flags: DWORD) -> LONG {
    if credential.is_null() {
        return 0; // FALSE
    }

    let cred = &*credential;

    if cred.target_name.is_null() {
        return 0; // FALSE
    }

    let mut slot_index = None;

    for (i, stored) in (*core::ptr::addr_of_mut!(CREDENTIAL_STORE))
        .iter_mut()
        .enumerate()
    {
        if stored.in_use && wide_str_equal(&stored.target_name, cred.target_name) {
            slot_index = Some(i);
            break;
        }
    }

    if slot_index.is_none() {
        for (i, stored) in (*core::ptr::addr_of!(CREDENTIAL_STORE)).iter().enumerate() {
            if !stored.in_use {
                slot_index = Some(i);
                break;
            }
        }
    }

    let index = match slot_index {
        Some(idx) => idx,
        None => return 0, // Storage full
    };

    let stored = &mut CREDENTIAL_STORE[index];
    stored.flags = cred.flags;
    stored.cred_type = cred.r#type;
    copy_wide_to_buffer(&mut stored.target_name, cred.target_name);
    copy_wide_to_buffer(&mut stored.comment, cred.comment);
    stored.last_written = get_current_filetime();
    stored.persist = cred.persist;
    copy_wide_to_buffer(&mut stored.target_alias, cred.target_alias);
    copy_wide_to_buffer(&mut stored.user_name, cred.user_name);

    if !cred.credential_blob.is_null() && cred.credential_blob_size > 0 {
        let copy_size = core::cmp::min(
            cred.credential_blob_size as usize,
            stored.credential_blob.len(),
        );
        let blob_slice = core::slice::from_raw_parts(cred.credential_blob, copy_size);
        stored.credential_blob[..copy_size].copy_from_slice(blob_slice);
        stored.credential_blob_size = copy_size as DWORD;
    } else {
        stored.credential_blob_size = 0;
    }

    stored.in_use = true;

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredReadW(
    target_name: PCWSTR,
    r#type: DWORD,
    _flags: DWORD,
    credential: *mut PCREDENTIALW,
) -> LONG {
    if target_name.is_null() || credential.is_null() {
        return 0; // FALSE
    }

    for stored in (*core::ptr::addr_of!(CREDENTIAL_STORE)).iter() {
        if !stored.in_use {
            continue;
        }

        if stored.cred_type != r#type {
            continue;
        }

        if !wide_str_equal(&stored.target_name, target_name) {
            continue;
        }

        // Note: In real implementation, this would use local_alloc
        // For kernel stub, we'll use a static buffer
        static mut CRED_BUFFER: CREDENTIALW = CREDENTIALW {
            flags: 0,
            r#type: 0,
            target_name: null_mut(),
            comment: null_mut(),
            last_written: FILETIME {
                dw_low_date_time: 0,
                dw_high_date_time: 0,
            },
            credential_blob_size: 0,
            credential_blob: null_mut(),
            persist: 0,
            attribute_count: 0,
            attributes: null_mut(),
            target_alias: null_mut(),
            user_name: null_mut(),
        };

        CRED_BUFFER.flags = stored.flags;
        CRED_BUFFER.r#type = stored.cred_type;
        CRED_BUFFER.target_name = stored.target_name.as_ptr() as PWSTR;
        CRED_BUFFER.comment = stored.comment.as_ptr() as PWSTR;
        CRED_BUFFER.last_written = stored.last_written;
        CRED_BUFFER.credential_blob_size = stored.credential_blob_size;
        CRED_BUFFER.credential_blob = stored.credential_blob.as_ptr() as *mut BYTE;
        CRED_BUFFER.persist = stored.persist;
        CRED_BUFFER.attribute_count = 0;
        CRED_BUFFER.attributes = null_mut();
        CRED_BUFFER.target_alias = stored.target_alias.as_ptr() as PWSTR;
        CRED_BUFFER.user_name = stored.user_name.as_ptr() as PWSTR;

        *credential = core::ptr::addr_of!(CRED_BUFFER) as *const _ as *mut _;
        return 1; // TRUE
    }

    0 // FALSE - not found
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredDeleteW(target_name: PCWSTR, r#type: DWORD, _flags: DWORD) -> LONG {
    if target_name.is_null() {
        return 0; // FALSE
    }

    for stored in (*core::ptr::addr_of_mut!(CREDENTIAL_STORE)).iter_mut() {
        if !stored.in_use {
            continue;
        }

        if stored.cred_type != r#type {
            continue;
        }

        if !wide_str_equal(&stored.target_name, target_name) {
            continue;
        }

        stored.in_use = false;
        return 1; // TRUE
    }

    0 // FALSE - not found
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredEnumerateW(
    _filter: PCWSTR,
    _flags: DWORD,
    count: *mut DWORD,
    credentials: *mut *mut PCREDENTIALW,
) -> LONG {
    if count.is_null() || credentials.is_null() {
        return 0; // FALSE
    }

    let mut used_count = 0;
    for stored in (*core::ptr::addr_of!(CREDENTIAL_STORE)).iter() {
        if stored.in_use {
            used_count += 1;
        }
    }

    *count = used_count;

    if used_count == 0 {
        *credentials = null_mut();
        return 1; // TRUE
    }

    *count = 0;
    *credentials = null_mut();

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredFree(_buffer: PVOID) {
    // For kernel stub, we use static buffers so nothing to free
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredGetSessionTypes(
    maximum_persist_count: DWORD,
    maximum_persist: *mut DWORD,
) -> LONG {
    if maximum_persist.is_null() {
        return 0; // FALSE
    }

    if maximum_persist_count >= 1 {
        *maximum_persist.add(0) = CRED_PERSIST_SESSION;
    }
    if maximum_persist_count >= 2 {
        *maximum_persist.add(1) = CRED_PERSIST_LOCAL_MACHINE;
    }

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredIsMarshaledCredentialW(marshaled_credential: PCWSTR) -> LONG {
    if marshaled_credential.is_null() {
        return 0; // FALSE
    }

    if *marshaled_credential == '@' as u16 && *marshaled_credential.add(1) == '@' as u16 {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredUnmarshalCredentialW(
    marshaled_credential: PCWSTR,
    cred_type: *mut DWORD,
    credential: *mut PVOID,
) -> LONG {
    if marshaled_credential.is_null() || cred_type.is_null() || credential.is_null() {
        return 0; // FALSE
    }

    0 // FALSE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredMarshalCredentialW(
    _cred_type: DWORD,
    credential: PVOID,
    marshaled_credential: *mut PWSTR,
) -> LONG {
    if credential.is_null() || marshaled_credential.is_null() {
        return 0; // FALSE
    }

    0 // FALSE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredGetTargetInfoW(
    target_name: PCWSTR,
    _flags: DWORD,
    target_info: *mut PVOID,
) -> LONG {
    if target_name.is_null() || target_info.is_null() {
        return 0; // FALSE
    }

    0 // FALSE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredRenameW(
    old_target_name: PCWSTR,
    new_target_name: PCWSTR,
    r#type: DWORD,
    _flags: DWORD,
) -> LONG {
    if old_target_name.is_null() || new_target_name.is_null() {
        return 0; // FALSE
    }

    for stored in (*core::ptr::addr_of_mut!(CREDENTIAL_STORE)).iter_mut() {
        if !stored.in_use {
            continue;
        }

        if stored.cred_type != r#type {
            continue;
        }

        if !wide_str_equal(&stored.target_name, old_target_name) {
            continue;
        }

        copy_wide_to_buffer(&mut stored.target_name, new_target_name);
        return 1; // TRUE
    }

    0 // FALSE - not found
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredFindBestCredentialW(
    target_name: PCWSTR,
    r#type: DWORD,
    flags: DWORD,
    credential: *mut PCREDENTIALW,
) -> LONG {
    // For simple implementation, just use CredReadW
    CredReadW(target_name, r#type, flags, credential)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredProtectW(
    _f_as_self: LONG,
    psz_credentials: PWSTR,
    cch_credentials: DWORD,
    psz_protected_credentials: PWSTR,
    pcch_max_chars: *mut DWORD,
    protection_type: *mut DWORD,
) -> LONG {
    if psz_credentials.is_null() || pcch_max_chars.is_null() {
        return 0; // FALSE
    }

    if !psz_protected_credentials.is_null() {
        let copy_len = core::cmp::min(cch_credentials as usize, *pcch_max_chars as usize);
        for i in 0..copy_len {
            *psz_protected_credentials.add(i) = *psz_credentials.add(i);
        }
        if copy_len < *pcch_max_chars as usize {
            *psz_protected_credentials.add(copy_len) = 0;
        }
    }

    *pcch_max_chars = cch_credentials;
    if !protection_type.is_null() {
        *protection_type = 1; // CredProtected
    }

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn CredUnprotectW(
    _f_as_self: LONG,
    psz_protected_credentials: PWSTR,
    cch_protected_credentials: DWORD,
    psz_credentials: PWSTR,
    pcch_max_chars: *mut DWORD,
) -> LONG {
    if psz_protected_credentials.is_null() || pcch_max_chars.is_null() {
        return 0; // FALSE
    }

    if !psz_credentials.is_null() {
        let copy_len = core::cmp::min(cch_protected_credentials as usize, *pcch_max_chars as usize);
        for i in 0..copy_len {
            *psz_credentials.add(i) = *psz_protected_credentials.add(i);
        }
        if copy_len < *pcch_max_chars as usize {
            *psz_credentials.add(copy_len) = 0;
        }
    }

    *pcch_max_chars = cch_protected_credentials;

    1 // TRUE
}
