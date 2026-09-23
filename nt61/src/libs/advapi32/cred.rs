//! advapi32 — Credential Management APIs
//
//! Implements Windows Credential Manager functions:
//! - CredWriteW — Write a credential to storage
//! - CredReadW — Read a credential from storage
//! - CredDeleteW — Delete a credential
//! - CredEnumerateW — Enumerate stored credentials
//! - CredFree — Free credential memory
//! - CredGetSessionTypes — Get session credential types

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case, non_upper_case_globals, dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use super::types::*;
use crate::libs::ntdll::types::{HANDLE, PVOID, DWORD, PWSTR, PCWSTR};
use core::ptr::{null_mut, null};
use alloc::vec::Vec;
use alloc::boxed::Box;


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
            last_written: FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 },
            credential_blob: [0; 512],
            credential_blob_size: 0,
            persist: 0,
            target_alias: [0; 256],
            user_name: [0; 256],
            in_use: false,
        }
    }
}

static mut CREDENTIAL_STORE: [StoredCredential; MAX_CREDENTIALS] = [StoredCredential::new(); MAX_CREDENTIALS];

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
    unsafe {
        COUNTER += 1;
        FILETIME {
            dwLowDateTime: (COUNTER & 0xFFFFFFFF) as DWORD,
            dwHighDateTime: (COUNTER >> 32) as DWORD,
        }
    }
}


#[no_mangle]
pub unsafe extern "C" fn CredWriteW(
    Credential: PCREDENTIALW,
    Flags: DWORD,
) -> LONG {
    if Credential.is_null() {
        return 0; // FALSE
    }

    let cred = &*Credential;

    if cred.TargetName.is_null() {
        return 0; // FALSE
    }

    let mut slot_index = None;

    for (i, stored) in CREDENTIAL_STORE.iter_mut().enumerate() {
        if stored.in_use && wide_str_equal(&stored.target_name, cred.TargetName) {
            slot_index = Some(i);
            break;
        }
    }

    if slot_index.is_none() {
        for (i, stored) in CREDENTIAL_STORE.iter().enumerate() {
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
    stored.flags = cred.Flags;
    stored.cred_type = cred.Type;
    copy_wide_to_buffer(&mut stored.target_name, cred.TargetName);
    copy_wide_to_buffer(&mut stored.comment, cred.Comment);
    stored.last_written = get_current_filetime();
    stored.persist = cred.Persist;
    copy_wide_to_buffer(&mut stored.target_alias, cred.TargetAlias);
    copy_wide_to_buffer(&mut stored.user_name, cred.UserName);

    if !cred.CredentialBlob.is_null() && cred.CredentialBlobSize > 0 {
        let copy_size = core::cmp::min(cred.CredentialBlobSize as usize, stored.credential_blob.len());
        let blob_slice = core::slice::from_raw_parts(cred.CredentialBlob, copy_size);
        stored.credential_blob[..copy_size].copy_from_slice(blob_slice);
        stored.credential_blob_size = copy_size as DWORD;
    } else {
        stored.credential_blob_size = 0;
    }

    stored.in_use = true;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn CredReadW(
    TargetName: PCWSTR,
    Type: DWORD,
    Flags: DWORD,
    Credential: *mut PCREDENTIALW,
) -> LONG {
    if TargetName.is_null() || Credential.is_null() {
        return 0; // FALSE
    }

    for stored in CREDENTIAL_STORE.iter() {
        if !stored.in_use {
            continue;
        }

        if stored.cred_type != Type {
            continue;
        }

        if !wide_str_equal(&stored.target_name, TargetName) {
            continue;
        }

        // Note: In real implementation, this would use LocalAlloc
        // For kernel stub, we'll use a static buffer
        static mut CRED_BUFFER: CREDENTIALW = CREDENTIALW {
            Flags: 0,
            Type: 0,
            TargetName: null_mut(),
            Comment: null_mut(),
            LastWritten: FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 },
            CredentialBlobSize: 0,
            CredentialBlob: null_mut(),
            Persist: 0,
            AttributeCount: 0,
            Attributes: null_mut(),
            TargetAlias: null_mut(),
            UserName: null_mut(),
        };

        CRED_BUFFER.Flags = stored.flags;
        CRED_BUFFER.Type = stored.cred_type;
        CRED_BUFFER.TargetName = stored.target_name.as_ptr() as PWSTR;
        CRED_BUFFER.Comment = stored.comment.as_ptr() as PWSTR;
        CRED_BUFFER.LastWritten = stored.last_written;
        CRED_BUFFER.CredentialBlobSize = stored.credential_blob_size;
        CRED_BUFFER.CredentialBlob = stored.credential_blob.as_ptr() as *mut BYTE;
        CRED_BUFFER.Persist = stored.persist;
        CRED_BUFFER.AttributeCount = 0;
        CRED_BUFFER.Attributes = null_mut();
        CRED_BUFFER.TargetAlias = stored.target_alias.as_ptr() as PWSTR;
        CRED_BUFFER.UserName = stored.user_name.as_ptr() as PWSTR;

        *Credential = &CRED_BUFFER as *const _ as *mut _;
        return 1; // TRUE
    }

    0 // FALSE - not found
}

#[no_mangle]
pub unsafe extern "C" fn CredDeleteW(
    TargetName: PCWSTR,
    Type: DWORD,
    Flags: DWORD,
) -> LONG {
    if TargetName.is_null() {
        return 0; // FALSE
    }

    for stored in CREDENTIAL_STORE.iter_mut() {
        if !stored.in_use {
            continue;
        }

        if stored.cred_type != Type {
            continue;
        }

        if !wide_str_equal(&stored.target_name, TargetName) {
            continue;
        }

        stored.in_use = false;
        return 1; // TRUE
    }

    0 // FALSE - not found
}

#[no_mangle]
pub unsafe extern "C" fn CredEnumerateW(
    Filter: PCWSTR,
    Flags: DWORD,
    Count: *mut DWORD,
    Credentials: *mut *mut PCREDENTIALW,
) -> LONG {
    if Count.is_null() || Credentials.is_null() {
        return 0; // FALSE
    }

    let mut count = 0;
    for stored in CREDENTIAL_STORE.iter() {
        if stored.in_use {
            count += 1;
        }
    }

    *Count = count;

    if count == 0 {
        *Credentials = null_mut();
        return 1; // TRUE
    }

    *Count = 0;
    *Credentials = null_mut();

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn CredFree(Buffer: PVOID) {
    // For kernel stub, we use static buffers so nothing to free
}

#[no_mangle]
pub unsafe extern "C" fn CredGetSessionTypes(
    MaximumPersistCount: DWORD,
    MaximumPersist: *mut DWORD,
) -> LONG {
    if MaximumPersist.is_null() {
        return 0; // FALSE
    }

    if MaximumPersistCount >= 1 {
        *MaximumPersist.add(0) = CRED_PERSIST_SESSION;
    }
    if MaximumPersistCount >= 2 {
        *MaximumPersist.add(1) = CRED_PERSIST_LOCAL_MACHINE;
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn CredIsMarshaledCredentialW(
    MarshaledCredential: PCWSTR,
) -> LONG {
    if MarshaledCredential.is_null() {
        return 0; // FALSE
    }

    if *MarshaledCredential == '@' as u16 && *MarshaledCredential.add(1) == '@' as u16 {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

#[no_mangle]
pub unsafe extern "C" fn CredUnmarshalCredentialW(
    MarshaledCredential: PCWSTR,
    CredType: *mut DWORD,
    Credential: *mut PVOID,
) -> LONG {
    if MarshaledCredential.is_null() || CredType.is_null() || Credential.is_null() {
        return 0; // FALSE
    }

    0 // FALSE
}

#[no_mangle]
pub unsafe extern "C" fn CredMarshalCredentialW(
    CredType: DWORD,
    Credential: PVOID,
    MarshaledCredential: *mut PWSTR,
) -> LONG {
    if Credential.is_null() || MarshaledCredential.is_null() {
        return 0; // FALSE
    }

    0 // FALSE
}

#[no_mangle]
pub unsafe extern "C" fn CredGetTargetInfoW(
    TargetName: PCWSTR,
    Flags: DWORD,
    TargetInfo: *mut PVOID,
) -> LONG {
    if TargetName.is_null() || TargetInfo.is_null() {
        return 0; // FALSE
    }

    0 // FALSE
}

#[no_mangle]
pub unsafe extern "C" fn CredRenameW(
    OldTargetName: PCWSTR,
    NewTargetName: PCWSTR,
    Type: DWORD,
    Flags: DWORD,
) -> LONG {
    if OldTargetName.is_null() || NewTargetName.is_null() {
        return 0; // FALSE
    }

    for stored in CREDENTIAL_STORE.iter_mut() {
        if !stored.in_use {
            continue;
        }

        if stored.cred_type != Type {
            continue;
        }

        if !wide_str_equal(&stored.target_name, OldTargetName) {
            continue;
        }

        copy_wide_to_buffer(&mut stored.target_name, NewTargetName);
        return 1; // TRUE
    }

    0 // FALSE - not found
}

#[no_mangle]
pub unsafe extern "C" fn CredFindBestCredentialW(
    TargetName: PCWSTR,
    Type: DWORD,
    Flags: DWORD,
    Credential: *mut PCREDENTIALW,
) -> LONG {
    // For simple implementation, just use CredReadW
    CredReadW(TargetName, Type, Flags, Credential)
}

#[no_mangle]
pub unsafe extern "C" fn CredProtectW(
    fAsSelf: LONG,
    pszCredentials: PWSTR,
    cchCredentials: DWORD,
    pszProtectedCredentials: PWSTR,
    pcchMaxChars: *mut DWORD,
    ProtectionType: *mut DWORD,
) -> LONG {
    if pszCredentials.is_null() || pcchMaxChars.is_null() {
        return 0; // FALSE
    }

    if !pszProtectedCredentials.is_null() {
        let copy_len = core::cmp::min(cchCredentials as usize, *pcchMaxChars as usize);
        for i in 0..copy_len {
            *pszProtectedCredentials.add(i) = *pszCredentials.add(i);
        }
        if copy_len < *pcchMaxChars as usize {
            *pszProtectedCredentials.add(copy_len) = 0;
        }
    }

    *pcchMaxChars = cchCredentials;
    if !ProtectionType.is_null() {
        *ProtectionType = 1; // CredProtected
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn CredUnprotectW(
    fAsSelf: LONG,
    pszProtectedCredentials: PWSTR,
    cchProtectedCredentials: DWORD,
    pszCredentials: PWSTR,
    pcchMaxChars: *mut DWORD,
) -> LONG {
    if pszProtectedCredentials.is_null() || pcchMaxChars.is_null() {
        return 0; // FALSE
    }

    if !pszCredentials.is_null() {
        let copy_len = core::cmp::min(cchProtectedCredentials as usize, *pcchMaxChars as usize);
        for i in 0..copy_len {
            *pszCredentials.add(i) = *pszProtectedCredentials.add(i);
        }
        if copy_len < *pcchMaxChars as usize {
            *pszCredentials.add(copy_len) = 0;
        }
    }

    *pcchMaxChars = cchProtectedCredentials;

    1 // TRUE
}
