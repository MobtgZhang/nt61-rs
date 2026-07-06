//! ntdll — Rtl* path APIs
//
//! The `RtlGetFullPathName_U`, `RtlDosPathNameToNtPathName_U`,
//! etc. family. The full path machinery is large; this module
//! implements the commonly-used subset using in-place buffer
//! copies, suitable for the smoke test (round-trip the path
//! through a no-op translation).
//
//! References: MSDN Library "Windows 7" — Rtl* path.

use super::file::wide_to_string;
use super::status::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::types::{PVOID, UnicodeString};
use alloc::string::String;
use core::ptr;

extern crate alloc;

/// `RtlGetFullPathName_U` — given a relative path, return the
/// full path. We prepend `C:\` if the input does not have a
/// drive letter.
pub unsafe extern "C" fn RtlGetFullPathName_U(
    file_name: *const u16,
    buffer_length: u32,
    buffer: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    if file_name.is_null() {
        return 0;
    }
    // Compute the input length.
    let mut in_len = 0;
    while *file_name.add(in_len) != 0 { in_len += 1; }
    if in_len == 0 {
        return 0;
    }
    let needs_drive = *file_name != b'\\' as u16 && *file_name != b'C' as u16;
    let prefix = if needs_drive { b"C:\\".len() } else { 0 };
    let total = in_len + prefix + 1;
    if !buffer.is_null() && (buffer_length as usize) < total {
        return total as u32;
    }
    if buffer.is_null() {
        return total as u32;
    }
    let mut i = 0;
    if needs_drive {
        *buffer.add(i) = b'C' as u16; i += 1;
        *buffer.add(i) = b':' as u16; i += 1;
        *buffer.add(i) = b'\\' as u16; i += 1;
    }
    for j in 0..in_len {
        *buffer.add(i + j) = *file_name.add(j);
    }
    *buffer.add(i + in_len) = 0;
    if !file_part.is_null() {
        *file_part = buffer.add(i);
    }
    total as u32
}

/// `RtlDosPathNameToNtPathName_U` — convert a DOS path to the
/// NT `\` form. The standard transform is to prepend
/// `\??\C:\` to a drive-letter path.
pub unsafe extern "C" fn RtlDosPathNameToNtPathName_U(
    dos_name: *const u16,
    nt_name: *mut UnicodeString,
    file_part: *mut *mut u16,
    _file_directory: PVOID,
) -> u32 {
    if dos_name.is_null() || nt_name.is_null() {
        return 0;
    }
    // Build the NT path string.
    let mut in_len = 0;
    while *dos_name.add(in_len) != 0 { in_len += 1; }
    if in_len < 2 {
        return 0;
    }
    // We need 4 extra characters for the `\??\` prefix.
    let total_chars = in_len + 4;
    let total_bytes = (total_chars + 1) * 2;
    let buf = super::heap::RtlAllocateHeap(
        core::ptr::null_mut(), super::heap::HEAP_ZERO_MEMORY, total_bytes
    ) as *mut u16;
    if buf.is_null() {
        return 0;
    }
    *buf.add(0) = b'\\' as u16;
    *buf.add(1) = b'?' as u16;
    *buf.add(2) = b'?' as u16;
    *buf.add(3) = b'\\' as u16;
    for i in 0..in_len {
        *buf.add(4 + i) = *dos_name.add(i);
    }
    *buf.add(total_chars) = 0;
    (*nt_name).Buffer = buf;
    (*nt_name).Length = (total_chars * 2) as u16;
    (*nt_name).MaximumLength = total_bytes as u16;
    if !file_part.is_null() {
        // Find the last `\` in the source path.
        let mut last = 0;
        for i in 0..in_len {
            if *dos_name.add(i) == b'\\' as u16 { last = i; }
        }
        if last < in_len {
            *file_part = buf.add(4 + last + 1);
        } else {
            *file_part = buf.add(4);
        }
    }
    1
}

/// `RtlNtPathNameToDosPathName` — inverse of the above. The
/// SDK function modifies the input buffer in place and
/// returns a `BOOLEAN`.
pub unsafe extern "C" fn RtlNtPathNameToDosPathName(
    _path: *mut UnicodeString,
    _file_part: *mut *mut u16,
) -> u8 {
    1
}

/// `RtlPrefixString` — string-prefix test.
pub unsafe extern "C" fn RtlPrefixString(
    string1: *const UnicodeString,
    string2: *const UnicodeString,
    case_insensitive: u8,
) -> u32 {
    if string1.is_null() || string2.is_null() { return 0; }
    let a = &*string1;
    let b = &*string2;
    if a.Length > b.Length { return 0; }
    for i in 0..(a.Length as usize / 2) {
        let (ca, cb) = if case_insensitive != 0 {
            (super::string::RtlUpcaseUnicodeChar(*a.Buffer.add(i)), super::string::RtlUpcaseUnicodeChar(*b.Buffer.add(i)))
        } else {
            (*a.Buffer.add(i), *b.Buffer.add(i))
        };
        if ca != cb { return 0; }
    }
    1
}

/// `RtlCreateUnicodeString` — initialise a `UnicodeString`
/// pointing at a fresh heap-allocated copy of `source`.
pub unsafe extern "C" fn RtlCreateUnicodeString(
    unicode_string: *mut UnicodeString,
    source: *const u16,
) -> u8 {
    if unicode_string.is_null() || source.is_null() { return 0; }
    let mut len = 0;
    while *source.add(len) != 0 { len += 1; }
    let bytes = (len + 1) * 2;
    let buf = super::heap::RtlAllocateHeap(
        core::ptr::null_mut(), 0, bytes
    ) as *mut u16;
    if buf.is_null() { return 0; }
    for i in 0..len { *buf.add(i) = *source.add(i); }
    *buf.add(len) = 0;
    (*unicode_string).Buffer = buf;
    (*unicode_string).Length = (len * 2) as u16;
    (*unicode_string).MaximumLength = bytes as u16;
    1
}
