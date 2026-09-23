//! ntdll — RTL hash and conversion utilities
//
//! Additional RTL utility functions: hash functions, integer conversion,
//! time conversion, and other helpers.
//
//! References: MSDN Library "Windows 7" — RTL utilities.

use super::string::BOOLEAN;
use super::types::{UnicodeString, ULONG};
use core::ptr;

pub unsafe extern "C" fn RtlHashUnicodeString(
    string: *const UnicodeString,
    case_insensitive: BOOLEAN,
    hash_algorithm: u32,
    hash_value: *mut u32,
) -> i32 {
    use super::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

    if string.is_null() || hash_value.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let s = &*string;
    if s.Buffer.is_null() {
        *hash_value = 0;
        return STATUS_SUCCESS;
    }

    let len = s.char_len();
    let mut hash: u32 = match hash_algorithm {
        0 => 0x811C9DC5, // FNV-1a offset basis
        1 => 0,           // Simple additive
        _ => 0x811C9DC5,
    };

    for i in 0..len {
        let mut ch = *s.Buffer.add(i);
        if case_insensitive != 0 && ch >= b'a' as u16 && ch <= b'z' as u16 {
            ch -= 0x20; // Convert to uppercase
        }

        match hash_algorithm {
            0 => {
                hash ^= ch as u32;
                hash = hash.wrapping_mul(0x01000193);
            }
            1 => {
                hash = hash.wrapping_add(ch as u32);
            }
            _ => {
                hash ^= ch as u32;
                hash = hash.wrapping_mul(0x01000193);
            }
        }
    }

    *hash_value = hash;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlIntegerToUnicodeString(
    value: u32,
    base: u32,
    string: *mut UnicodeString,
) -> i32 {
    use super::status::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

    if string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let s = &mut *string;
    if s.Buffer.is_null() || s.MaximumLength < 2 {
        return STATUS_BUFFER_TOO_SMALL;
    }

    let base = if base == 0 || base > 36 { 10 } else { base };
    let mut val = value;
    let mut digits = [0u16; 32];
    let mut count = 0usize;

    if val == 0 {
        digits[0] = b'0' as u16;
        count = 1;
    } else {
        while val > 0 {
            let digit = (val % base) as u8;
            digits[count] = if digit < 10 {
                (b'0' + digit) as u16
            } else {
                (b'A' + digit - 10) as u16
            };
            val /= base;
            count += 1;
        }
    }

    let needed = (count + 1) * 2;
    if (s.MaximumLength as usize) < needed {
        return STATUS_BUFFER_TOO_SMALL;
    }

    for i in 0..count {
        *s.Buffer.add(i) = digits[count - 1 - i];
    }
    *s.Buffer.add(count) = 0;
    s.Length = (count * 2) as u16;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlUnicodeStringToInteger(
    string: *const UnicodeString,
    base: u32,
    value: *mut u32,
) -> i32 {

    if string.is_null() || value.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let s = &*string;
    *value = 0;

    if s.Buffer.is_null() || s.Length == 0 {
        return STATUS_SUCCESS;
    }

    let len = s.char_len();
    let mut idx = 0usize;
    let mut result = 0u32;
    let mut actual_base = base;

    while idx < len && (*s.Buffer.add(idx) == b' ' as u16 || *s.Buffer.add(idx) == b'\t' as u16) {
        idx += 1;
    }

    if idx >= len {
        return STATUS_SUCCESS;
    }

    if actual_base == 0 {
        if idx + 1 < len && *s.Buffer.add(idx) == b'0' as u16 {
            let next = *s.Buffer.add(idx + 1);
            if next == b'x' as u16 || next == b'X' as u16 {
                actual_base = 16;
                idx += 2;
            } else {
                actual_base = 8;
                idx += 1;
            }
        } else {
            actual_base = 10;
        }
    }

    if actual_base < 2 || actual_base > 36 {
        actual_base = 10;
    }

    while idx < len {
        let ch = *s.Buffer.add(idx);
        let digit = if ch >= b'0' as u16 && ch <= b'9' as u16 {
            (ch - b'0' as u16) as u32
        } else if ch >= b'A' as u16 && ch <= b'Z' as u16 {
            (ch - b'A' as u16 + 10) as u32
        } else if ch >= b'a' as u16 && ch <= b'z' as u16 {
            (ch - b'a' as u16 + 10) as u32
        } else {
            break;
        };

        if digit >= actual_base {
            break;
        }

        result = result.wrapping_mul(actual_base).wrapping_add(digit);
        idx += 1;
    }

    *value = result;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlInt64ToUnicodeString(
    value: u64,
    base: u32,
    string: *mut UnicodeString,
) -> i32 {

    if string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let s = &mut *string;
    if s.Buffer.is_null() || s.MaximumLength < 2 {
        return STATUS_BUFFER_TOO_SMALL;
    }

    let base = if base == 0 || base > 36 { 10 } else { base };
    let mut val = value;
    let mut digits = [0u16; 64];
    let mut count = 0usize;

    if val == 0 {
        digits[0] = b'0' as u16;
        count = 1;
    } else {
        while val > 0 {
            let digit = (val % base as u64) as u8;
            digits[count] = if digit < 10 {
                (b'0' + digit) as u16
            } else {
                (b'A' + digit - 10) as u16
            };
            val /= base as u64;
            count += 1;
        }
    }

    let needed = (count + 1) * 2;
    if (s.MaximumLength as usize) < needed {
        return STATUS_BUFFER_TOO_SMALL;
    }

    for i in 0..count {
        *s.Buffer.add(i) = digits[count - 1 - i];
    }
    *s.Buffer.add(count) = 0;
    s.Length = (count * 2) as u16;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlTimeToSecondsSince1970(
    time: *const i64,
    elapsed_seconds: *mut u32,
) -> i32 {

    if time.is_null() || elapsed_seconds.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    const EPOCH_DIFF: i64 = 116444736000000000;

    let ft = *time;
    if ft < EPOCH_DIFF {
        *elapsed_seconds = 0;
    } else {
        *elapsed_seconds = ((ft - EPOCH_DIFF) / 10000000) as u32;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlSecondsSince1970ToTime(
    elapsed_seconds: u32,
    time: *mut i64,
) -> i32 {

    if time.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    const EPOCH_DIFF: i64 = 116444736000000000;
    *time = EPOCH_DIFF + (elapsed_seconds as i64) * 10000000;

    STATUS_SUCCESS
}

#[repr(C)]
pub struct OsVersionInfoW {
    pub size_of_structure: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub service_pack: [u16; 128],
}

pub unsafe extern "C" fn RtlGetVersion(version_info: *mut OsVersionInfoW) -> i32 {

    if version_info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let info = &mut *version_info;
    info.major_version = 6;  // Windows 7
    info.minor_version = 1;
    info.build_number = 7601;
    info.platform_id = 2;    // VER_PLATFORM_WIN32_NT
    info.service_pack[0] = 0;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlGetNtVersionNumbers(
    major: *mut u32,
    minor: *mut u32,
    build: *mut u32,
) {
    if !major.is_null() {
        *major = 6;
    }
    if !minor.is_null() {
        *minor = 1;
    }
    if !build.is_null() {
        *build = 7601;
    }
}
