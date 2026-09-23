//! ntdll — RTL prefix and suffix operations
//
//! Additional string manipulation functions: prefix/suffix testing,
//! character operations, and string utilities.

use super::string::BOOLEAN;
use super::types::UnicodeString;

pub unsafe extern "C" fn RtlPrefixUnicodeString(
    string1: *const UnicodeString,
    string2: *const UnicodeString,
    case_insensitive: BOOLEAN,
) -> BOOLEAN {
    if string1.is_null() || string2.is_null() {
        return 0;
    }

    let s1 = &*string1;
    let s2 = &*string2;
    let len1 = s1.char_len();
    let len2 = s2.char_len();

    if len1 > len2 {
        return 0;
    }

    for i in 0..len1 {
        let mut c1 = *s1.Buffer.add(i);
        let mut c2 = *s2.Buffer.add(i);

        if case_insensitive != 0 {
            if c1 >= b'a' as u16 && c1 <= b'z' as u16 {
                c1 -= 0x20;
            }
            if c2 >= b'a' as u16 && c2 <= b'z' as u16 {
                c2 -= 0x20;
            }
        }

        if c1 != c2 {
            return 0;
        }
    }

    1
}

pub unsafe extern "C" fn RtlSuffixUnicodeString(
    string1: *const UnicodeString,
    string2: *const UnicodeString,
    case_insensitive: BOOLEAN,
) -> BOOLEAN {
    if string1.is_null() || string2.is_null() {
        return 0;
    }

    let s1 = &*string1;
    let s2 = &*string2;
    let len1 = s1.char_len();
    let len2 = s2.char_len();

    if len1 > len2 {
        return 0;
    }

    let offset = len2 - len1;

    for i in 0..len1 {
        let mut c1 = *s1.Buffer.add(i);
        let mut c2 = *s2.Buffer.add(offset + i);

        if case_insensitive != 0 {
            if c1 >= b'a' as u16 && c1 <= b'z' as u16 {
                c1 -= 0x20;
            }
            if c2 >= b'a' as u16 && c2 <= b'z' as u16 {
                c2 -= 0x20;
            }
        }

        if c1 != c2 {
            return 0;
        }
    }

    1
}

pub unsafe extern "C" fn RtlFindCharInUnicodeString(
    flags: u32,
    string_to_search: *const UnicodeString,
    char_set: *const UnicodeString,
    non_inclusive_index: *mut u16,
) -> i32 {
    use super::status::{STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND, STATUS_SUCCESS};

    if string_to_search.is_null() || char_set.is_null() || non_inclusive_index.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let search = &*string_to_search;
    let chars = &*char_set;

    let search_len = search.char_len();
    let chars_len = chars.char_len();

    if search_len == 0 || chars_len == 0 {
        return STATUS_NOT_FOUND;
    }

    let find_first = (flags & 0x01) != 0;

    if find_first {
        for i in 0..search_len {
            let sc = *search.Buffer.add(i);
            for j in 0..chars_len {
                if sc == *chars.Buffer.add(j) {
                    *non_inclusive_index = (i * 2) as u16;
                    return STATUS_SUCCESS;
                }
            }
        }
    } else {
        for i in (0..search_len).rev() {
            let sc = *search.Buffer.add(i);
            for j in 0..chars_len {
                if sc == *chars.Buffer.add(j) {
                    *non_inclusive_index = (i * 2) as u16;
                    return STATUS_SUCCESS;
                }
            }
        }
    }

    STATUS_NOT_FOUND
}

pub unsafe extern "C" fn RtlIsTextUnicode(
    buffer: *const u8,
    size: u32,
    result: *mut u32,
) -> BOOLEAN {
    if buffer.is_null() || size < 2 {
        return 0;
    }

    let slice = core::slice::from_raw_parts(buffer, size as usize);
    let mut score = 0i32;

    if size >= 2 {
        if slice[0] == 0xFF && slice[1] == 0xFE {
            score += 10;
        } else if slice[0] == 0xFE && slice[1] == 0xFF {
            score += 10;
        }
    }

    let mut even_nulls = 0;
    let mut odd_nulls = 0;

    for i in (0..size as usize).step_by(2) {
        if i + 1 < size as usize {
            if slice[i] == 0 {
                even_nulls += 1;
            }
            if slice[i + 1] == 0 {
                odd_nulls += 1;
            }
        }
    }

    if odd_nulls > even_nulls && odd_nulls > (size as usize / 4) {
        score += 5;
    }

    if !result.is_null() {
        *result = if score > 5 { 1 } else { 0 };
    }

    if score > 5 { 1 } else { 0 }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub unsafe extern "C" fn RtlGUIDFromString(
    guid_string: *const UnicodeString,
    guid: *mut Guid,
) -> i32 {
    use super::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

    if guid_string.is_null() || guid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    *guid = Guid::default();

    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlStringFromGUID(
    guid: *const Guid,
    guid_string: *mut UnicodeString,
) -> i32 {

    if guid.is_null() || guid_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let s = &mut *guid_string;
    if !s.Buffer.is_null() && s.MaximumLength >= 2 {
        *s.Buffer = 0;
        s.Length = 0;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlCharToInteger(
    string: *const i8,
    base: u32,
    value: *mut u32,
) -> i32 {

    if string.is_null() || value.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let ch = *string as u8;
    let digit = if ch >= b'0' && ch <= b'9' {
        ch - b'0'
    } else if ch >= b'A' && ch <= b'Z' {
        ch - b'A' + 10
    } else if ch >= b'a' && ch <= b'z' {
        ch - b'a' + 10
    } else {
        0
    };

    let actual_base = if base == 0 { 10 } else { base };
    *value = if (digit as u32) < actual_base {
        digit as u32
    } else {
        0
    };

    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlUpperChar(character: i8) -> i8 {
    let ch = character as u8;
    if ch >= b'a' && ch <= b'z' {
        (ch - 0x20) as i8
    } else {
        character
    }
}

pub unsafe extern "C" fn RtlLowerChar(character: i8) -> i8 {
    let ch = character as u8;
    if ch >= b'A' && ch <= b'Z' {
        (ch + 0x20) as i8
    } else {
        character
    }
}
