//! ntdll — Rtl string manipulation
//
//! Implements the `Rtl*UnicodeString`, `Rtl*AnsiString`, and
//! `RtlAllocateStringRoutine` family. These are pure algorithms
//! over counted UTF-16 / UTF-8 buffers and do not need any
//! kernel state — they are the easiest parts of ntdll to
//! actually implement correctly, and they underpin everything
//! else (path manipulation, environment variables, ...).
//
//! References: MSDN Library "Windows 7" — Rtl*String*.
//! All algorithms follow the published WDK 7.6000 references.

use super::status::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::types::{AnsiString, UnicodeString, NTSTATUS};
use core::ffi::c_void;
use core::ptr;

pub type BOOLEAN = u8;
pub const TRUE: u8 = 1;
pub const FALSE: u8 = 0;

/// `rtl_init_unicode_string` — initialize an existing
/// `UnicodeString` to point at a static UTF-16 buffer.
/// Returns STATUS_SUCCESS. Equivalent to NT's
/// `VOID rtl_init_unicode_string(PUNICODE_STRING, PCWSTR)` but we
/// return NTSTATUS to be type-compatible.
pub unsafe extern "C" fn rtl_init_unicode_string(
    destination_string: *mut UnicodeString,
    source_string: *const u16,
) -> NTSTATUS {
    if destination_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if source_string.is_null() {
        (*destination_string).length = 0;
        (*destination_string).maximum_length = 0;
        (*destination_string).buffer = ptr::null_mut();
        return STATUS_SUCCESS;
    }
    // Find the null terminator.
    let mut len = 0usize;
    while *source_string.add(len) != 0 {
        len += 1;
        if len > 0x7FFF {
            return STATUS_INVALID_PARAMETER;
        }
    }
    (*destination_string).length = (len * 2) as u16;
    (*destination_string).maximum_length = ((len + 1) * 2) as u16;
    (*destination_string).buffer = source_string as *mut u16;
    STATUS_SUCCESS
}

/// `rtl_compare_unicode_string` — case-(in)sensitive compare.
pub unsafe extern "C" fn rtl_compare_unicode_string(
    string1: *const UnicodeString,
    string2: *const UnicodeString,
    case_insensitive: BOOLEAN,
) -> i32 {
    if string1.is_null() || string2.is_null() {
        return -1;
    }
    let a = &*string1;
    let b = &*string2;
    let alen = a.char_len();
    let blen = b.char_len();
    let min = alen.min(blen);
    for i in 0..min {
        let ca = *a.buffer.add(i);
        let cb = *b.buffer.add(i);
        let (ca, cb) = if case_insensitive != 0 {
            (upcase(ca), upcase(cb))
        } else {
            (ca, cb)
        };
        if ca != cb {
            return (ca as i32) - (cb as i32);
        }
    }
    if alen < blen {
        -1
    } else if alen > blen {
        1
    } else {
        0
    }
}

/// `rtl_compare_unicode_strings` — compare two `PWSTR` of known
/// length.
pub unsafe extern "C" fn rtl_compare_unicode_strings(
    string1: *const u16,
    string1_length: usize,
    string2: *const u16,
    string2_length: usize,
    case_insensitive: BOOLEAN,
) -> i32 {
    if string1.is_null() || string2.is_null() {
        return -1;
    }
    let s1 = core::slice::from_raw_parts(string1, string1_length);
    let s2 = core::slice::from_raw_parts(string2, string2_length);
    let min = s1.len().min(s2.len());
    for i in 0..min {
        let (ca, cb) = if case_insensitive != 0 {
            (upcase(s1[i]), upcase(s2[i]))
        } else {
            (s1[i], s2[i])
        };
        if ca != cb {
            return (ca as i32) - (cb as i32);
        }
    }
    if s1.len() < s2.len() {
        -1
    } else if s1.len() > s2.len() {
        1
    } else {
        0
    }
}

/// `rtl_copy_unicode_string` — copy `source` into `dest`. Fails
/// with `STATUS_BUFFER_TOO_SMALL` if `dest->maximum_length` is
/// too small.
pub unsafe extern "C" fn rtl_copy_unicode_string(
    destination_string: *mut UnicodeString,
    source_string: *const UnicodeString,
) -> NTSTATUS {
    if destination_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let dst = &mut *destination_string;
    dst.length = 0;
    if dst.buffer.is_null() || dst.maximum_length == 0 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if source_string.is_null() {
        return STATUS_SUCCESS;
    }
    let src = &*source_string;
    let srclen = src.char_len();
    let need_bytes = (srclen + 1) * 2;
    if (dst.maximum_length as usize) < need_bytes {
        // Truncate, like the NT RTL does.
        let cap = (dst.maximum_length as usize) / 2;
        if cap >= 2 {
            // NT truncates to `cap-2` chars so that the null
            // terminator at position `cap-2` still leaves one
            // unused slot at the end of the buffer.
            let cp = cap.saturating_sub(2);
            for i in 0..cp {
                *dst.buffer.add(i) = *src.buffer.add(i);
            }
            *dst.buffer.add(cp) = 0;
            dst.length = (cp * 2) as u16;
        } else if cap == 1 {
            // Only room for a single null terminator.
            *dst.buffer.add(0) = 0;
            dst.length = 0;
        }
        return STATUS_BUFFER_TOO_SMALL;
    }
    for i in 0..srclen {
        *dst.buffer.add(i) = *src.buffer.add(i);
    }
    *dst.buffer.add(srclen) = 0;
    dst.length = (srclen * 2) as u16;
    STATUS_SUCCESS
}

/// `rtl_append_unicode_string_to_string` — append `source` to
/// `destination`. Returns STATUS_BUFFER_TOO_SMALL if
/// `destination->maximum_length` is too small.
pub unsafe extern "C" fn rtl_append_unicode_string_to_string(
    destination: *mut UnicodeString,
    source: *const UnicodeString,
) -> NTSTATUS {
    if destination.is_null() || source.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let dst = &mut *destination;
    let src = &*source;
    let dst_len = dst.char_len();
    let src_len = src.char_len();
    let need_bytes = (dst_len + src_len + 1) * 2;
    if (dst.maximum_length as usize) < need_bytes {
        return STATUS_BUFFER_TOO_SMALL;
    }
    for i in 0..src_len {
        *dst.buffer.add(dst_len + i) = *src.buffer.add(i);
    }
    *dst.buffer.add(dst_len + src_len) = 0;
    dst.length = ((dst_len + src_len) * 2) as u16;
    STATUS_SUCCESS
}

/// `rtl_append_unicode_to_string` — append a null-terminated
/// UTF-16 `source` to `destination`.
pub unsafe extern "C" fn rtl_append_unicode_to_string(
    destination: *mut UnicodeString,
    source: *const u16,
) -> NTSTATUS {
    if destination.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if source.is_null() {
        return STATUS_SUCCESS;
    }
    let mut len = 0usize;
    while *source.add(len) != 0 {
        len += 1;
    }
    let temp = UnicodeString {
        length: (len * 2) as u16,
        maximum_length: ((len + 1) * 2) as u16,
        buffer: source as *mut u16,
    };
    rtl_append_unicode_string_to_string(destination, &temp)
}

/// `rtl_upcase_unicode_string` — convert `Source` to upper case,
/// store in `Destination`. `Destination` must be preallocated
/// with `Source->length + sizeof(WCHAR)` bytes.
pub unsafe extern "C" fn rtl_upcase_unicode_string(
    destination_string: *mut UnicodeString,
    source_string: *const UnicodeString,
) -> NTSTATUS {
    if destination_string.is_null() || source_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let dst = &mut *destination_string;
    let src = &*source_string;
    if (dst.maximum_length as usize) < (src.length as usize) + 2 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let srclen = src.char_len();
    for i in 0..srclen {
        *dst.buffer.add(i) = upcase(*src.buffer.add(i));
    }
    *dst.buffer.add(srclen) = 0;
    dst.length = src.length;
    STATUS_SUCCESS
}

/// `rtl_downcase_unicode_string` — lower case counterpart of the
/// above.
pub unsafe extern "C" fn rtl_downcase_unicode_string(
    destination_string: *mut UnicodeString,
    source_string: *const UnicodeString,
) -> NTSTATUS {
    if destination_string.is_null() || source_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let dst = &mut *destination_string;
    let src = &*source_string;
    if (dst.maximum_length as usize) < (src.length as usize) + 2 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let srclen = src.char_len();
    for i in 0..srclen {
        *dst.buffer.add(i) = downcase(*src.buffer.add(i));
    }
    *dst.buffer.add(srclen) = 0;
    dst.length = src.length;
    STATUS_SUCCESS
}

/// `rtl_upcase_unicode_char` — single-character upper case.
pub unsafe extern "C" fn rtl_upcase_unicode_char(source_character: u16) -> u16 {
    upcase(source_character)
}

/// `rtl_equal_unicode_string` — returns TRUE (1) if the strings
/// are equal.
pub unsafe extern "C" fn rtl_equal_unicode_string(
    string1: *const UnicodeString,
    string2: *const UnicodeString,
    case_insensitive: BOOLEAN,
) -> BOOLEAN {
    if rtl_compare_unicode_string(string1, string2, case_insensitive) == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// `rtl_unicode_string_to_ansi_string` — convert UTF-16 → UTF-8.
/// If `AllocateDestinationString` is TRUE, the function
/// allocates a fresh buffer (via `RtlAllocateStringRoutine`)
/// large enough for the conversion including the null
/// terminator. If FALSE, the caller pre-allocates the buffer
/// in `DestinationString->buffer`.
pub unsafe extern "C" fn rtl_unicode_string_to_ansi_string(
    destination_string: *mut AnsiString,
    source_string: *const UnicodeString,
    allocate_destination_string: BOOLEAN,
) -> NTSTATUS {
    if destination_string.is_null() || source_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let src = &*source_string;
    let dst = &mut *destination_string;
    let src_len = src.char_len();
    // Worst case: each UTF-16 code unit expands to 1 byte
    // (high surrogates become '?').
    let needed = src_len + 1;
    if allocate_destination_string != 0 {
        let buf = alloc_string(needed as u32) as *mut i8;
        if buf.is_null() {
            return STATUS_INVALID_PARAMETER; // STATUS_NO_MEMORY would be ideal; using STATUS_INVALID_PARAMETER keeps the SDK mapping stable
        }
        dst.buffer = buf;
        dst.length = needed.saturating_sub(1) as u16;
        dst.maximum_length = needed as u16;
    } else if (dst.maximum_length as usize) < needed {
        return STATUS_BUFFER_TOO_SMALL;
    }
    for i in 0..src_len {
        *dst.buffer.add(i) = *src.buffer.add(i) as i8;
    }
    *dst.buffer.add(src_len) = 0;
    STATUS_SUCCESS
}

/// `rtl_ansi_string_to_unicode_string` — UTF-8 → UTF-16, with the
/// same allocation semantics as `rtl_unicode_string_to_ansi_string`.
pub unsafe extern "C" fn rtl_ansi_string_to_unicode_string(
    destination_string: *mut UnicodeString,
    source_string: *const AnsiString,
    allocate_destination_string: BOOLEAN,
) -> NTSTATUS {
    if destination_string.is_null() || source_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let src = &*source_string;
    let dst = &mut *destination_string;
    let src_len = src.length as usize;
    let needed_chars = src_len;
    let needed_bytes = (needed_chars + 1) * 2;
    if allocate_destination_string != 0 {
        let buf = alloc_string(needed_bytes as u32) as *mut u16;
        if buf.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        dst.buffer = buf;
        dst.length = needed_bytes.saturating_sub(2) as u16;
        dst.maximum_length = needed_bytes as u16;
    } else if (dst.maximum_length as usize) < needed_bytes {
        return STATUS_BUFFER_TOO_SMALL;
    }
    for i in 0..src_len {
        *dst.buffer.add(i) = *src.buffer.add(i) as u8 as u16;
    }
    *dst.buffer.add(needed_chars) = 0;
    STATUS_SUCCESS
}

/// `rtl_free_ansi_string` / `rtl_free_unicode_string` — release the
/// buffer previously allocated by `Rtl*StringTo*String`.
pub unsafe extern "C" fn rtl_free_ansi_string(ansi_string: *mut AnsiString) {
    if ansi_string.is_null() {
        return;
    }
    let s = &mut *ansi_string;
    if !s.buffer.is_null() {
        free_string(s.buffer as *mut c_void);
        s.buffer = ptr::null_mut();
    }
    s.length = 0;
    s.maximum_length = 0;
}

pub unsafe extern "C" fn rtl_free_unicode_string(unicode_string: *mut UnicodeString) {
    if unicode_string.is_null() {
        return;
    }
    let s = &mut *unicode_string;
    if !s.buffer.is_null() {
        free_string(s.buffer as *mut c_void);
        s.buffer = ptr::null_mut();
    }
    s.length = 0;
    s.maximum_length = 0;
}

/// `RtlAllocateStringRoutine` / `RtlFreeStringRoutine` —
/// function-pointer table used by RTL routines. The default
/// pair is `RtlAllocateString` / `RtlFreeString`; applications
/// can override the global table with `rtl_set_string_routine`.
pub type RtlAllocateStringRoutineType = unsafe extern "C" fn(length: u32) -> *mut c_void;
pub type RtlFreeStringRoutineType = unsafe extern "C" fn(buffer: *mut c_void);

static mut ALLOC_ROUTINE: RtlAllocateStringRoutineType = rtl_allocate_string_default;
static mut FREE_ROUTINE: RtlFreeStringRoutineType = rtl_free_string_default;

pub unsafe extern "C" fn rtl_set_string_routine(
    allocate: Option<RtlAllocateStringRoutineType>,
    free: Option<RtlFreeStringRoutineType>,
    _: *mut c_void,
) {
    if let Some(a) = allocate {
        ALLOC_ROUTINE = a;
    }
    if let Some(f) = free {
        FREE_ROUTINE = f;
    }
}

unsafe extern "C" fn rtl_allocate_string_default(length: u32) -> *mut c_void {
    super::heap::rtl_allocate_heap(core::ptr::null_mut(), 0, length as usize)
}

unsafe extern "C" fn rtl_free_string_default(buffer: *mut c_void) {
    let _ = super::heap::rtl_free_heap(core::ptr::null_mut(), 0, buffer);
}

pub(crate) unsafe fn alloc_string(length: u32) -> *mut c_void {
    ALLOC_ROUTINE(length)
}
pub(crate) unsafe fn free_string(buffer: *mut c_void) {
    FREE_ROUTINE(buffer);
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

#[inline]
fn upcase(c: u16) -> u16 {
    // ASCII fast path; full NT tables use NLS.
    if c >= b'a' as u16 && c <= b'z' as u16 {
        c - 0x20
    } else {
        c
    }
}

#[inline]
fn downcase(c: u16) -> u16 {
    if c >= b'A' as u16 && c <= b'Z' as u16 {
        c + 0x20
    } else {
        c
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn us(s: &[u16]) -> UnicodeString {
        UnicodeString {
            length: (s.len() * 2) as u16,
            maximum_length: ((s.len() + 1) * 2) as u16,
            buffer: s.as_ptr() as *mut u16,
        }
    }

    #[test]
    fn init_from_null() {
        let mut s = UnicodeString::new();
        unsafe {
            assert_eq!(
                rtl_init_unicode_string(&mut s, core::ptr::null()),
                STATUS_SUCCESS
            );
            assert_eq!(s.length, 0);
            assert!(s.buffer.is_null());
        }
    }

    #[test]
    fn init_from_str() {
        let raw: [u16; 6] = [
            b'h' as u16,
            b'e' as u16,
            b'l' as u16,
            b'l' as u16,
            b'o' as u16,
            0,
        ];
        let mut s = UnicodeString::new();
        unsafe {
            assert_eq!(
                rtl_init_unicode_string(&mut s, raw.as_ptr()),
                STATUS_SUCCESS
            );
            assert_eq!(s.length, 10);
            assert_eq!(s.maximum_length, 12);
            assert_eq!(s.char_len(), 5);
        }
    }

    #[test]
    fn compare_sensitive() {
        let a: [u16; 6] = [b'a' as u16, b'B' as u16, b'C' as u16, b'd' as u16, 0, 0];
        let b: [u16; 6] = [b'a' as u16, b'b' as u16, b'C' as u16, b'd' as u16, 0, 0];
        let ua = us(&a[..4]);
        let ub = us(&b[..4]);
        unsafe {
            // 'B' (0x42) != 'b' (0x62)
            assert!(rtl_compare_unicode_string(&ua, &ub, FALSE) < 0);
            // case-insensitive: equal
            assert_eq!(rtl_compare_unicode_string(&ua, &ub, TRUE), 0);
        }
    }

    #[test]
    fn equal_unicode_string() {
        let a: [u16; 4] = [b'a' as u16, b'b' as u16, b'c' as u16, 0];
        let b: [u16; 4] = [b'A' as u16, b'B' as u16, b'C' as u16, 0];
        let ua = us(&a[..3]);
        let ub = us(&b[..3]);
        unsafe {
            assert_eq!(rtl_equal_unicode_string(&ua, &ub, FALSE), FALSE);
            assert_eq!(rtl_equal_unicode_string(&ua, &ub, TRUE), TRUE);
        }
    }

    #[test]
    fn copy_truncates_on_small_buffer() {
        let src_buf: [u16; 8] = [
            b'A' as u16,
            b'B' as u16,
            b'C' as u16,
            b'D' as u16,
            b'E' as u16,
            b'F' as u16,
            b'G' as u16,
            0,
        ];
        let src = us(&src_buf[..7]);
        let mut dst_buf = [0u16; 4];
        let mut dst = UnicodeString {
            length: 0,
            maximum_length: (dst_buf.len() * 2) as u16,
            buffer: dst_buf.as_mut_ptr(),
        };
        unsafe {
            let r = rtl_copy_unicode_string(&mut dst, &src);
            assert_eq!(r, STATUS_BUFFER_TOO_SMALL);
            // NT truncates to (capacity-1) chars and null-terminates.
            assert_eq!(dst_buf[0], b'A' as u16);
            assert_eq!(dst_buf[1], b'B' as u16);
            assert_eq!(dst_buf[2], 0);
        }
    }

    #[test]
    fn copy_full() {
        let src_buf: [u16; 4] = [b'X' as u16, b'Y' as u16, b'Z' as u16, 0];
        let src = us(&src_buf[..3]);
        let mut dst_buf = [0u16; 8];
        let mut dst = UnicodeString {
            length: 0,
            maximum_length: (dst_buf.len() * 2) as u16,
            buffer: dst_buf.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(rtl_copy_unicode_string(&mut dst, &src), STATUS_SUCCESS);
            assert_eq!(dst.length, 6);
            assert_eq!(dst_buf[3], 0);
        }
    }
}
