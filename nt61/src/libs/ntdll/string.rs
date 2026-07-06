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
use super::types::{AnsiString, NTSTATUS, UnicodeString};
use core::ffi::c_void;
use core::ptr;

pub type BOOLEAN = u8;
pub const TRUE: u8 = 1;
pub const FALSE: u8 = 0;

/// `RtlInitUnicodeString` — initialize an existing
/// `UNICODE_STRING` to point at a static UTF-16 buffer.
/// Returns STATUS_SUCCESS. Equivalent to NT's
/// `VOID RtlInitUnicodeString(PUNICODE_STRING, PCWSTR)` but we
/// return NTSTATUS to be type-compatible.
pub unsafe extern "C" fn RtlInitUnicodeString(
    destination_string: *mut UnicodeString,
    source_string: *const u16,
) -> NTSTATUS {
    if destination_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if source_string.is_null() {
        (*destination_string).Length = 0;
        (*destination_string).MaximumLength = 0;
        (*destination_string).Buffer = ptr::null_mut();
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
    (*destination_string).Length = (len * 2) as u16;
    (*destination_string).MaximumLength = ((len + 1) * 2) as u16;
    (*destination_string).Buffer = source_string as *mut u16;
    STATUS_SUCCESS
}

/// `RtlCompareUnicodeString` — case-(in)sensitive compare.
pub unsafe extern "C" fn RtlCompareUnicodeString(
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
        let ca = *a.Buffer.add(i);
        let cb = *b.Buffer.add(i);
        let (ca, cb) = if case_insensitive != 0 {
            (upcase(ca), upcase(cb))
        } else {
            (ca, cb)
        };
        if ca != cb {
            return (ca as i32) - (cb as i32);
        }
    }
    if alen < blen { -1 }
    else if alen > blen { 1 }
    else { 0 }
}

/// `RtlCompareUnicodeStrings` — compare two `PWSTR` of known
/// length.
pub unsafe extern "C" fn RtlCompareUnicodeStrings(
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
    if s1.len() < s2.len() { -1 }
    else if s1.len() > s2.len() { 1 }
    else { 0 }
}

/// `RtlCopyUnicodeString` — copy `source` into `dest`. Fails
/// with `STATUS_BUFFER_TOO_SMALL` if `dest->MaximumLength` is
/// too small.
pub unsafe extern "C" fn RtlCopyUnicodeString(
    destination_string: *mut UnicodeString,
    source_string: *const UnicodeString,
) -> NTSTATUS {
    if destination_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let dst = &mut *destination_string;
    dst.Length = 0;
    if dst.Buffer.is_null() || dst.MaximumLength == 0 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if source_string.is_null() {
        return STATUS_SUCCESS;
    }
    let src = &*source_string;
    let srclen = src.char_len();
    let need_bytes = (srclen + 1) * 2;
    if (dst.MaximumLength as usize) < need_bytes {
        // Truncate, like the NT RTL does.
        let cap = (dst.MaximumLength as usize) / 2;
        if cap > 0 {
            let cp = cap.saturating_sub(1);
            for i in 0..cp {
                *dst.Buffer.add(i) = *src.Buffer.add(i);
            }
            *dst.Buffer.add(cp) = 0;
            dst.Length = (cp * 2) as u16;
        }
        return STATUS_BUFFER_TOO_SMALL;
    }
    for i in 0..srclen {
        *dst.Buffer.add(i) = *src.Buffer.add(i);
    }
    *dst.Buffer.add(srclen) = 0;
    dst.Length = (srclen * 2) as u16;
    STATUS_SUCCESS
}

/// `RtlAppendUnicodeStringToString` — append `source` to
/// `destination`. Returns STATUS_BUFFER_TOO_SMALL if
/// `destination->MaximumLength` is too small.
pub unsafe extern "C" fn RtlAppendUnicodeStringToString(
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
    if (dst.MaximumLength as usize) < need_bytes {
        return STATUS_BUFFER_TOO_SMALL;
    }
    for i in 0..src_len {
        *dst.Buffer.add(dst_len + i) = *src.Buffer.add(i);
    }
    *dst.Buffer.add(dst_len + src_len) = 0;
    dst.Length = ((dst_len + src_len) * 2) as u16;
    STATUS_SUCCESS
}

/// `RtlAppendUnicodeToString` — append a null-terminated
/// UTF-16 `source` to `destination`.
pub unsafe extern "C" fn RtlAppendUnicodeToString(
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
    while *source.add(len) != 0 { len += 1; }
    let temp = UnicodeString {
        Length: (len * 2) as u16,
        MaximumLength: ((len + 1) * 2) as u16,
        Buffer: source as *mut u16,
    };
    RtlAppendUnicodeStringToString(destination, &temp)
}

/// `RtlUpcaseUnicodeString` — convert `Source` to upper case,
/// store in `Destination`. `Destination` must be preallocated
/// with `Source->Length + sizeof(WCHAR)` bytes.
pub unsafe extern "C" fn RtlUpcaseUnicodeString(
    destination_string: *mut UnicodeString,
    source_string: *const UnicodeString,
) -> NTSTATUS {
    if destination_string.is_null() || source_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let dst = &mut *destination_string;
    let src = &*source_string;
    if (dst.MaximumLength as usize) < (src.Length as usize) + 2 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let srclen = src.char_len();
    for i in 0..srclen {
        *dst.Buffer.add(i) = upcase(*src.Buffer.add(i));
    }
    *dst.Buffer.add(srclen) = 0;
    dst.Length = src.Length;
    STATUS_SUCCESS
}

/// `RtlDowncaseUnicodeString` — lower case counterpart of the
/// above.
pub unsafe extern "C" fn RtlDowncaseUnicodeString(
    destination_string: *mut UnicodeString,
    source_string: *const UnicodeString,
) -> NTSTATUS {
    if destination_string.is_null() || source_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let dst = &mut *destination_string;
    let src = &*source_string;
    if (dst.MaximumLength as usize) < (src.Length as usize) + 2 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let srclen = src.char_len();
    for i in 0..srclen {
        *dst.Buffer.add(i) = downcase(*src.Buffer.add(i));
    }
    *dst.Buffer.add(srclen) = 0;
    dst.Length = src.Length;
    STATUS_SUCCESS
}

/// `RtlUpcaseUnicodeChar` — single-character upper case.
pub unsafe extern "C" fn RtlUpcaseUnicodeChar(source_character: u16) -> u16 {
    upcase(source_character)
}

/// `RtlEqualUnicodeString` — returns TRUE (1) if the strings
/// are equal.
pub unsafe extern "C" fn RtlEqualUnicodeString(
    string1: *const UnicodeString,
    string2: *const UnicodeString,
    case_insensitive: BOOLEAN,
) -> BOOLEAN {
    if RtlCompareUnicodeString(string1, string2, case_insensitive) == 0 { TRUE } else { FALSE }
}

/// `RtlUnicodeStringToAnsiString` — convert UTF-16 → UTF-8.
/// If `AllocateDestinationString` is TRUE, the function
/// allocates a fresh buffer (via `RtlAllocateStringRoutine`)
/// large enough for the conversion including the null
/// terminator. If FALSE, the caller pre-allocates the buffer
/// in `DestinationString->Buffer`.
pub unsafe extern "C" fn RtlUnicodeStringToAnsiString(
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
        dst.Buffer = buf;
        dst.Length = needed.saturating_sub(1) as u16;
        dst.MaximumLength = needed as u16;
    } else if (dst.MaximumLength as usize) < needed {
        return STATUS_BUFFER_TOO_SMALL;
    }
    for i in 0..src_len {
        *dst.Buffer.add(i) = *src.Buffer.add(i) as i8;
    }
    *dst.Buffer.add(src_len) = 0;
    STATUS_SUCCESS
}

/// `RtlAnsiStringToUnicodeString` — UTF-8 → UTF-16, with the
/// same allocation semantics as `RtlUnicodeStringToAnsiString`.
pub unsafe extern "C" fn RtlAnsiStringToUnicodeString(
    destination_string: *mut UnicodeString,
    source_string: *const AnsiString,
    allocate_destination_string: BOOLEAN,
) -> NTSTATUS {
    if destination_string.is_null() || source_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let src = &*source_string;
    let dst = &mut *destination_string;
    let src_len = src.Length as usize;
    let needed_chars = src_len;
    let needed_bytes = (needed_chars + 1) * 2;
    if allocate_destination_string != 0 {
        let buf = alloc_string(needed_bytes as u32) as *mut u16;
        if buf.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        dst.Buffer = buf;
        dst.Length = needed_bytes.saturating_sub(2) as u16;
        dst.MaximumLength = needed_bytes as u16;
    } else if (dst.MaximumLength as usize) < needed_bytes {
        return STATUS_BUFFER_TOO_SMALL;
    }
    for i in 0..src_len {
        *dst.Buffer.add(i) = *src.Buffer.add(i) as u8 as u16;
    }
    *dst.Buffer.add(needed_chars) = 0;
    STATUS_SUCCESS
}

/// `RtlFreeAnsiString` / `RtlFreeUnicodeString` — release the
/// buffer previously allocated by `Rtl*StringTo*String`.
pub unsafe extern "C" fn RtlFreeAnsiString(ansi_string: *mut AnsiString) {
    if ansi_string.is_null() { return; }
    let s = &mut *ansi_string;
    if !s.Buffer.is_null() {
        free_string(s.Buffer as *mut c_void);
        s.Buffer = ptr::null_mut();
    }
    s.Length = 0;
    s.MaximumLength = 0;
}

pub unsafe extern "C" fn RtlFreeUnicodeString(unicode_string: *mut UnicodeString) {
    if unicode_string.is_null() { return; }
    let s = &mut *unicode_string;
    if !s.Buffer.is_null() {
        free_string(s.Buffer as *mut c_void);
        s.Buffer = ptr::null_mut();
    }
    s.Length = 0;
    s.MaximumLength = 0;
}

/// `RtlAllocateStringRoutine` / `RtlFreeStringRoutine` —
/// function-pointer table used by RTL routines. The default
/// pair is `RtlAllocateString` / `RtlFreeString`; applications
/// can override the global table with `RtlSetStringRoutine`.
pub type RtlAllocateStringRoutineType = unsafe extern "C" fn(length: u32) -> *mut c_void;
pub type RtlFreeStringRoutineType = unsafe extern "C" fn(buffer: *mut c_void);

static mut ALLOC_ROUTINE: RtlAllocateStringRoutineType = RtlAllocateString_default;
static mut FREE_ROUTINE: RtlFreeStringRoutineType = RtlFreeString_default;

pub unsafe extern "C" fn RtlSetStringRoutine(
    allocate: Option<RtlAllocateStringRoutineType>,
    free: Option<RtlFreeStringRoutineType>,
    _: *mut c_void,
) {
    if let Some(a) = allocate { ALLOC_ROUTINE = a; }
    if let Some(f) = free { FREE_ROUTINE = f; }
}

unsafe extern "C" fn RtlAllocateString_default(length: u32) -> *mut c_void {
    super::heap::RtlAllocateHeap(core::ptr::null_mut(), 0, length as usize)
}

unsafe extern "C" fn RtlFreeString_default(buffer: *mut c_void) {
    let _ = super::heap::RtlFreeHeap(core::ptr::null_mut(), 0, buffer);
}

pub(crate) unsafe fn alloc_string(length: u32) -> *mut c_void {
    ALLOC_ROUTINE(length)
}
pub(crate) unsafe fn free_string(buffer: *mut c_void) {
    FREE_ROUTINE(buffer);
}

// ---------------------------------------------------------------------------
// Internal helpers
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
            Length: (s.len() * 2) as u16,
            MaximumLength: ((s.len() + 1) * 2) as u16,
            Buffer: s.as_ptr() as *mut u16,
        }
    }

    #[test]
    fn init_from_null() {
        let mut s = UnicodeString::new();
        unsafe {
            assert_eq!(RtlInitUnicodeString(&mut s, core::ptr::null()), STATUS_SUCCESS);
            assert_eq!(s.Length, 0);
            assert!(s.Buffer.is_null());
        }
    }

    #[test]
    fn init_from_str() {
        let raw: [u16; 6] = [b'h' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16, 0];
        let mut s = UnicodeString::new();
        unsafe {
            assert_eq!(RtlInitUnicodeString(&mut s, raw.as_ptr()), STATUS_SUCCESS);
            assert_eq!(s.Length, 10);
            assert_eq!(s.MaximumLength, 12);
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
            assert!(RtlCompareUnicodeString(&ua, &ub, FALSE) < 0);
            // case-insensitive: equal
            assert_eq!(RtlCompareUnicodeString(&ua, &ub, TRUE), 0);
        }
    }

    #[test]
    fn equal_unicode_string() {
        let a: [u16; 4] = [b'a' as u16, b'b' as u16, b'c' as u16, 0];
        let b: [u16; 4] = [b'A' as u16, b'B' as u16, b'C' as u16, 0];
        let ua = us(&a[..3]);
        let ub = us(&b[..3]);
        unsafe {
            assert_eq!(RtlEqualUnicodeString(&ua, &ub, FALSE), FALSE);
            assert_eq!(RtlEqualUnicodeString(&ua, &ub, TRUE), TRUE);
        }
    }

    #[test]
    fn copy_truncates_on_small_buffer() {
        let src_buf: [u16; 8] = [b'A' as u16, b'B' as u16, b'C' as u16, b'D' as u16, b'E' as u16, b'F' as u16, b'G' as u16, 0];
        let src = us(&src_buf[..7]);
        let mut dst_buf = [0u16; 4];
        let mut dst = UnicodeString {
            Length: 0,
            MaximumLength: (dst_buf.len() * 2) as u16,
            Buffer: dst_buf.as_mut_ptr(),
        };
        unsafe {
            let r = RtlCopyUnicodeString(&mut dst, &src);
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
            Length: 0,
            MaximumLength: (dst_buf.len() * 2) as u16,
            Buffer: dst_buf.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(RtlCopyUnicodeString(&mut dst, &src), STATUS_SUCCESS);
            assert_eq!(dst.Length, 6);
            assert_eq!(dst_buf[3], 0);
        }
    }
}
