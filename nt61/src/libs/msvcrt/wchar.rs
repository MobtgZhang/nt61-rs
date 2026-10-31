//! Wide Character Support
//!
//! Implements wide character string operations (wcslen, wcscpy, mbstowcs, etc.)

use super::string::*;
use super::types::*;
use core::ptr;

#[inline]
fn to_lower_wchar(c: WcharT) -> WcharT {
    if c >= 'A' as WcharT && c <= 'Z' as WcharT {
        c + ('a' as WcharT - 'A' as WcharT)
    } else {
        c
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcslen(s: *const WcharT) -> SizeT {
    if s.is_null() {
        return 0;
    }

    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcscpy(dest: *mut WcharT, src: *const WcharT) -> *mut WcharT {
    if dest.is_null() || src.is_null() {
        return dest;
    }

    let mut i = 0;
    loop {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            break;
        }
        i += 1;
    }
    dest
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcsncpy(dest: *mut WcharT, src: *const WcharT, n: SizeT) -> *mut WcharT {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }

    let mut i = 0;
    while i < n {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            break;
        }
        i += 1;
    }

    while i < n {
        *dest.add(i) = 0;
        i += 1;
    }
    dest
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcscat(dest: *mut WcharT, src: *const WcharT) -> *mut WcharT {
    if dest.is_null() || src.is_null() {
        return dest;
    }

    let dest_len = wcslen(dest);
    wcscpy(dest.add(dest_len), src);
    dest
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcsncat(dest: *mut WcharT, src: *const WcharT, n: SizeT) -> *mut WcharT {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }

    let dest_len = wcslen(dest);
    let dest_end = dest.add(dest_len);

    let mut i = 0;
    while i < n && *src.add(i) != 0 {
        *dest_end.add(i) = *src.add(i);
        i += 1;
    }
    *dest_end.add(i) = 0;
    dest
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcscmp(s1: *const WcharT, s2: *const WcharT) -> CInt {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let mut i = 0;
    loop {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);

        if c1 != c2 {
            return (c1 as CInt) - (c2 as CInt);
        }

        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcsncmp(s1: *const WcharT, s2: *const WcharT, n: SizeT) -> CInt {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }

    for i in 0..n {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);

        if c1 != c2 {
            return (c1 as CInt) - (c2 as CInt);
        }

        if c1 == 0 {
            return 0;
        }
    }
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcschr(s: *const WcharT, c: WcharT) -> *mut WcharT {
    if s.is_null() {
        return ptr::null_mut();
    }

    let mut i = 0;
    loop {
        let ch = *s.add(i);
        if ch == c {
            return s.add(i) as *mut WcharT;
        }
        if ch == 0 {
            break;
        }
        i += 1;
    }
    ptr::null_mut()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcsrchr(s: *const WcharT, c: WcharT) -> *mut WcharT {
    if s.is_null() {
        return ptr::null_mut();
    }

    let len = wcslen(s);
    for i in (0..=len).rev() {
        if *s.add(i) == c {
            return s.add(i) as *mut WcharT;
        }
    }
    ptr::null_mut()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcsstr(haystack: *const WcharT, needle: *const WcharT) -> *mut WcharT {
    if haystack.is_null() || needle.is_null() {
        return ptr::null_mut();
    }

    let needle_len = wcslen(needle);
    if needle_len == 0 {
        return haystack as *mut WcharT;
    }

    let haystack_len = wcslen(haystack);
    if needle_len > haystack_len {
        return ptr::null_mut();
    }

    for i in 0..=(haystack_len - needle_len) {
        if wcsncmp(haystack.add(i), needle, needle_len) == 0 {
            return haystack.add(i) as *mut WcharT;
        }
    }
    ptr::null_mut()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcsdup(s: *const WcharT) -> *mut WcharT {
    if s.is_null() {
        return ptr::null_mut();
    }

    let len = wcslen(s);
    let new_str = crate::libs::msvcrt::memory::malloc((len + 1) * 2) as *mut WcharT;
    if !new_str.is_null() {
        wcscpy(new_str, s);
    }
    new_str
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _wcsicmp(s1: *const WcharT, s2: *const WcharT) -> CInt {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let mut i = 0;
    loop {
        let c1 = to_lower_wchar(*s1.add(i));
        let c2 = to_lower_wchar(*s2.add(i));

        if c1 != c2 {
            return (c1 as CInt) - (c2 as CInt);
        }

        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _wcsnicmp(s1: *const WcharT, s2: *const WcharT, n: SizeT) -> CInt {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }

    for i in 0..n {
        let c1 = to_lower_wchar(*s1.add(i));
        let c2 = to_lower_wchar(*s2.add(i));

        if c1 != c2 {
            return (c1 as CInt) - (c2 as CInt);
        }

        if c1 == 0 {
            return 0;
        }
    }
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn mbstowcs(dest: *mut WcharT, src: *const CChar, n: SizeT) -> SizeT {
    if src.is_null() {
        return 0;
    }

    let src_len = msvcrt_strlen_c(src);
    let convert_len = if dest.is_null() {
        src_len
    } else {
        if n < src_len {
            n
        } else {
            src_len
        }
    };

    if !dest.is_null() {
        for i in 0..convert_len {
            *dest.add(i) = (*src.add(i) as u8) as WcharT;
        }
        if convert_len < n {
            *dest.add(convert_len) = 0;
        }
    }

    convert_len
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcstombs(dest: *mut CChar, src: *const WcharT, n: SizeT) -> SizeT {
    if src.is_null() {
        return 0;
    }

    let src_len = wcslen(src);
    let convert_len = if dest.is_null() {
        src_len
    } else {
        if n < src_len {
            n
        } else {
            src_len
        }
    };

    if !dest.is_null() {
        for i in 0..convert_len {
            let wc = *src.add(i);
            *dest.add(i) = if wc <= 0xFF {
                wc as CChar
            } else {
                b'?' as CChar
            };
        }
        if convert_len < n {
            *dest.add(convert_len) = 0;
        }
    }

    convert_len
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn mbtowc(pwc: *mut WcharT, s: *const CChar, n: SizeT) -> CInt {
    if s.is_null() {
        return 0; // Not state-dependent
    }

    if n == 0 {
        return -1;
    }

    let c = *s as u8;
    if !pwc.is_null() {
        *pwc = c as WcharT;
    }

    if c == 0 {
        0
    } else {
        1
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wctomb(s: *mut CChar, wc: WcharT) -> CInt {
    if s.is_null() {
        return 0; // Not state-dependent
    }

    if wc <= 0xFF {
        *s = wc as CChar;
        1
    } else {
        *s = b'?' as CChar;
        1
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcscpy_s(
    dest: *mut WcharT,
    dest_size: SizeT,
    src: *const WcharT,
) -> ErrnoT {
    if dest.is_null() || src.is_null() || dest_size == 0 {
        return EINVAL;
    }

    let src_len = wcslen(src);
    if src_len >= dest_size {
        *dest = 0;
        return ERANGE;
    }

    wcscpy(dest, src);
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn wcscat_s(
    dest: *mut WcharT,
    dest_size: SizeT,
    src: *const WcharT,
) -> ErrnoT {
    if dest.is_null() || src.is_null() || dest_size == 0 {
        return EINVAL;
    }

    let dest_len = wcslen(dest);
    let src_len = wcslen(src);

    if dest_len + src_len >= dest_size {
        return ERANGE;
    }

    wcscat(dest, src);
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fputwc(wc: WcharT, stream: *mut FILE) -> WcharT {
    if stream.is_null() {
        return 0xFFFF; // WEOF
    }

    let c = (wc & 0xFF) as u8;
    if crate::libs::msvcrt::stdio::fputc(c as CInt, stream) == EOF {
        0xFFFF
    } else {
        wc
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fgetwc(stream: *mut FILE) -> WcharT {
    if stream.is_null() {
        return 0xFFFF; // WEOF
    }

    let c = crate::libs::msvcrt::stdio::fgetc(stream);
    if c == EOF {
        0xFFFF
    } else {
        (c as u8) as WcharT
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fputws(ws: *const WcharT, stream: *mut FILE) -> CInt {
    if ws.is_null() || stream.is_null() {
        return EOF;
    }

    let len = wcslen(ws);
    for i in 0..len {
        if fputwc(*ws.add(i), stream) == 0xFFFF {
            return EOF;
        }
    }
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fgetws(ws: *mut WcharT, n: CInt, stream: *mut FILE) -> *mut WcharT {
    if ws.is_null() || stream.is_null() || n <= 0 {
        return ptr::null_mut();
    }

    let mut i: usize = 0;
    while i < (n - 1) as usize {
        let wc = fgetwc(stream);
        if wc == 0xFFFF {
            if i == 0 {
                return ptr::null_mut();
            }
            break;
        }

        *ws.add(i) = wc;
        i += 1;

        if wc == b'\n' as WcharT {
            break;
        }
    }

    *ws.add(i) = 0;
    ws
}
