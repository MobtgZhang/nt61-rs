//! Wide Character Support
//!
//! Implements wide character string operations (wcslen, wcscpy, mbstowcs, etc.)

use super::types::*;
use super::string::*;
use core::ptr;

#[inline]
fn to_lower_wchar(c: wchar_t) -> wchar_t {
    if c >= 'A' as wchar_t && c <= 'Z' as wchar_t {
        c + ('a' as wchar_t - 'A' as wchar_t)
    } else {
        c
    }
}


#[no_mangle]
pub unsafe extern "C" fn wcslen(s: *const wchar_t) -> size_t {
    if s.is_null() {
        return 0;
    }

    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}


#[no_mangle]
pub unsafe extern "C" fn wcscpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
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

#[no_mangle]
pub unsafe extern "C" fn wcsncpy(
    dest: *mut wchar_t,
    src: *const wchar_t,
    n: size_t,
) -> *mut wchar_t {
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


#[no_mangle]
pub unsafe extern "C" fn wcscat(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    if dest.is_null() || src.is_null() {
        return dest;
    }

    let dest_len = wcslen(dest);
    wcscpy(dest.add(dest_len), src);
    dest
}

#[no_mangle]
pub unsafe extern "C" fn wcsncat(
    dest: *mut wchar_t,
    src: *const wchar_t,
    n: size_t,
) -> *mut wchar_t {
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


#[no_mangle]
pub unsafe extern "C" fn wcscmp(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let mut i = 0;
    loop {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);

        if c1 != c2 {
            return (c1 as c_int) - (c2 as c_int);
        }

        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcsncmp(s1: *const wchar_t, s2: *const wchar_t, n: size_t) -> c_int {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }

    for i in 0..n {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);

        if c1 != c2 {
            return (c1 as c_int) - (c2 as c_int);
        }

        if c1 == 0 {
            return 0;
        }
    }
    0
}


#[no_mangle]
pub unsafe extern "C" fn wcschr(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    if s.is_null() {
        return ptr::null_mut();
    }

    let mut i = 0;
    loop {
        let ch = *s.add(i);
        if ch == c {
            return s.add(i) as *mut wchar_t;
        }
        if ch == 0 {
            break;
        }
        i += 1;
    }
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn wcsrchr(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    if s.is_null() {
        return ptr::null_mut();
    }

    let len = wcslen(s);
    for i in (0..=len).rev() {
        if *s.add(i) == c {
            return s.add(i) as *mut wchar_t;
        }
    }
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn wcsstr(haystack: *const wchar_t, needle: *const wchar_t) -> *mut wchar_t {
    if haystack.is_null() || needle.is_null() {
        return ptr::null_mut();
    }

    let needle_len = wcslen(needle);
    if needle_len == 0 {
        return haystack as *mut wchar_t;
    }

    let haystack_len = wcslen(haystack);
    if needle_len > haystack_len {
        return ptr::null_mut();
    }

    for i in 0..=(haystack_len - needle_len) {
        if wcsncmp(haystack.add(i), needle, needle_len) == 0 {
            return haystack.add(i) as *mut wchar_t;
        }
    }
    ptr::null_mut()
}


#[no_mangle]
pub unsafe extern "C" fn wcsdup(s: *const wchar_t) -> *mut wchar_t {
    if s.is_null() {
        return ptr::null_mut();
    }

    let len = wcslen(s);
    let new_str = crate::libs::msvcrt::memory::malloc((len + 1) * 2) as *mut wchar_t;
    if !new_str.is_null() {
        wcscpy(new_str, s);
    }
    new_str
}


#[no_mangle]
pub unsafe extern "C" fn _wcsicmp(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let mut i = 0;
    loop {
        let c1 = to_lower_wchar(*s1.add(i));
        let c2 = to_lower_wchar(*s2.add(i));

        if c1 != c2 {
            return (c1 as c_int) - (c2 as c_int);
        }

        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn _wcsnicmp(s1: *const wchar_t, s2: *const wchar_t, n: size_t) -> c_int {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }

    for i in 0..n {
        let c1 = to_lower_wchar(*s1.add(i));
        let c2 = to_lower_wchar(*s2.add(i));

        if c1 != c2 {
            return (c1 as c_int) - (c2 as c_int);
        }

        if c1 == 0 {
            return 0;
        }
    }
    0
}


#[no_mangle]
pub unsafe extern "C" fn mbstowcs(
    dest: *mut wchar_t,
    src: *const c_char,
    n: size_t,
) -> size_t {
    if src.is_null() {
        return 0;
    }

    let src_len = strlen(src);
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
            *dest.add(i) = (*src.add(i) as u8) as wchar_t;
        }
        if convert_len < n {
            *dest.add(convert_len) = 0;
        }
    }

    convert_len
}

#[no_mangle]
pub unsafe extern "C" fn wcstombs(
    dest: *mut c_char,
    src: *const wchar_t,
    n: size_t,
) -> size_t {
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
            *dest.add(i) = if wc <= 0xFF { wc as c_char } else { b'?' as c_char };
        }
        if convert_len < n {
            *dest.add(convert_len) = 0;
        }
    }

    convert_len
}


#[no_mangle]
pub unsafe extern "C" fn mbtowc(
    pwc: *mut wchar_t,
    s: *const c_char,
    n: size_t,
) -> c_int {
    if s.is_null() {
        return 0; // Not state-dependent
    }

    if n == 0 {
        return -1;
    }

    let c = *s as u8;
    if !pwc.is_null() {
        *pwc = c as wchar_t;
    }

    if c == 0 {
        0
    } else {
        1
    }
}

#[no_mangle]
pub unsafe extern "C" fn wctomb(s: *mut c_char, wc: wchar_t) -> c_int {
    if s.is_null() {
        return 0; // Not state-dependent
    }

    if wc <= 0xFF {
        *s = wc as c_char;
        1
    } else {
        *s = b'?' as c_char;
        1
    }
}


#[no_mangle]
pub unsafe extern "C" fn wcscpy_s(
    dest: *mut wchar_t,
    dest_size: size_t,
    src: *const wchar_t,
) -> errno_t {
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

#[no_mangle]
pub unsafe extern "C" fn wcscat_s(
    dest: *mut wchar_t,
    dest_size: size_t,
    src: *const wchar_t,
) -> errno_t {
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


#[no_mangle]
pub unsafe extern "C" fn fputwc(wc: wchar_t, stream: *mut FILE) -> wchar_t {
    if stream.is_null() {
        return 0xFFFF; // WEOF
    }

    let c = (wc & 0xFF) as u8;
    if crate::libs::msvcrt::stdio::fputc(c as c_int, stream) == EOF {
        0xFFFF
    } else {
        wc
    }
}

#[no_mangle]
pub unsafe extern "C" fn fgetwc(stream: *mut FILE) -> wchar_t {
    if stream.is_null() {
        return 0xFFFF; // WEOF
    }

    let c = crate::libs::msvcrt::stdio::fgetc(stream);
    if c == EOF {
        0xFFFF
    } else {
        (c as u8) as wchar_t
    }
}

#[no_mangle]
pub unsafe extern "C" fn fputws(ws: *const wchar_t, stream: *mut FILE) -> c_int {
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

#[no_mangle]
pub unsafe extern "C" fn fgetws(ws: *mut wchar_t, n: c_int, stream: *mut FILE) -> *mut wchar_t {
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

        if wc == b'\n' as wchar_t {
            break;
        }
    }

    *ws.add(i) = 0;
    ws
}
