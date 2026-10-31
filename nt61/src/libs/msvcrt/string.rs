//! String and Memory Operations
//!
//! Implements string manipulation and memory operations (strcpy, strcmp, memcpy, etc.)

use super::types::*;
use core::ptr;

// for internal use.

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: SizeT) -> *mut c_void {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }
    ptr::copy_nonoverlapping(src as *const u8, dest as *mut u8, n);
    dest
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: SizeT) -> *mut c_void {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }
    ptr::copy(src as *const u8, dest as *mut u8, n);
    dest
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn memset(s: *mut c_void, c: CInt, n: SizeT) -> *mut c_void {
    if s.is_null() || n == 0 {
        return s;
    }
    ptr::write_bytes(s as *mut u8, c as u8, n);
    s
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: SizeT) -> CInt {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let p1 = s1 as *const u8;
    let p2 = s2 as *const u8;

    for i in 0..n {
        let a = *p1.add(i);
        let b = *p2.add(i);
        if a != b {
            return (a as CInt) - (b as CInt);
        }
    }
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memchr(s: *const c_void, c: CInt, n: SizeT) -> *mut c_void {
    if s.is_null() {
        return ptr::null_mut();
    }

    let p = s as *const u8;
    let target = c as u8;

    for i in 0..n {
        if *p.add(i) == target {
            return p.add(i) as *mut c_void;
        }
    }
    ptr::null_mut()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn msvcrt_strlen_c(s: *const CChar) -> SizeT {
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
pub unsafe extern "C" fn msvcrt_strlen(s: *const u8) -> SizeT {
    msvcrt_strlen_c(s.cast::<CChar>())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strcpy(dest: *mut CChar, src: *const CChar) -> *mut CChar {
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
pub unsafe extern "C" fn strncpy(dest: *mut CChar, src: *const CChar, n: SizeT) -> *mut CChar {
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
pub unsafe extern "C" fn strcat(dest: *mut CChar, src: *const CChar) -> *mut CChar {
    if dest.is_null() || src.is_null() {
        return dest;
    }

    let dest_len = msvcrt_strlen_c(dest);
    strcpy(dest.add(dest_len), src);
    dest
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strncat(dest: *mut CChar, src: *const CChar, n: SizeT) -> *mut CChar {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }

    let dest_len = msvcrt_strlen_c(dest);
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
pub unsafe extern "C" fn strcmp(s1: *const CChar, s2: *const CChar) -> CInt {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let mut i = 0;
    loop {
        let c1 = *s1.add(i) as u8;
        let c2 = *s2.add(i) as u8;

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
pub unsafe extern "C" fn strncmp(s1: *const CChar, s2: *const CChar, n: SizeT) -> CInt {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }

    for i in 0..n {
        let c1 = *s1.add(i) as u8;
        let c2 = *s2.add(i) as u8;

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
pub unsafe extern "C" fn strchr(s: *const CChar, c: CInt) -> *mut CChar {
    if s.is_null() {
        return ptr::null_mut();
    }

    let target = c as CChar;
    let mut i = 0;

    loop {
        let ch = *s.add(i);
        if ch == target {
            return s.add(i) as *mut CChar;
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
pub unsafe extern "C" fn strrchr(s: *const CChar, c: CInt) -> *mut CChar {
    if s.is_null() {
        return ptr::null_mut();
    }

    let target = c as CChar;
    let len = msvcrt_strlen_c(s);

    for i in (0..=len).rev() {
        if *s.add(i) == target {
            return s.add(i) as *mut CChar;
        }
    }
    ptr::null_mut()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strstr(haystack: *const CChar, needle: *const CChar) -> *mut CChar {
    if haystack.is_null() || needle.is_null() {
        return ptr::null_mut();
    }

    let needle_len = msvcrt_strlen_c(needle);
    if needle_len == 0 {
        return haystack as *mut CChar;
    }

    let haystack_len = msvcrt_strlen_c(haystack);
    if needle_len > haystack_len {
        return ptr::null_mut();
    }

    for i in 0..=(haystack_len - needle_len) {
        if strncmp(haystack.add(i), needle, needle_len) == 0 {
            return haystack.add(i) as *mut CChar;
        }
    }
    ptr::null_mut()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strdup(s: *const CChar) -> *mut CChar {
    if s.is_null() {
        return ptr::null_mut();
    }

    let len = msvcrt_strlen_c(s);
    let new_str = crate::libs::msvcrt::memory::malloc(len + 1) as *mut CChar;
    if !new_str.is_null() {
        strcpy(new_str, s);
    }
    new_str
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _stricmp(s1: *const CChar, s2: *const CChar) -> CInt {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let mut i = 0;
    loop {
        let c1 = (*s1.add(i) as u8).to_ascii_lowercase();
        let c2 = (*s2.add(i) as u8).to_ascii_lowercase();

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
pub unsafe extern "C" fn _strnicmp(s1: *const CChar, s2: *const CChar, n: SizeT) -> CInt {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }

    for i in 0..n {
        let c1 = (*s1.add(i) as u8).to_ascii_lowercase();
        let c2 = (*s2.add(i) as u8).to_ascii_lowercase();

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
pub unsafe extern "C" fn strcpy_s(dest: *mut CChar, dest_size: SizeT, src: *const CChar) -> ErrnoT {
    if dest.is_null() || src.is_null() || dest_size == 0 {
        return EINVAL;
    }

    let src_len = msvcrt_strlen_c(src);
    if src_len >= dest_size {
        *dest = 0;
        return ERANGE;
    }

    strcpy(dest, src);
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strcat_s(dest: *mut CChar, dest_size: SizeT, src: *const CChar) -> ErrnoT {
    if dest.is_null() || src.is_null() || dest_size == 0 {
        return EINVAL;
    }

    let dest_len = msvcrt_strlen_c(dest);
    let src_len = msvcrt_strlen_c(src);

    if dest_len + src_len >= dest_size {
        return ERANGE;
    }

    strcat(dest, src);
    0
}

#[cfg(test)]
mod tests {
    use super::memmove;
    use core::ffi::c_void;

    #[test]
    fn memmove_copies_overlapping_ranges_forward() {
        let mut bytes = *b"0123456789";

        unsafe {
            memmove(
                bytes.as_mut_ptr().add(2) as *mut c_void,
                bytes.as_ptr() as *const c_void,
                8,
            );
        }

        assert_eq!(&bytes, b"0101234567");
    }

    #[test]
    fn memmove_copies_overlapping_ranges_backward() {
        let mut bytes = *b"0123456789";

        unsafe {
            memmove(
                bytes.as_mut_ptr() as *mut c_void,
                bytes.as_ptr().add(2) as *const c_void,
                8,
            );
        }

        assert_eq!(&bytes, b"2345678989");
    }
}
