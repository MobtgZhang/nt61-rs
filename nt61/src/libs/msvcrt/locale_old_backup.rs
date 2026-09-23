use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};


use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use super::types::*;
use core::ptr;

pub const LC_ALL: c_int = 0;
pub const LC_COLLATE: c_int = 1;
pub const LC_CTYPE: c_int = 2;
pub const LC_MONETARY: c_int = 3;
pub const LC_NUMERIC: c_int = 4;
pub const LC_TIME: c_int = 5;

#[repr(C)]
pub struct lconv {
    pub decimal_point: *mut c_char,
    pub thousands_sep: *mut c_char,
    pub grouping: *mut c_char,
    pub int_curr_symbol: *mut c_char,
    pub currency_symbol: *mut c_char,
    pub mon_decimal_point: *mut c_char,
    pub mon_thousands_sep: *mut c_char,
    pub mon_grouping: *mut c_char,
    pub positive_sign: *mut c_char,
    pub negative_sign: *mut c_char,
    pub int_frac_digits: c_char,
    pub frac_digits: c_char,
    pub p_cs_precedes: c_char,
    pub p_sep_by_space: c_char,
    pub n_cs_precedes: c_char,
    pub n_sep_by_space: c_char,
    pub p_sign_posn: c_char,
    pub n_sign_posn: c_char,
}

static CURRENT_LOCALE: Lazy<Mutex<[c_char; 32]>> = Lazy::new(|| Mutex::new([0; 32]));
static mut LOCALE_CONV: lconv = lconv {
    decimal_point: ptr::null_mut(),
    thousands_sep: ptr::null_mut(),
    grouping: ptr::null_mut(),
    int_curr_symbol: ptr::null_mut(),
    currency_symbol: ptr::null_mut(),
    mon_decimal_point: ptr::null_mut(),
    mon_thousands_sep: ptr::null_mut(),
    mon_grouping: ptr::null_mut(),
    positive_sign: ptr::null_mut(),
    negative_sign: ptr::null_mut(),
    int_frac_digits: 127,
    frac_digits: 127,
    p_cs_precedes: 127,
    p_sep_by_space: 127,
    n_cs_precedes: 127,
    n_sep_by_space: 127,
    p_sign_posn: 127,
    n_sign_posn: 127,
};

static DECIMAL_POINT_STR: Lazy<Mutex<[c_char; 2]>> = Lazy::new(|| Mutex::new([b'.' as c_char, 0]));
static THOUSANDS_SEP_STR: Lazy<Mutex<[c_char; 2]>> = Lazy::new(|| Mutex::new([b',' as c_char, 0]));
static EMPTY_STR: Lazy<Mutex<[c_char; 1]>> = Lazy::new(|| Mutex::new([0]));
static CURRENCY_STR: Lazy<Mutex<[c_char; 2]>> = Lazy::new(|| Mutex::new([b'$' as c_char, 0]));
static PLUS_STR: Lazy<Mutex<[c_char; 2]>> = Lazy::new(|| Mutex::new([b'+' as c_char, 0]));
static MINUS_STR: Lazy<Mutex<[c_char; 2]>> = Lazy::new(|| Mutex::new([b'-' as c_char, 0]));

unsafe fn init_c_locale() {
    let c_locale = b"C\0";
    for i in 0..c_locale.len() {
        CURRENT_LOCALE[i] = c_locale[i] as c_char;
    }

    LOCALE_CONV.decimal_point = DECIMAL_POINT_STR.as_mut_ptr();
    LOCALE_CONV.thousands_sep = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.grouping = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.int_curr_symbol = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.currency_symbol = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.mon_decimal_point = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.mon_thousands_sep = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.mon_grouping = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.positive_sign = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.negative_sign = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.int_frac_digits = 127;
    LOCALE_CONV.frac_digits = 127;
    LOCALE_CONV.p_cs_precedes = 127;
    LOCALE_CONV.p_sep_by_space = 127;
    LOCALE_CONV.n_cs_precedes = 127;
    LOCALE_CONV.n_sep_by_space = 127;
    LOCALE_CONV.p_sign_posn = 127;
    LOCALE_CONV.n_sign_posn = 127;
}

unsafe fn init_en_us_locale() {
    let locale_name = b"en_US.UTF-8\0";
    for i in 0..locale_name.len().min(31) {
        CURRENT_LOCALE[i] = locale_name[i] as c_char;
    }

    LOCALE_CONV.decimal_point = DECIMAL_POINT_STR.as_mut_ptr();
    LOCALE_CONV.thousands_sep = THOUSANDS_SEP_STR.as_mut_ptr();
    LOCALE_CONV.grouping = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.int_curr_symbol = b"USD \0".as_ptr() as *mut c_char;
    LOCALE_CONV.currency_symbol = CURRENCY_STR.as_mut_ptr();
    LOCALE_CONV.mon_decimal_point = DECIMAL_POINT_STR.as_mut_ptr();
    LOCALE_CONV.mon_thousands_sep = THOUSANDS_SEP_STR.as_mut_ptr();
    LOCALE_CONV.mon_grouping = EMPTY_STR.as_mut_ptr();
    LOCALE_CONV.positive_sign = PLUS_STR.as_mut_ptr();
    LOCALE_CONV.negative_sign = MINUS_STR.as_mut_ptr();
    LOCALE_CONV.int_frac_digits = 2;
    LOCALE_CONV.frac_digits = 2;
    LOCALE_CONV.p_cs_precedes = 1;
    LOCALE_CONV.p_sep_by_space = 0;
    LOCALE_CONV.n_cs_precedes = 1;
    LOCALE_CONV.n_sep_by_space = 0;
    LOCALE_CONV.p_sign_posn = 1;
    LOCALE_CONV.n_sign_posn = 1;
}

#[no_mangle]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char {
    static INITIALIZED: AtomicBool = AtomicBool::new(false);
    if !INITIALIZED {
        init_c_locale();
        INITIALIZED = true;
    }

    if locale.is_null() {
        return CURRENT_LOCALE.as_mut_ptr();
    }

    if category < LC_ALL || category > LC_TIME {
        return ptr::null_mut();
    }

    let mut i = 0;
    let mut locale_len = 0;
    while *locale.add(i) != 0 && i < 31 {
        locale_len += 1;
        i += 1;
    }

    if locale_len == 1 && *locale == b'C' as c_char {
        init_c_locale();
        return CURRENT_LOCALE.as_mut_ptr();
    }

    // Check for empty string (use environment)
    if locale_len == 0 {
        init_c_locale();
        return CURRENT_LOCALE.as_mut_ptr();
    }

    if locale_len >= 5 {
        let mut is_en_us = true;
        let en_us = b"en_US";
        for i in 0..5 {
            if *locale.add(i) != en_us[i] as c_char {
                is_en_us = false;
                break;
            }
        }

        if is_en_us {
            init_en_us_locale();
            return CURRENT_LOCALE.as_mut_ptr();
        }
    }

    init_c_locale();
    CURRENT_LOCALE.as_mut_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn localeconv() -> *mut lconv {
    static INITIALIZED: AtomicBool = AtomicBool::new(false);
    if !INITIALIZED {
        init_c_locale();
        INITIALIZED = true;
    }

    &mut LOCALE_CONV as *mut lconv
}

#[no_mangle]
pub unsafe extern "C" fn _wsetlocale(category: c_int, locale: *const wchar_t) -> *mut wchar_t {
    if locale.is_null() {
        static WIDE_LOCALE: Lazy<Mutex<[wchar_t; 32]>> = Lazy::new(|| Mutex::new([0; 32]));
        for i in 0..32 {
            if CURRENT_LOCALE[i] == 0 {
                WIDE_LOCALE[i] = 0;
                break;
            }
            WIDE_LOCALE[i] = CURRENT_LOCALE[i] as wchar_t;
        }
        return WIDE_LOCALE.as_mut_ptr();
    }

    let mut narrow_locale = [0 as c_char; 32];
    let mut i = 0;
    while *locale.add(i) != 0 && i < 31 {
        narrow_locale[i] = *locale.add(i) as c_char;
        i += 1;
    }

    let result = setlocale(category, narrow_locale.as_ptr());
    if result.is_null() {
        return ptr::null_mut();
    }

    static WIDE_RESULT: Lazy<Mutex<[wchar_t; 32]>> = Lazy::new(|| Mutex::new([0; 32]));
    i = 0;
    while *result.add(i) != 0 && i < 31 {
        WIDE_RESULT[i] = *result.add(i) as wchar_t;
        i += 1;
    }
    WIDE_RESULT[i] = 0;

    WIDE_RESULT.as_mut_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn strcoll(s1: *const c_char, s2: *const c_char) -> c_int {
    super::string::strcmp(s1, s2)
}

#[no_mangle]
pub unsafe extern "C" fn strxfrm(dest: *mut c_char, src: *const c_char, n: size_t) -> size_t {
    if dest.is_null() || n == 0 {
        return super::string::strlen(src);
    }

    let mut i = 0;
    while i < n - 1 && *src.add(i) != 0 {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    *dest.add(i) = 0;

    super::string::strlen(src)
}

#[no_mangle]
pub unsafe extern "C" fn wcscoll(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    super::wchar::wcscmp(s1, s2)
}

#[no_mangle]
pub unsafe extern "C" fn wcsxfrm(dest: *mut wchar_t, src: *const wchar_t, n: size_t) -> size_t {
    if dest.is_null() || n == 0 {
        return super::wchar::wcslen(src);
    }

    let mut i = 0;
    while i < n - 1 && *src.add(i) != 0 {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    *dest.add(i) = 0;

    super::wchar::wcslen(src)
}

/// Locale-aware character classification (uses current locale)
#[no_mangle]
pub unsafe extern "C" fn _isctype(c: c_int, mask: c_int) -> c_int {
    let ch = c as u8;

    const _UPPER: c_int = 0x01;
    const _LOWER: c_int = 0x02;
    const _DIGIT: c_int = 0x04;
    const _SPACE: c_int = 0x08;
    const _PUNCT: c_int = 0x10;
    const _CONTROL: c_int = 0x20;
    const _BLANK: c_int = 0x40;
    const _HEX: c_int = 0x80;
    const _ALPHA: c_int = _UPPER | _LOWER;

    let mut result = 0;

    if ch >= b'A' && ch <= b'Z' {
        result |= _UPPER | _ALPHA;
    }
    if ch >= b'a' && ch <= b'z' {
        result |= _LOWER | _ALPHA;
    }
    if ch >= b'0' && ch <= b'9' {
        result |= _DIGIT;
    }
    if ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r' {
        result |= _SPACE;
    }
    if ch == b' ' || ch == b'\t' {
        result |= _BLANK;
    }
    if ch < 32 || ch == 127 {
        result |= _CONTROL;
    }
    if (ch >= b'0' && ch <= b'9') || (ch >= b'a' && ch <= b'f') || (ch >= b'A' && ch <= b'F') {
        result |= _HEX;
    }
    if !((ch >= b'0' && ch <= b'9') || (ch >= b'a' && ch <= b'z') || (ch >= b'A' && ch <= b'Z') || ch < 32 || ch == 127 || ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r') {
        result |= _PUNCT;
    }

    if (result & mask) != 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn ___lc_codepage_func() -> c_uint {
    65001
}

#[no_mangle]
pub unsafe extern "C" fn ___lc_locale_name_func() -> *mut *mut wchar_t {
    static mut LOCALE_NAME_PTR: *mut wchar_t = ptr::null_mut();
    static LOCALE_NAME: Lazy<Mutex<[wchar_t; 32]>> = Lazy::new(|| Mutex::new([0; 32]));

    if LOCALE_NAME_PTR.is_null() {
        let locale = b"C\0";
        for i in 0..locale.len() {
            LOCALE_NAME[i] = locale[i] as wchar_t;
        }
        LOCALE_NAME_PTR = LOCALE_NAME.as_mut_ptr();
    }

    &mut LOCALE_NAME_PTR as *mut *mut wchar_t
}
