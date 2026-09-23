use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};


use super::types::*;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

extern crate alloc;
use alloc::string::String;

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

struct LocaleData {
    current_locale: [c_char; 32],
    locale_conv: lconv,
    decimal_point_str: [c_char; 2],
    thousands_sep_str: [c_char; 2],
    empty_str: [c_char; 1],
    currency_str: [c_char; 2],
    plus_str: [c_char; 2],
    minus_str: [c_char; 2],
}

impl LocaleData {
    const fn new() -> Self {
        Self {
            current_locale: [0; 32],
            locale_conv: lconv {
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
            },
            decimal_point_str: [b'.' as c_char, 0],
            thousands_sep_str: [b',' as c_char, 0],
            empty_str: [0],
            currency_str: [b'$' as c_char, 0],
            plus_str: [b'+' as c_char, 0],
            minus_str: [b'-' as c_char, 0],
        }
    }
}

static LOCALE_DATA: Lazy<Mutex<LocaleData>> = Lazy::new(|| {
    let mut data = LocaleData::new();
    unsafe { init_c_locale_internal(&mut data); }
    Mutex::new(data)
});

static LOCALE_INITIALIZED: AtomicBool = AtomicBool::new(false);

unsafe fn init_c_locale_internal(data: &mut LocaleData) {
    let c_locale = b"C\0";
    for i in 0..c_locale.len() {
        data.current_locale[i] = c_locale[i] as c_char;
    }

    data.locale_conv.decimal_point = data.decimal_point_str.as_mut_ptr();
    data.locale_conv.thousands_sep = data.empty_str.as_mut_ptr();
    data.locale_conv.grouping = data.empty_str.as_mut_ptr();
    data.locale_conv.int_curr_symbol = data.empty_str.as_mut_ptr();
    data.locale_conv.currency_symbol = data.empty_str.as_mut_ptr();
    data.locale_conv.mon_decimal_point = data.empty_str.as_mut_ptr();
    data.locale_conv.mon_thousands_sep = data.empty_str.as_mut_ptr();
    data.locale_conv.mon_grouping = data.empty_str.as_mut_ptr();
    data.locale_conv.positive_sign = data.empty_str.as_mut_ptr();
    data.locale_conv.negative_sign = data.empty_str.as_mut_ptr();
}

pub const LC_ALL: c_int = 0;
pub const LC_COLLATE: c_int = 1;
pub const LC_CTYPE: c_int = 2;
pub const LC_MONETARY: c_int = 3;
pub const LC_NUMERIC: c_int = 4;
pub const LC_TIME: c_int = 5;

#[no_mangle]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char {
    if locale.is_null() {
        let data = LOCALE_DATA.lock();
        return data.current_locale.as_ptr() as *mut c_char;
    }

    let mut data = LOCALE_DATA.lock();

    if *locale == 0 || (*locale == b'C' as c_char && *locale.add(1) == 0) {
        init_c_locale_internal(&mut data);
        return data.current_locale.as_ptr() as *mut c_char;
    }

    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn localeconv() -> *mut lconv {
    let data = LOCALE_DATA.lock();
    &data.locale_conv as *const lconv as *mut lconv
}

#[no_mangle]
pub unsafe extern "C" fn _wsetlocale(category: c_int, locale: *const wchar_t) -> *mut wchar_t {
    static mut WIDE_LOCALE: Mutex<[wchar_t; 32]> = Mutex::new([0; 32]);

    if locale.is_null() {
        let mut wlocale = WIDE_LOCALE.lock();
        wlocale[0] = b'C' as wchar_t;
        wlocale[1] = 0;
        return wlocale.as_mut_ptr();
    }

    ptr::null_mut()
}
