use core::sync::atomic::AtomicBool;
use spin::{Lazy, Mutex};

use super::types::*;
use core::ptr;

extern crate alloc;

#[repr(C)]
pub struct lconv {
    pub decimal_point: *mut CChar,
    pub thousands_sep: *mut CChar,
    pub grouping: *mut CChar,
    pub int_curr_symbol: *mut CChar,
    pub currency_symbol: *mut CChar,
    pub mon_decimal_point: *mut CChar,
    pub mon_thousands_sep: *mut CChar,
    pub mon_grouping: *mut CChar,
    pub positive_sign: *mut CChar,
    pub negative_sign: *mut CChar,
    pub int_frac_digits: CChar,
    pub frac_digits: CChar,
    pub p_cs_precedes: CChar,
    pub p_sep_by_space: CChar,
    pub n_cs_precedes: CChar,
    pub n_sep_by_space: CChar,
    pub p_sign_posn: CChar,
    pub n_sign_posn: CChar,
}

// The locale data is only reachable through the mutex-guarded static that
// owns it, so the pointer fields can be shared across threads.
unsafe impl Send for lconv {}

pub struct LocaleData {
    current_locale: [CChar; 32],
    locale_conv: lconv,
    decimal_point_str: [CChar; 2],
    pub thousands_sep_str: [CChar; 2],
    empty_str: [CChar; 1],
    pub currency_str: [CChar; 2],
    pub plus_str: [CChar; 2],
    pub minus_str: [CChar; 2],
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
            decimal_point_str: [b'.' as CChar, 0],
            thousands_sep_str: [b',' as CChar, 0],
            empty_str: [0],
            currency_str: [b'$' as CChar, 0],
            plus_str: [b'+' as CChar, 0],
            minus_str: [b'-' as CChar, 0],
        }
    }
}

static LOCALE_DATA: Lazy<Mutex<LocaleData>> = Lazy::new(|| {
    let mut data = LocaleData::new();
    unsafe {
        init_c_locale_internal(&mut data);
    }
    Mutex::new(data)
});

pub static LOCALE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn init_c_locale_internal(data: &mut LocaleData) {
    let c_locale = b"C\0";
    for i in 0..c_locale.len() {
        data.current_locale[i] = c_locale[i] as CChar;
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

pub const LC_ALL: CInt = 0;
pub const LC_COLLATE: CInt = 1;
pub const LC_CTYPE: CInt = 2;
pub const LC_MONETARY: CInt = 3;
pub const LC_NUMERIC: CInt = 4;
pub const LC_TIME: CInt = 5;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn setlocale(_category: CInt, locale: *const CChar) -> *mut CChar {
    if locale.is_null() {
        let data = LOCALE_DATA.lock();
        return data.current_locale.as_ptr() as *mut CChar;
    }

    let mut data = LOCALE_DATA.lock();

    if *locale == 0 || (*locale == b'C' as CChar && *locale.add(1) == 0) {
        init_c_locale_internal(&mut data);
        return data.current_locale.as_ptr() as *mut CChar;
    }

    ptr::null_mut()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn localeconv() -> *mut lconv {
    let data = LOCALE_DATA.lock();
    &data.locale_conv as *const lconv as *mut lconv
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _wsetlocale(_category: CInt, locale: *const WcharT) -> *mut WcharT {
    static mut WIDE_LOCALE: Mutex<[WcharT; 32]> = Mutex::new([0; 32]);

    if locale.is_null() {
        let mut wlocale = (*core::ptr::addr_of!(WIDE_LOCALE)).lock();
        wlocale[0] = b'C' as WcharT;
        wlocale[1] = 0;
        return wlocale.as_mut_ptr();
    }

    ptr::null_mut()
}
