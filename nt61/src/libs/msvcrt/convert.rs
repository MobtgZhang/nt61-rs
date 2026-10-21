//! String Conversion and Character Classification
//!
//! Implements atoi, strtol, itoa, and character classification functions

use super::types::*;
use core::ptr;

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isalpha(c: CInt) -> CInt {
    let ch = c as u8;
    if (ch >= b'a' && ch <= b'z') || (ch >= b'A' && ch <= b'Z') {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isdigit(c: CInt) -> CInt {
    let ch = c as u8;
    if ch >= b'0' && ch <= b'9' {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isalnum(c: CInt) -> CInt {
    if isalpha(c) != 0 || isdigit(c) != 0 {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isspace(c: CInt) -> CInt {
    let ch = c as u8;
    if ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r' || ch == b'\x0b' || ch == b'\x0c' {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isupper(c: CInt) -> CInt {
    let ch = c as u8;
    if ch >= b'A' && ch <= b'Z' {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn islower(c: CInt) -> CInt {
    let ch = c as u8;
    if ch >= b'a' && ch <= b'z' {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isxdigit(c: CInt) -> CInt {
    let ch = c as u8;
    if (ch >= b'0' && ch <= b'9') || (ch >= b'a' && ch <= b'f') || (ch >= b'A' && ch <= b'F') {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isprint(c: CInt) -> CInt {
    let ch = c as u8;
    if ch >= 32 && ch <= 126 {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isgraph(c: CInt) -> CInt {
    let ch = c as u8;
    if ch >= 33 && ch <= 126 {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn iscntrl(c: CInt) -> CInt {
    let ch = c as u8;
    if ch < 32 || ch == 127 {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn ispunct(c: CInt) -> CInt {
    if isgraph(c) != 0 && isalnum(c) == 0 {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn tolower(c: CInt) -> CInt {
    let ch = c as u8;
    if ch >= b'A' && ch <= b'Z' {
        (ch - b'A' + b'a') as CInt
    } else {
        c
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn toupper(c: CInt) -> CInt {
    let ch = c as u8;
    if ch >= b'a' && ch <= b'z' {
        (ch - b'a' + b'A') as CInt
    } else {
        c
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn _tolower(c: CInt) -> CInt {
    tolower(c)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn _toupper(c: CInt) -> CInt {
    toupper(c)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn atoi(s: *const CChar) -> CInt {
    if s.is_null() {
        return 0;
    }

    let mut result: CInt = 0;
    let mut sign: CInt = 1;
    let mut i = 0;

    while isspace(*s.add(i) as CInt) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as CChar {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as CChar {
        i += 1;
    }

    while isdigit(*s.add(i) as CInt) != 0 {
        let digit = (*s.add(i) as u8 - b'0') as CInt;
        result = result.wrapping_mul(10).wrapping_add(digit);
        i += 1;
    }

    result * sign
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn atol(s: *const CChar) -> CLong {
    if s.is_null() {
        return 0;
    }

    let mut result: CLong = 0;
    let mut sign: CLong = 1;
    let mut i = 0;

    while isspace(*s.add(i) as CInt) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as CChar {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as CChar {
        i += 1;
    }

    while isdigit(*s.add(i) as CInt) != 0 {
        let digit = (*s.add(i) as u8 - b'0') as CLong;
        result = result.wrapping_mul(10).wrapping_add(digit);
        i += 1;
    }

    result * sign
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn atoll(s: *const CChar) -> CLonglong {
    if s.is_null() {
        return 0;
    }

    let mut result: CLonglong = 0;
    let mut sign: CLonglong = 1;
    let mut i = 0;

    while isspace(*s.add(i) as CInt) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as CChar {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as CChar {
        i += 1;
    }

    while isdigit(*s.add(i) as CInt) != 0 {
        let digit = (*s.add(i) as u8 - b'0') as CLonglong;
        result = result.wrapping_mul(10).wrapping_add(digit);
        i += 1;
    }

    result * sign
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn atof(s: *const CChar) -> CDouble {
    strtod(s, ptr::null_mut())
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strtol(s: *const CChar, endptr: *mut *mut CChar, base: CInt) -> CLong {
    if s.is_null() || base < 0 || base == 1 || base > 36 {
        return 0;
    }

    let mut result: CLong = 0;
    let mut sign: CLong = 1;
    let mut i = 0;

    while isspace(*s.add(i) as CInt) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as CChar {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as CChar {
        i += 1;
    }

    let actual_base = if base == 0 {
        if *s.add(i) == b'0' as CChar {
            if *s.add(i + 1) == b'x' as CChar || *s.add(i + 1) == b'X' as CChar {
                i += 2;
                16
            } else {
                8
            }
        } else {
            10
        }
    } else {
        if base == 16 && *s.add(i) == b'0' as CChar {
            if *s.add(i + 1) == b'x' as CChar || *s.add(i + 1) == b'X' as CChar {
                i += 2;
            }
        }
        base
    };

    let start_i = i;

    loop {
        let ch = *s.add(i) as u8;
        let digit = if ch >= b'0' && ch <= b'9' {
            (ch - b'0') as CInt
        } else if ch >= b'a' && ch <= b'z' {
            (ch - b'a' + 10) as CInt
        } else if ch >= b'A' && ch <= b'Z' {
            (ch - b'A' + 10) as CInt
        } else {
            break;
        };

        if digit >= actual_base {
            break;
        }

        result = result
            .wrapping_mul(actual_base as CLong)
            .wrapping_add(digit as CLong);
        i += 1;
    }

    if !endptr.is_null() {
        if i == start_i {
            *endptr = s as *mut CChar;
        } else {
            *endptr = s.add(i) as *mut CChar;
        }
    }

    result * sign
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strtoul(s: *const CChar, endptr: *mut *mut CChar, base: CInt) -> CUlong {
    strtol(s, endptr, base) as CUlong
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strtoll(
    s: *const CChar,
    endptr: *mut *mut CChar,
    base: CInt,
) -> CLonglong {
    if s.is_null() || base < 0 || base == 1 || base > 36 {
        return 0;
    }

    let mut result: CLonglong = 0;
    let mut sign: CLonglong = 1;
    let mut i = 0;

    while isspace(*s.add(i) as CInt) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as CChar {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as CChar {
        i += 1;
    }

    let actual_base = if base == 0 {
        if *s.add(i) == b'0' as CChar {
            if *s.add(i + 1) == b'x' as CChar || *s.add(i + 1) == b'X' as CChar {
                i += 2;
                16
            } else {
                8
            }
        } else {
            10
        }
    } else {
        base
    };

    let start_i = i;

    loop {
        let ch = *s.add(i) as u8;
        let digit = if ch >= b'0' && ch <= b'9' {
            (ch - b'0') as CInt
        } else if ch >= b'a' && ch <= b'z' {
            (ch - b'a' + 10) as CInt
        } else if ch >= b'A' && ch <= b'Z' {
            (ch - b'A' + 10) as CInt
        } else {
            break;
        };

        if digit >= actual_base {
            break;
        }

        result = result
            .wrapping_mul(actual_base as CLonglong)
            .wrapping_add(digit as CLonglong);
        i += 1;
    }

    if !endptr.is_null() {
        if i == start_i {
            *endptr = s as *mut CChar;
        } else {
            *endptr = s.add(i) as *mut CChar;
        }
    }

    result * sign
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strtoull(
    s: *const CChar,
    endptr: *mut *mut CChar,
    base: CInt,
) -> CUlonglong {
    strtoll(s, endptr, base) as CUlonglong
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strtod(s: *const CChar, endptr: *mut *mut CChar) -> CDouble {
    if s.is_null() {
        return 0.0;
    }

    let mut result: CDouble = 0.0;
    let mut sign: CDouble = 1.0;
    let mut i = 0;

    while isspace(*s.add(i) as CInt) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as CChar {
        sign = -1.0;
        i += 1;
    } else if *s.add(i) == b'+' as CChar {
        i += 1;
    }

    let start_i = i;

    while isdigit(*s.add(i) as CInt) != 0 {
        let digit = (*s.add(i) as u8 - b'0') as CDouble;
        result = result * 10.0 + digit;
        i += 1;
    }

    if *s.add(i) == b'.' as CChar {
        i += 1;
        let mut fraction = 0.0;
        let mut divisor = 1.0;

        while isdigit(*s.add(i) as CInt) != 0 {
            let digit = (*s.add(i) as u8 - b'0') as CDouble;
            fraction = fraction * 10.0 + digit;
            divisor *= 10.0;
            i += 1;
        }

        result += fraction / divisor;
    }

    if *s.add(i) == b'e' as CChar || *s.add(i) == b'E' as CChar {
        i += 1;
        let mut exp_sign = 1;
        let mut exponent = 0;

        if *s.add(i) == b'-' as CChar {
            exp_sign = -1;
            i += 1;
        } else if *s.add(i) == b'+' as CChar {
            i += 1;
        }

        while isdigit(*s.add(i) as CInt) != 0 {
            let digit = (*s.add(i) as u8 - b'0') as i32;
            exponent = exponent * 10 + digit;
            i += 1;
        }

        let exp_value = crate::libs::msvcrt::math::pow(10.0, (exponent * exp_sign) as CDouble);
        result *= exp_value;
    }

    if !endptr.is_null() {
        if i == start_i {
            *endptr = s as *mut CChar;
        } else {
            *endptr = s.add(i) as *mut CChar;
        }
    }

    result * sign
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strtof(s: *const CChar, endptr: *mut *mut CChar) -> CFloat {
    strtod(s, endptr) as CFloat
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn itoa(value: CInt, str: *mut CChar, base: CInt) -> *mut CChar {
    if str.is_null() || base < 2 || base > 36 {
        return ptr::null_mut();
    }

    let mut num = value;
    let mut i = 0;
    let negative = num < 0 && base == 10;

    if negative {
        num = -num;
    }

    let mut temp: [CChar; 33] = [0; 33];
    let mut temp_i = 0;

    if num == 0 {
        temp[temp_i] = b'0' as CChar;
        temp_i += 1;
    } else {
        while num != 0 {
            let digit = (num % base) as u8;
            temp[temp_i] = if digit < 10 {
                (b'0' + digit) as CChar
            } else {
                (b'a' + digit - 10) as CChar
            };
            num /= base;
            temp_i += 1;
        }
    }

    if negative {
        *str.add(i) = b'-' as CChar;
        i += 1;
    }

    for j in (0..temp_i).rev() {
        *str.add(i) = temp[j];
        i += 1;
    }

    *str.add(i) = 0;
    str
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _itoa(value: CInt, str: *mut CChar, base: CInt) -> *mut CChar {
    itoa(value, str, base)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _ltoa(value: CLong, str: *mut CChar, base: CInt) -> *mut CChar {
    itoa(value as CInt, str, base)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _itoa_s(value: CInt, str: *mut CChar, size: SizeT, base: CInt) -> ErrnoT {
    if str.is_null() || size == 0 || base < 2 || base > 36 {
        return EINVAL;
    }

    let result = itoa(value, str, base);
    if result.is_null() {
        return EINVAL;
    }

    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _ltoa_s(value: CLong, str: *mut CChar, size: SizeT, base: CInt) -> ErrnoT {
    _itoa_s(value as CInt, str, size, base)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _i64toa(value: CLonglong, str: *mut CChar, base: CInt) -> *mut CChar {
    itoa(value as CInt, str, base)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _ui64toa(value: CUlonglong, str: *mut CChar, base: CInt) -> *mut CChar {
    itoa(value as CInt, str, base)
}
