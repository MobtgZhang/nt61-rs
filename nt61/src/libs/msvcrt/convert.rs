//! String Conversion and Character Classification
//!
//! Implements atoi, strtol, itoa, and character classification functions

use super::types::*;
use core::ptr;


#[no_mangle]
pub extern "C" fn isalpha(c: c_int) -> c_int {
    let ch = c as u8;
    if (ch >= b'a' && ch <= b'z') || (ch >= b'A' && ch <= b'Z') {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn isdigit(c: c_int) -> c_int {
    let ch = c as u8;
    if ch >= b'0' && ch <= b'9' {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn isalnum(c: c_int) -> c_int {
    if isalpha(c) != 0 || isdigit(c) != 0 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn isspace(c: c_int) -> c_int {
    let ch = c as u8;
    if ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r' || ch == b'\x0b' || ch == b'\x0c' {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn isupper(c: c_int) -> c_int {
    let ch = c as u8;
    if ch >= b'A' && ch <= b'Z' {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn islower(c: c_int) -> c_int {
    let ch = c as u8;
    if ch >= b'a' && ch <= b'z' {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn isxdigit(c: c_int) -> c_int {
    let ch = c as u8;
    if (ch >= b'0' && ch <= b'9') || (ch >= b'a' && ch <= b'f') || (ch >= b'A' && ch <= b'F') {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn isprint(c: c_int) -> c_int {
    let ch = c as u8;
    if ch >= 32 && ch <= 126 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn isgraph(c: c_int) -> c_int {
    let ch = c as u8;
    if ch >= 33 && ch <= 126 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn iscntrl(c: c_int) -> c_int {
    let ch = c as u8;
    if ch < 32 || ch == 127 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn ispunct(c: c_int) -> c_int {
    if isgraph(c) != 0 && isalnum(c) == 0 {
        1
    } else {
        0
    }
}


#[no_mangle]
pub extern "C" fn tolower(c: c_int) -> c_int {
    let ch = c as u8;
    if ch >= b'A' && ch <= b'Z' {
        (ch - b'A' + b'a') as c_int
    } else {
        c
    }
}

#[no_mangle]
pub extern "C" fn toupper(c: c_int) -> c_int {
    let ch = c as u8;
    if ch >= b'a' && ch <= b'z' {
        (ch - b'a' + b'A') as c_int
    } else {
        c
    }
}

#[no_mangle]
pub extern "C" fn _tolower(c: c_int) -> c_int {
    tolower(c)
}

#[no_mangle]
pub extern "C" fn _toupper(c: c_int) -> c_int {
    toupper(c)
}


#[no_mangle]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    if s.is_null() {
        return 0;
    }

    let mut result: c_int = 0;
    let mut sign: c_int = 1;
    let mut i = 0;

    while isspace(*s.add(i) as c_int) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as c_char {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as c_char {
        i += 1;
    }

    while isdigit(*s.add(i) as c_int) != 0 {
        let digit = (*s.add(i) as u8 - b'0') as c_int;
        result = result.wrapping_mul(10).wrapping_add(digit);
        i += 1;
    }

    result * sign
}

#[no_mangle]
pub unsafe extern "C" fn atol(s: *const c_char) -> c_long {
    if s.is_null() {
        return 0;
    }

    let mut result: c_long = 0;
    let mut sign: c_long = 1;
    let mut i = 0;

    while isspace(*s.add(i) as c_int) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as c_char {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as c_char {
        i += 1;
    }

    while isdigit(*s.add(i) as c_int) != 0 {
        let digit = (*s.add(i) as u8 - b'0') as c_long;
        result = result.wrapping_mul(10).wrapping_add(digit);
        i += 1;
    }

    result * sign
}

#[no_mangle]
pub unsafe extern "C" fn atoll(s: *const c_char) -> c_longlong {
    if s.is_null() {
        return 0;
    }

    let mut result: c_longlong = 0;
    let mut sign: c_longlong = 1;
    let mut i = 0;

    while isspace(*s.add(i) as c_int) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as c_char {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as c_char {
        i += 1;
    }

    while isdigit(*s.add(i) as c_int) != 0 {
        let digit = (*s.add(i) as u8 - b'0') as c_longlong;
        result = result.wrapping_mul(10).wrapping_add(digit);
        i += 1;
    }

    result * sign
}

#[no_mangle]
pub unsafe extern "C" fn atof(s: *const c_char) -> c_double {
    strtod(s, ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn strtol(
    s: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    if s.is_null() || base < 0 || base == 1 || base > 36 {
        return 0;
    }

    let mut result: c_long = 0;
    let mut sign: c_long = 1;
    let mut i = 0;

    while isspace(*s.add(i) as c_int) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as c_char {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as c_char {
        i += 1;
    }

    let actual_base = if base == 0 {
        if *s.add(i) == b'0' as c_char {
            if *s.add(i + 1) == b'x' as c_char || *s.add(i + 1) == b'X' as c_char {
                i += 2;
                16
            } else {
                8
            }
        } else {
            10
        }
    } else {
        if base == 16 && *s.add(i) == b'0' as c_char {
            if *s.add(i + 1) == b'x' as c_char || *s.add(i + 1) == b'X' as c_char {
                i += 2;
            }
        }
        base
    };

    let start_i = i;

    loop {
        let ch = *s.add(i) as u8;
        let digit = if ch >= b'0' && ch <= b'9' {
            (ch - b'0') as c_int
        } else if ch >= b'a' && ch <= b'z' {
            (ch - b'a' + 10) as c_int
        } else if ch >= b'A' && ch <= b'Z' {
            (ch - b'A' + 10) as c_int
        } else {
            break;
        };

        if digit >= actual_base {
            break;
        }

        result = result.wrapping_mul(actual_base as c_long).wrapping_add(digit as c_long);
        i += 1;
    }

    if !endptr.is_null() {
        if i == start_i {
            *endptr = s as *mut c_char;
        } else {
            *endptr = s.add(i) as *mut c_char;
        }
    }

    result * sign
}

#[no_mangle]
pub unsafe extern "C" fn strtoul(
    s: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    strtol(s, endptr, base) as c_ulong
}

#[no_mangle]
pub unsafe extern "C" fn strtoll(
    s: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_longlong {
    if s.is_null() || base < 0 || base == 1 || base > 36 {
        return 0;
    }

    let mut result: c_longlong = 0;
    let mut sign: c_longlong = 1;
    let mut i = 0;

    while isspace(*s.add(i) as c_int) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as c_char {
        sign = -1;
        i += 1;
    } else if *s.add(i) == b'+' as c_char {
        i += 1;
    }

    let actual_base = if base == 0 {
        if *s.add(i) == b'0' as c_char {
            if *s.add(i + 1) == b'x' as c_char || *s.add(i + 1) == b'X' as c_char {
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
            (ch - b'0') as c_int
        } else if ch >= b'a' && ch <= b'z' {
            (ch - b'a' + 10) as c_int
        } else if ch >= b'A' && ch <= b'Z' {
            (ch - b'A' + 10) as c_int
        } else {
            break;
        };

        if digit >= actual_base {
            break;
        }

        result = result.wrapping_mul(actual_base as c_longlong).wrapping_add(digit as c_longlong);
        i += 1;
    }

    if !endptr.is_null() {
        if i == start_i {
            *endptr = s as *mut c_char;
        } else {
            *endptr = s.add(i) as *mut c_char;
        }
    }

    result * sign
}

#[no_mangle]
pub unsafe extern "C" fn strtoull(
    s: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulonglong {
    strtoll(s, endptr, base) as c_ulonglong
}

#[no_mangle]
pub unsafe extern "C" fn strtod(s: *const c_char, endptr: *mut *mut c_char) -> c_double {
    if s.is_null() {
        return 0.0;
    }

    let mut result: c_double = 0.0;
    let mut sign: c_double = 1.0;
    let mut i = 0;

    while isspace(*s.add(i) as c_int) != 0 {
        i += 1;
    }

    if *s.add(i) == b'-' as c_char {
        sign = -1.0;
        i += 1;
    } else if *s.add(i) == b'+' as c_char {
        i += 1;
    }

    let start_i = i;

    while isdigit(*s.add(i) as c_int) != 0 {
        let digit = (*s.add(i) as u8 - b'0') as c_double;
        result = result * 10.0 + digit;
        i += 1;
    }

    if *s.add(i) == b'.' as c_char {
        i += 1;
        let mut fraction = 0.0;
        let mut divisor = 1.0;

        while isdigit(*s.add(i) as c_int) != 0 {
            let digit = (*s.add(i) as u8 - b'0') as c_double;
            fraction = fraction * 10.0 + digit;
            divisor *= 10.0;
            i += 1;
        }

        result += fraction / divisor;
    }

    if *s.add(i) == b'e' as c_char || *s.add(i) == b'E' as c_char {
        i += 1;
        let mut exp_sign = 1;
        let mut exponent = 0;

        if *s.add(i) == b'-' as c_char {
            exp_sign = -1;
            i += 1;
        } else if *s.add(i) == b'+' as c_char {
            i += 1;
        }

        while isdigit(*s.add(i) as c_int) != 0 {
            let digit = (*s.add(i) as u8 - b'0') as i32;
            exponent = exponent * 10 + digit;
            i += 1;
        }

        let exp_value = crate::libs::msvcrt::math::pow(10.0, (exponent * exp_sign) as c_double);
        result *= exp_value;
    }

    if !endptr.is_null() {
        if i == start_i {
            *endptr = s as *mut c_char;
        } else {
            *endptr = s.add(i) as *mut c_char;
        }
    }

    result * sign
}

#[no_mangle]
pub unsafe extern "C" fn strtof(s: *const c_char, endptr: *mut *mut c_char) -> c_float {
    strtod(s, endptr) as c_float
}


#[no_mangle]
pub unsafe extern "C" fn itoa(value: c_int, str: *mut c_char, base: c_int) -> *mut c_char {
    if str.is_null() || base < 2 || base > 36 {
        return ptr::null_mut();
    }

    let mut num = value;
    let mut i = 0;
    let negative = num < 0 && base == 10;

    if negative {
        num = -num;
    }

    let mut temp: [c_char; 33] = [0; 33];
    let mut temp_i = 0;

    if num == 0 {
        temp[temp_i] = b'0' as c_char;
        temp_i += 1;
    } else {
        while num != 0 {
            let digit = (num % base) as u8;
            temp[temp_i] = if digit < 10 {
                (b'0' + digit) as c_char
            } else {
                (b'a' + digit - 10) as c_char
            };
            num /= base;
            temp_i += 1;
        }
    }

    if negative {
        *str.add(i) = b'-' as c_char;
        i += 1;
    }

    for j in (0..temp_i).rev() {
        *str.add(i) = temp[j];
        i += 1;
    }

    *str.add(i) = 0;
    str
}

#[no_mangle]
pub unsafe extern "C" fn _itoa(value: c_int, str: *mut c_char, base: c_int) -> *mut c_char {
    itoa(value, str, base)
}

#[no_mangle]
pub unsafe extern "C" fn _ltoa(value: c_long, str: *mut c_char, base: c_int) -> *mut c_char {
    itoa(value as c_int, str, base)
}

#[no_mangle]
pub unsafe extern "C" fn _itoa_s(
    value: c_int,
    str: *mut c_char,
    size: size_t,
    base: c_int,
) -> errno_t {
    if str.is_null() || size == 0 || base < 2 || base > 36 {
        return EINVAL;
    }

    let result = itoa(value, str, base);
    if result.is_null() {
        return EINVAL;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn _ltoa_s(
    value: c_long,
    str: *mut c_char,
    size: size_t,
    base: c_int,
) -> errno_t {
    _itoa_s(value as c_int, str, size, base)
}

#[no_mangle]
pub unsafe extern "C" fn _i64toa(
    value: c_longlong,
    str: *mut c_char,
    base: c_int,
) -> *mut c_char {
    itoa(value as c_int, str, base)
}

#[no_mangle]
pub unsafe extern "C" fn _ui64toa(
    value: c_ulonglong,
    str: *mut c_char,
    base: c_int,
) -> *mut c_char {
    itoa(value as c_int, str, base)
}
