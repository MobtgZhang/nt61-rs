//! Scanf Format Parser and Implementation
//!
//! Complete implementation of scanf-style format string parsing

use super::types::*;

#[derive(Default)]
pub struct ScanfSpec {
    pub suppress: bool,       // '*' - don't assign
    pub width: Option<usize>, // max field width
    pub length: LengthModifier,
    pub specifier: char,
}

#[derive(Copy, Clone, PartialEq)]
pub enum LengthModifier {
    None,
    Char,       // hh
    Short,      // h
    Long,       // l
    LongLong,   // ll
    IntMax,     // j
    Size,       // z
    PtrDiff,    // t
    LongDouble, // L
}

impl Default for LengthModifier {
    fn default() -> Self {
        LengthModifier::None
    }
}

pub unsafe fn skip_whitespace(input: *const CChar, pos: &mut usize) {
    while *input.add(*pos) != 0 {
        let ch = *input.add(*pos) as u8;
        if ch != b' ' && ch != b'\t' && ch != b'\n' && ch != b'\r' {
            break;
        }
        *pos += 1;
    }
}

pub unsafe fn parse_scanf_spec(format: *const CChar, pos: &mut usize) -> Option<ScanfSpec> {
    if *format.add(*pos) != b'%' as CChar {
        return None;
    }
    *pos += 1;

    if *format.add(*pos) == b'%' as CChar {
        *pos += 1;
        return None;
    }

    let mut spec = ScanfSpec::default();

    if *format.add(*pos) == b'*' as CChar {
        spec.suppress = true;
        *pos += 1;
    }

    if (*format.add(*pos) as u8).is_ascii_digit() {
        let mut width = 0;
        while (*format.add(*pos) as u8).is_ascii_digit() {
            width = width * 10 + (*format.add(*pos) as u8 - b'0') as usize;
            *pos += 1;
        }
        spec.width = Some(width);
    }

    spec.length = match *format.add(*pos) as u8 {
        b'h' => {
            *pos += 1;
            if *format.add(*pos) == b'h' as CChar {
                *pos += 1;
                LengthModifier::Char
            } else {
                LengthModifier::Short
            }
        }
        b'l' => {
            *pos += 1;
            if *format.add(*pos) == b'l' as CChar {
                *pos += 1;
                LengthModifier::LongLong
            } else {
                LengthModifier::Long
            }
        }
        b'j' => {
            *pos += 1;
            LengthModifier::IntMax
        }
        b'z' => {
            *pos += 1;
            LengthModifier::Size
        }
        b't' => {
            *pos += 1;
            LengthModifier::PtrDiff
        }
        b'L' => {
            *pos += 1;
            LengthModifier::LongDouble
        }
        _ => LengthModifier::None,
    };

    let ch = *format.add(*pos) as u8;
    if ch.is_ascii_alphabetic() || ch == b'[' {
        spec.specifier = ch as char;
        *pos += 1;
        Some(spec)
    } else {
        None
    }
}

pub unsafe fn scan_integer(
    input: *const CChar,
    pos: &mut usize,
    base: u32,
    width: Option<usize>,
) -> Option<i64> {
    let start = *pos;
    let max_width = width.unwrap_or(usize::MAX);

    skip_whitespace(input, pos);

    let mut negative = false;
    if *input.add(*pos) == b'-' as CChar {
        negative = true;
        *pos += 1;
    } else if *input.add(*pos) == b'+' as CChar {
        *pos += 1;
    }

    let mut actual_base = base;
    if base == 0 || base == 16 {
        if *input.add(*pos) == b'0' as CChar {
            *pos += 1;
            if (*input.add(*pos) as u8 == b'x' || *input.add(*pos) as u8 == b'X') && base != 8 {
                *pos += 1;
                actual_base = 16;
            } else if base == 0 {
                actual_base = 8;
            }
        } else if base == 0 {
            actual_base = 10;
        }
    }

    let mut value: u64 = 0;
    let mut digit_count = 0;

    while *input.add(*pos) != 0 && (*pos - start) < max_width {
        let ch = *input.add(*pos) as u8;
        let digit_val = match ch {
            b'0'..=b'9' => (ch - b'0') as u32,
            b'a'..=b'z' => (ch - b'a' + 10) as u32,
            b'A'..=b'Z' => (ch - b'A' + 10) as u32,
            _ => break,
        };

        if digit_val >= actual_base {
            break;
        }

        value = value * actual_base as u64 + digit_val as u64;
        digit_count += 1;
        *pos += 1;
    }

    if digit_count == 0 {
        return None;
    }

    let result = if negative {
        -(value as i64)
    } else {
        value as i64
    };

    Some(result)
}

pub unsafe fn scan_unsigned(
    input: *const CChar,
    pos: &mut usize,
    base: u32,
    width: Option<usize>,
) -> Option<u64> {
    let start = *pos;
    let max_width = width.unwrap_or(usize::MAX);

    skip_whitespace(input, pos);

    let mut actual_base = base;
    if base == 0 || base == 16 {
        if *input.add(*pos) == b'0' as CChar {
            *pos += 1;
            if (*input.add(*pos) as u8 == b'x' || *input.add(*pos) as u8 == b'X') && base != 8 {
                *pos += 1;
                actual_base = 16;
            } else if base == 0 {
                actual_base = 8;
            }
        } else if base == 0 {
            actual_base = 10;
        }
    }

    let mut value: u64 = 0;
    let mut digit_count = 0;

    while *input.add(*pos) != 0 && (*pos - start) < max_width {
        let ch = *input.add(*pos) as u8;
        let digit_val = match ch {
            b'0'..=b'9' => (ch - b'0') as u32,
            b'a'..=b'z' => (ch - b'a' + 10) as u32,
            b'A'..=b'Z' => (ch - b'A' + 10) as u32,
            _ => break,
        };

        if digit_val >= actual_base {
            break;
        }

        value = value * actual_base as u64 + digit_val as u64;
        digit_count += 1;
        *pos += 1;
    }

    if digit_count == 0 {
        return None;
    }

    Some(value)
}

pub unsafe fn scan_float(
    input: *const CChar,
    pos: &mut usize,
    width: Option<usize>,
) -> Option<f64> {
    let start = *pos;
    let max_width = width.unwrap_or(usize::MAX);

    skip_whitespace(input, pos);

    let mut negative = false;
    if *input.add(*pos) == b'-' as CChar {
        negative = true;
        *pos += 1;
    } else if *input.add(*pos) == b'+' as CChar {
        *pos += 1;
    }

    if (*input.add(*pos) as u8 == b'i' || *input.add(*pos) as u8 == b'I')
        && (*input.add(*pos + 1) as u8 == b'n' || *input.add(*pos + 1) as u8 == b'N')
        && (*input.add(*pos + 2) as u8 == b'f' || *input.add(*pos + 2) as u8 == b'F')
    {
        *pos += 3;
        return Some(if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }

    if (*input.add(*pos) as u8 == b'n' || *input.add(*pos) as u8 == b'N')
        && (*input.add(*pos + 1) as u8 == b'a' || *input.add(*pos + 1) as u8 == b'A')
        && (*input.add(*pos + 2) as u8 == b'n' || *input.add(*pos + 2) as u8 == b'N')
    {
        *pos += 3;
        return Some(f64::NAN);
    }

    let mut value = 0.0;
    let mut has_digits = false;

    while *input.add(*pos) != 0 && (*pos - start) < max_width {
        let ch = *input.add(*pos) as u8;
        if ch >= b'0' && ch <= b'9' {
            value = value * 10.0 + (ch - b'0') as f64;
            has_digits = true;
            *pos += 1;
        } else {
            break;
        }
    }

    if *input.add(*pos) == b'.' as CChar && (*pos - start) < max_width {
        *pos += 1;
        let mut fraction = 0.1;
        while *input.add(*pos) != 0 && (*pos - start) < max_width {
            let ch = *input.add(*pos) as u8;
            if ch >= b'0' && ch <= b'9' {
                value += (ch - b'0') as f64 * fraction;
                fraction *= 0.1;
                has_digits = true;
                *pos += 1;
            } else {
                break;
            }
        }
    }

    if !has_digits {
        return None;
    }

    if (*input.add(*pos) as u8 == b'e' || *input.add(*pos) as u8 == b'E')
        && (*pos - start) < max_width
    {
        *pos += 1;
        let mut exp_negative = false;
        if *input.add(*pos) == b'-' as CChar {
            exp_negative = true;
            *pos += 1;
        } else if *input.add(*pos) == b'+' as CChar {
            *pos += 1;
        }

        let mut exponent = 0i32;
        while *input.add(*pos) != 0 && (*pos - start) < max_width {
            let ch = *input.add(*pos) as u8;
            if ch >= b'0' && ch <= b'9' {
                exponent = exponent * 10 + (ch - b'0') as i32;
                *pos += 1;
            } else {
                break;
            }
        }

        if exp_negative {
            exponent = -exponent;
        }

        let mut exp_val = 1.0;
        let mut e = exponent.abs();
        let base = if exponent >= 0 { 10.0 } else { 0.1 };
        while e > 0 {
            if e & 1 == 1 {
                exp_val *= base;
            }
            e >>= 1;
        }
        value *= exp_val;
    }

    Some(if negative { -value } else { value })
}

pub unsafe fn scan_string(
    input: *const CChar,
    pos: &mut usize,
    dest: *mut CChar,
    width: Option<usize>,
) -> bool {
    let max_width = width.unwrap_or(usize::MAX);

    skip_whitespace(input, pos);

    let mut count = 0;
    while *input.add(*pos) != 0 && count < max_width {
        let ch = *input.add(*pos) as u8;
        if ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r' {
            break;
        }
        *dest.add(count) = ch as CChar;
        count += 1;
        *pos += 1;
    }

    if count == 0 {
        return false;
    }

    *dest.add(count) = 0;
    true
}

pub unsafe fn scan_char(
    input: *const CChar,
    pos: &mut usize,
    dest: *mut CChar,
    width: Option<usize>,
) -> bool {
    let count = width.unwrap_or(1);

    for i in 0..count {
        if *input.add(*pos) == 0 {
            return i > 0;
        }
        *dest.add(i) = *input.add(*pos);
        *pos += 1;
    }

    true
}
