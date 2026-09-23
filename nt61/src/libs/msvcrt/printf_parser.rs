//! Printf Format Parser and Implementation
//!
//! Complete implementation of printf-style format string parsing

use super::types::*;
use core::ptr;

#[derive(Default)]
struct FormatFlags {
    left_justify: bool,    // '-'
    force_sign: bool,      // '+'
    space_sign: bool,      // ' '
    alternate: bool,       // '#'
    zero_pad: bool,        // '0'
}

struct FormatSpec {
    flags: FormatFlags,
    width: Option<usize>,
    precision: Option<usize>,
    length: LengthModifier,
    specifier: char,
}

#[derive(Copy, Clone, PartialEq)]
enum LengthModifier {
    None,
    Char,      // hh
    Short,     // h
    Long,      // l
    LongLong,  // ll
    IntMax,    // j
    Size,      // z
    PtrDiff,   // t
    LongDouble, // L
}

impl Default for LengthModifier {
    fn default() -> Self {
        LengthModifier::None
    }
}

unsafe fn parse_format_spec(format: *const c_char, pos: &mut usize) -> Option<FormatSpec> {
    let start = *pos;

    if *format.add(*pos) != b'%' as c_char {
        return None;
    }
    *pos += 1;

    if *format.add(*pos) == b'%' as c_char {
        *pos += 1;
        return None; // Special case: literal %
    }

    let mut spec = FormatSpec {
        flags: FormatFlags::default(),
        width: None,
        precision: None,
        length: LengthModifier::None,
        specifier: '\0',
    };

    loop {
        match *format.add(*pos) as u8 {
            b'-' => spec.flags.left_justify = true,
            b'+' => spec.flags.force_sign = true,
            b' ' => spec.flags.space_sign = true,
            b'#' => spec.flags.alternate = true,
            b'0' => spec.flags.zero_pad = true,
            _ => break,
        }
        *pos += 1;
    }

    if *format.add(*pos) == b'*' as c_char {
        spec.width = Some(usize::MAX); // Marker for dynamic width
        *pos += 1;
    } else if (*format.add(*pos) as u8).is_ascii_digit() {
        let mut width = 0;
        while (*format.add(*pos) as u8).is_ascii_digit() {
            width = width * 10 + (*format.add(*pos) as u8 - b'0') as usize;
            *pos += 1;
        }
        spec.width = Some(width);
    }

    if *format.add(*pos) == b'.' as c_char {
        *pos += 1;
        if *format.add(*pos) == b'*' as c_char {
            spec.precision = Some(usize::MAX); // Marker for dynamic precision
            *pos += 1;
        } else {
            let mut precision = 0;
            while (*format.add(*pos) as u8).is_ascii_digit() {
                precision = precision * 10 + (*format.add(*pos) as u8 - b'0') as usize;
                *pos += 1;
            }
            spec.precision = Some(precision);
        }
    }

    spec.length = match *format.add(*pos) as u8 {
        b'h' => {
            *pos += 1;
            if *format.add(*pos) == b'h' as c_char {
                *pos += 1;
                LengthModifier::Char
            } else {
                LengthModifier::Short
            }
        }
        b'l' => {
            *pos += 1;
            if *format.add(*pos) == b'l' as c_char {
                *pos += 1;
                LengthModifier::LongLong
            } else {
                LengthModifier::Long
            }
        }
        b'j' => { *pos += 1; LengthModifier::IntMax }
        b'z' => { *pos += 1; LengthModifier::Size }
        b't' => { *pos += 1; LengthModifier::PtrDiff }
        b'L' => { *pos += 1; LengthModifier::LongDouble }
        _ => LengthModifier::None,
    };

    let ch = *format.add(*pos) as u8;
    if ch.is_ascii_alphabetic() || ch == b'%' {
        spec.specifier = ch as char;
        *pos += 1;
        Some(spec)
    } else {
        None
    }
}

fn format_int_with_spec(
    value: i64,
    base: u32,
    uppercase: bool,
    spec: &FormatSpec,
    buf: &mut [u8],
) -> usize {
    let mut temp = [0u8; 128];
    let mut temp_len = 0;

    let negative = value < 0;
    let mut num = if negative { value.wrapping_neg() as u64 } else { value as u64 };

    let digits = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };

    if num == 0 {
        temp[temp_len] = b'0';
        temp_len += 1;
    } else {
        while num > 0 {
            temp[temp_len] = digits[(num % base as u64) as usize];
            num /= base as u64;
            temp_len += 1;
        }
    }

    let mut prefix = [0u8; 3];
    let mut prefix_len = 0;

    if negative {
        prefix[prefix_len] = b'-';
        prefix_len += 1;
    } else if spec.flags.force_sign {
        prefix[prefix_len] = b'+';
        prefix_len += 1;
    } else if spec.flags.space_sign {
        prefix[prefix_len] = b' ';
        prefix_len += 1;
    }

    if spec.flags.alternate && base == 16 && value != 0 {
        prefix[prefix_len] = b'0';
        prefix_len += 1;
        prefix[prefix_len] = if uppercase { b'X' } else { b'x' };
        prefix_len += 1;
    } else if spec.flags.alternate && base == 8 && value != 0 {
        prefix[prefix_len] = b'0';
        prefix_len += 1;
    }

    let precision = spec.precision.unwrap_or(1);
    while temp_len < precision && temp_len < 126 {
        temp[temp_len] = b'0';
        temp_len += 1;
    }

    let total_len = prefix_len + temp_len;
    let width = spec.width.unwrap_or(0);

    let mut pos = 0;

    if !spec.flags.left_justify && width > total_len {
        let pad_char = if spec.flags.zero_pad && spec.precision.is_none() { b'0' } else { b' ' };

        if pad_char == b'0' {
            for i in 0..prefix_len {
                buf[pos] = prefix[i];
                pos += 1;
            }
            for _ in 0..(width - total_len) {
                buf[pos] = b'0';
                pos += 1;
            }
        } else {
            for _ in 0..(width - total_len) {
                buf[pos] = b' ';
                pos += 1;
            }
            for i in 0..prefix_len {
                buf[pos] = prefix[i];
                pos += 1;
            }
        }
    } else {
        for i in 0..prefix_len {
            buf[pos] = prefix[i];
            pos += 1;
        }
    }

    for i in (0..temp_len).rev() {
        buf[pos] = temp[i];
        pos += 1;
    }

    if spec.flags.left_justify && width > total_len {
        for _ in 0..(width - total_len) {
            buf[pos] = b' ';
            pos += 1;
        }
    }

    pos
}

fn format_uint_with_spec(
    value: u64,
    base: u32,
    uppercase: bool,
    spec: &FormatSpec,
    buf: &mut [u8],
) -> usize {
    let mut temp = [0u8; 128];
    let mut temp_len = 0;

    let mut num = value;
    let digits = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };

    if num == 0 {
        temp[temp_len] = b'0';
        temp_len += 1;
    } else {
        while num > 0 {
            temp[temp_len] = digits[(num % base as u64) as usize];
            num /= base as u64;
            temp_len += 1;
        }
    }

    let mut prefix = [0u8; 2];
    let mut prefix_len = 0;

    if spec.flags.alternate && base == 16 && value != 0 {
        prefix[0] = b'0';
        prefix[1] = if uppercase { b'X' } else { b'x' };
        prefix_len = 2;
    } else if spec.flags.alternate && base == 8 && value != 0 {
        prefix[0] = b'0';
        prefix_len = 1;
    }

    let precision = spec.precision.unwrap_or(1);
    while temp_len < precision && temp_len < 126 {
        temp[temp_len] = b'0';
        temp_len += 1;
    }

    let total_len = prefix_len + temp_len;
    let width = spec.width.unwrap_or(0);
    let mut pos = 0;

    if !spec.flags.left_justify && width > total_len {
        let pad_char = if spec.flags.zero_pad && spec.precision.is_none() { b'0' } else { b' ' };

        if pad_char == b'0' {
            for i in 0..prefix_len {
                buf[pos] = prefix[i];
                pos += 1;
            }
            for _ in 0..(width - total_len) {
                buf[pos] = b'0';
                pos += 1;
            }
        } else {
            for _ in 0..(width - total_len) {
                buf[pos] = b' ';
                pos += 1;
            }
            for i in 0..prefix_len {
                buf[pos] = prefix[i];
                pos += 1;
            }
        }
    } else {
        for i in 0..prefix_len {
            buf[pos] = prefix[i];
            pos += 1;
        }
    }

    for i in (0..temp_len).rev() {
        buf[pos] = temp[i];
        pos += 1;
    }

    if spec.flags.left_justify && width > total_len {
        for _ in 0..(width - total_len) {
            buf[pos] = b' ';
            pos += 1;
        }
    }

    pos
}

unsafe fn format_string_with_spec(
    s: *const c_char,
    spec: &FormatSpec,
    buf: &mut [u8],
) -> usize {
    if s.is_null() {
        let null_str = b"(null)";
        let len = null_str.len();
        buf[..len].copy_from_slice(null_str);
        return len;
    }

    let mut str_len = 0;
    while *s.add(str_len) != 0 {
        str_len += 1;
    }

    if let Some(precision) = spec.precision {
        if precision < str_len {
            str_len = precision;
        }
    }

    let width = spec.width.unwrap_or(0);
    let mut pos = 0;

    if !spec.flags.left_justify && width > str_len {
        for _ in 0..(width - str_len) {
            buf[pos] = b' ';
            pos += 1;
        }
    }

    for i in 0..str_len {
        buf[pos] = *s.add(i) as u8;
        pos += 1;
    }

    if spec.flags.left_justify && width > str_len {
        for _ in 0..(width - str_len) {
            buf[pos] = b' ';
            pos += 1;
        }
    }

    pos
}

fn format_float_with_spec(
    value: f64,
    spec: &FormatSpec,
    buf: &mut [u8],
    exp_format: bool,
) -> usize {
    if value.is_nan() {
        let nan = b"nan";
        buf[..3].copy_from_slice(nan);
        return 3;
    }
    if value.is_infinite() {
        if value < 0.0 {
            buf[..4].copy_from_slice(b"-inf");
            return 4;
        } else {
            buf[..3].copy_from_slice(b"inf");
            return 3;
        }
    }

    let mut pos = 0;
    let mut val = value;

    if val < 0.0 {
        buf[pos] = b'-';
        pos += 1;
        val = -val;
    } else if spec.flags.force_sign {
        buf[pos] = b'+';
        pos += 1;
    } else if spec.flags.space_sign {
        buf[pos] = b' ';
        pos += 1;
    }

    let precision = spec.precision.unwrap_or(6);

    if exp_format {
        let mut exponent = 0i32;

        if val != 0.0 {
            while val >= 10.0 {
                val /= 10.0;
                exponent += 1;
            }
            while val < 1.0 {
                val *= 10.0;
                exponent -= 1;
            }
        }

        let int_part = val as u64;
        buf[pos] = (b'0' + int_part as u8);
        pos += 1;

        if precision > 0 || spec.flags.alternate {
            buf[pos] = b'.';
            pos += 1;
        }

        let mut frac = val - int_part as f64;
        for _ in 0..precision {
            frac *= 10.0;
            let digit = frac as u8;
            buf[pos] = b'0' + digit;
            pos += 1;
            frac -= digit as f64;
        }

        buf[pos] = if spec.specifier == 'E' { b'E' } else { b'e' };
        pos += 1;

        if exponent >= 0 {
            buf[pos] = b'+';
            pos += 1;
        } else {
            buf[pos] = b'-';
            pos += 1;
            exponent = -exponent;
        }

        if exponent < 10 {
            buf[pos] = b'0';
            pos += 1;
        }

        let exp_str = format_uint_with_spec(
            exponent as u64,
            10,
            false,
            &FormatSpec {
                flags: FormatFlags::default(),
                width: None,
                precision: None,
                length: LengthModifier::None,
                specifier: 'd',
            },
            &mut buf[pos..],
        );
        pos += exp_str;
    } else {
        let int_part = val as u64;
        let int_len = format_uint_with_spec(
            int_part,
            10,
            false,
            &FormatSpec {
                flags: FormatFlags::default(),
                width: None,
                precision: None,
                length: LengthModifier::None,
                specifier: 'd',
            },
            &mut buf[pos..],
        );
        pos += int_len;

        if precision > 0 || spec.flags.alternate {
            buf[pos] = b'.';
            pos += 1;
        }

        let mut frac = val - int_part as f64;
        for _ in 0..precision {
            frac *= 10.0;
            let digit = frac as u8;
            buf[pos] = b'0' + digit;
            pos += 1;
            frac -= digit as f64;
        }
    }

    pos
}
