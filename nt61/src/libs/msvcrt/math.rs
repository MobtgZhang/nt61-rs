//! Mathematical Functions
//!
//! Implements standard C math library functions with hardware acceleration where possible.

use super::types::*;

#[cfg(target_arch = "x86_64")]
#[inline]
fn sqrt_impl_f64(x: f64) -> f64 {
    if x < 0.0 { return f64::NAN; }
    if x == 0.0 { return 0.0; }

    unsafe {
        use core::arch::x86_64::_mm_sqrt_sd;
        use core::arch::x86_64::_mm_set_sd;
        use core::arch::x86_64::_mm_cvtsd_f64;
        let xmm = _mm_set_sd(x);
        let result = _mm_sqrt_sd(xmm, xmm);
        _mm_cvtsd_f64(result)
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn sqrt_impl_f32(x: f32) -> f32 {
    if x < 0.0 { return f32::NAN; }
    if x == 0.0 { return 0.0; }

    unsafe {
        use core::arch::x86_64::_mm_sqrt_ss;
        use core::arch::x86_64::_mm_set_ss;
        use core::arch::x86_64::_mm_cvtss_f32;
        let xmm = _mm_set_ss(x);
        let result = _mm_sqrt_ss(xmm);
        _mm_cvtss_f32(result)
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn sqrt_impl_f64(x: f64) -> f64 {
    if x < 0.0 { return f64::NAN; }
    if x == 0.0 { return 0.0; }
    let mut z = x;
    for _ in 0..20 {
        z = (z + x / z) * 0.5;
    }
    z
}

#[cfg(not(target_arch = "x86_64"))]
fn sqrt_impl_f32(x: f32) -> f32 {
    if x < 0.0 { return f32::NAN; }
    if x == 0.0 { return 0.0; }
    let mut z = x;
    for _ in 0..15 {
        z = (z + x / z) * 0.5;
    }
    z
}

fn ln_impl_f64(x: f64) -> f64 {
    if x <= 0.0 { return f64::NEG_INFINITY; }
    if x == 1.0 { return 0.0; }

    // For x near 1, use Taylor series around 1
    if x > 0.5 && x < 2.0 {
        let y = (x - 1.0) / (x + 1.0);
        let y2 = y * y;
        let mut result = 0.0;
        let mut term = y;
        let mut n = 1.0;

        for _ in 0..30 {
            result += term / n;
            term *= y2;
            n += 2.0;
            if term.abs() < 1e-16 { break; }
        }
        return result * 2.0;
    }

    // For other values, use argument reduction: ln(x) = ln(m * 2^e) = ln(m) + e*ln(2)
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i32 - 1023;
    let mantissa = f64::from_bits((bits & 0x000FFFFFFFFFFFFF) | 0x3FF0000000000000);

    const LN2: f64 = 0.693147180559945309417232121458;
    ln_impl_f64(mantissa) + (exp as f64) * LN2
}

fn ln_impl_f32(x: f32) -> f32 {
    ln_impl_f64(x as f64) as f32
}

fn exp_impl_f64(x: f64) -> f64 {
    if x > 700.0 { return f64::INFINITY; }
    if x < -700.0 { return 0.0; }

    const LN2: f64 = 0.693147180559945309417232121458;
    let k_f = x / LN2;
    let k = if k_f >= 0.0 { k_f + 0.5 } else { k_f - 0.5 } as i32 as f64;
    let r = x - k * LN2;

    let mut result = 1.0;
    let mut term = 1.0;
    for i in 1..25 {
        term *= r / (i as f64);
        result += term;
        if term.abs() < 1e-16 { break; }
    }

    let ki = k as i32;
    if ki >= -1022 && ki <= 1023 {
        let scale = f64::from_bits(((ki + 1023) as u64) << 52);
        result * scale
    } else {
        result * pow_impl_f64(2.0, k)
    }
}

fn exp_impl_f32(x: f32) -> f32 {
    exp_impl_f64(x as f64) as f32
}

fn pow_impl_f64(x: f64, y: f64) -> f64 {
    if y == 0.0 { return 1.0; }
    if x == 0.0 {
        if y > 0.0 { return 0.0; }
        return f64::INFINITY;
    }
    if x == 1.0 { return 1.0; }
    if y == 1.0 { return x; }
    if y == 2.0 { return x * x; }
    if y == 0.5 { return sqrt_impl_f64(x); }

    // For integer exponents, use repeated multiplication
    let y_int = y as i64;
    if y as f64 == y_int as f64 && y.abs() < 100.0 {
        let mut result = 1.0;
        let mut base = x;
        let mut exp = y.abs() as i32;

        while exp > 0 {
            if exp & 1 == 1 {
                result *= base;
            }
            base *= base;
            exp >>= 1;
        }

        if y < 0.0 {
            return 1.0 / result;
        }
        return result;
    }

    if x < 0.0 { return f64::NAN; }

    exp_impl_f64(y * ln_impl_f64(x))
}

fn pow_impl_f32(x: f32, y: f32) -> f32 {
    pow_impl_f64(x as f64, y as f64) as f32
}

fn sin_impl_f64(mut x: f64) -> f64 {
    const PI: f64 = 3.14159265358979323846;
    const PI2: f64 = 6.28318530717958647692;

    x = x % PI2;
    if x > PI { x -= PI2; }
    if x < -PI { x += PI2; }

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    x = x.abs();

    if x > PI / 2.0 {
        x = PI - x;
    }

    let mut result = x;
    let mut term = x;
    let x2 = x * x;

    for n in 1..25 {
        term *= -x2 / ((2 * n) * (2 * n + 1)) as f64;
        result += term;
        if term.abs() < 1e-16 { break; }
    }

    result * sign
}

fn sin_impl_f32(x: f32) -> f32 {
    sin_impl_f64(x as f64) as f32
}

fn cos_impl_f64(x: f64) -> f64 {
    const PI_2: f64 = 1.57079632679489661923;
    sin_impl_f64(PI_2 - x)
}

fn cos_impl_f32(x: f32) -> f32 {
    cos_impl_f64(x as f64) as f32
}

fn tan_impl_f64(x: f64) -> f64 {
    sin_impl_f64(x) / cos_impl_f64(x)
}

fn tan_impl_f32(x: f32) -> f32 {
    tan_impl_f64(x as f64) as f32
}

fn atan_impl_f64(x: f64) -> f64 {
    const PI_2: f64 = 1.57079632679489661923;

    if x.is_nan() { return x; }
    if x.is_infinite() {
        return if x > 0.0 { PI_2 } else { -PI_2 };
    }

    // For |x| > 1, use atan(x) = π/2 - atan(1/x)
    if x > 1.0 {
        return PI_2 - atan_impl_f64(1.0 / x);
    }
    if x < -1.0 {
        return -PI_2 - atan_impl_f64(1.0 / x);
    }

    let mut result = x;
    let mut term = x;
    let x2 = x * x;

    for n in 1..30 {
        term *= -x2;
        result += term / (2 * n + 1) as f64;
        if term.abs() < 1e-16 { break; }
    }

    result
}

fn atan_impl_f32(x: f32) -> f32 {
    atan_impl_f64(x as f64) as f32
}


#[no_mangle]
pub extern "C" fn abs(n: c_int) -> c_int {
    if n < 0 { -n } else { n }
}

#[no_mangle]
pub extern "C" fn labs(n: c_long) -> c_long {
    if n < 0 { -n } else { n }
}

#[no_mangle]
pub extern "C" fn llabs(n: c_longlong) -> c_longlong {
    if n < 0 { -n } else { n }
}

#[no_mangle]
pub extern "C" fn fabs(x: c_double) -> c_double {
    if x < 0.0 { -x } else { x }
}

#[no_mangle]
pub extern "C" fn fabsf(x: c_float) -> c_float {
    if x < 0.0 { -x } else { x }
}


#[no_mangle]
pub extern "C" fn div(numer: c_int, denom: c_int) -> div_t {
    div_t {
        quot: numer / denom,
        rem: numer % denom,
    }
}

#[no_mangle]
pub extern "C" fn ldiv(numer: c_long, denom: c_long) -> ldiv_t {
    ldiv_t {
        quot: numer / denom,
        rem: numer % denom,
    }
}


#[no_mangle]
pub extern "C" fn pow(x: c_double, y: c_double) -> c_double {
    pow_impl_f64(x, y)
}

#[no_mangle]
pub extern "C" fn powf(x: c_float, y: c_float) -> c_float {
    pow_impl_f32(x, y)
}

#[no_mangle]
pub extern "C" fn sqrt(x: c_double) -> c_double {
    sqrt_impl_f64(x)
}

#[no_mangle]
pub extern "C" fn sqrtf(x: c_float) -> c_float {
    sqrt_impl_f32(x)
}

#[no_mangle]
pub extern "C" fn cbrt(x: c_double) -> c_double {
    if x == 0.0 { return 0.0; }
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    pow_impl_f64(x.abs(), 1.0 / 3.0) * sign
}

#[no_mangle]
pub extern "C" fn cbrtf(x: c_float) -> c_float {
    cbrt(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn exp(x: c_double) -> c_double {
    exp_impl_f64(x)
}

#[no_mangle]
pub extern "C" fn expf(x: c_float) -> c_float {
    exp_impl_f32(x)
}

#[no_mangle]
pub extern "C" fn exp2(x: c_double) -> c_double {
    pow_impl_f64(2.0, x)
}

#[no_mangle]
pub extern "C" fn exp2f(x: c_float) -> c_float {
    pow_impl_f32(2.0, x)
}

#[no_mangle]
pub extern "C" fn expm1(x: c_double) -> c_double {
    if x.abs() < 1e-5 {
        x + x * x / 2.0 + x * x * x / 6.0
    } else {
        exp_impl_f64(x) - 1.0
    }
}

#[no_mangle]
pub extern "C" fn expm1f(x: c_float) -> c_float {
    expm1(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn log(x: c_double) -> c_double {
    ln_impl_f64(x)
}

#[no_mangle]
pub extern "C" fn logf(x: c_float) -> c_float {
    ln_impl_f32(x)
}

#[no_mangle]
pub extern "C" fn log10(x: c_double) -> c_double {
    const LN10: f64 = 2.302585092994046;
    ln_impl_f64(x) / LN10
}

#[no_mangle]
pub extern "C" fn log10f(x: c_float) -> c_float {
    const LN10: f32 = 2.302585092994046f32;
    ln_impl_f32(x) / LN10
}

#[no_mangle]
pub extern "C" fn log2(x: c_double) -> c_double {
    const LN2: f64 = 0.693147180559945309417232121458;
    ln_impl_f64(x) / LN2
}

#[no_mangle]
pub extern "C" fn log2f(x: c_float) -> c_float {
    const LN2: f32 = 0.693147180559945309417232121458f32;
    ln_impl_f32(x) / LN2
}

#[no_mangle]
pub extern "C" fn log1p(x: c_double) -> c_double {
    if x.abs() < 1e-4 {
        x - x * x / 2.0 + x * x * x / 3.0
    } else {
        ln_impl_f64(1.0 + x)
    }
}

#[no_mangle]
pub extern "C" fn log1pf(x: c_float) -> c_float {
    log1p(x as f64) as f32
}


#[no_mangle]
pub extern "C" fn sin(x: c_double) -> c_double {
    sin_impl_f64(x)
}

#[no_mangle]
pub extern "C" fn sinf(x: c_float) -> c_float {
    sin_impl_f32(x)
}

#[no_mangle]
pub extern "C" fn cos(x: c_double) -> c_double {
    cos_impl_f64(x)
}

#[no_mangle]
pub extern "C" fn cosf(x: c_float) -> c_float {
    cos_impl_f32(x)
}

#[no_mangle]
pub extern "C" fn tan(x: c_double) -> c_double {
    tan_impl_f64(x)
}

#[no_mangle]
pub extern "C" fn tanf(x: c_float) -> c_float {
    tan_impl_f32(x)
}

#[no_mangle]
pub extern "C" fn asin(x: c_double) -> c_double {
    if x < -1.0 || x > 1.0 { return f64::NAN; }
    if x.abs() == 1.0 {
        const PI_2: f64 = 1.57079632679489661923;
        return PI_2 * x;
    }
    atan_impl_f64(x / sqrt_impl_f64(1.0 - x * x))
}

#[no_mangle]
pub extern "C" fn asinf(x: c_float) -> c_float {
    asin(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn acos(x: c_double) -> c_double {
    if x < -1.0 || x > 1.0 { return f64::NAN; }
    const PI_2: f64 = 1.57079632679489661923;
    PI_2 - asin(x)
}

#[no_mangle]
pub extern "C" fn acosf(x: c_float) -> c_float {
    acos(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn atan(x: c_double) -> c_double {
    atan_impl_f64(x)
}

#[no_mangle]
pub extern "C" fn atanf(x: c_float) -> c_float {
    atan_impl_f32(x)
}

#[no_mangle]
pub extern "C" fn atan2(y: c_double, x: c_double) -> c_double {
    const PI: f64 = 3.14159265358979323846;
    const PI_2: f64 = 1.57079632679489661923;

    if x.is_nan() || y.is_nan() { return f64::NAN; }

    if x > 0.0 {
        atan_impl_f64(y / x)
    } else if x < 0.0 && y >= 0.0 {
        atan_impl_f64(y / x) + PI
    } else if x < 0.0 && y < 0.0 {
        atan_impl_f64(y / x) - PI
    } else if x == 0.0 && y > 0.0 {
        PI_2
    } else if x == 0.0 && y < 0.0 {
        -PI_2
    } else {
        0.0  // x == 0 && y == 0
    }
}

#[no_mangle]
pub extern "C" fn atan2f(y: c_float, x: c_float) -> c_float {
    atan2(y as f64, x as f64) as f32
}


#[no_mangle]
pub extern "C" fn sinh(x: c_double) -> c_double {
    if x.abs() > 20.0 {
        let sign = if x < 0.0 { -1.0 } else { 1.0 };
        return sign * exp_impl_f64(x.abs()) / 2.0;
    }
    let ex = exp_impl_f64(x);
    let emx = exp_impl_f64(-x);
    (ex - emx) / 2.0
}

#[no_mangle]
pub extern "C" fn sinhf(x: c_float) -> c_float {
    sinh(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn cosh(x: c_double) -> c_double {
    if x.abs() > 20.0 {
        return exp_impl_f64(x.abs()) / 2.0;
    }
    let ex = exp_impl_f64(x);
    let emx = exp_impl_f64(-x);
    (ex + emx) / 2.0
}

#[no_mangle]
pub extern "C" fn coshf(x: c_float) -> c_float {
    cosh(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn tanh(x: c_double) -> c_double {
    if x > 20.0 { return 1.0; }
    if x < -20.0 { return -1.0; }
    sinh(x) / cosh(x)
}

#[no_mangle]
pub extern "C" fn tanhf(x: c_float) -> c_float {
    tanh(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn asinh(x: c_double) -> c_double {
    ln_impl_f64(x + sqrt_impl_f64(x * x + 1.0))
}

#[no_mangle]
pub extern "C" fn asinhf(x: c_float) -> c_float {
    asinh(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn acosh(x: c_double) -> c_double {
    if x < 1.0 { return f64::NAN; }
    ln_impl_f64(x + sqrt_impl_f64(x * x - 1.0))
}

#[no_mangle]
pub extern "C" fn acoshf(x: c_float) -> c_float {
    acosh(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn atanh(x: c_double) -> c_double {
    if x.abs() >= 1.0 { return f64::NAN; }
    0.5 * ln_impl_f64((1.0 + x) / (1.0 - x))
}

#[no_mangle]
pub extern "C" fn atanhf(x: c_float) -> c_float {
    atanh(x as f64) as f32
}


#[no_mangle]
pub extern "C" fn ceil(x: c_double) -> c_double {
    let trunc = x as i64 as f64;
    if x > 0.0 && x > trunc {
        trunc + 1.0
    } else {
        trunc
    }
}

#[no_mangle]
pub extern "C" fn ceilf(x: c_float) -> c_float {
    ceil(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn floor(x: c_double) -> c_double {
    let trunc = x as i64 as f64;
    if x < trunc {
        trunc - 1.0
    } else {
        trunc
    }
}

#[no_mangle]
pub extern "C" fn floorf(x: c_float) -> c_float {
    floor(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn round(x: c_double) -> c_double {
    if x >= 0.0 {
        floor(x + 0.5)
    } else {
        ceil(x - 0.5)
    }
}

#[no_mangle]
pub extern "C" fn roundf(x: c_float) -> c_float {
    round(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn trunc(x: c_double) -> c_double {
    x as i64 as f64
}

#[no_mangle]
pub extern "C" fn truncf(x: c_float) -> c_float {
    x as i32 as f32
}

#[no_mangle]
pub extern "C" fn fmod(x: c_double, y: c_double) -> c_double {
    if y == 0.0 { return f64::NAN; }
    x - trunc(x / y) * y
}

#[no_mangle]
pub extern "C" fn fmodf(x: c_float, y: c_float) -> c_float {
    fmod(x as f64, y as f64) as f32
}

#[no_mangle]
pub extern "C" fn remainder(x: c_double, y: c_double) -> c_double {
    if y == 0.0 { return f64::NAN; }
    x - round(x / y) * y
}

#[no_mangle]
pub extern "C" fn remainderf(x: c_float, y: c_float) -> c_float {
    remainder(x as f64, y as f64) as f32
}

#[no_mangle]
pub extern "C" fn modf(x: c_double, iptr: *mut c_double) -> c_double {
    unsafe {
        let int_part = trunc(x);
        let frac_part = x - int_part;
        if !iptr.is_null() {
            *iptr = int_part;
        }
        frac_part
    }
}

#[no_mangle]
pub extern "C" fn modff(x: c_float, iptr: *mut c_float) -> c_float {
    unsafe {
        let int_part = truncf(x);
        let frac_part = x - int_part;
        if !iptr.is_null() {
            *iptr = int_part;
        }
        frac_part
    }
}


#[no_mangle]
pub extern "C" fn frexp(x: c_double, exp: *mut c_int) -> c_double {
    unsafe {
        if x == 0.0 {
            if !exp.is_null() {
                *exp = 0;
            }
            return 0.0;
        }
        let bits = x.to_bits();
        let exponent = ((bits >> 52) & 0x7FF) as i32 - 1022;
        let mantissa = f64::from_bits((bits & 0x800FFFFFFFFFFFFF) | 0x3FE0000000000000);
        if !exp.is_null() {
            *exp = exponent;
        }
        mantissa
    }
}

#[no_mangle]
pub extern "C" fn frexpf(x: c_float, exp: *mut c_int) -> c_float {
    unsafe {
        if x == 0.0 {
            if !exp.is_null() {
                *exp = 0;
            }
            return 0.0;
        }
        let bits = x.to_bits();
        let exponent = ((bits >> 23) & 0xFF) as i32 - 126;
        let mantissa = f32::from_bits((bits & 0x807FFFFF) | 0x3F000000);
        if !exp.is_null() {
            *exp = exponent;
        }
        mantissa
    }
}

#[no_mangle]
pub extern "C" fn ldexp(x: c_double, exp: c_int) -> c_double {
    x * pow_impl_f64(2.0, exp as f64)
}

#[no_mangle]
pub extern "C" fn ldexpf(x: c_float, exp: c_int) -> c_float {
    x * pow_impl_f32(2.0, exp as f32)
}

#[no_mangle]
pub extern "C" fn copysign(x: c_double, y: c_double) -> c_double {
    let x_bits = x.to_bits();
    let y_bits = y.to_bits();
    f64::from_bits((x_bits & 0x7FFFFFFFFFFFFFFF) | (y_bits & 0x8000000000000000))
}

#[no_mangle]
pub extern "C" fn copysignf(x: c_float, y: c_float) -> c_float {
    let x_bits = x.to_bits();
    let y_bits = y.to_bits();
    f32::from_bits((x_bits & 0x7FFFFFFF) | (y_bits & 0x80000000))
}

#[no_mangle]
pub extern "C" fn hypot(x: c_double, y: c_double) -> c_double {
    let ax = x.abs();
    let ay = y.abs();
    if ax > ay {
        let ratio = ay / ax;
        ax * sqrt_impl_f64(1.0 + ratio * ratio)
    } else if ay > 0.0 {
        let ratio = ax / ay;
        ay * sqrt_impl_f64(1.0 + ratio * ratio)
    } else {
        0.0
    }
}

#[no_mangle]
pub extern "C" fn hypotf(x: c_float, y: c_float) -> c_float {
    hypot(x as f64, y as f64) as f32
}

#[no_mangle]
pub extern "C" fn fma(x: c_double, y: c_double, z: c_double) -> c_double {
    // Fused multiply-add: x*y + z
    // In real implementation would use hardware FMA if available
    x * y + z
}

#[no_mangle]
pub extern "C" fn fmaf(x: c_float, y: c_float, z: c_float) -> c_float {
    x * y + z
}


#[no_mangle]
pub extern "C" fn isnan(x: c_double) -> c_int {
    if x.is_nan() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn isinf(x: c_double) -> c_int {
    if x.is_infinite() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn isfinite(x: c_double) -> c_int {
    if x.is_finite() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn isnormal(x: c_double) -> c_int {
    if x.is_normal() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn signbit(x: c_double) -> c_int {
    if x.is_sign_negative() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn fpclassify(x: c_double) -> c_int {
    if x.is_nan() { 0 }  // FP_NAN
    else if x.is_infinite() { 1 }  // FP_INFINITE
    else if x == 0.0 { 2 }  // FP_ZERO
    else if x.is_subnormal() { 3 }  // FP_SUBNORMAL
    else { 4 }  // FP_NORMAL
}


#[no_mangle]
pub extern "C" fn fmin(x: c_double, y: c_double) -> c_double {
    if x.is_nan() { return y; }
    if y.is_nan() { return x; }
    if x < y { x } else { y }
}

#[no_mangle]
pub extern "C" fn fminf(x: c_float, y: c_float) -> c_float {
    if x.is_nan() { return y; }
    if y.is_nan() { return x; }
    if x < y { x } else { y }
}

#[no_mangle]
pub extern "C" fn fmax(x: c_double, y: c_double) -> c_double {
    if x.is_nan() { return y; }
    if y.is_nan() { return x; }
    if x > y { x } else { y }
}

#[no_mangle]
pub extern "C" fn fmaxf(x: c_float, y: c_float) -> c_float {
    if x.is_nan() { return y; }
    if y.is_nan() { return x; }
    if x > y { x } else { y }
}

#[no_mangle]
pub extern "C" fn fdim(x: c_double, y: c_double) -> c_double {
    if x > y { x - y } else { 0.0 }
}

#[no_mangle]
pub extern "C" fn fdimf(x: c_float, y: c_float) -> c_float {
    if x > y { x - y } else { 0.0 }
}


use core::sync::atomic::{AtomicU32, Ordering};
static RAND_SEED: AtomicU32 = AtomicU32::new(1);

#[no_mangle]
pub unsafe extern "C" fn rand() -> c_int {
    let old_seed = RAND_SEED.load(Ordering::Relaxed);
    let new_seed = old_seed.wrapping_mul(214013).wrapping_add(2531011);
    RAND_SEED.store(new_seed, Ordering::Relaxed);
    ((new_seed >> 16) & 0x7FFF) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn srand(seed: c_uint) {
    RAND_SEED.store(seed, Ordering::Relaxed);
}

#[no_mangle]
pub static HUGE_VAL_CONST: c_double = f64::INFINITY;

#[no_mangle]
pub static HUGE_VALF_CONST: c_float = f32::INFINITY;
