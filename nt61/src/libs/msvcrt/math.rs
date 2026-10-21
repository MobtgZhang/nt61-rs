//! Mathematical Functions
//!
//! Implements standard C math library functions with hardware acceleration where possible.

use super::types::*;

fn sqrt_impl_f64(x: f64) -> f64 {
    crate::arch::sqrt_f64(x)
}

fn sqrt_impl_f32(x: f32) -> f32 {
    crate::arch::sqrt_f32(x)
}

fn ln_impl_f64(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::NEG_INFINITY;
    }
    if x == 1.0 {
        return 0.0;
    }

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
            if term.abs() < 1e-16 {
                break;
            }
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
    if x > 700.0 {
        return f64::INFINITY;
    }
    if x < -700.0 {
        return 0.0;
    }

    const LN2: f64 = 0.693147180559945309417232121458;
    let k_f = x / LN2;
    let k = if k_f >= 0.0 { k_f + 0.5 } else { k_f - 0.5 } as i32 as f64;
    let r = x - k * LN2;

    let mut result = 1.0;
    let mut term = 1.0;
    for i in 1..25 {
        term *= r / (i as f64);
        result += term;
        if term.abs() < 1e-16 {
            break;
        }
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
    if y == 0.0 {
        return 1.0;
    }
    if x == 0.0 {
        if y > 0.0 {
            return 0.0;
        }
        return f64::INFINITY;
    }
    if x == 1.0 {
        return 1.0;
    }
    if y == 1.0 {
        return x;
    }
    if y == 2.0 {
        return x * x;
    }
    if y == 0.5 {
        return sqrt_impl_f64(x);
    }

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

    if x < 0.0 {
        return f64::NAN;
    }

    exp_impl_f64(y * ln_impl_f64(x))
}

fn pow_impl_f32(x: f32, y: f32) -> f32 {
    pow_impl_f64(x as f64, y as f64) as f32
}

fn sin_impl_f64(mut x: f64) -> f64 {
    const PI: f64 = 3.14159265358979323846;
    const PI2: f64 = 6.28318530717958647692;

    x = x % PI2;
    if x > PI {
        x -= PI2;
    }
    if x < -PI {
        x += PI2;
    }

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
        if term.abs() < 1e-16 {
            break;
        }
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

    if x.is_nan() {
        return x;
    }
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
        if term.abs() < 1e-16 {
            break;
        }
    }

    result
}

fn atan_impl_f32(x: f32) -> f32 {
    atan_impl_f64(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn abs(n: CInt) -> CInt {
    if n < 0 {
        -n
    } else {
        n
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn labs(n: CLong) -> CLong {
    if n < 0 {
        -n
    } else {
        n
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn llabs(n: CLonglong) -> CLonglong {
    if n < 0 {
        -n
    } else {
        n
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fabs(x: CDouble) -> CDouble {
    if x < 0.0 {
        -x
    } else {
        x
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fabsf(x: CFloat) -> CFloat {
    if x < 0.0 {
        -x
    } else {
        x
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn div(numer: CInt, denom: CInt) -> div_t {
    div_t {
        quot: numer / denom,
        rem: numer % denom,
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn ldiv(numer: CLong, denom: CLong) -> ldiv_t {
    ldiv_t {
        quot: numer / denom,
        rem: numer % denom,
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn pow(x: CDouble, y: CDouble) -> CDouble {
    pow_impl_f64(x, y)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn powf(x: CFloat, y: CFloat) -> CFloat {
    pow_impl_f32(x, y)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sqrt(x: CDouble) -> CDouble {
    sqrt_impl_f64(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sqrtf(x: CFloat) -> CFloat {
    sqrt_impl_f32(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn cbrt(x: CDouble) -> CDouble {
    if x == 0.0 {
        return 0.0;
    }
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    pow_impl_f64(x.abs(), 1.0 / 3.0) * sign
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn cbrtf(x: CFloat) -> CFloat {
    cbrt(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn exp(x: CDouble) -> CDouble {
    exp_impl_f64(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn expf(x: CFloat) -> CFloat {
    exp_impl_f32(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn exp2(x: CDouble) -> CDouble {
    pow_impl_f64(2.0, x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn exp2f(x: CFloat) -> CFloat {
    pow_impl_f32(2.0, x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn expm1(x: CDouble) -> CDouble {
    if x.abs() < 1e-5 {
        x + x * x / 2.0 + x * x * x / 6.0
    } else {
        exp_impl_f64(x) - 1.0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn expm1f(x: CFloat) -> CFloat {
    expm1(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn log(x: CDouble) -> CDouble {
    ln_impl_f64(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn logf(x: CFloat) -> CFloat {
    ln_impl_f32(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn log10(x: CDouble) -> CDouble {
    const LN10: f64 = 2.302585092994046;
    ln_impl_f64(x) / LN10
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn log10f(x: CFloat) -> CFloat {
    const LN10: f32 = 2.302585092994046f32;
    ln_impl_f32(x) / LN10
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn log2(x: CDouble) -> CDouble {
    const LN2: f64 = 0.693147180559945309417232121458;
    ln_impl_f64(x) / LN2
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn log2f(x: CFloat) -> CFloat {
    const LN2: f32 = 0.693147180559945309417232121458f32;
    ln_impl_f32(x) / LN2
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn log1p(x: CDouble) -> CDouble {
    if x.abs() < 1e-4 {
        x - x * x / 2.0 + x * x * x / 3.0
    } else {
        ln_impl_f64(1.0 + x)
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn log1pf(x: CFloat) -> CFloat {
    log1p(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sin(x: CDouble) -> CDouble {
    sin_impl_f64(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sinf(x: CFloat) -> CFloat {
    sin_impl_f32(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn cos(x: CDouble) -> CDouble {
    cos_impl_f64(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn cosf(x: CFloat) -> CFloat {
    cos_impl_f32(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn tan(x: CDouble) -> CDouble {
    tan_impl_f64(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn tanf(x: CFloat) -> CFloat {
    tan_impl_f32(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn asin(x: CDouble) -> CDouble {
    if x < -1.0 || x > 1.0 {
        return f64::NAN;
    }
    if x.abs() == 1.0 {
        const PI_2: f64 = 1.57079632679489661923;
        return PI_2 * x;
    }
    atan_impl_f64(x / sqrt_impl_f64(1.0 - x * x))
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn asinf(x: CFloat) -> CFloat {
    asin(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn acos(x: CDouble) -> CDouble {
    if x < -1.0 || x > 1.0 {
        return f64::NAN;
    }
    const PI_2: f64 = 1.57079632679489661923;
    PI_2 - asin(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn acosf(x: CFloat) -> CFloat {
    acos(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn atan(x: CDouble) -> CDouble {
    atan_impl_f64(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn atanf(x: CFloat) -> CFloat {
    atan_impl_f32(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn atan2(y: CDouble, x: CDouble) -> CDouble {
    const PI: f64 = 3.14159265358979323846;
    const PI_2: f64 = 1.57079632679489661923;

    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }

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
        0.0 // x == 0 && y == 0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn atan2f(y: CFloat, x: CFloat) -> CFloat {
    atan2(y as f64, x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sinh(x: CDouble) -> CDouble {
    if x.abs() > 20.0 {
        let sign = if x < 0.0 { -1.0 } else { 1.0 };
        return sign * exp_impl_f64(x.abs()) / 2.0;
    }
    let ex = exp_impl_f64(x);
    let emx = exp_impl_f64(-x);
    (ex - emx) / 2.0
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sinhf(x: CFloat) -> CFloat {
    sinh(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn cosh(x: CDouble) -> CDouble {
    if x.abs() > 20.0 {
        return exp_impl_f64(x.abs()) / 2.0;
    }
    let ex = exp_impl_f64(x);
    let emx = exp_impl_f64(-x);
    (ex + emx) / 2.0
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn coshf(x: CFloat) -> CFloat {
    cosh(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn tanh(x: CDouble) -> CDouble {
    if x > 20.0 {
        return 1.0;
    }
    if x < -20.0 {
        return -1.0;
    }
    sinh(x) / cosh(x)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn tanhf(x: CFloat) -> CFloat {
    tanh(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn asinh(x: CDouble) -> CDouble {
    ln_impl_f64(x + sqrt_impl_f64(x * x + 1.0))
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn asinhf(x: CFloat) -> CFloat {
    asinh(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn acosh(x: CDouble) -> CDouble {
    if x < 1.0 {
        return f64::NAN;
    }
    ln_impl_f64(x + sqrt_impl_f64(x * x - 1.0))
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn acoshf(x: CFloat) -> CFloat {
    acosh(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn atanh(x: CDouble) -> CDouble {
    if x.abs() >= 1.0 {
        return f64::NAN;
    }
    0.5 * ln_impl_f64((1.0 + x) / (1.0 - x))
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn atanhf(x: CFloat) -> CFloat {
    atanh(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn ceil(x: CDouble) -> CDouble {
    let trunc = x as i64 as f64;
    if x > 0.0 && x > trunc {
        trunc + 1.0
    } else {
        trunc
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn ceilf(x: CFloat) -> CFloat {
    ceil(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn floor(x: CDouble) -> CDouble {
    let trunc = x as i64 as f64;
    if x < trunc {
        trunc - 1.0
    } else {
        trunc
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn floorf(x: CFloat) -> CFloat {
    floor(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn round(x: CDouble) -> CDouble {
    if x >= 0.0 {
        floor(x + 0.5)
    } else {
        ceil(x - 0.5)
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn roundf(x: CFloat) -> CFloat {
    round(x as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn trunc(x: CDouble) -> CDouble {
    x as i64 as f64
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn truncf(x: CFloat) -> CFloat {
    x as i32 as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fmod(x: CDouble, y: CDouble) -> CDouble {
    if y == 0.0 {
        return f64::NAN;
    }
    x - trunc(x / y) * y
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fmodf(x: CFloat, y: CFloat) -> CFloat {
    fmod(x as f64, y as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn remainder(x: CDouble, y: CDouble) -> CDouble {
    if y == 0.0 {
        return f64::NAN;
    }
    x - round(x / y) * y
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn remainderf(x: CFloat, y: CFloat) -> CFloat {
    remainder(x as f64, y as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn modf(x: CDouble, iptr: *mut CDouble) -> CDouble {
    unsafe {
        let int_part = trunc(x);
        let frac_part = x - int_part;
        if !iptr.is_null() {
            *iptr = int_part;
        }
        frac_part
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn modff(x: CFloat, iptr: *mut CFloat) -> CFloat {
    unsafe {
        let int_part = truncf(x);
        let frac_part = x - int_part;
        if !iptr.is_null() {
            *iptr = int_part;
        }
        frac_part
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn frexp(x: CDouble, exp: *mut CInt) -> CDouble {
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

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn frexpf(x: CFloat, exp: *mut CInt) -> CFloat {
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

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn ldexp(x: CDouble, exp: CInt) -> CDouble {
    x * pow_impl_f64(2.0, exp as f64)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn ldexpf(x: CFloat, exp: CInt) -> CFloat {
    x * pow_impl_f32(2.0, exp as f32)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn copysign(x: CDouble, y: CDouble) -> CDouble {
    let x_bits = x.to_bits();
    let y_bits = y.to_bits();
    f64::from_bits((x_bits & 0x7FFFFFFFFFFFFFFF) | (y_bits & 0x8000000000000000))
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn copysignf(x: CFloat, y: CFloat) -> CFloat {
    let x_bits = x.to_bits();
    let y_bits = y.to_bits();
    f32::from_bits((x_bits & 0x7FFFFFFF) | (y_bits & 0x80000000))
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn hypot(x: CDouble, y: CDouble) -> CDouble {
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

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn hypotf(x: CFloat, y: CFloat) -> CFloat {
    hypot(x as f64, y as f64) as f32
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fma(x: CDouble, y: CDouble, z: CDouble) -> CDouble {
    // Fused multiply-add: x*y + z
    // In real implementation would use hardware FMA if available
    x * y + z
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fmaf(x: CFloat, y: CFloat, z: CFloat) -> CFloat {
    x * y + z
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isnan(x: CDouble) -> CInt {
    if x.is_nan() {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isinf(x: CDouble) -> CInt {
    if x.is_infinite() {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isfinite(x: CDouble) -> CInt {
    if x.is_finite() {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn isnormal(x: CDouble) -> CInt {
    if x.is_normal() {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn signbit(x: CDouble) -> CInt {
    if x.is_sign_negative() {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fpclassify(x: CDouble) -> CInt {
    if x.is_nan() {
        0
    }
    // FP_NAN
    else if x.is_infinite() {
        1
    }
    // FP_INFINITE
    else if x == 0.0 {
        2
    }
    // FP_ZERO
    else if x.is_subnormal() {
        3
    }
    // FP_SUBNORMAL
    else {
        4
    } // FP_NORMAL
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fmin(x: CDouble, y: CDouble) -> CDouble {
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    if x < y {
        x
    } else {
        y
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fminf(x: CFloat, y: CFloat) -> CFloat {
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    if x < y {
        x
    } else {
        y
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fmax(x: CDouble, y: CDouble) -> CDouble {
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    if x > y {
        x
    } else {
        y
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fmaxf(x: CFloat, y: CFloat) -> CFloat {
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    if x > y {
        x
    } else {
        y
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fdim(x: CDouble, y: CDouble) -> CDouble {
    if x > y {
        x - y
    } else {
        0.0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn fdimf(x: CFloat, y: CFloat) -> CFloat {
    if x > y {
        x - y
    } else {
        0.0
    }
}

use core::sync::atomic::{AtomicU32, Ordering};
static RAND_SEED: AtomicU32 = AtomicU32::new(1);

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rand() -> CInt {
    let old_seed = RAND_SEED.load(Ordering::Relaxed);
    let new_seed = old_seed.wrapping_mul(214013).wrapping_add(2531011);
    RAND_SEED.store(new_seed, Ordering::Relaxed);
    ((new_seed >> 16) & 0x7FFF) as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn srand(seed: CUint) {
    RAND_SEED.store(seed, Ordering::Relaxed);
}

#[cfg_attr(not(test), no_mangle)]
pub static HUGE_VAL_CONST: CDouble = f64::INFINITY;

#[cfg_attr(not(test), no_mangle)]
pub static HUGE_VALF_CONST: CFloat = f32::INFINITY;
