use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, AtomicI32, AtomicI64, AtomicPtr, Ordering};

use super::types::*;


fn sqrt_impl_f64(x: f64) -> f64 {
    if x < 0.0 { return f64::NAN; }
    if x == 0.0 { return 0.0; }
    let mut z = x;
    for _ in 0..10 {
        z = (z + x / z) * 0.5;
    }
    z
}

fn sqrt_impl_f32(x: f32) -> f32 {
    if x < 0.0 { return f32::NAN; }
    if x == 0.0 { return 0.0; }
    let mut z = x;
    for _ in 0..8 {
        z = (z + x / z) * 0.5;
    }
    z
}

fn pow_impl_f64(x: f64, y: f64) -> f64 {
    if y == 0.0 { return 1.0; }
    if x == 0.0 { return 0.0; }
    if y == 1.0 { return x; }
    if y == 2.0 { return x * x; }
    // For general case, use exp(y * ln(x))
    exp_impl_f64(y * ln_impl_f64(x))
}

fn pow_impl_f32(x: f32, y: f32) -> f32 {
    if y == 0.0 { return 1.0; }
    if x == 0.0 { return 0.0; }
    if y == 1.0 { return x; }
    if y == 2.0 { return x * x; }
    exp_impl_f32(y * ln_impl_f32(x))
}

fn ln_impl_f64(x: f64) -> f64 {
    if x <= 0.0 { return f64::NEG_INFINITY; }
    if x == 1.0 { return 0.0; }
    let mut result = 0.0;
    let mut term = (x - 1.0) / (x + 1.0);
    let term_squared = term * term;
    for i in 0..20 {
        result += term / (2 * i + 1) as f64;
        term *= term_squared;
    }
    result * 2.0
}

fn ln_impl_f32(x: f32) -> f32 {
    if x <= 0.0 { return f32::NEG_INFINITY; }
    if x == 1.0 { return 0.0; }
    let mut result = 0.0;
    let mut term = (x - 1.0) / (x + 1.0);
    let term_squared = term * term;
    for i in 0..15 {
        result += term / (2 * i + 1) as f32;
        term *= term_squared;
    }
    result * 2.0
}

fn exp_impl_f64(x: f64) -> f64 {
    let mut result = 1.0;
    let mut term = 1.0;
    for i in 1..20 {
        term *= x / i as f64;
        result += term;
    }
    result
}

fn exp_impl_f32(x: f32) -> f32 {
    let mut result = 1.0;
    let mut term = 1.0;
    for i in 1..15 {
        term *= x / i as f32;
        result += term;
    }
    result
}

fn sin_impl_f64(x: f64) -> f64 {
    let x = x % (2.0 * 3.14159265358979323846);
    let mut result = x;
    let mut term = x;
    for i in 1..10 {
        term *= -x * x / ((2 * i) * (2 * i + 1)) as f64;
        result += term;
    }
    result
}

fn sin_impl_f32(x: f32) -> f32 {
    let x = x % (2.0 * 3.14159265358979323846f32);
    let mut result = x;
    let mut term = x;
    for i in 1..8 {
        term *= -x * x / ((2 * i) * (2 * i + 1)) as f32;
        result += term;
    }
    result
}

fn cos_impl_f64(x: f64) -> f64 {
    sin_impl_f64(1.57079632679489661923 - x)
}

fn cos_impl_f32(x: f32) -> f32 {
    sin_impl_f32(1.57079632679489661923f32 - x)
}

fn f64_powi(x: f64, n: i32) -> f64 {
    if n == 0 { return 1.0; }
    if n == 1 { return x; }
    if n < 0 { return 1.0 / f64_powi(x, -n); }
    let mut result = 1.0;
    let mut base = x;
    let mut exp = n;
    while exp > 0 {
        if exp % 2 == 1 {
            result *= base;
        }
        base *= base;
        exp /= 2;
    }
    result
}

fn f32_powi(x: f32, n: i32) -> f32 {
    if n == 0 { return 1.0; }
    if n == 1 { return x; }
    if n < 0 { return 1.0 / f32_powi(x, -n); }
    let mut result = 1.0;
    let mut base = x;
    let mut exp = n;
    while exp > 0 {
        if exp % 2 == 1 {
            result *= base;
        }
        base *= base;
        exp /= 2;
    }
    result
}

fn f64_log2(x: f64) -> f64 {
    if x <= 0.0 { return f64::NEG_INFINITY; }
    if x == 1.0 { return 0.0; }
    let ln_2 = 0.693147180559945309417232121458;
    f64_ln(x) / ln_2
}

fn f32_log2(x: f32) -> f32 {
    if x <= 0.0 { return f32::NEG_INFINITY; }
    if x == 1.0 { return 0.0; }
    let ln_2 = 0.693147180559945309417232121458f32;
    f32_ln(x) / ln_2
}

fn f64_ln(x: f64) -> f64 {
    if x <= 0.0 { return f64::NEG_INFINITY; }
    if x == 1.0 { return 0.0; }
    let mut result = 0.0;
    let mut term = (x - 1.0) / (x + 1.0);
    let term_squared = term * term;
    for i in 0..20 {
        result += term / (2 * i + 1) as f64;
        term *= term_squared;
    }
    result * 2.0
}

fn f32_ln(x: f32) -> f32 {
    if x <= 0.0 { return f32::NEG_INFINITY; }
    if x == 1.0 { return 0.0; }
    let mut result = 0.0;
    let mut term = (x - 1.0) / (x + 1.0);
    let term_squared = term * term;
    for i in 0..15 {
        result += term / (2 * i + 1) as f32;
        term *= term_squared;
    }
    result * 2.0
}

fn f64_trunc(x: f64) -> f64 {
    if x >= 0.0 {
        let int_part = x as i64 as f64;
        if int_part <= x { int_part } else { int_part - 1.0 }
    } else {
        let int_part = x as i64 as f64;
        if int_part >= x { int_part } else { int_part + 1.0 }
    }
}

fn f32_trunc(x: f32) -> f32 {
    if x >= 0.0 {
        let int_part = x as i32 as f32;
        if int_part <= x { int_part } else { int_part - 1.0 }
    } else {
        let int_part = x as i32 as f32;
        if int_part >= x { int_part } else { int_part + 1.0 }
    }
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
    libm::pow(x, y)
}

#[no_mangle]
pub extern "C" fn powf(x: c_float, y: c_float) -> c_float {
    libm::powf(x, y)
}

#[no_mangle]
pub extern "C" fn sqrt(x: c_double) -> c_double {
    libm::sqrt(x)
}

#[no_mangle]
pub extern "C" fn sqrtf(x: c_float) -> c_float {
    libm::sqrtf(x)
}

#[no_mangle]
pub extern "C" fn exp(x: c_double) -> c_double {
    libm::exp(x)
}

#[no_mangle]
pub extern "C" fn expf(x: c_float) -> c_float {
    libm::expf(x)
}

#[no_mangle]
pub extern "C" fn exp2(x: c_double) -> c_double {
    libm::exp2(x)
}

#[no_mangle]
pub extern "C" fn exp2f(x: c_float) -> c_float {
    libm::exp2f(x)
}

#[no_mangle]
pub extern "C" fn log(x: c_double) -> c_double {
    libm::log(x)
}

#[no_mangle]
pub extern "C" fn logf(x: c_float) -> c_float {
    libm::logf(x)
}

#[no_mangle]
pub extern "C" fn log10(x: c_double) -> c_double {
    libm::log10(x)
}

#[no_mangle]
pub extern "C" fn log10f(x: c_float) -> c_float {
    libm::log10f(x)
}

#[no_mangle]
pub extern "C" fn log2(x: c_double) -> c_double {
    if x <= 0.0 {
        return f64::NEG_INFINITY;
    }
    f64_log2(x)
}

#[no_mangle]
pub extern "C" fn log2f(x: c_float) -> c_float {
    if x <= 0.0 {
        return f32::NEG_INFINITY;
    }
    f32_log2(x)
}


#[no_mangle]
pub extern "C" fn sin(x: c_double) -> c_double {
    libm::sin(x)
}

#[no_mangle]
pub extern "C" fn sinf(x: c_float) -> c_float {
    libm::sinf(x)
}

#[no_mangle]
pub extern "C" fn cos(x: c_double) -> c_double {
    libm::cos(x)
}

#[no_mangle]
pub extern "C" fn cosf(x: c_float) -> c_float {
    libm::cosf(x)
}

#[no_mangle]
pub extern "C" fn tan(x: c_double) -> c_double {
    libm::tan(x)
}

#[no_mangle]
pub extern "C" fn tanf(x: c_float) -> c_float {
    libm::tanf(x)
}

#[no_mangle]
pub extern "C" fn asin(x: c_double) -> c_double {
    libm::asin(x)
}

#[no_mangle]
pub extern "C" fn asinf(x: c_float) -> c_float {
    libm::asinf(x)
}

#[no_mangle]
pub extern "C" fn acos(x: c_double) -> c_double {
    libm::acos(x)
}

#[no_mangle]
pub extern "C" fn acosf(x: c_float) -> c_float {
    libm::acosf(x)
}

#[no_mangle]
pub extern "C" fn atan(x: c_double) -> c_double {
    libm::atan(x)
}

#[no_mangle]
pub extern "C" fn atanf(x: c_float) -> c_float {
    libm::atanf(x)
}

#[no_mangle]
pub extern "C" fn atan2(y: c_double, x: c_double) -> c_double {
    libm::atan2(y, x)
}

#[no_mangle]
pub extern "C" fn atan2f(y: c_float, x: c_float) -> c_float {
    libm::atan2f(y, x)
}


#[no_mangle]
pub extern "C" fn sinh(x: c_double) -> c_double {
    libm::sinh(x)
}

#[no_mangle]
pub extern "C" fn sinhf(x: c_float) -> c_float {
    libm::sinhf(x)
}

#[no_mangle]
pub extern "C" fn cosh(x: c_double) -> c_double {
    libm::cosh(x)
}

#[no_mangle]
pub extern "C" fn coshf(x: c_float) -> c_float {
    libm::coshf(x)
}

#[no_mangle]
pub extern "C" fn tanh(x: c_double) -> c_double {
    libm::tanh(x)
}

#[no_mangle]
pub extern "C" fn tanhf(x: c_float) -> c_float {
    libm::tanhf(x)
}


#[no_mangle]
pub extern "C" fn ceil(x: c_double) -> c_double {
    libm::ceil(x)
}

#[no_mangle]
pub extern "C" fn ceilf(x: c_float) -> c_float {
    libm::ceilf(x)
}

#[no_mangle]
pub extern "C" fn floor(x: c_double) -> c_double {
    libm::floor(x)
}

#[no_mangle]
pub extern "C" fn floorf(x: c_float) -> c_float {
    libm::floorf(x)
}

#[no_mangle]
pub extern "C" fn round(x: c_double) -> c_double {
    libm::round(x)
}

#[no_mangle]
pub extern "C" fn roundf(x: c_float) -> c_float {
    libm::roundf(x)
}

#[no_mangle]
pub extern "C" fn trunc(x: c_double) -> c_double {
    libm::trunc(x)
}

#[no_mangle]
pub extern "C" fn truncf(x: c_float) -> c_float {
    libm::truncf(x)
}

#[no_mangle]
pub extern "C" fn fmod(x: c_double, y: c_double) -> c_double {
    libm::fmod(x, y)
}

#[no_mangle]
pub extern "C" fn fmodf(x: c_float, y: c_float) -> c_float {
    libm::fmodf(x, y)
}

#[no_mangle]
pub extern "C" fn modf(x: c_double, iptr: *mut c_double) -> c_double {
    libm::modf(x, iptr)
}

#[no_mangle]
pub extern "C" fn modff(x: c_float, iptr: *mut c_float) -> c_float {
    libm::modff(x, iptr)
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
        let mantissa = f64::from_bits((bits & 0x800F_FFFF_FFFF_FFFF) | 0x3FE0_0000_0000_0000);
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
        let mantissa = f32::from_bits((bits & 0x807F_FFFF) | 0x3F00_0000);
        if !exp.is_null() {
            *exp = exponent;
        }
        mantissa
    }
}

#[no_mangle]
pub extern "C" fn ldexp(x: c_double, exp: c_int) -> c_double {
    libm::ldexp(x, exp)
}

#[no_mangle]
pub extern "C" fn ldexpf(x: c_float, exp: c_int) -> c_float {
    libm::ldexpf(x, exp)
}

#[no_mangle]
pub extern "C" fn copysign(x: c_double, y: c_double) -> c_double {
    libm::copysign(x, y)
}

#[no_mangle]
pub extern "C" fn copysignf(x: c_float, y: c_float) -> c_float {
    libm::copysignf(x, y)
}

#[no_mangle]
pub extern "C" fn hypot(x: c_double, y: c_double) -> c_double {
    libm::hypot(x, y)
}

#[no_mangle]
pub extern "C" fn hypotf(x: c_float, y: c_float) -> c_float {
    libm::hypotf(x, y)
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
pub extern "C" fn fmin(x: c_double, y: c_double) -> c_double {
    if x < y { x } else { y }
}

#[no_mangle]
pub extern "C" fn fminf(x: c_float, y: c_float) -> c_float {
    if x < y { x } else { y }
}

#[no_mangle]
pub extern "C" fn fmax(x: c_double, y: c_double) -> c_double {
    if x > y { x } else { y }
}

#[no_mangle]
pub extern "C" fn fmaxf(x: c_float, y: c_float) -> c_float {
    if x > y { x } else { y }
}


static RAND_SEED: AtomicU32 = AtomicU32::new(1);

#[no_mangle]
pub unsafe extern "C" fn rand() -> c_int {
    RAND_SEED = RAND_SEED.wrapping_mul(1103515245).wrapping_add(12345);
    ((RAND_SEED / 65536) % 32768) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn srand(seed: c_uint) {
    RAND_SEED = seed;
}

#[no_mangle]
pub static HUGE_VAL_CONST: c_double = f64::INFINITY;

#[no_mangle]
pub static HUGE_VALF_CONST: c_float = f32::INFINITY;
