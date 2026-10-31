//! user32 — UTF-16 (LPCWSTR) string helpers
//!
//! Every W-suffixed Win32 API exchanges NUL-terminated UTF-16
//! strings. These helpers are the single conversion point shared
//! by the class, window, message and dialog modules.
//!
//! References:
//!   * MSDN Library "Windows 7" — Unicode (UTF-16) conventions
//!   * RFC 2781 — UTF-16 encoding

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Windows limits window / class names to 256 wide characters
/// (winuser.h class-name limits).
pub const MAX_STRING_CHARS: usize = 256;

/// Build a compile-time NUL-terminated UTF-16 array from a
/// plain string literal. The terminator is appended, so the
/// literal itself must not contain one.
#[macro_export]
macro_rules! utf16 {
    ($s:literal) => {{
        const BYTES: &[u8] = $s.as_bytes();
        const WIDE_LEN: usize = BYTES.len() + 1;
        const WIDE: [u16; WIDE_LEN] = {
            let mut out = [0u16; WIDE_LEN];
            let mut i = 0;
            while i < BYTES.len() {
                out[i] = BYTES[i] as u16;
                i += 1;
            }
            out
        };
        WIDE
    }};
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Read a NUL-terminated UTF-16 string, bounded by
/// MAX_STRING_CHARS so a missing terminator cannot run away.
pub unsafe fn units_of(ptr: *const u16) -> Vec<u16> {
    if ptr.is_null() {
        return Vec::new();
    }
    let mut units = Vec::new();
    let mut i = 0usize;
    while i < MAX_STRING_CHARS && *ptr.add(i) != 0 {
        units.push(*ptr.add(i));
        i += 1;
    }
    units
}

/// FNV-1a over UTF-16 code units. The kernel derives window
/// class atoms from this hash, mirroring how user32 hands out
/// string atoms for class names.
pub const fn fnv1a_hash(units: &[u16]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
    const FNV_PRIME: u32 = 0x0100_0193;
    let mut hash = FNV_OFFSET_BASIS;
    let mut i = 0;
    while i < units.len() {
        hash ^= units[i] as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// Convert UTF-16 code units into a Rust string for logging.
/// Unpaired surrogates decode to the Unicode replacement
/// character (U+FFFD) instead of failing the call.
pub fn to_utf8_lossy(units: &[u16]) -> String {
    const REPLACEMENT_CHAR: u32 = 0xFFFD;
    const SURROGATE_HIGH_FIRST: u16 = 0xD800;
    const SURROGATE_HIGH_LAST: u16 = 0xDBFF;
    const SURROGATE_LOW_FIRST: u16 = 0xDC00;
    const SURROGATE_LOW_LAST: u16 = 0xDFFF;
    const SURROGATE_BITS: u32 = 10;
    const SURROGATE_OFFSET: u32 = 0x1_0000;

    let mut out = String::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let unit = units[i];
        i += 1;
        let scalar = if (SURROGATE_HIGH_FIRST..=SURROGATE_HIGH_LAST).contains(&unit) {
            if i < units.len() && (SURROGATE_LOW_FIRST..=SURROGATE_LOW_LAST).contains(&units[i]) {
                let low = units[i];
                i += 1;
                SURROGATE_OFFSET
                    + (((unit - SURROGATE_HIGH_FIRST) as u32) << SURROGATE_BITS)
                    + (low - SURROGATE_LOW_FIRST) as u32
            } else {
                REPLACEMENT_CHAR
            }
        } else if (SURROGATE_LOW_FIRST..=SURROGATE_LOW_LAST).contains(&unit) {
            REPLACEMENT_CHAR
        } else {
            unit as u32
        };
        match char::from_u32(scalar) {
            Some(c) => out.push(c),
            None => out.push('\u{FFFD}'),
        }
    }
    out
}
