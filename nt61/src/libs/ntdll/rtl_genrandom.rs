//! rtl_gen_random / SystemFunction036
//!
//! The user-mode entry point for kernel CSPRNG output. NT 6.1
//! declares this in `ntsecapi.h` and exports it from both
//! `advapi32.dll` (as `SystemFunction036`) and `cryptbase.dll`
//! (as `rtl_gen_random`). We route both names to the same
//! kernel implementation.

use crate::crypto::csprng;

/// `rtl_gen_random` — fill `buffer` with `length` random bytes.
/// Returns TRUE on success, FALSE on failure.
#[no_mangle]
pub unsafe extern "C" fn rtl_gen_random(buffer: *mut u8, length: u32) -> i32 {
    csprng::rtl_gen_random(buffer, length)
}

/// `SystemFunction036` — the advapi32 alias for rtl_gen_random.
#[no_mangle]
pub unsafe extern "C" fn SystemFunction036(buffer: *mut u8, length: u32) -> i32 {
    csprng::rtl_gen_random(buffer, length)
}
