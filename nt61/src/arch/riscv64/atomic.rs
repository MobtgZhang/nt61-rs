//! RISC-V64 Atomic Operations
//!
//! Comprehensive atomic operations support:
//! - AMO (Atomic Memory Operation) instructions
//! - LR/SC (Load-Reserved/Store-Conditional)
//! - Memory ordering

use core::arch::asm;
use core::sync::atomic::Ordering;

/// Convert Rust Ordering to RISC-V fence bits
fn ordering_to_fence(order: Ordering) -> &'static str {
    match order {
        Ordering::Relaxed => "",
        Ordering::Acquire => ".aq",
        Ordering::Release => ".rl",
        Ordering::AcqRel | Ordering::SeqCst => ".aqrl",
        _ => "",
    }
}

/// Atomic compare-and-swap (64-bit)
#[inline]
pub fn atomic_cas_u64(ptr: *mut u64, old: u64, new: u64, order: Ordering) -> Result<u64, u64> {
    let result: u64;
    let success: u64;

    unsafe {
        match order {
            Ordering::Relaxed => {
                asm!(
                    "1:",
                    "lr.d {result}, ({ptr})",
                    "bne {result}, {old}, 2f",
                    "sc.d {success}, {new}, ({ptr})",
                    "bnez {success}, 1b",
                    "2:",
                    ptr = in(reg) ptr,
                    old = in(reg) old,
                    new = in(reg) new,
                    result = out(reg) result,
                    success = out(reg) success,
                    options(nostack)
                );
            }
            Ordering::Acquire => {
                asm!(
                    "1:",
                    "lr.d.aq {result}, ({ptr})",
                    "bne {result}, {old}, 2f",
                    "sc.d {success}, {new}, ({ptr})",
                    "bnez {success}, 1b",
                    "2:",
                    ptr = in(reg) ptr,
                    old = in(reg) old,
                    new = in(reg) new,
                    result = out(reg) result,
                    success = out(reg) success,
                    options(nostack)
                );
            }
            Ordering::Release => {
                asm!(
                    "1:",
                    "lr.d {result}, ({ptr})",
                    "bne {result}, {old}, 2f",
                    "sc.d.rl {success}, {new}, ({ptr})",
                    "bnez {success}, 1b",
                    "2:",
                    ptr = in(reg) ptr,
                    old = in(reg) old,
                    new = in(reg) new,
                    result = out(reg) result,
                    success = out(reg) success,
                    options(nostack)
                );
            }
            _ => {
                asm!(
                    "1:",
                    "lr.d.aq {result}, ({ptr})",
                    "bne {result}, {old}, 2f",
                    "sc.d.rl {success}, {new}, ({ptr})",
                    "bnez {success}, 1b",
                    "2:",
                    ptr = in(reg) ptr,
                    old = in(reg) old,
                    new = in(reg) new,
                    result = out(reg) result,
                    success = out(reg) success,
                    options(nostack)
                );
            }
        }
    }

    if success == 0 {
        Ok(result)
    } else {
        Err(result)
    }
}

/// Atomic swap (64-bit)
#[inline]
pub fn atomic_swap_u64(ptr: *mut u64, val: u64, order: Ordering) -> u64 {
    let result: u64;

    unsafe {
        match order {
            Ordering::Relaxed => {
                asm!("amoswap.d {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr,
                    val = in(reg) val,
                    result = out(reg) result,
                    options(nostack));
            }
            Ordering::Acquire => {
                asm!("amoswap.d.aq {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr,
                    val = in(reg) val,
                    result = out(reg) result,
                    options(nostack));
            }
            Ordering::Release => {
                asm!("amoswap.d.rl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr,
                    val = in(reg) val,
                    result = out(reg) result,
                    options(nostack));
            }
            _ => {
                asm!("amoswap.d.aqrl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr,
                    val = in(reg) val,
                    result = out(reg) result,
                    options(nostack));
            }
        }
    }

    result
}

/// Atomic add (64-bit)
#[inline]
pub fn atomic_add_u64(ptr: *mut u64, val: u64, order: Ordering) -> u64 {
    let result: u64;

    unsafe {
        match order {
            Ordering::Relaxed => {
                asm!("amoadd.d {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr,
                    val = in(reg) val,
                    result = out(reg) result,
                    options(nostack));
            }
            Ordering::Acquire => {
                asm!("amoadd.d.aq {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr,
                    val = in(reg) val,
                    result = out(reg) result,
                    options(nostack));
            }
            Ordering::Release => {
                asm!("amoadd.d.rl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr,
                    val = in(reg) val,
                    result = out(reg) result,
                    options(nostack));
            }
            _ => {
                asm!("amoadd.d.aqrl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr,
                    val = in(reg) val,
                    result = out(reg) result,
                    options(nostack));
            }
        }
    }

    result
}

/// Atomic AND (64-bit)
#[inline]
pub fn atomic_and_u64(ptr: *mut u64, val: u64, order: Ordering) -> u64 {
    let result: u64;

    unsafe {
        match order {
            Ordering::Relaxed => {
                asm!("amoand.d {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
            _ => {
                asm!("amoand.d.aqrl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
        }
    }

    result
}

/// Atomic OR (64-bit)
#[inline]
pub fn atomic_or_u64(ptr: *mut u64, val: u64, order: Ordering) -> u64 {
    let result: u64;

    unsafe {
        match order {
            Ordering::Relaxed => {
                asm!("amoor.d {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
            _ => {
                asm!("amoor.d.aqrl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
        }
    }

    result
}

/// Atomic XOR (64-bit)
#[inline]
pub fn atomic_xor_u64(ptr: *mut u64, val: u64, order: Ordering) -> u64 {
    let result: u64;

    unsafe {
        match order {
            Ordering::Relaxed => {
                asm!("amoxor.d {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
            _ => {
                asm!("amoxor.d.aqrl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
        }
    }

    result
}

/// Atomic max (64-bit signed)
#[inline]
pub fn atomic_max_i64(ptr: *mut i64, val: i64, order: Ordering) -> i64 {
    let result: i64;

    unsafe {
        match order {
            Ordering::Relaxed => {
                asm!("amomax.d {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
            _ => {
                asm!("amomax.d.aqrl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
        }
    }

    result
}

/// Atomic min (64-bit signed)
#[inline]
pub fn atomic_min_i64(ptr: *mut i64, val: i64, order: Ordering) -> i64 {
    let result: i64;

    unsafe {
        match order {
            Ordering::Relaxed => {
                asm!("amomin.d {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
            _ => {
                asm!("amomin.d.aqrl {result}, {val}, ({ptr})",
                    ptr = in(reg) ptr, val = in(reg) val, result = out(reg) result, options(nostack));
            }
        }
    }

    result
}

/// Memory fence
#[inline]
pub fn fence(predecessor: &str, successor: &str) {
    unsafe {
        match (predecessor, successor) {
            ("rw", "rw") => asm!("fence rw, rw", options(nostack)),
            ("r", "rw") => asm!("fence r, rw", options(nostack)),
            ("w", "w") => asm!("fence w, w", options(nostack)),
            _ => asm!("fence rw, rw", options(nostack)),
        }
    }
}

/// Full memory fence
#[inline]
pub fn fence_full() {
    unsafe {
        asm!("fence rw, rw", options(nostack));
    }
}

/// Instruction fence
#[inline]
pub fn fence_i() {
    unsafe {
        asm!("fence.i", options(nostack));
    }
}
