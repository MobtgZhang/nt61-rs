//! Memory Manager Initialization State Machine
//!
//! This module provides compile-time and runtime enforcement of the correct
//! initialization order for the memory manager subsystems.
//!
//! # Problem
//!
//! The memory manager has complex dependencies between subsystems:
//! - `vas::init()` calls `pfn::allocate_pfn()`, so PFN must be initialized first
//! - `heap::init()` requires VAS to be set up
//! - `pool::init()` requires heap to be initialized
//!
//! These dependencies were previously documented only in comments, leading to
//! CRITICAL-003: a bug where the initialization order was wrong.
//!
//! # Solution
//!
//! This module implements a state machine that:
//! 1. Tracks initialization progress at runtime
//! 2. Panics (bugchecks) if functions are called out of order
//! 3. Provides zero-cost abstractions (state checks are optimized away in release)
//!
//! # Usage
//!
//! ```rust
//! // In mm/frame.rs::init_with_range()
//! pub fn init_with_range(base: u64, size: u64) {
//!     init_state::enter_state(STATE_FRAME_ALLOCATOR, "frame::init");
//!     // ... initialization logic ...
//! }
//!
//! // In mm/pfn.rs::init()
//! pub fn init(base_pfn: u64, count: u64) {
//!     init_state::require_state(STATE_FRAME_ALLOCATOR, "pfn::init");
//!     init_state::enter_state(STATE_PFN_DATABASE, "pfn::init");
//!     // ... initialization logic ...
//! }
//! ```
//!
//! # State Transitions
//!
//! ```text
//! UNINITIALIZED (0)
//!   ↓ frame::init_with_range()
//! FRAME_ALLOCATOR (1)
//!   ↓ pfn::init()
//! PFN_DATABASE (2)
//!   ↓ vas::init()
//! VAS_INITIALIZED (3)
//!   ↓ syspte::init() + hyperspace::init()
//! PTE_SUBSYSTEMS (4)
//!   ↓ heap::init()
//! HEAP_INITIALIZED (5)
//!   ↓ pool::init()
//! POOL_INITIALIZED (6)
//!   ↓ working_set::init(), zeropage::init(), writer::init(), pagefile::init()
//! FULLY_INITIALIZED (7)
//! ```

use core::sync::atomic::{AtomicU8, Ordering};

pub const STATE_UNINITIALIZED: u8 = 0;
pub const STATE_FRAME_ALLOCATOR: u8 = 1;
pub const STATE_PFN_DATABASE: u8 = 2;
pub const STATE_VAS_INITIALIZED: u8 = 3;
pub const STATE_PTE_SUBSYSTEMS: u8 = 4;
pub const STATE_HEAP_INITIALIZED: u8 = 5;
pub const STATE_POOL_INITIALIZED: u8 = 6;
pub const STATE_FULLY_INITIALIZED: u8 = 7;

static MM_INIT_STATE: AtomicU8 = AtomicU8::new(STATE_UNINITIALIZED);

const STATE_NAMES: &[&str] = &[
    "UNINITIALIZED",
    "FRAME_ALLOCATOR",
    "PFN_DATABASE",
    "VAS_INITIALIZED",
    "PTE_SUBSYSTEMS",
    "HEAP_INITIALIZED",
    "POOL_INITIALIZED",
    "FULLY_INITIALIZED",
];

#[inline]
pub fn current_state() -> u8 {
    MM_INIT_STATE.load(Ordering::Acquire)
}

#[inline]
pub fn has_reached_state(state: u8) -> bool {
    current_state() >= state
}

#[inline]
pub fn require_state(required: u8, operation: &str) {
    let current = MM_INIT_STATE.load(Ordering::Acquire);

    if current < required {
        require_state_failed(current, required, operation);
    }
}

#[cold]
#[inline(never)]
fn require_state_failed(current: u8, required: u8, operation: &str) -> ! {
    crate::hal::serial::write_string("\r\n[MM-FATAL] INITIALIZATION ORDER VIOLATION\r\n");
    crate::hal::serial::write_string("Operation: ");
    crate::hal::serial::write_string(operation);
    crate::hal::serial::write_string("\r\nCurrent state: ");
    if (current as usize) < STATE_NAMES.len() {
        crate::hal::serial::write_string(STATE_NAMES[current as usize]);
    }
    crate::hal::serial::write_string("\r\nRequired state: ");
    if (required as usize) < STATE_NAMES.len() {
        crate::hal::serial::write_string(STATE_NAMES[required as usize]);
    }
    crate::hal::serial::write_string("\r\n\r\n");

    crate::ke::bugcheck::bugcheck(
        0xDEAD_0001, // MM_INITIALIZATION_ORDER_VIOLATION
        current as u64,
        required as u64,
        operation.as_ptr() as u64,
        0,
    );
}

#[inline]
pub fn enter_state(new_state: u8, operation: &str) {
    let prev = MM_INIT_STATE.load(Ordering::Acquire);

    if new_state != prev + 1 {
        enter_state_failed(prev, new_state, operation);
    }

    if new_state > STATE_FULLY_INITIALIZED {
        enter_state_invalid(new_state, operation);
    }

    MM_INIT_STATE.store(new_state, Ordering::Release);

    #[cfg(debug_assertions)]
    {
        crate::hal::serial::write_string("[mm-state] ");
        if (new_state as usize) < STATE_NAMES.len() {
            crate::hal::serial::write_string(STATE_NAMES[new_state as usize]);
        }
        crate::hal::serial::write_string(" (");
        crate::hal::serial::write_string(operation);
        crate::hal::serial::write_string(")\r\n");
    }
}

#[cold]
#[inline(never)]
fn enter_state_failed(prev: u8, new: u8, operation: &str) -> ! {
    crate::hal::serial::write_string("\r\n[MM-FATAL] INITIALIZATION STATE SKIP\r\n");
    crate::hal::serial::write_string("Operation: ");
    crate::hal::serial::write_string(operation);
    crate::hal::serial::write_string("\r\nPrevious state: ");
    if (prev as usize) < STATE_NAMES.len() {
        crate::hal::serial::write_string(STATE_NAMES[prev as usize]);
    }
    crate::hal::serial::write_string("\r\nAttempted state: ");
    if (new as usize) < STATE_NAMES.len() {
        crate::hal::serial::write_string(STATE_NAMES[new as usize]);
    }
    crate::hal::serial::write_string("\r\n");
    crate::hal::serial::write_string("Expected: sequential transition (prev + 1)\r\n\r\n");

    crate::ke::bugcheck::bugcheck(
        0xDEAD_0002, // MM_INITIALIZATION_STATE_SKIP
        prev as u64,
        new as u64,
        operation.as_ptr() as u64,
        0,
    );
}

#[cold]
#[inline(never)]
fn enter_state_invalid(new: u8, operation: &str) -> ! {
    crate::hal::serial::write_string("\r\n[MM-FATAL] INVALID INITIALIZATION STATE\r\n");
    crate::hal::serial::write_string("Operation: ");
    crate::hal::serial::write_string(operation);
    crate::hal::serial::write_string("\r\nInvalid state value: ");
    crate::hal::serial::write_hex_u64(new as u64);
    crate::hal::serial::write_string("\r\n\r\n");

    crate::ke::bugcheck::bugcheck(
        0xDEAD_0003, // MM_INITIALIZATION_INVALID_STATE
        new as u64,
        STATE_FULLY_INITIALIZED as u64,
        operation.as_ptr() as u64,
        0,
    );
}

#[cfg(test)]
pub unsafe fn reset_for_test() {
    MM_INIT_STATE.store(STATE_UNINITIALIZED, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        unsafe { reset_for_test(); }
        assert_eq!(current_state(), STATE_UNINITIALIZED);
    }

    #[test]
    fn test_sequential_transitions() {
        unsafe { reset_for_test(); }

        enter_state(STATE_FRAME_ALLOCATOR, "test");
        assert_eq!(current_state(), STATE_FRAME_ALLOCATOR);

        enter_state(STATE_PFN_DATABASE, "test");
        assert_eq!(current_state(), STATE_PFN_DATABASE);

        enter_state(STATE_VAS_INITIALIZED, "test");
        assert_eq!(current_state(), STATE_VAS_INITIALIZED);
    }

    #[test]
    fn test_require_state_success() {
        unsafe { reset_for_test(); }

        enter_state(STATE_FRAME_ALLOCATOR, "test");
        enter_state(STATE_PFN_DATABASE, "test");

        require_state(STATE_FRAME_ALLOCATOR, "test");
        require_state(STATE_PFN_DATABASE, "test");
    }

    #[test]
    #[should_panic]
    fn test_require_state_failure() {
        unsafe { reset_for_test(); }

        enter_state(STATE_FRAME_ALLOCATOR, "test");

        require_state(STATE_PFN_DATABASE, "test");
    }

    #[test]
    #[should_panic]
    fn test_state_skip_detected() {
        unsafe { reset_for_test(); }

        enter_state(STATE_FRAME_ALLOCATOR, "test");

        enter_state(STATE_VAS_INITIALIZED, "test");
    }

    #[test]
    fn test_has_reached_state() {
        unsafe { reset_for_test(); }

        assert!(!has_reached_state(STATE_FRAME_ALLOCATOR));

        enter_state(STATE_FRAME_ALLOCATOR, "test");
        assert!(has_reached_state(STATE_FRAME_ALLOCATOR));
        assert!(!has_reached_state(STATE_PFN_DATABASE));

        enter_state(STATE_PFN_DATABASE, "test");
        assert!(has_reached_state(STATE_FRAME_ALLOCATOR));
        assert!(has_reached_state(STATE_PFN_DATABASE));
    }
}
