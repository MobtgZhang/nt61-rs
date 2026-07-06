//! Testing Framework for Kernel Smoke Tests
//
//! Provides unified assertion macros, test statistics tracking, and
//! consistent test output formatting for all kernel subsystems.
//
//! ## Usage
//
//! ```rust
//! use crate::rtl::testing::TestStats;
//
//! pub fn smoke_test() -> bool {
//!     let mut stats = TestStats::new("MM");
//
//!     stats.test("PFN Database", test_pfn_database);
//!     stats.test("Kernel Heap", test_kernel_heap);
//!     stats.test("Kernel Pool", test_kernel_pool);
//
//!     stats.finish()
//! }
//! ```

use core::sync::atomic::{AtomicU32, Ordering};

/// Test result statistics for a subsystem
pub struct TestStats {
    /// Subsystem name for output formatting
    name: &'static str,
    /// Total number of tests run
    total: u32,
    /// Number of tests passed
    passed: u32,
    /// Number of tests failed
    failed: u32,
    /// Whether the test has started
    started: bool,
}

impl TestStats {
    /// Create a new TestStats for a subsystem
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            total: 0,
            passed: 0,
            failed: 0,
            started: false,
        }
    }

    /// Start the test suite (prints header)
    pub fn start(&mut self) {
        if !self.started {
            self.started = true;
            crate::boot_println!("========================================");
            crate::boot_println!("[{} SMOKE] Running {} smoke tests...", self.name, self.name);
            crate::boot_println!("========================================");
        }
    }

    /// Run a single test and record the result
    ///
    /// Returns the result of the test function (true = pass)
    pub fn test<F>(&mut self, name: &str, f: F) -> bool
    where
        F: Fn() -> bool,
    {
        self.start();

        let result = f();
        self.total += 1;

        if result {
            self.passed += 1;
            crate::boot_println!("  [{} SMOKE]   PASS: {}", self.name, name);
        } else {
            self.failed += 1;
            crate::boot_println!("  [{} SMOKE]   FAIL: {}", self.name, name);
        }

        result
    }

    /// Run a test with detailed failure information
    pub fn test_detailed(&mut self, name: &str, result: bool, details: &str) -> bool {
        self.start();

        self.total += 1;

        if result {
            self.passed += 1;
            crate::boot_println!("  [{} SMOKE]   PASS: {} - {}", self.name, name, details);
        } else {
            self.failed += 1;
            crate::boot_println!("  [{} SMOKE]   FAIL: {} - {}", self.name, name, details);
        }

        result
    }

    /// Finish the test suite and print summary
    ///
    /// Returns true if all tests passed
    pub fn finish(&self) -> bool {
        crate::boot_println!("========================================");
        crate::boot_println!(
            "[{} SMOKE] Results: {}/{} tests passed",
            self.name,
            self.passed,
            self.total
        );

        if self.failed == 0 {
            crate::boot_println!("[{} SMOKE] STATUS: ALL TESTS PASSED", self.name);
        } else {
            crate::boot_println!(
                "[{} SMOKE] STATUS: {}/{} TESTS FAILED",
                self.name,
                self.failed,
                self.total
            );
        }

        crate::boot_println!("========================================");

        self.failed == 0
    }

    /// Get total test count
    pub fn total(&self) -> u32 {
        self.total
    }

    /// Get passed test count
    pub fn passed(&self) -> u32 {
        self.passed
    }

    /// Get failed test count
    pub fn failed(&self) -> u32 {
        self.failed
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.total > 0
    }
}

/// Simple smoke test result aggregator
pub struct SmokeAggregator {
    /// Total subsystems
    total: u32,
    /// Passed subsystems
    passed: u32,
}

impl SmokeAggregator {
    /// Create a new aggregator
    pub fn new() -> Self {
        Self { total: 0, passed: 0 }
    }

    /// Record a subsystem test result
    pub fn record(&mut self, subsystem: &str, result: bool) {
        self.total += 1;
        if result {
            self.passed += 1;
            crate::boot_println!("[SMOKE]   PASS: {}", subsystem);
        } else {
            crate::boot_println!("[SMOKE]   FAIL: {}", subsystem);
        }
    }

    /// Finish aggregation and print summary
    pub fn finish(&self) -> bool {
        crate::boot_println!("========================================");
        crate::boot_println!(
            "[SMOKE] Subsystem Results: {}/{} passed",
            self.passed,
            self.total
        );

        if self.passed == self.total {
            crate::boot_println!("[SMOKE] STATUS: ALL SUBSYSTEM TESTS PASSED");
        } else {
            crate::boot_println!(
                "[SMOKE] STATUS: {}/{} SUBSYSTEM TESTS FAILED",
                self.total - self.passed,
                self.total
            );
        }

        crate::boot_println!("========================================");

        self.passed == self.total
    }

    /// Get total subsystem count
    pub fn total(&self) -> u32 {
        self.total
    }

    /// Get passed subsystem count
    pub fn passed(&self) -> u32 {
        self.passed
    }
}

impl Default for SmokeAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unified Assertion Macros
// ============================================================================

/// Assert a condition is true
///
/// Usage: `smoke_assert!(condition, "description of what failed");`
#[macro_export]
macro_rules! smoke_assert {
    ($cond:expr, $msg:expr) => {{
        if !($cond) {
            $crate::boot_println!(
                "  [SMOKE ASSERT FAIL] {} at {}:{}",
                $msg,
                core::file!(),
                core::line!()
            );
            return false;
        }
        true
    }};
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {{
        if !($cond) {
            $crate::boot_println!(
                "  [SMOKE ASSERT FAIL] {} at {}:{}",
                core::format_args!($fmt, $($arg)*),
                core::file!(),
                core::line!()
            );
            return false;
        }
        true
    }};
}

/// Assert two values are equal
///
/// Usage: `smoke_assert_eq!(actual, expected, "description");`
#[macro_export]
macro_rules! smoke_assert_eq {
    ($left:expr, $right:expr, $msg:expr) => {{
        let left_val = $left;
        let right_val = $right;
        if left_val != right_val {
            $crate::boot_println!(
                "  [SMOKE ASSERT FAIL] {}: {} != {} (expected {}) at {}:{}",
                $msg,
                left_val,
                right_val,
                right_val,
                core::file!(),
                core::line!()
            );
            return false;
        }
        true
    }};
}

/// Assert two values are not equal
///
/// Usage: `smoke_assert_ne!(actual, unexpected, "description");`
#[macro_export]
macro_rules! smoke_assert_ne {
    ($left:expr, $right:expr, $msg:expr) => {{
        let left_val = $left;
        let right_val = $right;
        if left_val == right_val {
            $crate::boot_println!(
                "  [SMOKE ASSERT FAIL] {}: {} == {} (expected not equal) at {}:{}",
                $msg,
                left_val,
                right_val,
                core::file!(),
                core::line!()
            );
            return false;
        }
        true
    }};
}

/// Assert a pointer is not null
///
/// Usage: `smoke_assert_ptr!(ptr, "pointer name");`
#[macro_export]
macro_rules! smoke_assert_ptr {
    ($ptr:expr, $msg:expr) => {{
        let ptr_val = $ptr;
        if ptr_val.is_null() {
            $crate::boot_println!(
                "  [SMOKE ASSERT FAIL] {} is NULL at {}:{}",
                $msg,
                core::file!(),
                core::line!()
            );
            return false;
        }
        true
    }};
    ($ptr:expr, $null_check:expr, $msg:expr) => {{
        let ptr_val = $ptr;
        if ptr_val.is_null() != $null_check {
            $crate::boot_println!(
                "  [SMOKE ASSERT FAIL] {} null_check={} failed at {}:{}",
                $msg,
                $null_check,
                core::file!(),
                core::line!()
            );
            return false;
        }
        if ptr_val.is_null() {
            $crate::boot_println!(
                "  [SMOKE ASSERT FAIL] {} is NULL at {}:{}",
                $msg,
                core::file!(),
                core::line!()
            );
            return false;
        }
        true
    }};
}

/// Assert a value is within a range
///
/// Usage: `smoke_assert_in_range!(value, min, max, "description");`
#[macro_export]
macro_rules! smoke_assert_in_range {
    ($val:expr, $min:expr, $max:expr, $msg:expr) => {{
        let val = $val;
        let min = $min;
        let max = $max;
        if val < min || val > max {
            $crate::boot_println!(
                "  [SMOKE ASSERT FAIL] {}: {} not in range [{}, {}] at {}:{}",
                $msg,
                val,
                min,
                max,
                core::file!(),
                core::line!()
            );
            return false;
        }
        true
    }};
}

// ============================================================================
// Test Counter for Aggregating Multiple Test Files
// ============================================================================

/// Global test counter for tracking test execution across modules
pub static SMOKE_TEST_COUNTER: AtomicU32 = AtomicU32::new(0);
pub static SMOKE_PASSED_COUNTER: AtomicU32 = AtomicU32::new(0);
pub static SMOKE_FAILED_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Reset all test counters
pub fn reset_counters() {
    SMOKE_TEST_COUNTER.store(0, Ordering::SeqCst);
    SMOKE_PASSED_COUNTER.store(0, Ordering::SeqCst);
    SMOKE_FAILED_COUNTER.store(0, Ordering::SeqCst);
}

/// Get current test count
pub fn test_count() -> u32 {
    SMOKE_TEST_COUNTER.load(Ordering::SeqCst)
}

/// Get current passed count
pub fn passed_count() -> u32 {
    SMOKE_PASSED_COUNTER.load(Ordering::SeqCst)
}

/// Get current failed count
pub fn failed_count() -> u32 {
    SMOKE_FAILED_COUNTER.load(Ordering::SeqCst)
}

/// Report a test result (for simple step-based tests)
pub fn report_test(name: &str, passed: bool) {
    let n = SMOKE_TEST_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;

    if passed {
        SMOKE_PASSED_COUNTER.fetch_add(1, Ordering::SeqCst);
        crate::boot_println!("  [SMOKE {:02}] PASS: {}", n, name);
    } else {
        SMOKE_FAILED_COUNTER.fetch_add(1, Ordering::SeqCst);
        crate::boot_println!("  [SMOKE {:02}] FAIL: {}", n, name);
    }
}

/// Print summary of all tests
pub fn print_summary() {
    let total = SMOKE_TEST_COUNTER.load(Ordering::SeqCst);
    let passed = SMOKE_PASSED_COUNTER.load(Ordering::SeqCst);
    let failed = SMOKE_FAILED_COUNTER.load(Ordering::SeqCst);

    crate::boot_println!("========================================");
    crate::boot_println!("[SMOKE] Total Tests: {}", total);
    crate::boot_println!("[SMOKE] Passed: {}", passed);
    crate::boot_println!("[SMOKE] Failed: {}", failed);

    if failed == 0 && total > 0 {
        crate::boot_println!("[SMOKE] STATUS: ALL TESTS PASSED");
    } else if failed > 0 {
        crate::boot_println!("[SMOKE] STATUS: {}/{} TESTS FAILED", failed, total);
    }

    crate::boot_println!("========================================");
}
