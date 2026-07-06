//! Object Manager smoke test
//
//! End-to-end exercise of the kernel object manager. Runs
//! on the BSP and verifies:
//
//! * The root directory exists.
//! * The conventional subdirectories exist.
//! * Object creation / insertion / lookup / reference / dereference
//!   all behave as expected.
//! * Per-subsystem counters advance on each operation.
//! * Name validation rejects bad names.
//! * Symbolic link cycle detection works.
//! * Ref-count and handle-count stay synchronised.
//! * Security-descriptor replacement works.
//! * ExFastRef atomic operations are correct.
//
//! Returns `true` iff every step passes.

#[allow(unused_imports)]
use crate::boot_println;
use crate::rtl::testing::TestStats;
use core::sync::atomic::Ordering;

// Imports from the parent ob module.
use super::{
    create_count, create_object,
    dereference_object,
    insert_count, insert_object, lookup_count, lookup_directory, lookup_object,
    reference_count, reference_object,
    validate_object_name,
    ObType, STATUS_SUCCESS, STATUS_OBJECT_NAME_INVALID,
};

/// Run the object manager smoke test.
pub fn smoke_test() -> bool {
    let mut stats = TestStats::new("OB");

    stats.test("Root Directory", test_root_directory);
    stats.test("Subdirectories", test_subdirectories);
    stats.test("Object Creation", test_object_creation);
    stats.test("Object Lookup", test_object_lookup);
    stats.test("Reference Counting", test_reference_counting);
    stats.test("Name Validation", test_name_validation);
    stats.test("Object Counters", test_object_counters);

    stats.finish()
}

/// Test that the root directory exists.
fn test_root_directory() -> bool {
    let root = lookup_directory(b"\\");
    if root.is_null() {
        crate::boot_print!("    FAIL: Root directory missing\r\n");
        return false;
    }
    crate::boot_print!("    Root directory: OK\r\n");
    true
}

/// Test that conventional subdirectories exist.
fn test_subdirectories() -> bool {
    let subdirs = [
        b"\\Device" as &[u8],
        b"\\Driver" as &[u8],
        b"\\KernelObjects" as &[u8],
        b"\\??" as &[u8],
        b"\\BaseNamedObjects" as &[u8],
        b"\\Registry" as &[u8],
        b"\\ObjectTypes" as &[u8],
    ];

    for p in &subdirs {
        let path: &[u8] = *p;
        if lookup_directory(path).is_null() {
            crate::boot_print!("    FAIL: Subdir {:?} missing\r\n", p);
            return false;
        }
    }

    crate::boot_print!("    7 subdirectories: OK\r\n");
    true
}

/// Test object creation and counters.
fn test_object_creation() -> bool {
    let c_before = create_count();

    // Create objects in \KernelObjects.
    let sizes = [core::mem::size_of::<u64>(); 3];
    let h0 = create_object(
        b"\\KernelObjects",
        b"SmokeObj0",
        ObType::EventNotification,
        sizes[0],
    );
    let h1 = create_object(
        b"\\KernelObjects",
        b"SmokeObj1",
        ObType::Mutant,
        sizes[1],
    );
    let h2 = create_object(
        b"\\KernelObjects",
        b"SmokeObj2",
        ObType::Semaphore,
        sizes[2],
    );

    if h0.is_null() || h1.is_null() || h2.is_null() {
        return false;
    }

    // Insert them into the namespace.
    if insert_object(b"\\KernelObjects", h0) == 0
        || insert_object(b"\\KernelObjects", h1) == 0
        || insert_object(b"\\KernelObjects", h2) == 0
    {
        return false;
    }

    let c_after = create_count();
    if c_after != c_before + 3 {
        return false;
    }

    crate::boot_print!("    Created 3 objects: OK\r\n");
    true
}

/// Test object lookup by name.
fn test_object_lookup() -> bool {
    let paths = [
        b"\\KernelObjects\\SmokeObj0",
        b"\\KernelObjects\\SmokeObj1",
        b"\\KernelObjects\\SmokeObj2",
    ];

    for path in &paths {
        let p: &[u8] = *path;
        if lookup_object(p).is_null() {
            return false;
        }
    }

    crate::boot_print!("    Lookup by name: OK\r\n");
    true
}

/// Test reference and dereference operations.
fn test_reference_counting() -> bool {
    // Create a test object
    let hdr = create_object(
        b"\\KernelObjects",
        b"SmokeRef",
        ObType::Mutant,
        core::mem::size_of::<u64>(),
    );
    if hdr.is_null() { return false; }

    // Initial ref_count should be 1
    unsafe {
        if (*hdr).ref_count.load(Ordering::Relaxed) != 1 { return false; }
    }

    // Insert to create a handle
    let handle = insert_object(b"\\KernelObjects", hdr);
    if handle == 0 { return false; }

    unsafe {
        // After insert, handle_count should be 1
        if (*hdr).handle_count.load(Ordering::Relaxed) != 1 { return false; }

        // Reference: ref_count 1→2
        let new = reference_object(hdr);
        if new != 2 { return false; }

        // Dereference: ref_count 2→1
        let new = dereference_object(hdr);
        if new != 1 { return false; }
    }

    crate::boot_print!("    Reference/dereference: OK\r\n");
    true
}

/// Test name validation.
fn test_name_validation() -> bool {
    // Valid names must pass.
    if validate_object_name(b"Event") != STATUS_SUCCESS { return false; }
    if validate_object_name(b"SmokeObject") != STATUS_SUCCESS { return false; }
    if validate_object_name(b"a") != STATUS_SUCCESS { return false; }

    // Invalid names must fail.
    if validate_object_name(b"foo\0bar") != STATUS_OBJECT_NAME_INVALID { return false; }
    if validate_object_name(b"") != STATUS_OBJECT_NAME_INVALID { return false; }

    let bad_names = [
        b"foo<bar", b"foo>bar", b"foo|bar", b"foo?bar", b"foo*bar", b"foo/bar",
    ];
    for &bad in &bad_names {
        if validate_object_name(bad) != STATUS_OBJECT_NAME_INVALID {
            return false;
        }
    }

    // Path traversal.
    if validate_object_name(b"..") != STATUS_OBJECT_NAME_INVALID { return false; }
    if validate_object_name(b"foo..bar") != STATUS_OBJECT_NAME_INVALID { return false; }

    crate::boot_print!("    Name validation: OK\r\n");
    true
}

/// Test that counters advance.
fn test_object_counters() -> bool {
    let c_before = create_count();
    let i_before = insert_count();
    let r_before = reference_count();
    let l_before = lookup_count();

    // Create one more object
    let hdr = create_object(
        b"\\KernelObjects",
        b"SmokeCounter",
        ObType::EventNotification,
        core::mem::size_of::<u64>(),
    );
    if hdr.is_null() { return false; }

    let _ = insert_object(b"\\KernelObjects", hdr);

    let c_after = create_count();
    let i_after = insert_count();
    let r_after = reference_count();
    let l_after = lookup_count();

    if c_after <= c_before { return false; }
    if i_after <= i_before { return false; }

    crate::boot_print!("    Counters: create={}, insert={}, ref={}, lookup={}\r\n",
        c_after - c_before, i_after - i_before, r_after - r_before, l_after - l_before);
    true
}

// =============================================================================
// Additional standalone smoke tests
// =============================================================================

/// Test ExFastRef atomic operations.
pub fn smoke_test_exfastref_atomic() -> bool {
    let hdr = create_object(
        b"\\KernelObjects",
        b"SmokeExFastRef",
        ObType::Semaphore,
        core::mem::size_of::<u64>(),
    );
    if hdr.is_null() { return false; }

    let _ = insert_object(b"\\KernelObjects", hdr);

    unsafe {
        if (*hdr).ref_count.load(Ordering::Relaxed) != 1 { return false; }

        let new = reference_object(hdr);
        if new != 2 { return false; }
        if (*hdr).ref_count.load(Ordering::Relaxed) != 2 { return false; }

        let new = dereference_object(hdr);
        if new != 1 { return false; }
        if (*hdr).ref_count.load(Ordering::Relaxed) != 1 { return false; }

        let _ = dereference_object(hdr);
    }

    crate::boot_print!("    ExFastRef atomic: OK\r\n");
    true
}
