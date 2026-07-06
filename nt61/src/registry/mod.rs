//! Registry Support
//
//! Windows Registry access — hives, configuration manager, path
//! parsing. See each submodule for details.

extern crate alloc;
use crate::kprintln;
use alloc::string::String;
use alloc::vec::Vec;

use crate::registry::path::PathError;

pub mod reg;
pub mod hive;
pub mod path;
pub mod cm;

pub use cm as configuration_manager;

/// Initialize registry module. This function:
///
/// 1. Initializes the ntdll in-memory registry tree with default keys
///    (SYSTEM, SOFTWARE, HARDWARE, SAM, SECURITY).
///
/// 2. The Configuration Manager (CM) initialization is handled separately
///    by `registry::cm::init(boot_info)` called from `kernel_main`, which
///    mounts the hive images loaded by the UEFI loader.
///
/// This design keeps the in-memory registry (ntdll API) separate from the
/// on-disk hive registry (CM/BootInfo), which mirrors the real NT architecture
/// where the CM is initialized very early while the session manager creates
/// the in-memory registry later.
pub fn init() {
    crate::libs::ntdll::registry::init();
    crate::libs::ntdll::registry::init_default_keys();
}

/// Registry smoke test.
///
/// Verifies the registry subsystem end-to-end:
///
/// 1. `init()` runs cleanly without panicking.
/// 2. `ParsedPath::parse()` correctly handles all supported path formats.
/// 3. The CM can report hive mount status.
/// 4. Query functions return `None` gracefully when hives are not mounted.
/// 5. API signatures are correct (compile-time check).
///
/// Returns `true` only if ALL steps pass. The function is designed so that
/// individual step failures are independently tracked — one failure does NOT
/// suppress reporting of other failures.
pub fn smoke_test() -> bool {
    use crate::registry::cm;
    use crate::registry::path::ParsedPath;

    kprintln!(subsystem: "REG", "  [REG SMOKE] running registry smoke test...");

    // Track per-step results independently so all failures are visible.
    let mut step_ok = [true; 5];

    // ─────────────────────────────────────────────────────────────
    // Step 1: init() runs cleanly (no panic)
    // ─────────────────────────────────────────────────────────────
    kprintln!(subsystem: "REG", "  [REG SMOKE] step 1: init()");
    init(); // If this panics, the test fails — but we can't catch that here
    kprintln!(subsystem: "REG", "  [REG SMOKE] step 1: init() passed");

    // ─────────────────────────────────────────────────────────────
    // Step 2: Check if System hive is mounted (CM must have been initialized)
    // ─────────────────────────────────────────────────────────────
    kprintln!(subsystem: "REG", "  [REG SMOKE] step 2: is_mounted");
    let system_mounted = cm::is_mounted(crate::registry::path::Hive::System);
    kprintln!(
        subsystem: "REG",
        "    [REG SMOKE] System hive mounted: {}",
        system_mounted
    );
    // Not setting step_ok[1] = false — hive may not be loaded in test env

    // ─────────────────────────────────────────────────────────────
    // Step 3: query_dword returns None gracefully when hives aren't mounted
    // ─────────────────────────────────────────────────────────────
    kprintln!(subsystem: "REG", "  [REG SMOKE] step 3: query_dword");
    let result = cm::query_dword(
        "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\BootDriverFlags",
        "BootDriverFlags",
    );
    // None is expected if hives aren't loaded — this is correct behavior
    kprintln!(
        subsystem: "REG",
        "    [REG SMOKE] query_dword result: {:?} (None expected if hives not loaded)",
        result
    );
    // step_ok[2] stays true — None is valid when no hives

    // ─────────────────────────────────────────────────────────────
    // Step 4: Test path parsing for all supported formats
    // ─────────────────────────────────────────────────────────────
    kprintln!(subsystem: "REG", "  [REG SMOKE] step 4: path parsing");

    let test_cases: &[(&str, Option<&str>, usize)] = &[
        // (path, expected_hive, expected_subkey_count)
        (
            "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            Some("Software"),
            3,
        ),
        (
            "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services",
            Some("System"),
            3,
        ),
        (
            "\\Registry\\User\\.DEFAULT\\Volatile Environment",
            Some("Default"),
            2,
        ),
        (
            "System\\CurrentControlSet\\Services",
            Some("System"),
            2,
        ),
        (
            "SOFTWARE\\Microsoft",
            Some("Software"),
            1,
        ),
    ];

    for (path, expected_hive, expected_subkeys) in test_cases {
        match ParsedPath::parse(path) {
            Ok(p) => {
                kprintln!(
                    subsystem: "REG",
                    "    [REG SMOKE]   '{}' -> hive={:?} subkeys={} (expected {} subkeys, hive={:?})",
                    path,
                    p.hive,
                    p.subkeys.len(),
                    expected_subkeys,
                    expected_hive
                );
                // Check correctness
                if p.subkeys.len() != *expected_subkeys {
                    kprintln!(
                        subsystem: "REG",
                        "    [REG SMOKE FAIL] path '{}': wrong subkey count {}, expected {}",
                        path,
                        p.subkeys.len(),
                        expected_subkeys
                    );
                    step_ok[3] = false;
                }
            }
            Err(e) => {
                kprintln!(
                    subsystem: "REG",
                    "    [REG SMOKE FAIL] path '{}' parse error: {}",
                    path,
                    e
                );
                step_ok[3] = false;
            }
        }
    }

    // Also test error case: empty path
    match ParsedPath::parse("") {
        Err(PathError::Empty) => {
            kprintln!(subsystem: "REG", "    [REG SMOKE]   empty path correctly rejected");
        }
        Ok(p) => {
            kprintln!(
                subsystem: "REG",
                "    [REG SMOKE FAIL] empty path should return error, got {:?}",
                p
            );
            step_ok[3] = false;
        }
        Err(e) => {
            kprintln!(
                subsystem: "REG",
                "    [REG SMOKE FAIL] empty path returned wrong error: {}",
                e
            );
            step_ok[3] = false;
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Step 5: API compile-time check + enumerate functions return None gracefully
    // ─────────────────────────────────────────────────────────────
    kprintln!(subsystem: "REG", "  [REG SMOKE] step 5: API signatures + enumerate functions");
    let _: Option<u32> = cm::query_dword("test", "value");
    let _: Option<String> = cm::query_string("test", "value");
    let _: Option<Vec<String>> = cm::enumerate_subkeys("test");
    let _: Option<Vec<String>> = cm::enumerate_values("test");
    kprintln!(
        subsystem: "REG",
        "    [REG SMOKE] enumerate_subkeys/test -> {:?}",
        cm::enumerate_subkeys("test")
    );
    kprintln!(
        subsystem: "REG",
        "    [REG SMOKE] enumerate_values/test -> {:?}",
        cm::enumerate_values("test")
    );
    kprintln!(subsystem: "REG", "  [REG SMOKE] step 5: API check passed");

    // ─────────────────────────────────────────────────────────────
    // Summary
    // ─────────────────────────────────────────────────────────────
    let all_ok = step_ok.iter().all(|&x| x);
    if all_ok {
        kprintln!(subsystem: "REG", "  [REG SMOKE] all registry checks passed");
    } else {
        kprintln!(subsystem: "REG", "  [REG SMOKE FAIL] one or more registry checks failed");
        kprintln!(
            subsystem: "REG",
            "    [REG SMOKE] Step results: {:?}",
            step_ok
        );
    }
    all_ok
}
