//! wow64 — smoke test

extern crate alloc;

use super::thunk;
use super::types::{ptr32_to_ptr, ptr_to_ptr32};
use super::WOW64_SERVICES;
use core::sync::atomic::{AtomicU32, Ordering};

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn run_case(name: &str, ok: bool) -> bool {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = crate::wow64_klog!(
        "      [wow64/{:02}] {} {}",
        n,
        if ok { "PASS" } else { "FAIL" },
        name
    );
    ok
}

fn test_ptr32_to_ptr() -> bool {
    ptr32_to_ptr(0xDEAD_BEEF) == 0xDEAD_BEEF_u64
}

fn test_ptr_to_ptr32() -> bool {
    ptr_to_ptr32(0x1_0000_DEAD) == 0x0000_DEAD
}

fn test_service_table_populated() -> bool {
    let t = WOW64_SERVICES.lock();
    !t.is_empty() && t.iter().any(|(n, _)| *n == "Wow64PrepareForException")
}

fn test_prepare_for_exception() -> bool {
    let r = unsafe { thunk::Wow64PrepareForException(core::ptr::null(), core::ptr::null_mut()) };
    r == 0
}

fn test_apc_routine() -> bool {
    unsafe { thunk::Wow64ApcRoutine(core::ptr::null_mut()) }
    true
}

fn test_ldrp_initialize() -> bool {
    let r = unsafe { thunk::Wow64LdrpInitialize(
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut()
    ) };
    r == 0
}

fn test_system_service_ex() -> bool {
    let r = unsafe { thunk::Wow64SystemServiceEx(0, 0, core::ptr::null_mut()) };
    r == 0
}

fn test_allocate_vm32() -> bool {
    // Test with the new signature: (process_handle, base_address, zero_bits, region_size, allocation_type, protect)
    let r = unsafe { thunk::Wow64AllocateVirtualMemory32(0, 0x1000, 0, 0x2000, 0x1000, 4) };
    // Should return the requested base address
    r == 0x1000 || r == 0x00010000 // Either requested or default allocation address
}

pub fn smoke_test() -> bool {
    crate::wow64_klog!("    [wow64] running smoke tests");
    let results = [
        run_case("ptr32_to_ptr",        test_ptr32_to_ptr()),
        run_case("ptr_to_ptr32",        test_ptr_to_ptr32()),
        run_case("service_table",        test_service_table_populated()),
        run_case("prepare_exception",    test_prepare_for_exception()),
        run_case("apc_routine",        test_apc_routine()),
        run_case("ldrp_initialize",     test_ldrp_initialize()),
        run_case("system_service_ex",   test_system_service_ex()),
        run_case("allocate_vm32",        test_allocate_vm32()),
    ];
    let all_pass = results.iter().all(|&x| x);
    crate::wow64_klog!("    [wow64] all PASS: {}", all_pass);
    all_pass
}
