//! wow64 — public WoW64 callback entry points
//
//! This module exports the public WoW64 callback functions that are
//! called from 32-bit code. These functions serve as the initial
//! entry points into the WoW64 layer and forward to the appropriate
//! internal implementation.
//
//! References:
//!   * geoffchappell.com — wow64 system service dispatching
//!   * ReactOS WoW64 implementation

use super::WOW64_SERVICES;

/// Register the WoW64 service table.
/// This populates the WOW64_SERVICES list for introspection/debugging.
pub fn register_services() {
    let mut t = WOW64_SERVICES.lock();
    t.push(("Wow64PrepareForException", 0x0000_DEAD_BEEF_0001));
    t.push(("Wow64ApcRoutine", 0x0000_DEAD_BEEF_0002));
    t.push(("Wow64LdrpInitialize", 0x0000_DEAD_BEEF_0003));
    t.push(("Wow64SystemServiceEx", 0x0000_DEAD_BEEF_0004));
    t.push(("Wow64AllocateVirtualMemory32", 0x0000_DEAD_BEEF_0005));
    t.push(("Wow64FreeVirtualMemory32", 0x0000_DEAD_BEEF_0006));
    t.push(("Wow64ReadVirtualMemory32", 0x0000_DEAD_BEEF_0007));
    t.push(("Wow64WriteVirtualMemory32", 0x0000_DEAD_BEEF_0008));
    t.push(("Wow64QueryInformationProcess", 0x0000_DEAD_BEEF_0009));
    t.push(("Wow64SetInformationThread", 0x0000_DEAD_BEEF_000A));
    crate::wow64_klog!("Registered {} WoW64 services", t.len());
}

/// `wow64_prepare_for_exception` — handle exception in WoW64 context.
/// Returns 0 on success, error code on failure.
pub unsafe extern "C" fn wow64_prepare_for_exception(
    exception_record: *const core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> i32 {
    crate::wow64_klog!(
        "Wow64PrepareForException er={:p} ctx={:p}",
        exception_record,
        context
    );
    // Forward to the APC/exception thunk layer
    super::apc_exc_thunk::wow64_prepare_for_exception(exception_record, context)
}

/// `wow64_apc_routine` — APC delivery thunk for 32-bit threads.
/// This is called when a kernel APC needs to be delivered to a 32-bit thread.
pub unsafe extern "C" fn wow64_apc_routine(apc: *mut core::ffi::c_void) {
    crate::wow64_klog!("Wow64ApcRoutine apc={:p}", apc);
    // Forward to the APC thunk layer
    super::apc_exc_thunk::wow64_apc_routine(apc);
}

/// `wow64_ldrp_initialize` — Initialize the 32-bit loader.
/// This sets up the 32-bit ntdll and prepares for module loading.
pub unsafe extern "C" fn wow64_ldrp_initialize(
    context: *mut core::ffi::c_void,
    entry: *mut core::ffi::c_void,
    param: *mut core::ffi::c_void,
) -> i32 {
    crate::wow64_klog!(
        "Wow64LdrpInitialize ctx={:p} entry={:p} param={:p}",
        context,
        entry,
        param
    );
    // Forward to the APC/exception thunk layer for loader initialization
    super::apc_exc_thunk::wow64_ldrp_initialize(context, entry, param)
}

/// `wow64_system_service_ex` — System call dispatcher for WoW64.
/// Translates 32-bit system calls to 64-bit and back.
pub unsafe extern "C" fn wow64_system_service_ex(
    service_table: u32,
    service_number: u32,
    args: *mut u32,
) -> u32 {
    crate::wow64_klog!(
        "Wow64SystemServiceEx tbl={:#x} svc={:#x} args={:p}",
        service_table,
        service_number,
        args
    );
    // Forward to the central SSD dispatcher
    super::ssd::dispatch_service(service_number, args)
}

/// `wow64_allocate_virtual_memory32` — Allocate virtual memory in
/// 32-bit address space.
pub unsafe extern "C" fn wow64_allocate_virtual_memory32(
    process_handle: u32,
    base_address: u32,
    zero_bits: u32,
    region_size: u32,
    allocation_type: u32,
    protect: u32,
) -> u32 {
    crate::wow64_klog!(
        "Wow64AllocateVirtualMemory32 proc={:#x} base={:#x} zb={:#x} size={:#x} type={:#x} prot={:#x}",
        process_handle, base_address, zero_bits, region_size,
        allocation_type, protect
    );
    // Forward to the memory thunk layer
    super::mem_thunk::wow64_allocate_virtual_memory(
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect,
    )
}

/// `wow64_free_virtual_memory32` — Free virtual memory in 32-bit address space.
pub unsafe extern "C" fn wow64_free_virtual_memory32(
    process_handle: u32,
    base_address: u32,
    region_size: u32,
    free_type: u32,
) -> u32 {
    crate::wow64_klog!(
        "Wow64FreeVirtualMemory32 proc={:#x} base={:#x} size={:#x} type={:#x}",
        process_handle,
        base_address,
        region_size,
        free_type
    );
    // Forward to the memory thunk layer
    super::mem_thunk::wow64_free_virtual_memory(
        process_handle,
        base_address,
        region_size,
        free_type,
    )
}

/// `wow64_read_virtual_memory32` — read memory from a 32-bit process.
pub unsafe extern "C" fn wow64_read_virtual_memory32(
    process_handle: u32,
    base_address: u32,
    buffer: u32,
    size: u32,
) -> u32 {
    crate::wow64_klog!(
        "Wow64ReadVirtualMemory32 proc={:#x} src={:#x} dst={:#x} size={}",
        process_handle,
        base_address,
        buffer,
        size
    );
    // Forward to the memory thunk layer
    super::mem_thunk::wow64_read_virtual_memory(process_handle, base_address, buffer, size)
}

/// `wow64_write_virtual_memory32` — write memory to a 32-bit process.
pub unsafe extern "C" fn wow64_write_virtual_memory32(
    process_handle: u32,
    base_address: u32,
    buffer: u32,
    size: u32,
) -> u32 {
    crate::wow64_klog!(
        "Wow64WriteVirtualMemory32 proc={:#x} dst={:#x} src={:#x} size={}",
        process_handle,
        base_address,
        buffer,
        size
    );
    // Forward to the memory thunk layer
    super::mem_thunk::wow64_write_virtual_memory(process_handle, base_address, buffer, size)
}

/// `wow64_query_information_process` — Query process information for WoW64 process.
pub unsafe extern "C" fn wow64_query_information_process(
    process_handle: u32,
    information_class: u32,
    buffer: u32,
    buffer_size: u32,
) -> u32 {
    crate::wow64_klog!(
        "Wow64QueryInformationProcess proc={:#x} class={:#x} buf={:#x} sz={}",
        process_handle,
        information_class,
        buffer,
        buffer_size
    );
    // Forward to the process/thread thunk layer
    super::ps_thunk::wow64_query_information_process(
        process_handle,
        information_class,
        buffer,
        buffer_size,
    )
}

/// `wow64_set_information_thread` — Set thread information for WoW64 thread.
pub unsafe extern "C" fn wow64_set_information_thread(
    thread_handle: u32,
    information_class: u32,
    buffer: u32,
    buffer_size: u32,
) -> u32 {
    crate::wow64_klog!(
        "Wow64SetInformationThread thr={:#x} class={:#x} buf={:#x} sz={}",
        thread_handle,
        information_class,
        buffer,
        buffer_size
    );
    // Forward to the process/thread thunk layer
    super::ps_thunk::wow64_set_information_thread(
        thread_handle,
        information_class,
        buffer,
        buffer_size,
    )
}
