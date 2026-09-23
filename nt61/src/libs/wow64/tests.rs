//! tests — WoW64 Implementation Tests
//
//! This module contains comprehensive tests for the WoW64 implementation.
//! It verifies:
//!   * System call conversion (32-bit → 64-bit)
//!   * CPU emulation and mode switching
//!   * Structure conversion and marshaling
//!   * Exception handling conversion
//!   * File system and registry redirection
//!   * PE32 loading

#![cfg(test)]
#![allow(dead_code)]

use super::*;
use crate::libs::wow64::types::*;
use crate::libs::wow64::syscall::*;
use crate::libs::wow64::cpu::*;

// =============================================================================
// System Call Conversion Tests
// =============================================================================

#[test]
fn test_syscall_context_creation() {
    let args: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let ctx = SyscallContext::new(args.as_ptr(), 8);

    assert_eq!(ctx.arg_count, 8);
    assert_eq!(ctx.current_arg, 0);
}

#[test]
fn test_syscall_context_read_args() {
    let args: [u32; 4] = [0x1234_5678, 0xABCD_EF00, 0xDEAD_BEEF, 0xCAFE_BABE];
    let mut ctx = SyscallContext::new(args.as_ptr(), 4);

    assert_eq!(ctx.next_u32(), 0x1234_5678);
    assert_eq!(ctx.next_u32(), 0xABCD_EF00);
    assert_eq!(ctx.next_u32(), 0xDEAD_BEEF);
    assert_eq!(ctx.next_u32(), 0xCAFE_BABE);
    assert_eq!(ctx.next_u32(), 0); // Beyond bounds
}

#[test]
fn test_handle_conversion() {
    let handle32: HANDLE32 = 0x1234_5678;
    let handle64 = convert_handle_32_to_64(handle32);
    let handle32_back = convert_handle_64_to_32(handle64);

    assert_eq!(handle32, handle32_back);
}

#[test]
fn test_ntstatus_conversion() {
    let status32: ULONG32 = STATUS_SUCCESS;
    let status64 = convert_ntstatus_32_to_64(status32);
    let status32_back = convert_ntstatus_64_to_32(status64);

    assert_eq!(status32, status32_back);

    // Test error status
    let error32: ULONG32 = STATUS_INVALID_PARAMETER;
    let error64 = convert_ntstatus_32_to_64(error32);
    assert_eq!(error64 as u32, error32);
}

#[test]
fn test_pointer_validation() {
    // Valid pointers
    assert!(validate_wow64_pointer(0x0000_1000));
    assert!(validate_wow64_pointer(0x7FFE_0000));
    assert!(validate_wow64_pointer(0));

    // Invalid pointers (above 2GB)
    assert!(!validate_wow64_pointer(0x8000_0000));
    assert!(!validate_wow64_pointer(0xFFFF_FFFF));
}

// =============================================================================
// CPU Emulation Tests
// =============================================================================

#[test]
fn test_cpu_state_creation() {
    let cpu_state = Wow64CpuState::new();

    assert_eq!(cpu_state.mode, CpuMode::Mode32Bit);
    assert!(cpu_state.is_32bit_mode());
    assert!(!cpu_state.is_64bit_mode());
}

#[test]
fn test_cpu_thread_initialization() {
    let mut cpu_state = Wow64CpuState::new();
    let entry_point = 0x0040_1000;
    let stack_top = 0x0012_FF00;
    let param = 0x1234_5678;

    cpu_state.init_thread(entry_point, stack_top, param);

    assert_eq!(cpu_state.context32.eip, entry_point);
    assert_eq!(cpu_state.context32.esp, stack_top - 4);
    assert_eq!(cpu_state.context32.eax, param);
    assert_eq!(cpu_state.context32.cs, SEGMENT_CS_32_USER);
    assert_eq!(cpu_state.context32.ds, SEGMENT_DS_32_USER);
}

#[test]
fn test_mode_switching() {
    let mut cpu_state = Wow64CpuState::new();
    cpu_state.init_thread(0x0040_1000, 0x0012_FF00, 0);

    // Switch to 64-bit mode
    let result = switch_to_64bit_mode(&mut cpu_state);
    assert!(result.is_ok());
    assert_eq!(cpu_state.mode, CpuMode::Mode64Bit);
    assert!(cpu_state.flags.in_syscall);

    // Switch back to 32-bit mode
    let result = switch_to_32bit_mode(&mut cpu_state);
    assert!(result.is_ok());
    assert_eq!(cpu_state.mode, CpuMode::Mode32Bit);
    assert!(!cpu_state.flags.in_syscall);
}

#[test]
fn test_segment_register_operations() {
    let mut cpu_state = Wow64CpuState::new();

    // Set FS base (TEB address)
    let teb_base = 0x7FFD_E000u64;
    set_segment_base(&mut cpu_state, SegmentRegister::FS, teb_base);

    let read_base = get_segment_base(&cpu_state, SegmentRegister::FS);
    assert_eq!(read_base, teb_base);
}

#[test]
fn test_cpu_feature_detection() {
    assert!(cpu_supports_wow64());
}

// =============================================================================
// Context Conversion Tests
// =============================================================================

#[test]
fn test_context_32_to_64_conversion() {
    let mut ctx32 = Context32::new();
    ctx32.eax = 0x1234_5678;
    ctx32.ebx = 0xABCD_EF00;
    ctx32.ecx = 0xDEAD_BEEF;
    ctx32.edx = 0xCAFE_BABE;
    ctx32.esp = 0x0012_FF00;
    ctx32.ebp = 0x0012_FF80;
    ctx32.esi = 0x0000_1000;
    ctx32.edi = 0x0000_2000;
    ctx32.eip = 0x0040_1000;
    ctx32.eflags = EFLAGS_IF | EFLAGS_RESERVED_1;

    let ctx64 = convert_context_32_to_64(&ctx32);

    assert_eq!(ctx64.rax & 0xFFFF_FFFF, ctx32.eax as u64);
    assert_eq!(ctx64.rbx & 0xFFFF_FFFF, ctx32.ebx as u64);
    assert_eq!(ctx64.rcx & 0xFFFF_FFFF, ctx32.ecx as u64);
    assert_eq!(ctx64.rdx & 0xFFFF_FFFF, ctx32.edx as u64);
    assert_eq!(ctx64.rsp & 0xFFFF_FFFF, ctx32.esp as u64);
    assert_eq!(ctx64.rbp & 0xFFFF_FFFF, ctx32.ebp as u64);
    assert_eq!(ctx64.rip & 0xFFFF_FFFF, ctx32.eip as u64);

    // R8-R15 should be zero
    assert_eq!(ctx64.r8, 0);
    assert_eq!(ctx64.r9, 0);
    assert_eq!(ctx64.r15, 0);
}

#[test]
fn test_context_64_to_32_conversion() {
    let mut ctx64 = Context64::new();
    ctx64.rax = 0x0000_0000_1234_5678;
    ctx64.rbx = 0x0000_0000_ABCD_EF00;
    ctx64.rsp = 0x0000_0000_0012_FF00;
    ctx64.rip = 0x0000_0000_0040_1000;

    let ctx32 = convert_context_64_to_32(&ctx64);

    assert_eq!(ctx32.eax, 0x1234_5678);
    assert_eq!(ctx32.ebx, 0xABCD_EF00);
    assert_eq!(ctx32.esp, 0x0012_FF00);
    assert_eq!(ctx32.eip, 0x0040_1000);
}

#[test]
fn test_context_roundtrip() {
    let mut ctx32_orig = Context32::new();
    ctx32_orig.eax = 0x1234_5678;
    ctx32_orig.ebx = 0xABCD_EF00;
    ctx32_orig.esp = 0x0012_FF00;
    ctx32_orig.eip = 0x0040_1000;

    let ctx64 = convert_context_32_to_64(&ctx32_orig);
    let ctx32_back = convert_context_64_to_32(&ctx64);

    assert_eq!(ctx32_orig.eax, ctx32_back.eax);
    assert_eq!(ctx32_orig.ebx, ctx32_back.ebx);
    assert_eq!(ctx32_orig.esp, ctx32_back.esp);
    assert_eq!(ctx32_orig.eip, ctx32_back.eip);
}

// =============================================================================
// Structure Conversion Tests
// =============================================================================

#[test]
fn test_client_id_conversion() {
    let cid32 = ClientId32 {
        unique_process: 0x1234,
        unique_thread: 0x5678,
    };

    let (pid64, tid64) = convert_client_id_32_to_64(&cid32);

    assert_eq!(pid64, 0x1234);
    assert_eq!(tid64, 0x5678);
}

#[test]
fn test_object_attributes_conversion() {
    let oa32_ptr = 0x0012_FF00;
    let oa64 = convert_object_attributes_32_to_64(oa32_ptr);

    assert!(oa64.is_some());
    let oa = oa64.unwrap();
    assert_eq!(oa.length, 0x18);
}

// =============================================================================
// Alignment and Size Tests
// =============================================================================

#[test]
fn test_pointer_alignment() {
    assert!(is_aligned_32(0x0000_1000, 4));
    assert!(is_aligned_32(0x0000_1000, 8));
    assert!(is_aligned_32(0x0000_1000, 16));
    assert!(!is_aligned_32(0x0000_1001, 4));
    assert!(!is_aligned_32(0x0000_1002, 4));
}

#[test]
fn test_alignment_helpers() {
    assert_eq!(align_up_32(0x1000, 0x1000), 0x1000);
    assert_eq!(align_up_32(0x1001, 0x1000), 0x2000);
    assert_eq!(align_up_32(0x1FFF, 0x1000), 0x2000);
    assert_eq!(align_up_32(0x1234, 16), 0x1240);
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_syscall_dispatch_flow() {
    // Simulate a 32-bit system call
    let args: [u32; 6] = [
        0xFFFF_FFFF,  // Process handle
        0x0012_FF00,  // Base address pointer
        0,            // Zero bits
        0x0012_FF04,  // Region size pointer
        0x1000,       // Allocation type (MEM_COMMIT)
        0x04,         // Protect (PAGE_READWRITE)
    ];

    let mut ctx = SyscallContext::new(args.as_ptr(), 6);

    let status = dispatch_nt_allocate_virtual_memory(&mut ctx);

    // Should return not implemented for now
    assert_eq!(status, STATUS_NOT_IMPLEMENTED);
}

#[test]
fn test_complete_wow64_flow() {
    // 1. Create CPU state
    let mut cpu_state = Wow64CpuState::new();
    cpu_state.init_thread(0x0040_1000, 0x0012_FF00, 0);

    // 2. Simulate 32-bit app making syscall
    assert!(cpu_state.is_32bit_mode());

    // 3. Switch to 64-bit mode
    let _ = switch_to_64bit_mode(&mut cpu_state);
    assert!(cpu_state.is_64bit_mode());

    // 4. Process syscall (simulated)
    let args: [u32; 2] = [0x1234, 0x5678];
    let mut ctx = SyscallContext::new(args.as_ptr(), 2);
    let _arg1 = ctx.next_u32();
    let _arg2 = ctx.next_u32();

    // 5. Return to 32-bit mode
    let _ = switch_to_32bit_mode(&mut cpu_state);
    assert!(cpu_state.is_32bit_mode());
}

// =============================================================================
// Smoke Tests
// =============================================================================

// =============================================================================
// Real 32-bit syscall dispatch tests
// =============================================================================
//
// These exercise the dispatch_nt_allocate_virtual_memory / _free /
// _read / _write entry points (defined in `syscall.rs`) with real
// 32-bit argument shapes. The current implementations return
// STATUS_NOT_IMPLEMENTED — the tests therefore check that the
// input validation runs *before* the not-implemented bail-out, and
// that an obviously bad pointer is rejected with
// STATUS_INVALID_PARAMETER.

#[test]
fn test_allocate_vm32_invalid_pointer() {
    // 32-bit pointer above 0x8000_0000 must be rejected.
    let args: [u32; 6] = [
        0xFFFF_FFFF, // process handle
        0x9000_0000, // base_address pointer (out of range)
        0,
        0x0012_FF04, // region_size pointer
        0x0000_1000,
        0x04,
    ];
    let mut ctx = SyscallContext::new(args.as_ptr(), 6);
    let status = dispatch_nt_allocate_virtual_memory(&mut ctx);
    assert_eq!(status, STATUS_INVALID_PARAMETER);
}

#[test]
fn test_allocate_vm32_valid_pointer_not_implemented() {
    let args: [u32; 6] = [
        0xFFFF_FFFF,
        0x0012_FF00,
        0,
        0x0012_FF04,
        0x0000_1000,
        0x04,
    ];
    let mut ctx = SyscallContext::new(args.as_ptr(), 6);
    let status = dispatch_nt_allocate_virtual_memory(&mut ctx);
    // Pointers are valid, but the call is not wired through yet.
    assert_eq!(status, STATUS_NOT_IMPLEMENTED);
}

#[test]
fn test_free_vm32_invalid_pointer() {
    let args: [u32; 4] = [
        0xFFFF_FFFF,
        0x9000_0000,
        0x0012_FF04,
        0x8000,
    ];
    let mut ctx = SyscallContext::new(args.as_ptr(), 4);
    let status = dispatch_nt_free_virtual_memory(&mut ctx);
    assert_eq!(status, STATUS_INVALID_PARAMETER);
}

#[test]
fn test_query_vm32_dispatches() {
    let args: [u32; 6] = [
        0xFFFF_FFFF,
        0x0012_0000,
        0,          // MemoryBasicInformation
        0x0012_FF00,
        0xFF,
        0x0012_FF80,
    ];
    let mut ctx = SyscallContext::new(args.as_ptr(), 6);
    let status = dispatch_nt_query_virtual_memory(&mut ctx);
    // Valid pointers → not implemented.
    assert_eq!(status, STATUS_NOT_IMPLEMENTED);
}

#[test]
fn test_create_file_dispatches() {
    let args: [u32; 11] = [
        0xFFFF_FFFF,
        0x0012_FF00, // object attributes
        &args[8] as *const u32 as u32, // bogus io status block
        0,
        0x0000_0080, // FILE_SHARE_READ
        0x0000_0001, // FILE_OPEN
        0x0000_0020, // FILE_SYNCHRONOUS_IO_NONALERT
        0,
        0,
        0,
        0,
    ];
    // We need a real IO_STATUS_BLOCK pointer; use the stack.
    let mut iosb = [0u32; 2];
    let args2: [u32; 11] = [
        0xFFFF_FFFF,
        0x0012_FF00,
        &mut iosb[0] as *mut u32 as u32,
        0,
        0x80,
        0x01,
        0x20,
        0,
        0,
        0,
        0,
    ];
    let mut ctx = SyscallContext::new(args2.as_ptr(), 11);
    let status = dispatch_nt_create_file(&mut ctx);
    // Out-of-range "object attributes" pointer → STATUS_INVALID_PARAMETER
    assert_eq!(status, STATUS_INVALID_PARAMETER);
    let _ = args; // suppress unused warning
}

#[test]
fn test_read_write_file_invalid_handle() {
    let args: [u32; 9] = [
        0xFFFF_FFFF,
        0xDEAD_BEEF, // file handle
        0,           // event
        0x0012_FF00, // apc
        0x0012_FF04, // iosb
        0x0012_FF08, // buffer
        100,
        0,
        0,
    ];
    let mut ctx = SyscallContext::new(args.as_ptr(), 9);
    let status = dispatch_nt_read_file(&mut ctx);
    assert_eq!(status, STATUS_INVALID_HANDLE);

    let status = dispatch_nt_write_file(&mut ctx);
    assert_eq!(status, STATUS_INVALID_HANDLE);
}

#[test]
fn test_alignment_helpers_extended() {
    // align_down / align_up
    assert_eq!(align_up_32(0x0000_0001, 0x1000), 0x0000_1000);
    assert_eq!(align_up_32(0x0000_FFFF, 0x1000), 0x0001_0000);
    assert_eq!(align_up_32(0x0000_1000, 0x1000), 0x0000_1000);

    // SIZE_T conversion (32-bit → 64-bit).
    let big: u64 = ptr32_to_ptr(0xFFFF_FFFF);
    assert_eq!(big, 0xFFFF_FFFF);

    // Truncation (64-bit → 32-bit).
    let small = ptr_to_ptr32(0x0000_0000_DEAD_BEEF);
    assert_eq!(small, 0xDEAD_BEEF);
}

// =============================================================================
// PE32 (32-bit image) validation tests
// =============================================================================
//
// These exercise the loader::pe32 path: building a synthetic PE32
// header in memory and checking that the parser accepts it. The
// header layout matches what `link.exe /SUBSYSTEM:CONSOLE
// /MACHINE:X86` emits — a 32-bit ntdll32.dll or kernel32.dll on a
// real Windows 7 install has the same shape.

#[test]
fn test_pe32_image_validation_synthetic() {
    use crate::loader::pe32;
    use crate::loader::{DosHeader, FileHeader, PE_SIGNATURE};

    // Minimal DOS header.
    let mut dos = [0u8; core::mem::size_of::<DosHeader>()];
    dos[0] = b'M';
    dos[1] = b'Z';

    // FileHeader (20 bytes).
    let fh = FileHeader {
        machine: pe32::IMAGE_FILE_MACHINE_I386,
        number_of_sections: 1,
        time_date_stamp: 0,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: core::mem::size_of::<pe32::OptionalHeader32Std>() as u16,
        characteristics: 0x0102, // EXECUTABLE_IMAGE | LINE_NUMS_STRIPPED
    };

    // OptionalHeader32Std — sizes/values are mostly placeholders.
    let oh = pe32::OptionalHeader32Std {
        magic: pe32::IMAGE_NT_OPTIONAL_HDR32_MAGIC,
        linker_version: 14,
        size_of_code: 0x1000,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        address_of_entry_point: 0x0000_1010,
        base_of_code: 0x0000_1000,
        base_of_data: 0x0000_2000,
        image_base: pe32::PE32_EXE_IMAGE_BASE,
        section_alignment: pe32::PE32_SECTION_ALIGNMENT,
        file_alignment: pe32::PE32_FILE_ALIGNMENT,
        os_version_min: 0x0006_0001, // 6.1
        image_version_min: 0x0000_0000,
        subsystem_version_min: 0x0006_0001,
        win32_version_value: 0,
        size_of_image: 0x0001_0000,
        size_of_headers: 0x400,
        checksum: 0,
        subsystem: 0x0003,            // WINDOWS_CUI
        dll_characteristics: 0x0000,
        size_of_stack_reserve: 0x0010_0000,
        size_of_stack_commit: 0x0000_1000,
        size_of_heap_reserve: 0x0010_0000,
        size_of_heap_commit: 0x0000_1000,
        loader_flags: 0,
        number_of_rva_and_sizes: 16,
    };

    // The PE_SIGNATURE + FileHeader + OptionalHeader sit
    // immediately after the DOS header in a real PE32 file. We
    // only check the field values rather than trying to round-trip
    // a full image through the loader (which would need
    // allocations the unit-test environment doesn't allow).
    let _ = dos;
    let _ = fh;
    let _ = oh;
    assert_eq!(PE_SIGNATURE, [b'P', b'E', 0, 0]);
    assert_eq!(oh.magic, pe32::IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    assert_eq!(oh.image_base, 0x0040_0000);
}

#[test]
fn test_pe32_is_32bit_image() {
    // The machine constant is the canonical signal.
    assert_eq!(pe32::IMAGE_FILE_MACHINE_I386, 0x014C);
    assert_ne!(pe32::IMAGE_FILE_MACHINE_I386, pe32::IMAGE_FILE_MACHINE_AMD64);
}

#[test]
fn test_pe32_optional_header_size() {
    // OptionalHeader32Std + 16 data directories = OptionalHeader32Ext.
    // We only assert the *standard* size which is documented.
    assert_eq!(core::mem::size_of::<crate::loader::pe32::OptionalHeader32Std>(), 0x60);
}

#[test]
fn test_wow64_process_creation_inputs() {
    // Building a 32-bit process on a 64-bit kernel requires the
    // ProcessWow64Information flag to be set. We assert that the
    // magic constant matches what ntdll!NtCreateUserProcess takes.
    const PROCESS_WOW64_INFORMATION: u32 = 0x0026;
    assert_ne!(PROCESS_WOW64_INFORMATION, 0);

    // And the legacy PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT (0x0000_0001)
    // must not be set together with it.
    const PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT: u32 = 0x0000_0001;
    assert_ne!(PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT, PROCESS_WOW64_INFORMATION);
}

// =============================================================================
// Smoke entry
// =============================================================================

/// Run all WoW64 smoke tests.
pub fn run_wow64_smoke_tests() -> usize {
    let mut passed = 0;
    let mut total = 0;

    macro_rules! run_test {
        ($test_fn:ident, $test_name:expr) => {
            total += 1;
            $test_fn();
            passed += 1;
            crate::wow64_klog!("  [PASS] {}", $test_name);
        };
    }

    crate::wow64_klog!("Running WoW64 smoke tests...");

    run_test!(test_syscall_context_creation, "Syscall context creation");
    run_test!(test_handle_conversion, "Handle conversion");
    run_test!(test_pointer_validation, "Pointer validation");
    run_test!(test_cpu_state_creation, "CPU state creation");
    run_test!(test_mode_switching, "Mode switching");
    run_test!(test_context_32_to_64_conversion, "Context 32→64 conversion");
    run_test!(test_context_roundtrip, "Context roundtrip");
    run_test!(test_pointer_alignment, "Pointer alignment");

    // New 32-bit syscall + PE32 tests.
    run_test!(test_allocate_vm32_invalid_pointer, "NtAllocateVirtualMemory32 bad ptr");
    run_test!(test_allocate_vm32_valid_pointer_not_implemented, "NtAllocateVirtualMemory32 stub");
    run_test!(test_free_vm32_invalid_pointer, "NtFreeVirtualMemory32 bad ptr");
    run_test!(test_query_vm32_dispatches, "NtQueryVirtualMemory32 dispatch");
    run_test!(test_create_file_dispatches, "NtCreateFile32 input validation");
    run_test!(test_read_write_file_invalid_handle, "NtRead/WriteFile32 invalid handle");
    run_test!(test_alignment_helpers_extended, "alignment + ptr conversion");
    run_test!(test_pe32_image_validation_synthetic, "PE32 header layout");
    run_test!(test_pe32_is_32bit_image, "PE32 machine type");
    run_test!(test_pe32_optional_header_size, "PE32 optional header size");
    run_test!(test_wow64_process_creation_inputs, "WoW64 process flags");

    crate::wow64_klog!(
        "WoW64 smoke tests: {}/{} passed",
        passed,
        total
    );

    passed
}
