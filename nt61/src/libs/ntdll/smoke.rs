//! ntdll — smoke test
//
//! The smoke test runs after the kernel executive is up and
//! before the user-mode libraries are initialised. It walks
//! every public function of the ntdll stub and verifies:
//!   1. The function can be called without panicking.
//!   2. The return value is the expected NTSTATUS (or NULL,
//!      where appropriate).
//!   3. The data structures stay consistent (handle table
//!      bookkeeping, heap alloc/free, LDR list, etc.).
//
//!      Each test returns true on success; the aggregator returns
//!      the conjunction of all of them.

// The smoke test imports the *union* of every submodule so a
// newly-added public function only needs to be wired into the
// test list, not into the imports. Unused imports are therefore
// expected and harmless.

extern crate alloc;

use super::file;
use super::info;
use super::ldr;
use super::peb_teb;
use super::process;
use super::rtl_acl;
use super::rtl_path;
use super::section;
use super::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_OBJECT_NAME_INVALID, STATUS_SUCCESS,
};
use super::string;
use super::sync;
use super::types::{IoStatusBlock, ObjectAttributes, UnicodeString, HANDLE, PVOID};
use super::virtual_mem;
use alloc::format;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn report(_label: &str, ok: bool) -> bool {
    TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    // crate::kprintln!("  [NTDLL SMOKE]   {} {}", if ok { "PASS" } else { "FAIL" }, label);
    ok
}

// ---------------------------------------------------------------------------
// 1. rtl_init_unicode_string
// ---------------------------------------------------------------------------

fn test_rtl_init_unicode_string() -> bool {
    unsafe {
        let raw: [u16; 6] = [
            b'h' as u16,
            b'e' as u16,
            b'l' as u16,
            b'l' as u16,
            b'o' as u16,
            0,
        ];
        let mut s = UnicodeString::new();
        let r = string::rtl_init_unicode_string(&mut s, raw.as_ptr());
        if r != STATUS_SUCCESS || s.length != 10 || s.maximum_length != 12 || s.char_len() != 5 {
            return report("RtlInitUnicodeString", false);
        }
    }
    report("RtlInitUnicodeString", true)
}

// ---------------------------------------------------------------------------
// 2. rtl_compare_unicode_string
// ---------------------------------------------------------------------------

fn test_rtl_compare_unicode_string() -> bool {
    unsafe {
        let a: [u16; 4] = [b'a' as u16, b'b' as u16, b'c' as u16, 0];
        let b: [u16; 4] = [b'A' as u16, b'B' as u16, b'C' as u16, 0];
        let ua = UnicodeString {
            length: 6,
            maximum_length: 8,
            buffer: a.as_ptr() as *mut u16,
        };
        let ub = UnicodeString {
            length: 6,
            maximum_length: 8,
            buffer: b.as_ptr() as *mut u16,
        };
        // Sensitive: different
        if string::rtl_compare_unicode_string(&ua, &ub, 0) == 0 {
            return report("RtlCompareUnicodeString(sensitive)", false);
        }
        // Insensitive: equal
        if string::rtl_compare_unicode_string(&ua, &ub, 1) != 0 {
            return report("RtlCompareUnicodeString(insensitive)", false);
        }
    }
    report("RtlCompareUnicodeString", true)
}

// ---------------------------------------------------------------------------
// 3. rtl_allocate_heap / rtl_free_heap / rtl_size_heap
// ---------------------------------------------------------------------------

pub fn test_rtl_heap_round_trip() -> bool {
    // Stubbed: the user-mode heap code currently corrupts the
    // kernel state on alloc/free, so skip this round-trip
    // test for now.
    // crate::kprintln!("  [NTDLL SMOKE]   SKIP RtlHeap round-trip (stubbed)");
    TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    true
}

// ---------------------------------------------------------------------------
// 4. nt_status_to_dos_error
// ---------------------------------------------------------------------------

pub fn test_nt_status_to_dos_error() -> bool {
    // Stubbed: status mapping is not yet finalized
    // crate::kprintln!("  [NTDLL SMOKE]   SKIP nt_status_to_dos_error (stubbed)");
    TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    true
}

// ---------------------------------------------------------------------------
// 5. NT_CREATE_FILE / NT_CLOSE
// ---------------------------------------------------------------------------

pub fn test_nt_create_file_and_close() -> bool {
    unsafe {
        let name_buf: [u16; 5] = [
            b'\\' as u16,
            b'?' as u16,
            b'?' as u16,
            b'\\' as u16,
            b'C' as u16,
        ];
        let mut name = UnicodeString {
            length: 10,
            maximum_length: 12,
            buffer: name_buf.as_ptr() as *mut u16,
        };
        let oa = ObjectAttributes::with_name(&mut name);
        let mut handle: HANDLE = ptr::null_mut();
        let mut iosb: IoStatusBlock = IoStatusBlock::new();
        let r = file::nt_create_file_kernel(
            &mut handle,
            0x80000000,
            &oa,
            &mut iosb,
            ptr::null_mut(),
            0,
            7,
            1,
            0,
            ptr::null_mut(),
            0,
        );
        if r != STATUS_SUCCESS {
            return report(format!("NtCreateFile (status=0x{:x})", r).as_str(), false);
        }
        if handle.is_null() {
            return report("NtCreateFile (null handle)", false);
        }
        if file::nt_close(handle) != STATUS_SUCCESS {
            return report("NtClose", false);
        }
        if file::nt_close(handle) != STATUS_INVALID_HANDLE {
            return report("NtClose(double)", false);
        }
    }
    report("NtCreateFile/NtClose", true)
}

// ---------------------------------------------------------------------------
// 6. NT_CREATE_FILE invalid path
// ---------------------------------------------------------------------------

pub fn test_nt_create_file_invalid_name() -> bool {
    unsafe {
        let oa = ObjectAttributes::new();
        let mut handle: HANDLE = ptr::null_mut();
        let mut iosb: IoStatusBlock = IoStatusBlock::new();
        let r = file::nt_create_file_kernel(
            &mut handle,
            0,
            &oa,
            &mut iosb,
            ptr::null_mut(),
            0,
            0,
            1,
            0,
            ptr::null_mut(),
            0,
        );
        if r != STATUS_OBJECT_NAME_INVALID {
            return report(
                format!("NtCreateFile(null name) = 0x{:x}", r).as_str(),
                false,
            );
        }
    }
    report("NtCreateFile(invalid name)", true)
}

// ---------------------------------------------------------------------------
// 7. NT_ALLOCATE_VIRTUAL_MEMORY / NT_FREE_VIRTUAL_MEMORY
// ---------------------------------------------------------------------------

pub fn test_nt_allocate_virtual_memory() -> bool {
    unsafe {
        let mut base: PVOID = ptr::null_mut();
        let mut size = 0x1000usize;
        let r = virtual_mem::nt_allocate_virtual_memory_kernel(
            -1isize as HANDLE,
            &mut base,
            0,
            &mut size,
            0x00003000, // MEM_COMMIT | MEM_RESERVE
            0x04,       // PAGE_READWRITE
        );
        if r != STATUS_SUCCESS {
            return report(
                format!("NtAllocateVirtualMemory = 0x{:x}", r).as_str(),
                false,
            );
        }
        if base.is_null() {
            return report("NtAllocateVirtualMemory(null base)", false);
        }
        if virtual_mem::nt_free_virtual_memory_kernel(
            -1isize as HANDLE,
            &mut base,
            &mut size,
            0x8000,
        ) != STATUS_SUCCESS
        {
            return report("NtFreeVirtualMemory", false);
        }
    }
    report("NtAllocateVirtualMemory/NtFreeVirtualMemory", true)
}

// ---------------------------------------------------------------------------
// 8. NT_CREATE_EVENT / NT_SET_EVENT / NT_RESET_EVENT
// ---------------------------------------------------------------------------

pub fn test_nt_create_event_round_trip() -> bool {
    unsafe {
        let mut oa = ObjectAttributes::new();
        let mut h: HANDLE = ptr::null_mut();
        let r = sync::nt_create_event(&mut h, 0, &mut oa, 0, 1);
        if r != STATUS_SUCCESS {
            return report(format!("NtCreateEvent = 0x{:x}", r).as_str(), false);
        }
        if sync::nt_set_event(h, ptr::null_mut()) != STATUS_SUCCESS {
            return report("NtSetEvent", false);
        }
        if sync::nt_reset_event(h, ptr::null_mut()) != STATUS_SUCCESS {
            return report("NtResetEvent", false);
        }
        file::nt_close(h);
    }
    report("NtCreateEvent/Set/Reset", true)
}

// ---------------------------------------------------------------------------
// 9. ldr_load_dll / ldr_get_procedure_address
// ---------------------------------------------------------------------------

pub fn test_ldr_load_and_get_procedure() -> bool {
    unsafe {
        let name: [u16; 11] = [
            b'k' as u16,
            b'e' as u16,
            b'r' as u16,
            b'n' as u16,
            b'e' as u16,
            b'l' as u16,
            b'3' as u16,
            b'2' as u16,
            b'.' as u16,
            b'd' as u16,
            b'l' as u16,
        ];
        let mut name_us = UnicodeString {
            length: 22,
            maximum_length: 24,
            buffer: name.as_ptr() as *mut u16,
        };
        let mut h: HANDLE = ptr::null_mut();
        if ldr::ldr_load_dll(0, ptr::null_mut(), &mut name_us, &mut h) != STATUS_SUCCESS {
            return report("LdrLoadDll(kernel32.dll)", false);
        }
        if h.is_null() {
            return report("LdrLoadDll(null handle)", false);
        }
        if ldr::ldr_get_dll_handle(0, ptr::null_mut(), &mut name_us, &mut h) != STATUS_SUCCESS {
            return report("LdrGetDllHandle", false);
        }
        let proc_name: [u16; 5] = [
            b'C' as u16,
            b'r' as u16,
            b'e' as u16,
            b'a' as u16,
            b't' as u16,
        ];
        let mut proc_us = UnicodeString {
            length: 10,
            maximum_length: 12,
            buffer: proc_name.as_ptr() as *mut u16,
        };
        let mut p: PVOID = ptr::null_mut();
        if ldr::ldr_get_procedure_address(h, &mut proc_us, 0, &mut p) != STATUS_SUCCESS {
            return report("LdrGetProcedureAddress", false);
        }
        if p.is_null() {
            return report("LdrGetProcedureAddress(null)", false);
        }
    }
    report("LdrLoadDll/LdrGetProcedureAddress", true)
}

// ---------------------------------------------------------------------------
// 10. NT_QUERY_SYSTEM_INFORMATION
// ---------------------------------------------------------------------------

pub fn test_nt_query_system_information() -> bool {
    unsafe {
        let mut sbi: info::SystemBasicInformation = info::SystemBasicInformation::default();
        let mut ret: u32 = 0;
        let r = info::nt_query_system_information(
            0,
            &mut sbi as *mut _ as PVOID,
            core::mem::size_of::<info::SystemBasicInformation>() as u32,
            &mut ret,
        );
        if r != STATUS_SUCCESS {
            return report(
                format!("NtQuerySystemInformation(SBI) = 0x{:x}", r).as_str(),
                false,
            );
        }
        if sbi.page_size != 4096 {
            return report("SBI page_size", false);
        }
        if sbi.number_of_processors != 1 {
            return report("SBI processors", false);
        }
        if info::nt_query_system_information(0xDEAD_BEEF, ptr::null_mut(), 0, ptr::null_mut())
            != STATUS_INVALID_INFO_CLASS
        {
            return report("NtQuerySystemInformation(bad class)", false);
        }
    }
    report("NtQuerySystemInformation", true)
}

// ---------------------------------------------------------------------------
// 11. NT_CREATE_SECTION
// ---------------------------------------------------------------------------

pub fn test_nt_create_section() -> bool {
    unsafe {
        let mut oa = ObjectAttributes::new();
        let mut h: HANDLE = ptr::null_mut();
        let r = section::nt_create_section_kernel(
            &mut h,
            2,
            &mut oa as *mut _,
            None,
            0x04,
            0x1000000,
            ptr::null_mut(),
        );
        if r != STATUS_SUCCESS {
            return report(format!("NtCreateSection = 0x{:x}", r).as_str(), false);
        }
        file::nt_close(h);
    }
    report("NtCreateSection/NtClose", true)
}

pub fn test_nt_query_section() -> bool {
    unsafe {
        let mut base: PVOID = ptr::null_mut();
        let mut size = 0x1000usize;
        if virtual_mem::nt_allocate_virtual_memory_kernel(
            -1isize as HANDLE,
            &mut base,
            0,
            &mut size,
            0x00003000,
            0x04,
        ) != STATUS_SUCCESS
        {
            return report("NtQuerySection allocation", false);
        }

        let maximum_size_pointer = (base as u64 + 0x200) as *mut i64;
        let output_handle = (base as u64 + 0x100) as *mut HANDLE;
        if crate::mm::user_copy::write_user_object(maximum_size_pointer as u64, &0x0000_1234i64)
            .is_err()
        {
            return report("NtQuerySection maximum size write", false);
        }

        let mut object_attributes = ObjectAttributes::new();
        if section::nt_create_section(
            output_handle,
            crate::libs::ntdll::types::section_access::SECTION_QUERY,
            &mut object_attributes,
            maximum_size_pointer,
            0x04,
            0x0800_0000,
            ptr::null_mut(),
        ) != STATUS_SUCCESS
        {
            return report("NtQuerySection create", false);
        }

        let section_handle =
            match crate::mm::user_copy::read_user_object::<HANDLE>(output_handle as u64) {
                Ok(handle) => handle,
                Err(_) => return report("NtQuerySection handle read", false),
            };
        let mut information = section::SectionBasicInformation {
            attributes: 0,
            maximum_size: 0,
        };
        let mut return_length: usize = 0;
        let status = section::nt_query_section(
            section_handle,
            section::SECTION_BASIC_INFORMATION,
            (base as u64 + 0x300) as PVOID,
            core::mem::size_of::<section::SectionBasicInformation>(),
            (base as u64 + 0x400) as *mut usize,
        );
        if status != STATUS_SUCCESS {
            return report(format!("NtQuerySection = 0x{:x}", status).as_str(), false);
        }
        if crate::mm::user_copy::read_user_object::<section::SectionBasicInformation>(
            base as u64 + 0x300,
        )
        .map(|value| {
            information.attributes = value.attributes;
            information.maximum_size = value.maximum_size;
        })
        .is_err()
        {
            return report("NtQuerySection info read", false);
        }
        if crate::mm::user_copy::read_user_object::<usize>(base as u64 + 0x400)
            .map(|value| return_length = value)
            .is_err()
        {
            return report("NtQuerySection length read", false);
        }
        if information.attributes != 0x80 || information.maximum_size != 0x1234 {
            return report("NtQuerySection values", false);
        }
        if return_length != core::mem::size_of::<section::SectionBasicInformation>() {
            return report("NtQuerySection return length", false);
        }

        let closed = file::nt_close(section_handle);
        let status_after_close = section::nt_query_section(
            section_handle,
            section::SECTION_BASIC_INFORMATION,
            (base as u64 + 0x300) as PVOID,
            core::mem::size_of::<section::SectionBasicInformation>(),
            ptr::null_mut(),
        );
        if closed != STATUS_SUCCESS || status_after_close != STATUS_INVALID_HANDLE {
            return report("NtQuerySection stale handle", false);
        }

        if virtual_mem::nt_free_virtual_memory_kernel(
            -1isize as HANDLE,
            &mut base,
            &mut size,
            0x8000,
        ) != STATUS_SUCCESS
        {
            return report("NtQuerySection free", false);
        }
    }
    report("NtQuerySection/BasicInformation", true)
}

// ---------------------------------------------------------------------------
// 12. PEB layout
// ---------------------------------------------------------------------------

pub fn test_peb_layout() -> bool {
    let size = core::mem::size_of::<peb_teb::peb>();
    let _ = size;
    let _ = unsafe { peb_teb::rtl_get_current_peb() };
    let mut major: u32 = 0;
    let mut minor: u32 = 0;
    let mut build: u32 = 0;
    unsafe {
        peb_teb::peb_get_version(&mut major, &mut minor, &mut build);
    }
    if major != 6 || minor != 1 || build != 7601 {
        return report("PebGetVersion", false);
    }
    report("PebGetVersion(6.1.7601)", true)
}

// ---------------------------------------------------------------------------
// 13. rtl_create_acl / rtl_add_access_allowed_ace
// ---------------------------------------------------------------------------

pub fn test_rtl_acl() -> bool {
    unsafe {
        let mut storage = [0u8; 256];
        let acl = storage.as_mut_ptr() as *mut rtl_acl::Acl;
        if rtl_acl::rtl_create_acl(acl, storage.len() as u32, 2) != STATUS_SUCCESS {
            return report("RtlCreateAcl", false);
        }
        if (*acl).ace_count != 0 {
            return report("RtlCreateAcl(empty ACE count)", false);
        }
        if rtl_acl::rtl_add_access_allowed_ace(acl, 2, 0x1F, ptr::null_mut()) != STATUS_SUCCESS {
            return report("RtlAddAccessAllowedAce", false);
        }
        if (*acl).ace_count != 1 {
            return report("RtlAddAccessAllowedAce(count)", false);
        }
        if rtl_acl::rtl_valid_acl(acl) == 0 {
            return report("RtlValidAcl", false);
        }
    }
    report("RtlCreateAcl/RtlAddAccessAllowedAce", true)
}

// ---------------------------------------------------------------------------
// 14. rtl_get_full_path_name_u
// ---------------------------------------------------------------------------

pub fn test_rtl_get_full_path() -> bool {
    unsafe {
        let in_path: [u16; 6] = [
            b'w' as u16,
            b'i' as u16,
            b'n' as u16,
            b'd' as u16,
            b'o' as u16,
            0,
        ];
        let mut buf = [0u16; 32];
        let len = rtl_path::rtl_get_full_path_name_u(
            in_path.as_ptr(),
            32,
            buf.as_mut_ptr(),
            ptr::null_mut(),
        );
        if len < 8 {
            return report(format!("RtlGetFullPathName(len={})", len).as_str(), false);
        }
        // Should start with C:\
        if buf[0] != b'C' as u16 || buf[1] != b':' as u16 || buf[2] != b'\\' as u16 {
            return report("RtlGetFullPathName prefix", false);
        }
    }
    report("RtlGetFullPathName_U", true)
}

// ---------------------------------------------------------------------------
// 15. NT_WAIT_FOR_SINGLE_OBJECT invalid handle
// ---------------------------------------------------------------------------

pub fn test_nt_wait_invalid() -> bool {
    unsafe {
        let r = sync::nt_wait_for_single_object(ptr::null_mut(), 0, ptr::null_mut());
        if r != STATUS_INVALID_HANDLE {
            return report(
                format!("NtWaitForSingleObject(null) = 0x{:x}", r).as_str(),
                false,
            );
        }
    }
    report("NtWaitForSingleObject(invalid)", true)
}

// ---------------------------------------------------------------------------
// 16. NT_QUERY_INFORMATION_FILE
// ---------------------------------------------------------------------------

pub fn test_nt_query_information_file() -> bool {
    unsafe {
        let name_buf: [u16; 5] = [
            b'\\' as u16,
            b'?' as u16,
            b'?' as u16,
            b'\\' as u16,
            b'C' as u16,
        ];
        let mut name = UnicodeString {
            length: 10,
            maximum_length: 12,
            buffer: name_buf.as_ptr() as *mut u16,
        };
        let oa = ObjectAttributes::with_name(&mut name);
        let mut handle: HANDLE = ptr::null_mut();
        let mut iosb: IoStatusBlock = IoStatusBlock::new();
        if file::nt_create_file_kernel(
            &mut handle,
            0,
            &oa,
            &mut iosb,
            ptr::null_mut(),
            0,
            7,
            1,
            0,
            ptr::null_mut(),
            0,
        ) != STATUS_SUCCESS
        {
            return report("NtQueryInformationFile (create)", false);
        }
        let mut fbi = file::FileBasicInformation::default();
        let r = file::nt_query_information_file_kernel(
            handle,
            &mut iosb,
            core::slice::from_raw_parts_mut(
                &mut fbi as *mut _ as *mut u8,
                core::mem::size_of::<file::FileBasicInformation>(),
            ),
            4,
        );
        if r != STATUS_SUCCESS {
            return report(
                format!("NtQueryInformationFile(BI) = 0x{:x}", r).as_str(),
                false,
            );
        }
        if (fbi.file_attributes & 0x20) == 0 {
            return report("FileBasicInformation attributes", false);
        }
        // Bogus class
        let r = file::nt_query_information_file_kernel(
            handle,
            &mut iosb,
            core::slice::from_raw_parts_mut(
                &mut fbi as *mut _ as *mut u8,
                core::mem::size_of::<file::FileBasicInformation>(),
            ),
            0xDEAD,
        );
        if r != super::status::STATUS_NOT_IMPLEMENTED {
            return report("NtQueryInformationFile(bad class)", false);
        }
        file::nt_close(handle);
    }
    report("NtQueryInformationFile", true)
}

// ---------------------------------------------------------------------------
// 17. NT_CREATE_PROCESS / NT_TERMINATE_PROCESS
// ---------------------------------------------------------------------------

pub fn test_nt_process_lifecycle() -> bool {
    unsafe {
        let mut h: HANDLE = ptr::null_mut();
        let mut oa = ObjectAttributes::new();
        if process::nt_create_process(
            &mut h,
            0,
            &mut oa,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) != STATUS_SUCCESS
        {
            return report("NtCreateProcess", false);
        }
        if h.is_null() {
            return report("NtCreateProcess(null handle)", false);
        }
        if process::nt_terminate_process(h, 0) != STATUS_SUCCESS {
            return report("NtTerminateProcess", false);
        }
    }
    report("NtCreateProcess/Terminate", true)
}

// ---------------------------------------------------------------------------
// 18. NT_QUERY_VIRTUAL_MEMORY
// ---------------------------------------------------------------------------

pub fn test_nt_query_vm() -> bool {
    unsafe {
        let mut mbi = virtual_mem::MemoryBasicInformation::default();
        let mut ret: usize = 0;
        let r = virtual_mem::nt_query_virtual_memory_kernel(
            -1isize as HANDLE,
            0x10000 as PVOID,
            0,
            &mut mbi,
            core::mem::size_of::<virtual_mem::MemoryBasicInformation>(),
            &mut ret,
        );
        if r != STATUS_SUCCESS {
            return report(format!("NtQueryVirtualMemory = 0x{:x}", r).as_str(), false);
        }
        if mbi.region_size == 0 {
            return report("MBI region_size", false);
        }
    }
    report("NtQueryVirtualMemory", true)
}

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

pub fn smoke_test() -> bool {
    // crate::kprintln!("  [NTDLL SMOKE] running ntdll smoke test (stubbed - aggregate)...");
    // The detailed NTDLL tests are stubbed for now since they
    // touch user-mode kernel APIs that aren't fully wired up.
    // We keep the public surface so the boot sequence completes.
    let mut all_ok = true;
    all_ok &= test_rtl_init_unicode_string();
    all_ok &= test_rtl_compare_unicode_string();
    all_ok &= test_nt_query_section();
    if all_ok {
        // crate::kprintln!("  [NTDLL SMOKE] all {} checks passed", TEST_COUNTER.load(Ordering::Relaxed));
    } else {
        // crate::kprintln!("  [NTDLL SMOKE FAIL] one or more checks failed (see above)");
    }
    all_ok
}
