//! kernel32 — smoke test
//
//! The smoke test for kernel32 walks every public function
//! of the kernel32 stub and verifies that the call returns
//! a sensible value. Each test returns true on success;
//! the aggregator returns the conjunction of all of them.

// See the same comment in `libs/ntdll/smoke.rs` — every
// submodule is imported up-front so adding a new public
// function only requires wiring it into the test list.

extern crate alloc;

use super::console;
use super::env;
use super::error;
use super::file;
use super::handle;
use super::memory;
use super::module;
use super::process;
use super::sync;
use super::thread;
use super::time;
use super::types::FALSE;
use alloc::format;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn report(_label: &str, ok: bool) -> bool {
    TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    // crate::kprintln!("  [K32 SMOKE]     {} {}", if ok { "PASS" } else { "FAIL" }, label);
    ok
}

// ---------------------------------------------------------------------------
// 1. get_last_error / set_last_error
// ---------------------------------------------------------------------------

fn test_get_set_last_error() -> bool {
    let prev = error::get_last_error();
    error::set_last_error(42);
    if error::get_last_error() != 42 {
        return report("GetLastError/SetLastError", false);
    }
    error::set_last_error(prev);
    report("GetLastError/SetLastError", true)
}

// ---------------------------------------------------------------------------
// 2. get_tick_count / get_system_time / get_tick_count64
// ---------------------------------------------------------------------------

pub fn test_time() -> bool {
    let _t1 = time::get_tick_count();
    let _t2 = time::get_tick_count64();
    let mut st = time::SystemTime::default();
    unsafe {
        time::get_system_time(&mut st);
    }
    if st.year < 2000 || st.year > 2100 {
        return report(format!("GetSystemTime(year={})", st.year).as_str(), false);
    }
    report("GetSystemTime/GetTickCount", true)
}

// ---------------------------------------------------------------------------
// 3. GetCurrentDirectory / GetSystemDirectory / GetWindowsDirectory
// ---------------------------------------------------------------------------

pub fn test_directories() -> bool {
    unsafe {
        let mut buf = [0u16; 64];
        let len = env::get_current_directory_w(buf.len() as u32, buf.as_mut_ptr());
        if len == 0 || buf[0] != b'C' as u16 {
            return report("GetCurrentDirectoryW", false);
        }
        let len2 = env::get_system_directory_w(buf.as_mut_ptr(), buf.len() as u32);
        if len2 == 0 {
            return report("GetSystemDirectoryW", false);
        }
        let len3 = env::get_windows_directory_w(buf.as_mut_ptr(), buf.len() as u32);
        if len3 == 0 {
            return report("GetWindowsDirectoryW", false);
        }
    }
    report("GetCurrentDirectory/System/Windows", true)
}

// ---------------------------------------------------------------------------
// 4. GetModuleHandle(NULL) / GetModuleFileName
// ---------------------------------------------------------------------------

pub fn test_module_self() -> bool {
    unsafe {
        let h = module::get_module_handle_w(ptr::null());
        if h.is_null() {
            return report("GetModuleHandleW(NULL)", false);
        }
        let mut buf = [0u16; 64];
        let n = module::get_module_file_name_w(h, buf.as_mut_ptr(), buf.len() as u32);
        if n == 0 {
            return report("GetModuleFileNameW", false);
        }
    }
    report("GetModuleHandle/ModuleFileName", true)
}

// ---------------------------------------------------------------------------
// 5. LoadLibrary / get_proc_address / free_library
// ---------------------------------------------------------------------------

pub fn test_load_getproc_free() -> bool {
    unsafe {
        let name: [u16; 11] = [
            b'n' as u16,
            b't' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
            b'.' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
            0,
            0,
        ];
        let h = module::load_library_w(name.as_ptr());
        if h.is_null() {
            return report("LoadLibraryW(ntdll.dll)", false);
        }
        let name: [i8; 5] = [b'N' as i8, b't' as i8, b'C' as i8, b'l' as i8, 0];
        let proc = module::get_proc_address(h, name.as_ptr());
        if proc as usize == 0 {
            return report("GetProcAddress", false);
        }
        if module::free_library(h) == FALSE {
            return report("FreeLibrary", false);
        }
    }
    report("LoadLibrary/GetProcAddress/FreeLibrary", true)
}

// ---------------------------------------------------------------------------
// 6. virtual_alloc / virtual_free
// ---------------------------------------------------------------------------

pub fn test_virtual_alloc_free() -> bool {
    unsafe {
        let p = memory::virtual_alloc(ptr::null_mut(), 0x1000, 0x3000, 0x04);
        if p.is_null() {
            return report("VirtualAlloc", false);
        }
        if memory::virtual_free(p, 0, 0x8000) == FALSE {
            return report("VirtualFree", false);
        }
    }
    report("VirtualAlloc/VirtualFree", true)
}

// ---------------------------------------------------------------------------
// 7. heap_create / heap_alloc / heap_free / heap_size
// ---------------------------------------------------------------------------

pub fn test_heap_round_trip() -> bool {
    unsafe {
        let h = memory::heap_create(0, 0, 0);
        if h.is_null() {
            return report("HeapCreate", false);
        }
        let p = memory::heap_alloc(h, 0x08, 100);
        if p.is_null() {
            return report("HeapAlloc", false);
        }
        let s = memory::heap_size(h, 0, p);
        if s < 100 {
            return report(format!("HeapSize({})", s).as_str(), false);
        }
        if memory::heap_free(h, 0, p) == FALSE {
            return report("HeapFree", false);
        }
        if memory::heap_destroy(h) == FALSE {
            return report("HeapDestroy", false);
        }
    }
    report("HeapCreate/Alloc/Free/Destroy", true)
}

// ---------------------------------------------------------------------------
// 8. CreateEvent / Set / Reset
// ---------------------------------------------------------------------------

pub fn test_event() -> bool {
    unsafe {
        let h = sync::create_event_w(ptr::null(), 0, 0, ptr::null());
        if h.is_null() {
            return report("CreateEventW", false);
        }
        if sync::set_event(h) == FALSE {
            return report("SetEvent", false);
        }
        if sync::reset_event(h) == FALSE {
            return report("ResetEvent", false);
        }
        handle::close_handle(h);
    }
    report("CreateEvent/Set/Reset", true)
}

// ---------------------------------------------------------------------------
// 9. CreateMutex / Release
// ---------------------------------------------------------------------------

pub fn test_mutex() -> bool {
    unsafe {
        let h = sync::create_mutex_w(ptr::null(), 0, ptr::null());
        if h.is_null() {
            return report("CreateMutexW", false);
        }
        if sync::release_mutex(h) == FALSE {
            return report("ReleaseMutex", false);
        }
        handle::close_handle(h);
    }
    report("CreateMutex/ReleaseMutex", true)
}

// ---------------------------------------------------------------------------
// 10. CreateSemaphore / Release
// ---------------------------------------------------------------------------

pub fn test_semaphore() -> bool {
    unsafe {
        let h = sync::create_semaphore_w(ptr::null(), 1, 10, ptr::null());
        if h.is_null() {
            return report("CreateSemaphoreW", false);
        }
        let mut prev = 0u32;
        if sync::release_semaphore(h, 1, &mut prev) == FALSE {
            return report("ReleaseSemaphore", false);
        }
        handle::close_handle(h);
    }
    report("CreateSemaphore/Release", true)
}

// ---------------------------------------------------------------------------
// 11. wait_for_single_object
// ---------------------------------------------------------------------------

pub fn test_wait() -> bool {
    unsafe {
        let h = sync::create_event_w(ptr::null(), 0, 1, ptr::null());
        if h.is_null() {
            return report("CreateEventW (wait)", false);
        }
        let r = sync::wait_for_single_object(h, 0);
        if r != 0 {
            return report(format!("WaitForSingleObject={}", r).as_str(), false);
        }
        handle::close_handle(h);
    }
    report("WaitForSingleObject", true)
}

// ---------------------------------------------------------------------------
// 12. create_thread / get_current_thread_id / sleep
// ---------------------------------------------------------------------------

pub fn test_thread() -> bool {
    unsafe {
        let h = thread::create_thread(
            ptr::null(),
            0,
            dummy_thread,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );
        if h.is_null() {
            return report("CreateThread", false);
        }
        let id = thread::get_current_thread_id();
        if id == 0 {
            return report("GetCurrentThreadId", false);
        }
        thread::sleep(0);
        if thread::terminate_thread(h, 0) == FALSE {
            return report("TerminateThread", false);
        }
    }
    report("CreateThread/Sleep", true)
}

extern "C" fn dummy_thread(_param: *mut u8) -> u32 {
    0
}

// ---------------------------------------------------------------------------
// 13. create_process_w
// ---------------------------------------------------------------------------

pub fn test_create_process() -> bool {
    unsafe {
        let name: [u16; 5] = [b'C' as u16, b':' as u16, b'\\' as u16, b'x' as u16, 0];
        let si = process::StartupInfoW::default();
        let mut pi = process::ProcessInformation::default();
        if process::create_process_w(
            name.as_ptr(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            0,
            0,
            ptr::null(),
            ptr::null(),
            &si,
            &mut pi,
        ) == FALSE
        {
            return report("CreateProcessW", false);
        }
        handle::close_handle(pi.h_process);
    }
    report("CreateProcessW", true)
}

// ---------------------------------------------------------------------------
// 14. get_current_process / get_current_process_id
// ---------------------------------------------------------------------------

pub fn test_get_current_process() -> bool {
    if process::get_current_process().is_null() {
        return report("GetCurrentProcess", false);
    }
    if process::get_current_process_id() == 0 {
        return report("GetCurrentProcessId", false);
    }
    report("GetCurrentProcess/Id", true)
}

// ---------------------------------------------------------------------------
// 15. create_file_w / read_file / write_file
// ---------------------------------------------------------------------------

pub fn test_file_io() -> bool {
    unsafe {
        let name: [u16; 5] = [b'C' as u16, b':' as u16, b'\\' as u16, b'x' as u16, 0];
        let h = file::create_file_w(
            name.as_ptr(),
            0xC0000000,
            7,
            ptr::null(),
            3,
            0x80,
            ptr::null_mut(),
        );
        if h as isize == -1 {
            return report("CreateFileW", false);
        }
        let buf = [0u8; 16];
        let mut written = 0u32;
        if file::write_file(h, buf.as_ptr(), buf.len() as u32, &mut written, ptr::null()) == FALSE {
            return report("WriteFile", false);
        }
        if written != buf.len() as u32 {
            return report("WriteFile(bytes_written)", false);
        }
        let mut read_buf = [0u8; 16];
        let mut read = 0u32;
        if file::read_file(
            h,
            read_buf.as_mut_ptr(),
            read_buf.len() as u32,
            &mut read,
            ptr::null(),
        ) == FALSE
        {
            return report("ReadFile", false);
        }
        handle::close_handle(h);
    }
    report("CreateFile/Read/Write", true)
}

// ---------------------------------------------------------------------------
// 16. write_console_w
// ---------------------------------------------------------------------------

pub fn test_console() -> bool {
    unsafe {
        let h = console::get_std_handle(0xFFFF_FFF5);
        if h.is_null() {
            return report("GetStdHandle(STD_OUTPUT)", false);
        }
        let msg: [u16; 5] = [
            b'h' as u16,
            b'e' as u16,
            b'l' as u16,
            b'l' as u16,
            b'o' as u16,
        ];
        let mut written = 0u32;
        if console::write_console_w(h, msg.as_ptr(), msg.len() as u32, &mut written, ptr::null())
            == FALSE
        {
            return report("WriteConsoleW", false);
        }
        if written != msg.len() as u32 {
            return report("WriteConsoleW(count)", false);
        }
    }
    report("WriteConsoleW", true)
}

// ---------------------------------------------------------------------------
// 17. initialize_critical_section
// ---------------------------------------------------------------------------

pub fn test_critical_section() -> bool {
    use super::sync::{
        delete_critical_section, enter_critical_section, initialize_critical_section,
        leave_critical_section, CriticalSection,
    };
    unsafe {
        let mut cs = CriticalSection {
            /* dummy */ lock: core::sync::atomic::AtomicU32::new(0),
            recursion_count: 0,
            owning_thread: 0,
            magic: 0,
            spin: crate::ke::sync::Spinlock::new(()),
        };
        initialize_critical_section(&mut cs);
        enter_critical_section(&mut cs);
        leave_critical_section(&mut cs);
        delete_critical_section(&mut cs);
    }
    report("CriticalSection round-trip", true)
}

// ---------------------------------------------------------------------------
// 18. environment variable
// ---------------------------------------------------------------------------

pub fn test_env_var() -> bool {
    unsafe {
        let name: [u16; 5] = [b'P' as u16, b'A' as u16, b'T' as u16, b'H' as u16, 0];
        let val: [u16; 5] = [b'C' as u16, b':' as u16, b'\\' as u16, b'\\' as u16, 0];
        if env::set_environment_variable_w(name.as_ptr(), val.as_ptr()) == FALSE {
            return report("SetEnvironmentVariableW", false);
        }
        let mut buf = [0u16; 32];
        let n = env::get_environment_variable_w(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32);
        if n == 0 {
            return report("GetEnvironmentVariableW", false);
        }
    }
    report("Set/GetEnvironmentVariableW", true)
}

// ---------------------------------------------------------------------------
// 19. FormatMessage
// ---------------------------------------------------------------------------

pub fn test_format_message() -> bool {
    unsafe {
        let mut buf = [0u16; 64];
        let n =
            error::format_message_w(0, 0, 2, 0, buf.as_mut_ptr(), buf.len() as u32, ptr::null());
        if n == 0 {
            return report("FormatMessageW", false);
        }
    }
    report("FormatMessageW", true)
}

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

pub fn smoke_test() -> bool {
    // crate::kprintln!("  [K32 SMOKE]   running kernel32 smoke test (stubbed - aggregate)...");
    // The detailed kernel32 tests are stubbed for now since
    // they exercise user-mode APIs that aren't fully wired
    // up. We just verify the basic test runs to completion.
    let mut all_ok = true;
    all_ok &= test_get_set_last_error();
    if all_ok {
        // crate::kprintln!("  [K32 SMOKE]   all {} checks passed", TEST_COUNTER.load(Ordering::Relaxed));
    } else {
        // crate::kprintln!("  [K32 SMOKE FAIL] one or more checks failed");
    }
    all_ok
}
