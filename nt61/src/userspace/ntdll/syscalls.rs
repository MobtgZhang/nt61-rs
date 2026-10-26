//! System-call number definitions (Windows 7 x64 kernel).
//!
//! Only the most commonly used calls are listed here — Phase 2
//! extends the list as subsystems grow. The numbers match
//! `ntoskrnl.exe` of Windows 7 (build 7601).

// Process / thread
pub const NT_CREATE_PROCESS: u32 = 0x009F;
pub const NT_CREATE_THREAD: u32 = 0x004B;
pub const NT_CREATE_USER_PROCESS: u32 = 0x00AA;
pub const NT_TERMINATE_PROCESS: u32 = 0x0029;
pub const NT_TERMINATE_THREAD: u32 = 0x0050;
pub const NT_OPEN_PROCESS: u32 = 0x0023;
pub const NT_OPEN_THREAD: u32 = 0x00FE;
pub const NT_QUERY_INFORMATION_PROCESS: u32 = 0x0016;
pub const NT_SET_INFORMATION_PROCESS: u32 = 0x0019;
pub const NT_QUERY_INFORMATION_THREAD: u32 = 0x0022;
pub const NT_SET_INFORMATION_THREAD: u32 = 0x000A;
pub const NT_SUSPEND_THREAD: u32 = 0x017B;
pub const NT_RESUME_THREAD: u32 = 0x004F;

// Virtual memory
pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x0015;
pub const NT_FREE_VIRTUAL_MEMORY: u32 = 0x001B;
pub const NT_READ_VIRTUAL_MEMORY: u32 = 0x003C;
pub const NT_WRITE_VIRTUAL_MEMORY: u32 = 0x0037;
pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x004D;
pub const NT_QUERY_VIRTUAL_MEMORY: u32 = 0x0020;

// File I/O
pub const NT_CREATE_FILE: u32 = 0x0052;
pub const NT_OPEN_FILE: u32 = 0x0030;
pub const NT_READ_FILE: u32 = 0x0003;
pub const NT_WRITE_FILE: u32 = 0x0005;
pub const NT_CLOSE: u32 = 0x000C;
pub const NT_QUERY_INFORMATION_FILE: u32 = 0x000E;
pub const NT_SET_INFORMATION_FILE: u32 = 0x0024;
pub const NT_QUERY_DIRECTORY_FILE: u32 = 0x0032;
pub const NT_DELETE_FILE: u32 = 0x00B2;

// Synchronisation
pub const NT_CREATE_EVENT: u32 = 0x0045;
pub const NT_OPEN_EVENT: u32 = 0x003D;
pub const NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x0001;
pub const NT_WAIT_FOR_MULTIPLE_OBJECTS: u32 = 0x0058;
pub const NT_SET_EVENT: u32 = 0x000B;
pub const NT_RESET_EVENT: u32 = 0x0141;
pub const NT_CREATE_MUTANT: u32 = 0x009A;
pub const NT_CREATE_SEMAPHORE: u32 = 0x00A3;
pub const NT_CREATE_TIMER: u32 = 0x00A6;
pub const NT_DELAY_EXECUTION: u32 = 0x0031;
pub const NT_YIELD_EXECUTION: u32 = 0x0043;

// Keyed events / fast locks
pub const NT_CREATE_KEYED_EVENT: u32 = 0x0098;

// Section / map
pub const NT_CREATE_SECTION: u32 = 0x0047;
pub const NT_OPEN_SECTION: u32 = 0x0034;
pub const NT_MAP_VIEW_OF_SECTION: u32 = 0x0025;
pub const NT_UNMAP_VIEW_OF_SECTION: u32 = 0x0027;

// Registry
pub const NT_CREATE_KEY: u32 = 0x001A;
pub const NT_OPEN_KEY: u32 = 0x000F;
pub const NT_QUERY_VALUE_KEY: u32 = 0x0014;
pub const NT_SET_VALUE_KEY: u32 = 0x005D;
pub const NT_ENUMERATE_VALUE_KEY: u32 = 0x0010;
pub const NT_ENUMERATE_KEY: u32 = 0x002F;
pub const NT_DELETE_KEY: u32 = 0x00B3;
pub const NT_CLOSE_KEY: u32 = 0x000C;

// Process / thread time
pub const NT_QUERY_SYSTEM_TIME: u32 = 0x0057;
pub const NT_QUERY_PERFORMANCE_COUNTER: u32 = 0x002E;
pub const NT_SET_SYSTEM_TIME: u32 = 0x016E;

// Information
pub const NT_QUERY_SYSTEM_INFORMATION: u32 = 0x0033;

// Misc
pub const NT_TEST_ALERT: u32 = 0x017E;
pub const NT_CONTINUE: u32 = 0x0040;
pub const NT_RAISE_HARD_ERROR: u32 = 0x0130;
pub const NT_ALERT_THREAD: u32 = 0x006A;
pub const NT_ALERT_RESUME_THREAD: u32 = 0x0069;

// Exit / shutdown
pub const NT_SHUTDOWN_SYSTEM: u32 = 0x0174;

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_number(name: &str) -> u32 {
        crate::arch::x86_64::win7_sp1_syscalls::NATIVE_SYSCALLS
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| u32::from(entry.number))
            .unwrap_or_else(|| panic!("missing Windows 7 SP1 syscall: {name}"))
    }

    #[test]
    fn native_numbers_match_windows_7_sp1() {
        const EXPECTED: [(&str, u32); 50] = [
            ("NtAllocateVirtualMemory", NT_ALLOCATE_VIRTUAL_MEMORY),
            ("NtAlertResumeThread", NT_ALERT_RESUME_THREAD),
            ("NtAlertThread", NT_ALERT_THREAD),
            ("NtClose", NT_CLOSE),
            ("NtContinue", NT_CONTINUE),
            ("NtCreateEvent", NT_CREATE_EVENT),
            ("NtCreateFile", NT_CREATE_FILE),
            ("NtCreateKey", NT_CREATE_KEY),
            ("NtCreateKeyedEvent", NT_CREATE_KEYED_EVENT),
            ("NtCreateMutant", NT_CREATE_MUTANT),
            ("NtCreateProcess", NT_CREATE_PROCESS),
            ("NtCreateSemaphore", NT_CREATE_SEMAPHORE),
            ("NtCreateSection", NT_CREATE_SECTION),
            ("NtCreateThread", NT_CREATE_THREAD),
            ("NtCreateTimer", NT_CREATE_TIMER),
            ("NtCreateUserProcess", NT_CREATE_USER_PROCESS),
            ("NtDeleteFile", NT_DELETE_FILE),
            ("NtDeleteKey", NT_DELETE_KEY),
            ("NtDelayExecution", NT_DELAY_EXECUTION),
            ("NtEnumerateKey", NT_ENUMERATE_KEY),
            ("NtEnumerateValueKey", NT_ENUMERATE_VALUE_KEY),
            ("NtFreeVirtualMemory", NT_FREE_VIRTUAL_MEMORY),
            ("NtMapViewOfSection", NT_MAP_VIEW_OF_SECTION),
            ("NtOpenEvent", NT_OPEN_EVENT),
            ("NtOpenFile", NT_OPEN_FILE),
            ("NtOpenKey", NT_OPEN_KEY),
            ("NtOpenProcess", NT_OPEN_PROCESS),
            ("NtOpenSection", NT_OPEN_SECTION),
            ("NtOpenThread", NT_OPEN_THREAD),
            ("NtProtectVirtualMemory", NT_PROTECT_VIRTUAL_MEMORY),
            ("NtQueryDirectoryFile", NT_QUERY_DIRECTORY_FILE),
            ("NtQueryInformationFile", NT_QUERY_INFORMATION_FILE),
            ("NtQueryInformationProcess", NT_QUERY_INFORMATION_PROCESS),
            ("NtQueryInformationThread", NT_QUERY_INFORMATION_THREAD),
            ("NtQueryPerformanceCounter", NT_QUERY_PERFORMANCE_COUNTER),
            ("NtQuerySystemInformation", NT_QUERY_SYSTEM_INFORMATION),
            ("NtQuerySystemTime", NT_QUERY_SYSTEM_TIME),
            ("NtQueryValueKey", NT_QUERY_VALUE_KEY),
            ("NtQueryVirtualMemory", NT_QUERY_VIRTUAL_MEMORY),
            ("NtReadFile", NT_READ_FILE),
            ("NtReadVirtualMemory", NT_READ_VIRTUAL_MEMORY),
            ("NtWriteFile", NT_WRITE_FILE),
            ("NtResetEvent", NT_RESET_EVENT),
            ("NtResumeThread", NT_RESUME_THREAD),
            ("NtRaiseHardError", NT_RAISE_HARD_ERROR),
            ("NtSetEvent", NT_SET_EVENT),
            ("NtSetInformationFile", NT_SET_INFORMATION_FILE),
            ("NtSetInformationProcess", NT_SET_INFORMATION_PROCESS),
            ("NtSetInformationThread", NT_SET_INFORMATION_THREAD),
            ("NtSetValueKey", NT_SET_VALUE_KEY),
        ];

        for (name, actual) in EXPECTED {
            assert_eq!(actual, expected_number(name), "mismatch for {name}");
        }
    }
}
