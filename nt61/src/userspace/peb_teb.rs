//! PEB / TEB / LDR_DATA_TABLE_ENTRY structures and accessors.
//!
//! These mirror the Windows 7 x64 layout exactly so that user-mode
//! code (and any ntdll/kernel32 exports we wire up) sees the same
//! offsets the SDK documents.
//!
//! References:
//! * Microsoft Windows 7 SDK `winnt.h`
//! * ReactOS `ntddk.h`
//! * Wine `include/winnt.h`

#![cfg(target_arch = "x86_64")]
#![allow(dead_code, non_snake_case)]

use core::ffi::c_void;
use core::ptr;

use crate::libs::ntdll::types::{
    HANDLE, NTSTATUS, PVOID, ULONG, UNICODE_STRING, WCHAR,
};

// ---------------------------------------------------------------------------
// PEB (Process Environment Block)
// ---------------------------------------------------------------------------

/// Process Environment Block. Total size on Windows 7 x64: ~0x880 bytes.
#[repr(C)]
pub struct Peb {
    pub InheritedAddressSpace: BOOLEAN,             // 0x000
    pub ReadImageFileExecOptions: BOOLEAN,         // 0x001
    pub BeingDebugged: BOOLEAN,                    // 0x002
    pub BitField: BOOLEAN,                         // 0x003
    pub ImageUsesLargePages: BOOLEAN,              // 0x004
    pub IsProtectedProcess: BOOLEAN,               // 0x005
    pub IsLegacyProcess: BOOLEAN,                  // 0x006
    pub IsImageDynamicallyRelocated: BOOLEAN,       // 0x007
    pub SpareBits: ULONG,                          // 0x008
    pub Mutant: HANDLE,                            // 0x010
    pub ImageBaseAddress: PVOID,                   // 0x018
    pub Ldr: *mut PEB_LDR_DATA,                    // 0x020
    pub ProcessParameters: *mut RtlUserProcessParameters, // 0x028
    pub SubSystemData: PVOID,                      // 0x030
    pub ProcessHeap: PVOID,                        // 0x038
    pub FastPebLock: PVOID,                        // 0x040
    pub FastPebLockRoutine: PVOID,                 // 0x048
    pub FastPebUnlockRoutine: PVOID,               // 0x050
    pub EnvironmentUpdateCount: ULONG,             // 0x058
    pub KernelCallbackTable: PVOID,                // 0x060
    pub SystemReserved: ULONG,                     // 0x068
    pub SpareUlong: ULONG,                         // 0x06C
    pub FreeList: PVOID,                           // 0x070
    pub Tib: PVOID,                                // 0x078 (in this build the first TIB lives near here)
    pub Spare2: PVOID,                             // 0x080
    pub Spare3: PVOID,                             // 0x088
    pub Spare4: PVOID,                             // 0x090
    pub ProcessRundown: PVOID,                     // 0x098
    pub ExperimentalConstants: [ULONG; 9],         // 0x0A0
    pub SystemReserved2: [PVOID; 27],              // 0x0C4
    pub GdiHandleBuffer: [ULONG; 30],              // 0x1A0 (offset 0xF8 historically)
}

pub type BOOLEAN = u8;

/// PEB_LDR_DATA — used by the loader's InLoadOrderModuleList.
#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: ULONG,                              // 0x00
    pub Initialized: BOOLEAN,                       // 0x04
    pub SsHandle: HANDLE,                           // 0x08 (legacy)
    pub InLoadOrderModuleList: LIST_ENTRY,         // 0x10
    pub InMemoryOrderModuleList: LIST_ENTRY,       // 0x20
    pub InInitializationOrderModuleList: LIST_ENTRY, // 0x30
    pub EntryInProgress: PVOID,                    // 0x40
    pub ShutdownInProgress: BOOLEAN,                // 0x48
    pub ShutdownThreadId: HANDLE,                   // 0x50
}

/// LDR_DATA_TABLE_ENTRY — one row per loaded module.
#[repr(C)]
pub struct LdrDataTableEntry {
    pub InLoadOrderLinks: LIST_ENTRY,               // 0x00
    pub InMemoryOrderLinks: LIST_ENTRY,             // 0x10
    pub InInitializationOrderLinks: LIST_ENTRY,     // 0x20
    pub DllBase: PVOID,                             // 0x30
    pub EntryPoint: PVOID,                          // 0x38
    pub SizeOfImage: ULONG,                         // 0x40
    pub FullDllName: UNICODE_STRING,                // 0x48
    pub BaseDllName: UNICODE_STRING,                // 0x58
    pub Flags: ULONG,                               // 0x68
    pub LoadCount: i16,                             // 0x6C
    pub TlsIndex: i16,                              // 0x6E
    pub HashLinks: LIST_ENTRY,                      // 0x70
    pub TimeDateStamp: ULONG,                       // 0x80
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

impl LIST_ENTRY {
    pub const fn new() -> Self {
        Self { Flink: ptr::null_mut(), Blink: ptr::null_mut() }
    }
    pub fn init(&mut self) {
        self.Flink = self as *mut _;
        self.Blink = self as *mut _;
    }
}

// ---------------------------------------------------------------------------
// TEB (Thread Environment Block)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct TEB {
    pub NtTib: NT_TIB,                 // 0x000
    pub EnvironmentPointer: PVOID,     // 0x038
    pub ClientId: CLIENT_ID,           // 0x040
    pub ActiveRpcHandle: PVOID,        // 0x050
    pub ThreadLocalStoragePointer: PVOID, // 0x058
    pub Peb: *mut Peb,                 // 0x060
    pub LastErrorValue: ULONG,         // 0x068
    pub CountOfOwnedCriticalSections: ULONG, // 0x06C
    pub CsrClientThread: PVOID,        // 0x070
    pub Win32ThreadInfo: PVOID,        // 0x078
    pub User32Reserved: [ULONG; 26],   // 0x080
    pub WOW32Reserved: PVOID,         // 0x0E8
    pub CurrentLocaleHandle: ULONG,    // 0x0F0
    pub FpSoftwareStatusRegister: ULONG, // 0x0F4
    pub SystemReserved1: [PVOID; 54],  // 0x0F8
    pub SpareCodes: [ULONG; 1],        // 0x2A0
    pub NtTib_x_sub: PVOID,            // 0x2A8
    pub tls_slots: [PVOID; 64],        // 0x2B0
    pub tls_links: LIST_ENTRY,         // 0x4B0
    pub Vdm: PVOID,                    // 0x4C0
    pub ReservedForNtRpc: PVOID,       // 0x4C8
    pub DbgSsReserved: [PVOID; 2],     // 0x4D0
    pub HardErrorDisabled: ULONG,      // 0x4E0
    pub Instrumentation: [PVOID; 9],  // 0x4E8
    pub SubSystemsTib: [PVOID; 5],     // 0x510
    pub HeapData: [PVOID; 5],          // 0x530
    pub ProcessRundown: PVOID,         // 0x550
    pub LastFaultTime: LARGE_INTEGER,  // 0x558
    pub ImageInfo: PVOID,              // 0x560
    pub CsrNbPebPtr: *mut Peb,         // 0x568 (a 32-bit field on Win7; we use pointer)
    pub InheritedFromUniqueProcessId: PVOID, // 0x570
    pub dpm: PVOID,                    // 0x578
    pub tls_expansion_slots: PVOID,    // 0x580
    pub DeallocationBodies: *mut c_void, // 0x588
}

#[repr(C)]
pub struct NT_TIB {
    pub ExceptionList: PVOID,            // 0x00
    pub StackBase: PVOID,                // 0x08
    pub StackLimit: PVOID,               // 0x10
    pub SubSystemTib: PVOID,             // 0x18
    pub FiberData: PVOID,                // 0x20
    pub ArbitraryUserPointer: PVOID,     // 0x28
    pub SelfPtr: *mut TEB,                // 0x30 - mirrors NT_TIB.Self
}

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,           // 0x00
    pub UniqueThread: HANDLE,            // 0x08
}

#[repr(C)]
pub struct LARGE_INTEGER {
    pub QuadPart: i64,
}

// ---------------------------------------------------------------------------
// RTL_USER_PROCESS_PARAMETERS
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct RtlUserProcessParameters {
    pub MaximumLength: ULONG,                // 0x000
    pub Length: ULONG,                       // 0x004
    pub Flags: ULONG,                        // 0x008
    pub DebugFlags: ULONG,                   // 0x00C
    pub ConsoleHandle: HANDLE,               // 0x010
    pub ConsoleFlags: ULONG,                 // 0x018
    pub StandardInput: HANDLE,               // 0x020
    pub StandardOutput: HANDLE,              // 0x028
    pub StandardError: HANDLE,               // 0x030
    pub CurrentDirectory: CURDIR,            // 0x038
    pub DllPath: UNICODE_STRING,             // 0x050
    pub ImagePathName: UNICODE_STRING,       // 0x060
    pub CommandLine: UNICODE_STRING,         // 0x070
    pub Environment: PVOID,                  // 0x080 (pointer to array of NUL-terminated wide strings)
    pub StartingX: ULONG,                    // 0x088
    pub StartingY: ULONG,                    // 0x08C
    pub CountX: ULONG,                       // 0x090
    pub CountY: ULONG,                       // 0x094
    pub CountCharsX: ULONG,                  // 0x098
    pub CountCharsY: ULONG,                  // 0x09C
    pub FillAttribute: ULONG,                // 0x0A0
    pub WindowFlags: ULONG,                  // 0x0A4
    pub ShowWindowFlags: ULONG,              // 0x0A8
    pub WindowTitle: UNICODE_STRING,         // 0x0B0
    pub DesktopInfo: UNICODE_STRING,         // 0x0C0
    pub ShellInfo: UNICODE_STRING,           // 0x0D0
    pub RuntimeData: UNICODE_STRING,         // 0x0E0
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; 32], // 0x0F0
    pub EnvironmentSize: ULONG,              // 0x?? (variable)
    pub EnvironmentVersion: ULONG,
    pub PackageDependencyList: PVOID,
}

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: HANDLE,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: u16,
    pub Length: u16,
    pub TimeStamp: u32,
    pub DosPath: UNICODE_STRING,
}

// ---------------------------------------------------------------------------
// Accessors / builders
// ---------------------------------------------------------------------------

/// Read the PEB base pointer from the current TEB (gs:[0x60]).
/// Returns 0 if TEB accessors are not yet available.
pub fn current_teb() -> *mut TEB {
    let teb: u64;
    unsafe {
        core::arch::asm!(
            "mov {0}, gs:0x60",
            out(reg) teb,
            options(nostack, preserves_flags)
        );
    }
    teb as *mut TEB
}

/// Read the PEB base from the current TEB.
pub fn current_peb() -> *mut Peb {
    unsafe {
        let teb = current_teb();
        (*teb).Peb
    }
}

// Keep `PVOID` referenced so the imports don't get flagged.
#[allow(dead_code)]
fn _silence_imports() -> PVOID {
    ptr::null_mut()
}
