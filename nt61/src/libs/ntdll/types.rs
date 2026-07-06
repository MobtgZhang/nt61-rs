//! ntdll.dll — public types
//
//! NT 6.1 (Windows 7) public types from `ntddk.h`, `ntdef.h`, and
//! `winnt.h`. These mirror the layout of the Windows 7 SDK so the
//! DLL stubs have the correct FFI signatures. The structs are
//! `#[repr(C)]` and field-for-field compatible with the on-the-wire
//! NT types.
//
//! References (for layout only — no code is copied):
//!   * Microsoft Windows 7 SDK `ntddk.h` / `ntdef.h`
//!   * ReactOS 0.3.x `ntdef.h`
//!   * Wine 1.7.x `include/winnt.h`

use core::ffi::c_void;

/// NTSTATUS — `LONG` on every supported platform.
pub type NTSTATUS = i32;

/// Boolean (`BOOLEAN` in NT). Always 0 or 1.
pub type BOOLEAN = u8;

/// NT handle. `HANDLE` is a `void*` in the SDK; the value
/// `INVALID_HANDLE_VALUE` is `-1` cast to a pointer.
pub type HANDLE = *mut c_void;

/// Base address / virtual pointer (`PVOID`).
pub type PVOID = *mut c_void;

/// Const pointer to void.
pub type PCVOID = *const c_void;

/// Unsigned size_t (`SIZE_T`).
pub type SIZE_T = usize;

/// Signed size_t (`SSIZE_T`).
pub type SSIZE_T = isize;

/// Unsigned 8-bit byte.
pub type BYTE = u8;

/// Unsigned 16-bit word.
pub type WORD = u16;

/// Unsigned 32-bit doubleword.
pub type DWORD = u32;

/// Unsigned 32-bit (also `UINT`).
pub type UINT = u32;

/// Unsigned 64-bit.
pub type ULONG64 = u64;

/// Signed 32-bit.
pub type LONG = i32;

/// Unsigned 32-bit.
pub type ULONG = u32;

/// Signed 64-bit.
pub type LONGLONG = i64;

/// Wide character (UTF-16 code unit on NT).
pub type WCHAR = u16;

/// Wide string pointer (`PWSTR`).
pub type PWSTR = *mut WCHAR;

/// Const wide string pointer (`PCWSTR`).
pub type PCWSTR = *const WCHAR;

/// ANSI character.
pub type CCHAR = i8;

/// ANSI string pointer (`PSTR`).
pub type PSTR = *mut CCHAR;

/// Const ANSI string pointer (`PCSTR`).
pub type PCSTR = *const CCHAR;

/// `UNICODE_STRING` — counted UTF-16 string. The `Buffer` is
/// either `MaximumLength / 2` UTF-16 code units long, or — for
/// an empty string — `Buffer` may be `null_mut()` and `Length`
/// zero.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UnicodeString {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}

/// Alias for `UnicodeString` matching the original NT type casing.
pub type UNICODE_STRING = UnicodeString;

/// `LARGE_INTEGER` is defined later in this file (single `QuadPart`
/// representation) — see the second definition below. We provide an
/// alias here so callers can use either spelling.
pub type LARGE_INTEGER = LargeInteger;

impl UnicodeString {
    pub const fn new() -> Self {
        Self { Length: 0, MaximumLength: 0, Buffer: core::ptr::null_mut() }
    }

    pub fn from_slice(s: &[u16]) -> Self {
        Self {
            Length: (s.len() * 2) as u16,
            MaximumLength: ((s.len() + 1) * 2) as u16,
            Buffer: s.as_ptr() as *mut WCHAR,
        }
    }

    pub fn from_str(s: &str) -> Self {
        let mut buf = [0u16; 256];
        let mut i = 0;
        for c in s.chars().take(255) {
            buf[i] = c as u16;
            i += 1;
        }
        buf[i] = 0;
        Self {
            Length: (i * 2) as u16,
            MaximumLength: ((i + 1) * 2) as u16,
            Buffer: buf.as_mut_ptr(),
        }
    }

    /// Length in characters (not bytes).
    pub fn char_len(&self) -> usize {
        (self.Length / 2) as usize
    }

    pub fn as_slice(&self) -> &[u16] {
        if self.Buffer.is_null() || self.Length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.Buffer, self.char_len()) }
        }
    }
}

impl core::fmt::Debug for UnicodeString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.Buffer.is_null() {
            write!(f, "<null>")
        } else {
            let s = self.as_slice();
            for &c in s {
                if c == 0 { break; }
                if let Some(ch) = char::from_u32(c as u32) {
                    write!(f, "{}", ch)?;
                } else {
                    write!(f, "\\u{:04x}", c)?;
                }
            }
            Ok(())
        }
    }
}

/// `ANSI_STRING` — counted UTF-8/ASCII string.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AnsiString {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PSTR,
}

impl AnsiString {
    pub const fn new() -> Self {
        Self { Length: 0, MaximumLength: 0, Buffer: core::ptr::null_mut() }
    }
}

/// `LARGE_INTEGER` — 64-bit signed integer, union'd with a
/// `(LowPart, HighPart)` pair on 32-bit and a single `QuadPart`
/// on 64-bit. We always use `QuadPart`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LargeInteger {
    pub quad_part: i64,
}

impl LargeInteger {
    pub const fn new(v: i64) -> Self {
        Self { quad_part: v }
    }
}

/// `ULARGE_INTEGER` — unsigned counterpart of `LARGE_INTEGER`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ULargeInteger {
    pub quad_part: u64,
}

impl ULargeInteger {
    pub const fn new(v: u64) -> Self {
        Self { quad_part: v }
    }
}

/// `IO_STATUS_BLOCK` — every NT `Nt*File` API returns its
/// primary status in the `Status` field. `Information` is
/// operation-specific (bytes transferred, handle created, ...).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoStatusBlock {
    pub status: NTSTATUS,
    pub information: usize,
}

impl IoStatusBlock {
    pub const fn new() -> Self {
        Self { status: 0, information: 0 }
    }
}

/// `OBJECT_ATTRIBUTES` — passed to every `NtCreate*` /
/// `NtOpen*` API.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ObjectAttributes {
    pub Length: u32,
    pub root_directory: HANDLE,
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: PVOID,
    pub security_quality_of_service: PVOID,
}

impl ObjectAttributes {
    pub const fn new() -> Self {
        Self {
            Length: core::mem::size_of::<Self>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null_mut(),
            attributes: 0,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        }
    }

    pub fn with_name(name: *mut UnicodeString) -> Self {
        Self {
            object_name: name,
            ..Self::new()
        }
    }
}

/// `CLIENT_ID` — (ProcessId, ThreadId) pair used by NtOpen*.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ClientId {
    pub unique_process: HANDLE,
    pub unique_thread: HANDLE,
}

impl ClientId {
    pub const fn new() -> Self {
        Self { unique_process: core::ptr::null_mut(), unique_thread: core::ptr::null_mut() }
    }
}

/// `LIST_ENTRY` — doubly-linked list node.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl ListEntry {
    pub const fn new() -> Self {
        Self { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() }
    }

    pub fn init(&mut self) {
        self.flink = self as *mut _;
        self.blink = self as *mut _;
    }

    pub fn is_empty(&self) -> bool {
        let me = self as *const ListEntry as *mut ListEntry;
        self.flink.is_null() || self.flink == me
    }
}

/// File information class for `NtQueryInformationFile` /
/// `NtSetInformationFile`. Values are the NT 6.1 SDK.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileInformationClass {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileFullEaInformation = 15,
    FileModeInformation = 16,
    FileAlignmentInformation = 17,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileAlternateNameInformation = 21,
    FileStreamInformation = 22,
    FilePipeInformation = 23,
    FilePipeLocalInformation = 24,
    FilePipeRemoteInformation = 25,
    FileMailslotQueryInformation = 26,
    FileMailslotSetInformation = 27,
    FileCompressionInformation = 28,
    FileObjectIdInformation = 29,
    FileCompletionInformation = 30,
    FileMoveClusterInformation = 31,
    FileQuotaInformation = 32,
    FileReparsePointInformation = 33,
    FileNetworkOpenInformation = 34,
    FileAttributeTagInformation = 35,
    FileTrackingInformation = 36,
    FileIdBothDirectoryInformation = 37,
    FileIdFullDirectoryInformation = 38,
    FileValidDataLengthInformation = 39,
    FileShortNameInformation = 40,
}

impl FileInformationClass {
    pub fn from_u32(v: u32) -> Option<FileInformationClass> {
        match v {
            1  => Some(FileInformationClass::FileDirectoryInformation),
            2  => Some(FileInformationClass::FileFullDirectoryInformation),
            3  => Some(FileInformationClass::FileBothDirectoryInformation),
            4  => Some(FileInformationClass::FileBasicInformation),
            5  => Some(FileInformationClass::FileStandardInformation),
            6  => Some(FileInformationClass::FileInternalInformation),
            7  => Some(FileInformationClass::FileEaInformation),
            8  => Some(FileInformationClass::FileAccessInformation),
            9  => Some(FileInformationClass::FileNameInformation),
            10 => Some(FileInformationClass::FileRenameInformation),
            11 => Some(FileInformationClass::FileLinkInformation),
            12 => Some(FileInformationClass::FileNamesInformation),
            13 => Some(FileInformationClass::FileDispositionInformation),
            14 => Some(FileInformationClass::FilePositionInformation),
            15 => Some(FileInformationClass::FileFullEaInformation),
            16 => Some(FileInformationClass::FileModeInformation),
            17 => Some(FileInformationClass::FileAlignmentInformation),
            18 => Some(FileInformationClass::FileAllInformation),
            19 => Some(FileInformationClass::FileAllocationInformation),
            20 => Some(FileInformationClass::FileEndOfFileInformation),
            21 => Some(FileInformationClass::FileAlternateNameInformation),
            22 => Some(FileInformationClass::FileStreamInformation),
            23 => Some(FileInformationClass::FilePipeInformation),
            24 => Some(FileInformationClass::FilePipeLocalInformation),
            25 => Some(FileInformationClass::FilePipeRemoteInformation),
            26 => Some(FileInformationClass::FileMailslotQueryInformation),
            27 => Some(FileInformationClass::FileMailslotSetInformation),
            28 => Some(FileInformationClass::FileCompressionInformation),
            29 => Some(FileInformationClass::FileObjectIdInformation),
            30 => Some(FileInformationClass::FileCompletionInformation),
            31 => Some(FileInformationClass::FileMoveClusterInformation),
            32 => Some(FileInformationClass::FileQuotaInformation),
            33 => Some(FileInformationClass::FileReparsePointInformation),
            34 => Some(FileInformationClass::FileNetworkOpenInformation),
            35 => Some(FileInformationClass::FileAttributeTagInformation),
            36 => Some(FileInformationClass::FileTrackingInformation),
            37 => Some(FileInformationClass::FileIdBothDirectoryInformation),
            38 => Some(FileInformationClass::FileIdFullDirectoryInformation),
            39 => Some(FileInformationClass::FileValidDataLengthInformation),
            40 => Some(FileInformationClass::FileShortNameInformation),
            _  => None,
        }
    }
}

// ---------------------------------------------------------------------------
// FILE_*_DIRECTORY_INFORMATION structures used by NtQueryDirectoryFile.
//
// All three structures start with the same 0x40-byte header
// (next_entry_offset, file_index, four i64 timestamps, end_of_file,
// allocation_size, file_attributes, file_name_length, ea_size), then
// diverge. The trailing `file_name: [u16; 1]` is a Flexible Array
// Member (FAM) — callers append the actual UTF-16 name bytes after
// the fixed-size prefix.
//
// We use `#[repr(C)]` so the layout is bit-compatible with the NT
// kernel ABI. Compile-time asserts lock the documented sizes.
// ---------------------------------------------------------------------------

/// `FILE_DIRECTORY_INFORMATION` (FileInformationClass = 1).
/// 0x48-byte fixed prefix followed by the UTF-16 name.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileDirectoryInformation {
    pub next_entry_offset: u32,       // 0x00
    pub file_index: u32,              // 0x04
    pub creation_time: i64,           // 0x08
    pub last_access_time: i64,        // 0x10
    pub last_write_time: i64,         // 0x18
    pub change_time: i64,             // 0x20
    pub end_of_file: i64,             // 0x28
    pub allocation_size: i64,         // 0x30
    pub file_attributes: u32,         // 0x38
    pub file_name_length: u32,        // 0x3C
    pub ea_size: u32,                 // 0x40
    // 4 bytes of implicit padding to keep the FAM at 8-byte alignment.
    pub file_name: [u16; 1],          // 0x48 (FAM, variable length)
}
const _: () = assert!(
    core::mem::size_of::<FileDirectoryInformation>() == 0x48,
    "FILE_DIRECTORY_INFORMATION fixed prefix must be 0x48 bytes"
);

/// `FILE_BOTH_DIR_INFORMATION` (FileInformationClass = 3).
/// Adds the short (8.3) name before the long name.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileBothDirectoryInformation {
    pub next_entry_offset: u32,       // 0x00
    pub file_index: u32,              // 0x04
    pub creation_time: i64,           // 0x08
    pub last_access_time: i64,        // 0x10
    pub last_write_time: i64,         // 0x18
    pub change_time: i64,             // 0x20
    pub end_of_file: i64,             // 0x28
    pub allocation_size: i64,         // 0x30
    pub file_attributes: u32,         // 0x38
    pub file_name_length: u32,        // 0x3C
    pub ea_size: u32,                 // 0x40
    pub short_name_length: u8,        // 0x44
    pub _pad0: [u8; 1],               // 0x45
    pub short_name: [u16; 12],        // 0x46 (24 bytes)
    pub file_name: [u16; 1],          // 0x5E (FAM, variable length)
}
const _: () = assert!(
    core::mem::size_of::<FileBothDirectoryInformation>() == 0x60,
    "FILE_BOTH_DIR_INFORMATION fixed prefix must be 0x60 bytes (0x5E documented + 2-byte FAM alignment)"
);

/// `FILE_ID_BOTH_DIR_INFORMATION` (FileInformationClass = 37).
/// Adds an 8-byte file_id (typically the NTFS MFT reference) before
/// the long name. Used by callers that want a stable identity
/// independent of path.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileIdBothDirectoryInformation {
    pub next_entry_offset: u32,       // 0x00
    pub file_index: u32,              // 0x04
    pub creation_time: i64,           // 0x08
    pub last_access_time: i64,        // 0x10
    pub last_write_time: i64,         // 0x18
    pub change_time: i64,             // 0x20
    pub end_of_file: i64,             // 0x28
    pub allocation_size: i64,         // 0x30
    pub file_attributes: u32,         // 0x38
    pub file_name_length: u32,        // 0x3C
    pub ea_size: u32,                 // 0x40
    pub short_name_length: u8,        // 0x44
    pub _pad0: [u8; 1],               // 0x45
    pub short_name: [u16; 12],        // 0x46 (24 bytes)
    pub file_id: i64,                 // 0x5E
    pub file_name: [u16; 1],          // 0x66 (FAM, variable length)
}
const _: () = assert!(
    core::mem::size_of::<FileIdBothDirectoryInformation>() == 0x70,
    "FILE_ID_BOTH_DIR_INFORMATION fixed prefix must be 0x70 bytes (0x66 documented + 0xA trailing alignment)"
);

/// Process information class.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessInformationClass {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22,
    ProcessDeviceMap = 23,
    ProcessSessionInformation = 24,
    ProcessForegroundInformation = 25,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    ProcessTlsInformation = 35,
    ProcessCookie = 36,
    ProcessImageInformation = 37,
    ProcessCycleTime = 38,
    ProcessPagePriority = 39,
    ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41,
    ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43,
    ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45,
    ProcessMemoryAllocationMode = 46,
}

/// `SECTION_INHERIT` — how a view of a section is inherited.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionInherit {
    ViewShare = 1,
    ViewUnmap = 2,
}

/// Memory information class.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryInformationClass {
    MemoryBasicInformation = 0,
    MemoryWorkingSetInformation = 1,
    MemoryMappedFilenameInformation = 2,
    MemoryRegionInformation = 3,
    MemoryWorkingSetExInformation = 4,
    MemorySharedCommitInformation = 5,
    MemoryImageInformation = 6,
    MemoryRegionInformationEx = 7,
}

/// System information class.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInformationClass {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPagefileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessesInformation = 53,
}

/// `EVENT_TYPE` — `SynchronizationEvent` is auto-reset,
/// `NotificationEvent` is manual-reset.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    NotificationEvent = 0,
    SynchronizationEvent = 1,
}

/// `TIMER_TYPE` — used by `NtCreateTimer`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerType {
    NotificationTimer = 0,
    SynchronizationTimer = 1,
}

/// `WAIT_TYPE` — what `NtWaitForMultipleObjects` does.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitType {
    WaitAll = 0,
    WaitAny = 1,
}

/// Section access rights.
pub mod section_access {
    pub const SECTION_QUERY: u32 = 0x0001;
    pub const SECTION_MAP_WRITE: u32 = 0x0002;
    pub const SECTION_MAP_READ: u32 = 0x0004;
    pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
    pub const SECTION_EXTEND_SIZE: u32 = 0x0010;
    pub const SECTION_MAP_EXECUTE_EXPLICIT: u32 = 0x0020;
    pub const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
}

/// File create disposition.
pub mod file_disposition {
    pub const FILE_SUPERSEDE: u32 = 0x0000_0000;
    pub const FILE_OPEN: u32 = 0x0000_0001;
    pub const FILE_CREATE: u32 = 0x0000_0002;
    pub const FILE_OPEN_IF: u32 = 0x0000_0003;
    pub const FILE_OVERWRITE: u32 = 0x0000_0004;
    pub const FILE_OVERWRITE_IF: u32 = 0x0000_0005;
}

/// `CreateFileW` -> `NtCreateFile` desired access mapping helpers.
pub mod file_access {
    pub const FILE_READ_DATA: u32 = 0x0001;
    pub const FILE_WRITE_DATA: u32 = 0x0002;
    pub const FILE_APPEND_DATA: u32 = 0x0004;
    pub const FILE_READ_EA: u32 = 0x0008;
    pub const FILE_WRITE_EA: u32 = 0x0010;
    pub const FILE_EXECUTE: u32 = 0x0020;
    pub const FILE_DELETE_CHILD: u32 = 0x0040;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    pub const DELETE: u32 = 0x0001_0000;
    pub const READ_CONTROL: u32 = 0x0002_0000;
    pub const WRITE_DAC: u32 = 0x0004_0000;
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    pub const FILE_GENERIC_READ: u32 = STANDARD_RIGHTS_READ
        | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
    pub const FILE_GENERIC_WRITE: u32 = STANDARD_RIGHTS_WRITE
        | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE;
    pub const FILE_GENERIC_EXECUTE: u32 = STANDARD_RIGHTS_EXECUTE
        | FILE_READ_DATA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    pub const FILE_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF;
    pub const STANDARD_RIGHTS_READ: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_REQUIRED: u32 = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER;
}

/// Memory protection flags.
pub mod page {
    pub const PAGE_NOACCESS: u32 = 0x0001;
    pub const PAGE_READONLY: u32 = 0x0002;
    pub const PAGE_READWRITE: u32 = 0x0004;
    pub const PAGE_WRITECOPY: u32 = 0x0008;
    pub const PAGE_EXECUTE: u32 = 0x0010;
    pub const PAGE_EXECUTE_READ: u32 = 0x0020;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x0040;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x0080;
    pub const PAGE_GUARD: u32 = 0x0100;
    pub const PAGE_NOCACHE: u32 = 0x0200;
    pub const PAGE_WRITECOMBINE: u32 = 0x0400;
}

/// Memory allocation type.
pub mod mem {
    pub const MEM_COMMIT: u32 = 0x0000_1000;
    pub const MEM_RESERVE: u32 = 0x0000_2000;
    pub const MEM_DECOMMIT: u32 = 0x0000_4000;
    pub const MEM_RELEASE: u32 = 0x0000_8000;
    pub const MEM_FREE: u32 = 0x0001_0000;
    pub const MEM_PRIVATE: u32 = 0x0002_0000;
    pub const MEM_MAPPED: u32 = 0x0004_0000;
    pub const MEM_RESET: u32 = 0x0008_0000;
    pub const MEM_TOP_DOWN: u32 = 0x0010_0000;
    pub const MEM_LARGE_PAGES: u32 = 0x2000_0000;
    pub const MEM_4MB_PAGES: u32 = 0x8000_0000;
}

/// Object attributes flags.
pub mod obj {
    pub const OBJ_INHERIT: u32 = 0x0000_0002;
    pub const OBJ_PERMANENT: u32 = 0x0000_0010;
    pub const OBJ_EXCLUSIVE: u32 = 0x0000_0020;
    pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    pub const OBJ_OPENIF: u32 = 0x0000_0080;
    pub const OBJ_OPENLINK: u32 = 0x0000_0100;
    pub const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;
    pub const OBJ_FORCE_ACCESS_CHECK: u32 = 0x0000_0400;
}

// ---------------------------------------------------------------------------
// Additional structures for Windows 7 compatibility
// ---------------------------------------------------------------------------

/// `RTL_CRITICAL_SECTION_DEBUG` - Debug info for critical sections.
#[repr(C)]
pub struct RtlCriticalSectionDebug {
    pub debug_info: *mut RtlCriticalSectionDebug,
    pub reference_count: i32,
    pub entry_count: u32,
    pub flags: u32,
}

/// `RTL_CRITICAL_SECTION` - Critical section for thread synchronization.
/// Size must be 40 bytes on x64 (Windows 7 compatible).
#[repr(C)]
pub struct RtlCriticalSection {
    pub debug_info: *mut RtlCriticalSectionDebug,
    pub lock_count: i32,
    pub recursion_count: i32,
    pub owning_thread: HANDLE,
    pub lock_semaphore: HANDLE,
    pub spin_count: usize,
}

/// Compile-time assertion for RTL_CRITICAL_SECTION size.
/// Windows 7 x64: sizeof(RTL_CRITICAL_SECTION) == 40
const _: () = assert!(
    core::mem::size_of::<RtlCriticalSection>() == 40,
    "RTL_CRITICAL_SECTION must be 40 bytes on x64"
);

/// `PS_ATTRIBUTE_NUM` - Types of process/thread attributes.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsAttributeNum {
    PsAttributeParentProcess = 0,
    PsAttributeDebugPort = 1,
    PsAttributeToken = 2,
    PsAttributeClientId = 3,
    PsAttributeTebAddress = 4,
    PsAttributeImageName = 5,
    PsAttributeImageInfo = 6,
    PsAttributeMemoryReserve = 7,
    PsAttributePriorityClass = 8,
    PsAttributeErrorMode = 9,
    PsAttributeStdHandleInfo = 10,
    PsAttributeHandleList = 11,
    PsAttributeGroupAffinity = 12,
    PsAttributePreferredNode = 13,
    PsAttributeIdealProcessor = 14,
    PsAttributeUmsThread = 15,
    PsAttributeMitigationOptions = 16,
    PsAttributeMax = 17,
}

/// `PS_ATTRIBUTE` - Single attribute in an attribute list.
#[repr(C)]
pub struct PsAttribute {
    pub attribute: u32,
    pub size: usize,
    pub value: usize,
    pub return_length: *mut usize,
}

/// `PS_ATTRIBUTE_LIST` - Variable-length attribute list for NtCreateUserProcess.
/// This is a header only; actual attributes follow immediately after.
#[repr(C)]
pub struct PsAttributeList {
    pub total_length: usize,
}

/// `THREAD_BASIC_INFORMATION` - Thread information returned by NtQueryInformationThread.
#[repr(C)]
pub struct ThreadBasicInformation {
    pub exit_status: NTSTATUS,
    pub teb_base_address: PVOID,
    pub client_id: ClientId,
    pub affinity_mask: usize,
    pub priority: i32,
    pub base_priority: i32,
}

/// `PROCESS_BASIC_INFORMATION` - Process information returned by NtQueryInformationProcess.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessBasicInformation {
    pub exit_status: NTSTATUS,
    pub peb_base_address: PVOID,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
}
