//! Native NT 6.1 (Windows 7 SP1 x64 / Server 2008 R2) syscall numbers.
//
//! Every `Nt*` system call has a stable numeric identifier assigned
//! when the call is added to the kernel. The number is the value
//! the caller places in `rax` before executing the `syscall`
//! instruction. The kernel dispatch table reads the number out of
//! the saved `rax` and dispatches to the matching handler.
//
//! The constants in this module are the **canonical Windows 7 SP1 x64 /
//! NT 6.1 build 7601** numbers from j00ru/windows-syscalls project.
//
//! ## Data Source
//! - Primary: j00ru/windows-syscalls project (https://github.com/j00ru/windows-syscalls)
//! - CSV file: x64/csv/nt.csv
//! - Values: Windows 7 (SP1) column (11th column, index 10)

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]

// =================================================================
// Wait & Synchronization
// =================================================================

pub const NtWaitForSingleObject: u32 = 0x0001;
pub const NtWaitForMultipleObjects: u32 = 0x0058;
pub const NtDelayExecution: u32 = 0x0031;
pub const NtYieldExecution: u32 = 0x0046;
pub const NtSignalAndWaitForSingleObject: u32 = 0x0175;
pub const NtWaitForMultipleObjects32: u32 = 0x001A;

// =================================================================
// System Information & Control
// =================================================================

pub const NtQuerySystemInformation: u32 = 0x0033;
pub const NtSetSystemInformation: u32 = 0x016C;
pub const NtQuerySystemTime: u32 = 0x0057;
pub const NtSetSystemTime: u32 = 0x016E;
pub const NtQueryInterruptTime: u32 = 0x0058;
pub const NtSetInterruptTime: u32 = 0x0059;
pub const NtQueryTickCount: u32 = 0x00A8;
pub const NtGetCurrentProcessorNumber: u32 = 0x00CB;
pub const NtShutdownSystem: u32 = 0x0174;
pub const NtTestAlert: u32 = 0x017E;
pub const NtCallbackReturn: u32 = 0x0005;
pub const NtDisplayString: u32 = 0x00B8;
pub const NtQueryPerformanceCounter: u32 = 0x0123;
pub const NtSetSystemPowerState: u32 = 0x0097;
pub const NtShutdownWorkerFactory: u32 = 0x009A;

// =================================================================
// Object Management
// =================================================================

pub const NtClose: u32 = 0x000C;
pub const NtQueryObject: u32 = 0x0010;
pub const NtSetInformationObject: u32 = 0x005C;
pub const NtDuplicateObject: u32 = 0x003C;
pub const NtMakePermanentObject: u32 = 0x005C;
pub const NtMakeTemporaryObject: u32 = 0x005D;

// =================================================================
// Process Management
// =================================================================

pub const NtOpenProcess: u32 = 0x0023;
pub const NtQueryInformationProcess: u32 = 0x0016;
pub const NtSetInformationProcess: u32 = 0x0019;
pub const NtCreateProcess: u32 = 0x009F;
pub const NtCreateProcessEx: u32 = 0x004A;
pub const NtTerminateProcess: u32 = 0x0029;
pub const NtOpenProcessToken: u32 = 0x00F9;
pub const NtOpenProcessTokenEx: u32 = 0x002D;
pub const NtSuspendProcess: u32 = 0x0178;
pub const NtResumeProcess: u32 = 0x0141;

// =================================================================
// Thread Management
// =================================================================

pub const NtOpenThread: u32 = 0x00FE;
pub const NtQueryInformationThread: u32 = 0x0025;
pub const NtSetInformationThread: u32 = 0x000D;
pub const NtCreateThread: u32 = 0x004B;
pub const NtCreateThreadEx: u32 = 0x00A5;
pub const NtTerminateThread: u32 = 0x0050;
pub const NtSuspendThread: u32 = 0x017B;
pub const NtResumeThread: u32 = 0x004F;
pub const NtGetContextThread: u32 = 0x00CA;
pub const NtSetContextThread: u32 = 0x0150;
pub const NtOpenThreadToken: u32 = 0x0024;
pub const NtOpenThreadTokenEx: u32 = 0x002F;
pub const NtImpersonateThread: u32 = 0x00D5;
pub const NtRevertToSelf: u32 = 0x00D6;
pub const NtRegisterThreadTerminatePort: u32 = 0x0136;
pub const NtAlertThread: u32 = 0x000A;
pub const NtAlertResumeThread: u32 = 0x0009;

// =================================================================
// Memory Management
// =================================================================

pub const NtAllocateVirtualMemory: u32 = 0x0015;
pub const NtFreeVirtualMemory: u32 = 0x001B;
pub const NtReadVirtualMemory: u32 = 0x003E;
pub const NtWriteVirtualMemory: u32 = 0x0039;
pub const NtQueryVirtualMemory: u32 = 0x0020;
pub const NtProtectVirtualMemory: u32 = 0x004D;
pub const NtMapViewOfSection: u32 = 0x0025;
pub const NtUnmapViewOfSection: u32 = 0x0027;
pub const NtMapUserPhysicalPages: u32 = 0x00E7;
pub const NtAllocateUserPhysicalPages: u32 = 0x0004;
pub const NtFreeUserPhysicalPages: u32 = 0x00A0;
pub const NtLockVirtualMemory: u32 = 0x005B;
pub const NtUnlockVirtualMemory: u32 = 0x00A7;
pub const NtFlushVirtualMemory: u32 = 0x0055;

// =================================================================
// File I/O
// =================================================================

pub const NtCreateFile: u32 = 0x0052;
pub const NtOpenFile: u32 = 0x0033;
pub const NtReadFile: u32 = 0x0006;
pub const NtWriteFile: u32 = 0x0008;
pub const NtQueryInformationFile: u32 = 0x000F;
pub const NtSetInformationFile: u32 = 0x0025;
pub const NtDeleteFile: u32 = 0x00B2;
pub const NtFlushBuffersFile: u32 = 0x004B;
pub const NtFlushBuffersFileEx: u32 = 0x00D2;
pub const NtQueryVolumeInformationFile: u32 = 0x0049;
pub const NtSetVolumeInformationFile: u32 = 0x0173;
pub const NtQueryDirectoryFile: u32 = 0x0035;
pub const NtQueryAttributesFile: u32 = 0x003D;
pub const NtQueryFullAttributesFile: u32 = 0x0113;
pub const NtLockFile: u32 = 0x00E0;
pub const NtUnlockFile: u32 = 0x0188;
pub const NtNotifyChangeDirectoryFile: u32 = 0x00EA;
pub const NtCancelIoFile: u32 = 0x005D;
pub const NtCancelIoFileEx: u32 = 0x0086;
pub const NtReadFileScatter: u32 = 0x002E;
pub const NtWriteFileGather: u32 = 0x001B;
pub const NtQueryEaFile: u32 = 0x00CA;
pub const NtSetEaFile: u32 = 0x00D0;

// =================================================================
// Section / Shared Memory
// =================================================================

pub const NtCreateSection: u32 = 0x0047;
pub const NtOpenSection: u32 = 0x0037;
pub const NtExtendSection: u32 = 0x004A;
pub const NtCreateNamedPipeFile: u32 = 0x009B;
pub const NtCreateMailslotFile: u32 = 0x0099;
pub const NtCreateProfile: u32 = 0x001F;

// =================================================================
// Synchronization Objects
// =================================================================

pub const NtCreateEvent: u32 = 0x0048;
pub const NtOpenEvent: u32 = 0x0040;
pub const NtSetEvent: u32 = 0x000E;
pub const NtResetEvent: u32 = 0x0141;
pub const NtClearEvent: u32 = 0x003E;
pub const NtPulseEvent: u32 = 0x010C;
pub const NtQueryEvent: u32 = 0x0056;
pub const NtCreateMutant: u32 = 0x009A;
pub const NtOpenMutant: u32 = 0x00F6;
pub const NtReleaseMutant: u32 = 0x0020;
pub const NtQueryMutant: u32 = 0x007E;
pub const NtCreateSemaphore: u32 = 0x00B1;
pub const NtOpenSemaphore: u32 = 0x00FB;
pub const NtReleaseSemaphore: u32 = 0x000A;
pub const NtQuerySemaphore: u32 = 0x0080;
pub const NtCreateTimer: u32 = 0x00B4;
pub const NtOpenTimer: u32 = 0x00FF;
pub const NtSetTimer: u32 = 0x0062;
pub const NtCancelTimer: u32 = 0x0061;
pub const NtQueryTimer: u32 = 0x0038;
pub const NtQueryTimerResolution: u32 = 0x012A;
pub const NtSetTimerResolution: u32 = 0x0171;
pub const NtCreateKeyedEvent: u32 = 0x0098;
pub const NtOpenKeyedEvent: u32 = 0x00F5;
pub const NtReleaseKeyedEvent: u32 = 0x00D7;
pub const NtWaitForKeyedEvent: u32 = 0x018C;
pub const NtCreateEventPair: u32 = 0x0093;
pub const NtOpenEventPair: u32 = 0x00EF;
pub const NtSetEventBoostPriority: u32 = 0x002A;

// =================================================================
// Registry
// =================================================================

pub const NtCreateKey: u32 = 0x001D;
pub const NtOpenKey: u32 = 0x0012;
pub const NtDeleteKey: u32 = 0x00B3;
pub const NtDeleteValueKey: u32 = 0x00B6;
pub const NtQueryKey: u32 = 0x0016;
pub const NtSetValueKey: u32 = 0x005E;
pub const NtQueryValueKey: u32 = 0x0017;
pub const NtEnumerateKey: u32 = 0x0032;
pub const NtEnumerateValueKey: u32 = 0x0013;
pub const NtFlushKey: u32 = 0x00C3;
pub const NtLoadKey: u32 = 0x00DD;
pub const NtLoadKey2: u32 = 0x00DE;
pub const NtUnloadKey: u32 = 0x00A4;
pub const NtSaveKey: u32 = 0x0149;
pub const NtSaveKeyEx: u32 = 0x014A;
pub const NtNotifyChangeKey: u32 = 0x00EB;
pub const NtQueryOpenSubKeys: u32 = 0x0122;
pub const NtCompactKeys: u32 = 0x00F0;
pub const NtCompressKey: u32 = 0x00F1;
pub const NtCreateKeyTransacted: u32 = 0x0097;
pub const NtOpenKeyTransacted: u32 = 0x00F3;
pub const NtOpenKeyTransactedEx: u32 = 0x00F4;
pub const NtDeleteKeyTransacted: u32 = 0x00F3;
pub const NtSetValueKeyTransacted: u32 = 0x0160;
pub const NtSetInformationKey: u32 = 0x0155;
pub const NtRenameKey: u32 = 0x0139;
pub const NtQueryMultipleValueKey: u32 = 0x007D;

// =================================================================
// Directory & Symbolic Link
// =================================================================

pub const NtCreateDirectoryObject: u32 = 0x0091;
pub const NtOpenDirectoryObject: u32 = 0x0055;
pub const NtQueryDirectoryObject: u32 = 0x0110;
pub const NtCreateSymbolicLinkObject: u32 = 0x00A4;
pub const NtOpenSymbolicLinkObject: u32 = 0x00FD;
pub const NtQuerySymbolicLinkObject: u32 = 0x0129;

// =================================================================
// Security
// =================================================================

pub const NtAccessCheck: u32 = 0x0000;
pub const NtAccessCheckAndAuditAlarm: u32 = 0x0026;
pub const NtSetSecurityObject: u32 = 0x0169;
pub const NtQuerySecurityObject: u32 = 0x0127;
pub const NtPrivilegeCheck: u32 = 0x0107;
pub const NtImpersonateAnonymousToken: u32 = 0x00D4;

// =================================================================
// Token Management
// =================================================================

pub const NtCreateToken: u32 = 0x00B6;
pub const NtOpenObjectAuditAlarm: u32 = 0x00F7;
pub const NtFilterToken: u32 = 0x00D5;
pub const NtAdjustPrivilegesToken: u32 = 0x003B;
pub const NtAdjustGroupsToken: u32 = 0x003A;
pub const NtDuplicateToken: u32 = 0x003D;
pub const NtQueryInformationToken: u32 = 0x0118;
pub const NtSetInformationToken: u32 = 0x0156;

// =================================================================
// ALPC
// =================================================================

pub const NtCreatePort: u32 = 0x00A7;
pub const NtConnectPort: u32 = 0x008F;
pub const NtListenPort: u32 = 0x00DB;
pub const NtAcceptConnectPort: u32 = 0x0060;
pub const NtSendWaitReceivePort: u32 = 0x00AF;
pub const NtImpersonateClientOfPort: u32 = 0x001D;
pub const NtReplyWaitReceivePort: u32 = 0x0009;
pub const NtReplyPort: u32 = 0x000A;
pub const NtReplyWaitReceivePortEx: u32 = 0x002B;
pub const NtCreatePortSection: u32 = 0x00BD;
pub const NtSecureConnectPort: u32 = 0x014C;
pub const NtQueryInformationPort: u32 = 0x0117;
pub const NtRequestPort: u32 = 0x0140;
pub const NtRequestWaitReplyPort: u32 = 0x0020;
pub const NtCompleteConnectPort: u32 = 0x001A;
pub const NtReplyWaitReplyPort: u32 = 0x002C;

// =================================================================
// Job Objects
// =================================================================

pub const NtCreateJobSet: u32 = 0x0096;
pub const NtCreateJobObject: u32 = 0x0095;
pub const NtOpenJobObject: u32 = 0x00F2;
pub const NtAssignProcessToJobObject: u32 = 0x0085;
pub const NtTerminateJobObject: u32 = 0x017D;
pub const NtQueryJobInformation: u32 = 0x0178;
pub const NtSetJobInformation: u32 = 0x0179;
pub const NtQueryInformationJobObject: u32 = 0x0115;
pub const NtSetInformationJobObject: u32 = 0x0179;
pub const NtIsProcessInJob: u32 = 0x004C;

// =================================================================
// Locale & Culture
// =================================================================

pub const NtQueryDefaultLocale: u32 = 0x0015;
pub const NtSetDefaultLocale: u32 = 0x0153;
pub const NtQueryDefaultUILanguage: u32 = 0x0041;
pub const NtSetDefaultUILanguage: u32 = 0x0189;
pub const NtQueryDefaultHardErrorMode: u32 = 0x0108;
pub const NtSetDefaultHardErrorMode: u32 = 0x0187;
pub const NtReadOnlyLogonSessionTree: u32 = 0x0180;
pub const NtVerifySession: u32 = 0x0181;

// =================================================================
// Paging & Memory Management
// =================================================================

pub const NtCreatePagingFile: u32 = 0x009C;
pub const NtInitializeRegistry: u32 = 0x00D7;
pub const NtCreateProcessState: u32 = 0x0166;
pub const NtCreateProcessStateChange: u32 = 0x00BD;

// =================================================================
// User Processes
// =================================================================

pub const NtCreateUserProcess: u32 = 0x00AA;

// =================================================================
// Exception Handling
// =================================================================

pub const NtRaiseException: u32 = 0x012F;
pub const NtRaiseHardError: u32 = 0x0130;
pub const NtContinue: u32 = 0x001B;

// =================================================================
// LDT
// =================================================================

pub const NtSetLdtEntries: u32 = 0x0165;
pub const NtSetLdtSize: u32 = 0x0168;

// =================================================================
// DLL & Process Loading
// =================================================================

pub const NtQueryLicenseValue: u32 = 0x011F;
pub const NtAllocateLocallyUniqueId: u32 = 0x000B;
pub const NtAllocateUuids: u32 = 0x0184;

// =================================================================
// Transaction Manager
// =================================================================

pub const NtCreateTransaction: u32 = 0x00A8;
pub const NtOpenTransaction: u32 = 0x0100;
pub const NtCommitTransaction: u32 = 0x008A;
pub const NtRollbackTransaction: u32 = 0x0147;
pub const NtEnumerateTransaction: u32 = 0x0148;
pub const NtSetInformationTransaction: u32 = 0x015F;
pub const NtQueryInformationTransaction: u32 = 0x0119;
pub const NtCreateTransactionManager: u32 = 0x00A9;
pub const NtOpenTransactionManager: u32 = 0x0100;
pub const NtCommitComplete: u32 = 0x0086;
pub const NtRollbackComplete: u32 = 0x0087;
pub const NtEnumerateTransactionObject: u32 = 0x00BE;

// =================================================================
// System Service Table Information
// =================================================================

pub const NtSetSystemInformationEx: u32 = 0x012C;
pub const NtQuerySystemInformationEx: u32 = 0x012C;
pub const NtTrimProcessWorkingSet: u32 = 0x0157;

// =================================================================
// Worker Factory
// =================================================================

pub const NtWaitForWorkViaWorkerFactory: u32 = 0x018D;
pub const NtSetInformationWorkerFactory: u32 = 0x0159;
pub const NtQueryInformationWorkerFactory: u32 = 0x011B;
pub const NtReleaseWorkerFactoryWorker: u32 = 0x0138;

// =================================================================
// Private Namespaces
// =================================================================

pub const NtCreatePrivateNamespace: u32 = 0x009E;
pub const NtOpenPrivateNamespace: u32 = 0x00F8;
pub const NtDeletePrivateNamespace: u32 = 0x00B5;

// =================================================================
// Debug
// =================================================================

pub const NtCreateDebugObject: u32 = 0x001C;
pub const NtDebugActiveProcess: u32 = 0x0020;
pub const NtRemoveProcessDebug: u32 = 0x00DD;
pub const NtWaitForDebugEvent: u32 = 0x018B;
pub const NtDebugContinue: u32 = 0x003C;
pub const NtSetInformationDebugObject: u32 = 0x0092;
pub const NtQueryInformationDebugObject: u32 = 0x0125;
pub const NtDebugPrint: u32 = 0x003D;

// =================================================================
// System Environment
// =================================================================

pub const NtQuerySystemEnvironment: u32 = 0x0081;
pub const NtSetSystemEnvironmentValue: u32 = 0x0096;
pub const NtSetSystemEnvironmentValueEx: u32 = 0x016A;
pub const NtEnumerateBootEntries: u32 = 0x0043;
pub const NtEnumerateDriverEntries: u32 = 0x0048;
pub const NtEnumerateDriverPackage: u32 = 0x01A9;
pub const NtAddBootEntry: u32 = 0x0066;
pub const NtDeleteBootEntry: u32 = 0x003E;
pub const NtModifyBootEntry: u32 = 0x005F;
pub const NtSetBootEntryOrder: u32 = 0x008C;
pub const NtSetBootOptions: u32 = 0x008D;
pub const NtQueryBootEntryOrder: u32 = 0x0076;
pub const NtQueryBootOptions: u32 = 0x0077;
pub const NtAddDriverEntry: u32 = 0x0068;
pub const NtDeleteDriverEntry: u32 = 0x003F;
pub const NtModifyDriverEntry: u32 = 0x0070;
pub const NtSetDriverEntryOrder: u32 = 0x008F;
pub const NtQueryDriverEntryOrder: u32 = 0x0079;

// =================================================================
// Plug and Play / Power
// =================================================================

pub const NtPlugPlayControl: u32 = 0x00AD;
pub const NtGetPlugPlayEvent: u32 = 0x00A5;
pub const NtPowerInformation: u32 = 0x00AE;
pub const NtInitiatePowerAction: u32 = 0x00A8;
pub const NtSetThreadExecutionState: u32 = 0x0098;
pub const NtGetDevicePowerState: u32 = 0x00A1;
pub const NtIsSystemResumeAutomatic: u32 = 0x00A9;
pub const NtRequestWakeupLatency: u32 = 0x0084;
pub const NtSetIntervalProfile: u32 = 0x0093;
pub const NtQueryIntervalProfile: u32 = 0x007C;

// =================================================================
// IO Completion
// =================================================================

pub const NtCreateIoCompletion: u32 = 0x0050;
pub const NtOpenIoCompletion: u32 = 0x0101;
pub const NtSetIoCompletion: u32 = 0x015A;
pub const NtSetIoCompletionEx: u32 = 0x015B;
pub const NtQueryIoCompletion: u32 = 0x011C;
pub const NtRemoveIoCompletion: u32 = 0x00DB;
pub const NtRemoveIoCompletionEx: u32 = 0x00DC;
pub const NtWaitForAlertByThreadId: u32 = 0x01A6;

// =================================================================
// Atom Table
// =================================================================

pub const NtAddAtom: u32 = 0x0044;
pub const NtDeleteAtom: u32 = 0x00AF;
pub const NtQueryInformationAtom: u32 = 0x0114;
pub const NtFindAtom: u32 = 0x0051;

// =================================================================
// Environment / NLS
// =================================================================

pub const NtInitializeNlsFiles: u32 = 0x00A7;
pub const NtGetNlsSectionPtr: u32 = 0x00A3;
pub const NtQueryInstallUILanguage: u32 = 0x007B;
pub const NtIsUILanguageCommitted: u32 = 0x00AA;
pub const NtFlushInstallUILanguage: u32 = 0x0053;
pub const NtSetUuidSeed: u32 = 0x0099;

// =================================================================
// Resource Manager
// =================================================================

pub const NtGetNotificationResourceManager: u32 = 0x00A4;
pub const NtQueryInformationTransactionManager: u32 = 0x0119;
pub const NtSetInformationTransactionManager: u32 = 0x015F;

// =================================================================
// Other Important Syscalls
// =================================================================

pub const NtDeviceIoControlFile: u32 = 0x0042;
pub const NtFsControlFile: u32 = 0x0057;
pub const NtLoadDriver: u32 = 0x00AB;
pub const NtUnloadDriver: u32 = 0x00A3;
pub const NtQuerySection: u32 = 0x0125;
pub const NtWaitHighEventPair: u32 = 0x00A9;
pub const NtWaitLowEventPair: u32 = 0x00AA;
pub const NtSetHighEventPair: u32 = 0x0090;
pub const NtSetLowEventPair: u32 = 0x0094;
pub const NtSetHighWaitLowEventPair: u32 = 0x0091;
pub const NtSetLowWaitHighEventPair: u32 = 0x0095;
pub const NtTranslateFilePath: u32 = 0x00A0;
pub const NtStartService: u32 = 0x00EC;

// =================================================================
// APC
// =================================================================

pub const NtQueueApcThread: u32 = 0x00D0;
pub const NtReadRequestData: u32 = 0x0131;
pub const NtWriteRequestData: u32 = 0x018F;

// =================================================================
// Profile
// =================================================================

pub const NtStartProfile: u32 = 0x009C;
pub const NtStopProfile: u32 = 0x009D;
pub const NtQueryDebugFilterState: u32 = 0x0078;
pub const NtSetDebugFilterState: u32 = 0x008E;

// =================================================================
// System Debug Control
// =================================================================

pub const NtSystemDebugControl: u32 = 0x009F;

// =================================================================
// Enumerate System Environment Values
// =================================================================

pub const NtEnumerateSystemEnvironmentValuesEx: u32 = 0x0049;

// =================================================================
// Notify Change Session
// =================================================================

pub const NtNotifyChangeSession: u32 = 0x008C;

// =================================================================
// Flush Process Write Buffers
// =================================================================

pub const NtFlushProcessWriteBuffers: u32 = 0x006D;

// =================================================================
// Serialize Boot
// =================================================================

pub const NtSerializeBoot: u32 = 0x008B;

// =================================================================
// Maximum syscall number in native NT table
// =================================================================

pub const MAX_NT_SYSCALL: u32 = 0x01A9;

// =================================================================
// NT6.1.7601-kernel private syscalls (cmd.exe host)
// =================================================================
//
// These IDs are reserved for the kernel's own user-mode
// command host (`C:\Windows\System32\cmd.exe`). They live in the
// 0x0200..=0x02FF range, which is above the NT syscall table
// (max 0x01A9) so they cannot collide with any NT service.
//
// See `arch::x86_64::syscall::dispatch` for the kernel-side
// implementation and `system_image::build_cmd_exe` for the
// user-mode stub.

/// Tell the kernel to run `C:\tests\autoexec.bat` and return.
/// The kernel reads the file via FAT32, parses every line with
/// `libs::cmd::bat_parser`, and lets the batch processor emit
/// its output through the same console the cmd.exe stub is
/// attached to. The stub is parked inside the syscall until the
/// batch is finished, then the syscall returns.
pub const SYS_RUN_AUTOEXEC: u32 = 0x0200;

/// Terminate the current user-mode process. `arg0` is the exit
/// code (passed in `rdi` per the NT x64 calling convention).
pub const SYS_EXIT_PROCESS: u32 = 0x0201;

/// Print a single byte to the kernel debug console / serial
/// port. `arg0` (in `al` / `rdi`'s low byte) is the ASCII code
/// to emit. This exists so the Ring-3 `cmd.exe` stub and any
/// future user-mode diagnostic can produce log output without
/// touching the privileged I/O port space. The Ring-3 IOPL is
/// always 0 in this kernel, so `out dx, al` raises #GP; the
/// syscall avoids that entirely. Returns 0 on success.
pub const SYS_PUTCHAR: u32 = 0x0202;
