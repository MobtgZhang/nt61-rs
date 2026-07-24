//! System-call number definitions (Windows 7 x64 kernel).
//!
//! Only the most commonly used calls are listed here — Phase 2
//! extends the list as subsystems grow. The numbers match
//! `ntoskrnl.exe` of Windows 7 (build 7601).

#![allow(dead_code, non_snake_case)]

// Process / thread
pub const NtCreateProcess: u32                  = 0x002A;
pub const NtCreateThread: u32                   = 0x004F;
pub const NtCreateUserProcess: u32              = 0x00CA;
pub const NtTerminateProcess: u32               = 0x0029;
pub const NtTerminateThread: u32                = 0x0050;
pub const NtOpenProcess: u32                    = 0x0023;
pub const NtOpenThread: u32                     = 0x004E;
pub const NtQueryInformationProcess: u32        = 0x0019;
pub const NtSetInformationProcess: u32          = 0x001A;
pub const NtQueryInformationThread: u32         = 0x0024;
pub const NtSetInformationThread: u32           = 0x0015;
pub const NtSuspendThread: u32                  = 0x002D;
pub const NtResumeThread: u32                   = 0x004D;

// Virtual memory
pub const NtAllocateVirtualMemory: u32          = 0x0015;
pub const NtFreeVirtualMemory: u32              = 0x001B;
pub const NtReadVirtualMemory: u32              = 0x003A;
pub const NtWriteVirtualMemory: u32             = 0x0037;
pub const NtProtectVirtualMemory: u32           = 0x004E;
pub const NtQueryVirtualMemory: u32             = 0x0023;

// File I/O
pub const NtCreateFile: u32                     = 0x0027;
pub const NtOpenFile: u32                       = 0x0030;
pub const NtReadFile: u32                       = 0x0003;
pub const NtWriteFile: u32                      = 0x0004;
pub const NtClose: u32                          = 0x000C;
pub const NtQueryInformationFile: u32           = 0x000D;
pub const NtSetInformationFile: u32             = 0x0021;
pub const NtQueryDirectoryFile: u32            = 0x000E;
pub const NtDeleteFile: u32                     = 0x002F;
pub const NtRenameFile: u32                     = 0x0013;

// Synchronisation
pub const NtCreateEvent: u32                    = 0x0046;
pub const NtOpenEvent: u32                      = 0x004B;
pub const NtWaitForSingleObject: u32            = 0x0008;
pub const NtWaitForMultipleObjects: u32         = 0x0009;
pub const NtSetEvent: u32                       = 0x000E;
pub const NtResetEvent: u32                     = 0x0076;
pub const NtCreateMutant: u32                   = 0x001B + 0x10;
pub const NtCreateSemaphore: u32                = 0x0021 + 0x25;
pub const NtCreateTimer: u32                    = 0x004A;
pub const NtDelayExecution: u32                 = 0x002C;
pub const NtYieldExecution: u32                 = 0x0046 + 0x01;

// Keyed events / fast locks
pub const NtCreateKeyedEvent: u32               = 0x0091;

// Section / map
pub const NtCreateSection: u32                  = 0x0047;
pub const NtOpenSection: u32                    = 0x006D;
pub const NtMapViewOfSection: u32               = 0x0028;
pub const NtUnmapViewOfSection: u32             = 0x002A;

// Registry
pub const NtCreateKey: u32                      = 0x0031;
pub const NtOpenKey: u32                        = 0x002C;
pub const NtQueryValueKey: u32                  = 0x0014;
pub const NtSetValueKey: u32                    = 0x0025;
pub const NtEnumerateValueKey: u32              = 0x001B + 0x07;
pub const NtEnumerateKey: u32                   = 0x002F + 0x05;
pub const NtDeleteKey: u32                      = 0x0027 + 0x04;
pub const NtCloseKey: u32                       = 0x000C;

// Process / thread time
pub const NtQuerySystemTime: u32                = 0x005A;
pub const NtQueryPerformanceCounter: u32        = 0x0064;
pub const NtSetSystemTime: u32                  = 0x00CE;

// Information
pub const NtQuerySystemInformation: u32         = 0x003E;

// Misc
pub const NtTestAlert: u32                      = 0x0045;
pub const NtContinue: u32                       = 0x0002;
pub const NtRaiseHardError: u32                 = 0x0069;
pub const NtAlertThread: u32                    = 0x0007;
pub const NtAlertResumeThread: u32              = 0x0006;

// Exit / shutdown
pub const NtShutdownSystem: u32                 = 0x0003A;
