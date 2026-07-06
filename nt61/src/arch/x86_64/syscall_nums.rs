//! x86_64 NT Native Syscall Numbers — Windows 7 SP1 (NT 6.1.7601) x64
//
//! This file contains the syscall numbers for native NT system services.
//! These are the system calls dispatched through the main SSDT (KiServiceTable).
//
//! ## Data Source
//! All syscall numbers are sourced from j00ru/windows-syscalls project:
//!   - Repository: https://github.com/j00ru/windows-syscalls
//!   - CSV file: x64/csv/nt.csv
//!   - Values: Windows 7 (SP1) column
//
//! Win32k (Shadow SSDT) syscall numbers are defined separately in:
//!   - `src/ke/shadow_ssdt.rs` (win32k syscall numbers in range 0x1000-0x1FFF)
//
//! ## Syscall Number Ranges
//!   - 0x0000-0x00FF: Native NT syscall numbers
//!   - 0x1000-0x1FFF: Win32k (Shadow SSDT) syscall numbers

// =============================================================================
// Wait & Synchronization
// =============================================================================

/// NtWaitForSingleObject - Wait on a single object
pub const NtWaitForSingleObject: u16 = 0x0001;

/// NtWaitForMultipleObjects - Wait on multiple objects
pub const NtWaitForMultipleObjects: u16 = 0x0058;

/// NtDelayExecution - Delay execution
pub const NtDelayExecution: u16 = 0x0031;

/// NtYieldExecution - Yield execution to another thread
pub const NtYieldExecution: u16 = 0x0046;

// =============================================================================
// System Information & Control
// =============================================================================

/// NtQuerySystemInformation - Retrieve system information
pub const NtQuerySystemInformation: u16 = 0x0033;

/// NtSetSystemInformation - Set system information
pub const NtSetSystemInformation: u16 = 0x016C;

/// NtQuerySystemTime - Query the system time
pub const NtQuerySystemTime: u16 = 0x0057;

/// NtSetSystemTime - Set the system time
pub const NtSetSystemTime: u16 = 0x016E;

/// NtQueryInterruptTime - Query interrupt time
pub const NtQueryInterruptTime: u16 = 0x0058;

/// NtSetInterruptTime - Set interrupt time
pub const NtSetInterruptTime: u16 = 0x0059;

/// NtQueryTickCount - Query tick count
pub const NtQueryTickCount: u16 = 0x00A8;

/// NtGetCurrentProcessorNumber - Get current processor number
pub const NtGetCurrentProcessorNumber: u16 = 0x00CB;

/// NtShutdownSystem - Shutdown the system
pub const NtShutdownSystem: u16 = 0x0174;

/// NtTestAlert - Test for alert
pub const NtTestAlert: u16 = 0x017E;

/// NtCallbackReturn - Return from callback
pub const NtCallbackReturn: u16 = 0x0005;

/// NtDisplayString - Display a string
pub const NtDisplayString: u16 = 0x00B8;

// =============================================================================
// Object Management
// =============================================================================

/// NtClose - Close a handle
pub const NtClose: u16 = 0x000C;

/// NtQueryObject - Query information about an object
pub const NtQueryObject: u16 = 0x0010;

/// NtSetInformationObject - Set information about an object
pub const NtSetInformationObject: u16 = 0x005C;

/// NtDuplicateObject - Duplicate an object handle
pub const NtDuplicateObject: u16 = 0x003C;

// =============================================================================
// Process Management
// =============================================================================

/// NtOpenProcess - Open a process handle
pub const NtOpenProcess: u16 = 0x0023;

/// NtQueryInformationProcess - Query process information
pub const NtQueryInformationProcess: u16 = 0x0016;

/// NtSetInformationProcess - Set process information
pub const NtSetInformationProcess: u16 = 0x0019;

/// NtCreateProcess - Create a process
pub const NtCreateProcess: u16 = 0x009F;

/// NtCreateProcessEx - Create a process with extended options
pub const NtCreateProcessEx: u16 = 0x004A;

/// NtTerminateProcess - Terminate a process
pub const NtTerminateProcess: u16 = 0x0029;

/// NtOpenProcessToken - Open a process's token
pub const NtOpenProcessToken: u16 = 0x00F9;

/// NtOpenProcessTokenEx - Open a process's token with options
pub const NtOpenProcessTokenEx: u16 = 0x002D;

/// NtSuspendProcess - Suspend a process
pub const NtSuspendProcess: u16 = 0x0178;

/// NtResumeProcess - Resume a suspended process
pub const NtResumeProcess: u16 = 0x0141;

/// NtQueryInformationProcess_ProcessBasicInformation - Basic process info
pub const NtQueryInformationProcess_ProcessBasicInformation: u16 = 0x0016;

/// NtQueryInformationProcess_ProcessDebugPort - Debug port info
pub const NtQueryInformationProcess_ProcessDebugPort: u16 = 0x0016;

/// NtQueryInformationProcess_ProcessDebugObjectHandle - Debug object handle
pub const NtQueryInformationProcess_ProcessDebugObjectHandle: u16 = 0x0016;

/// NtQueryInformationProcess_ProcessDebugFlags - Debug flags
pub const NtQueryInformationProcess_ProcessDebugFlags: u16 = 0x0016;

// =============================================================================
// Thread Management
// =============================================================================

/// NtOpenThread - Open a thread handle
pub const NtOpenThread: u16 = 0x00FE;

/// NtQueryInformationThread - Query thread information
pub const NtQueryInformationThread: u16 = 0x0025;

/// NtSetInformationThread - Set thread information
pub const NtSetInformationThread: u16 = 0x000D;

/// NtCreateThread - Create a thread
pub const NtCreateThread: u16 = 0x004B;

/// NtTerminateThread - Terminate a thread
pub const NtTerminateThread: u16 = 0x0050;

/// NtSuspendThread - Suspend a thread
pub const NtSuspendThread: u16 = 0x017B;

/// NtResumeThread - Resume a suspended thread
pub const NtResumeThread: u16 = 0x004F;

/// NtGetContextThread - Get thread context
pub const NtGetContextThread: u16 = 0x00CA;

/// NtSetContextThread - Set thread context
pub const NtSetContextThread: u16 = 0x0150;

/// NtOpenThreadToken - Open a thread's token
pub const NtOpenThreadToken: u16 = 0x0024;

/// NtOpenThreadTokenEx - Open a thread's token with options
pub const NtOpenThreadTokenEx: u16 = 0x002F;

/// NtImpersonateThread - Impersonate another thread
pub const NtImpersonateThread: u16 = 0x00D5;

/// NtRevertToSelf - Revert to self
pub const NtRevertToSelf: u16 = 0x00D6;

/// NtRegisterThreadTerminatePort - Register thread terminate port
pub const NtRegisterThreadTerminatePort: u16 = 0x0136;

// =============================================================================
// Memory Management
// =============================================================================

/// NtAllocateVirtualMemory - Allocate virtual memory
pub const NtAllocateVirtualMemory: u16 = 0x0015;

/// NtFreeVirtualMemory - Free virtual memory
pub const NtFreeVirtualMemory: u16 = 0x001B;

/// NtReadVirtualMemory - Read virtual memory
pub const NtReadVirtualMemory: u16 = 0x003E;

/// NtWriteVirtualMemory - Write virtual memory
pub const NtWriteVirtualMemory: u16 = 0x0039;

/// NtQueryVirtualMemory - Query virtual memory information
pub const NtQueryVirtualMemory: u16 = 0x0020;

/// NtProtectVirtualMemory - Change memory protection
pub const NtProtectVirtualMemory: u16 = 0x004D;

/// NtMapViewOfSection - Map a view of a section
pub const NtMapViewOfSection: u16 = 0x0025;

/// NtUnmapViewOfSection - Unmap a view of a section
pub const NtUnmapViewOfSection: u16 = 0x0027;

/// NtUnmapViewOfSectionEx - Unmap a view of a section (extended)
pub const NtUnmapViewOfSectionEx: u16 = 0x0027;

/// NtMapUserPhysicalPages - Map user physical pages
pub const NtMapUserPhysicalPages: u16 = 0x00E7;

/// NtUnmapUserPhysicalPages - Unmap user physical pages
pub const NtUnmapUserPhysicalPages: u16 = 0x00E8;

// =============================================================================
// File I/O
// =============================================================================

/// NtCreateFile - Create or open a file
pub const NtCreateFile: u16 = 0x0052;

/// NtOpenFile - Open a file
pub const NtOpenFile: u16 = 0x0033;

/// NtReadFile - Read from a file
pub const NtReadFile: u16 = 0x0006;

/// NtWriteFile - Write to a file
pub const NtWriteFile: u16 = 0x0008;

/// NtQueryInformationFile - Query file information
pub const NtQueryInformationFile: u16 = 0x000F;

/// NtSetInformationFile - Set file information
pub const NtSetInformationFile: u16 = 0x0025;

/// NtDeleteFile - Delete a file
pub const NtDeleteFile: u16 = 0x00B2;

/// NtFlushBuffersFile - Flush file buffers
pub const NtFlushBuffersFile: u16 = 0x004B;

/// NtQueryVolumeInformationFile - Query volume information
pub const NtQueryVolumeInformationFile: u16 = 0x0049;

/// NtSetVolumeInformationFile - Set volume information
pub const NtSetVolumeInformationFile: u16 = 0x0173;

/// NtQueryDirectoryFile - Query directory information
pub const NtQueryDirectoryFile: u16 = 0x0035;

/// NtQueryAttributesFile - Query file attributes
pub const NtQueryAttributesFile: u16 = 0x003D;

/// NtQueryFullAttributesFile - Query full file attributes
pub const NtQueryFullAttributesFile: u16 = 0x0113;

/// NtLockFile - Lock a file
pub const NtLockFile: u16 = 0x00E0;

/// NtUnlockFile - Unlock a file
pub const NtUnlockFile: u16 = 0x0188;

/// NtNotifyChangeDirectoryFile - Notify of directory changes
pub const NtNotifyChangeDirectoryFile: u16 = 0x00EA;

/// NtCancelIoFile - Cancel I/O operation
pub const NtCancelIoFile: u16 = 0x005D;

/// NtCancelIoFileEx - Cancel I/O operation (extended)
pub const NtCancelIoFileEx: u16 = 0x0086;

// =============================================================================
// Section / Shared Memory
// =============================================================================

/// NtCreateSection - Create a section object
pub const NtCreateSection: u16 = 0x0047;

/// NtCreateSectionEx - Create a section object (extended)
pub const NtCreateSectionEx: u16 = 0x0047;

/// NtOpenSection - Open a section object
pub const NtOpenSection: u16 = 0x0037;

/// NtCreateNamedPipeFile - Create a named pipe
pub const NtCreateNamedPipeFile: u16 = 0x009B;

/// NtCreateMailslotFile - Create a mailslot
pub const NtCreateMailslotFile: u16 = 0x0099;

// =============================================================================
// Synchronization Objects (Events, Mutants, Semaphores, Timers)
// =============================================================================

/// NtCreateEvent - Create an event object
pub const NtCreateEvent: u16 = 0x0048;

/// NtOpenEvent - Open an event object
pub const NtOpenEvent: u16 = 0x0040;

/// NtSetEvent - Set an event to signaled state
pub const NtSetEvent: u16 = 0x000E;

/// NtResetEvent - Reset an event to non-signaled state
pub const NtResetEvent: u16 = 0x0141;

/// NtClearEvent - Clear an event
pub const NtClearEvent: u16 = 0x003E;

/// NtPulseEvent - Pulse an event
pub const NtPulseEvent: u16 = 0x010C;

/// NtQueryEvent - Query event information
pub const NtQueryEvent: u16 = 0x0056;

/// NtCreateMutant - Create a mutant (mutex) object
pub const NtCreateMutant: u16 = 0x009A;

/// NtOpenMutant - Open a mutant object
pub const NtOpenMutant: u16 = 0x00F6;

/// NtReleaseMutant - Release a mutant
pub const NtReleaseMutant: u16 = 0x0020;

/// NtCreateSemaphore - Create a semaphore object
pub const NtCreateSemaphore: u16 = 0x00B1;

/// NtOpenSemaphore - Open a semaphore object
pub const NtOpenSemaphore: u16 = 0x00FB;

/// NtReleaseSemaphore - Release a semaphore
pub const NtReleaseSemaphore: u16 = 0x000A;

/// NtCreateTimer - Create a timer object
pub const NtCreateTimer: u16 = 0x00B4;

/// NtOpenTimer - Open a timer object
pub const NtOpenTimer: u16 = 0x00FF;

/// NtSetTimer - Set a timer
pub const NtSetTimer: u16 = 0x0062;

/// NtCancelTimer - Cancel a timer
pub const NtCancelTimer: u16 = 0x0061;

/// NtQueryTimer - Query timer information
pub const NtQueryTimer: u16 = 0x0038;

// =============================================================================
// Registry
// =============================================================================

/// NtCreateKey - Create a registry key
pub const NtCreateKey: u16 = 0x001D;

/// NtOpenKey - Open a registry key
pub const NtOpenKey: u16 = 0x0012;

/// NtDeleteKey - Delete a registry key
pub const NtDeleteKey: u16 = 0x00B3;

/// NtDeleteValueKey - Delete a registry value
pub const NtDeleteValueKey: u16 = 0x00B6;

/// NtQueryKey - Query key information
pub const NtQueryKey: u16 = 0x0016;

/// NtSetValueKey - Set a registry value
pub const NtSetValueKey: u16 = 0x005E;

/// NtQueryValueKey - Query a registry value
pub const NtQueryValueKey: u16 = 0x0017;

/// NtEnumerateKey - Enumerate subkeys
pub const NtEnumerateKey: u16 = 0x0032;

/// NtEnumerateValueKey - Enumerate values
pub const NtEnumerateValueKey: u16 = 0x0013;

/// NtFlushKey - Flush a registry key
pub const NtFlushKey: u16 = 0x00C3;

/// NtLoadKey - Load a registry hive
pub const NtLoadKey: u16 = 0x00DD;

/// NtLoadKey2 - Load a registry hive (version 2)
pub const NtLoadKey2: u16 = 0x00DE;

/// NtSaveKey - Save a registry key
pub const NtSaveKey: u16 = 0x0149;

/// NtSaveKeyEx - Save a registry key (extended)
pub const NtSaveKeyEx: u16 = 0x014A;

/// NtNotifyChangeKey - Notify of key changes
pub const NtNotifyChangeKey: u16 = 0x00EB;

/// NtQueryOpenSubKeys - Query number of open subkeys
pub const NtQueryOpenSubKeys: u16 = 0x0122;

/// NtCompactKeys - Compact registry keys
pub const NtCompactKeys: u16 = 0x00F0;

/// NtCompressKey - Compress a registry key
pub const NtCompressKey: u16 = 0x00F1;

/// NtCreateKeyTransacted - Create a transacted registry key
pub const NtCreateKeyTransacted: u16 = 0x0097;

/// NtOpenKeyTransacted - Open a transacted registry key
pub const NtOpenKeyTransacted: u16 = 0x00F3;

/// NtDeleteKeyTransacted - Delete a transacted registry key
pub const NtDeleteKeyTransacted: u16 = 0x00F3;

// =============================================================================
// Directory & Symbolic Link Objects
// =============================================================================

/// NtCreateDirectoryObject - Create a directory object
pub const NtCreateDirectoryObject: u16 = 0x0091;

/// NtOpenDirectoryObject - Open a directory object
pub const NtOpenDirectoryObject: u16 = 0x0055;

/// NtQueryDirectoryObject - Query a directory object
pub const NtQueryDirectoryObject: u16 = 0x0110;

/// NtCreateSymbolicLinkObject - Create a symbolic link
pub const NtCreateSymbolicLinkObject: u16 = 0x00A4;

/// NtOpenSymbolicLinkObject - Open a symbolic link
pub const NtOpenSymbolicLinkObject: u16 = 0x00FD;

/// NtQuerySymbolicLinkObject - Query symbolic link target
pub const NtQuerySymbolicLinkObject: u16 = 0x0129;

// =============================================================================
// Security (Access Control)
// =============================================================================

/// NtAccessCheck - Check access rights
pub const NtAccessCheck: u16 = 0x0000;

/// NtAccessCheckAndAuditAlarm - Check access with audit
pub const NtAccessCheckAndAuditAlarm: u16 = 0x0029;

/// NtSetSecurityObject - Set security on an object
pub const NtSetSecurityObject: u16 = 0x0169;

/// NtQuerySecurityObject - Query security on an object
pub const NtQuerySecurityObject: u16 = 0x0127;

/// NtPrivilegeCheck - Check privileges
pub const NtPrivilegeCheck: u16 = 0x0107;

/// NtImpersonateAnonymousToken - Impersonate anonymous token
pub const NtImpersonateAnonymousToken: u16 = 0x00D4;

// =============================================================================
// Token Management
// =============================================================================

/// NtCreateToken - Create a security token
pub const NtCreateToken: u16 = 0x00B6;

/// NtOpenObjectAuditAlarm - Open object audit alarm
pub const NtOpenObjectAuditAlarm: u16 = 0x00F7;

/// NtFilterToken - Create a filtered token
pub const NtFilterToken: u16 = 0x00D5;

/// NtCheckLowBoxToken - Check low box token
pub const NtCheckLowBoxToken: u16 = 0x0197;

// =============================================================================
// ALPC (Advanced Local Procedure Call)
// =============================================================================

/// NtCreatePort - Create an ALPC port
pub const NtCreatePort: u16 = 0x00A7;

/// NtConnectPort - Connect to a port
pub const NtConnectPort: u16 = 0x008F;

/// NtListenPort - Listen for connections
pub const NtListenPort: u16 = 0x00DB;

/// NtAcceptConnectPort - Accept a connection
pub const NtAcceptConnectPort: u16 = 0x0060;

/// NtSendWaitReceivePort - Send and wait for reply
pub const NtSendWaitReceivePort: u16 = 0x00AF;

/// NtImpersonateClientOfPort - Impersonate client of port
pub const NtImpersonateClientOfPort: u16 = 0x001D;

/// NtReplyWaitReceivePort - Reply and wait for receive
pub const NtReplyWaitReceivePort: u16 = 0x0009;

/// NtReplyPort - Reply on a port
pub const NtReplyPort: u16 = 0x000A;

/// NtReplyWaitReceivePortEx - Reply and wait (extended)
pub const NtReplyWaitReceivePortEx: u16 = 0x002B;

/// NtCreatePortSection - Create a port section
pub const NtCreatePortSection: u16 = 0x00BD;

/// NtSecureConnectPort - Securely connect to a port
pub const NtSecureConnectPort: u16 = 0x014C;

/// NtQueryInformationPort - Query port information
pub const NtQueryInformationPort: u16 = 0x0117;

/// NtTransmitFile - Transmit file data
pub const NtTransmitFile: u16 = 0x0177;

/// NtRequestPort - Request a port
pub const NtRequestPort: u16 = 0x0140;

/// NtRequestWaitReplyPort - Request and wait for reply
pub const NtRequestWaitReplyPort: u16 = 0x0020;

// =============================================================================
// Job Objects
// =============================================================================

/// NtCreateJobSet - Create a job set
pub const NtCreateJobSet: u16 = 0x0096;

/// NtAssignProcessToJobObject - Assign process to job
pub const NtAssignProcessToJobObject: u16 = 0x0085;

/// NtTerminateJobObject - Terminate a job
pub const NtTerminateJobObject: u16 = 0x017D;

/// NtQueryJobInformation - Query job information
pub const NtQueryJobInformation: u16 = 0x0178;

/// NtSetJobInformation - Set job information
pub const NtSetJobInformation: u16 = 0x0179;

/// NtIsProcessInJob - Check if process is in a job
pub const NtIsProcessInJob: u16 = 0x004C;

// =============================================================================
// Locale & Culture
// =============================================================================

/// NtQueryDefaultLocale - Query default locale
pub const NtQueryDefaultLocale: u16 = 0x0015;

/// NtSetDefaultLocale - Set default locale
pub const NtSetDefaultLocale: u16 = 0x0153;

/// NtQueryDefaultHardErrorMode - Query default hard error mode
pub const NtQueryDefaultHardErrorMode: u16 = 0x0108;

/// NtSetDefaultHardErrorMode - Set default hard error mode
pub const NtSetDefaultHardErrorMode: u16 = 0x0187;

/// NtReadOnlyLogonSessionTree - Read-only logon session tree
pub const NtReadOnlyLogonSessionTree: u16 = 0x0180;

/// NtVerifySession - Verify a session
pub const NtVerifySession: u16 = 0x0181;

// =============================================================================
// Paging & Memory Management
// =============================================================================

/// NtCreatePagingFile - Create a paging file
pub const NtCreatePagingFile: u16 = 0x009C;

/// NtInitializeRegistry - Initialize registry
pub const NtInitializeRegistry: u16 = 0x00D7;

// =============================================================================
// User Processes
// =============================================================================

/// NtCreateUserProcess - Create a user process
pub const NtCreateUserProcess: u16 = 0x00AA;

// =============================================================================
// Exception Handling
// =============================================================================

/// NtRaiseException - Raise an exception
pub const NtRaiseException: u16 = 0x012F;

/// NtRaiseHardError - Raise a hard error
pub const NtRaiseHardError: u16 = 0x0130;

// =============================================================================
// LDT (Local Descriptor Table)
// =============================================================================

/// NtSetLdtEntries - Set LDT entries
pub const NtSetLdtEntries: u16 = 0x0165;

/// NtSetLdtSize - Set LDT size
pub const NtSetLdtSize: u16 = 0x0168;

// =============================================================================
// DLL & Process Loading
// =============================================================================

/// NtQueryLicenseValue - Query license value
pub const NtQueryLicenseValue: u16 = 0x011F;

// =============================================================================
// Transaction Manager
// =============================================================================

/// NtCreateTransaction - Create a transaction
pub const NtCreateTransaction: u16 = 0x00A8;

/// NtOpenTransaction - Open a transaction
pub const NtOpenTransaction: u16 = 0x0100;

/// NtCommitTransaction - Commit a transaction
pub const NtCommitTransaction: u16 = 0x008A;

/// NtRollbackTransaction - Rollback a transaction
pub const NtRollbackTransaction: u16 = 0x0147;

/// NtEnumerateTransaction - Enumerate transactions
pub const NtEnumerateTransaction: u16 = 0x0148;

/// NtSetInformationTransaction - Set transaction information
pub const NtSetInformationTransaction: u16 = 0x015F;

/// NtQueryInformationTransaction - Query transaction information
pub const NtQueryInformationTransaction: u16 = 0x0119;

// =============================================================================
// System Service Table Information
// =============================================================================

/// NtSetSystemInformationEx - Set system information (extended)
pub const NtSetSystemInformationEx: u16 = 0x012C;

/// NtQuerySystemInformationEx - Query system information (extended)
pub const NtQuerySystemInformationEx: u16 = 0x012C;

/// NtTrimProcessWorkingSet - Trim the working set of a process
pub const NtTrimProcessWorkingSet: u16 = 0x0157;

// =============================================================================
// Flush Buffers Extended
// =============================================================================

/// NtFlushBuffersFileEx - Flush file buffers (extended)
pub const NtFlushBuffersFileEx: u16 = 0x00D2;

// =============================================================================
// Worker Factory
// =============================================================================

/// NtWaitForWorkViaWorkerFactory - Wait for work via worker factory
pub const NtWaitForWorkViaWorkerFactory: u16 = 0x018D;

// =============================================================================
// Private Namespaces
// =============================================================================

/// NtCreatePrivateNamespace - Create a private namespace
pub const NtCreatePrivateNamespace: u16 = 0x009E;

/// NtOpenPrivateNamespace - Open a private namespace
pub const NtOpenPrivateNamespace: u16 = 0x00F8;

/// NtDeletePrivateNamespace - Delete a private namespace
pub const NtDeletePrivateNamespace: u16 = 0x00B5;

// =============================================================================
// Job Object Extended
// =============================================================================

/// NtEnumerateDriverPackage - Enumerate driver package
pub const NtEnumerateDriverPackage: u16 = 0x01A9;

// =============================================================================
// Process State
// =============================================================================

/// NtCreateProcessState - Create process state
pub const NtCreateProcessState: u16 = 0x0166;

// =============================================================================
// IRP (I/O Request Packet) Creation
// =============================================================================

/// NtCreateIRP - Create an IRP (for kernel use)
pub const NtCreateIRP: u16 = 0x01A5;

// =============================================================================
// System Startup
// =============================================================================

/// NtStartup - System startup (for boot loader use)
pub const NtStartup: u16 = 0x01A6;

// =============================================================================
// UUID / GUID Allocation
// =============================================================================

/// NtAllocateUuids - Allocate UUIDs
pub const NtAllocateUuids: u16 = 0x0184;

// =============================================================================
// Process/Thread Enumeration
// =============================================================================

/// NtGetNextProcess - Get next process in enumeration
pub const NtGetNextProcess: u16 = 0x00CE;

/// NtGetNextThread - Get next thread in enumeration
pub const NtGetNextThread: u16 = 0x00CF;

// =============================================================================
// Atom Table
// =============================================================================

/// NtAddAtom - Add an atom to the atom table
pub const NtAddAtom: u16 = 0x0047;

/// NtDeleteAtom - Delete an atom from the atom table
pub const NtDeleteAtom: u16 = 0x00AF;

/// NtQueryInformationAtom - Query atom information
pub const NtQueryInformationAtom: u16 = 0x0114;

// =============================================================================
// Maximum syscall number in native NT table
// =============================================================================

/// Maximum syscall number in the native NT SSDT
/// This is used to validate syscall numbers before dispatch
pub const NT_SSDT_MAX_SERVICE: u16 = 0x01A9;
