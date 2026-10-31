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
pub const NT_WAIT_FOR_SINGLE_OBJECT: u16 = 0x0001;

/// NtWaitForMultipleObjects - Wait on multiple objects
pub const NT_WAIT_FOR_MULTIPLE_OBJECTS: u16 = 0x0058;

/// NtDelayExecution - Delay execution
pub const NT_DELAY_EXECUTION: u16 = 0x0031;

/// NtYieldExecution - Yield execution to another thread
pub const NT_YIELD_EXECUTION: u16 = 0x0046;

// =============================================================================
// System Information & Control
// =============================================================================

/// NtQuerySystemInformation - Retrieve system information
pub const NT_QUERY_SYSTEM_INFORMATION: u16 = 0x0033;

/// NtSetSystemInformation - Set system information
pub const NT_SET_SYSTEM_INFORMATION: u16 = 0x016C;

/// NtQuerySystemTime - Query the system time
pub const NT_QUERY_SYSTEM_TIME: u16 = 0x0057;

/// NtSetSystemTime - Set the system time
pub const NT_SET_SYSTEM_TIME: u16 = 0x016E;

/// NtQueryInterruptTime - Query interrupt time
pub const NT_QUERY_INTERRUPT_TIME: u16 = 0x0058;

/// NtSetInterruptTime - Set interrupt time
pub const NT_SET_INTERRUPT_TIME: u16 = 0x0059;

/// NtQueryTickCount - Query tick count
pub const NT_QUERY_TICK_COUNT: u16 = 0x00A8;

/// NtGetCurrentProcessorNumber - Get current processor number
pub const NT_GET_CURRENT_PROCESSOR_NUMBER: u16 = 0x00CB;

/// NtShutdownSystem - Shutdown the system
pub const NT_SHUTDOWN_SYSTEM: u16 = 0x0174;

/// NtTestAlert - Test for alert
pub const NT_TEST_ALERT: u16 = 0x017E;

/// NtCallbackReturn - Return from callback
pub const NT_CALLBACK_RETURN: u16 = 0x0005;

/// NtDisplayString - Display a string
pub const NT_DISPLAY_STRING: u16 = 0x00B8;

// =============================================================================
// Object Management
// =============================================================================

/// NtClose - Close a handle
pub const NT_CLOSE: u16 = 0x000C;

/// NtQueryObject - Query information about an object
pub const NT_QUERY_OBJECT: u16 = 0x0010;

/// NtSetInformationObject - Set information about an object
pub const NT_SET_INFORMATION_OBJECT: u16 = 0x005C;

/// NtDuplicateObject - Duplicate an object handle
pub const NT_DUPLICATE_OBJECT: u16 = 0x003C;

// =============================================================================
// Process Management
// =============================================================================

/// NtOpenProcess - Open a process handle
pub const NT_OPEN_PROCESS: u16 = 0x0023;

/// NtQueryInformationProcess - Query process information
pub const NT_QUERY_INFORMATION_PROCESS: u16 = 0x0016;

/// NtSetInformationProcess - Set process information
pub const NT_SET_INFORMATION_PROCESS: u16 = 0x0019;

/// NtCreateProcess - Create a process
pub const NT_CREATE_PROCESS: u16 = 0x009F;

/// NtCreateProcessEx - Create a process with extended options
pub const NT_CREATE_PROCESS_EX: u16 = 0x004A;

/// NtTerminateProcess - Terminate a process
pub const NT_TERMINATE_PROCESS: u16 = 0x0029;

/// NtOpenProcessToken - Open a process's token
pub const NT_OPEN_PROCESS_TOKEN: u16 = 0x00F9;

/// NtOpenProcessTokenEx - Open a process's token with options
pub const NT_OPEN_PROCESS_TOKEN_EX: u16 = 0x002D;

/// NtSuspendProcess - Suspend a process
pub const NT_SUSPEND_PROCESS: u16 = 0x0178;

/// NtResumeProcess - Resume a suspended process
pub const NT_RESUME_PROCESS: u16 = 0x0141;

/// NtQueryInformationProcess_ProcessBasicInformation - Basic process info
pub const NT_QUERY_INFORMATION_PROCESS_PROCESS_BASIC_INFORMATION: u16 = 0x0016;

/// NtQueryInformationProcess_ProcessDebugPort - Debug port info
pub const NT_QUERY_INFORMATION_PROCESS_PROCESS_DEBUG_PORT: u16 = 0x0016;

/// NtQueryInformationProcess_ProcessDebugObjectHandle - Debug object handle
pub const NT_QUERY_INFORMATION_PROCESS_PROCESS_DEBUG_OBJECT_HANDLE: u16 = 0x0016;

/// NtQueryInformationProcess_ProcessDebugFlags - Debug flags
pub const NT_QUERY_INFORMATION_PROCESS_PROCESS_DEBUG_FLAGS: u16 = 0x0016;

// =============================================================================
// Thread Management
// =============================================================================

/// NtOpenThread - Open a thread handle
pub const NT_OPEN_THREAD: u16 = 0x00FE;

/// NtQueryInformationThread - Query thread information
pub const NT_QUERY_INFORMATION_THREAD: u16 = 0x0025;

/// NtSetInformationThread - Set thread information
pub const NT_SET_INFORMATION_THREAD: u16 = 0x000D;

/// NtCreateThread - Create a thread
pub const NT_CREATE_THREAD: u16 = 0x004B;

/// NtTerminateThread - Terminate a thread
pub const NT_TERMINATE_THREAD: u16 = 0x0050;

/// NtSuspendThread - Suspend a thread
pub const NT_SUSPEND_THREAD: u16 = 0x017B;

/// NtResumeThread - Resume a suspended thread
pub const NT_RESUME_THREAD: u16 = 0x004F;

/// NtGetContextThread - Get thread context
pub const NT_GET_CONTEXT_THREAD: u16 = 0x00CA;

/// NtSetContextThread - Set thread context
pub const NT_SET_CONTEXT_THREAD: u16 = 0x0150;

/// NtOpenThreadToken - Open a thread's token
pub const NT_OPEN_THREAD_TOKEN: u16 = 0x0024;

/// NtOpenThreadTokenEx - Open a thread's token with options
pub const NT_OPEN_THREAD_TOKEN_EX: u16 = 0x002F;

/// NtImpersonateThread - Impersonate another thread
pub const NT_IMPERSONATE_THREAD: u16 = 0x00D5;

/// NtRevertToSelf - Revert to self
pub const NT_REVERT_TO_SELF: u16 = 0x00D6;

/// NtRegisterThreadTerminatePort - Register thread terminate port
pub const NT_REGISTER_THREAD_TERMINATE_PORT: u16 = 0x0136;

// =============================================================================
// Memory Management
// =============================================================================

/// NtAllocateVirtualMemory - Allocate virtual memory
pub const NT_ALLOCATE_VIRTUAL_MEMORY: u16 = 0x0015;

/// NtFreeVirtualMemory - Free virtual memory
pub const NT_FREE_VIRTUAL_MEMORY: u16 = 0x001B;

/// NtReadVirtualMemory - Read virtual memory
pub const NT_READ_VIRTUAL_MEMORY: u16 = 0x003E;

/// NtWriteVirtualMemory - Write virtual memory
pub const NT_WRITE_VIRTUAL_MEMORY: u16 = 0x0039;

/// NtQueryVirtualMemory - Query virtual memory information
pub const NT_QUERY_VIRTUAL_MEMORY: u16 = 0x0020;

/// NtProtectVirtualMemory - Change memory protection
pub const NT_PROTECT_VIRTUAL_MEMORY: u16 = 0x004D;

/// NtMapViewOfSection - Map a view of a section
pub const NT_MAP_VIEW_OF_SECTION: u16 = 0x0025;

/// NtUnmapViewOfSection - Unmap a view of a section
pub const NT_UNMAP_VIEW_OF_SECTION: u16 = 0x0027;

/// NtUnmapViewOfSectionEx - Unmap a view of a section (extended)
pub const NT_UNMAP_VIEW_OF_SECTION_EX: u16 = 0x0027;

/// NtMapUserPhysicalPages - Map user physical pages
pub const NT_MAP_USER_PHYSICAL_PAGES: u16 = 0x00E7;

/// NtUnmapUserPhysicalPages - Unmap user physical pages
pub const NT_UNMAP_USER_PHYSICAL_PAGES: u16 = 0x00E8;

// =============================================================================
// File I/O
// =============================================================================

/// NtCreateFile - Create or open a file
pub const NT_CREATE_FILE: u16 = 0x0052;

/// NtOpenFile - Open a file
pub const NT_OPEN_FILE: u16 = 0x0033;

/// NtReadFile - Read from a file
pub const NT_READ_FILE: u16 = 0x0006;

/// NtWriteFile - Write to a file
pub const NT_WRITE_FILE: u16 = 0x0008;

/// NtQueryInformationFile - Query file information
pub const NT_QUERY_INFORMATION_FILE: u16 = 0x000F;

/// NtSetInformationFile - Set file information
pub const NT_SET_INFORMATION_FILE: u16 = 0x0025;

/// NtDeleteFile - Delete a file
pub const NT_DELETE_FILE: u16 = 0x00B2;

/// NtFlushBuffersFile - Flush file buffers
pub const NT_FLUSH_BUFFERS_FILE: u16 = 0x004B;

/// NtQueryVolumeInformationFile - Query volume information
pub const NT_QUERY_VOLUME_INFORMATION_FILE: u16 = 0x0049;

/// NtSetVolumeInformationFile - Set volume information
pub const NT_SET_VOLUME_INFORMATION_FILE: u16 = 0x0173;

/// NtQueryDirectoryFile - Query directory information
pub const NT_QUERY_DIRECTORY_FILE: u16 = 0x0035;

/// NtQueryAttributesFile - Query file attributes
pub const NT_QUERY_ATTRIBUTES_FILE: u16 = 0x003D;

/// NtQueryFullAttributesFile - Query full file attributes
pub const NT_QUERY_FULL_ATTRIBUTES_FILE: u16 = 0x0113;

/// NtLockFile - Lock a file
pub const NT_LOCK_FILE: u16 = 0x00E0;

/// NtUnlockFile - Unlock a file
pub const NT_UNLOCK_FILE: u16 = 0x0188;

/// NtNotifyChangeDirectoryFile - Notify of directory changes
pub const NT_NOTIFY_CHANGE_DIRECTORY_FILE: u16 = 0x00EA;

/// NtCancelIoFile - Cancel I/O operation
pub const NT_CANCEL_IO_FILE: u16 = 0x005D;

/// NtCancelIoFileEx - Cancel I/O operation (extended)
pub const NT_CANCEL_IO_FILE_EX: u16 = 0x0086;

// =============================================================================
// Section / Shared Memory
// =============================================================================

/// NtCreateSection - Create a section object
pub const NT_CREATE_SECTION: u16 = 0x0047;

/// NtCreateSectionEx - Create a section object (extended)
pub const NT_CREATE_SECTION_EX: u16 = 0x0047;

/// NtOpenSection - Open a section object
pub const NT_OPEN_SECTION: u16 = 0x0037;

/// NtCreateNamedPipeFile - Create a named pipe
pub const NT_CREATE_NAMED_PIPE_FILE: u16 = 0x009B;

/// NtCreateMailslotFile - Create a mailslot
pub const NT_CREATE_MAILSLOT_FILE: u16 = 0x0099;

// =============================================================================
// Synchronization Objects (Events, Mutants, Semaphores, Timers)
// =============================================================================

/// NtCreateEvent - Create an event object
pub const NT_CREATE_EVENT: u16 = 0x0048;

/// NtOpenEvent - Open an event object
pub const NT_OPEN_EVENT: u16 = 0x0040;

/// NtSetEvent - Set an event to signaled state
pub const NT_SET_EVENT: u16 = 0x000E;

/// NtResetEvent - Reset an event to non-signaled state
pub const NT_RESET_EVENT: u16 = 0x0141;

/// NtClearEvent - Clear an event
pub const NT_CLEAR_EVENT: u16 = 0x003E;

/// NtPulseEvent - Pulse an event
pub const NT_PULSE_EVENT: u16 = 0x010C;

/// NtQueryEvent - Query event information
pub const NT_QUERY_EVENT: u16 = 0x0056;

/// NtCreateMutant - Create a mutant (mutex) object
pub const NT_CREATE_MUTANT: u16 = 0x009A;

/// NtOpenMutant - Open a mutant object
pub const NT_OPEN_MUTANT: u16 = 0x00F6;

/// NtReleaseMutant - Release a mutant
pub const NT_RELEASE_MUTANT: u16 = 0x0020;

/// NtCreateSemaphore - Create a semaphore object
pub const NT_CREATE_SEMAPHORE: u16 = 0x00B1;

/// NtOpenSemaphore - Open a semaphore object
pub const NT_OPEN_SEMAPHORE: u16 = 0x00FB;

/// NtReleaseSemaphore - Release a semaphore
pub const NT_RELEASE_SEMAPHORE: u16 = 0x000A;

/// NtCreateTimer - Create a timer object
pub const NT_CREATE_TIMER: u16 = 0x00B4;

/// NtOpenTimer - Open a timer object
pub const NT_OPEN_TIMER: u16 = 0x00FF;

/// NtSetTimer - Set a timer
pub const NT_SET_TIMER: u16 = 0x0062;

/// NtCancelTimer - Cancel a timer
pub const NT_CANCEL_TIMER: u16 = 0x0061;

/// NtQueryTimer - Query timer information
pub const NT_QUERY_TIMER: u16 = 0x0038;

// =============================================================================
// Registry
// =============================================================================

/// NtCreateKey - Create a registry key
pub const NT_CREATE_KEY: u16 = 0x001D;

/// NtOpenKey - Open a registry key
pub const NT_OPEN_KEY: u16 = 0x0012;

/// NtDeleteKey - Delete a registry key
pub const NT_DELETE_KEY: u16 = 0x00B3;

/// NtDeleteValueKey - Delete a registry value
pub const NT_DELETE_VALUE_KEY: u16 = 0x00B6;

/// NtQueryKey - Query key information
pub const NT_QUERY_KEY: u16 = 0x0016;

/// NtSetValueKey - Set a registry value
pub const NT_SET_VALUE_KEY: u16 = 0x005E;

/// NtQueryValueKey - Query a registry value
pub const NT_QUERY_VALUE_KEY: u16 = 0x0017;

/// NtEnumerateKey - Enumerate subkeys
pub const NT_ENUMERATE_KEY: u16 = 0x0032;

/// NtEnumerateValueKey - Enumerate values
pub const NT_ENUMERATE_VALUE_KEY: u16 = 0x0013;

/// NtFlushKey - Flush a registry key
pub const NT_FLUSH_KEY: u16 = 0x00C3;

/// NtLoadKey - Load a registry hive
pub const NT_LOAD_KEY: u16 = 0x00DD;

/// NtLoadKey2 - Load a registry hive (version 2)
pub const NT_LOAD_KEY2: u16 = 0x00DE;

/// NtSaveKey - Save a registry key
pub const NT_SAVE_KEY: u16 = 0x0149;

/// NtSaveKeyEx - Save a registry key (extended)
pub const NT_SAVE_KEY_EX: u16 = 0x014A;

/// NtNotifyChangeKey - Notify of key changes
pub const NT_NOTIFY_CHANGE_KEY: u16 = 0x00EB;

/// NtQueryOpenSubKeys - Query number of open subkeys
pub const NT_QUERY_OPEN_SUB_KEYS: u16 = 0x0122;

/// NtCompactKeys - Compact registry keys
pub const NT_COMPACT_KEYS: u16 = 0x00F0;

/// NtCompressKey - Compress a registry key
pub const NT_COMPRESS_KEY: u16 = 0x00F1;

/// NtCreateKeyTransacted - Create a transacted registry key
pub const NT_CREATE_KEY_TRANSACTED: u16 = 0x0097;

/// NtOpenKeyTransacted - Open a transacted registry key
pub const NT_OPEN_KEY_TRANSACTED: u16 = 0x00F3;

/// NtDeleteKeyTransacted - Delete a transacted registry key
pub const NT_DELETE_KEY_TRANSACTED: u16 = 0x00F3;

// =============================================================================
// Directory & Symbolic Link Objects
// =============================================================================

/// NtCreateDirectoryObject - Create a directory object
pub const NT_CREATE_DIRECTORY_OBJECT: u16 = 0x0091;

/// NtOpenDirectoryObject - Open a directory object
pub const NT_OPEN_DIRECTORY_OBJECT: u16 = 0x0055;

/// NtQueryDirectoryObject - Query a directory object
pub const NT_QUERY_DIRECTORY_OBJECT: u16 = 0x0110;

/// NtCreateSymbolicLinkObject - Create a symbolic link
pub const NT_CREATE_SYMBOLIC_LINK_OBJECT: u16 = 0x00A4;

/// NtOpenSymbolicLinkObject - Open a symbolic link
pub const NT_OPEN_SYMBOLIC_LINK_OBJECT: u16 = 0x00FD;

/// NtQuerySymbolicLinkObject - Query symbolic link target
pub const NT_QUERY_SYMBOLIC_LINK_OBJECT: u16 = 0x0129;

// =============================================================================
// Security (Access Control)
// =============================================================================

/// NtAccessCheck - Check access rights
pub const NT_ACCESS_CHECK: u16 = 0x0000;

/// NtAccessCheckAndAuditAlarm - Check access with audit
pub const NT_ACCESS_CHECK_AND_AUDIT_ALARM: u16 = 0x0029;

/// NtSetSecurityObject - Set security on an object
pub const NT_SET_SECURITY_OBJECT: u16 = 0x0169;

/// NtQuerySecurityObject - Query security on an object
pub const NT_QUERY_SECURITY_OBJECT: u16 = 0x0127;

/// NtPrivilegeCheck - Check privileges
pub const NT_PRIVILEGE_CHECK: u16 = 0x0107;

/// NtImpersonateAnonymousToken - Impersonate anonymous token
pub const NT_IMPERSONATE_ANONYMOUS_TOKEN: u16 = 0x00D4;

// =============================================================================
// Token Management
// =============================================================================

/// NtCreateToken - Create a security token
pub const NT_CREATE_TOKEN: u16 = 0x00B6;

/// NtOpenObjectAuditAlarm - Open object audit alarm
pub const NT_OPEN_OBJECT_AUDIT_ALARM: u16 = 0x00F7;

/// NtFilterToken - Create a filtered token
pub const NT_FILTER_TOKEN: u16 = 0x00D5;

/// NtCheckLowBoxToken - Check low box token
pub const NT_CHECK_LOW_BOX_TOKEN: u16 = 0x0197;

// =============================================================================
// ALPC (Advanced Local Procedure Call)
// =============================================================================

/// NtCreatePort - Create an ALPC port
pub const NT_CREATE_PORT: u16 = 0x00A7;

/// NtConnectPort - Connect to a port
pub const NT_CONNECT_PORT: u16 = 0x008F;

/// NtListenPort - Listen for connections
pub const NT_LISTEN_PORT: u16 = 0x00DB;

/// NtAcceptConnectPort - Accept a connection
pub const NT_ACCEPT_CONNECT_PORT: u16 = 0x0060;

/// NtSendWaitReceivePort - Send and wait for reply
pub const NT_SEND_WAIT_RECEIVE_PORT: u16 = 0x00AF;

/// NtImpersonateClientOfPort - Impersonate client of port
pub const NT_IMPERSONATE_CLIENT_OF_PORT: u16 = 0x001D;

/// NtReplyWaitReceivePort - Reply and wait for receive
pub const NT_REPLY_WAIT_RECEIVE_PORT: u16 = 0x0009;

/// NtReplyPort - Reply on a port
pub const NT_REPLY_PORT: u16 = 0x000A;

/// NtReplyWaitReceivePortEx - Reply and wait (extended)
pub const NT_REPLY_WAIT_RECEIVE_PORT_EX: u16 = 0x002B;

/// NtCreatePortSection - Create a port section
pub const NT_CREATE_PORT_SECTION: u16 = 0x00BD;

/// NtSecureConnectPort - Securely connect to a port
pub const NT_SECURE_CONNECT_PORT: u16 = 0x014C;

/// NtQueryInformationPort - Query port information
pub const NT_QUERY_INFORMATION_PORT: u16 = 0x0117;

/// NtTransmitFile - Transmit file data
pub const NT_TRANSMIT_FILE: u16 = 0x0177;

/// NtRequestPort - Request a port
pub const NT_REQUEST_PORT: u16 = 0x0140;

/// NtRequestWaitReplyPort - Request and wait for reply
pub const NT_REQUEST_WAIT_REPLY_PORT: u16 = 0x0020;

// =============================================================================
// Job Objects
// =============================================================================

/// NtCreateJobSet - Create a job set
pub const NT_CREATE_JOB_SET: u16 = 0x0096;

/// NtAssignProcessToJobObject - Assign process to job
pub const NT_ASSIGN_PROCESS_TO_JOB_OBJECT: u16 = 0x0085;

/// NtTerminateJobObject - Terminate a job
pub const NT_TERMINATE_JOB_OBJECT: u16 = 0x017D;

/// NtQueryJobInformation - Query job information
pub const NT_QUERY_JOB_INFORMATION: u16 = 0x0178;

/// NtSetJobInformation - Set job information
pub const NT_SET_JOB_INFORMATION: u16 = 0x0179;

/// NtIsProcessInJob - Check if process is in a job
pub const NT_IS_PROCESS_IN_JOB: u16 = 0x004C;

// =============================================================================
// Locale & Culture
// =============================================================================

/// NtQueryDefaultLocale - Query default locale
pub const NT_QUERY_DEFAULT_LOCALE: u16 = 0x0015;

/// NtSetDefaultLocale - Set default locale
pub const NT_SET_DEFAULT_LOCALE: u16 = 0x0153;

/// NtQueryDefaultHardErrorMode - Query default hard error mode
pub const NT_QUERY_DEFAULT_HARD_ERROR_MODE: u16 = 0x0108;

/// NtSetDefaultHardErrorMode - Set default hard error mode
pub const NT_SET_DEFAULT_HARD_ERROR_MODE: u16 = 0x0187;

/// NtReadOnlyLogonSessionTree - Read-only logon session tree
pub const NT_READ_ONLY_LOGON_SESSION_TREE: u16 = 0x0180;

/// NtVerifySession - Verify a session
pub const NT_VERIFY_SESSION: u16 = 0x0181;

// =============================================================================
// Paging & Memory Management
// =============================================================================

/// NtCreatePagingFile - Create a paging file
pub const NT_CREATE_PAGING_FILE: u16 = 0x009C;

/// NtInitializeRegistry - Initialize registry
pub const NT_INITIALIZE_REGISTRY: u16 = 0x00D7;

// =============================================================================
// User Processes
// =============================================================================

/// NtCreateUserProcess - Create a user process
pub const NT_CREATE_USER_PROCESS: u16 = 0x00AA;

// =============================================================================
// Exception Handling
// =============================================================================

/// NtRaiseException - Raise an exception
pub const NT_RAISE_EXCEPTION: u16 = 0x012F;

/// NtRaiseHardError - Raise a hard error
pub const NT_RAISE_HARD_ERROR: u16 = 0x0130;

// =============================================================================
// LDT (Local Descriptor Table)
// =============================================================================

/// NtSetLdtEntries - Set LDT entries
pub const NT_SET_LDT_ENTRIES: u16 = 0x0165;

/// NtSetLdtSize - Set LDT size
pub const NT_SET_LDT_SIZE: u16 = 0x0168;

// =============================================================================
// DLL & Process Loading
// =============================================================================

/// NtQueryLicenseValue - Query license value
pub const NT_QUERY_LICENSE_VALUE: u16 = 0x011F;

// =============================================================================
// Transaction Manager
// =============================================================================

/// NtCreateTransaction - Create a transaction
pub const NT_CREATE_TRANSACTION: u16 = 0x00A8;

/// NtOpenTransaction - Open a transaction
pub const NT_OPEN_TRANSACTION: u16 = 0x0100;

/// NtCommitTransaction - Commit a transaction
pub const NT_COMMIT_TRANSACTION: u16 = 0x008A;

/// NtRollbackTransaction - Rollback a transaction
pub const NT_ROLLBACK_TRANSACTION: u16 = 0x0147;

/// NtEnumerateTransaction - Enumerate transactions
pub const NT_ENUMERATE_TRANSACTION: u16 = 0x0148;

/// NtSetInformationTransaction - Set transaction information
pub const NT_SET_INFORMATION_TRANSACTION: u16 = 0x015F;

/// NtQueryInformationTransaction - Query transaction information
pub const NT_QUERY_INFORMATION_TRANSACTION: u16 = 0x0119;

// =============================================================================
// System Service Table Information
// =============================================================================

/// NtSetSystemInformationEx - Set system information (extended)
pub const NT_SET_SYSTEM_INFORMATION_EX: u16 = 0x012C;

/// NtQuerySystemInformationEx - Query system information (extended)
pub const NT_QUERY_SYSTEM_INFORMATION_EX: u16 = 0x012C;

/// NtTrimProcessWorkingSet - Trim the working set of a process
pub const NT_TRIM_PROCESS_WORKING_SET: u16 = 0x0157;

// =============================================================================
// Flush Buffers Extended
// =============================================================================

/// NtFlushBuffersFileEx - Flush file buffers (extended)
pub const NT_FLUSH_BUFFERS_FILE_EX: u16 = 0x00D2;

// =============================================================================
// Worker Factory
// =============================================================================

/// NtWaitForWorkViaWorkerFactory - Wait for work via worker factory
pub const NT_WAIT_FOR_WORK_VIA_WORKER_FACTORY: u16 = 0x018D;

// =============================================================================
// Private Namespaces
// =============================================================================

/// NtCreatePrivateNamespace - Create a private namespace
pub const NT_CREATE_PRIVATE_NAMESPACE: u16 = 0x009E;

/// NtOpenPrivateNamespace - Open a private namespace
pub const NT_OPEN_PRIVATE_NAMESPACE: u16 = 0x00F8;

/// NtDeletePrivateNamespace - Delete a private namespace
pub const NT_DELETE_PRIVATE_NAMESPACE: u16 = 0x00B5;

// =============================================================================
// Job Object Extended
// =============================================================================

/// NtEnumerateDriverPackage - Enumerate driver package
pub const NT_ENUMERATE_DRIVER_PACKAGE: u16 = 0x01A9;

// =============================================================================
// Process State
// =============================================================================

/// NtCreateProcessState - Create process state
pub const NT_CREATE_PROCESS_STATE: u16 = 0x0166;

// =============================================================================
// IRP (I/O Request Packet) Creation
// =============================================================================

/// NtCreateIRP - Create an IRP (for kernel use)
pub const NT_CREATE_IRP: u16 = 0x01A5;

// =============================================================================
// System Startup
// =============================================================================

/// NtStartup - System startup (for boot loader use)
pub const NT_STARTUP: u16 = 0x01A6;

// =============================================================================
// UUID / GUID Allocation
// =============================================================================

/// NtAllocateUuids - Allocate UUIDs
pub const NT_ALLOCATE_UUIDS: u16 = 0x0184;

// =============================================================================
// Process/Thread Enumeration
// =============================================================================

/// NtGetNextProcess - Get next process in enumeration
pub const NT_GET_NEXT_PROCESS: u16 = 0x00CE;

/// NtGetNextThread - Get next thread in enumeration
pub const NT_GET_NEXT_THREAD: u16 = 0x00CF;

// =============================================================================
// Atom Table
// =============================================================================

/// NtAddAtom - Add an atom to the atom table
pub const NT_ADD_ATOM: u16 = 0x0047;

/// NtDeleteAtom - Delete an atom from the atom table
pub const NT_DELETE_ATOM: u16 = 0x00AF;

/// NtQueryInformationAtom - Query atom information
pub const NT_QUERY_INFORMATION_ATOM: u16 = 0x0114;

// =============================================================================
// Maximum syscall number in native NT table
// =============================================================================

/// Maximum syscall number in the native NT SSDT
/// This is used to validate syscall numbers before dispatch
pub const NT_SSDT_MAX_SERVICE: u16 = 0x01A9;
