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

// =================================================================
// Wait & Synchronization
// =================================================================

pub const NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x0001;
pub const NT_WAIT_FOR_MULTIPLE_OBJECTS: u32 = 0x0058;
pub const NT_DELAY_EXECUTION: u32 = 0x0031;
pub const NT_YIELD_EXECUTION: u32 = 0x0043;
pub const NT_SIGNAL_AND_WAIT_FOR_SINGLE_OBJECT: u32 = 0x0176;
pub const NT_WAIT_FOR_MULTIPLE_OBJECTS32: u32 = 0x0017;

// =================================================================
// System Information & control
// =================================================================

pub const NT_QUERY_SYSTEM_INFORMATION: u32 = 0x0033;
pub const NT_SET_SYSTEM_INFORMATION: u32 = 0x016C;
pub const NT_QUERY_SYSTEM_TIME: u32 = 0x0057;
pub const NT_SET_SYSTEM_TIME: u32 = 0x016E;
pub const NT_QUERY_INTERRUPT_TIME: u32 = 0x0058;
pub const NT_SET_INTERRUPT_TIME: u32 = 0x0059;
pub const NT_QUERY_TICK_COUNT: u32 = 0x00A8;
pub const NT_GET_CURRENT_PROCESSOR_NUMBER: u32 = 0x00CB;
pub const NT_SHUTDOWN_SYSTEM: u32 = 0x0174;
pub const NT_TEST_ALERT: u32 = 0x017E;
pub const NT_CALLBACK_RETURN: u32 = 0x0002;
pub const NT_DISPLAY_STRING: u32 = 0x00B8;
pub const NT_QUERY_PERFORMANCE_COUNTER: u32 = 0x002E;
pub const NT_SET_SYSTEM_POWER_STATE: u32 = 0x016D;
pub const NT_SHUTDOWN_WORKER_FACTORY: u32 = 0x0175;

// =================================================================
// Object Management
// =================================================================

pub const NT_CLOSE: u32 = 0x000C;
pub const NT_QUERY_OBJECT: u32 = 0x000D;
pub const NT_SET_INFORMATION_OBJECT: u32 = 0x0059;
pub const NT_DUPLICATE_OBJECT: u32 = 0x0039;
pub const NT_MAKE_PERMANENT_OBJECT: u32 = 0x00E4;
pub const NT_MAKE_TEMPORARY_OBJECT: u32 = 0x00E5;

// =================================================================
// Process Management
// =================================================================

pub const NT_OPEN_PROCESS: u32 = 0x0023;
pub const NT_QUERY_INFORMATION_PROCESS: u32 = 0x0016;
pub const NT_SET_INFORMATION_PROCESS: u32 = 0x0019;
pub const NT_CREATE_PROCESS: u32 = 0x009F;
pub const NT_CREATE_PROCESS_EX: u32 = 0x004A;
pub const NT_TERMINATE_PROCESS: u32 = 0x0029;
pub const NT_OPEN_PROCESS_TOKEN: u32 = 0x00F9;
pub const NT_OPEN_PROCESS_TOKEN_EX: u32 = 0x002D;
pub const NT_SUSPEND_PROCESS: u32 = 0x017A;
pub const NT_RESUME_PROCESS: u32 = 0x0144;

// =================================================================
// Thread Management
// =================================================================

pub const NT_OPEN_THREAD: u32 = 0x00FE;
pub const NT_QUERY_INFORMATION_THREAD: u32 = 0x0022;
pub const NT_SET_INFORMATION_THREAD: u32 = 0x000A;
pub const NT_CREATE_THREAD: u32 = 0x004B;
pub const NT_CREATE_THREAD_EX: u32 = 0x00A5;
pub const NT_TERMINATE_THREAD: u32 = 0x0050;
pub const NT_SUSPEND_THREAD: u32 = 0x017B;
pub const NT_RESUME_THREAD: u32 = 0x004F;
pub const NT_GET_CONTEXT_THREAD: u32 = 0x00CA;
pub const NT_SET_CONTEXT_THREAD: u32 = 0x0150;
pub const NT_OPEN_THREAD_TOKEN: u32 = 0x0021;
pub const NT_OPEN_THREAD_TOKEN_EX: u32 = 0x002C;
pub const NT_IMPERSONATE_THREAD: u32 = 0x00D5;
pub const NT_REVERT_TO_SELF: u32 = 0x00D6;
pub const NT_REGISTER_THREAD_TERMINATE_PORT: u32 = 0x0136;
pub const NT_ALERT_THREAD: u32 = 0x006A;
pub const NT_ALERT_RESUME_THREAD: u32 = 0x0069;

// =================================================================
// Memory Management
// =================================================================

pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x0015;
pub const NT_FREE_VIRTUAL_MEMORY: u32 = 0x001B;
pub const NT_READ_VIRTUAL_MEMORY: u32 = 0x003C;
pub const NT_WRITE_VIRTUAL_MEMORY: u32 = 0x0037;
pub const NT_QUERY_VIRTUAL_MEMORY: u32 = 0x0020;
pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x004D;
pub const NT_MAP_VIEW_OF_SECTION: u32 = 0x0025;
pub const NT_UNMAP_VIEW_OF_SECTION: u32 = 0x0027;
pub const NT_MAP_USER_PHYSICAL_PAGES: u32 = 0x00E7;
pub const NT_ALLOCATE_USER_PHYSICAL_PAGES: u32 = 0x006D;
pub const NT_FREE_USER_PHYSICAL_PAGES: u32 = 0x00C7;
pub const NT_LOCK_VIRTUAL_MEMORY: u32 = 0x00E3;
pub const NT_UNLOCK_VIRTUAL_MEMORY: u32 = 0x0189;
pub const NT_FLUSH_VIRTUAL_MEMORY: u32 = 0x00C5;

// =================================================================
// File I/O
// =================================================================

pub const NT_CREATE_FILE: u32 = 0x0052;
pub const NT_OPEN_FILE: u32 = 0x0030;
pub const NT_READ_FILE: u32 = 0x0003;
pub const NT_WRITE_FILE: u32 = 0x0005;
pub const NT_QUERY_INFORMATION_FILE: u32 = 0x000E;
pub const NT_SET_INFORMATION_FILE: u32 = 0x0024;
pub const NT_DELETE_FILE: u32 = 0x00B2;
pub const NT_FLUSH_BUFFERS_FILE: u32 = 0x0048;
pub const NT_FLUSH_BUFFERS_FILE_EX: u32 = 0x00D2;
pub const NT_QUERY_VOLUME_INFORMATION_FILE: u32 = 0x0046;
pub const NT_SET_VOLUME_INFORMATION_FILE: u32 = 0x0173;
pub const NT_QUERY_DIRECTORY_FILE: u32 = 0x0032;
pub const NT_QUERY_ATTRIBUTES_FILE: u32 = 0x003A;
pub const NT_QUERY_FULL_ATTRIBUTES_FILE: u32 = 0x0113;
pub const NT_LOCK_FILE: u32 = 0x00E0;
pub const NT_UNLOCK_FILE: u32 = 0x0188;
pub const NT_NOTIFY_CHANGE_DIRECTORY_FILE: u32 = 0x00EA;
pub const NT_CANCEL_IO_FILE: u32 = 0x005A;
pub const NT_CANCEL_IO_FILE_EX: u32 = 0x0086;
pub const NT_READ_FILE_SCATTER: u32 = 0x002B;
pub const NT_WRITE_FILE_GATHER: u32 = 0x0018;
pub const NT_QUERY_EA_FILE: u32 = 0x0112;
pub const NT_SET_EA_FILE: u32 = 0x0156;

// =================================================================
// Section / Shared Memory
// =================================================================

pub const NT_CREATE_SECTION: u32 = 0x0047;
pub const NT_OPEN_SECTION: u32 = 0x0034;
pub const NT_EXTEND_SECTION: u32 = 0x00BF;
pub const NT_CREATE_NAMED_PIPE_FILE: u32 = 0x009B;
pub const NT_CREATE_MAILSLOT_FILE: u32 = 0x0099;
pub const NT_CREATE_PROFILE: u32 = 0x00A0;

// =================================================================
// Synchronization Objects
// =================================================================

pub const NT_CREATE_EVENT: u32 = 0x0045;
pub const NT_OPEN_EVENT: u32 = 0x003D;
pub const NT_SET_EVENT: u32 = 0x000B;
pub const NT_RESET_EVENT: u32 = 0x0141;
pub const NT_CLEAR_EVENT: u32 = 0x003B;
pub const NT_PULSE_EVENT: u32 = 0x010C;
pub const NT_QUERY_EVENT: u32 = 0x0053;
pub const NT_CREATE_MUTANT: u32 = 0x009A;
pub const NT_OPEN_MUTANT: u32 = 0x00F6;
pub const NT_RELEASE_MUTANT: u32 = 0x001D;
pub const NT_QUERY_MUTANT: u32 = 0x0121;
pub const NT_CREATE_SEMAPHORE: u32 = 0x00A3;
pub const NT_OPEN_SEMAPHORE: u32 = 0x00FB;
pub const NT_RELEASE_SEMAPHORE: u32 = 0x0007;
pub const NT_QUERY_SEMAPHORE: u32 = 0x0128;
pub const NT_CREATE_TIMER: u32 = 0x00A6;
pub const NT_OPEN_TIMER: u32 = 0x00FF;
pub const NT_SET_TIMER: u32 = 0x005F;
pub const NT_CANCEL_TIMER: u32 = 0x005E;
pub const NT_QUERY_TIMER: u32 = 0x0035;
pub const NT_QUERY_TIMER_RESOLUTION: u32 = 0x012D;
pub const NT_SET_TIMER_RESOLUTION: u32 = 0x0171;
pub const NT_CREATE_KEYED_EVENT: u32 = 0x0098;
pub const NT_OPEN_KEYED_EVENT: u32 = 0x00F5;
pub const NT_RELEASE_KEYED_EVENT: u32 = 0x0137;
pub const NT_WAIT_FOR_KEYED_EVENT: u32 = 0x018C;
pub const NT_CREATE_EVENT_PAIR: u32 = 0x0093;
pub const NT_OPEN_EVENT_PAIR: u32 = 0x00EF;
pub const NT_SET_EVENT_BOOST_PRIORITY: u32 = 0x002A;

// =================================================================
// Registry
// =================================================================

pub const NT_CREATE_KEY: u32 = 0x001A;
pub const NT_OPEN_KEY: u32 = 0x000F;
pub const NT_DELETE_KEY: u32 = 0x00B3;
pub const NT_DELETE_VALUE_KEY: u32 = 0x00B6;
pub const NT_QUERY_KEY: u32 = 0x0013;
pub const NT_SET_VALUE_KEY: u32 = 0x005D;
pub const NT_QUERY_VALUE_KEY: u32 = 0x0014;
pub const NT_ENUMERATE_KEY: u32 = 0x002F;
pub const NT_ENUMERATE_VALUE_KEY: u32 = 0x0010;
pub const NT_FLUSH_KEY: u32 = 0x00C3;
pub const NT_LOAD_KEY: u32 = 0x00DD;
pub const NT_LOAD_KEY2: u32 = 0x00DE;
pub const NT_UNLOAD_KEY: u32 = 0x0185;
pub const NT_SAVE_KEY: u32 = 0x0149;
pub const NT_SAVE_KEY_EX: u32 = 0x014A;
pub const NT_NOTIFY_CHANGE_KEY: u32 = 0x00EB;
pub const NT_QUERY_OPEN_SUB_KEYS: u32 = 0x0122;
pub const NT_COMPACT_KEYS: u32 = 0x008B;
pub const NT_COMPRESS_KEY: u32 = 0x008E;
pub const NT_CREATE_KEY_TRANSACTED: u32 = 0x0097;
pub const NT_OPEN_KEY_TRANSACTED: u32 = 0x00F3;
pub const NT_OPEN_KEY_TRANSACTED_EX: u32 = 0x00F4;
pub const NT_DELETE_KEY_TRANSACTED: u32 = 0x00F3;
pub const NT_SET_VALUE_KEY_TRANSACTED: u32 = 0x0160;
pub const NT_SET_INFORMATION_KEY: u32 = 0x015C;
pub const NT_RENAME_KEY: u32 = 0x013B;
pub const NT_QUERY_MULTIPLE_VALUE_KEY: u32 = 0x0120;

// =================================================================
// Directory & Symbolic Link
// =================================================================

pub const NT_CREATE_DIRECTORY_OBJECT: u32 = 0x0091;
pub const NT_OPEN_DIRECTORY_OBJECT: u32 = 0x0055;
pub const NT_QUERY_DIRECTORY_OBJECT: u32 = 0x0110;
pub const NT_CREATE_SYMBOLIC_LINK_OBJECT: u32 = 0x00A4;
pub const NT_OPEN_SYMBOLIC_LINK_OBJECT: u32 = 0x00FD;
pub const NT_QUERY_SYMBOLIC_LINK_OBJECT: u32 = 0x0129;

// =================================================================
// Security
// =================================================================

pub const NT_ACCESS_CHECK: u32 = 0x0061;
pub const NT_ACCESS_CHECK_AND_AUDIT_ALARM: u32 = 0x0026;
pub const NT_SET_SECURITY_OBJECT: u32 = 0x0169;
pub const NT_QUERY_SECURITY_OBJECT: u32 = 0x0127;
pub const NT_PRIVILEGE_CHECK: u32 = 0x0107;
pub const NT_IMPERSONATE_ANONYMOUS_TOKEN: u32 = 0x00D4;

// =================================================================
// Token Management
// =================================================================

pub const NT_CREATE_TOKEN: u32 = 0x00A7;
pub const NT_OPEN_OBJECT_AUDIT_ALARM: u32 = 0x00F7;
pub const NT_FILTER_TOKEN: u32 = 0x00C0;
pub const NT_ADJUST_PRIVILEGES_TOKEN: u32 = 0x003E;
pub const NT_ADJUST_GROUPS_TOKEN: u32 = 0x0068;
pub const NT_DUPLICATE_TOKEN: u32 = 0x003F;
pub const NT_QUERY_INFORMATION_TOKEN: u32 = 0x001E;
pub const NT_SET_INFORMATION_TOKEN: u32 = 0x015E;

// =================================================================
// ALPC
// =================================================================

pub const NT_CREATE_PORT: u32 = 0x009D;
pub const NT_CONNECT_PORT: u32 = 0x008F;
pub const NT_LISTEN_PORT: u32 = 0x00DB;
pub const NT_ACCEPT_CONNECT_PORT: u32 = 0x0060;
pub const NT_SEND_WAIT_RECEIVE_PORT: u32 = 0x00AF;
pub const NT_IMPERSONATE_CLIENT_OF_PORT: u32 = 0x001C;
pub const NT_REPLY_WAIT_RECEIVE_PORT: u32 = 0x0008;
pub const NT_REPLY_PORT: u32 = 0x0009;
pub const NT_REPLY_WAIT_RECEIVE_PORT_EX: u32 = 0x0028;
pub const NT_CREATE_PORT_SECTION: u32 = 0x00BD;
pub const NT_SECURE_CONNECT_PORT: u32 = 0x014C;
pub const NT_QUERY_INFORMATION_PORT: u32 = 0x0117;
pub const NT_REQUEST_PORT: u32 = 0x0140;
pub const NT_REQUEST_WAIT_REPLY_PORT: u32 = 0x001F;
pub const NT_COMPLETE_CONNECT_PORT: u32 = 0x008D;
pub const NT_REPLY_WAIT_REPLY_PORT: u32 = 0x013F;

// =================================================================
// Job Objects
// =================================================================

pub const NT_CREATE_JOB_SET: u32 = 0x0096;
pub const NT_CREATE_JOB_OBJECT: u32 = 0x0095;
pub const NT_OPEN_JOB_OBJECT: u32 = 0x00F1;
pub const NT_ASSIGN_PROCESS_TO_JOB_OBJECT: u32 = 0x0085;
pub const NT_TERMINATE_JOB_OBJECT: u32 = 0x017D;
pub const NT_QUERY_JOB_INFORMATION: u32 = 0x0178;
pub const NT_SET_JOB_INFORMATION: u32 = 0x0179;
pub const NT_QUERY_INFORMATION_JOB_OBJECT: u32 = 0x0116;
pub const NT_SET_INFORMATION_JOB_OBJECT: u32 = 0x015B;
pub const NT_IS_PROCESS_IN_JOB: u32 = 0x004C;

// =================================================================
// Locale & Culture
// =================================================================

pub const NT_QUERY_DEFAULT_LOCALE: u32 = 0x0012;
pub const NT_SET_DEFAULT_LOCALE: u32 = 0x0153;
pub const NT_QUERY_DEFAULT_UILANGUAGE: u32 = 0x0041;
pub const NT_SET_DEFAULT_UILANGUAGE: u32 = 0x0189;
pub const NT_QUERY_DEFAULT_HARD_ERROR_MODE: u32 = 0x0108;
pub const NT_SET_DEFAULT_HARD_ERROR_MODE: u32 = 0x0187;
pub const NT_READ_ONLY_LOGON_SESSION_TREE: u32 = 0x0180;
pub const NT_VERIFY_SESSION: u32 = 0x0181;

// =================================================================
// Paging & Memory Management
// =================================================================

pub const NT_CREATE_PAGING_FILE: u32 = 0x009C;
pub const NT_INITIALIZE_REGISTRY: u32 = 0x00D7;
pub const NT_CREATE_PROCESS_STATE: u32 = 0x0166;
pub const NT_CREATE_PROCESS_STATE_CHANGE: u32 = 0x00BD;

// =================================================================
// User Processes
// =================================================================

pub const NT_CREATE_USER_PROCESS: u32 = 0x00AA;

// =================================================================
// Exception Handling
// =================================================================

pub const NT_RAISE_EXCEPTION: u32 = 0x012F;
pub const NT_RAISE_HARD_ERROR: u32 = 0x0130;
pub const NT_CONTINUE: u32 = 0x0040;

// =================================================================
// LDT
// =================================================================

pub const NT_SET_LDT_ENTRIES: u32 = 0x0165;
pub const NT_SET_LDT_SIZE: u32 = 0x0168;

// =================================================================
// DLL & Process Loading
// =================================================================

pub const NT_QUERY_LICENSE_VALUE: u32 = 0x011F;
pub const NT_ALLOCATE_LOCALLY_UNIQUE_ID: u32 = 0x006B;
pub const NT_ALLOCATE_UUIDS: u32 = 0x006E;

// =================================================================
// Transaction Manager
// =================================================================

pub const NT_CREATE_TRANSACTION: u32 = 0x00A8;
pub const NT_OPEN_TRANSACTION: u32 = 0x0100;
pub const NT_COMMIT_TRANSACTION: u32 = 0x008A;
pub const NT_ROLLBACK_TRANSACTION: u32 = 0x0147;
pub const NT_ENUMERATE_TRANSACTION: u32 = 0x0148;
pub const NT_SET_INFORMATION_TRANSACTION: u32 = 0x015F;
pub const NT_QUERY_INFORMATION_TRANSACTION: u32 = 0x0119;
pub const NT_CREATE_TRANSACTION_MANAGER: u32 = 0x00A9;
pub const NT_OPEN_TRANSACTION_MANAGER: u32 = 0x0101;
pub const NT_COMMIT_COMPLETE: u32 = 0x0088;
pub const NT_ROLLBACK_COMPLETE: u32 = 0x0145;
pub const NT_ENUMERATE_TRANSACTION_OBJECT: u32 = 0x00BE;

// =================================================================
// System Service Table Information
// =================================================================

pub const NT_SET_SYSTEM_INFORMATION_EX: u32 = 0x012C;
pub const NT_QUERY_SYSTEM_INFORMATION_EX: u32 = 0x012C;
pub const NT_TRIM_PROCESS_WORKING_SET: u32 = 0x0157;

// =================================================================
// Worker Factory
// =================================================================

pub const NT_WAIT_FOR_WORK_VIA_WORKER_FACTORY: u32 = 0x018D;
pub const NT_SET_INFORMATION_WORKER_FACTORY: u32 = 0x0161;
pub const NT_QUERY_INFORMATION_WORKER_FACTORY: u32 = 0x011B;
pub const NT_RELEASE_WORKER_FACTORY_WORKER: u32 = 0x0138;

// =================================================================
// Private Namespaces
// =================================================================

pub const NT_CREATE_PRIVATE_NAMESPACE: u32 = 0x009E;
pub const NT_OPEN_PRIVATE_NAMESPACE: u32 = 0x00F8;
pub const NT_DELETE_PRIVATE_NAMESPACE: u32 = 0x00B5;

// =================================================================
// Debug
// =================================================================

pub const NT_CREATE_DEBUG_OBJECT: u32 = 0x0090;
pub const NT_DEBUG_ACTIVE_PROCESS: u32 = 0x00AD;
pub const NT_REMOVE_PROCESS_DEBUG: u32 = 0x013A;
pub const NT_WAIT_FOR_DEBUG_EVENT: u32 = 0x018B;
pub const NT_DEBUG_CONTINUE: u32 = 0x00AE;
pub const NT_SET_INFORMATION_DEBUG_OBJECT: u32 = 0x0159;
pub const NT_QUERY_INFORMATION_DEBUG_OBJECT: u32 = 0x0125;
pub const NT_DEBUG_PRINT: u32 = 0x003D;

// =================================================================
// System environment
// =================================================================

pub const NT_QUERY_SYSTEM_ENVIRONMENT: u32 = 0x0081;
pub const NT_SET_SYSTEM_ENVIRONMENT_VALUE: u32 = 0x016A;
pub const NT_SET_SYSTEM_ENVIRONMENT_VALUE_EX: u32 = 0x016B;
pub const NT_ENUMERATE_BOOT_ENTRIES: u32 = 0x00BB;
pub const NT_ENUMERATE_DRIVER_ENTRIES: u32 = 0x00BC;
pub const NT_ENUMERATE_DRIVER_PACKAGE: u32 = 0x01A9;
pub const NT_ADD_BOOT_ENTRY: u32 = 0x0066;
pub const NT_DELETE_BOOT_ENTRY: u32 = 0x00B0;
pub const NT_MODIFY_BOOT_ENTRY: u32 = 0x00E8;
pub const NT_SET_BOOT_ENTRY_ORDER: u32 = 0x014E;
pub const NT_SET_BOOT_OPTIONS: u32 = 0x014F;
pub const NT_QUERY_BOOT_ENTRY_ORDER: u32 = 0x010D;
pub const NT_QUERY_BOOT_OPTIONS: u32 = 0x010E;
pub const NT_ADD_DRIVER_ENTRY: u32 = 0x0067;
pub const NT_DELETE_DRIVER_ENTRY: u32 = 0x00B1;
pub const NT_MODIFY_DRIVER_ENTRY: u32 = 0x00E9;
pub const NT_SET_DRIVER_ENTRY_ORDER: u32 = 0x0155;
pub const NT_QUERY_DRIVER_ENTRY_ORDER: u32 = 0x0111;

// =================================================================
// Plug and Play / power
// =================================================================

pub const NT_PLUG_PLAY_CONTROL: u32 = 0x0102;
pub const NT_GET_PLUG_PLAY_EVENT: u32 = 0x00D2;
pub const NT_POWER_INFORMATION: u32 = 0x005C;
pub const NT_INITIATE_POWER_ACTION: u32 = 0x00D8;
pub const NT_SET_THREAD_EXECUTION_STATE: u32 = 0x016F;
pub const NT_GET_DEVICE_POWER_STATE: u32 = 0x00CC;
pub const NT_IS_SYSTEM_RESUME_AUTOMATIC: u32 = 0x00D9;
pub const NT_REQUEST_WAKEUP_LATENCY: u32 = 0x0084;
pub const NT_SET_INTERVAL_PROFILE: u32 = 0x0162;
pub const NT_QUERY_INTERVAL_PROFILE: u32 = 0x011D;

// =================================================================
// IO Completion
// =================================================================

pub const NT_CREATE_IO_COMPLETION: u32 = 0x0094;
pub const NT_OPEN_IO_COMPLETION: u32 = 0x00F0;
pub const NT_SET_IO_COMPLETION: u32 = 0x0163;
pub const NT_SET_IO_COMPLETION_EX: u32 = 0x0164;
pub const NT_QUERY_IO_COMPLETION: u32 = 0x011E;
pub const NT_REMOVE_IO_COMPLETION: u32 = 0x0006;
pub const NT_REMOVE_IO_COMPLETION_EX: u32 = 0x0139;
pub const NT_WAIT_FOR_ALERT_BY_THREAD_ID: u32 = 0x01A6;

// =================================================================
// Atom Table
// =================================================================

pub const NT_ADD_ATOM: u32 = 0x0044;
pub const NT_DELETE_ATOM: u32 = 0x00AF;
pub const NT_QUERY_INFORMATION_ATOM: u32 = 0x0114;
pub const NT_FIND_ATOM: u32 = 0x0011;

// =================================================================
// environment / NLS
// =================================================================

pub const NT_INITIALIZE_NLS_FILES: u32 = 0x00D6;
pub const NT_GET_NLS_SECTION_PTR: u32 = 0x00D0;
pub const NT_QUERY_INSTALL_UILANGUAGE: u32 = 0x007B;
pub const NT_IS_UILANGUAGE_COMMITTED: u32 = 0x00AA;
pub const NT_FLUSH_INSTALL_UILANGUAGE: u32 = 0x0053;
pub const NT_SET_UUID_SEED: u32 = 0x0172;

// =================================================================
// Resource Manager
// =================================================================

pub const NT_GET_NOTIFICATION_RESOURCE_MANAGER: u32 = 0x00D1;
pub const NT_QUERY_INFORMATION_TRANSACTION_MANAGER: u32 = 0x011A;
pub const NT_SET_INFORMATION_TRANSACTION_MANAGER: u32 = 0x0160;

// =================================================================
// Other Important Syscalls
// =================================================================

pub const NT_DEVICE_IO_CONTROL_FILE: u32 = 0x0004;
pub const NT_FS_CONTROL_FILE: u32 = 0x0036;
pub const NT_LOAD_DRIVER: u32 = 0x00DC;
pub const NT_UNLOAD_DRIVER: u32 = 0x0184;
pub const NT_QUERY_SECTION: u32 = 0x004E;
pub const NT_WAIT_HIGH_EVENT_PAIR: u32 = 0x018E;
pub const NT_WAIT_LOW_EVENT_PAIR: u32 = 0x00AA;
pub const NT_SET_HIGH_EVENT_PAIR: u32 = 0x0157;
pub const NT_SET_LOW_EVENT_PAIR: u32 = 0x0166;
pub const NT_SET_HIGH_WAIT_LOW_EVENT_PAIR: u32 = 0x0158;
pub const NT_SET_LOW_WAIT_HIGH_EVENT_PAIR: u32 = 0x0167;
pub const NT_TRANSLATE_FILE_PATH: u32 = 0x0182;
pub const NT_START_SERVICE: u32 = 0x00EC;

// =================================================================
// APC
// =================================================================

pub const NT_QUEUE_APC_THREAD: u32 = 0x0042;
pub const NT_READ_REQUEST_DATA: u32 = 0x0051;
pub const NT_WRITE_REQUEST_DATA: u32 = 0x0054;

// =================================================================
// Profile
// =================================================================

pub const NT_START_PROFILE: u32 = 0x0178;
pub const NT_STOP_PROFILE: u32 = 0x0179;
pub const NT_QUERY_DEBUG_FILTER_STATE: u32 = 0x010F;
pub const NT_SET_DEBUG_FILTER_STATE: u32 = 0x0151;

// =================================================================
// System Debug control
// =================================================================

pub const NT_SYSTEM_DEBUG_CONTROL: u32 = 0x017C;

// =================================================================
// Enumerate System environment Values
// =================================================================

pub const NT_ENUMERATE_SYSTEM_ENVIRONMENT_VALUES_EX: u32 = 0x00BD;

// =================================================================
// Notify Change Session
// =================================================================

pub const NT_NOTIFY_CHANGE_SESSION: u32 = 0x00ED;

// =================================================================
// Flush Process write Buffers
// =================================================================

pub const NT_FLUSH_PROCESS_WRITE_BUFFERS: u32 = 0x00C4;

// =================================================================
// Serialize Boot
// =================================================================

pub const NT_SERIALIZE_BOOT: u32 = 0x014D;

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

/// Poll the PS/2 controller for a pressed key. Returns 0 (no
/// key available) or a non-zero value whose low byte holds the
/// PS/2 scancode. The cmd.exe stub polls this in a tight loop
/// to feed its character-by-character read routine. The kernel
/// also drains the serial UART's RX FIFO and converts CRLF to
/// `\n`, so the same syscall also surfaces any bytes the QEMU
/// monitor typed at the guest.
pub const SYS_POLL_KEY: u32 = 0x0203;

/// Block-wait for a single keypress, returning the PS/2
/// scancode (or a serial RX byte) in `arg0`. Used by the cmd
/// read-line routine when the user has disabled the busy-poll
/// loop.
pub const SYS_GET_KEY: u32 = 0x0204;

/// read a line of input from the serial UART into the user buffer.
/// `arg0` is a pointer to a user-mode buffer, `arg1` is the buffer
/// length in bytes. The kernel drains the COM1 RX FIFO (same
/// source the QEMU `-serial mon:stdio` write feeds) until it sees
/// `\r`, `\n`, or the buffer fills. Returns the number of bytes
/// copied (not counting the terminator) or a negative NTSTATUS on
/// copy fault.
pub const SYS_READ_LINE: u32 = 0x0211;

/// Clear the visible console on the bootvid linear framebuffer
/// AND home the cursor at (0, 0). The `cls` cmd.exe built-in
/// invokes this so the user sees a fresh blank screen instead of
/// the boot-time log being half-painted over the Win7 banner.
/// Returns 0 on success. `arg0`/`arg1`/`arg2` are unused.
pub const SYS_CLEARSCREEN: u32 = 0x0205;

/// Spawn the named subsystem EXE from disk. `arg0` is a pointer
/// to a UTF-8 (or UTF-16, depending on the path convention) NUL-
/// terminated path string in the caller's address space (Ring-3
/// user pointer). The kernel copies the bytes safely into a
/// 256-byte scratch buffer, asks the mounted file-system driver
/// (NTFS, FAT32, or EXT4) for the file bytes, parses the PE, and
/// creates a new Ring-3 process. The new process's PID is
/// returned in `rax`. Used by `winlogon.exe` to spawn the
/// Session-1 csrss.exe and `userinit.exe`, and by `userinit.exe`
/// to spawn `cmd.exe`.
pub const SYS_SPAWN_SUBSYSTEM_PROCESS: u32 = 0x0210;

/// read the CMOS real-time clock and copy a 16-byte
/// `cmos::TimeFields`-shaped struct into the user buffer at
/// `arg0`. The layout (little endian) is:
///
/// ```text
///   [0..2]  year      (u16, full year e.g. 2026)
///   [2]     month     (u8, 1..12)
///   [3]     day       (u8, 1..31)
///   [4]     hour      (u8, 0..23)
///   [5]     minute    (u8, 0..59)
///   [6]     second    (u8, 0..59)
///   [7]     weekday   (u8, 0..6, Sunday = 0)
///   [8..16] reserved  (zero)
/// ```
///
/// Returns the number of bytes written (16) on success, or 0 if
/// the CMOS update flag was stuck or `arg0` is NULL. The data is
/// read directly from CMOS registers via `hal::x86_64::cmos`,
/// which already handles BCD decode and 12/24-hour mode. Used by
/// the user-mode `cmd.exe` stub's `time` and `date` builtins so
/// the value printed matches the host's wall clock instead of a
/// hard-coded literal in `autoexec.bat`.
pub const SYS_GET_RTC: u32 = 0x0212;

/// Copy the active IPv4 configuration into the user buffer at
/// `arg0`. The 16-byte layout (network byte order) is:
///
/// ```text
///   [0..4]   IPv4 address    (4 bytes, big endian)
///   [4..8]   subnet mask     (4 bytes, big endian)
///   [8..12]  default gateway (4 bytes, big endian)
///   [12]     interface count (u8)
///   [13..16] reserved        (zero)
/// ```
///
/// Returns the number of bytes written (16) on success, or 0 if
/// `arg0` is NULL. If no IP interface has been registered yet,
/// the kernel falls back to a sane default (127.0.0.1 / 255.0.0.0
/// / 0.0.0.0, count = 1) so the user-mode `ipconfig` always
/// prints a valid answer even on a network-less QEMU harness.
/// Used by the user-mode `cmd.exe` stub's `ipconfig` builtin.
pub const SYS_NETCFG_GET: u32 = 0x0213;

/// Execute one complete command line from the Ring-3 command host.
/// `arg0` points to UTF-8 bytes and `arg1` is the byte count. The
/// command text is not case-normalized by user mode; kernel command
/// matching remains case-insensitive while preserving input display.
pub const SYS_CMD_EXECUTE: u32 = 0x0215;
pub const SYS_PRINT_PROMPT: u32 = 0x0216;

/// Return control to firmware. `arg0` is one of the
/// `FIRMWARE_REENTRY` values understood by
/// `hal::x86_64::halt::hal_return_to_firmware`:
///
///   0 = HAL_HALT (park the CPU)
///   1 = HAL_REBOOT (warm reset)
///   2 = HAL_SHUTDOWN (ACPI S5 soft-off)
///
/// The syscall never returns.
pub const SYS_RETURN_TO_FIRMWARE: u32 = 0x0214;
pub const SYS_FILE_OPEN: u32 = 0x0220;
pub const SYS_FILE_READ: u32 = 0x0221;
pub const SYS_FILE_CLOSE: u32 = 0x0223;
pub const SYS_FILE_DELETE: u32 = 0x0225;
pub const SYS_FILE_LIST: u32 = 0x0226;
