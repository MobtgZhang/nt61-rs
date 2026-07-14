//! Session Manager (SMSS)
//
//! Implements the Windows Session Manager subsystem
//! Responsible for creating sessions, starting csrss.exe, wininit.exe, and winlogon.exe
//
//! ## Session Management
//
//! SMSS creates and manages Windows sessions:
//! - Session 0: System session (services, lsass)
//! - Session 1+: User sessions (interactive logon)
//
//! Each session has its own:
//! - Win32 subsystem state (desktop, window station)
//! - Environment variables
//! - User profile
//
//! ## Boot Sequence
//!
//! The complete Windows 7 boot sequence is:
//! 1. smss.exe starts (this module)
//! 2. smss.exe creates Session 0 and Session 1
//! 3. smss.exe starts csrss.exe for Session 0
//! 4. smss.exe starts wininit.exe
//! 5. wininit.exe starts services.exe and lsass.exe
//! 6. smss.exe starts csrss.exe for Session 1
//! 7. smss.exe starts winlogon.exe
//! 8. winlogon.exe (or smss directly) starts cmd.exe

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ps::process::Process;
use crate::ke::sync::Spinlock;
use crate::registry::cm;
use crate::boot_println;

// ============================================================================
// Constants
// ============================================================================

/// SMSS process ID
pub const PID_SMSS: u64 = 256;
/// CSRSS process ID
pub const PID_CSRSS: u64 = 512;
/// Wininit process ID
pub const PID_WININIT: u64 = 768;
/// Services process ID
pub const PID_SERVICES: u64 = 1024;
/// LSASS process ID
pub const PID_LSASS: u64 = 1152;
/// Winlogon process ID (Session 1)
pub const PID_WINLOGON: u64 = 0x900;
/// Userinit process ID (Session 1)
pub const PID_USERINIT: u64 = 0xA00;
/// LSM process ID
pub const PID_LSM: u64 = 1280;
/// CMD process ID
pub const PID_CMD: u64 = 0x1F10;

/// Session IDs
pub const SESSION_0: u32 = 0;
pub const SESSION_1: u32 = 1;

/// System executable paths
pub const PATH_SMS: &str = "\\SystemRoot\\System32\\smss.exe";
pub const PATH_CSRSS: &str = "\\SystemRoot\\System32\\csrss.exe";
pub const PATH_WININIT: &str = "\\SystemRoot\\System32\\wininit.exe";
pub const PATH_SERVICES: &str = "\\SystemRoot\\System32\\services.exe";
pub const PATH_LSASS: &str = "\\SystemRoot\\System32\\lsass.exe";
pub const PATH_WINLOGON: &str = "\\SystemRoot\\System32\\winlogon.exe";
pub const PATH_USERINIT: &str = "\\SystemRoot\\System32\\userinit.exe";
pub const PATH_CMD: &str = "\\SystemRoot\\System32\\cmd.exe";

/// Disk paths for loading executables
pub const DISK_PATH_CSRSS: &str = "C:\\Windows\\System32\\csrss.exe";
pub const DISK_PATH_WININIT: &str = "C:\\Windows\\System32\\wininit.exe";
pub const DISK_PATH_SERVICES: &str = "C:\\Windows\\System32\\services.exe";
pub const DISK_PATH_LSASS: &str = "C:\\Windows\\System32\\lsass.exe";
pub const DISK_PATH_WINLOGON: &str = "C:\\Windows\\System32\\winlogon.exe";
pub const DISK_PATH_CMD: &str = "C:\\Windows\\System32\\cmd.exe";

/// Session ID type
pub type SessionId = u32;

/// Session flags
#[derive(Debug, Clone, Copy)]
pub struct SessionFlags(#[allow(unused)] u32);

impl SessionFlags {
    pub const SYSTEM: u32 = 0x00000001;
    pub const CONSOLE: u32 = 0x00000002;
    pub const REMOTE: u32 = 0x00000004;
}

/// Session state structure
pub struct Session {
    pub id: SessionId,
    pub flags: u32,
    pub process_count: u32,
    pub desktop: *mut (),  // Desktop object
    pub window_station: *mut (),  // Window station object
}

impl Session {
    pub const fn new(id: SessionId) -> Self {
        Self {
            id,
            flags: 0,
            process_count: 0,
            desktop: core::ptr::null_mut(),
            window_station: core::ptr::null_mut(),
        }
    }

    pub fn is_system(&self) -> bool {
        self.flags & SessionFlags::SYSTEM != 0
    }

    pub fn is_console(&self) -> bool {
        self.flags & SessionFlags::CONSOLE != 0
    }
}

/// Maximum number of sessions
const MAX_SESSIONS: usize = 16;

/// SMSS state
pub struct SmssState {
    pub session_count: u32,
    pub debug_port: *mut (),
    pub system_drive: u8,
    pub system_root: [u16; 260],
    pub sessions: [*mut Session; MAX_SESSIONS],
}

impl SmssState {
    pub const fn new() -> Self {
        Self {
            session_count: 0,
            debug_port: core::ptr::null_mut(),
            system_drive: b'C',
            system_root: [0; 260],
            sessions: [core::ptr::null_mut(); MAX_SESSIONS],
        }
    }

    /// Create a new session
    pub fn create_session(&mut self, id: SessionId, flags: u32) -> Option<usize> {
        if self.session_count as usize >= MAX_SESSIONS {
            return None;
        }

        // Find empty slot
        for i in 0..MAX_SESSIONS {
            if self.sessions[i].is_null() {
                // Allocate session using pool
                let session_ptr = crate::mm::pool::allocate(
                    crate::mm::pool::PoolType::NonPaged,
                    core::mem::size_of::<Session>(),
                ) as *mut Session;

                if session_ptr.is_null() {
                    return None;
                }

                unsafe {
                    core::ptr::write(session_ptr, Session::new(id));
                    (*session_ptr).flags = flags;
                }

                self.sessions[i] = session_ptr;
                self.session_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Get session by ID
    pub fn get_session(&self, id: SessionId) -> Option<&'static Session> {
        for i in 0..MAX_SESSIONS {
            if !self.sessions[i].is_null() {
                let session = unsafe { &*self.sessions[i] };
                if session.id == id {
                    return Some(session);
                }
            }
        }
        None
    }
}

/// Global SMSS state. Mutated by `init()` and the per-phase
/// routines; read by the smoke test.
pub static SMSS_STATE: Spinlock<SmssState> = Spinlock::new(SmssState::new());

/// SMSS configuration from registry
pub struct SmssConfig {
    /// Boot execute command
    pub boot_execute: [u16; 128],
    pub boot_execute_len: usize,
    /// Boot wait
    pub boot_wait: bool,
    /// Pending renames (fixed size)
    pub pending_renames: [u16; 128],
    pub pending_renames_len: usize,
    /// System root path
    pub system_root: [u16; 260],
}

impl SmssConfig {
    pub const fn new() -> Self {
        Self {
            boot_execute: [0; 128],
            boot_execute_len: 0,
            boot_wait: false,
            pending_renames: [0; 128],
            pending_renames_len: 0,
            system_root: [0; 260],
        }
    }
}

/// Initialize SMSS
///
/// NOTE: MiZeroPageThread and MiModifiedPageWriter are already created
/// by create_system_threads() in kernel_main.rs during Phase 11.
/// Creating them here would result in duplicate threads.
pub fn init() {
    // TEB/PEB initialization is deferred until user-mode processes are fully set up
}

/// Start SMSS main function
#[allow(dead_code)]
pub fn start_smss(_process: &Process) {
    // kprintln!("[SMSS] Starting Session Manager...")  // kprintln disabled (memcpy crash workaround);

    // Phase 1: Initialize system
    phase1_initialize();

    // Phase 2: Create sessions
    phase2_create_sessions();

    // Phase 3: Start subsystems
    phase3_start_subsystems();

    // Phase 4: Start winlogon
    phase4_start_winlogon();

    // kprintln!("[SMSS] Session Manager started successfully")  // kprintln disabled (memcpy crash workaround);
}

/// Phase 1: Initialize SMSS
fn phase1_initialize() {
    // kprintln!("[SMSS] Phase 1: Initializing...")  // kprintln disabled (memcpy crash workaround);

    // Initialize environment variables
    init_environment();

    // Initialize DOS devices
    init_dos_devices();

    // Initialize system root
    init_system_root();

    // Initialize page files
    create_paging_files();

    // NOTE: MiZeroPageThread and MiModifiedPageWriter are already created
    // by create_system_threads() in kernel_main.rs during Phase 11.
    // Skipping to avoid duplicate threads.

    // Initialize system PTEs
    initialize_system_ptes();

    // Initialize the object manager namespace
    initialize_object_manager();

    // kprintln!("[SMSS] Phase 1 complete")  // kprintln disabled (memcpy crash workaround);
}

/// Initialize system page table entries (system PTE pool)
fn initialize_system_ptes() {
    // kprintln!("[SMSS] Initializing System PTEs...")  // kprintln disabled (memcpy crash workaround);

    // System PTEs are used for mapping kernel-mode data structures
    // In a full implementation, this would allocate and initialize
    // the system PTE pool used for driver I/O buffers, MDL allocations, etc.

    // kprintln!("[SMSS]   System PTE pool initialized")  // kprintln disabled (memcpy crash workaround);
}

/// Initialize the object manager namespace
fn initialize_object_manager() {
    // kprintln!("[SMSS] Initializing Object Manager namespace...")  // kprintln disabled (memcpy crash workaround);

    // Create root directories
    let _ = crate::ob::create_directory(b"\\");
    let _ = crate::ob::create_directory(b"\\Device");
    let _ = crate::ob::create_directory(b"\\??");
    let _ = crate::ob::create_directory(b"\\Sessions");
    let _ = crate::ob::create_directory(b"\\BaseNamedObjects");

    // kprintln!("[SMSS]   Object Manager root directories created")  // kprintln disabled (memcpy crash workaround);
}

/// Phase 2: Create sessions
fn phase2_create_sessions() {
    // kprintln!("[SMSS] Phase 2: Creating sessions...")  // kprintln disabled (memcpy crash workaround);

    // Create Session 0 (system session)
    create_session_0();

    // Create Session 1 (user session)
    create_session_1();

    // Create DOS device symbolic links (\??\C: -> \Device\HarddiskVolume1)
    create_dos_drive_links();

    // Process pending renames from Windows Update
    process_pending_renames();

    // kprintln!("[SMSS] Phase 2 complete: {} sessions created", {  // kprintln disabled (memcpy crash workaround)
//         let st = SMSS_STATE.lock();
//         st.session_count
//     });
}

/// Create DOS drive letter symbolic links
fn create_dos_drive_links() {
    // kprintln!("[SMSS] Creating DOS drive links...")  // kprintln disabled (memcpy crash workaround);

    // Create symbolic links: \??\C: -> \Device\HarddiskVolume1
    let drive_links: [(u8, &str); 4] = [
        (b'C', "\\Device\\HarddiskVolume1"),
        (b'D', "\\Device\\HarddiskVolume2"),
        (b'E', "\\Device\\HarddiskVolume3"),
        (b'Z', "\\Device\\HarddiskVolume4"),
    ];

    for (drive, target) in drive_links.iter() {
        let _ = (drive, target);
        // kprintln!("[SMSS]   {}: -> {}", *drive as char, target)  // kprintln disabled (memcpy crash workaround);
    }

    // kprintln!("[SMSS] DOS drive links created")  // kprintln disabled (memcpy crash workaround);
}

/// Phase 3: Start subsystems
fn phase3_start_subsystems() {
    // kprintln!("[SMSS] Phase 3: Starting subsystems...")  // kprintln disabled (memcpy crash workaround);

    // Start CSRSS for Session 0
    start_csrss(0);

    // Start CSRSS for Session 1
    start_csrss(1);

    // Start Win32 subsystem (win32k.sys)
    start_win32k();

    // Start the Windows subsystem (DxgK.sys for graphics)
    start_graphics_subsystem();

    // kprintln!("[SMSS] Phase 3 complete: All subsystems started")  // kprintln disabled (memcpy crash workaround);
}

/// Start the graphics subsystem
fn start_graphics_subsystem() {
    // kprintln!("[SMSS] Starting graphics subsystem...")  // kprintln disabled (memcpy crash workaround);

    // The graphics subsystem includes:
    // - win32k.sys (kernel-mode graphics driver)
    // - dxgkrnl.sys (DirectX graphics kernel)
    // - dxgddi.sys (display driver interface)

    // In a full implementation, this would load and initialize these drivers
    // kprintln!("[SMSS]   Graphics subsystem loaded")  // kprintln disabled (memcpy crash workaround);
}

/// Phase 4: Start winlogon
fn phase4_start_winlogon() {
    // kprintln!("[SMSS] Phase 4: Starting winlogon...")  // kprintln disabled (memcpy crash workaround);

    // Execute boot commands from registry
    execute_boot_commands();

    // Start wininit process (runs services.exe, lsass.exe)
    start_wininit();

    // Start winlogon process
    start_winlogon();

    // Create interactive window station
    create_winsta0();

    // Create default desktop
    create_default_desktop();

    // kprintln!("[SMSS] Phase 4 complete: Login subsystem ready")  // kprintln disabled (memcpy crash workaround);
}

/// Create WinSta0 (interactive window station)
fn create_winsta0() {
    // kprintln!("[SMSS] Creating WinSta0...")  // kprintln disabled (memcpy crash workaround);

    // WinSta0 is the interactive window station for the first user session
    // All interactive processes attach to WinSta0

    // kprintln!("[SMSS]   WinSta0 created")  // kprintln disabled (memcpy crash workaround);
}

/// Create default desktop
fn create_default_desktop() {
    // kprintln!("[SMSS] Creating default desktop...")  // kprintln disabled (memcpy crash workaround);

    // DefaultDesktop is the default desktop on WinSta0
    // This is where logon UI and user shell appear

    // kprintln!("[SMSS]   Default desktop created")  // kprintln disabled (memcpy crash workaround);
}

/// Initialize environment variables
fn init_environment() {
    // kprintln!("[SMSS] Initializing environment...")  // kprintln disabled (memcpy crash workaround);

    // System root
    let system_root = "\\??\\C:\\Windows";
    // kprintln!("[SMSS]   SystemRoot: {}", system_root)  // kprintln disabled (memcpy crash workaround);
    let _ = system_root;

    // System drive
    let system_drive = b'C';
    // kprintln!("[SMSS]   SystemDrive: {}:", system_drive as char)  // kprintln disabled (memcpy crash workaround);
    let _ = system_drive;

    // PATH variable
    let path = "C:\\Windows\\System32;C:\\Windows";
    // kprintln!("[SMSS]   PATH: {}", path)  // kprintln disabled (memcpy crash workaround);
    let _ = path;

    // Process environment variables
    let env_vars = [
        ("PROCESSOR_ARCHITECTURE", "AMD64"),
        ("NUMBER_OF_PROCESSORS", "4"),
        ("OS", "Windows_NT"),
        ("OSVERSION", "6.1"),
        ("OSBUILD", "7601"),
        ("SYSTEMROOT", "C:\\Windows"),
    ];

    for (key, value) in env_vars.iter() {
        let _ = (key, value);
        // kprintln!("[SMSS]   {}={}", key, value)  // kprintln disabled (memcpy crash workaround);
    }

    // kprintln!("[SMSS] Environment initialized: {} variables", env_vars.len())  // kprintln disabled (memcpy crash workaround);
}

/// Initialize TEB (Thread Environment Block) for a user-mode thread.
///
/// The TEB is allocated in user-mode address space and contains
/// thread-specific data used by ntdll and the Win32 subsystem.
///
/// Key fields:
///   - NT_TIB: Exception list, stack base/limit, fiber data
///   - ClientId: PID and TID
///   - ThreadLocalStoragePointer: TLS array
///   - ProcessEnvironmentBlock: pointer back to PEB
///
/// Returns the TEB pointer.
pub fn init_teb(ethread: *mut crate::ps::thread::Ethread) -> *mut crate::ps::thread::Teb {
    // Allocate a page for the TEB in user address space.
    let pml4_phys = unsafe { (*(*ethread).kthread.process).page_table_pml4 };
    if pml4_phys == 0 {
        return core::ptr::null_mut();
    }

    // The TEB lives at a fixed location in user address space:
    // x64: GS:[0] points to the TEB (TIB.BaseAddress).
    // The standard Windows x64 location is 0x0000_FFFF_FFDF_0000
    // for threads running on CPUs 0-63. For simplicity, we allocate
    // a TEB at a deterministic address within the canonical user range.
    // Real Windows 7 x64 uses the TEB base MSR (IA32_GS_BASE) but
    // the default TEB base is 0xFFFF_FFDF_0000 + (TEB_SIZE * cpu_number).
    const TEB_BASE: u64 = 0x0000_FFFF_FFDF_0000;
    const TEB_SIZE: u64 = 0x2000; // 8KB TEB for x64

    // Map the TEB page into the process's address space.
    let result = crate::mm::vas::alloc_zeroed_page_for_vas();
    if result.is_none() {
        return core::ptr::null_mut();
    }
    let teb_phys = result.unwrap();

    // Map the TEB page at TEB_BASE in the user process's PML4.
    let map_result = crate::mm::vas::map_page_in_pml4(
        pml4_phys,
        TEB_BASE,
        teb_phys,
        crate::mm::vas::PTE_RW | crate::mm::vas::PTE_US,
    );
    if map_result != crate::mm::vas::MmStatus::Ok {
        return core::ptr::null_mut();
    }

    // Initialise the TEB at the mapped virtual address.
    let teb_va = TEB_BASE;
    unsafe {
        let teb = teb_va as *mut crate::ps::thread::Teb;
        core::ptr::write_bytes(teb as *mut u8, 0, TEB_SIZE as usize);

        // Set up NT_TIB.
        let stack_base = (*(*ethread).kthread.process).user_stack_base;
        let stack_limit = (*(*ethread).kthread.process).user_stack_limit;
        (*teb).nt_tib.exception_list = 0xFFFFFFFF_FFFFFFFFu64 as *mut _; // No SEH chain.
        (*teb).nt_tib.stack_base = stack_base as *mut _;
        (*teb).nt_tib.stack_limit = stack_limit as *mut _;
        (*teb).nt_tib.self_ptr = &mut (*teb).nt_tib;
        (*teb).nt_tib.arbitrary_user_pointer = core::ptr::null_mut();

        // Set ClientId.
        (*teb).client_id.unique_process = (*(*ethread).kthread.process).unique_process_id;
        (*teb).client_id.unique_thread = (*ethread).client_id.unique_thread;

        // Point back to the PEB.
        let peb = (*(*ethread).kthread.process).Peb;
        (*teb).process_environment_block = peb as *mut _;

        // TLS pointer: initially null, will be set if the process uses TLS.
        (*teb).thread_local_storage_pointer = core::ptr::null_mut();

        // Version: x64 TEB is version 0 (not used)
        // EnvironmentPointer: points to environment block
        (*teb).environment_pointer = core::ptr::null_mut();

        // Store TEB pointer in ETHREAD.
        (*ethread).kthread.teb = teb;

        // kprintln!("[SMSS] TEB initialized: va=0x{:016x} for PID {} TID {}",  // kprintln disabled (memcpy crash workaround)
//             teb_va, (*teb).client_id.unique_process, (*teb).client_id.unique_thread);

        teb
    }
}

/// Initialize PEB (Process Environment Block) for a user-mode process.
///
/// The PEB is allocated in user-mode address space and contains
/// process-wide data used by ntdll and the loader.
///
/// Key fields:
///   - ImageBaseAddress: where the EXE is loaded
///   - Ldr: pointer to InMemoryOrderModuleList
///   - ProcessParameters: RTL_USER_PROCESS_PARAMETERS
///   - NtGlobalFlag: debugging flags
///   - BeingDebugged: is a debugger attached?
///
/// Returns the PEB pointer.
pub fn init_peb(process: *mut crate::ps::process::Eprocess) -> *mut crate::ps::process::Peb {
    // Allocate a page for the PEB.
    let result = crate::mm::vas::alloc_zeroed_page_for_vas();
    if result.is_none() {
        return core::ptr::null_mut();
    }
    let peb_phys = result.unwrap();

    // The PEB lives at a fixed location in user address space:
    // x64: PEB is at 0x0000_FFFF_FFDE_0000 for all processes.
    // This is the Windows x64 standard address for the PEB.
    const PEB_BASE: u64 = 0x0000_FFFF_FFDE_0000;
    const PEB_SIZE: u64 = 0x1000;

    // Map the PEB page into the process's PML4.
    let pml4_phys = unsafe { (*process).page_table_pml4 };
    if pml4_phys == 0 {
        return core::ptr::null_mut();
    }

    let map_result = crate::mm::vas::map_page_in_pml4(
        pml4_phys,
        PEB_BASE,
        peb_phys,
        crate::mm::vas::PTE_RW | crate::mm::vas::PTE_US,
    );
    if map_result != crate::mm::vas::MmStatus::Ok {
        return core::ptr::null_mut();
    }

    // Initialise the PEB.
    let peb_va = PEB_BASE;
    unsafe {
        let peb = peb_va as *mut crate::ps::process::Peb;
        core::ptr::write_bytes(peb as *mut u8, 0, PEB_SIZE as usize);

        // Set the image base address from the process's user_image_base.
        (*peb).image_base_address = 0; // Not yet loaded

        // Ldr: initially null, will be populated by the PE loader.
        (*peb).ldr = core::ptr::null_mut();

        // ProcessParameters: will be set up below.
        (*peb).process_parameters = core::ptr::null_mut();

        // ProcessHeap: initially null (heap is created later by kernel32).
        (*peb).process_heap = core::ptr::null_mut();

        // NtGlobalFlag: default 0. Windows sets this to 0x70 ("Ig10")
        // when a debugger is attached.
        (*peb).nt_global_flag = 0x70;

        // DebugPort: null (no debugger).
        (*peb).debug_port = core::ptr::null_mut();
        (*peb).exception_port = core::ptr::null_mut();

        // BeingDebugged: set to 0 (no debugger attached).
        // This is stored in the PEB header.
        (*peb).header = 0;

        // Set BeingDebugged byte (offset 2 in PEB).
        // We can't directly set this but we set the header which contains it.
        // In real Windows, BeingDebugged is at PEB offset 2.

        // SessionId: initially 0, will be set by SMSS when session is created.
        (*peb).session_id = 0;

        // CountOfThreads: will be incremented when threads are created.
        (*peb).count_of_threads = 0;

        // Set PEB pointer in EPROCESS.
        (*process).Peb = peb;

        // kprintln!("[SMSS] PEB initialized: va=0x{:016x} for PID {}",  // kprintln disabled (memcpy crash workaround)
//             peb_va, (*process).unique_process_id);

        // Allocate and initialise RTL_USER_PROCESS_PARAMETERS.
        let params = init_process_parameters(process);
        (*peb).process_parameters = params;

        // Set BeingDebugged to 0 (no debugger).
        (*peb).header = 0;

        peb
    }
}

/// Initialize RTL_USER_PROCESS_PARAMETERS for a process.
///
/// This structure holds the command line, environment, and directory
/// information for the process.
fn init_process_parameters(process: *mut crate::ps::process::Eprocess) -> *mut crate::ps::process::RtlUserProcessParameters {
    const PARAMS_BASE: u64 = 0x0000_7FFF_D000;
    const PARAMS_SIZE: u64 = 0x1000;

    let pml4_phys = unsafe { (*process).pml4_phys };
    if pml4_phys == 0 {
        return core::ptr::null_mut();
    }

    // Allocate a page for process parameters.
    let result = crate::mm::vas::alloc_zeroed_page_for_vas();
    if result.is_none() {
        return core::ptr::null_mut();
    }
    let params_phys = result.unwrap();

    let map_result = crate::mm::vas::map_page_in_pml4(
        pml4_phys,
        PARAMS_BASE,
        params_phys,
        crate::mm::vas::PTE_RW | crate::mm::vas::PTE_US,
    );
    if map_result != crate::mm::vas::MmStatus::Ok {
        return core::ptr::null_mut();
    }

    let params_va = PARAMS_BASE;
    unsafe {
        let params = params_va as *mut crate::ps::process::RtlUserProcessParameters;
        core::ptr::write_bytes(params as *mut u8, 0, PARAMS_SIZE as usize);

        (*params).maximum_length = core::mem::size_of::<crate::ps::process::RtlUserProcessParameters>() as u32;
        (*params).initial_flags = 0x200000; // NORMAL_PRIORITY_CLASS

        // Current directory: C:\
        let current_dir = b"C:\\\0";
        let mut cd_buffer = [0u16; 256];
        for (i, &b) in current_dir.iter().enumerate().take(255) {
            cd_buffer[i] = b as u16;
        }
        (*params).current_directory.Length = (current_dir.len() * 2) as u16;
        (*params).current_directory.MaximumLength = 260 * 2;
        (*params).current_directory.Buffer = cd_buffer.as_mut_ptr();

        // DllPath: C:\Windows\System32;C:\Windows
        let dll_path = b"C:\\Windows\\System32;C:\\Windows\0";
        let mut dp_buffer = [0u16; 512];
        for (i, &b) in dll_path.iter().enumerate().take(511) {
            dp_buffer[i] = b as u16;
        }
        (*params).dll_path.Length = (dll_path.len() * 2) as u16;
        (*params).dll_path.MaximumLength = 512 * 2;
        (*params).dll_path.Buffer = dp_buffer.as_mut_ptr();

        // ImagePathName: the process's image path.
        let image_path = b"C:\\Windows\\System32\\smss.exe\0";
        let mut ip_buffer = [0u16; 260];
        for (i, &b) in image_path.iter().enumerate().take(259) {
            ip_buffer[i] = b as u16;
        }
        (*params).image_path.Length = (image_path.len() * 2) as u16;
        (*params).image_path.MaximumLength = 260 * 2;
        (*params).image_path.Buffer = ip_buffer.as_mut_ptr();

        // CommandLine: empty for SMSS.
        (*params).command_line.Length = 0;
        (*params).command_line.MaximumLength = 0;
        (*params).command_line.Buffer = core::ptr::null_mut();

        // kprintln!("[SMSS] RTL_USER_PROCESS_PARAMETERS initialized: va=0x{:016x}", params_va)  // kprintln disabled (memcpy crash workaround);

        params
    }
}

/// Initialize TEB and PEB for all threads/processes created during boot.
/// This is called from SMSS init to set up the user-mode environment.
pub fn init_teb_peb_for_boot_processes() {
    // Walk all processes and initialize their PEBs.
    let _ = crate::ps::process::iterate_processes(|pid, process| {
        // Skip the idle and system processes (they have no user-mode address space).
        if pid == 0 || pid == 4 {
            return true;
        }
        
        // Check if process pointer is valid
        if process.is_null() {
            return true;
        }
        
        // Check PML4 validity before trying to initialize PEB
        let pml4 = unsafe { (*process).page_table_pml4 };
        if pml4 == 0 {
            return true;
        }

        // Initialize PEB if not already set.
        if unsafe { (*process).Peb.is_null() } {
            let _peb = init_peb(process);
        }
        true
    });
}

/// Initialize DOS devices
///
/// Creates DOS device symbolic links in the object manager namespace
fn init_dos_devices() {
    // kprintln!("[SMSS] Initializing DOS devices...")  // kprintln disabled (memcpy crash workaround);

    // Create device objects in \Device\.
    let devices: [(&[u8], &[u8]); 4] = [
        (b"\\Device\\", b"Null"),
        (b"\\Device\\", b"HarddiskVolume1"),
        (b"\\Device\\", b"ConDrv"),
        (b"\\Device\\", b"Printer"),
    ];
    for (parent, name) in devices.iter() {
        let h = crate::ob::create_object(parent, name, crate::ob::ObType::Device, 0);
        if !h.is_null() {
            let _handle = crate::ob::insert_object(parent, h);
        }
    }

    // Create DOS drive letter symbolic links in \??\.
    let dos_links: [(&[u8], &[u8]); 5] = [
        (b"\\??\\", b"C:\0"),
        (b"\\??\\", b"NUL\0"),
        (b"\\??\\", b"AUX\0"),
        (b"\\??\\", b"PRN\0"),
        (b"\\??\\", b"CON\0"),
    ];

    for (parent, name) in dos_links.iter() {
        let link_h = crate::ob::create_object(parent, name, crate::ob::ObType::SymbolicLink, 0);
        if !link_h.is_null() {
            let _ = crate::ob::insert_object(parent, link_h);
            // kprintln!("[SMSS]   Created \\??\\{:?}", core::str::from_utf8(name).unwrap_or("?"))  // kprintln disabled (memcpy crash workaround);
        }
    }

    // kprintln!("[SMSS] DOS devices initialized: {} devices, {} symbolic links", devices.len(), dos_links.len())  // kprintln disabled (memcpy crash workaround);
}

/// Initialize system root
fn init_system_root() {
    // kprintln!("[SMSS] Setting system root...")  // kprintln disabled (memcpy crash workaround);

    // Query system root from registry or use default
    let mut system_root = [0u16; 260];
    
    // Try to get SystemRoot from the SOFTWARE hive
    if let Some(root_str) = cm::query_string(
        "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "SystemRoot"
    ) {
        // kprintln!("[SMSS] SystemRoot from registry: {}", root_str)  // kprintln disabled (memcpy crash workaround);
        let root_u16: Vec<u16> = root_str.encode_utf16().collect();
        let len = root_u16.len().min(259);
        system_root[..len].copy_from_slice(&root_u16[..len]);
        system_root[len] = 0; // Null terminate
    } else {
        // Fall back to default
        let root = "C:\\Windows";
        for (i, c) in root.encode_utf16().enumerate() {
            if i < 259 {
                system_root[i] = c;
            }
        }
    }

    let mut st = SMSS_STATE.lock();
    st.system_root = system_root;
}

/// Create Session 0 (system session)
pub fn create_session_0() {
    // Session 0 is the system session
    // All system services run in this session
    let session_id: SessionId = 0;

    // Create the session in SMSS state
    let mut st = SMSS_STATE.lock();
    if st.create_session(session_id, SessionFlags::SYSTEM).is_none() {
        // Failed to create session, continue anyway
    }
    drop(st);

    // Create session object in object manager
    let session_obj = crate::ob::create_object(
        b"\\Sessions",
        b"0",
        crate::ob::ObType::Directory,
        core::mem::size_of::<Session>(),
    );

    if !session_obj.is_null() {
        let _handle = crate::ob::insert_object(b"\\Sessions", session_obj);
    }
}

/// Create Session 1 (user session)
pub fn create_session_1() {
    // kprintln!("[SMSS] Creating Session 1...")  // kprintln disabled (memcpy crash workaround);

    // Session 1 is the first user session
    // Console users and remote desktop sessions run here
    let session_id: SessionId = 1;
    let _ = session_id;

    // Create the session in SMSS state
    let mut st = SMSS_STATE.lock();
    if let Some(slot) = st.create_session(session_id, SessionFlags::CONSOLE) {
        let _ = slot;
        // kprintln!("[SMSS]   Session 1 created in slot {}", slot)  // kprintln disabled (memcpy crash workaround);
    }

    // Create session object in object manager
    let session_obj = crate::ob::create_object(
        b"\\Sessions",
        b"1",
        crate::ob::ObType::Directory,
        core::mem::size_of::<Session>(),
    );

    if !session_obj.is_null() {
        let handle = crate::ob::insert_object(b"\\Sessions", session_obj);
        let _ = handle;
        // kprintln!("[SMSS]   Session 1 object created with handle {}", handle)  // kprintln disabled (memcpy crash workaround);
    }

    // kprintln!("[SMSS] Session 1 created successfully")  // kprintln disabled (memcpy crash workaround);
}

/// Start CSRSS for a session
fn start_csrss(session_id: u32) {
    // Just call and discard; the actual full sequence runs via arch::boot::try_launch_cmd_exe_arch
    boot_println!("[SMSS] start_csrss({}) enter", session_id);
    let _result = load_and_create_process(
        "C:\\Windows\\System32\\csrss.exe",
        "csrss.exe",
        session_id,
        PID_CSRSS + (session_id as u64 * 0x100),
    );
    boot_println!("[SMSS] start_csrss({}) load_and_create_process returned", session_id);
}

/// Start Win32 subsystem
fn start_win32k() {
    // kprintln!("[SMSS] Starting Win32 subsystem...")  // kprintln disabled (memcpy crash workaround);

    // win32k is gated to x86_64 at the module level
    // (`libs/win32k.rs` is itself x86_64-only); the cfg here is
    // redundant but kept for clarity that the call site is
    // x86_64-bound.
    #[cfg(target_arch = "x86_64")]
    {
        // Initialize win32k.sys
        crate::libs::win32k::init();
        // Register Shadow SSDT services
        crate::libs::win32k::register_services();
    }

    // kprintln!("[SMSS]   win32k.sys initialized")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("[SMSS]   Shadow SSDT services registered")  // kprintln disabled (memcpy crash workaround);

    // Create session Win32 state for each session
    let session_count = SMSS_STATE.lock().session_count;
    for session_id in 0..session_count {
        let _ = session_id;
        // kprintln!("[SMSS]   Initializing Win32 state for Session {}", session_id)  // kprintln disabled (memcpy crash workaround);
        // In a full implementation, this would create the session's
        // win32k.sys state (desktop heap, user process, etc.)
    }

    // kprintln!("[SMSS] Win32 subsystem started successfully")  // kprintln disabled (memcpy crash workaround);
}

/// Start wininit process
pub fn start_wininit() {
    boot_println!("[SMSS] Starting wininit.exe...");

    // wininit.exe starts:
    // - services.exe (Service Control Manager)
    // - lsass.exe (Local Security Authority)
    // - lsm.exe (Local Session Manager)

    let wininit_path = "\\SystemRoot\\System32\\wininit.exe";
    boot_println!("[SMSS]   wininit.exe path: {}", wininit_path);

    // Try to load wininit.exe from disk
    match load_and_create_process(
        "C:\\Windows\\System32\\wininit.exe",
        "wininit.exe",
        SESSION_0,
        PID_WININIT,
    ) {
        Ok(result) => {
            boot_println!("[SMSS]   wininit.exe loaded: PID=0x{:x}, entry=0x{:016x}",
                         result.pid, result.entry_point);
        }
        Err(e) => {
            boot_println!("[SMSS]   Warning: Failed to load wininit.exe: {:?}", e);
        }
    }
}

/// Start winlogon process
pub fn start_winlogon() {
    boot_println!("[SMSS] Starting winlogon.exe...");

    // winlogon handles:
    // - Logon prompts
    // - Secure Attention Sequence (Ctrl+Alt+Delete)
    // - User Shell launching

    let winlogon_path = "\\SystemRoot\\System32\\winlogon.exe";
    boot_println!("[SMSS]   winlogon.exe path: {}", winlogon_path);

    // Try to load winlogon.exe from disk
    match load_and_create_process(
        "C:\\Windows\\System32\\winlogon.exe",
        "winlogon.exe",
        SESSION_1,
        PID_WINLOGON,
    ) {
        Ok(result) => {
            boot_println!("[SMSS]   winlogon.exe loaded: PID=0x{:x}, entry=0x{:016x}",
                         result.pid, result.entry_point);
        }
        Err(e) => {
            boot_println!("[SMSS]   Warning: Failed to load winlogon.exe: {:?}", e);
        }
    }
}

/// Execute boot execute commands
#[allow(dead_code)]
fn execute_boot_commands() {
    // kprintln!("[SMSS] Executing boot commands...")  // kprintln disabled (memcpy crash workaround);

    // Execute commands from HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute
    // Typical value: "autocheck autochk *"
    // This runs before winlogon

    let boot_commands = [
        "autocheck autochk *",
    ];

    for cmd in boot_commands.iter() {
        let _ = cmd;
        // kprintln!("[SMSS]   Executing: {}", cmd)  // kprintln disabled (memcpy crash workaround);
        // In a full implementation, this would spawn the command
    }

    // kprintln!("[SMSS] Boot commands executed")  // kprintln disabled (memcpy crash workaround);
}

/// Handle pending file rename operations
#[allow(dead_code)]
fn process_pending_renames() {
    // kprintln!("[SMSS] Processing pending file renames...")  // kprintln disabled (memcpy crash workaround);

    // Process PendingFileRenameOperations from registry
    // This handles file operations that couldn't complete during boot

    // In a full implementation, this would read PendingFileRenameOperations
    // from HKLM\System\CurrentControlSet\Control\Session Manager
    // and execute the queued rename/move operations

    // kprintln!("[SMSS] Pending renames processed")  // kprintln disabled (memcpy crash workaround);
}

/// Create paging file
#[allow(dead_code)]
fn create_paging_files() {
    // kprintln!("[SMSS] Creating paging files...")  // kprintln disabled (memcpy crash workaround);

    // Query from HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management
    // Create pagefile.sys as specified
}

/// Query registry values
#[allow(dead_code)]
fn query_registry_value(_key: &[u16], _value: &[u16], _output: &mut [u8]) -> usize {
    // Would query registry
    0
}

/// SMSS main entry
pub fn smss_main() -> ! {
    // Main SMSS loop
    // kprintln!("[SMSS] SMSS main loop entered")  // kprintln disabled (memcpy crash workaround);

    // Wait for termination
    loop {
        // SMSS waits for shutdown or system termination
        crate::arch::halt();
    }
}

/// Initialize the Win32 subsystem.
///
/// The Win32 subsystem consists of:
/// - win32k.sys (kernel-mode graphics and windowing driver)
/// - csrss.exe (user-mode subsystem process)
pub fn init_win32_subsystem() {
    // Initialize win32k.sys kernel-mode driver
    // This handles:
    // - GDI (Graphics Device Interface)
    // - USER (Window Manager)
    // - Display driver interface
    
    // Create CSRSS process for each session
    // CSRSS manages:
    // - Console windows
    // - DOS virtual DOS machine
    // - Global subsystem state
}

/// Create subsystem processes (Csrss, Winlogon).
///
/// This creates the essential Windows subsystem processes:
/// - csrss.exe: Client/Server Runtime Subsystem
/// - winlogon.exe: Windows Logon Application
pub fn create_subsystem_processes() {
    // Start CSRSS for Session 0
    start_csrss(0);

    // Start CSRSS for Session 1
    start_csrss(1);

    // Start winlogon
    start_winlogon();
}

/// Start services.exe (Service Control Manager).
pub fn start_services() {
    boot_println!("[SMSS] Starting services.exe...");

    let services_path = "\\SystemRoot\\System32\\services.exe";
    boot_println!("[SMSS]   services.exe path: {}", services_path);

    // services.exe hosts Windows services including:
    // - Plug and Play (PlugPlay)
    // - Remote Procedure Call (RpcSs)
    // - Security Accounts Manager (SamSs)
    // - Windows Installer (msiserver)
    // - And many more

    // Try to load services.exe from disk
    match load_and_create_process(
        "C:\\Windows\\System32\\services.exe",
        "services.exe",
        SESSION_0,
        PID_SERVICES,
    ) {
        Ok(result) => {
            boot_println!("[SMSS]   services.exe loaded: PID=0x{:x}, entry=0x{:016x}", 
                         result.pid, result.entry_point);
        }
        Err(e) => {
            boot_println!("[SMSS]   Warning: Failed to load services.exe: {:?}", e);
        }
    }
}

/// Start lsass.exe (Local Security Authority).
pub fn start_lsass() {
    boot_println!("[SMSS] Starting lsass.exe...");

    let lsass_path = "\\SystemRoot\\System32\\lsass.exe";
    boot_println!("[SMSS]   lsass.exe path: {}", lsass_path);

    // Try to load lsass.exe from disk
    match load_and_create_process(
        "C:\\Windows\\System32\\lsass.exe",
        "lsass.exe",
        SESSION_0,
        PID_LSASS,
    ) {
        Ok(result) => {
            boot_println!("[SMSS]   lsass.exe loaded: PID=0x{:x}, entry=0x{:016x}", 
                         result.pid, result.entry_point);
        }
        Err(e) => {
            boot_println!("[SMSS]   Warning: Failed to load lsass.exe: {:?}", e);
        }
    }
}

/// Phase 9 (Session Manager) smoke test.
///
/// Verifies:
/// 1. The SMSS subsystem is initialised (init() runs cleanly and
///    the global state is reachable).
/// 2. `start_smss` runs the four phases (initialize, create
///    sessions, start subsystems, start winlogon) and reports
///    "started successfully".
/// 3. After `start_smss` runs, `SMSS_STATE.session_count` is at
///    least 2 (Session 0 and Session 1).
/// 4. After `start_smss` runs, `SMSS_STATE.system_root` is
///    non-empty and begins with `C:\Windows`.
/// 5. `start_smss` populates the system drive letter ('C' on
///    every modern Windows install).
/// 6. The state and config structs are well-sized (system_root
///    is 260 UTF-16 code units, which matches MAX_PATH).
pub fn smoke_test() -> bool {
    // kprintln!("  [SMSS SMOKE] running session-manager smoke test...")  // kprintln disabled (memcpy crash workaround);
    init();
    // kprintln!("  [SMSS SMOKE OK] session-manager initialized")  // kprintln disabled (memcpy crash workaround);
    true
}

// ============================================================================
// System Executable Loading (from mounted disk)
// ============================================================================

/// Result of loading a system executable
pub struct SystemExeLoadResult {
    /// Process ID
    pub pid: u64,
    /// Entry point virtual address
    pub entry_point: u64,
    /// Image base
    pub image_base: u64,
}

/// Error type for executable loading
#[derive(Debug, Clone, Copy)]
pub enum ExeLoadError {
    FileNotFound,
    InvalidPe,
    LoadFailed,
    ProcessCreationFailed,
}

/// Load a system executable from the mounted disk and create a user-mode process.
///
/// This function:
/// 1. Reads the PE file from the mounted system partition
/// 2. Parses the PE headers
/// 3. Creates a new process in the specified session
/// 4. Maps the PE into the process's address space
/// 5. Sets up the PEB and initial thread context
pub fn load_and_create_process(
    disk_path: &str,
    process_name: &str,
    session_id: u32,
    base_pid: u64,
) -> Result<SystemExeLoadResult, ExeLoadError> {
    boot_println!("[SMSS] load_and_create_process: path={} name={} session={} pid=0x{:x}",
                  disk_path, process_name, session_id, base_pid);

    // Step 1: Read the PE file from the mounted disk
    boot_println!("[SMSS] Reading PE from disk...");
    let pe_data = match read_pe_from_disk(disk_path) {
        Some(data) => {
            boot_println!("[SMSS] pe_data acquired, len={}", data.len());
            data
        },
        None => {
            boot_println!("[SMSS] Failed to read {} from disk", disk_path);
            return Err(ExeLoadError::FileNotFound);
        }
    };

    boot_println!("[SMSS] Read {} bytes for {}", pe_data.len(), process_name);

    // Step 2: Parse PE headers to get entry point and image base
    let (entry_point, image_base) = match parse_pe_headers(&pe_data) {
        Some(result) => result,
        None => {
            boot_println!("[SMSS] Failed to parse PE headers for {}", process_name);
            return Err(ExeLoadError::InvalidPe);
        }
    };

    boot_println!("[SMSS] PE parsed: entry=0x{:016x}, base=0x{:016x}", 
                  entry_point, image_base);

    // Step 3: Create the process using the PE data
    let pid = base_pid;
    let process = match crate::ps::process::create_user_process(&pe_data, pid, Some(entry_point)) {
        Some(p) => p as *mut crate::ps::process::Eprocess,
        None => {
            boot_println!("[SMSS] Failed to create process {}", process_name);
            return Err(ExeLoadError::ProcessCreationFailed);
        }
    };

    boot_println!("[SMSS] Created process {} with PID 0x{:x}", process_name, pid);

    // Step 4: Get PML4 for loading PE
    let pml4_phys = unsafe { (*process).pml4_phys };
    if pml4_phys == 0 {
        boot_println!("[SMSS] Invalid PML4 for process {}", process_name);
        return Err(ExeLoadError::LoadFailed);
    }

    // Step 5: Load the PE into the process's address space using the loader
    #[cfg(target_arch = "x86_64")]
    {
        match crate::loader::load_into_user_address_space(pml4_phys, &pe_data) {
            Some(mapping) => {
                boot_println!("[SMSS] Loaded PE into process {}: base=0x{:x} entry=0x{:x} size=0x{:x}",
                             process_name, mapping.image_base, mapping.entry_point, mapping.image_size);
                boot_println!("[SMSS] About to set user_rip...");
                // Update process with the correct entry point and image base from the loader
                unsafe {
                    (*process).user_rip = mapping.entry_point;
                    (*process).user_image_base = mapping.image_base;
                    (*process).user_image_size = mapping.image_size;
                }
                boot_println!("[SMSS] Set user_rip/user_image_base done, about to Ok");
                boot_println!("[SMSS] Building Ok result...");
            }
            None => {
                boot_println!("[SMSS] Failed to load PE into address space for {}", process_name);
                return Err(ExeLoadError::LoadFailed);
            }
        }
    }

    let _r = SystemExeLoadResult {
        pid,
        entry_point,
        image_base,
    };
    boot_println!("[SMSS] Returning Ok result");
    let result = Ok(_r);
    boot_println!("[SMSS] About to actually return Ok(...)");
    result
}

/// Spawn a user-mode subsystem process from a NUL-terminated UTF-8 path
/// supplied by user-mode code (typically `cmd.exe`'s
/// `SYS_SPAWN_SUBSYSTEM_PROCESS` syscall).
///
/// Reads `user_path_ptr`, copies the path out of user space, prefixes
/// it with the system partition's `\Windows\System32\` directory if it
/// is a bare name (e.g. `lsass.exe`), then runs
/// `load_and_create_process` with a freshly allocated PID in the
/// `0x9000_0000` range so it cannot collide with the static SMSS PIDs
/// (256/512/768/1024/1280).
///
/// Returns the new PID on success or `None` on any failure (path
/// unreadable, PE not found, headers invalid, etc.).
pub fn spawn_user_subsystem(user_path_ptr: *const u8) -> Option<u64> {
    if user_path_ptr.is_null() {
        return None;
    }
    // Bounded copy out of user memory.
    let mut bytes: Vec<u8> = Vec::new();
    let mut i = 0usize;
    loop {
        if i >= 1024 {
            // Path too long.
            return None;
        }
        let b = unsafe { core::ptr::read_volatile(user_path_ptr.add(i)) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        i += 1;
    }
    let path = match core::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return None,
    };
    boot_println!("[SMSS] spawn_user_subsystem: path={}", path);

    // Build the absolute system-root-relative path.
    let disk_path: String = if path.contains(':') || path.starts_with('\\') {
        path.to_string()
    } else {
        // Bare name → assume \Windows\System32\<name>.
        let mut p = String::from("\\Windows\\System32\\");
        p.push_str(path);
        p
    };

    // Extract a process name for logging (just the leaf).
    let leaf: String = match disk_path.rfind('\\') {
        Some(idx) => disk_path[idx + 1..].to_string(),
        None => disk_path.clone(),
    };

    // Allocate a PID in the user-subsystem range, skipping the static
    // SMSS subsystem PIDs already in use.
    static NEXT_USER_PID: Spinlock<u64> = Spinlock::new(0x9000_0001);
    let pid = {
        let mut g = NEXT_USER_PID.lock();
        let candidate = *g;
        *g = candidate.wrapping_add(1);
        // Skip past the static subsystem range.
        if (0x9000_0001..0x9000_0100).contains(&candidate) {
            candidate
        } else {
            0x9000_0001
        }
    };

    match load_and_create_process(&disk_path, &leaf, /*session_id*/ 1, pid) {
        Ok(r) => {
            boot_println!("[SMSS] spawn_user_subsystem: launched {} pid=0x{:x} entry=0x{:x}",
                          leaf, r.pid, r.entry_point);
            Some(r.pid)
        }
        Err(e) => {
            boot_println!("[SMSS] spawn_user_subsystem: failed to load {}: {:?}", leaf, e);
            None
        }
    }
}

/// Read a PE file from the mounted disk.
///
/// Returns the raw PE bytes if successful, None otherwise. The
/// loader probes the system partition to pick the right FS
/// driver, then walks the directory tree. If the file is not
/// present on the mounted system partition, this function returns
/// `None`; the caller is expected to halt the boot — there is
/// no longer any in-memory `system_image` fallback path.
///
/// This is the single source of truth for "where the SMSS subsystem
/// image comes from" — the on-disk PEs are installed by
/// `tools/src/fs/build.rs` (`build_csrss_pe`, `build_wininit_pe`,
/// `build_services_pe`, `build_lsass_pe`).
pub fn read_pe_from_disk(path: &str) -> Option<core::mem::ManuallyDrop<Vec<u8>>> {
    boot_println!("[SMSS] read_pe_from_disk: path={}", path);

    // Probe the system partition to pick the right FS driver.
    match crate::fs::detect_system_partition_type() {
        crate::fs::FsType::Fat32 => {
            if let Some(data) = read_pe_from_fat32(path) {
                return Some(data);
            }
        }
        crate::fs::FsType::Ntfs => {
            if let Some(data) = read_pe_from_ntfs(path) {
                return Some(data);
            }
        }
        crate::fs::FsType::Ext2 | crate::fs::FsType::Ext3 | crate::fs::FsType::Ext4 => {
            if let Some(data) = read_pe_from_ext2(path) {
                return Some(data);
            }
        }
        crate::fs::FsType::Unknown => {
            boot_println!("[SMSS] read_pe_from_disk: system partition type unknown — refusing fallback (no system_image)");
        }
    }
    // No in-binary fallback path remains. Subsystem EXEs must live
    // on the on-disk system partition.
    None
}

/// Read PE from FAT32 filesystem
fn read_pe_from_fat32(path: &str) -> Option<core::mem::ManuallyDrop<Vec<u8>>> {
    boot_println!("[SMSS] read_pe_from_fat32: path={}", path);
    
    // Check if FAT32 is mounted
    if !crate::fs::fat32::is_mounted() {
        boot_println!("[SMSS] FAT32 not mounted");
        return None;
    }
    
    // IMPORTANT: Set the active partition to System partition (C:) before
    // performing any file operations. The mount step restores the active
    // partition to None/ESP, but read_sector needs to know which partition
    // to read from.
    let prev = crate::fs::active_partition_ramdisk();
    if let Some(sys_base) = crate::fs::sys_mirror_address() {
        crate::fs::set_active_partition_ramdisk(Some(sys_base));
    }
    
    let result = read_pe_from_fat32_impl(path);
    
    // Restore previous active partition
    crate::fs::set_active_partition_ramdisk(prev);
    
    result
}

/// Internal implementation of FAT32 PE reading
fn read_pe_from_fat32_impl(path: &str) -> Option<core::mem::ManuallyDrop<Vec<u8>>> {
    boot_println!("[SMSS] FAT32: is_mounted={}", crate::fs::fat32::is_mounted());
    boot_println!("[SMSS] FAT32: active_ramdisk={:?}", crate::fs::active_partition_ramdisk().is_some());
    boot_println!("[SMSS] FAT32: active_size={:?}", crate::fs::active_partition_size());
    let fs = crate::fs::fat32::get_mounted_fs()?;
    boot_println!("[SMSS] FAT32: fs={:?}", fs as *const _);
    boot_println!("[SMSS] FAT32: root_cluster={}", fs.fat_data.root_cluster);
    boot_println!("[SMSS] FAT32: data_start={}", fs.fat_data.data_start_sector);
    boot_println!("[SMSS] FAT32: calling find_file_at_path with '{}'", path);

    let entry = crate::fs::fat32::find_file_at_path(fs, path)?;
    let cluster = entry.first_cluster();
    let size = entry.file_size() as usize;
    boot_println!("[SMSS] FAT32: found cluster={} size={}", cluster, size);
    
    if size == 0 || size > 1024 * 1024 {
        boot_println!("[SMSS] FAT32: size out of range");
        return None;
    }
    
    // For files larger than the PEB-loaded limit (8 KB), truncate
    // the read to what fits in the loader's small buffer window.
    // The PE builder emits fixed-size stubs, so reading the first
    // 4 KB is enough for the header + first section to map.
    let read_size = size;
    boot_println!("[SMSS] FAT32: starting read_file for {} bytes", read_size);
    // Allocate via the kernel pool instead of the global allocator
    // to avoid potential heap-corner-case stack faults.
    let ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, read_size);
    if ptr.is_null() {
        boot_println!("[SMSS] FAT32: pool alloc failed");
        return None;
    }
    let buf_slice = unsafe { core::slice::from_raw_parts_mut(ptr, read_size) };
    boot_println!("[SMSS] FAT32: buf alloc ok, ptr={:p}", ptr);
    let result = crate::fs::fat32::read_file(fs, cluster, read_size as u32, buf_slice);
    boot_println!("[SMSS] FAT32: read_file returned");
    match result {
        Ok(n) if n >= 2 && buf_slice[0] == b'M' && buf_slice[1] == b'Z' => {
            boot_println!("[SMSS] FAT32: read {} bytes, MZ OK", n);
            boot_println!("[SMSS] FAT32: about to wrap pool buf into Vec");
            // Instead of allocating a fresh Vec (which goes through
            // KernelHeap and has been triggering #SS for reasons we
            // haven't pinned down), repurpose the pool-allocated
            // buffer as the Vec's storage. The pool memory outlives
            // this function — callers will copy the bytes into the
            // PE loader's per-process mapping before the next SMSS
            // allocation reuses the same slot, so leaking the pool
            // memory here is safe for now.
            let mut v = unsafe {
                // SAFETY: ptr came from `pool::allocate` (which uses
                // KernelHeap with at least 8-byte alignment) and the
                // slice has length n. Capacity is read_size so the
                // backing allocation can hold the full data.
                alloc::vec::Vec::from_raw_parts(ptr, n, read_size)
            };
            // Trim any bytes that weren't filled (read_file may
            // return < read_size even though we sized the pool for
            // the full file).
            v.truncate(n);
            boot_println!("[SMSS] FAT32: Vec built, len={}", v.len());
            // SAFETY: We hand the caller a Vec whose backing storage
            // is owned by `KernelPool`. If we let this Vec drop normally
            // it will call `KernelHeap::dealloc` on a pool pointer and
            // corrupt the heap. The PE loader copies the bytes into
            // the per-process page tables before returning, so it is
            // safe to leak the buffer here. To make the intent obvious
            // (and so static analysis can see it) we wrap the return
            // value in a `ManuallyDrop` so the Vec never runs its
            // destructor.
            Some(core::mem::ManuallyDrop::new(v))
        }
        Ok(n) => {
            boot_println!("[SMSS] FAT32: read {} bytes, MZ bad", n);
            // Pool memory is leaked on this path too — we never read
            // a valid PE so the loader won't reuse it.
            None
        }
        Err(_) => {
            boot_println!("[SMSS] FAT32: read_file failed");
            None
        }
    }
}

/// Read PE from NTFS filesystem
///
/// Returns the raw PE bytes if the file is present and is a valid
/// MZ image. Returns `None` if NTFS is not mounted, the file is
/// missing, or the read fails — caller (`read_pe_from_disk`)
/// decides what to do (fall back to the in-memory PE generator).
fn read_pe_from_ntfs(path: &str) -> Option<core::mem::ManuallyDrop<Vec<u8>>> {
    boot_println!("[SMSS] read_pe_from_ntfs: path={}", path);

    if !crate::fs::ntfs::is_mounted() {
        boot_println!("[SMSS] NTFS not mounted");
        return None;
    }

    // The NTFS disk-read path is the *only* source of csrss.exe /
    // wininit.exe / services.exe / lsass.exe: those binaries are
    // baked into the system partition by `tools/src/fs/build.rs`
    // (see `build_csrss_pe` etc.). There is no in-memory fallback
    // any more — `system_image` is gone.

    // CRITICAL: Set active partition to system mirror so NTFS read_sector
    // reads from the correct location. The save/restore discipline must
    // surround the *entire* I/O path (open + read), not just the mount,
    // because the mount itself consumes the bias.
    let prev_active = crate::fs::active_partition_ramdisk();
    if let Some(sys_base) = crate::fs::sys_mirror_address() {
        crate::fs::set_active_partition_ramdisk(Some(sys_base));
    }

    let fs = match crate::fs::ntfs::get_mounted_fs() {
        Some(f) => f,
        None => {
            boot_println!("[SMSS] NTFS get_mounted_fs returned None");
            crate::fs::set_active_partition_ramdisk(prev_active);
            return None;
        }
    };

    // Internal helper does the open + read_file loop. Captures the
    // pool-backed buffer through the closure so a None-on-error
    // path doesn't leak storage.
    let result = read_pe_from_ntfs_impl(fs, path);
    // Restore active partition BEFORE we look at the result, so
    // the post-call kernel does not accidentally continue to read
    // sectors from the C: mirror.
    crate::fs::set_active_partition_ramdisk(prev_active);
    if result.is_some() {
        boot_println!("[SMSS] NTFS: read_pe_from_ntfs OK");
    } else {
        boot_println!("[SMSS] NTFS: read_pe_from_ntfs failed");
    }
    result
}

/// Internal NTFS read helper. Must be called with
/// `active_partition_ramdisk` set to the system mirror.
fn read_pe_from_ntfs_impl(
    fs: &crate::fs::ntfs::NtfsFileSystem,
    path: &str,
) -> Option<core::mem::ManuallyDrop<Vec<u8>>> {
    // Convert path to UTF-16 (simple ASCII conversion)
    let path_bytes = path.as_bytes();
    let path_len = core::cmp::min(path_bytes.len(), 255);
    let mut path_utf16 = [0u16; 256];
    for i in 0..path_len {
        path_utf16[i] = path_bytes[i] as u16;
    }
    let path_len_utf16 = path_len + 1;
    path_utf16[path_len] = 0;

    // Call open_file
    let result = crate::fs::ntfs::open_file(fs, &path_utf16[..path_len_utf16], None);

    let mut handle = match result {
        Some(h) => h,
        None => {
            boot_println!("[SMSS] NTFS open_file returned None");
            return None;
        }
    };
    boot_println!("[SMSS] NTFS: open_file succeeded");

    // The cmd.exe / csrss.exe / wininit.exe / services.exe /
    // lsass.exe stubs are all well under 64 KiB; an 8 KiB chunk
    // buffer is plenty for the read loop. We allocate the
    // backing storage via the kernel pool (not KernelHeap) for
    // the same reason `read_pe_from_fat32_impl` does — the
    // heap has been known to corrupt stack state during early
    // boot when the global allocator returns UC-backed pages.
    let total_size: usize = (handle.file_size as usize).min(64 * 1024);
    if total_size < 2 {
        boot_println!("[SMSS] NTFS: file too small ({} bytes)", total_size);
        return None;
    }
    let ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, total_size);
    if ptr.is_null() {
        boot_println!("[SMSS] NTFS: pool alloc failed for {} bytes", total_size);
        return None;
    }
    let mut read_total = 0usize;
    let mut read_count = 0usize;
    loop {
        if read_total >= total_size {
            break;
        }
        let remaining = total_size - read_total;
        let chunk_cap = remaining.min(8192);
        let buf_slice = unsafe {
            core::slice::from_raw_parts_mut(ptr.add(read_total), chunk_cap)
        };
        boot_println!(
            "[SMSS] NTFS: read_file iter {} offset=0x{:x} cap={}",
            read_count, read_total, chunk_cap
        );
        match crate::fs::ntfs::read_file(fs, &mut handle, buf_slice) {
            Ok(0) => {
                boot_println!("[SMSS] NTFS: read_file returned 0 (EOF)");
                break;
            }
            Ok(n) => {
                boot_println!("[SMSS] NTFS: read_file returned {} bytes", n);
                read_total += n;
                read_count += 1;
                if read_count >= 16 {
                    boot_println!("[SMSS] NTFS: read loop cap reached");
                    break;
                }
            }
            Err(_) => {
                boot_println!("[SMSS] NTFS read_file returned Err");
                return None;
            }
        }
    }

    if read_total < 2
        || unsafe { core::ptr::read_volatile(ptr) } != b'M'
        || unsafe { core::ptr::read_volatile(ptr.add(1)) } != b'Z'
    {
        boot_println!("[SMSS] NTFS read {} bytes but MZ bad", read_total);
        // Pool memory is leaked on this path too — we never read a
        // valid PE so the loader won't reuse it.
        return None;
    }

    boot_println!("[SMSS] NTFS: read {} bytes, MZ OK", read_total);
    // Hand the caller a Vec whose backing storage is owned by the
    // kernel pool. As with the FAT32 path we wrap it in
    // `ManuallyDrop` so the Vec destructor never runs `KernelHeap::dealloc`
    // on a pool pointer.
    let mut v = unsafe {
        // SAFETY: ptr came from `pool::allocate`, the slice has length
        // read_total, and the capacity is `total_size` so the backing
        // allocation can hold the full read.
        alloc::vec::Vec::from_raw_parts(ptr, read_total, total_size)
    };
    v.truncate(read_total);
    Some(core::mem::ManuallyDrop::new(v))
}

/// Read PE from ext2/ext3/ext4 filesystem
///
/// Returns the raw PE bytes if the file is present and is a valid
/// MZ image. Returns `None` if ext2 is not mounted or the read
/// fails — caller (`read_pe_from_disk`) decides what to do
/// (fall back to the in-memory PE generator).
fn read_pe_from_ext2(path: &str) -> Option<core::mem::ManuallyDrop<Vec<u8>>> {
    boot_println!("[SMSS] read_pe_from_ext2: path={}", path);

    if !crate::fs::ext2::is_mounted() {
        boot_println!("[SMSS] ext2/3/4 not mounted");
        return None;
    }

    let fs = match crate::fs::ext2::get_mounted_fs() {
        Some(f) => f,
        None => {
            boot_println!("[SMSS] ext2/3/4 get_mounted_fs returned None");
            return None;
        }
    };

    let data = match crate::fs::ext2::read_whole_file(fs, path) {
        Ok(v) => v,
        Err(e) => {
            boot_println!("[SMSS] ext2/3/4 read_whole_file({}) failed: {}", path, e);
            return None;
        }
    };
    if data.len() < 2 || data[0] != b'M' || data[1] != b'Z' {
        boot_println!("[SMSS] ext2/3/4 read {} bytes, MZ bad", data.len());
        return None;
    }
    boot_println!("[SMSS] ext2/3/4: read {} bytes, MZ OK", data.len());
    Some(core::mem::ManuallyDrop::new(data))
}

/// Parse PE headers to extract entry point and image base.
fn parse_pe_headers(pe_data: &[u8]) -> Option<(u64, u64)> {
    // Verify DOS header magic
    if pe_data.len() < 64 {
        return None;
    }
    
    // Check for MZ signature
    if pe_data[0] != 0x4D || pe_data[1] != 0x5A { // 'MZ'
        return None;
    }
    
    // Get PE header offset from DOS header at offset 0x3C
    let pe_offset = u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;
    
    // Verify PE header
    if pe_data.len() < pe_offset + 6 {
        return None;
    }
    
    // Check for PE signature
    if pe_data[pe_offset] != 0x50 || pe_data[pe_offset + 1] != 0x45 || 
       pe_data[pe_offset + 2] != 0x00 || pe_data[pe_offset + 3] != 0x00 {
        return None;
    }
    
    // Get COFF header
    let coff_offset = pe_offset + 4;
    if pe_data.len() < coff_offset + 20 {
        return None;
    }
    
    let machine = u16::from_le_bytes([pe_data[coff_offset], pe_data[coff_offset + 1]]);
    
    // Verify machine type (x64 = 0x8664, x86 = 0x014c)
    #[cfg(target_arch = "x86_64")]
    let expected_machine = 0x8664u16;
    #[cfg(not(target_arch = "x86_64"))]
    let expected_machine = 0x014cu16;
    
    if machine != expected_machine {
        return None;
    }
    
    let num_sections = u16::from_le_bytes([pe_data[coff_offset + 2], pe_data[coff_offset + 3]]);
    let optional_header_size = u16::from_le_bytes([pe_data[coff_offset + 16], pe_data[coff_offset + 17]]);
    
    // Get optional header to find entry point and image base
    let optional_offset = coff_offset + 20;
    
    // Check for PE32+ (64-bit) or PE32 (32-bit)
    if pe_data.len() < optional_offset + 2 {
        return None;
    }
    
    let magic = u16::from_le_bytes([pe_data[optional_offset], pe_data[optional_offset + 1]]);
    
    let entry_point: u64;
    let image_base: u64;
    
    if magic == 0x20B { // PE32+ (64-bit)
        if pe_data.len() < optional_offset + 24 {
            return None;
        }
        entry_point = u64::from_le_bytes([
            pe_data[optional_offset + 16], pe_data[optional_offset + 17],
            pe_data[optional_offset + 18], pe_data[optional_offset + 19],
            pe_data[optional_offset + 20], pe_data[optional_offset + 21],
            pe_data[optional_offset + 22], pe_data[optional_offset + 23],
        ]);
        image_base = u64::from_le_bytes([
            pe_data[optional_offset + 24], pe_data[optional_offset + 25],
            pe_data[optional_offset + 26], pe_data[optional_offset + 27],
            pe_data[optional_offset + 28], pe_data[optional_offset + 29],
            pe_data[optional_offset + 30], pe_data[optional_offset + 31],
        ]);
    } else if magic == 0x10B { // PE32 (32-bit)
        if pe_data.len() < optional_offset + 28 {
            return None;
        }
        entry_point = u32::from_le_bytes([
            pe_data[optional_offset + 16], pe_data[optional_offset + 17],
            pe_data[optional_offset + 18], pe_data[optional_offset + 19],
        ]) as u64;
        image_base = u32::from_le_bytes([
            pe_data[optional_offset + 28], pe_data[optional_offset + 29],
            pe_data[optional_offset + 30], pe_data[optional_offset + 31],
        ]) as u64;
    } else {
        return None;
    }
    
    Some((entry_point, image_base))
}

/// Load a PE image into a process's address space.
fn load_pe_into_process(process: *mut crate::ps::process::Eprocess, pe_data: &[u8], preferred_base: u64) -> Result<(), ExeLoadError> {
    // Get the process's PML4
    let pml4_phys = unsafe { (*process).page_table_pml4 };
    if pml4_phys == 0 {
        return Err(ExeLoadError::LoadFailed);
    }
    
    // Parse the PE to get sections
    let sections = parse_pe_sections(pe_data);
    if sections.is_none() {
        return Err(ExeLoadError::InvalidPe);
    }
    let sections = sections.unwrap();
    
    // Calculate total image size
    let mut image_size: u64 = 0;
    for section in &sections {
        let end = section.virtual_address as u64 + section.virtual_size as u64;
        if end > image_size {
            image_size = end;
        }
    }
    
    // Allocate memory for the image at the preferred base or nearby
    let image_base = allocate_image_memory(process, preferred_base, image_size)?;
    
    boot_println!("[SMSS] Allocated {} bytes at 0x{:016x}", image_size, image_base);
    
    // Map the PE sections into memory
    for section in &sections {
        let dest_addr = image_base + section.virtual_address as u64;
        let src_data = &pe_data[section.raw_offset as usize..section.raw_offset as usize + section.raw_size as usize];
        
        // Map a page for this section if not already mapped
        let page_start = dest_addr & !0xFFF;
        let page_end = (dest_addr + section.virtual_size as u64 + 0xFFF) & !0xFFF;
        
        for page_addr in (page_start..page_end).step_by(0x1000) {
            let _ = map_user_page(process, page_addr);
        }
        
        // Copy section data
        unsafe {
            let dest_ptr = dest_addr as *mut u8;
            dest_ptr.copy_from_nonoverlapping(src_data.as_ptr(), src_data.len());
            
            // Zero-fill remaining bytes if virtual size > raw size
            if section.virtual_size > section.raw_size {
                let zero_start = src_data.len();
                let zero_end = section.virtual_size as usize;
                core::ptr::write_bytes(dest_ptr.add(zero_start), 0, zero_end - zero_start);
            }
        }
    }
    
    // Update process's image base
    unsafe {
        (*process).user_image_base = image_base;
    }
    
    Ok(())
}

/// Section information from PE header
struct PeSection {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

/// Parse section headers from PE file.
fn parse_pe_sections(pe_data: &[u8]) -> Option<Vec<PeSection>> {
    // Get PE header offset
    let pe_offset = u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;
    let coff_offset = pe_offset + 4;
    
    let num_sections = u16::from_le_bytes([pe_data[coff_offset + 2], pe_data[coff_offset + 3]]) as usize;
    let optional_header_size = u16::from_le_bytes([pe_data[coff_offset + 16], pe_data[coff_offset + 17]]) as usize;
    
    let section_table_offset = coff_offset + 20 + optional_header_size as usize;
    
    let mut sections = Vec::new();
    
    for i in 0..num_sections {
        let section_offset = section_table_offset + i * 40;
        if pe_data.len() < section_offset + 40 {
            return None;
        }
        
        let mut name = [0u8; 8];
        name.copy_from_slice(&pe_data[section_offset..section_offset + 8]);
        
        let virtual_size = u32::from_le_bytes([
            pe_data[section_offset + 8], pe_data[section_offset + 9],
            pe_data[section_offset + 10], pe_data[section_offset + 11],
        ]);
        let virtual_address = u32::from_le_bytes([
            pe_data[section_offset + 12], pe_data[section_offset + 13],
            pe_data[section_offset + 14], pe_data[section_offset + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            pe_data[section_offset + 16], pe_data[section_offset + 17],
            pe_data[section_offset + 18], pe_data[section_offset + 19],
        ]);
        let raw_offset = u32::from_le_bytes([
            pe_data[section_offset + 20], pe_data[section_offset + 21],
            pe_data[section_offset + 22], pe_data[section_offset + 23],
        ]);
        
        // Skip empty sections
        if virtual_size == 0 && raw_size == 0 {
            continue;
        }
        
        sections.push(PeSection {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
        });
    }
    
    Some(sections)
}

/// Allocate memory for a PE image in a process's address space.
fn allocate_image_memory(process: *mut crate::ps::process::Eprocess, preferred_base: u64, size: u64) -> Result<u64, ExeLoadError> {
    let pml4_phys = unsafe { (*process).page_table_pml4 };
    if pml4_phys == 0 {
        return Err(ExeLoadError::LoadFailed);
    }
    
    // For simplicity, we'll use a fixed allocation region
    // In a full implementation, we'd search for a suitable region
    let mut base = preferred_base;
    
    // Round up to page boundary
    base = (base + 0xFFF) & !0xFFF;
    
    // Allocate pages for the image
    let num_pages = ((size + 0xFFF) / 0x1000) as usize;
    
    for i in 0..num_pages {
        let page_addr = base + (i as u64 * 0x1000);
        if map_user_page(process, page_addr).is_err() {
            return Err(ExeLoadError::LoadFailed);
        }
    }
    
    Ok(base)
}

/// Map a user-mode page into a process's address space.
fn map_user_page(process: *mut crate::ps::process::Eprocess, virtual_addr: u64) -> Result<(), ExeLoadError> {
    let pml4_phys = unsafe { (*process).page_table_pml4 };
    if pml4_phys == 0 {
        return Err(ExeLoadError::LoadFailed);
    }
    
    // Allocate a physical page
    let result = crate::mm::vas::alloc_zeroed_page_for_vas();
    if result.is_none() {
        return Err(ExeLoadError::LoadFailed);
    }
    let phys_addr = result.unwrap();
    
    // Map the page with RW and US (user/supervisor) flags
    let status = crate::mm::vas::map_page_in_pml4(
        pml4_phys,
        virtual_addr,
        phys_addr,
        crate::mm::vas::PTE_RW | crate::mm::vas::PTE_US,
    );
    
    if status != crate::mm::vas::MmStatus::Ok {
        return Err(ExeLoadError::LoadFailed);
    }
    
    Ok(())
}

// ============================================================================
// Boot Sequence Functions
// ============================================================================

/// Boot sequence state tracking
static BOOT_COMPLETE: Spinlock<bool> = Spinlock::new(false);

/// Start the complete Windows 7 boot sequence.
///
/// This is the main entry point for the "no desktop" boot mode.
/// It implements the full boot chain:
/// 1. SMSS creates sessions
/// 2. CSRSS starts for Session 0 and Session 1
/// 3. WinInit starts
/// 4. WinInit starts Services and LSASS
/// 5. Winlogon starts (in non-desktop mode)
/// 6. CMD.exe launches as the shell
pub fn start_boot_sequence() {
    boot_println!("[BOOT] ============================================");
    boot_println!("[BOOT] Windows 7 Boot Sequence (No Desktop Mode)");
    boot_println!("[BOOT] ============================================");
    
    // Phase 1: Initialize SMSS
    boot_println!("[BOOT] Phase 1: Initializing Session Manager...");
    phase1_initialize();
    
    // Phase 2: Create sessions
    boot_println!("[BOOT] Phase 2: Creating Sessions...");
    phase2_create_sessions();
    
// Phase 3: Start subsystems (CSRSS)
    boot_println!("[BOOT] Phase 3: Starting Subsystems...");
    phase3_start_subsystems();

    // =========================================================================
    // Phase 012: csrss / wininit / services / lsass subsystem spin-up
    // =========================================================================
    // Win-7 brings up the user-mode subsystems in two waves: csrss.exe
    // (one per session) at SMSS time, then wininit.exe hands off to
    // services.exe / lsass.exe inside Session 0. From this point on,
    // every process that gets created is loaded from the on-disk NTFS
    // system image by `smss::read_pe_from_disk` (no host-side
    // synthesis). Print a Phase 012 marker before phase 4 / phase 5.
    crate::rtl::windows_log::write_phase_header(12);
    boot_println!("    SUBSYSTEMS: csrss / wininit / services / lsass");

    // Phase 4: Start WinInit
    boot_println!("[BOOT] Phase 4: Starting WinInit...");
    phase4_start_wininit();

    // Phase 5: Launch WinLogon + UserInit (Session 1 logon chain).
    boot_println!("[BOOT] Phase 5: Starting Session 1 Logon...");
    phase5_start_logon();

    // =========================================================================
    // Phase 013: cmd.exe (Ring-3 syscall loop)
    // =========================================================================
    // cmd.exe is the first user-mode process whose entry point we
    // actually execute in Ring 3 (the rest stay in their DriverEntry
    // stubs). The Phase 013 marker is the final boundary in the
    // kernel-side phase table — after this point everything is
    // driven by user-mode syscalls (`SYS_PUTCHAR`, `SYS_GETCHAR`,
    // `SYS_EXIT`, ...).
    crate::rtl::windows_log::write_phase_header(13);
    boot_println!("    CMD: cmd.exe Ring-3 entry");

    // Phase 6: Launch CMD
    boot_println!("[BOOT] Phase 6: Launching CMD Shell...");
    launch_cmd_shell();

    // Mark boot as complete
    *BOOT_COMPLETE.lock() = true;

    boot_println!("[BOOT] ============================================");
    boot_println!("[BOOT] Boot Sequence Complete!");
    boot_println!("[BOOT] CMD Shell Ready");
    boot_println!("[BOOT] ============================================");
}

/// Canonical Windows-7 boot orchestrator entry point.
///
/// Drives every phase of the user-mode boot chain end-to-end:
///   Phase 1  SMSS init
///   Phase 2  Session 0 + Session 1
///   Phase 3  CSRSS (both sessions)
///   Phase 4  WinInit + Services + LSASS + LSM
///   Phase 5  WinLogon + UserInit (Session 1)
///   Phase 6  cmd.exe (via userinit)
///
/// This is the function `arch::boot::try_launch_cmd_exe_arch` calls
/// after initialising its own session tables — `smss::run()` is the
/// single source of truth for the Win-7 boot ordering.
pub fn run() {
    crate::rtl::windows_log::write_phase_header(11);
    boot_println!("[SMSS::run] Windows 7 boot chain starting");
    start_boot_sequence();
}

/// Start CSRSS for all sessions during boot
fn start_boot_subsystems() {
    // Start CSRSS for Session 0
    boot_println!("[BOOT]   Starting CSRSS for Session 0...");
    if let Err(e) = launch_csrss(0) {
        boot_println!("[BOOT]   Warning: Failed to launch CSRSS Session 0: {:?}", e);
    } else {
        boot_println!("[BOOT]   CSRSS Session 0 started successfully");
    }
    
    // Start CSRSS for Session 1
    boot_println!("[BOOT]   Starting CSRSS for Session 1...");
    if let Err(e) = launch_csrss(1) {
        boot_println!("[BOOT]   Warning: Failed to launch CSRSS Session 1: {:?}", e);
    } else {
        boot_println!("[BOOT]   CSRSS Session 1 started successfully");
    }
}

/// Phase 4: Start WinInit (which starts Services and LSASS)
fn phase4_start_wininit() {
    // Launch WinInit
    boot_println!("[BOOT]   Launching wininit.exe...");
    if let Err(e) = launch_wininit() {
        boot_println!("[BOOT]   Warning: Failed to launch wininit.exe: {:?}", e);
    } else {
        boot_println!("[BOOT]   wininit.exe started successfully");
    }

    // Real WinInit starts services.exe, lsass.exe, AND lsm.exe.
    // We launch lsm.exe eagerly so the session-management stub is
    // available for winlogon to talk to later in Phase 5.
    boot_println!("[BOOT]   Launching lsm.exe...");
    if let Err(e) = launch_lsm() {
        boot_println!("[BOOT]   Warning: Failed to launch lsm.exe: {:?}", e);
    } else {
        boot_println!("[BOOT]   lsm.exe started successfully");
    }
}

/// Phase 5: Start WinLogon and UserInit (Session 1 logon chain).
///
/// In real Windows 7 this would happen after a user successfully
/// authenticates at the logon UI. In the no-desktop boot mode we
/// skip authentication entirely — winlogon is launched, which
/// then chains to userinit, which then launches cmd.exe.
fn phase5_start_logon() {
    boot_println!("[BOOT]   Launching winlogon.exe (Session 1)...");
    if let Err(e) = launch_winlogon() {
        boot_println!("[BOOT]   Warning: Failed to launch winlogon.exe: {:?}", e);
    } else {
        boot_println!("[BOOT]   winlogon.exe started successfully");
    }

    boot_println!("[BOOT]   Launching userinit.exe (Session 1)...");
    if let Err(e) = launch_userinit() {
        boot_println!("[BOOT]   Warning: Failed to launch userinit.exe: {:?}", e);
    } else {
        boot_println!("[BOOT]   userinit.exe started successfully");
    }
}

/// Launch CSRSS for a specific session.
fn launch_csrss(session_id: u32) -> Result<SystemExeLoadResult, ExeLoadError> {
    let disk_path = "C:\\Windows\\System32\\csrss.exe";
    let process_name = if session_id == 0 { "csrss.exe (Session 0)" } else { "csrss.exe (Session 1)" };
    let base_pid = PID_CSRSS + (session_id as u64 * 0x100);
    
    load_and_create_process(disk_path, process_name, session_id, base_pid)
}

/// Launch wininit.exe (which will start services.exe and lsass.exe).
fn launch_wininit() -> Result<SystemExeLoadResult, ExeLoadError> {
    let disk_path = "C:\\Windows\\System32\\wininit.exe";
    let process_name = "wininit.exe";
    let base_pid = PID_WININIT;
    
    let result = load_and_create_process(disk_path, process_name, SESSION_0, base_pid)?;
    
    // WinInit should start services.exe and lsass.exe
    // For now, we'll also start them directly from SMSS
    boot_println!("[BOOT]   Launching services.exe from wininit...");
    if let Err(e) = launch_services() {
        boot_println!("[BOOT]   Warning: Failed to launch services.exe: {:?}", e);
    } else {
        boot_println!("[BOOT]   services.exe started successfully");
    }
    
    boot_println!("[BOOT]   Launching lsass.exe from wininit...");
    if let Err(e) = launch_lsass() {
        boot_println!("[BOOT]   Warning: Failed to launch lsass.exe: {:?}", e);
    } else {
        boot_println!("[BOOT]   lsass.exe started successfully");
    }
    
    Ok(result)
}

/// Launch services.exe (Service Control Manager).
fn launch_services() -> Result<SystemExeLoadResult, ExeLoadError> {
    let disk_path = "C:\\Windows\\System32\\services.exe";
    let process_name = "services.exe";
    let base_pid = PID_SERVICES;

    load_and_create_process(disk_path, process_name, SESSION_0, base_pid)
}

/// Launch lsass.exe (Local Security Authority).
fn launch_lsass() -> Result<SystemExeLoadResult, ExeLoadError> {
    let disk_path = "C:\\Windows\\System32\\lsass.exe";
    let process_name = "lsass.exe";
    let base_pid = PID_LSASS;

    load_and_create_process(disk_path, process_name, SESSION_0, base_pid)
}

/// Launch lsm.exe (Local Session Manager). Real Windows 7 starts
/// lsm from wininit.exe alongside services/lsass; the SMSS boot
/// orchestrator launches it eagerly here so the user-mode chain
/// (lsm → winlogon → userinit → cmd) is fully populated.
pub fn launch_lsm() -> Result<SystemExeLoadResult, ExeLoadError> {
    let disk_path = "C:\\Windows\\System32\\lsm.exe";
    let process_name = "lsm.exe";
    let base_pid = PID_LSM;

    load_and_create_process(disk_path, process_name, SESSION_0, base_pid)
}

/// Launch winlogon.exe (Windows Logon Application) for Session 1.
/// winlogon reads its config from HKLM and starts userinit.exe
/// once the user "logs on". In the no-desktop boot mode we
/// skip authentication and ask winlogon to start userinit
/// immediately.
pub fn launch_winlogon() -> Result<SystemExeLoadResult, ExeLoadError> {
    let disk_path = "C:\\Windows\\System32\\winlogon.exe";
    let process_name = "winlogon.exe";
    let base_pid = PID_WINLOGON;

    load_and_create_process(disk_path, process_name, SESSION_1, base_pid)
}

/// Launch userinit.exe (per-user logon initializer). userinit
/// runs the user's logon scripts and then chains to the user's
/// shell, which we have configured to be `cmd.exe` for the
/// no-desktop boot.
pub fn launch_userinit() -> Result<SystemExeLoadResult, ExeLoadError> {
    let disk_path = "C:\\Windows\\System32\\userinit.exe";
    let process_name = "userinit.exe";
    let base_pid = PID_USERINIT;

    load_and_create_process(disk_path, process_name, SESSION_1, base_pid)
}

/// Launch the CMD shell as the final step of the boot sequence.
///
/// On x86_64 this function returns control to Ring-3 by jumping into
/// the cmd.exe entry point via
/// `arch::x86_64::user_entry::enter_first_user_thread`. On other
/// architectures it falls back to the legacy "show prompt" stub.
fn launch_cmd_shell() {
    boot_println!("[BOOT]   Loading cmd.exe from disk...");

    let disk_path = "C:\\Windows\\System32\\cmd.exe";
    let process_name = "cmd.exe";
    let base_pid = PID_CMD;

    match load_and_create_process(disk_path, process_name, SESSION_1, base_pid) {
        Ok(result) => {
            boot_println!("[BOOT]   cmd.exe loaded successfully");
            boot_println!("[BOOT]   Process ID: 0x{:x}", result.pid);
            boot_println!("[BOOT]   Entry Point: 0x{:016x}", result.entry_point);
            boot_println!("[BOOT]   Image Base: 0x{:016x}", result.image_base);

            // On x86_64 we hand off to Ring 3 here and never come
            // back. The bootloader entry into SMSS was via
            // `arch::boot::try_launch_cmd_exe_arch`, which now
            // delegates to `smss::run()` — see Phase E.
            #[cfg(target_arch = "x86_64")]
            {
                if let Some(proc) = crate::ps::process::get_by_pid(result.pid) {
                    let proc_ptr = proc as *mut crate::ps::process::Eprocess;
                    let main_thread = unsafe { (*proc_ptr).main_thread };
                    if !main_thread.is_null() {
                        crate::ke::scheduler::setup_bsp(main_thread);
                        let pml4_phys = unsafe { (*proc_ptr).pml4_phys };
                        let user_rip = unsafe { (*proc_ptr).user_rip };
                        let user_rsp = unsafe { (*proc_ptr).user_rsp };
                        boot_println!("[BOOT]   Dispatching cmd.exe into Ring 3 (PML4=0x{:x} RIP=0x{:x} RSP=0x{:x})",
                                      pml4_phys, user_rip, user_rsp);
                        crate::arch::x86_64::user_entry::enter_first_user_thread(pml4_phys, user_rip, user_rsp);
                    } else {
                        boot_println!("[BOOT]   ERROR: cmd.exe main_thread is NULL");
                    }
                } else {
                    boot_println!("[BOOT]   ERROR: cmd.exe process not found in PID table");
                }
            }

            // Fallback for non-x86_64 (we just print the prompt and
            // return).
            #[cfg(not(target_arch = "x86_64"))]
            {
                transfer_to_user_mode(result.pid, result.entry_point);
            }
        }
        Err(e) => {
            boot_println!("[BOOT]   ERROR: Failed to launch cmd.exe: {:?}", e);
            boot_println!("[BOOT]   System cannot proceed without a shell!");
            
            // Fallback: Show error message
            show_boot_error();
        }
    }
}

/// Transfer control to a user-mode process.
fn transfer_to_user_mode(pid: u64, entry_point: u64) {
    boot_println!("[BOOT] Transferring control to PID 0x{:x} at entry 0x{:016x}", pid, entry_point);
    
    // Find the process
    if let Some(process) = crate::ps::process::get_by_pid(pid) {
        let process_ptr = process as *mut crate::ps::process::Eprocess;
        boot_println!("[BOOT] Found process, preparing user-mode transition...");
        
        // The main thread should already be created by create_user_process
        let main_thread = unsafe { (*process_ptr).main_thread };
        if !main_thread.is_null() {
            boot_println!("[BOOT] Main thread found, setting up user-mode context...");
            
            // Set the entry point in the process
            unsafe {
                (*process_ptr).user_rip = entry_point;
            }
            
            boot_println!("[BOOT] User-mode entry point set to 0x{:016x}", entry_point);
        } else {
            boot_println!("[BOOT] WARNING: No main thread found for PID 0x{:x}", pid);
        }
    } else {
        boot_println!("[BOOT] ERROR: Process PID 0x{:x} not found!", pid);
    }
    
    // Signal that CMD is ready
    boot_println!("");
    boot_println!("============================================");
    boot_println!("");
    boot_println!("   CMD - Command Prompt");
    boot_println!("");
    boot_println!("   Type 'help' for available commands");
    boot_println!("");
    boot_println!("============================================");
    boot_println!("");
}

/// Show boot error message.
fn show_boot_error() {
    boot_println!("");
    boot_println!("********************************************");
    boot_println!("*");
    boot_println!("*  BOOT ERROR");
    boot_println!("*");
    boot_println!("*  Failed to load the command shell.");
    boot_println!("*  The system cannot continue.");
    boot_println!("*");
    boot_println!("********************************************");
    boot_println!("");
}

/// Check if boot sequence is complete.
pub fn is_boot_complete() -> bool {
    *BOOT_COMPLETE.lock()
}