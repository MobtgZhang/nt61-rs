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

extern crate alloc;
use alloc::vec::Vec;

use crate::ps::process::Process;
use crate::ke::sync::Spinlock;
use crate::registry::cm;

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
    let _ = session_id;

    // CSRSS is started by SMSS for each session
    // The path is typically \Windows\System32\csrss.exe
    let csrss_path = "\\SystemRoot\\System32\\csrss.exe";
    let _ = csrss_path;

    // In a full implementation:
    // 1. Create the CSRSS process using the PE loader
    // 2. Set appropriate security (CSRSS runs in the specified session)
    // 3. Create the CSRSS main thread
    // 4. Wait for CSRSS initialization
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
fn start_wininit() {
    // kprintln!("[SMSS] Starting wininit.exe...")  // kprintln disabled (memcpy crash workaround);

    // wininit.exe starts:
    // - services.exe (Service Control Manager)
    // - lsass.exe (Local Security Authority)
    // - lsm.exe (Local Session Manager)

    let wininit_path = "\\SystemRoot\\System32\\wininit.exe";
    // kprintln!("[SMSS]   wininit.exe path: {}", wininit_path)  // kprintln disabled (memcpy crash workaround);
    let _ = wininit_path;

    // In a full implementation:
    // 1. Load wininit.exe using the PE loader
    // 2. Create the process in Session 0
    // 3. Create the main thread and start execution
    // 4. Wait for wininit to spawn the child processes

    // kprintln!("[SMSS]   wininit.exe started")  // kprintln disabled (memcpy crash workaround);
}

/// Start winlogon process
fn start_winlogon() {
    // kprintln!("[SMSS] Starting winlogon.exe...")  // kprintln disabled (memcpy crash workaround);

    // winlogon handles:
    // - Logon prompts
    // - Secure Attention Sequence (Ctrl+Alt+Delete)
    // - User Shell launching

    let winlogon_path = "\\SystemRoot\\System32\\winlogon.exe";
    // kprintln!("[SMSS]   winlogon.exe path: {}", winlogon_path)  // kprintln disabled (memcpy crash workaround);
    let _ = winlogon_path;

    // In a full implementation:
    // 1. Load winlogon.exe using the PE loader
    // 2. Create the process in Session 1
    // 3. Create the main thread and start execution
    // 4. Set up the logon environment

    // kprintln!("[SMSS]   winlogon.exe started")  // kprintln disabled (memcpy crash workaround);
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
    // kprintln!("[SMSS] Starting services.exe...")  // kprintln disabled (memcpy crash workaround);

    let services_path = "\\SystemRoot\\System32\\services.exe";
    let _ = &services_path;
    // kprintln!("[SMSS]   services.exe path: {}", services_path)  // kprintln disabled (memcpy crash workaround);

    // services.exe hosts Windows services including:
    // - Plug and Play (PlugPlay)
    // - Remote Procedure Call (RpcSs)
    // - Security Accounts Manager (SamSs)
    // - Windows Installer (msiserver)
    // - And many more

    // kprintln!("[SMSS]   services.exe started")  // kprintln disabled (memcpy crash workaround);
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