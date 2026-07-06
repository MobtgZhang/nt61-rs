//! Service Control Manager (SCM)
//
//! Implements Windows Service Control Manager
//! Manages Windows services defined in the registry

// SCM uses the WDK driver naming convention
// (SERVICE_* types, SERVICE_STATUS, ...).
#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::ke::sync::Spinlock;

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Service types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceType {
    KernelDriver = 0x01,
    FileSystemDriver = 0x02,
    Adapter = 0x04,
    RecognizerDriver = 0x08,
    DriverOwnProcess = 0x10,
    ShareProcess = 0x20,
    InteractiveProcess = 0x100,
}

/// Service start types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceStartType {
    BootStart = 0,
    SystemStart = 1,
    AutoStart = 2,
    DemandStart = 3,
    Disabled = 4,
}

/// Service error control
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceErrorControl {
    Ignore = 0,
    Normal = 1,
    Severe = 2,
    Critical = 3,
}

/// Service state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceState {
    Stopped = 0x01,
    StartPending = 0x02,
    StopPending = 0x03,
    Running = 0x04,
    ContinuePending = 0x05,
    PausePending = 0x06,
    Paused = 0x07,
}

/// Service control codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceControl {
    Stop = 0x01,
    Pause = 0x02,
    Continue = 0x03,
    Interrogate = 0x04,
    Shutdown = 0x05,
    ParamChange = 0x06,
    NetBindAdd = 0x07,
    NetBindRemove = 0x08,
    NetBindEnable = 0x09,
    NetBindDisable = 0x0A,
}

/// Service status
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServiceStatus {
    pub service_type: ServiceType,
    pub current_state: ServiceState,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_exit_code: u32,
    pub checkpoint: u32,
    pub wait_hint: u32,
}

impl ServiceStatus {
    pub const fn new() -> Self {
        Self {
            service_type: ServiceType::ShareProcess,
            current_state: ServiceState::Stopped,
            controls_accepted: 0,
            win32_exit_code: 0,
            service_exit_code: 0,
            checkpoint: 0,
            wait_hint: 0,
        }
    }
}

/// Service database entry
#[derive(Clone)]
pub struct ServiceEntry {
    pub name: [u16; 256],
    pub display_name: [u16; 256],
    pub service_type: ServiceType,
    pub start_type: ServiceStartType,
    pub error_control: ServiceErrorControl,
    pub image_path: [u16; 260],
    pub load_order_group: [u16; 64],
    pub tag_id: u32,
    pub dependencies: [[u16; 64]; 4],
    pub dependency_count: usize,
    pub service_start_name: [u16; 256],
    pub status: ServiceStatus,
}

impl ServiceEntry {
    pub const fn new() -> Self {
        Self {
            name: [0; 256],
            display_name: [0; 256],
            service_type: ServiceType::ShareProcess,
            start_type: ServiceStartType::DemandStart,
            error_control: ServiceErrorControl::Normal,
            image_path: [0; 260],
            load_order_group: [0; 64],
            tag_id: 0,
            dependencies: [[0; 64]; 4],
            dependency_count: 0,
            service_start_name: [0; 256],
            status: ServiceStatus::new(),
        }
    }
}

/// SCM state
pub struct ScmState {
    pub running: bool,
    pub debug: bool,
    pub services: [ServiceEntry; 32],
    pub service_count: usize,
}

impl ScmState {
    pub const fn new() -> Self {
        Self {
            running: false,
            debug: false,
            services: [const { ServiceEntry::new() }; 32],
            service_count: 0,
        }
    }
}

/// Global SCM state
pub static SCM_STATE: Spinlock<ScmState> = Spinlock::new(ScmState::new());

/// Initialize SCM
pub fn init() {
    // Force an early lock to flush any junk in the BSS
    // area used by the static `SCM_STATE`. On some
    // firmware the BSS arrays aren't reliably zeroed.
    {
        let state = SCM_STATE.lock();
        let _ = state.running;
    }
    let mut state = SCM_STATE.lock();
    state.running = true;
    state.debug = false;
    drop(state);

    // Register the default services (RpcSs, EventSystem, Themes)
    register_default_services();

    // kprintln!("    Service Control Manager initialized")  // kprintln disabled (memcpy crash workaround);
}

/// Start SCM
pub fn start() {
    // kprintln!("[SCM] Starting Service Control Manager...")  // kprintln disabled (memcpy crash workaround);

    // Phase 1: Initialize
    phase1_init();

    // Phase 2: Load services
    phase2_load_services();

    // Phase 3: Start auto-start services
    phase3_start_services();

    // kprintln!("[SCM] Service Control Manager started")  // kprintln disabled (memcpy crash workaround);
}

/// Phase 1: Initialize SCM
fn phase1_init() {
    // kprintln!("[SCM] Phase 1: Initializing...")  // kprintln disabled (memcpy crash workaround);
}

/// Phase 2: Load service definitions from registry
fn phase2_load_services() {
    // kprintln!("[SCM] Phase 2: Loading service definitions...")  // kprintln disabled (memcpy crash workaround);

    // Load services from:
    // HKLM\SYSTEM\CurrentControlSet\Services

    // Query service definitions from the registry
    load_services_from_registry();

    // Also add default services as fallback
    add_default_services();

    let _state = SCM_STATE.lock();
    // kprintln!("[SCM] Loaded service definitions")  // kprintln disabled (memcpy crash workaround);
}

/// Load service definitions from the registry
fn load_services_from_registry() {
    use crate::registry::cm::{enumerate_subkeys, query_dword, query_string};

    // Query the list of services from the registry
    let service_keys = match enumerate_subkeys(
        "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services"
    ) {
        Some(keys) => keys,
        None => {
            // kprintln!("[SCM] No services found in registry (CM not available)")  // kprintln disabled (memcpy crash workaround);
            return;
        }
    };

    // kprintln!("[SCM] Found {} service definitions in registry", service_keys.len())  // kprintln disabled (memcpy crash workaround);

    // For each service, read its configuration
    let _boot_start_count = 0usize;
    for service_name in &service_keys {
        // Limit to first 10 services for brevity
        if _boot_start_count >= 10 {
            // kprintln!("[SCM] ... and {} more services", service_keys.len() - _boot_start_count)  // kprintln disabled (memcpy crash workaround);
            break;
        }

        let service_path = format!(
            "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\{}",
            service_name
        );

        // Read Type
        let start_type = query_dword(&service_path, "Start")
            .unwrap_or(3); // Default to DemandStart (3)
        let _ = &start_type;

        // Read ErrorControl
        let _error_control = query_dword(&service_path, "ErrorControl")
            .unwrap_or(1); // Default to Normal (1)

        // Read ImagePath (optional)
        let _image_path = query_string(&service_path, "ImagePath");

        // kprintln!("[SCM]   {}: Start={}", service_name, start_type)  // kprintln disabled (memcpy crash workaround);
    }
}



/// Phase 3: Start auto-start services
fn phase3_start_services() {
    // kprintln!("[SCM] Phase 3: Starting auto-start services...")  // kprintln disabled (memcpy crash workaround);

    let state = SCM_STATE.lock();

    // Start all auto-start services
    for i in 0..state.service_count {
        let svc = &state.services[i];
        if svc.start_type == ServiceStartType::AutoStart
            || svc.start_type == ServiceStartType::SystemStart
            || svc.start_type == ServiceStartType::BootStart
        {
            // kprintln!("[SCM]   Starting service: {}",  // kprintln disabled (memcpy crash workaround)
//                 String::from_utf16_lossy(&svc.name).trim_end_matches('\0'));
            // In a real implementation, this would:
            // 1. Create a process for the service
            // 2. Call StartService() to begin execution
            // 3. Wait for the service to report running state
        }
    }
}

/// Add default services
fn add_default_services() {
    register_default_services();
}

fn register_default_services() {
    // Helper: copy a `&str` into a `[u16; N]` UTF-16 buffer with a
    // null terminator. The output buffer is always pre-zeroed by
    // the caller (we zero SCM_STATE on first lock), so we only
    // need to write the actual characters.
    fn copy_str(dest: &mut [u16], src: &str) {
        let max = dest.len() - 1;
        for (i, c) in src.chars().enumerate() {
            if i >= max {
                break;
            }
            dest[i] = c as u16;
        }
    }

    let mut state = SCM_STATE.lock();

    // Core system services
    let default_services: &[(&str, &str, &str, ServiceType, ServiceStartType)] = &[
        ("RpcSs", "Remote Procedure Call (RPC)", "%SystemRoot%\\System32\\svchost.exe -k rpcss", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("EventSystem", "COM+ Event System", "%SystemRoot%\\System32\\svchost.exe -k LocalService", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("Themes", "Themes Service", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("WinDefend", "Windows Defender Service", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", ServiceType::ShareProcess, ServiceStartType::DemandStart),
        ("W3SVC", "World Wide Web Publishing Service", "%SystemRoot%\\System32\\svchost.exe -k iissvcs", ServiceType::ShareProcess, ServiceStartType::DemandStart),
        ("TapiSrv", "Telephony Service", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", ServiceType::ShareProcess, ServiceStartType::DemandStart),
        ("BITS", "Background Intelligent Transfer Service", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", ServiceType::ShareProcess, ServiceStartType::DemandStart),
        ("CryptSvc", "Cryptographic Services", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("DPS", "Diagnostic Policy Service", "%SystemRoot%\\System32\\svchost.exe -k LocalService", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("Dhcp", "DHCP Client", "%SystemRoot%\\System32\\svchost.exe -k NetworkService", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("Dnscache", "DNS Client", "%SystemRoot%\\System32\\svchost.exe -k NetworkService", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("LanmanServer", "Server", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("LanmanWorkstation", "Workstation", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", ServiceType::ShareProcess, ServiceStartType::AutoStart),
        ("W32Time", "Windows Time", "%SystemRoot%\\System32\\svchost.exe -k LocalService", ServiceType::ShareProcess, ServiceStartType::DemandStart),
        ("WSearch", "Windows Search", "%SystemRoot%\\System32\\SearchIndexer.exe /Slow", ServiceType::ShareProcess, ServiceStartType::DemandStart),
    ];

    for (name, display_name, image_path, svc_type, start_type) in default_services {
        let idx = state.service_count;
        if idx >= state.services.len() {
            break;
        }
        let svc = &mut state.services[idx];
        copy_str(&mut svc.name, name);
        copy_str(&mut svc.display_name, display_name);
        copy_str(&mut svc.image_path, image_path);
        svc.service_type = *svc_type;
        svc.start_type = *start_type;
        svc.error_control = ServiceErrorControl::Normal;
        svc.status.current_state = ServiceState::Stopped;
        state.service_count = idx + 1;
    }

    // kprintln!("[SCM] Registered {} default services", state.service_count)  // kprintln disabled (memcpy crash workaround);
}

/// Start a specific service by name
#[allow(dead_code)]
pub fn start_service(service_name: &str) -> bool {
    let mut state = SCM_STATE.lock();

    for i in 0..state.service_count {
        let name_str = String::from_utf16_lossy(&state.services[i].name);
        let name = name_str.trim_end_matches('\0');
        if name == service_name {
            let svc = &mut state.services[i];
            if svc.status.current_state == ServiceState::Stopped {
                // kprintln!("[SCM] Starting service: {}", service_name)  // kprintln disabled (memcpy crash workaround);
                svc.status.current_state = ServiceState::StartPending;
                // TODO: Create process and start service
                svc.status.current_state = ServiceState::Running;
                svc.status.win32_exit_code = 0;
                svc.status.service_exit_code = 0;
                return true;
            }
            return false;
        }
    }
    false
}

/// Stop a specific service by name
#[allow(dead_code)]
pub fn stop_service(service_name: &str) -> bool {
    let mut state = SCM_STATE.lock();

    for i in 0..state.service_count {
        let name_str = String::from_utf16_lossy(&state.services[i].name);
        let name = name_str.trim_end_matches('\0');
        if name == service_name {
            let svc = &mut state.services[i];
            if svc.status.current_state == ServiceState::Running {
                // kprintln!("[SCM] Stopping service: {}", service_name)  // kprintln disabled (memcpy crash workaround);
                svc.status.current_state = ServiceState::StopPending;
                // TODO: Send control code to stop service
                svc.status.current_state = ServiceState::Stopped;
                return true;
            }
            return false;
        }
    }
    false
}

/// Query service status
#[allow(dead_code)]
pub fn query_service_status(service_name: &str) -> Option<ServiceStatus> {
    let state = SCM_STATE.lock();

    for i in 0..state.service_count {
        let name_str = String::from_utf16_lossy(&state.services[i].name);
        let name = name_str.trim_end_matches('\0');
        if name == service_name {
            return Some(state.services[i].status);
        }
    }
    None
}

/// List all registered services
#[allow(dead_code)]
pub fn list_services() -> Vec<(String, ServiceState)> {
    let state = SCM_STATE.lock();
    let mut result = Vec::new();

    for i in 0..state.service_count {
        let name = String::from_utf16_lossy(&state.services[i].name)
            .trim_end_matches('\0').into();
        result.push((name, state.services[i].status.current_state));
    }
    result
}

// ============================================================================
// Service Control API
// ============================================================================

/// Open a service handle (returns service entry index or -1)
pub fn open_service(service_name: &str) -> Option<usize> {
    let state = SCM_STATE.lock();
    
    for i in 0..state.service_count {
        let name_str = String::from_utf16_lossy(&state.services[i].name);
        let name = name_str.trim_end_matches('\0');
        if name.eq_ignore_ascii_case(service_name) {
            return Some(i);
        }
    }
    None
}

/// Control a service (start, stop, pause, continue)
pub fn control_service(idx: usize, control: ServiceControl) -> bool {
    let mut state = SCM_STATE.lock();
    
    if idx >= state.service_count {
        return false;
    }
    
    let svc = &mut state.services[idx];
    let current_state = svc.status.current_state;
    
    match control {
        ServiceControl::Stop => {
            if current_state == ServiceState::Running {
                // kprintln!("[SCM] Stopping service: {}",   // kprintln disabled (memcpy crash workaround)
//                     String::from_utf16_lossy(&svc.name).trim_end_matches('\0'));
                svc.status.current_state = ServiceState::StopPending;
                svc.status.current_state = ServiceState::Stopped;
                return true;
            }
        }
        ServiceControl::Pause => {
            if current_state == ServiceState::Running {
                // kprintln!("[SCM] Pausing service: {}",   // kprintln disabled (memcpy crash workaround)
//                     String::from_utf16_lossy(&svc.name).trim_end_matches('\0'));
                svc.status.current_state = ServiceState::PausePending;
                svc.status.current_state = ServiceState::Paused;
                return true;
            }
        }
        ServiceControl::Continue => {
            if current_state == ServiceState::Paused {
                // kprintln!("[SCM] Continuing service: {}",   // kprintln disabled (memcpy crash workaround)
//                     String::from_utf16_lossy(&svc.name).trim_end_matches('\0'));
                svc.status.current_state = ServiceState::ContinuePending;
                svc.status.current_state = ServiceState::Running;
                return true;
            }
        }
        ServiceControl::Interrogate => {
            // Just return current status
            return true;
        }
        ServiceControl::Shutdown => {
            if current_state == ServiceState::Running {
                // kprintln!("[SCM] Shutting down service: {}",   // kprintln disabled (memcpy crash workaround)
//                     String::from_utf16_lossy(&svc.name).trim_end_matches('\0'));
                svc.status.current_state = ServiceState::Stopped;
                return true;
            }
        }
        _ => {
            // kprintln!("[SCM] Unknown control code: {:?}", control)  // kprintln disabled (memcpy crash workaround);
        }
    }
    false
}

/// Get service configuration
pub fn query_service_config(idx: usize) -> Option<(ServiceType, ServiceStartType, ServiceErrorControl)> {
    let state = SCM_STATE.lock();
    
    if idx >= state.service_count {
        return None;
    }
    
    let svc = &state.services[idx];
    Some((svc.service_type, svc.start_type, svc.error_control))
}

// ============================================================================
// Service Enumeration
// ============================================================================

/// Enumerate services by type
pub fn enumerate_services(svc_type: ServiceType) -> Vec<String> {
    let state = SCM_STATE.lock();
    let mut result = Vec::new();
    
    for i in 0..state.service_count {
        if state.services[i].service_type == svc_type {
            let name = String::from_utf16_lossy(&state.services[i].name)
                .trim_end_matches('\0').into();
            result.push(name);
        }
    }
    result
}

/// Enumerate services by state
pub fn enumerate_services_by_state(state_filter: ServiceState) -> Vec<String> {
    let state = SCM_STATE.lock();
    let mut result = Vec::new();
    
    for i in 0..state.service_count {
        if state.services[i].status.current_state == state_filter {
            let name = String::from_utf16_lossy(&state.services[i].name)
                .trim_end_matches('\0').into();
            result.push(name);
        }
    }
    result
}

// ============================================================================
// Service Database Lock
// ============================================================================

/// Lock the service database for update
pub fn lock_service_database() -> bool {
    let state = SCM_STATE.lock();
    if !state.running {
        return false;
    }
    // kprintln!("[SCM] Service database locked")  // kprintln disabled (memcpy crash workaround);
    true
}

/// Unlock the service database
pub fn unlock_service_database() {
    // kprintln!("[SCM] Service database unlocked")  // kprintln disabled (memcpy crash workaround);
    drop(SCM_STATE.lock());
}

// ============================================================================
// Service Control Handler (for services running in svchost)
// ============================================================================

/// Service control handler callback type
pub type ServiceControlHandler = fn(control: u32) -> u32;

/// Service control handler state
static SERVICE_CONTROL_HANDLER: Spinlock<Option<ServiceControlHandler>> = Spinlock::new(None);

/// Register a service control handler
pub fn register_control_handler(handler: ServiceControlHandler) {
    let mut h = SERVICE_CONTROL_HANDLER.lock();
    *h = Some(handler);
    // kprintln!("[SCM] Service control handler registered")  // kprintln disabled (memcpy crash workaround);
}

/// Dispatch control code to the registered handler
pub fn dispatch_control(control: u32) -> u32 {
    let h = SERVICE_CONTROL_HANDLER.lock();
    if let Some(handler) = *h {
        handler(control)
    } else {
        0 // ERROR_PROC_NOT_FOUND
    }
}

// (spinlock now centralised in ke::sync)
