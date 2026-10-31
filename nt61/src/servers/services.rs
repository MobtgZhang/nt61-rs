//! Service control Manager (SCM)
//
//! Implements Windows Service control Manager
//! Manages Windows services defined in the registry

// SCM uses the WDK driver naming convention
// (SERVICE_* types, SERVICE_STATUS, ...).

use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicUsize, Ordering};

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Backslash character constant for path construction.
const BS: &str = "\\";

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
    Start = 0x00,
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

impl Default for ServiceStatus {
    fn default() -> Self {
        Self::new()
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
    /// Hosting process id (0 while the service has not been started).
    pub process_id: u32,
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
            process_id: 0,
        }
    }
}

impl Default for ServiceEntry {
    fn default() -> Self {
        Self::new()
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

impl Default for ScmState {
    fn default() -> Self {
        Self::new()
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

    // kprintln!("    Service control Manager initialized");
}

/// Start SCM
pub fn start() {
    // kprintln!("[SCM] Starting Service control Manager...");

    // Phase 1: Initialize
    phase1_init();

    // Phase 2: Load services
    phase2_load_services();

    // Phase 3: Start auto-start services
    phase3_start_services();

    // kprintln!("[SCM] Service control Manager started");
}

/// Phase 1: Initialize SCM
fn phase1_init() {
    // kprintln!("[SCM] Phase 1: Initializing...");
}

/// Phase 2: Load service definitions from registry
fn phase2_load_services() {
    // kprintln!("[SCM] Phase 2: Loading service definitions...");

    // Load services from:
    // HKLM\SYSTEM\CurrentControlSet\Services

    // Query service definitions from the registry
    load_services_from_registry();

    // Also add default services as fallback
    add_default_services();

    let _state = SCM_STATE.lock();
    // kprintln!("[SCM] Loaded service definitions");
}

/// Load service definitions from the registry
fn load_services_from_registry() {
    use crate::registry::cm::{enumerate_subkeys, query_dword, query_string};

    // Query the list of services from the registry
    let service_keys =
        match enumerate_subkeys("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services") {
            Some(keys) => keys,
            None => {
                // kprintln!("[SCM] No services found in registry (CM not available)");
                return;
            }
        };

    // kprintln!("[SCM] Found {} service definitions in registry", service_keys.len());

    // For each service, read its configuration
    for service_name in &service_keys {
        let service_path = format!(
            "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\{}",
            service_name
        );

        // Read Type (service type bits) and Start (start type).
        let reg_type = query_dword(&service_path, "Type").unwrap_or(0x20);
        let reg_start = query_dword(&service_path, "Start").unwrap_or(3); // DemandStart (3)

        // read ErrorControl
        let reg_error = query_dword(&service_path, "ErrorControl").unwrap_or(1); // Normal (1)

        // read ImagePath and DisplayName (optional)
        let image_path = query_string(&service_path, "ImagePath");
        let display_name =
            query_string(&service_path, "DisplayName").unwrap_or_else(|| service_name.clone());

        // Map the registry values onto the SCM entry types. Unknown
        // bits fall back to the closest Win32 meaning instead of being
        // silently dropped.
        let start_type = match reg_start {
            0 => ServiceStartType::BootStart,
            1 => ServiceStartType::SystemStart,
            2 => ServiceStartType::AutoStart,
            4 => ServiceStartType::Disabled,
            _ => ServiceStartType::DemandStart,
        };
        let service_type = if reg_type & 0x01 != 0 {
            ServiceType::KernelDriver
        } else if reg_type & 0x02 != 0 {
            ServiceType::FileSystemDriver
        } else if reg_type & 0x10 != 0 {
            ServiceType::DriverOwnProcess
        } else {
            ServiceType::ShareProcess
        };
        let error_control = match reg_error {
            0 => ServiceErrorControl::Ignore,
            2 => ServiceErrorControl::Severe,
            3 => ServiceErrorControl::Critical,
            _ => ServiceErrorControl::Normal,
        };

        // Convert the registry entry into a real ServiceEntry in the
        // SCM database. Skip duplicates so repeated calls stay
        // idempotent, and stop when the fixed-size table is full.
        let mut state = SCM_STATE.lock();
        let already_registered = state.services[..state.service_count].iter().any(|entry| {
            let utf16: Vec<u16> = service_name.chars().map(|c| c as u16).collect();
            entry.name[..utf16.len()] == *utf16
        });
        if already_registered {
            continue;
        }
        let idx = state.service_count;
        if idx >= state.services.len() {
            break;
        }
        let svc = &mut state.services[idx];
        copy_str_utf16(&mut svc.name, service_name);
        copy_str_utf16(&mut svc.display_name, &display_name);
        if let Some(ref path) = image_path {
            copy_str_utf16(&mut svc.image_path, path);
        }
        svc.service_type = service_type;
        svc.start_type = start_type;
        svc.error_control = error_control;
        svc.status.current_state = ServiceState::Stopped;
        state.service_count = idx + 1;
    }
}

/// Phase 3: Start auto-start services
fn phase3_start_services() {
    // Collect the names of auto-start services under the lock,
    // then start them one at a time through the public
    // `start_service` entry point (which re-acquires the lock
    // internally) to avoid a re-entrant deadlock.
    let names: alloc::vec::Vec<alloc::string::String> = {
        let state = SCM_STATE.lock();
        (0..state.service_count)
            .filter_map(|i| {
                let svc = &state.services[i];
                if svc.start_type == ServiceStartType::AutoStart
                    || svc.start_type == ServiceStartType::SystemStart
                    || svc.start_type == ServiceStartType::BootStart
                {
                    Some(utf16_to_string(&svc.name))
                } else {
                    None
                }
            })
            .collect()
    };
    for name in names {
        start_service(&name);
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
        (
            "RpcSs",
            "Remote Procedure Call (RPC)",
            "%SystemRoot%\\System32\\svchost.exe -k rpcss",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "EventSystem",
            "COM+ Event System",
            "%SystemRoot%\\System32\\svchost.exe -k LocalService",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "Themes",
            "Themes Service",
            "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "WinDefend",
            "Windows Defender Service",
            "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
            ServiceType::ShareProcess,
            ServiceStartType::DemandStart,
        ),
        (
            "W3SVC",
            "World Wide Web Publishing Service",
            "%SystemRoot%\\System32\\svchost.exe -k iissvcs",
            ServiceType::ShareProcess,
            ServiceStartType::DemandStart,
        ),
        (
            "TapiSrv",
            "Telephony Service",
            "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
            ServiceType::ShareProcess,
            ServiceStartType::DemandStart,
        ),
        (
            "BITS",
            "Background Intelligent Transfer Service",
            "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
            ServiceType::ShareProcess,
            ServiceStartType::DemandStart,
        ),
        (
            "CryptSvc",
            "Cryptographic Services",
            "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "DPS",
            "Diagnostic Policy Service",
            "%SystemRoot%\\System32\\svchost.exe -k LocalService",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "Dhcp",
            "DHCP Client",
            "%SystemRoot%\\System32\\svchost.exe -k NetworkService",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "Dnscache",
            "DNS Client",
            "%SystemRoot%\\System32\\svchost.exe -k NetworkService",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "LanmanServer",
            "Server",
            "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "LanmanWorkstation",
            "Workstation",
            "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
            ServiceType::ShareProcess,
            ServiceStartType::AutoStart,
        ),
        (
            "W32Time",
            "Windows Time",
            "%SystemRoot%\\System32\\svchost.exe -k LocalService",
            ServiceType::ShareProcess,
            ServiceStartType::DemandStart,
        ),
        (
            "WSearch",
            "Windows Search",
            "%SystemRoot%\\System32\\SearchIndexer.exe /Slow",
            ServiceType::ShareProcess,
            ServiceStartType::DemandStart,
        ),
    ];

    for (name, display_name, image_path, svc_type, start_type) in default_services {
        // Skip a service that is already in the database so repeated
        // init() calls are idempotent (previously a second init()
        // doubled the table, and a third filled it so new services
        // could no longer be registered).
        let already_registered = state.services[..state.service_count].iter().any(|entry| {
            let utf16: Vec<u16> = name.chars().map(|c| c as u16).collect();
            entry.name[..utf16.len()] == *utf16
        });
        if already_registered {
            continue;
        }
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

    // kprintln!("[SCM] Registered {} default services", state.service_count);
}

/// Maximum recursion depth for dependency resolution.
const MAX_DEPENDENCY_DEPTH: usize = 8;

/// Win32 error code for ERROR_SERVICE_NEVER_STARTED (1066).
const ERROR_SERVICE_NEVER_STARTED: u32 = 1066;

/// Record a start failure: transition to Stopped with error codes.
fn record_start_failure(state: &mut ScmState, idx: usize, ntstatus: u32) {
    let svc = &mut state.services[idx];
    svc.status.current_state = ServiceState::Stopped;
    svc.status.win32_exit_code = ERROR_SERVICE_NEVER_STARTED;
    svc.status.service_exit_code = ntstatus;
}

/// Copy a `&str` into a `[u16; N]` UTF-16 buffer with a null terminator.
fn copy_str_utf16(dest: &mut [u16], src: &str) {
    let max = dest.len() - 1;
    for (i, c) in src.chars().enumerate() {
        if i >= max {
            break;
        }
        dest[i] = c as u16;
    }
}

/// Internal: start a service (and its dependencies) while holding the SCM lock.
fn start_service_index_locked(state: &mut ScmState, idx: usize, depth: usize) -> bool {
    if depth > MAX_DEPENDENCY_DEPTH {
        return false;
    }
    if idx >= state.service_count {
        return false;
    }
    let svc = &state.services[idx];
    match svc.status.current_state {
        ServiceState::Running => return true,
        ServiceState::StartPending | ServiceState::StopPending => return false,
        _ => {}
    }

    let dep_indices: alloc::vec::Vec<usize> = svc
        .dependencies
        .iter()
        .take(svc.dependency_count)
        .filter_map(|dep| {
            let dep_name = utf16_to_string(dep);
            if dep_name.is_empty() {
                return None;
            }
            find_service(state, &dep_name)
        })
        .collect();

    for dep_idx in dep_indices {
        let dep_svc = &state.services[dep_idx];
        if dep_svc.status.current_state == ServiceState::Running {
            continue;
        }
        if dep_svc.start_type == ServiceStartType::BootStart
            || dep_svc.start_type == ServiceStartType::SystemStart
        {
            continue;
        }
        if !start_service_index_locked(state, dep_idx, depth + 1) {
            return false;
        }
    }

    state.services[idx].status.current_state = ServiceState::StartPending;
    state.services[idx].status.win32_exit_code = 0;
    state.services[idx].status.service_exit_code = 0;

    let svc_type = state.services[idx].service_type;
    let is_driver =
        svc_type == ServiceType::KernelDriver || svc_type == ServiceType::FileSystemDriver;

    if is_driver {
        let b = '\\';
        let path = utf16_to_string(&state.services[idx].image_path);
        let image_path = path.trim_end_matches(b);
        let pe_path = if image_path.starts_with("%SystemRoot%") {
            image_path.replacen("%SystemRoot%", "C:\\Windows", 1)
        } else if image_path.starts_with("\\\\SystemRoot\\\\") {
            image_path.replacen("\\\\SystemRoot\\\\", "C:\\Windows\\", 1)
        } else {
            alloc::string::ToString::to_string(image_path)
        };

        let pe_loaded = if pe_path.is_empty() {
            true
        } else {
            match crate::servers::smss::read_pe_from_disk(&pe_path) {
                Some(pe) => {
                    let data = core::mem::ManuallyDrop::into_inner(pe);
                    data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A
                }
                None => false,
            }
        };

        if !pe_loaded {
            record_start_failure(state, idx, 0xC000_0135);
            return false;
        }

        let name_bytes = {
            let s = utf16_to_string(&state.services[idx].name);
            let s = s.trim_end_matches(BS);
            let bytes = s.as_bytes();
            let mut buf = [0u8; 64];
            let len = bytes.len().min(64);
            buf[..len].copy_from_slice(&bytes[..len]);
            buf
        };
        let driver = crate::io::find_registered_driver(&name_bytes);
        if driver.is_null() {
            record_start_failure(state, idx, 0xC000_0135);
            return false;
        }
    } else {
        // Non-driver services need a user-mode service host that loads
        // the image named by image_path, runs it, and reports readiness
        // back to SCM. No such host exists yet, so the old behaviour of
        // allocating a PID, creating an unrelated system process and
        // marking the service Running was a fake success. Be honest:
        // verify the image is present (so the error code tells the
        // operator whether the image or the host is missing) and then
        // record a start failure with the service left Stopped.
        const BS: char = '\\';
        let path = utf16_to_string(&state.services[idx].image_path);
        let image_path = path.trim_end_matches(BS);
        if image_path.is_empty() {
            record_start_failure(state, idx, 0xC000_0135);
            return false;
        }
        let expanded = if image_path.starts_with("%SystemRoot%") {
            image_path.replacen("%SystemRoot%", "C:\\Windows", 1)
        } else if image_path.starts_with("\\\\SystemRoot\\\\") {
            image_path.replacen("\\\\SystemRoot\\\\", "C:\\Windows\\", 1)
        } else {
            alloc::string::ToString::to_string(image_path)
        };
        let image_present = match crate::servers::smss::read_pe_from_disk(&expanded) {
            Some(pe) => {
                let data = core::mem::ManuallyDrop::into_inner(pe);
                data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A
            }
            None => false,
        };
        if !image_present {
            record_start_failure(state, idx, 0xC000_0135);
            return false;
        }
        // Image exists but cannot be executed: STATUS_NOT_IMPLEMENTED.
        record_start_failure(state, idx, 0xC000_0002);
        return false;
    }

    state.services[idx].status.current_state = ServiceState::Running;
    true
}

/// Start a specific service by name
pub fn start_service(service_name: &str) -> bool {
    let mut state = SCM_STATE.lock();
    let idx = match find_service(&state, service_name) {
        Some(idx) => idx,
        None => return false,
    };
    start_service_index_locked(&mut state, idx, 0)
}

/// Stop a specific service by name
pub fn stop_service(service_name: &str) -> bool {
    let idx = {
        let state = SCM_STATE.lock();
        match find_service(&state, service_name) {
            Some(idx) => idx,
            None => return false,
        }
    };
    control_service(idx, ServiceControl::Stop)
}

/// Query service status
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
pub fn list_services() -> Vec<(String, ServiceState)> {
    let state = SCM_STATE.lock();
    let mut result = Vec::new();

    for i in 0..state.service_count {
        let name = String::from_utf16_lossy(&state.services[i].name)
            .trim_end_matches('\0')
            .into();
        result.push((name, state.services[i].status.current_state));
    }
    result
}

// ============================================================================
// Service control API
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

/// control a service (start, stop, pause, continue)
pub fn control_service(idx: usize, control: ServiceControl) -> bool {
    match control {
        ServiceControl::Stop => control_stop(idx),
        ServiceControl::Start => {
            let mut state = SCM_STATE.lock();
            start_service_index_locked(&mut state, idx, 0)
        }
        ServiceControl::Pause => control_pause(idx),
        ServiceControl::Continue => control_continue(idx),
        ServiceControl::Interrogate => true,
        ServiceControl::Shutdown => control_stop(idx),
        _ => false,
    }
}

/// Phase-based stop: validate, notify handler, transition to Stopped.
fn control_stop(idx: usize) -> bool {
    let svc_type;
    let process_id;
    // Snapshot the service name so we can look up the control handler
    // by name. The HANDLER_TABLE is indexed by registration order, not
    // by the service-database index, so table.get(idx) used to call
    // another service's handler (or miss entirely).
    let mut svc_name = [0u16; 256];
    let mut svc_name_len = 0usize;
    {
        let state = SCM_STATE.lock();
        if idx >= state.service_count {
            return false;
        }
        let svc = &state.services[idx];
        for (i, c) in svc.name.iter().enumerate() {
            if *c == 0 || i >= 256 {
                break;
            }
            svc_name[i] = *c;
            svc_name_len = i + 1;
        }
        if svc.status.current_state != ServiceState::Running {
            return false;
        }
        svc_type = svc.service_type;
        process_id = svc.process_id;
    }

    let table = HANDLER_TABLE.lock();
    let handler = table.iter().find_map(|slot| {
        let entry = slot.as_ref()?;
        if entry.name_len == svc_name_len
            && entry.name[..entry.name_len] == svc_name[..svc_name_len]
        {
            Some(entry.handler)
        } else {
            None
        }
    });
    drop(table);
    if let Some(handler) = handler {
        let _result = handler(ServiceControl::Stop as u32);
    }

    let mut state = SCM_STATE.lock();
    if idx >= state.service_count {
        return false;
    }
    let svc = &mut state.services[idx];
    svc.status.current_state = ServiceState::StopPending;

    let is_driver =
        svc_type == ServiceType::KernelDriver || svc_type == ServiceType::FileSystemDriver;
    if is_driver {
        // Kernel driver unload is managed by the PnP manager.
    } else if process_id != 0 {
        crate::ps::process::free_pid(process_id as u64);
        svc.process_id = 0;
    }

    svc.status.current_state = ServiceState::Stopped;
    true
}

fn control_pause(idx: usize) -> bool {
    let mut state = SCM_STATE.lock();
    if idx >= state.service_count {
        return false;
    }
    if state.services[idx].status.current_state != ServiceState::Running {
        return false;
    }
    state.services[idx].status.current_state = ServiceState::PausePending;
    state.services[idx].status.current_state = ServiceState::Paused;
    true
}

fn control_continue(idx: usize) -> bool {
    let mut state = SCM_STATE.lock();
    if idx >= state.service_count {
        return false;
    }
    if state.services[idx].status.current_state != ServiceState::Paused {
        return false;
    }
    state.services[idx].status.current_state = ServiceState::ContinuePending;
    state.services[idx].status.current_state = ServiceState::Running;
    true
}

/// Get service configuration
pub fn query_service_config(
    idx: usize,
) -> Option<(ServiceType, ServiceStartType, ServiceErrorControl)> {
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
                .trim_end_matches('\0')
                .into();
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
                .trim_end_matches('\0')
                .into();
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
    // kprintln!("[SCM] Service database locked");
    true
}

/// Unlock the service database
pub fn unlock_service_database() {
    // kprintln!("[SCM] Service database unlocked");
    drop(SCM_STATE.lock());
}

// ============================================================================
// Service control Handler (for services running in svchost)
// ============================================================================

/// Service control handler callback type
pub type ServiceControlHandler = fn(control: u32) -> u32;

/// Service control handler state
static SERVICE_CONTROL_HANDLER: Spinlock<Option<ServiceControlHandler>> = Spinlock::new(None);

/// Register a service control handler
pub fn register_control_handler(handler: ServiceControlHandler) {
    let mut h = SERVICE_CONTROL_HANDLER.lock();
    *h = Some(handler);
    // kprintln!("[SCM] Service control handler registered");
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

// ============================================================================
// Service main-thread API (used by sshd in SCM mode)
// ============================================================================

/// Maximum length of a service name in UTF-16 cells.
pub const SERVICE_NAME_MAX: usize = 256;

/// Maximum length of a service display name in UTF-16 cells.
pub const SERVICE_DISPLAY_NAME_MAX: usize = 256;

/// Maximum length of an image path in UTF-16 cells.
pub const SERVICE_IMAGE_PATH_MAX: usize = 260;

/// Per-service registered control handler entry. The handler is
/// invoked by `dispatch_service_control(name, code)` whenever the
/// SCM sends a control code to a running service.
#[derive(Clone, Copy)]
pub struct ServiceControlHandlerEntry {
    pub name: [u16; SERVICE_NAME_MAX],
    pub name_len: usize,
    pub handler: ServiceControlHandler,
    pub current_status: ServiceStatus,
    /// Last reported checkpoint (for hung-service detection).
    pub last_checkpoint_time_ms: u64,
}

impl ServiceControlHandlerEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0u16; SERVICE_NAME_MAX],
            name_len: 0,
            handler: empty_handler,
            current_status: ServiceStatus::new(),
            last_checkpoint_time_ms: 0,
        }
    }
}

fn empty_handler(_control: u32) -> u32 {
    0
}

const MAX_HANDLER_ENTRIES: usize = 32;
static HANDLER_TABLE: Spinlock<[Option<ServiceControlHandlerEntry>; MAX_HANDLER_ENTRIES]> =
    Spinlock::new([const { None }; MAX_HANDLER_ENTRIES]);

/// `RegisterServiceCtrlHandlerExW`-equivalent. Registers a service
/// control handler for the running service. Returns the entry's
/// index, or `None` if the table is full or the name collides.
///
/// `service_name` is a UTF-16 slice (null-terminated not required).
pub fn register_service_ctrl_handler(
    service_name: &[u16],
    handler: ServiceControlHandler,
) -> Option<usize> {
    if service_name.is_empty() || service_name.len() > SERVICE_NAME_MAX {
        return None;
    }
    let mut table = HANDLER_TABLE.lock();
    for slot in table.iter_mut() {
        if let Some(entry) = slot.as_ref() {
            if entry.name_len == service_name.len() && entry.name[..entry.name_len] == *service_name
            {
                return None;
            }
        }
    }
    for (idx, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            let mut entry = ServiceControlHandlerEntry::empty();
            entry.name_len = service_name.len();
            for (i, c) in service_name.iter().enumerate() {
                entry.name[i] = *c;
            }
            entry.handler = handler;
            entry.current_status = ServiceStatus::new();
            entry.current_status.current_state = ServiceState::StartPending;
            *slot = Some(entry);
            return Some(idx);
        }
    }
    None
}

/// `SetServiceStatus`-equivalent. Updates the cached status for a
/// service that previously registered a control handler.
pub fn set_service_status(idx: usize, status: ServiceStatus) -> bool {
    let mut table = HANDLER_TABLE.lock();
    if idx >= MAX_HANDLER_ENTRIES {
        return false;
    }
    if let Some(slot) = table[idx].as_mut() {
        slot.current_status = status;
        true
    } else {
        false
    }
}

/// Get the most recent status reported by `set_service_status`.
pub fn query_service_status_ex(idx: usize) -> Option<ServiceStatus> {
    let table = HANDLER_TABLE.lock();
    table
        .get(idx)
        .and_then(|s| s.as_ref().map(|e| e.current_status))
}

/// Dispatch a control code to a registered handler by name.
/// Returns the handler's return value, or `0` (ERROR_PROC_NOT_FOUND)
/// if no such service is registered.
pub fn dispatch_service_control(service_name: &[u16], control: u32) -> u32 {
    let table = HANDLER_TABLE.lock();
    for slot in table.iter() {
        if let Some(entry) = slot.as_ref() {
            if entry.name_len == service_name.len() && entry.name[..entry.name_len] == *service_name
            {
                let h = entry.handler;
                drop(table);
                return h(control);
            }
        }
    }
    0
}

/// Convert a control code (raw u32) to a `ServiceControl` value.
pub fn control_from_code(code: u32) -> Option<ServiceControl> {
    match code {
        0x00 => Some(ServiceControl::Start),
        0x01 => Some(ServiceControl::Stop),
        0x02 => Some(ServiceControl::Pause),
        0x03 => Some(ServiceControl::Continue),
        0x04 => Some(ServiceControl::Interrogate),
        0x05 => Some(ServiceControl::Shutdown),
        0x06 => Some(ServiceControl::ParamChange),
        0x07 => Some(ServiceControl::NetBindAdd),
        0x08 => Some(ServiceControl::NetBindRemove),
        0x09 => Some(ServiceControl::NetBindEnable),
        0x0A => Some(ServiceControl::NetBindDisable),
        _ => None,
    }
}

// ============================================================================
// Service information, dependency and control pipe API
// ============================================================================

/// Snapshot of one service database entry.
#[derive(Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub service_type: ServiceType,
    pub start_type: ServiceStartType,
    pub error_control: ServiceErrorControl,
    pub image_path: String,
    pub load_order_group: String,
    pub state: ServiceState,
    pub process_id: u32,
    pub dependencies: Vec<String>,
}

fn utf16_to_string(value: &[u16]) -> String {
    String::from_utf16_lossy(value)
        .trim_end_matches('\0')
        .into()
}

fn find_service(state: &ScmState, service_name: &str) -> Option<usize> {
    (0..state.service_count)
        .find(|&i| utf16_to_string(&state.services[i].name).eq_ignore_ascii_case(service_name))
}

/// Query the full service record (`QueryServiceEx` / `QueryServiceLockStatus`).
pub fn query_service_info(service_name: &str) -> Option<ServiceInfo> {
    let state = SCM_STATE.lock();
    let idx = find_service(&state, service_name)?;
    let svc = &state.services[idx];

    let mut dependencies = Vec::new();
    for dep in svc.dependencies.iter().take(svc.dependency_count) {
        let name = utf16_to_string(dep);
        if !name.is_empty() {
            dependencies.push(name);
        }
    }

    Some(ServiceInfo {
        name: utf16_to_string(&svc.name),
        display_name: utf16_to_string(&svc.display_name),
        service_type: svc.service_type,
        start_type: svc.start_type,
        error_control: svc.error_control,
        image_path: utf16_to_string(&svc.image_path),
        load_order_group: utf16_to_string(&svc.load_order_group),
        state: svc.status.current_state,
        process_id: svc.process_id,
        dependencies,
    })
}

/// Query every service: `(name, state, hosting process id)`.
pub fn query_all_services() -> Vec<(String, ServiceState, u32)> {
    let state = SCM_STATE.lock();
    let mut result = Vec::new();
    for i in 0..state.service_count {
        result.push((
            utf16_to_string(&state.services[i].name),
            state.services[i].status.current_state,
            state.services[i].process_id,
        ));
    }
    result
}

/// Check whether a service may start: every dependency must already be
/// running, or be a boot/system-start driver that the SCM starts earlier
/// (SCM dependency rules, see MSDN `StartService` and ReactOS
/// `services.exe` dependency handling).
pub fn check_dependencies(service_name: &str) -> bool {
    let state = SCM_STATE.lock();
    let idx = match find_service(&state, service_name) {
        Some(idx) => idx,
        None => return false,
    };
    let svc = &state.services[idx];

    if svc.dependency_count == 0 {
        return true;
    }

    for dep in svc.dependencies.iter().take(svc.dependency_count) {
        let dep_name = utf16_to_string(dep);
        if dep_name.is_empty() {
            continue;
        }
        let dep_idx = match find_service(&state, &dep_name) {
            Some(idx) => idx,
            None => return false,
        };
        let dep_svc = &state.services[dep_idx];
        let satisfied = dep_svc.status.current_state == ServiceState::Running
            || dep_svc.start_type == ServiceStartType::BootStart
            || dep_svc.start_type == ServiceStartType::SystemStart;
        if !satisfied {
            return false;
        }
    }
    true
}

static CONTROL_PIPE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// create the SCM control pipe for a service (`CreateServicePipe`).
/// Returns the pipe handle, or `None` when the service is unknown.
pub fn create_service_pipe(service_name: &str) -> Option<usize> {
    let state = SCM_STATE.lock();
    find_service(&state, service_name)?;
    // Handles start at 1 so that 0 keeps meaning "no pipe".
    Some(CONTROL_PIPE_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_code_round_trip() {
        assert_eq!(control_from_code(0x01), Some(ServiceControl::Stop));
        assert_eq!(control_from_code(0x05), Some(ServiceControl::Shutdown));
        assert_eq!(control_from_code(0xFF), None);
    }

    #[test]
    fn set_service_status_updates_state() {
        let name: [u16; 4] = ['t' as u16, 'e' as u16, 's' as u16, 't' as u16];
        let idx = register_service_ctrl_handler(&name, empty_handler).unwrap();
        let mut st = ServiceStatus::new();
        st.current_state = ServiceState::Running;
        assert!(set_service_status(idx, st));
        let got = query_service_status_ex(idx).unwrap();
        assert_eq!(got.current_state, ServiceState::Running);
    }

    #[test]
    fn dispatch_unknown_service_returns_zero() {
        let bogus: [u16; 3] = ['x' as u16, 'y' as u16, 'z' as u16];
        assert_eq!(dispatch_service_control(&bogus, 0x01), 0);
    }
}
