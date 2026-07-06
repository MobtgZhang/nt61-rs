//! Intel i915 DDI (Digital Display Interface) Port Initialization
//
//! Configures the DDI ports for HDMI, DisplayPort, and eDP outputs.
//! DDI ports are used on modern Intel GPUs starting from Ivy Bridge.
//
//! Clean-room implementation based on Intel Graphics PRM.

use alloc::vec::Vec;
use crate::drivers::video::log;
use crate::drivers::video::intel::i915_pll;

/// DDI port identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdiPort {
    /// DDI A (typically used for HDMI/DP)
    DdiA = 0,
    /// DDI B
    DdiB = 1,
    /// DDI C
    DdiC = 2,
    /// DDI D (often used for eDP on laptops)
    DdiD = 3,
    /// DDI E (reserved)
    DdiE = 4,
    /// DDI F (reserved)
    DdiF = 5,
    /// DDI G (reserved)
    DdiG = 6,
    /// DDI H (reserved)
    DdiH = 7,
    /// DDI T (TC ports)
    DdiT = 8,
}

impl DdiPort {
    /// Get the register offset for DDI buffer control
    pub fn buf_ctl_reg(&self) -> u32 {
        match self {
            DdiPort::DdiA => 0x64100,
            DdiPort::DdiB => 0x64140,
            DdiPort::DdiC => 0x64180,
            DdiPort::DdiD => 0x641C0,
            DdiPort::DdiT => 0x64200,
            _ => 0x64100,
        }
    }
    
    /// Get the register offset for DDI AUX control
    pub fn aux_ctl_reg(&self) -> u32 {
        match self {
            DdiPort::DdiA => 0x64104,
            DdiPort::DdiB => 0x64144,
            DdiPort::DdiC => 0x64184,
            DdiPort::DdiD => 0x641C4,
            DdiPort::DdiT => 0x64204,
            _ => 0x64104,
        }
    }
    
    /// Get the register offset for DDI_BUF_TRANS
    pub fn buf_trans_reg(&self) -> u32 {
        match self {
            DdiPort::DdiA => 0x64E00,
            DdiPort::DdiB => 0x64E60,
            DdiPort::DdiC => 0x64EC0,
            DdiPort::DdiD => 0x64F20,
            DdiPort::DdiT => 0x64F80,
            _ => 0x64E00,
        }
    }
}

/// Port type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortType {
    /// Analog VGA
    AnalogVga,
    /// DisplayPort
    DisplayPort,
    /// HDMI
    HDMI,
    /// Embedded DisplayPort
    EmbeddedDp,
    /// Digital Video Out
    Dvo,
    /// Unknown
    Unknown,
}

/// DDI port state
#[derive(Debug, Clone)]
pub struct DdiPortState {
    pub port: DdiPort,
    pub port_type: PortType,
    pub enabled: bool,
    pub has_hotplug: bool,
}

/// DDI buffer control bits
const DDI_BUF_CTL_ENABLE: u32 = 1 << 31;
const DDI_BUF_CTL_PORT_WIDTH_1: u32 = 0 << 26;
const DDI_BUF_CTL_PORT_WIDTH_2: u32 = 1 << 26;
const DDI_BUF_CTL_PORT_WIDTH_4: u32 = 2 << 26;

const DDI_BUF_CTL_IDLE_DETECT: u32 = 1 << 7;

/// DDI AUX control bits
const DDI_AUX_CTL_SEND_BUSY: u32 = 1 << 31;
const DDI_AUX_CTL_SEND_DONE: u32 = 1 << 30;
const DDI_AUX_CTL_TIMEOUT_500US: u32 = 0 << 28;

const DDI_AUX_CTL_REPLY_ACK: u32 = 1 << 24;


/// Hotplug status bits
const HOTPLUG_INT_STATUS_A: u32 = 1 << 0;
const HOTPLUG_INT_STATUS_B: u32 = 1 << 2;
const HOTPLUG_INT_STATUS_C: u32 = 1 << 4;
const HOTPLUG_INT_STATUS_D: u32 = 1 << 6;
const HOTPLUG_INT_STATUS_TC1: u32 = 1 << 10;




/// Detect if a monitor is connected to a DDI port
pub fn detect_monitor(mmio: u64, port: DdiPort) -> bool {
    let buf_ctl = port.buf_ctl_reg();
    
    unsafe {
        let val = core::ptr::read_volatile((mmio + buf_ctl as u64) as *const u32);
        
        // Check if port is enabled and not idle
        (val & DDI_BUF_CTL_ENABLE) != 0 && (val & DDI_BUF_CTL_IDLE_DETECT) == 0
    }
}

/// Read SFUSE (Silicon Fuse) strap for port detection
pub fn read_sfuse_strap(mmio: u64) -> u32 {
    // SFUSE register varies by generation
    // On modern platforms it's at 0x20100 or similar
    unsafe {
        core::ptr::read_volatile((mmio + 0x20100) as *const u32)
    }
}

/// Get the port type based on platform configuration
pub fn get_port_type(port: DdiPort) -> PortType {
    match port {
        DdiPort::DdiA => PortType::DisplayPort, // Most common
        DdiPort::DdiB => PortType::HDMI,
        DdiPort::DdiC => PortType::DisplayPort,
        DdiPort::DdiD => PortType::EmbeddedDp,
        DdiPort::DdiT => PortType::DisplayPort, // USB-C/Thunderbolt
        _ => PortType::Unknown,
    }
}

/// Configure DDI buffer for DisplayPort output
pub fn config_dp_buffer(mmio: u64, port: DdiPort, lane_count: u8) {
    let buf_ctl = port.buf_ctl_reg();
    let buf_trans = port.buf_trans_reg();
    
    // Configure buffer enable
    let width_ctl = match lane_count {
        1 => DDI_BUF_CTL_PORT_WIDTH_1,
        2 => DDI_BUF_CTL_PORT_WIDTH_2,
        4 => DDI_BUF_CTL_PORT_WIDTH_4,
        _ => DDI_BUF_CTL_PORT_WIDTH_4,
    };
    
    let buf_ctl_val = DDI_BUF_CTL_ENABLE | width_ctl;
    
    unsafe {
        // Disable buffer first
        core::ptr::write_volatile(
            (mmio + buf_ctl as u64) as *mut u32,
            0,
        );
        
        // Configure buffer translation entries
        // Entry 0: default entry for DP
        core::ptr::write_volatile(
            (mmio + buf_trans as u64) as *mut u32,
            0x7F7F7F7F, // Default balanced entry
        );
        
        // Enable buffer
        core::ptr::write_volatile(
            (mmio + buf_ctl as u64) as *mut u32,
            buf_ctl_val,
        );
    }
    
    log::video_log("i915-ddi", &alloc::format!("Port {:?} buffer configured for {} lanes", port, lane_count));
}

/// Configure DDI buffer for HDMI output
pub fn config_hdmi_buffer(mmio: u64, port: DdiPort) {
    let buf_ctl = port.buf_ctl_reg();
    let buf_trans = port.buf_trans_reg();
    
    unsafe {
        // Disable buffer first
        core::ptr::write_volatile(
            (mmio + buf_ctl as u64) as *mut u32,
            0,
        );
        
        // Configure buffer translation for HDMI
        // Use TMDS character rate entries
        for i in 0..8 {
            core::ptr::write_volatile(
                (mmio + buf_trans as u64 + (i * 4) as u64) as *mut u32,
                0x5F5F5F5F, // TMDS compatible entry
            );
        }
        
        // Enable buffer with 4 lanes
        core::ptr::write_volatile(
            (mmio + buf_ctl as u64) as *mut u32,
            DDI_BUF_CTL_ENABLE | DDI_BUF_CTL_PORT_WIDTH_4,
        );
    }
    
    log::video_log("i915-ddi", &alloc::format!("Port {:?} configured for HDMI", port));
}

/// Configure DDI buffer for eDP output
pub fn config_edp_buffer(mmio: u64, port: DdiPort, lane_count: u8) {
    let buf_ctl = port.buf_ctl_reg();
    
    let width_ctl = match lane_count {
        1 => DDI_BUF_CTL_PORT_WIDTH_1,
        2 => DDI_BUF_CTL_PORT_WIDTH_2,
        4 => DDI_BUF_CTL_PORT_WIDTH_4,
        _ => DDI_BUF_CTL_PORT_WIDTH_4,
    };
    
    unsafe {
        // Configure for eDP
        core::ptr::write_volatile(
            (mmio + buf_ctl as u64) as *mut u32,
            DDI_BUF_CTL_ENABLE | width_ctl,
        );
    }
    
    log::video_log("i915-ddi", &alloc::format!("Port {:?} configured for eDP ({} lanes)", port, lane_count));
}

/// Enable DDI port
pub fn enable_port(mmio: u64, port: DdiPort, port_type: PortType, lane_count: u8) {
    match port_type {
        PortType::DisplayPort => config_dp_buffer(mmio, port, lane_count),
        PortType::HDMI => config_hdmi_buffer(mmio, port),
        PortType::EmbeddedDp => config_edp_buffer(mmio, port, lane_count),
        _ => {}
    }
}

/// Disable DDI port
pub fn disable_port(mmio: u64, port: DdiPort) {
    let buf_ctl = port.buf_ctl_reg();
    
    unsafe {
        core::ptr::write_volatile(
            (mmio + buf_ctl as u64) as *mut u32,
            0,
        );
    }
    
    log::video_log("i915-ddi", &alloc::format!("Port {:?} disabled", port));
}

/// Read hotplug status
pub fn read_hotplug_status(mmio: u64) -> u32 {
    // Hotplug status register location varies by generation
    unsafe {
        core::ptr::read_volatile((mmio + 0xC4030) as *const u32)
    }
}

/// Clear hotplug interrupt
pub fn clear_hotplug_interrupt(mmio: u64, port: DdiPort) {
    let mask = match port {
        DdiPort::DdiA => HOTPLUG_INT_STATUS_A,
        DdiPort::DdiB => HOTPLUG_INT_STATUS_B,
        DdiPort::DdiC => HOTPLUG_INT_STATUS_C,
        DdiPort::DdiD => HOTPLUG_INT_STATUS_D,
        DdiPort::DdiT => HOTPLUG_INT_STATUS_TC1,
        _ => 0,
    };
    
    if mask != 0 {
        unsafe {
            core::ptr::write_volatile(
                (mmio + 0xC4038) as *mut u32,
                mask,
            );
        }
    }
}

/// Perform AUX channel transaction
pub fn aux_transaction(
    mmio: u64,
    port: DdiPort,
    cmd: u8,
    addr: u32,
    write_data: &[u8],
    read_len: usize,
) -> Result<Vec<u8>, &'static str> {
    let aux_ctl = port.aux_ctl_reg();
    
    // Wait for any previous transaction to complete
    for _ in 0..1000 {
        unsafe {
            let status = core::ptr::read_volatile((mmio + aux_ctl as u64) as *const u32);
            if status & DDI_AUX_CTL_SEND_BUSY == 0 {
                break;
            }
        }
        core::hint::spin_loop();
    }
    
    // Build command
    // Bits 31-28: Command type
    // Bits 27-20: Message length
    // Bits 19-8: I2C address or DPCD address
    // Bits 7-0: Address bytes
    
    let cmd_val = (cmd as u32) << 28;
    let len_val = ((write_data.len() as u32) << 16) | ((read_len as u32) << 8);
    let addr_val = addr & 0xFFFF;
    
    // Write command to AUX DATA register (varies by generation)
    unsafe {
        core::ptr::write_volatile(
            (mmio + aux_ctl as u64 + 4) as *mut u32,
            cmd_val | len_val | addr_val,
        );
    }
    
    // Write data if any
    for (i, &byte) in write_data.iter().enumerate() {
        unsafe {
            core::ptr::write_volatile(
                (mmio + aux_ctl as u64 + 8 + (i as u64 * 4)) as *mut u32,
                byte as u32,
            );
        }
    }
    
    // Start transaction
    unsafe {
        core::ptr::write_volatile(
            (mmio + aux_ctl as u64) as *mut u32,
            DDI_AUX_CTL_SEND_BUSY | DDI_AUX_CTL_TIMEOUT_500US,
        );
    }
    
    // Wait for completion
    for _ in 0..5000 {
        unsafe {
            let status = core::ptr::read_volatile((mmio + aux_ctl as u64) as *const u32);
            if status & DDI_AUX_CTL_SEND_DONE != 0 {
                // Check for ACK
                if status & DDI_AUX_CTL_REPLY_ACK != 0 {
                    // Read response data
                    let mut response = Vec::with_capacity(read_len);
                    for i in 0..read_len.min(16) {
                        let val = core::ptr::read_volatile(
                            (mmio + aux_ctl as u64 + 8 + (i as u64 * 4)) as *const u32
                        );
                        response.push(val as u8);
                    }
                    return Ok(response);
                } else {
                    return Err("AUX NACK");
                }
            }
        }
        core::hint::spin_loop();
    }
    
    Err("AUX timeout")
}

/// Read DPCD register via AUX
pub fn dpcd_read(mmio: u64, port: DdiPort, addr: u32) -> Result<u8, &'static str> {
    let data = aux_transaction(mmio, port, 0x9, addr, &[], 1)?;
    Ok(data.first().copied().unwrap_or(0))
}

/// Write DPCD register via AUX
pub fn dpcd_write(mmio: u64, port: DdiPort, addr: u32, value: u8) -> Result<(), &'static str> {
    aux_transaction(mmio, port, 0x8, addr, &[value], 0)?;
    Ok(())
}

/// Initialize the DDI subsystem
pub fn init() {
    log::video_log("i915-ddi", "Digital display interface ready");
}

/// Probe for available DDI ports
pub fn probe_ports(mmio: u64) -> Vec<DdiPortState> {
    let mut ports = Vec::new();
    let sfuse = read_sfuse_strap(mmio);
    // Publish the SFUSE strap for diagnostics, then use a derived value
    // (number of DDI ports enabled) to drive heuristics further down.
    LAST_SFUSE.store(sfuse as u32, core::sync::atomic::Ordering::Relaxed);
    let port_count_hint = ((sfuse & 0xF) as usize).max(4).min(8);

    log::video_log("i915-ddi", &alloc::format!("SFUSE strap: 0x{:08x}", sfuse));
    LAST_PORT_HINT.store(port_count_hint as u32, core::sync::atomic::Ordering::Relaxed);
    ports.reserve(port_count_hint);

    // Check each port for presence
    let port_list = [
        DdiPort::DdiA,
        DdiPort::DdiB,
        DdiPort::DdiC,
        DdiPort::DdiD,
    ];
    
    for port in port_list {
        let port_type = get_port_type(port);
        let has_monitor = detect_monitor(mmio, port);
        
        ports.push(DdiPortState {
            port,
            port_type,
            enabled: has_monitor,
            has_hotplug: true, // Most DDI ports support hotplug
        });
        
        if has_monitor {
            log::video_log("i915-ddi", &alloc::format!("Port {:?} ({:?}): connected", port, port_type));
        }
    }

    ports
}

static LAST_SFUSE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static LAST_PORT_HINT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Return the latest SFUSE strap value read by `probe_ports()`.
pub fn last_sfuse() -> u32 {
    LAST_SFUSE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Return the latest port-count hint derived from the SFUSE strap.
pub fn last_port_hint() -> u32 {
    LAST_PORT_HINT.load(core::sync::atomic::Ordering::Relaxed)
}

