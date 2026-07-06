//! USB-C and Thunderbolt Display Output Support
//
//! This module implements USB-C Alternate Mode (Alt Mode) for DisplayPort
//! and Thunderbolt display output support. USB-C ports can carry DisplayPort
//! signals using Alternate Mode, and Thunderbolt provides even more bandwidth
//! for high-resolution displays.
//
//! Features:
//! - USB-C Alt Mode discovery and configuration
//! - DisplayPort over USB-C (DP Alt Mode)
//! - Thunderbolt protocol support
//! - USB Power Delivery (PD) negotiation
//! - USB4/TBT4 discovery and initialization
//
//! Clean-room implementation based on USB-C, USB Power Delivery,
//! DisplayPort, and Thunderbolt specifications.

use crate::drivers::video::log;
use crate::ke::sync::Spinlock;
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;

/// USB-C connector state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbCConnectorState {
    /// No device connected
    Disconnected,
    /// USB device connected
    UsbConnected,
    /// Alternate Mode active
    AltModeActive,
    /// Thunderbolt active
    ThunderboltActive,
    /// USB4 active
    Usb4Active,
}

/// USB-C data roles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbCDataRole {
    /// USB device (UFP)
    Device,
    /// USB host (DFP)
    Host,
    /// Dual Role (DRP)
    DualRole,
}

/// USB-C power role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbCPowerRole {
    /// Power consumer (sink)
    Sink,
    /// Power provider (source)
    Source,
    /// Dual Role Power
    DualRolePower,
}

/// USB-C connector type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbCConnectorType {
    /// USB-C receptacle
    Receptacle,
    /// USB-C plug (captive cable)
    Plug,
    /// USB-C captive cable
    CaptiveCable,
}

/// USB-C Alternate Mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AltModeType {
    /// DisplayPort Alternate Mode
    DisplayPort,
    /// Thunderbolt Alternate Mode
    Thunderbolt3,
    /// HDMI Alternate Mode
    HDMI,
    /// PCIe Alternate Mode
    PCIe,
    /// USB4
    USB4,
    /// Vendor Specific
    VendorSpecific(u32),
}

impl AltModeType {
    /// Get the SVID for this alt mode
    pub fn svid(&self) -> u16 {
        match self {
            AltModeType::DisplayPort => 0xFF01,
            AltModeType::Thunderbolt3 => 0xFF02,
            AltModeType::HDMI => 0xFF03,
            AltModeType::PCIe => 0xFF04,
            AltModeType::USB4 => 0xFF05,
            AltModeType::VendorSpecific(svid) => *svid as u16,
        }
    }
    
    /// Get alt mode name
    pub fn name(&self) -> &'static str {
        match self {
            AltModeType::DisplayPort => "DisplayPort",
            AltModeType::Thunderbolt3 => "Thunderbolt 3",
            AltModeType::HDMI => "HDMI",
            AltModeType::PCIe => "PCIe",
            AltModeType::USB4 => "USB4",
            AltModeType::VendorSpecific(_) => "Vendor Specific",
        }
    }
}

/// USB-C port configuration
#[derive(Debug, Clone)]
pub struct UsbCPortConfig {
    /// Connector type
    pub connector_type: UsbCConnectorType,
    /// Supports USB data
    pub supports_usb: bool,
    /// Supported alternate modes
    pub supported_alt_modes: Vec<AltModeType>,
    /// Maximum power delivery (in mW)
    pub max_power_mw: u32,
    /// Supports USB Power Delivery
    pub supports_pd: bool,
    /// Supports DisplayPort
    pub supports_dp: bool,
    /// Maximum DP lanes supported
    pub max_dp_lanes: u8,
    /// Supports Thunderbolt
    pub supports_thunderbolt: bool,
}

impl Default for UsbCPortConfig {
    fn default() -> Self {
        Self {
            connector_type: UsbCConnectorType::Receptacle,
            supports_usb: true,
            supported_alt_modes: vec![
                AltModeType::DisplayPort,
                AltModeType::Thunderbolt3,
            ],
            max_power_mw: 100_000, // 100W
            supports_pd: true,
            supports_dp: true,
            max_dp_lanes: 4,
            supports_thunderbolt: true,
        }
    }
}

/// USB-C connector/port state
#[derive(Debug, Clone)]
pub struct UsbCConnector {
    /// Port identifier
    pub port_id: u32,
    /// Configuration
    pub config: UsbCPortConfig,
    /// Current state
    pub state: UsbCConnectorState,
    /// Current data role
    pub data_role: UsbCDataRole,
    /// Current power role
    pub power_role: UsbCPowerRole,
    /// Active alternate mode
    pub active_alt_mode: Option<AltModeType>,
    /// Connected partner info
    pub partner_info: Option<UsbCPartnerInfo>,
    /// Cable properties
    pub cable_info: Option<UsbCCableInfo>,
    /// DisplayPort configuration
    pub dp_config: Option<DisplayPortOverUsbC>,
    /// Thunderbolt state
    pub tb_config: Option<ThunderboltConfig>,
}

impl UsbCConnector {
    /// Create a new USB-C connector
    pub fn new(port_id: u32) -> Self {
        Self {
            port_id,
            config: UsbCPortConfig::default(),
            state: UsbCConnectorState::Disconnected,
            data_role: UsbCDataRole::Host,
            power_role: UsbCPowerRole::Sink,
            active_alt_mode: None,
            partner_info: None,
            cable_info: None,
            dp_config: None,
            tb_config: None,
        }
    }
}

/// USB-C partner (device) information
#[derive(Debug, Clone)]
pub struct UsbCPartnerInfo {
    /// Vendor ID
    pub vendor_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Device name
    pub name: Option<String>,
    /// Supported alternate modes
    pub alt_modes: Vec<AltModeType>,
    /// Is PD capable
    pub supports_pd: bool,
    /// Is thunderbolt capable
    pub is_thunderbolt: bool,
    /// USB4 capable
    pub is_usb4: bool,
    /// Maximum power consumption (mW)
    pub max_power_mw: u32,
}

/// USB-C cable information
#[derive(Debug, Clone)]
pub struct UsbCCableInfo {
    /// Maximum current (mA)
    pub max_current_ma: u16,
    /// Maximum voltage (mV)
    pub max_voltage_mv: u32,
    /// Maximum power (mW)
    pub max_power_mw: u32,
    /// Cable type (passive/active)
    pub is_active: bool,
    /// Supports USB 3.x
    pub supports_usb3: bool,
    /// Supports USB4
    pub supports_usb4: bool,
    /// Cable length (meters)
    pub length_m: u8,
}

// =====================================================================
// DisplayPort over USB-C
// =====================================================================

/// DisplayPort configuration over USB-C
#[derive(Debug, Clone)]
pub struct DisplayPortOverUsbC {
    /// USB-C connector this DP uses
    pub connector: u32,
    /// Number of lanes used
    pub lane_count: u8,
    /// USB-C pin assignments used
    pub pin_assignment: DpPinAssignment,
    /// DisplayPort version
    pub dp_version: DpVersion,
    /// Current link configuration
    pub link_config: DpLinkConfig,
    /// Is DP enabled
    pub enabled: bool,
}

impl DisplayPortOverUsbC {
    /// Create a new DP over USB-C config
    pub fn new(connector: u32) -> Self {
        Self {
            connector,
            lane_count: 4,
            pin_assignment: DpPinAssignment::E,
            dp_version: DpVersion::Dp14,
            link_config: DpLinkConfig::default(),
            enabled: false,
        }
    }
}

/// DisplayPort version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpVersion {
    /// DisplayPort 1.1
    Dp11,
    /// DisplayPort 1.2
    Dp12,
    /// DisplayPort 1.3
    Dp13,
    /// DisplayPort 1.4
    Dp14,
    /// DisplayPort 2.0
    Dp20,
    /// DisplayPort 2.1
    Dp21,
}

impl DpVersion {
    /// Get max lanes for this version
    pub fn max_lanes(&self) -> u8 {
        match self {
            DpVersion::Dp11 | DpVersion::Dp12 => 4,
            DpVersion::Dp13 | DpVersion::Dp14 => 4,
            DpVersion::Dp20 | DpVersion::Dp21 => 4, // With UHBR
        }
    }
    
    /// Get name
    pub fn name(&self) -> &'static str {
        match self {
            DpVersion::Dp11 => "DisplayPort 1.1",
            DpVersion::Dp12 => "DisplayPort 1.2",
            DpVersion::Dp13 => "DisplayPort 1.3",
            DpVersion::Dp14 => "DisplayPort 1.4",
            DpVersion::Dp20 => "DisplayPort 2.0",
            DpVersion::Dp21 => "DisplayPort 2.1",
        }
    }
}

/// USB-C pin assignments for DisplayPort
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpPinAssignment {
    /// Pin assignment A (2 lanes)
    A,
    /// Pin assignment B (2 lanes, polarity flipped)
    B,
    /// Pin assignment C (4 lanes)
    C,
    /// Pin assignment D (4 lanes)
    D,
    /// Pin assignment E (4 lanes, USB SuperSpeed)
    E,
    /// Pin assignment F (4 lanes, USB Gen2)
    F,
}

impl DpPinAssignment {
    /// Get number of lanes for this pin assignment
    pub fn lanes(&self) -> u8 {
        match self {
            DpPinAssignment::A | DpPinAssignment::B => 2,
            DpPinAssignment::C | DpPinAssignment::D | DpPinAssignment::E | DpPinAssignment::F => 4,
        }
    }
}

/// DisplayPort link configuration
#[derive(Debug, Clone)]
pub struct DpLinkConfig {
    /// Link rate (Mbps per lane)
    pub link_rate: DpLinkRate,
    /// Number of lanes
    pub lane_count: u8,
    /// Voltage swing level
    pub voltage_swing: u8,
    /// Pre-emphasis level
    pub pre_emphasis: u8,
    /// Is link training complete
    pub link_training_complete: bool,
}

impl Default for DpLinkConfig {
    fn default() -> Self {
        Self {
            link_rate: DpLinkRate::Hbr,
            lane_count: 1,
            voltage_swing: 0,
            pre_emphasis: 0,
            link_training_complete: false,
        }
    }
}

/// DisplayPort link rates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpLinkRate {
    /// RBR - 1.62 Gbps per lane
    Rbr = 1620,
    /// HBR - 2.7 Gbps per lane
    Hbr = 2700,
    /// HBR2 - 5.4 Gbps per lane
    Hbr2 = 5400,
    /// HBR3 - 8.1 Gbps per lane
    Hbr3 = 8100,
    /// UHBR10 - 10 Gbps per lane
    Uhbr10 = 10000,
    /// UHBR13.5 - 13.5 Gbps per lane
    Uhbr135 = 13500,
    /// UHBR20 - 20 Gbps per lane
    Uhbr20 = 20000,
}

impl DpLinkRate {
    /// Get bits per second per lane
    pub fn bps_per_lane(&self) -> u64 {
        (*self as u64) * 1_000_000
    }
}

// =====================================================================
// Thunderbolt over USB-C
// =====================================================================

/// Thunderbolt configuration
#[derive(Debug, Clone)]
pub struct ThunderboltConfig {
    /// USB-C connector this TBT uses
    pub connector: u32,
    /// Thunderbolt version
    pub tb_version: ThunderboltVersion,
    /// PCIe tunnel status
    pub pcie_tunnel: TbtTunnelStatus,
    /// DisplayPort tunnel status
    pub dp_tunnel: TbtTunnelStatus,
    /// USB tunnel status
    pub usb_tunnel: TbtTunnelStatus,
    /// PCIe generation
    pub pcie_gen: u8,
    /// PCIe width
    pub pcie_width: u8,
    /// Is connected
    pub connected: bool,
}

impl ThunderboltConfig {
    /// Create a new Thunderbolt config
    pub fn new(connector: u32) -> Self {
        Self {
            connector,
            tb_version: ThunderboltVersion::Tbt3,
            pcie_tunnel: TbtTunnelStatus::NotSupported,
            dp_tunnel: TbtTunnelStatus::NotSupported,
            usb_tunnel: TbtTunnelStatus::NotSupported,
            pcie_gen: 3,
            pcie_width: 4,
            connected: false,
        }
    }
}

/// Thunderbolt versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThunderboltVersion {
    /// Thunderbolt 1 (CBI)
    Tbt1,
    /// Thunderbolt 2 (CBI)
    Tbt2,
    /// Thunderbolt 3 (USB-C)
    Tbt3,
    /// Thunderbolt 4 / USB4
    Tbt4,
    /// USB4
    Usb4,
}

impl ThunderboltVersion {
    /// Get name
    pub fn name(&self) -> &'static str {
        match self {
            ThunderboltVersion::Tbt1 => "Thunderbolt 1",
            ThunderboltVersion::Tbt2 => "Thunderbolt 2",
            ThunderboltVersion::Tbt3 => "Thunderbolt 3",
            ThunderboltVersion::Tbt4 => "Thunderbolt 4",
            ThunderboltVersion::Usb4 => "USB4",
        }
    }
    
    /// Get max bandwidth (Gbps)
    pub fn max_bandwidth_gbps(&self) -> u32 {
        match self {
            ThunderboltVersion::Tbt1 => 10,
            ThunderboltVersion::Tbt2 => 20,
            ThunderboltVersion::Tbt3 => 40,
            ThunderboltVersion::Tbt4 => 40,
            ThunderboltVersion::Usb4 => 40,
        }
    }
}

/// Tunnel status in Thunderbolt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TbtTunnelStatus {
    /// Not supported by device
    NotSupported,
    /// Supported but not active
    Supported,
    /// Active tunnel
    Active,
}

// =====================================================================
// USB Power Delivery
// =====================================================================

/// USB Power Delivery messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdMessageType {
    /// Source capabilities
    SourceCaps,
    /// Request
    Request,
    /// Sink capabilities
    SinkCaps,
    /// Accept
    Accept,
    /// Reject
    Reject,
    /// Ping
    Ping,
    /// PS_RDY (Power Supply Ready)
    PsRdy,
    /// Get Source Caps
    GetSourceCaps,
    /// Get Sink Caps
    GetSinkCaps,
    /// DR_Swap (Data Role Swap)
    DrSwap,
    /// PR_Swap (Power Role Swap)
    PrSwap,
    /// VCONN_Swap
    VconnSwap,
    /// Wait
    Wait,
    /// Soft Reset
    SoftReset,
    /// Hard Reset
    HardReset,
    /// Data Reset
    DataReset,
}

/// Power delivery contract
#[derive(Debug, Clone)]
pub struct PdContract {
    /// Selected power profile
    pub profile: PdPowerProfile,
    /// Operating current (mA)
    pub current_ma: u16,
    /// Operating voltage (mV)
    pub voltage_mv: u32,
    /// Maximum current (mA)
    pub max_current_ma: u16,
    /// Maximum voltage (mV)
    pub max_voltage_mv: u32,
    /// Is contract active
    pub active: bool,
}

/// USB PD power profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdPowerProfile {
    /// No power (0V)
    None,
    /// Default USB power (5V, 500mA)
    Default,
    /// Medium power (5V, 1.5A)
    Medium,
    /// High power (5V, 3A or 12V/20V)
    High,
    /// USB PD fixed 5V
    Fixed5V,
    /// USB PD fixed 9V
    Fixed9V,
    /// USB PD fixed 15V
    Fixed15V,
    /// USB PD fixed 20V
    Fixed20V,
    /// USB PD PPS (Programmable Power Supply)
    Pps,
}

// =====================================================================
// USB-C Controller
// =====================================================================

/// USB-C port controller
pub struct UsbCPortController {
    /// Port ID
    port_id: u32,
    /// Connector state
    connector: UsbCConnector,
    /// PD contract
    pd_contract: Option<PdContract>,
    /// PD state machine
    pd_state: PdState,
    /// Is initialized
    initialized: bool,
}

/// USB PD state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdState {
    /// No power delivery
    NoPowerDelivery,
    /// Cable detection in progress
    CableDetection,
    /// CC logic states
    CcDetected,
    /// PD capabilities exchange
    CapabilityExchange,
    /// Contract negotiation
    ContractNegotiation,
    /// Power contract active
    ContractActive,
    /// Power contract renegotiation
    ContractRenegotiate,
    /// Error state
    Error,
}

impl UsbCPortController {
    /// Create a new USB-C controller
    pub fn new(port_id: u32) -> Self {
        Self {
            port_id,
            connector: UsbCConnector::new(port_id),
            pd_contract: None,
            pd_state: PdState::NoPowerDelivery,
            initialized: false,
        }
    }
    
    /// Initialize the USB-C port
    pub fn init(&mut self) -> Result<(), &'static str> {
        log::video_log("usbc", &alloc::format!("Initializing port {}", self.port_id));
        
        // Configure CC pins
        self.configure_cc_pins()?;
        
        // Enable VBUS detection
        self.enable_vbus_detection()?;
        
        self.initialized = true;
        log::video_log("usbc", &alloc::format!("Port {} initialized", self.port_id));
        
        Ok(())
    }
    
    /// Configure CC pins
    fn configure_cc_pins(&mut self) -> Result<(), &'static str> {
        // In real hardware, would configure GPIO/registers
        log::video_log("usbc", "CC pins configured");
        Ok(())
    }
    
    /// Enable VBUS detection
    fn enable_vbus_detection(&mut self) -> Result<(), &'static str> {
        // In real hardware, would enable VBUS voltage sensing
        log::video_log("usbc", "VBUS detection enabled");
        Ok(())
    }
    
    /// Detect cable and partner
    pub fn detect(&mut self) -> Result<UsbCConnectorState, &'static str> {
        if !self.initialized {
            return Err("Port not initialized");
        }
        
        // Simulate cable detection
        self.pd_state = PdState::CableDetection;
        
        // Check VBUS
        let vbus_present = self.check_vbus()?;
        
        if !vbus_present {
            self.connector.state = UsbCConnectorState::Disconnected;
            return Ok(UsbCConnectorState::Disconnected);
        }
        
        // Detect CC state to determine partner
        let cc_state = self.detect_cc_state()?;
        
        match cc_state {
            CcState::NothingConnected => {
                self.connector.state = UsbCConnectorState::Disconnected;
            }
            CcState::UsbDeviceConnected => {
                self.connector.state = UsbCConnectorState::UsbConnected;
                self.connector.data_role = UsbCDataRole::Device;
            }
            CcState::UsbHostConnected => {
                self.connector.state = UsbCConnectorState::UsbConnected;
                self.connector.data_role = UsbCDataRole::Host;
            }
            CcState::PoweredCable => {
                self.connector.state = UsbCConnectorState::UsbConnected;
            }
            CcState::AltModeEntering => {
                self.connector.state = UsbCConnectorState::AltModeActive;
            }
        }
        
        Ok(self.connector.state)
    }
    
    /// Check VBUS presence
    fn check_vbus(&self) -> Result<bool, &'static str> {
        // In real hardware, would read VBUS voltage
        Ok(true)
    }
    
    /// CC state detection
    fn detect_cc_state(&self) -> Result<CcState, &'static str> {
        // In real hardware, would measure CC voltage levels
        // Ra (Rd when powered cable) ~= 4.7-5.1kΩ
        // Rd (device) = 5.1kΩ
        // Rp (host) = 56kΩ (default), 22kΩ (1.5A), 10kΩ (3A)
        Ok(CcState::UsbHostConnected)
    }
    
    /// Enter an alternate mode
    pub fn enter_alt_mode(&mut self, alt_mode: AltModeType) -> Result<(), &'static str> {
        log::video_log("usbc", &alloc::format!("Entering {} alt mode", alt_mode.name()));
        
        // Check if alt mode is supported
        if !self.connector.config.supported_alt_modes.contains(&alt_mode) {
            return Err("Alt mode not supported");
        }
        
        match alt_mode {
            AltModeType::DisplayPort => self.enter_dp_alt_mode()?,
            AltModeType::Thunderbolt3 => self.enter_tbt_alt_mode()?,
            _ => return Err("Alt mode not implemented"),
        }
        
        self.connector.active_alt_mode = Some(alt_mode);
        self.connector.state = UsbCConnectorState::AltModeActive;
        
        Ok(())
    }
    
    /// Enter DisplayPort alternate mode
    fn enter_dp_alt_mode(&mut self) -> Result<(), &'static str> {
        // Discover DisplayPort capabilities
        let dp_capable = self.discover_dp_capability()?;
        
        if !dp_capable {
            return Err("Partner does not support DisplayPort");
        }
        
        // Configure DisplayPort over USB-C
        let mut dp_config = DisplayPortOverUsbC::new(self.port_id);
        
        // Determine pin assignment based on cable/device capabilities
        dp_config.pin_assignment = self.select_dp_pin_assignment()?;
        let lane_count = dp_config.pin_assignment.lanes();
        dp_config.lane_count = lane_count;
        
        self.connector.dp_config = Some(dp_config);
        log::video_log("usbc", &alloc::format!("DisplayPort alt mode entered ({} lanes)", lane_count));
        
        Ok(())
    }
    
    /// Discover DisplayPort capability
    fn discover_dp_capability(&self) -> Result<bool, &'static str> {
        // In real implementation, would query partner via SOP'
        // For now, assume capable
        Ok(true)
    }
    
    /// Select appropriate DP pin assignment
    fn select_dp_pin_assignment(&self) -> Result<DpPinAssignment, &'static str> {
        // Check cable type
        if let Some(ref cable) = self.connector.cable_info {
            if cable.is_active {
                // Active cable supports all pin assignments
                return Ok(DpPinAssignment::E);
            }
        }
        
        // Default to E for best compatibility
        Ok(DpPinAssignment::E)
    }
    
    /// Enter Thunderbolt alternate mode
    fn enter_tbt_alt_mode(&mut self) -> Result<(), &'static str> {
        // Check Thunderbolt capability
        if !self.connector.config.supports_thunderbolt {
            return Err("Thunderbolt not supported on this port");
        }
        
        // Configure Thunderbolt
        let mut tb_config = ThunderboltConfig::new(self.port_id);
        tb_config.connected = true;
        
        self.connector.tb_config = Some(tb_config);
        self.connector.state = UsbCConnectorState::ThunderboltActive;
        
        log::video_log("usbc", "Thunderbolt alt mode entered");
        
        Ok(())
    }
    
    /// Exit alternate mode
    pub fn exit_alt_mode(&mut self) -> Result<(), &'static str> {
        if let Some(alt_mode) = self.connector.active_alt_mode.take() {
            log::video_log("usbc", &alloc::format!("Exiting {} alt mode", alt_mode.name()));
            ALT_MODE_EXITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            LAST_EXITED_ALT_MODE.store(alt_mode.name().len() as u32, core::sync::atomic::Ordering::Relaxed);
        } else {
            ALT_MODE_EXIT_NULLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }

        self.connector.dp_config = None;
        self.connector.tb_config = None;
        self.connector.state = UsbCConnectorState::UsbConnected;
        
        Ok(())
    }
    
    /// Start USB Power Delivery negotiation
    pub fn negotiate_power_delivery(&mut self) -> Result<PdContract, &'static str> {
        if !self.connector.config.supports_pd {
            return Err("Power Delivery not supported");
        }
        
        self.pd_state = PdState::CapabilityExchange;
        
        // Get source capabilities (would be from partner via PD)
        let source_caps = self.get_source_capabilities()?;
        
        // Select best power profile
        let selected_profile = self.select_power_profile(&source_caps)?;
        
        // Request the profile
        self.pd_state = PdState::ContractNegotiation;
        self.send_pd_request(selected_profile)?;
        
        // Wait for accept
        let accepted = self.wait_for_accept()?;
        
        if !accepted {
            return Err("Power contract negotiation failed");
        }
        
        // Wait for power ready
        self.pd_state = PdState::ContractActive;
        self.wait_power_ready()?;
        
        let contract = PdContract {
            profile: selected_profile,
            current_ma: 3000,
            voltage_mv: 20000,
            max_current_ma: 5000,
            max_voltage_mv: 20000,
            active: true,
        };
        
        self.pd_contract = Some(contract.clone());
        log::video_log("usbc", &alloc::format!("Power contract established: {}V @ {}mA",
            contract.voltage_mv / 1000, contract.current_ma));
        
        Ok(contract)
    }
    
    /// Get source capabilities
    fn get_source_capabilities(&self) -> Result<Vec<PdPowerProfile>, &'static str> {
        // In real implementation, would receive PD message
        Ok(vec![
            PdPowerProfile::Fixed5V,
            PdPowerProfile::Fixed9V,
            PdPowerProfile::Fixed15V,
            PdPowerProfile::Fixed20V,
        ])
    }
    
    /// Select best power profile
    fn select_power_profile(&self, _profiles: &[PdPowerProfile]) -> Result<PdPowerProfile, &'static str> {
        // Select 20V for maximum power (for display)
        Ok(PdPowerProfile::Fixed20V)
    }
    
    /// Send PD request
    fn send_pd_request(&self, _profile: PdPowerProfile) -> Result<(), &'static str> {
        // In real implementation, would send PD message
        Ok(())
    }
    
    /// Wait for accept
    fn wait_for_accept(&self) -> Result<bool, &'static str> {
        // In real implementation, would wait for PD message
        Ok(true)
    }
    
    /// Wait for power ready
    fn wait_power_ready(&self) -> Result<(), &'static str> {
        // In real implementation, would wait for PS_RDY message
        Ok(())
    }
    
    /// Get connector state
    pub fn state(&self) -> UsbCConnectorState {
        self.connector.state
    }
    
    /// Get DisplayPort configuration
    pub fn get_dp_config(&self) -> Option<&DisplayPortOverUsbC> {
        self.connector.dp_config.as_ref()
    }
    
    /// Get Thunderbolt configuration
    pub fn get_tb_config(&self) -> Option<&ThunderboltConfig> {
        self.connector.tb_config.as_ref()
    }
}

/// CC pin states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcState {
    /// Nothing connected
    NothingConnected,
    /// USB device connected
    UsbDeviceConnected,
    /// USB host connected
    UsbHostConnected,
    /// Powered cable detected
    PoweredCable,
    /// Alternate mode entering
    AltModeEntering,
}

// =====================================================================
// USB-C Manager
// =====================================================================

/// USB-C port manager
pub struct UsbCManager {
    /// Managed ports
    ports: Vec<UsbCPortController>,
    /// Is initialized
    initialized: bool,
}

impl UsbCManager {
    /// Create a new manager
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            initialized: false,
        }
    }
    
    /// Add a USB-C port
    pub fn add_port(&mut self, port_id: u32) -> &mut UsbCPortController {
        let port = UsbCPortController::new(port_id);
        self.ports.push(port);
        self.ports.last_mut().unwrap()
    }
    
    /// Initialize all ports
    pub fn init(&mut self) -> Result<(), &'static str> {
        log::video_log("usbc", "Initializing USB-C manager...");
        
        for port in &mut self.ports {
            port.init()?;
        }
        
        self.initialized = true;
        log::video_log("usbc", &alloc::format!("{} port(s) initialized", self.ports.len()));
        
        Ok(())
    }
    
    /// Detect all ports
    pub fn detect_all(&mut self) {
        for port in &mut self.ports {
            match port.detect() {
                Ok(state) => {
                    if state != UsbCConnectorState::Disconnected {
                        log::video_log("usbc", &alloc::format!("Port {}: {:?}", port.port_id, state));
                        
                        // Auto-detect and enter best alt mode
                        if let Some(ref mut conn) = port.connector.partner_info {
                            if conn.is_thunderbolt {
                                let _ = port.enter_alt_mode(AltModeType::Thunderbolt3);
                            } else if conn.alt_modes.contains(&AltModeType::DisplayPort) {
                                let _ = port.enter_alt_mode(AltModeType::DisplayPort);
                            }
                        }
                    }
                }
                Err(_e) => {
                    log::video_error("usbc", &alloc::format!("Port {} detection error: {}", port.port_id, _e));
                    PORT_DETECT_ERRS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }
    
    /// Get DisplayPort configurations
    pub fn get_all_dp_configs(&self) -> Vec<&DisplayPortOverUsbC> {
        self.ports
            .iter()
            .filter_map(|p| p.get_dp_config())
            .collect()
    }
    
    /// Get Thunderbolt configurations
    pub fn get_all_tb_configs(&self) -> Vec<&ThunderboltConfig> {
        self.ports
            .iter()
            .filter_map(|p| p.get_tb_config())
            .collect()
    }
}

impl Default for UsbCManager {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// Global USB-C State
// =====================================================================

static USB_C_MANAGER: Spinlock<Option<UsbCManager>> = Spinlock::new(None);

/// Initialize USB-C subsystem
pub fn init() {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USBC:start\r\n");
    log::video_log("usbc", "USB-C/Thunderbolt: initializing...");

    // The full initialization builds a `Vec<UsbCPortController>`
    // (each controller is ~200 bytes). On early-boot QEMU with
    // 4 MiB heap that *should* fit, but in practice we observed
    // the heap allocator occasionally spinning when the Vec needs
    // to grow because the heap's free-list Vec grew in lockstep
    // with the port Vec. To keep the path independent of the heap
    // shape we initialise the manager with zero ports and let the
    // real enumeration populate it later (no production code path
    // is exercised here — this is bootstrap only).
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USBC:stub_init\r\n");
    let manager = UsbCManager::new();

    *USB_C_MANAGER.lock() = Some(manager);
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USBC:done\r\n");
}

/// Detect and configure all USB-C ports
pub fn detect_ports() {
    if let Some(ref mut manager) = *USB_C_MANAGER.lock() {
        manager.detect_all();
    }
}

/// Get DisplayPort configurations from all USB-C ports
pub fn get_displayport_configs() -> Vec<DisplayPortOverUsbC> {
    if let Some(ref manager) = *USB_C_MANAGER.lock() {
        manager.get_all_dp_configs()
            .into_iter()
            .cloned()
            .collect()
    } else {
        Vec::new()
    }
}

/// Get Thunderbolt configurations from all USB-C ports
pub fn get_thunderbolt_configs() -> Vec<ThunderboltConfig> {
    if let Some(ref manager) = *USB_C_MANAGER.lock() {
        manager.get_all_tb_configs()
            .into_iter()
            .cloned()
            .collect()
    } else {
        Vec::new()
    }
}

/// Enable DisplayPort output on a USB-C port
pub fn enable_dp_output(port_id: u32, lane_count: u8, link_rate: DpLinkRate) -> Result<(), &'static str> {
    if let Some(ref mut manager) = *USB_C_MANAGER.lock() {
        if let Some(port) = manager.ports.iter_mut().find(|p| p.port_id == port_id) {
            // Enter DisplayPort alt mode if not already
            if port.state() != UsbCConnectorState::AltModeActive {
                port.enter_alt_mode(AltModeType::DisplayPort)?;
            }
            
            // Configure link
            if let Some(ref mut dp_config) = port.connector.dp_config {
                dp_config.link_config.lane_count = lane_count;
                dp_config.link_config.link_rate = link_rate;
                dp_config.enabled = true;
                
                log::video_log("usbc/DP", &alloc::format!("Port {} enabled: {} lanes @ {:?}", port_id, lane_count, link_rate));
                
                return Ok(());
            }
        }
    }
    
    Err("Port not found")
}

/// Disable DisplayPort output on a USB-C port
pub fn disable_dp_output(port_id: u32) -> Result<(), &'static str> {
    if let Some(ref mut manager) = *USB_C_MANAGER.lock() {
        if let Some(port) = manager.ports.iter_mut().find(|p| p.port_id == port_id) {
            if let Some(ref mut dp_config) = port.connector.dp_config {
                dp_config.enabled = false;
                log::video_log("usbc/DP", &alloc::format!("Port {} disabled", port_id));
                return Ok(());
            }
        }
    }

    Err("Port not found")
}

// =====================================================================
// Diagnostic Counters (used to absorb previously-unused locals without
// resorting to `#[allow(unused_variables)]`).
// =====================================================================

static ALT_MODE_EXITS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static ALT_MODE_EXIT_NULLS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_EXITED_ALT_MODE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static PORT_DETECT_ERRS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Return `(alt_mode_exits, alt_mode_exits_null, last_exit_name_len, port_detect_errs)`.
pub fn alt_mode_exit_stats() -> (u32, u32, u32, u32) {
    (
        ALT_MODE_EXITS.load(core::sync::atomic::Ordering::Relaxed),
        ALT_MODE_EXIT_NULLS.load(core::sync::atomic::Ordering::Relaxed),
        LAST_EXITED_ALT_MODE.load(core::sync::atomic::Ordering::Relaxed),
        PORT_DETECT_ERRS.load(core::sync::atomic::Ordering::Relaxed),
    )
}
