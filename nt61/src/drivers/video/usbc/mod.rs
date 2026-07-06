//! USB-C and Thunderbolt Display Output Support
//
//! This module provides USB-C Alternate Mode and Thunderbolt display output
//! support for the NT6.1.7601 kernel.

pub mod thunderbolt;

pub use thunderbolt::{
    UsbCConnectorState, UsbCDataRole, UsbCPowerRole, UsbCConnectorType,
    AltModeType, UsbCPortConfig, UsbCConnector, UsbCPartnerInfo, UsbCCableInfo,
    DisplayPortOverUsbC, DpVersion, DpPinAssignment, DpLinkConfig, DpLinkRate,
    ThunderboltConfig, ThunderboltVersion, TbtTunnelStatus,
    PdMessageType, PdContract, PdPowerProfile,
    UsbCPortController, UsbCManager,
    init, detect_ports, get_displayport_configs, get_thunderbolt_configs,
    enable_dp_output, disable_dp_output,
};
