//! USB-C and Thunderbolt Display Output Support
//
//! This module provides USB-C Alternate Mode and Thunderbolt display output
//! support for the NT6.1.7601 kernel.

pub mod thunderbolt;

pub use thunderbolt::{
    detect_ports, disable_dp_output, enable_dp_output, get_displayport_configs,
    get_thunderbolt_configs, init, AltModeType, DisplayPortOverUsbC, DpLinkConfig, DpLinkRate,
    DpPinAssignment, DpVersion, PdContract, PdMessageType, PdPowerProfile, TbtTunnelStatus,
    ThunderboltConfig, ThunderboltVersion, UsbCCableInfo, UsbCConnector, UsbCConnectorState,
    UsbCConnectorType, UsbCDataRole, UsbCManager, UsbCPartnerInfo, UsbCPortConfig,
    UsbCPortController, UsbCPowerRole,
};
