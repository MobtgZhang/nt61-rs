//! OID (Object Identifier) Request Handling
//
//! NDIS uses OIDs to query and set NIC capabilities. This module
//! implements the most common OIDs used by network drivers.
//
//! Clean-room implementation based on NDIS 6.0 specification.

use crate::drivers::net::ndis::miniport_adapter::MiniportAdapterContext;

/// OID constants
pub mod oid {
    // General OIDs
    pub const GEN_SUPPORTED_GUIDS: u32 = 0x00010100;
    pub const GEN_PHYSICAL_MEDIUM: u32 = 0x00010202;

    // Version OIDs
    pub const OID_GEN_MINIPORT_INFO: u32 = 0x0001010B;
    pub const OID_GEN_DRIVER_VERSION: u32 = 0x00010210;
    pub const OID_GEN_MAXIMUM_FRAME_SIZE: u32 = 0x00010104;
    pub const OID_GEN_TRANSMIT_BLOCK_SIZE: u32 = 0x00010105;
    pub const OID_GEN_RECEIVE_BLOCK_SIZE: u32 = 0x00010106;

    // Connection OIDs
    pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x00010108;
    pub const OID_GEN_CURRENT_LOOKAHEAD: u32 = 0x00010109;
    pub const OID_GEN_MAXIMUM_TOTAL_SIZE: u32 = 0x00010111;
    pub const OID_GEN_MEDIA_CAPABILITIES: u32 = 0x00010203;
    pub const OID_GEN_MEDIA_CONNECT_STATUS: u32 = 0x00010143;
    pub const OID_GEN_LINK_SPEED: u32 = 0x00010114;
    pub const OID_GEN_VENDOR_DESCRIPTION: u32 = 0x0001011A;
    pub const OID_GEN_VENDOR_DRIVER_VERSION: u32 = 0x00010116;
    pub const OID_GEN_CURRENT_PORT_STATE: u32 = 0x00010259;
    pub const OID_GEN_INTERRUPT_MODERATION: u32 = 0x0001021A;

    // Plug and Play OIDs
    pub const OID_PNP_CAPABILITIES: u32 = 0x0001010C;
    pub const OID_PNP_SET_POWER: u32 = 0x0001010D;
    pub const OID_PNP_QUERY_POWER: u32 = 0x0001010E;
    pub const OID_PNP_ADD_WAKE_UP_PATTERN: u32 = 0x0001010F;
    pub const OID_PNP_REMOVE_WAKE_UP_PATTERN: u32 = 0x00010110;
    pub const OID_PNP_WAKE_UP_PATTERN_LIST: u32 = 0x00010112;

    // Statistics OIDs
    pub const OID_GEN_XMIT_OK: u32 = 0x00020101;
    pub const OID_GEN_XMIT_ERROR: u32 = 0x00020102;
    pub const OID_GEN_RCV_OK: u32 = 0x00020103;
    pub const OID_GEN_RCV_ERROR: u32 = 0x00020104;
    pub const OID_GEN_XMIT_NO_BUFFER: u32 = 0x00020105;

    // 802.3 OIDs (Ethernet specific)
    pub const NDIS_802_3_PERMANENT_ADDRESS: u32 = 0x01010101;
    pub const NDIS_802_3_CURRENT_ADDRESS: u32 = 0x01010102;
    pub const NDIS_802_3_MAXIMUM_LIST_SIZE: u32 = 0x01010104;
    pub const NDIS_802_3_MAC_OPTIONS: u32 = 0x01010105;
    pub const NDIS_802_3_MAC_ADDRESS: u32 = 0x01010106;

    // 802.3 Statistics
    pub const OID_802_3_XMIT_ONE COLLISION: u32 = 0x01020201;
    pub const OID_802_3_XMIT_MORE_COLLISIONS: u32 = 0x01020202;
    pub const OID_802_3_XMIT_MAX_COLLISIONS: u32 = 0x01020203;
    pub const OID_802_3_RCV_ALIGNMENT_ERRORS: u32 = 0x01020204;
    pub const OID_802_3_RCV_FCS_ERRORS: u32 = 0x01020205;
    pub const OID_802_3_RCV_OVERRUN_ERRORS: u32 = 0x01020206;
    pub const OID_802_3_RCV_CARRIER_ERRORS: u32 = 0x01020207;
}

/// NDIS status codes
pub mod status {
    pub const SUCCESS: i32 = 0x00000000;
    pub const PENDING: i32 = 0x00000103;
    pub const FAILURE: i32 = 0xC0000001;
    pub const RESOURCES: i32 = 0xC000009A;
    pub const HARDWARE_ERRORS: i32 = 0xC0000185;
    pub const MEDIA_DISCONNECTED: i32 = 0x4000000B;
    pub const NOT_SUPPORTED: i32 = 0xC00000BB;
    pub const INVALID_LENGTH: i32 = 0xC0000004;
    pub const INVALID_DATA: i32 = 0xC000000D;
}

/// Media state for OID_GEN_MEDIA_CONNECT_STATUS
pub mod media_state {
    pub const CONNECTED: u32 = 0x00000000;
    pub const DISCONNECTED: u32 = 0x00000001;
}

/// Media capabilities
pub mod media_capabilities {
    pub const RECEIVE_MCAST: u32 = 0x00000001;
    pub const RECEIVE_BCAST: u32 = 0x00000002;
    pub const RECEIVE_PHYSICAL_MCAST: u32 = 0x00000004;
    pub const MULTICAST: u32 = 0x00000100;
    pub const BROADCAST: u32 = 0x00000200;
    pub const PROMISCUOUS: u32 = 0x00000400;
    pub const AMBIENT_CAPABILITY: u32 = 0x00010000;
}

/// OID request information
pub struct OidRequestInfo {
    pub oid: u32,
    pub info_buffer: *mut u8,
    pub info_buffer_length: u32,
    pub bytes_written: u32,
    pub bytes_needed: u32,
}

/// Handle an OID query request
pub fn query_oid(
    adapter: *mut MiniportAdapterContext,
    oid: u32,
    out_buffer: *mut u8,
    out_buffer_length: u32,
    bytes_written: &mut u32,
    bytes_needed: &mut u32,
) -> i32 {
    if adapter.is_null() {
        return status::FAILURE;
    }

    *bytes_written = 0;
    *bytes_needed = 0;

    unsafe {
        match oid {
            oid::OID_GEN_CURRENT_PACKET_FILTER => {
                // Return current packet filter
                if out_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(out_buffer as *mut u32, (*adapter).current_filter);
                *bytes_written = 4;
                status::SUCCESS
            }

            oid::NDIS_802_3_CURRENT_ADDRESS => {
                // Return current MAC address
                if out_buffer_length < 6 {
                    *bytes_needed = 6;
                    return status::INVALID_LENGTH;
                }
                core::ptr::copy_nonoverlapping(
                    (*adapter).mac.as_ptr(),
                    out_buffer,
                    6
                );
                *bytes_written = 6;
                status::SUCCESS
            }

            oid::NDIS_802_3_PERMANENT_ADDRESS => {
                // Return permanent MAC address (same as current for our implementation)
                if out_buffer_length < 6 {
                    *bytes_needed = 6;
                    return status::INVALID_LENGTH;
                }
                core::ptr::copy_nonoverlapping(
                    (*adapter).mac.as_ptr(),
                    out_buffer,
                    6
                );
                *bytes_written = 6;
                status::SUCCESS
            }

            oid::OID_GEN_LINK_SPEED => {
                // Return link speed (in 100 bps units)
                if out_buffer_length < 8 {
                    *bytes_needed = 8;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(
                    out_buffer as *mut u64,
                    (*adapter).capabilities.link_speed / 100
                );
                *bytes_written = 8;
                status::SUCCESS
            }

            oid::OID_GEN_MEDIA_CONNECT_STATUS => {
                // Return media connect status
                if out_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                let state = if (*adapter).link_up {
                    media_state::CONNECTED
                } else {
                    media_state::DISCONNECTED
                };
                core::ptr::write_volatile(out_buffer as *mut u32, state);
                *bytes_written = 4;
                status::SUCCESS
            }

            oid::OID_GEN_MAXIMUM_FRAME_SIZE => {
                // Return maximum frame size
                if out_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(
                    out_buffer as *mut u32,
                    (*adapter).capabilities.max_frame_size
                );
                *bytes_written = 4;
                status::SUCCESS
            }

            oid::OID_GEN_TRANSMIT_BLOCK_SIZE => {
                if out_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(out_buffer as *mut u32, 1514);
                *bytes_written = 4;
                status::SUCCESS
            }

            oid::OID_GEN_RECEIVE_BLOCK_SIZE => {
                if out_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(out_buffer as *mut u32, 1514);
                *bytes_written = 4;
                status::SUCCESS
            }

            oid::OID_GEN_MAXIMUM_TOTAL_SIZE => {
                if out_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(out_buffer as *mut u32, 1514);
                *bytes_written = 4;
                status::SUCCESS
            }

            oid::OID_GEN_XMIT_OK => {
                if out_buffer_length < 8 {
                    *bytes_needed = 8;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(
                    out_buffer as *mut u64,
                    (*adapter).stats.tx_packets.load(core::sync::atomic::Ordering::Relaxed)
                );
                *bytes_written = 8;
                status::SUCCESS
            }

            oid::OID_GEN_RCV_OK => {
                if out_buffer_length < 8 {
                    *bytes_needed = 8;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(
                    out_buffer as *mut u64,
                    (*adapter).stats.rx_packets.load(core::sync::atomic::Ordering::Relaxed)
                );
                *bytes_written = 8;
                status::SUCCESS
            }

            oid::OID_GEN_XMIT_ERROR => {
                if out_buffer_length < 8 {
                    *bytes_needed = 8;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(
                    out_buffer as *mut u64,
                    (*adapter).stats.tx_errors.load(core::sync::atomic::Ordering::Relaxed)
                );
                *bytes_written = 8;
                status::SUCCESS
            }

            oid::OID_GEN_RCV_ERROR => {
                if out_buffer_length < 8 {
                    *bytes_needed = 8;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(
                    out_buffer as *mut u64,
                    (*adapter).stats.rx_errors.load(core::sync::atomic::Ordering::Relaxed)
                );
                *bytes_written = 8;
                status::SUCCESS
            }

            oid::NDIS_802_3_MAXIMUM_LIST_SIZE => {
                // Maximum multicast address list size
                if out_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(out_buffer as *mut u32, 32);
                *bytes_written = 4;
                status::SUCCESS
            }

            oid::NDIS_802_3_MAC_OPTIONS => {
                // No special MAC options
                if out_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                core::ptr::write_volatile(out_buffer as *mut u32, 0);
                *bytes_written = 4;
                status::SUCCESS
            }

            _ => status::NOT_SUPPORTED,
        }
    }
}

/// Handle an OID set request
pub fn set_oid(
    adapter: *mut MiniportAdapterContext,
    oid: u32,
    in_buffer: *const u8,
    in_buffer_length: u32,
    bytes_read: &mut u32,
    bytes_needed: &mut u32,
) -> i32 {
    if adapter.is_null() {
        return status::FAILURE;
    }

    *bytes_read = 0;
    *bytes_needed = 0;

    unsafe {
        match oid {
            oid::OID_GEN_CURRENT_PACKET_FILTER => {
                if in_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                let filter = core::ptr::read_volatile(in_buffer as *const u32);
                (*adapter).current_filter = filter;
                (*adapter).promiscuous = (filter & media_capabilities::PROMISCUOUS) != 0;
                *bytes_read = 4;
                status::SUCCESS
            }

            oid::OID_GEN_CURRENT_LOOKAHEAD => {
                // Set lookahead size (informational only in our implementation)
                if in_buffer_length < 4 {
                    *bytes_needed = 4;
                    return status::INVALID_LENGTH;
                }
                *bytes_read = 4;
                status::SUCCESS
            }

            _ => status::NOT_SUPPORTED,
        }
    }
}
