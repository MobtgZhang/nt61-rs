//! Ethernet Protocol Implementation
//
//! Handles Ethernet II frame parsing and construction.
//
//! Clean-room implementation based on IEEE 802.3 and Ethernet II standards.

/// Ethernet II frame EtherType values
pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_RARP: u16 = 0x8035;
pub const ETHER_TYPE_VLAN: u16 = 0x8100;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;

/// Ethernet frame minimum size (header + FCS)
pub const ETHER_MIN_SIZE: usize = 64;
/// Ethernet frame maximum size (header + payload + FCS)
pub const ETHER_MAX_SIZE: usize = 1518;
/// Ethernet header size
pub const ETHER_HDR_SIZE: usize = 14;

/// Ethernet header structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EthernetHeader {
    /// Destination MAC address
    pub dst_mac: [u8; 6],
    /// Source MAC address
    pub src_mac: [u8; 6],
    /// EtherType (network byte order)
    pub ether_type: u16,
}

impl EthernetHeader {
    /// Parse an Ethernet header from a byte slice
    pub fn from_bytes(data: &[u8]) -> Option<EthernetHeader> {
        if data.len() < ETHER_HDR_SIZE {
            return None;
        }

        Some(EthernetHeader {
            dst_mac: [data[0], data[1], data[2], data[3], data[4], data[5]],
            src_mac: [data[6], data[7], data[8], data[9], data[10], data[11]],
            ether_type: u16::from_be_bytes([data[12], data[13]]),
        })
    }

    /// Write the header to a byte slice
    pub fn to_bytes(&self, data: &mut [u8]) {
        if data.len() < ETHER_HDR_SIZE {
            return;
        }

        data[0..6].copy_from_slice(&self.dst_mac);
        data[6..12].copy_from_slice(&self.src_mac);
        data[12..14].copy_from_slice(&self.ether_type.to_be_bytes());
    }

    /// Get the payload offset
    pub fn payload_offset(&self) -> usize {
        ETHER_HDR_SIZE
    }

    /// Get the payload length
    pub fn payload_length(&self, total_len: usize) -> usize {
        if total_len < ETHER_HDR_SIZE {
            0
        } else {
            total_len - ETHER_HDR_SIZE
        }
    }
}

/// Broadcast MAC address
pub const ETHER_BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// Check if MAC is broadcast
pub fn is_broadcast(mac: &[u8; 6]) -> bool {
    mac == &ETHER_BROADCAST_MAC
}

/// Check if MAC is multicast
pub fn is_multicast(mac: &[u8; 6]) -> bool {
    mac[0] & 0x01 != 0 && !is_broadcast(mac)
}

/// Check if MAC is unicast
pub fn is_unicast(mac: &[u8; 6]) -> bool {
    mac[0] & 0x01 == 0
}

/// Parse an Ethernet frame
/// Returns the header and a reference to the payload
pub fn parse_ethernet_frame(data: &[u8]) -> Option<(EthernetHeader, &[u8])> {
    let header = EthernetHeader::from_bytes(data)?;
    let payload = &data[ETHER_HDR_SIZE..];
    Some((header, payload))
}

/// Build an Ethernet frame
pub fn build_ethernet_frame(
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    ether_type: u16,
    payload: &[u8],
) -> alloc::vec::Vec<u8> {
    let mut frame = alloc::vec::Vec::with_capacity(ETHER_HDR_SIZE + payload.len());
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Build an Ethernet frame with space for header
pub fn build_ethernet_frame_with_header(
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    ether_type: u16,
    payload_len: usize,
) -> alloc::vec::Vec<u8> {
    let mut frame = alloc::vec::Vec::with_capacity(ETHER_HDR_SIZE + payload_len);
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    // Reserve space for payload
    frame.resize(ETHER_HDR_SIZE + payload_len, 0);
    frame
}
