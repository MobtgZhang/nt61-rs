//! IPv4 Protocol Implementation
//
//! Handles IPv4 packet parsing, construction, and processing.
//
//! Clean-room implementation based on RFC 791.

use crate::netstack::eth::{self, ETHER_TYPE_IPV4};
use crate::drivers::net::NicType;

/// IPv4 header constants
pub const IPV4_HDR_SIZE: usize = 20;
pub const IPV4_MIN_SIZE: usize = 20;
pub const IPV4_MAX_SIZE: usize = 65535;

/// Protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Raw = 255,
}

impl Protocol {
    pub fn from_u8(v: u8) -> Option<Protocol> {
        match v {
            1 => Some(Protocol::Icmp),
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            _ => None,
        }
    }
}

/// IPv4 header structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    /// Version (4) and IHL (5) - network byte order
    pub version_ihl: u8,
    /// Type of Service
    pub tos: u8,
    /// Total length (network byte order)
    pub total_length: u16,
    /// Identification (network byte order)
    pub identification: u16,
    /// Flags (3 bits) and Fragment Offset (13 bits) - network byte order
    pub flags_offset: u16,
    /// Time To Live
    pub ttl: u8,
    /// Protocol
    pub protocol: u8,
    /// Header Checksum (network byte order)
    pub checksum: u16,
    /// Source IP Address (network byte order)
    pub src_ip: u32,
    /// Destination IP Address (network byte order)
    pub dst_ip: u32,
}

impl Ipv4Header {
    /// Get the header length in bytes
    pub fn header_length(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    /// Get the total header length in bytes
    pub fn total_length(&self) -> usize {
        u16::from_be(self.total_length) as usize
    }

    /// Get the payload length
    pub fn payload_length(&self) -> usize {
        self.total_length() - self.header_length()
    }

    /// Check if don't fragment flag is set
    pub fn dont_fragment(&self) -> bool {
        (u16::from_be(self.flags_offset) & 0x4000) != 0
    }

    /// Check if more fragments flag is set
    pub fn more_fragments(&self) -> bool {
        (u16::from_be(self.flags_offset) & 0x2000) != 0
    }

    /// Get fragment offset
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be(self.flags_offset) & 0x1FFF
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Ipv4Header> {
        if data.len() < IPV4_MIN_SIZE {
            return None;
        }

        let header = Ipv4Header {
            version_ihl: data[0],
            tos: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags_offset: u16::from_be_bytes([data[6], data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src_ip: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            dst_ip: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
        };

        // Verify version
        if (header.version_ihl >> 4) != 4 {
            return None;
        }

        // Verify header length
        if header.header_length() < IPV4_MIN_SIZE {
            return None;
        }

        // Verify checksum (skip for now, verify later)
        // if !header.verify_checksum() {
        //     return None;
        // }

        Some(header)
    }

    /// Write to bytes
    pub fn to_bytes(&self, data: &mut [u8]) {
        if data.len() < IPV4_HDR_SIZE {
            return;
        }

        data[0] = self.version_ihl;
        data[1] = self.tos;
        data[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        data[4..6].copy_from_slice(&self.identification.to_be_bytes());
        data[6..8].copy_from_slice(&self.flags_offset.to_be_bytes());
        data[8] = self.ttl;
        data[9] = self.protocol;
        data[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        data[12..16].copy_from_slice(&self.src_ip.to_be_bytes());
        data[16..20].copy_from_slice(&self.dst_ip.to_be_bytes());
    }
}

/// Calculate IPv4 checksum
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += chunk[0] as u32;
        }
    }

    // Add carries
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Verify IPv4 checksum
pub fn verify_checksum(_header: &Ipv4Header, data: &[u8]) -> bool {
    let checksum = calculate_checksum(data);
    // IPv4 checksum: 0 means correct (ones complement)
    checksum == 0
}

/// Parse an IPv4 header from bytes
pub fn parse_ipv4_header(data: &[u8]) -> Option<(Ipv4Header, &[u8])> {
    let header = Ipv4Header::from_bytes(data)?;

    // Verify checksum
    if !verify_checksum(&header, &data[..header.header_length()]) {
        return None;
    }

    let payload = if data.len() > header.header_length() {
        &data[header.header_length()..]
    } else {
        &[]
    };

    Some((header, payload))
}

/// Build an IPv4 packet
pub fn build_ipv4_packet(
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    ttl: u8,
    payload: &[u8],
) -> alloc::vec::Vec<u8> {
    let total_length = (IPV4_HDR_SIZE + payload.len()) as u16;
    let identification: u16 = 0; // Could be incremented per-packet

    let mut packet = alloc::vec::Vec::with_capacity(IPV4_HDR_SIZE + payload.len());

    // Header fields
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0);    // TOS
    packet.extend_from_slice(&total_length.to_be_bytes());
    packet.extend_from_slice(&identification.to_be_bytes());
    packet.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    packet.push(ttl);
    packet.push(protocol);
    packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    packet.extend_from_slice(&src_ip.to_be_bytes());
    packet.extend_from_slice(&dst_ip.to_be_bytes());

    // Calculate and set checksum
    let checksum = calculate_checksum(&packet);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = checksum as u8;

    // Add payload
    packet.extend_from_slice(payload);

    packet
}

/// IPv4 input processing
/// Called when an IPv4 packet is received
pub fn ipv4_input(
    header: &Ipv4Header,
    payload: &[u8],
    _nic_type: NicType,
    _nic_index: usize,
) {
    // Check if the packet is for us
    use crate::netstack::ipif;

    // Get our IP addresses and check
    let our_ips = ipif::get_our_ip_addresses();
    let is_for_us = our_ips.iter().any(|&ip| ip == header.dst_ip);

    // Also check for broadcast
    let is_broadcast = header.dst_ip == 0xFFFFFFFF || is_broadcast_ip(header.dst_ip);

    if !is_for_us && !is_broadcast {
        // Not for us, check if we should forward
        return;
    }

    // Check TTL
    if header.ttl <= 1 {
        // TTL expired, send ICMP time exceeded
        return;
    }

    // Dispatch to protocol handler
    match Protocol::from_u8(header.protocol) {
        Some(Protocol::Icmp) => {
            crate::netstack::icmp::icmp_input(header.src_ip, payload);
        }
        Some(Protocol::Tcp) => {
            crate::netstack::tcp::tcp_input(header.src_ip, header.dst_ip, payload);
        }
        Some(Protocol::Udp) => {
            crate::netstack::udp::udp_input(header.src_ip, header.dst_ip, payload);
        }
        _ => {
            // Unknown protocol
        }
    }
}

/// Check if an IP address is a broadcast address
fn is_broadcast_ip(ip: u32) -> bool {
    // Check for subnet broadcast (all host bits set)
    // For now, just check for 255.255.255.255
    ip == 0xFFFFFFFF
}

/// Send an IPv4 packet
pub fn send_ipv4(
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    payload: &[u8],
) -> bool {
    // Build the packet
    let packet = build_ipv4_packet(src_ip, dst_ip, protocol, 64, payload);

    // Use ARP to resolve the destination MAC
    let dst_mac = match crate::netstack::arp::arp_resolve(dst_ip) {
        Some(mac) => mac,
        None => return false,
    };

    // Get our MAC address
    let src_mac = match crate::netstack::ethif::get_primary_mac() {
        Some(mac) => mac,
        None => return false,
    };

    // Build Ethernet frame
    let frame = eth::build_ethernet_frame(&dst_mac, &src_mac, ETHER_TYPE_IPV4, &packet);

    // Send to NIC
    let Some((nic_type, nic_idx)) = crate::netstack::ethif::get_primary_interface() else {
        return false;
    };

    crate::drivers::net::send_to_nic(nic_type, nic_idx, &frame)
}
