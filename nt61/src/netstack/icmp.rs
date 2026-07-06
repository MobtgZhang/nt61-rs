//! ICMP Protocol Implementation
//
//! Handles Internet Control Message Protocol for IPv4.
//
//! Clean-room implementation based on RFC 792.

use crate::netstack::ipv4;
use crate::netstack::ipif;
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

/// ICMP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    ParameterProblem = 12,
    TimestampRequest = 13,
    TimestampReply = 14,
    InfoRequest = 15,
    InfoReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
}

/// ICMP destination unreachable codes
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum DestinationUnreachableCode {
    NetworkUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeeded = 4,
    SourceRouteFailed = 5,
    NetworkUnknown = 6,
    HostUnknown = 7,
    SourceIsolated = 8,
    NetworkProhibited = 9,
    HostProhibited = 10,
    NetworkTosUnreachable = 11,
    HostTosUnreachable = 12,
    CommunicationProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoff = 15,
}

/// ICMP header structure
#[repr(C)]
pub struct IcmpHeader {
    /// Type
    pub icmp_type: u8,
    /// Code
    pub code: u8,
    /// Checksum
    pub checksum: u16,
    /// Rest of header (varies by type)
    pub rest: [u8; 4],
}

impl IcmpHeader {
    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<IcmpHeader> {
        if data.len() < 8 {
            return None;
        }

        Some(IcmpHeader {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            rest: [data[4], data[5], data[6], data[7]],
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, data: &mut [u8]) {
        if data.len() < 8 {
            return;
        }

        data[0] = self.icmp_type;
        data[1] = self.code;
        data[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        data[4..8].copy_from_slice(&self.rest);
    }
}

/// ICMP echo request/reply structure
#[repr(C)]
pub struct IcmpEchoHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
}

impl IcmpEchoHeader {
    pub fn from_bytes(data: &[u8]) -> Option<IcmpEchoHeader> {
        if data.len() < 8 {
            return None;
        }

        Some(IcmpEchoHeader {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence: u16::from_be_bytes([data[6], data[7]]),
        })
    }
}

/// ICMP statistics
pub struct IcmpStats {
    pub msg_in: u64,
    pub msg_out: u64,
    pub error_in: u64,
    pub error_out: u64,
    pub echo_request_in: u64,
    pub echo_reply_out: u64,
    pub dest_unreachable_out: u64,
}

impl Clone for IcmpStats {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for IcmpStats {}

impl IcmpStats {
    pub const fn new() -> Self {
        Self {
            msg_in: 0,
            msg_out: 0,
            error_in: 0,
            error_out: 0,
            echo_request_in: 0,
            echo_reply_out: 0,
            dest_unreachable_out: 0,
        }
    }

    pub const fn zero() -> Self {
        Self {
            msg_in: 0,
            msg_out: 0,
            error_in: 0,
            error_out: 0,
            echo_request_in: 0,
            echo_reply_out: 0,
            dest_unreachable_out: 0,
        }
    }
}

impl Default for IcmpStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Global ICMP statistics
static ICMP_STATS: Spinlock<IcmpStats> = Spinlock::new(IcmpStats::zero());

/// Initialize the ICMP module
pub fn init() {
    let mut stats = ICMP_STATS.lock();
    *stats = IcmpStats::new();
}

/// Calculate ICMP checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += chunk[0] as u32;
        }
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Process an incoming ICMP packet
pub fn icmp_input(src_ip: u32, data: &[u8]) {
    let header = match IcmpHeader::from_bytes(data) {
        Some(h) => h,
        None => return,
    };

    let mut stats = ICMP_STATS.lock();
    stats.msg_in += 1;

    match header.icmp_type as u8 {
        0 => {
            // Echo Reply
            stats.echo_reply_out += 1;
            handle_echo_reply(header, &data[8..]);
        }
        3 => {
            // Destination Unreachable
            stats.error_in += 1;
            handle_dest_unreachable(header, &data[8..]);
        }
        4 => {
            // Source Quench
            stats.error_in += 1;
        }
        5 => {
            // Redirect
        }
        8 => {
            // Echo Request
            stats.echo_request_in += 1;
            handle_echo_request(src_ip, header, &data[8..]);
        }
        11 => {
            // Time Exceeded
            stats.error_in += 1;
        }
        12 => {
            // Parameter Problem
            stats.error_in += 1;
        }
        _ => {}
    }
}

/// Handle ICMP echo request
fn handle_echo_request(src_ip: u32, header: IcmpHeader, data: &[u8]) {
    let identifier = u16::from_be_bytes([header.rest[0], header.rest[1]]);
    let sequence = u16::from_be_bytes([header.rest[2], header.rest[3]]);

    // Get our IP address
    let our_ips = ipif::get_our_ip_addresses();
    let dst_ip = match our_ips.first() {
        Some(&ip) => ip,
        None => return,
    };

    // Build echo reply
    send_echo_reply(src_ip, dst_ip, identifier, sequence, data);
}

/// Handle ICMP echo reply
fn handle_echo_reply(header: IcmpHeader, data: &[u8]) {
    let identifier = u16::from_be_bytes([header.rest[0], header.rest[1]]);
    let sequence = u16::from_be_bytes([header.rest[2], header.rest[3]]);

    // Track echo reply for ping measurements
    let _reply_info = (identifier, sequence, data.len());

    // Update statistics
    let mut stats = ICMP_STATS.lock();
    stats.echo_reply_out += 1;
}

/// Handle ICMP destination unreachable
fn handle_dest_unreachable(header: IcmpHeader, data: &[u8]) {
    let code = header.code;

    // Handle ICMP destination unreachable codes
    match code {
        3 => { /* Port unreachable - UDP should be notified */ }
        1 => { /* Host unreachable */ }
        0 => { /* Network unreachable */ }
        4 => { /* Fragmentation needed */ }
        _ => {}
    }

    // Update statistics
    let mut stats = ICMP_STATS.lock();
    stats.dest_unreachable_out += 1;

    // Could notify upper layer protocols about unreachable destination
    let _unused_data = data; // data contains original IP header + 8 bytes
}

/// Send an ICMP echo reply
pub fn send_echo_reply(
    src_ip: u32,
    dst_ip: u32,
    identifier: u16,
    sequence: u16,
    data: &[u8],
) {
    // Build ICMP header
    let mut header = [0u8; 8];
    header[0] = 0; // Echo Reply
    header[1] = 0; // Code
    header[2] = 0; // Checksum placeholder
    header[3] = 0;
    header[4] = (identifier >> 8) as u8;
    header[5] = identifier as u8;
    header[6] = (sequence >> 8) as u8;
    header[7] = sequence as u8;

    // Build ICMP packet
    let mut packet = Vec::with_capacity(8 + data.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(data);

    // Calculate checksum
    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    // Send as IPv4 packet with ICMP protocol
    let mut stats = ICMP_STATS.lock();
    stats.msg_out += 1;
    stats.echo_reply_out += 1;
    drop(stats);

    // Build IPv4 packet and send
    let _ = ipv4::send_ipv4(dst_ip, src_ip, 1, &packet);
}

/// Send ICMP destination unreachable
pub fn send_dest_unreachable(
    src_ip: u32,
    dst_ip: u32,
    code: DestinationUnreachableCode,
    original_packet: &[u8],
) {
    // Build ICMP header with original packet data
    let mut header = [0u8; 8];
    header[0] = 3; // Destination Unreachable
    header[1] = code as u8;
    header[2] = 0; // Checksum placeholder
    header[3] = 0;
    // Rest of header is zeroed

    // Build ICMP packet with original packet (up to 8 bytes + original packet)
    let mut packet = Vec::with_capacity(8 + 8 + original_packet.len().min(64));
    packet.extend_from_slice(&header);
    packet.extend_from_slice(original_packet); // Include original packet for context

    // Calculate checksum
    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    let mut stats = ICMP_STATS.lock();
    stats.msg_out += 1;
    stats.dest_unreachable_out += 1;
    drop(stats);

    // Send as IPv4 packet with ICMP protocol
    let _ = ipv4::send_ipv4(dst_ip, src_ip, 1, &packet);
}

/// Send ICMP time exceeded
pub fn send_time_exceeded(
    src_ip: u32,
    dst_ip: u32,
    original_packet: &[u8],
) {
    let mut header = [0u8; 8];
    header[0] = 11; // Time Exceeded
    header[1] = 0; // Code 0: TTL expired
    header[2] = 0; // Checksum placeholder
    header[3] = 0;

    let mut packet = Vec::with_capacity(8 + 8 + original_packet.len().min(64));
    packet.extend_from_slice(&header);
    packet.extend_from_slice(original_packet);

    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    let _ = ipv4::send_ipv4(dst_ip, src_ip, 1, &packet);
}

/// Get ICMP statistics
pub fn get_stats() -> IcmpStats {
    (*ICMP_STATS.lock()).clone()
}
