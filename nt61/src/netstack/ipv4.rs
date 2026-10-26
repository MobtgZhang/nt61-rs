//! IPv4 Protocol Implementation
//
//! Handles IPv4 packet parsing, construction, and processing.
//
//! Clean-room implementation based on RFC 791.

use crate::drivers::net::NicType;
use crate::netstack::eth::{self, ETHER_TYPE_IPV4};

/// IPv4 header constants
pub const IPV4_HDR_SIZE: usize = 20;
pub const IPV4_MIN_SIZE: usize = 20;
pub const IPV4_MAX_SIZE: usize = 65535;
/// Maximum IPv4 header length: IHL is a 4-bit field, so the largest legal
/// header is 15 * 4 = 60 bytes (RFC 791 section 3.1).
pub const IPV4_MAX_HDR_SIZE: usize = 60;

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
    /// r#type of Service
    pub tos: u8,
    /// Total length (network byte order)
    pub total_length: u16,
    /// Identification (network byte order)
    pub identification: u16,
    /// flags (3 bits) and Fragment offset (13 bits) - network byte order
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
        self.total_length as usize
    }

    /// Get the payload length
    /// Get the payload length.
    ///
    /// A malformed packet can advertise a `total_length` smaller than its
    /// IHL, which would underflow. Return 0 for such packets rather than
    /// wrapping around to a huge value.
    pub fn payload_length(&self) -> usize {
        self.total_length().saturating_sub(self.header_length())
    }

    /// Version nibble (must be 4 for this header type).
    pub fn version(&self) -> u8 {
        (self.version_ihl >> 4) as u8
    }

    /// Validate that `data` is a self-consistent IPv4 packet.
    ///
    /// `header_length()` is derived from an attacker-controlled IHL field,
    /// so callers must never index a slice with it before checking that the
    /// buffer actually contains that many bytes. RFC 791 requires IHL >= 5;
    /// `total_length` must be >= IHL and must not exceed the buffer.
    pub fn validate(&self, data: &[u8]) -> bool {
        let ihl = self.header_length();
        if ihl < IPV4_MIN_SIZE || ihl > IPV4_MAX_HDR_SIZE {
            return false;
        }
        if data.len() < ihl {
            return false;
        }
        if self.version() != 4 {
            return false;
        }
        let total = self.total_length();
        if total < ihl || total > data.len() {
            return false;
        }
        true
    }

    /// Check if don't fragment flag is set
    pub fn dont_fragment(&self) -> bool {
        (self.flags_offset & 0x4000) != 0
    }

    /// Check if more fragments flag is set
    pub fn more_fragments(&self) -> bool {
        (self.flags_offset & 0x2000) != 0
    }

    /// Get fragment offset
    pub fn fragment_offset(&self) -> u16 {
        self.flags_offset & 0x1FFF
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

    /// write to bytes
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
    if !header.validate(data) {
        return None;
    }
    if !verify_checksum(&header, &data[..header.header_length()]) {
        return None;
    }
    let payload_start = header.header_length();
    let payload_end = header.total_length();
    let payload = &data[payload_start..payload_end];
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
    packet.push(0); // TOS
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
/// Quote the offending datagram inside an ICMP error.
///
/// RFC 792 requires the internet header plus the first 64 bits of the
/// payload. Quoting more than that turns a small error into an amplification
/// vector, so the copy is capped.
fn quote_original(header: &Ipv4Header, payload: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(IPV4_HDR_SIZE + 8);
    let mut hdr = [0u8; IPV4_HDR_SIZE];
    header.to_bytes(&mut hdr);
    out.extend_from_slice(&hdr[..header.header_length().min(IPV4_HDR_SIZE)]);
    out.extend_from_slice(&payload[..payload.len().min(8)]);
    out
}

/// RFC 792 forbids generating an ICMP error in response to an ICMP error:
/// two hosts that both reject each other's errors would loop forever.
fn is_icmp_error(payload: &[u8]) -> bool {
    payload.len() >= 2 && matches!(payload[0], 3 | 11)
}

/// Deliver a complete datagram to the upper-layer protocol.
fn dispatch_datagram(header: &Ipv4Header, payload: &[u8], _nic_type: NicType, _nic_index: usize) {
    if !crate::netstack::ipsec::check_inbound_policy(header.src_ip, header.dst_ip, false) {
        return;
    }

    let mut header = header.clone();
    let mut translated_payload = payload.to_vec();
    let mut payload = translated_payload.as_slice();
    if crate::netstack::nat::is_enabled()
        && (header.protocol == 1 || header.protocol == 6 || header.protocol == 17)
    {
        let nat_dst_port = if header.protocol == 1 && payload.len() >= 8 {
            u16::from_be_bytes([payload[4], payload[5]])
        } else {
            transport_ports(header.protocol, payload).1
        };
        if let Some((internal_ip, internal_port)) =
            crate::netstack::nat::translate_inbound(nat_dst_port, header.protocol)
        {
            header.dst_ip = internal_ip;
            if header.protocol == 1 && payload.len() >= 8 {
                translated_payload[4..6].copy_from_slice(&internal_port.to_be_bytes());
                let icmp_checksum =
                    crate::netstack::ipv4::calculate_checksum(&translated_payload);
                translated_payload[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
            } else if header.protocol == 6 || header.protocol == 17 {
                rewrite_transport_destination_port(&mut translated_payload, internal_port);
            }
            payload = &translated_payload;
        }
    }

    let (src_port, dst_port) = transport_ports(header.protocol, payload);
    let action = crate::netstack::wfp::filter_packet(
        crate::netstack::wfp::FilterLayer::InboundIpv4,
        header.src_ip,
        header.dst_ip,
        src_port,
        dst_port,
        header.protocol,
        _nic_index as u32,
    );
    if !matches!(
        action,
        crate::netstack::wfp::FilterAction::Permit | crate::netstack::wfp::FilterAction::Continue
    ) {
        return;
    }

    match Protocol::from_u8(header.protocol) {
        Some(Protocol::Icmp) => {
            crate::netstack::icmp::icmp_input(header.src_ip, header.dst_ip, payload)
        }
        Some(Protocol::Tcp) => {
            crate::netstack::tcp::tcp_input(header.src_ip, header.dst_ip, payload)
        }
        Some(Protocol::Udp) => {
            if !crate::netstack::udp::udp_input(header.src_ip, header.dst_ip, payload)
                && header.protocol != 1
                && !is_icmp_error(payload)
            {
                crate::netstack::icmp::send_dest_unreachable(
                    header.dst_ip,
                    header.src_ip,
                    crate::netstack::icmp::DestinationUnreachableCode::PortUnreachable,
                    &quote_original(&header, payload),
                );
            }
        }

        _ => {
            // RFC 1122 section 3.2: an unsupported upper-layer protocol must
            // be reported to the sender as Destination Unreachable, code 2.
            if header.protocol != 1 && !is_icmp_error(payload) {
                crate::netstack::icmp::send_dest_unreachable(
                    header.dst_ip,
                    header.src_ip,
                    crate::netstack::icmp::DestinationUnreachableCode::ProtocolUnreachable,
                    &quote_original(&header, payload),
                );
            }
        }
    }
}

/// Forward a datagram we do not own.
///
/// RFC 1122 section 3.1: a router must decrement TTL before forwarding and
/// report a TTL expiry or an unroutable destination back to the sender.
pub fn forward_ipv4(header: &Ipv4Header, payload: &[u8]) -> bool {
    let Some(route) = crate::netstack::routing::find_route(header.dst_ip) else {
        if header.protocol != 1 && !is_icmp_error(payload) {
            crate::netstack::icmp::send_dest_unreachable(
                header.dst_ip,
                header.src_ip,
                crate::netstack::icmp::DestinationUnreachableCode::NetworkUnreachable,
                &quote_original(&header, payload),
            );
        }
        return false;
    };

    let ttl = match header.ttl.checked_sub(1) {
        Some(0) | None => {
            if header.protocol != 1 && !is_icmp_error(payload) {
                crate::netstack::icmp::send_time_exceeded(
                    header.dst_ip,
                    header.src_ip,
                    &quote_original(&header, payload),
                );
            }
            return false;
        }
        Some(t) => t,
    };

    // Rebuild the datagram with the decremented TTL. The header struct has no
    // storage for IP options, so options are not preserved on the forward
    // path; the fixed 20-byte header is what can be reconstructed faithfully.
    let mut packet = alloc::vec::Vec::with_capacity(IPV4_HDR_SIZE + payload.len());
    let mut hdr = [0u8; IPV4_HDR_SIZE];
    header.to_bytes(&mut hdr);
    packet.extend_from_slice(&hdr);
    packet[8] = ttl;
    packet[10] = 0;
    packet[11] = 0;
    let checksum = calculate_checksum(&packet);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = checksum as u8;
    packet.extend_from_slice(payload);

    let next_hop = if route.gateway != 0 {
        route.gateway
    } else {
        header.dst_ip
    };
    let dst_mac = match crate::netstack::arp::arp_resolve(next_hop) {
        Some(mac) => mac,
        None => return false,
    };
    let src_mac = match crate::netstack::ethif::get_primary_mac() {
        Some(mac) => mac,
        None => {
            crate::hal::serial::write_string_always("[NET-IPV4] no primary mac\r\n");
            return false;
        }
    };

    let frame = crate::netstack::eth::build_ethernet_frame(
        &dst_mac,
        &src_mac,
        crate::netstack::eth::ETHER_TYPE_IPV4,
        &packet,
    );
    let Some((nic_type, nic_index)) = crate::netstack::ethif::get_primary_interface() else {
        return false;
    };
    crate::drivers::net::send_to_nic(nic_type, nic_index, &frame)
}

pub fn ipv4_input(header: &Ipv4Header, payload: &[u8], nic_type: NicType, nic_index: usize) {
    use crate::netstack::ipif;

    // Reassembly first. A fragment other than the first, or any fragment with
    // MF set, cannot be dispatched until the whole datagram is present.
    if header.fragment_offset() != 0 || header.more_fragments() {
        let reassembled = crate::netstack::fragmentation::process_fragment(
            header.src_ip,
            header.dst_ip,
            header.protocol,
            u16::from_be(header.identification),
            header.fragment_offset(),
            header.more_fragments(),
            payload.to_vec(),
        );
        if let Some(datagram) = reassembled {
            dispatch_datagram(header, &datagram, nic_type, nic_index);
        }
        return;
    }

    // Check if the packet is for us
    let our_ips = ipif::get_our_ip_addresses();
    let is_for_us = our_ips.iter().any(|&ip| ip == header.dst_ip);

    // Also check for broadcast
    let is_broadcast = header.dst_ip == 0xFFFFFFFF || is_broadcast_ip(header.dst_ip);

    if !is_for_us && !is_broadcast {
        forward_ipv4(header, payload);
        return;
    }

    // Check TTL
    if header.ttl <= 1 {
        if header.protocol != 1 && !is_icmp_error(payload) {
            crate::netstack::icmp::send_time_exceeded(
                header.dst_ip,
                header.src_ip,
                &quote_original(&header, payload),
            );
        }
        return;
    }

    dispatch_datagram(header, payload, nic_type, nic_index);
}

/// Check if an IP address is a broadcast address
fn is_broadcast_ip(ip: u32) -> bool {
    // Check for subnet broadcast (all host bits set)
    // For now, just check for 255.255.255.255
    ip == 0xFFFFFFFF
}

/// Build an IPv4 fragment with explicit identification, flags, and
/// fragment offset. Used by `send_ipv4` to split payloads that
/// exceed the link MTU.
fn build_ipv4_fragment(
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    ttl: u8,
    identification: u16,
    more_fragments: bool,
    fragment_offset: u16,
    payload: &[u8],
) -> alloc::vec::Vec<u8> {
    let total_length = (IPV4_HDR_SIZE + payload.len()) as u16;
    let mut packet = alloc::vec::Vec::with_capacity(IPV4_HDR_SIZE + payload.len());

    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&total_length.to_be_bytes());
    packet.extend_from_slice(&identification.to_be_bytes());
    let flags_frag =
        (if more_fragments { 0x2000u16 } else { 0u16 }) | fragment_offset;
    packet.extend_from_slice(&flags_frag.to_be_bytes());
    packet.push(ttl);
    packet.push(protocol);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&src_ip.to_be_bytes());
    packet.extend_from_slice(&dst_ip.to_be_bytes());
    let checksum = calculate_checksum(&packet);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = checksum as u8;
    packet.extend_from_slice(payload);
    packet
}

fn transport_ports(protocol: u8, payload: &[u8]) -> (u16, u16) {
    match protocol {
        6 | 17 if payload.len() >= 4 => (
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[2], payload[3]]),
        ),
        _ => (0, 0),
    }
}

/// Rewrite the ICMP identifier used for connection tracking.
fn rewrite_icmp_identifier(payload: &mut [u8], identifier: u16) -> bool {
    if payload.len() < 8 {
        return false;
    }
    payload[4..6].copy_from_slice(&identifier.to_be_bytes());
    true
}

fn rewrite_transport_source_port(payload: &mut [u8], port: u16) -> bool {
    if payload.len() < 2 {
        return false;
    }
    payload[..2].copy_from_slice(&port.to_be_bytes());
    true
}

fn rewrite_transport_destination_port(payload: &mut [u8], port: u16) -> bool {
    if payload.len() < 4 {
        return false;
    }
    payload[2..4].copy_from_slice(&port.to_be_bytes());
    true
}

/// Send an IPv4 packet
pub fn send_ipv4(src_ip: u32, dst_ip: u32, protocol: u8, payload: &[u8]) -> bool {
    if crate::netstack::ipsec::check_outbound_policy(src_ip, dst_ip, 0, 0, protocol)
        == crate::netstack::ipsec::PolicyAction::Protect
    {
        return false;
    }

    let (src_port, dst_port) = transport_ports(protocol, payload);
    let action = crate::netstack::wfp::filter_packet(
        crate::netstack::wfp::FilterLayer::OutboundIpv4,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        0,
    );
    if !matches!(
        action,
        crate::netstack::wfp::FilterAction::Permit | crate::netstack::wfp::FilterAction::Continue
    ) {
        return false;
    }

    let mut translated_payload = None;
    let mut src_ip = src_ip;
    if crate::netstack::nat::is_enabled()
        && !crate::netstack::ipif::get_our_ip_addresses().contains(&dst_ip)
    {
        let Some(public_ip) = crate::netstack::nat::public_ip() else {
            return false;
        };
        if protocol == 1 {
            if payload.len() >= 8 && matches!(payload[0], 0 | 8) {
                let icmp_port = u16::from_be_bytes([payload[4], payload[5]]);
                let Some((nat_ip, nat_port)) = crate::netstack::nat::translate_outbound(
                    src_ip,
                    icmp_port,
                    dst_ip,
                    0,
                    protocol,
                    public_ip,
                ) else {
                    return false;
                };
                let mut payload = payload.to_vec();
                if !rewrite_icmp_identifier(&mut payload, nat_port) {
                    return false;
                }
                translated_payload = Some(payload);
                src_ip = nat_ip;
            }
        } else if protocol == 6 || protocol == 17 {
            let Some((nat_ip, nat_port)) = crate::netstack::nat::translate_outbound(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
                public_ip,
            ) else {
                return false;
            };
            let mut payload = payload.to_vec();
            if !rewrite_transport_source_port(&mut payload, nat_port) {
                return false;
            }
            translated_payload = Some(payload);
            src_ip = nat_ip;
        }
    }
    let payload = translated_payload.as_deref().unwrap_or(payload);

    // Loopback shortcut: 127.0.0.0/8 must NEVER hit the wire.
    // Re-inject the packet locally through ipv4_input with the
    // primary NIC type, which dispatches to TCP/UDP/ICMP just
    // like a packet from the network would.
    let our_ips = crate::netstack::ipif::get_our_ip_addresses();
    if (dst_ip & 0xFF000000) == 0x7F000000 || (our_ips.contains(&dst_ip) && src_ip == dst_ip) {
        let packet = build_ipv4_packet(src_ip, dst_ip, protocol, 64, payload);
        if let Some((header, ip_payload)) = parse_ipv4_header(&packet) {
            ipv4_input(&header, ip_payload, NicType::VirtioNet, 0);
            return true;
        }
        crate::hal::serial::write_string_always("[NET-IPV4] loopback build failed\r\n");
        return false;
    }

    // Resolve the next hop (gateway or final destination) via the
    // routing table. Falls back to the final destination when no
    // route exists.
    let next_hop_ip = crate::netstack::routing::find_route(dst_ip)
        .map(|route| if route.gateway == 0 { dst_ip } else { route.gateway })
        .unwrap_or(dst_ip);

    // Determine the effective MTU (Ethernet 1500 minus the
    // 14-byte Ethernet header).
    let mtu = 1500usize - 14;
    let identification: u16 = 0;
    let fragments = crate::netstack::fragmentation::fragment_packet(
        payload, mtu, identification,
    );
    let fragmented = fragments.len() > 1;

    // Resolve ARP for the next hop (gateway or destination).
    let dst_mac = if next_hop_ip == 0xFFFF_FFFF {
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    } else {
        if our_ips.contains(&next_hop_ip) && src_ip != dst_ip {
            crate::netstack::ethif::get_primary_mac().unwrap_or([0; 6])
        } else {
            match crate::netstack::arp::arp_resolve(next_hop_ip) {
                Some(mac) => mac,
                None => return false,
            }
        }
    };

    // Get our MAC address
    let src_mac = match crate::netstack::ethif::get_primary_mac() {
        Some(mac) => mac,
        None => {
            crate::hal::serial::write_string_always("[NET-IPV4] no primary mac\r\n");
            return false;
        }
    };

    // Send to NIC
    let Some((nic_type, nic_idx)) = crate::netstack::ethif::get_primary_interface() else {
        crate::hal::serial::write_string_always("[NET-IPV4] no primary interface\r\n");
        return false;
    };

    // Send each fragment (or the single packet) as its own
    // Ethernet frame. Non-fragmented payloads go through the
    // original builder for backward compatibility.
    let mut all_sent = true;
    let mut offset_units = 0u16;
    for (i, fragment_payload) in fragments.iter().enumerate() {
        let more = i < fragments.len() - 1;
        let packet = if fragmented {
            build_ipv4_fragment(
                src_ip, dst_ip, protocol, 64, identification, more,
                offset_units, fragment_payload,
            )
        } else {
            build_ipv4_packet(src_ip, dst_ip, protocol, 64, fragment_payload)
        };
        offset_units += ((fragment_payload.len() as u16) + 7) / 8;

        let frame =
            eth::build_ethernet_frame(&dst_mac, &src_mac, ETHER_TYPE_IPV4, &packet);
        let sent = crate::drivers::net::send_to_nic(nic_type, nic_idx, &frame);
        if !sent {
            crate::hal::serial::write_string_always("[NET-IPV4] nic send failed\r\n");
            all_sent = false;
        }
    }
    all_sent
}
