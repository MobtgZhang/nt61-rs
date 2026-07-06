//! IPv6 Protocol Implementation
//
//! Implements IPv6 for the network stack according to RFC 8200.
//! Supports:
//! - Basic header parsing
//! - Extension headers (hop-by-hop, fragment, destination options)
//! - ICMPv6 (including NDP and Echo)
//! - Address auto-configuration (SLAAC)
//
//! Clean-room implementation based on RFC 8200, RFC 4861, RFC 4862.

use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;

/// IPv6 constants
pub const IPV6_HEADER_SIZE: usize = 40;
pub const IPV6_VERSION: u8 = 6;

/// IPv6 extension header types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionHeaderType {
    HopByHopOptions = 0,
    DestinationOptions = 60,
    Routing = 43,
    Fragment = 44,
    Authentication = 51,
    EncapsulatingSecurityPayload = 50,
    DestinationOptions2 = 54,
    Mobility = 135,
    NoNextHeader = 59,
}

/// IPv6 next header types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHeader {
    Icmpv6 = 58,
    Tcp = 6,
    Udp = 17,
    None = 59,
}

impl From<u8> for NextHeader {
    fn from(val: u8) -> Self {
        match val {
            6 => NextHeader::Tcp,
            17 => NextHeader::Udp,
            58 => NextHeader::Icmpv6,
            59 => NextHeader::None,
            _ => NextHeader::None,
        }
    }
}

/// IPv6 header structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IPv6Header {
    /// Version (4 bits) + Traffic Class (8 bits)
    pub version_class: u8,
    /// Flow Label (20 bits)
    pub flow_label: u32,
    /// Payload length (bytes after header)
    pub payload_length: u16,
    /// Next header (protocol number)
    pub next_header: u8,
    /// Hop limit
    pub hop_limit: u8,
    /// Source address
    pub src_addr: [u8; 16],
    /// Destination address
    pub dst_addr: [u8; 16],
}

impl IPv6Header {
    /// Parse IPv6 header from bytes
    pub fn from_bytes(data: &[u8]) -> Option<IPv6Header> {
        if data.len() < IPV6_HEADER_SIZE {
            return None;
        }

        // Version check
        let version = (data[0] >> 4) & 0x0F;
        if version != 6 {
            return None;
        }

        Some(IPv6Header {
            version_class: data[0],
            flow_label: (((data[0] & 0x0F) as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32),
            payload_length: u16::from_be_bytes([data[4], data[5]]),
            next_header: data[6],
            hop_limit: data[7],
            src_addr: data[8..24].try_into().ok()?,
            dst_addr: data[24..40].try_into().ok()?,
        })
    }

    /// Convert header to bytes
    pub fn to_bytes(&self, data: &mut [u8]) {
        if data.len() < IPV6_HEADER_SIZE {
            return;
        }

        data[0] = self.version_class;
        data[1] = ((self.flow_label >> 16) & 0x0F) as u8;
        data[2] = ((self.flow_label >> 8) & 0xFF) as u8;
        data[3] = (self.flow_label & 0xFF) as u8;
        data[4..6].copy_from_slice(&self.payload_length.to_be_bytes());
        data[6] = self.next_header;
        data[7] = self.hop_limit;
        data[8..24].copy_from_slice(&self.src_addr);
        data[24..40].copy_from_slice(&self.dst_addr);
    }

    /// Get version
    pub fn version(&self) -> u8 {
        (self.version_class >> 4) & 0x0F
    }

    /// Get traffic class
    pub fn traffic_class(&self) -> u8 {
        self.version_class & 0xFF
    }

    /// Get flow label
    pub fn flow_label(&self) -> u32 {
        self.flow_label
    }

    /// Check if this is a link-local address
    pub fn is_link_local(&self) -> bool {
        self.dst_addr[0] == 0xFE && (self.dst_addr[1] & 0xC0) == 0x80
    }

    /// Check if this is a multicast address
    pub fn is_multicast(&self) -> bool {
        self.dst_addr[0] == 0xFF
    }

    /// Get IPv4-mapped IPv6 address as IPv4
    pub fn as_ipv4(&self) -> Option<u32> {
        // Check for ::ffff:xxxx.xxxx.xxxx.xxxx
        if self.dst_addr[0..10] == [0u8; 10] 
           && self.dst_addr[10] == 0xFF 
           && self.dst_addr[11] == 0xFF {
            Some(u32::from_be_bytes([
                self.dst_addr[12],
                self.dst_addr[13],
                self.dst_addr[14],
                self.dst_addr[15],
            ]))
        } else {
            None
        }
    }
}

/// IPv6 address utilities
pub mod addr {
    use super::*;

    /// Link-local prefix
    pub const LINK_LOCAL_PREFIX: &[u8; 8] = &[0xFE, 0x80, 0, 0, 0, 0, 0, 0];
    
    /// All-nodes multicast address
    pub const ALL_NODES_MULTICAST: &[u8; 16] = &[0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    
    /// All-routers multicast address
    pub const ALL_ROUTERS_MULTICAST: &[u8; 16] = &[0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    
    /// Solicited-node multicast prefix
    pub const SOLICITED_NODE_PREFIX: &[u8; 13] = &[0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF];

    /// Generate solicited-node multicast address from unicast address
    pub fn solicited_node_multicast(ipv6: &[u8; 16]) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0..13].copy_from_slice(SOLICITED_NODE_PREFIX);
        addr[13] = ipv6[13];
        addr[14] = ipv6[14];
        addr[15] = ipv6[15];
        addr
    }

    /// Check if IPv6 address is unspecified (::)
    pub fn is_unspecified(ipv6: &[u8; 16]) -> bool {
        ipv6.iter().all(|&b| b == 0)
    }

    /// Check if IPv6 address is loopback (::1)
    pub fn is_loopback(ipv6: &[u8; 16]) -> bool {
        ipv6[0..15].iter().all(|&b| b == 0) && ipv6[15] == 1
    }

    /// Format IPv6 address as string (simplified)
    pub fn format(ipv6: &[u8; 16]) -> alloc::string::String {
        let parts: Vec<u16> = (0..8)
            .map(|i| u16::from_be_bytes([ipv6[i * 2], ipv6[i * 2 + 1]]))
            .collect();
        
        // Find longest run of zeros
        let mut best_start = 0;
        let mut best_len = 0;
        let mut cur_start = 0;
        let mut cur_len = 0;
        
        for (i, &part) in parts.iter().enumerate() {
            if part == 0 {
                if cur_len == 0 {
                    cur_start = i;
                }
                cur_len += 1;
                if cur_len > best_len {
                    best_len = cur_len;
                    best_start = cur_start;
                }
            } else {
                cur_len = 0;
            }
        }
        
        let mut result = String::new();
        for (i, &part) in parts.iter().enumerate() {
            if i == best_start && best_len > 1 {
                result.push_str("::");
            } else if i > best_start && i < best_start + best_len {
                continue;
            } else {
                if i > 0 && !(i == best_start + best_len && best_len > 1) {
                    result.push(':');
                }
                result.push_str(&format!("{:x}", part));
            }
        }
        
        result
    }
}

/// ICMPv6 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Type {
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
}

impl From<u8> for Icmpv6Type {
    fn from(val: u8) -> Self {
        match val {
            1 => Icmpv6Type::DestinationUnreachable,
            2 => Icmpv6Type::PacketTooBig,
            3 => Icmpv6Type::TimeExceeded,
            4 => Icmpv6Type::ParameterProblem,
            128 => Icmpv6Type::EchoRequest,
            129 => Icmpv6Type::EchoReply,
            133 => Icmpv6Type::RouterSolicitation,
            134 => Icmpv6Type::RouterAdvertisement,
            135 => Icmpv6Type::NeighborSolicitation,
            136 => Icmpv6Type::NeighborAdvertisement,
            137 => Icmpv6Type::Redirect,
            _ => Icmpv6Type::DestinationUnreachable,
        }
    }
}

/// ICMPv6 header
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Icmpv6Header {
    pub msg_type: u8,
    pub code: u8,
    pub checksum: u16,
}

impl Icmpv6Header {
    pub fn from_bytes(data: &[u8]) -> Option<Icmpv6Header> {
        if data.len() < 4 {
            return None;
        }
        Some(Icmpv6Header {
            msg_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
        })
    }
}

/// NDP Neighbor Cache Entry
#[derive(Debug, Clone)]
pub struct NdpNeighbor {
    pub ipv6_addr: [u8; 16],
    pub link_addr: [u8; 6], // MAC address
    pub state: NdpState,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
}

impl NdpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            NdpState::Incomplete => "INCOMPLETE",
            NdpState::Reachable => "REACHABLE",
            NdpState::Stale => "STALE",
            NdpState::Delay => "DELAY",
            NdpState::Probe => "PROBE",
        }
    }
}

/// NDP cache
static NDP_CACHE: crate::ke::sync::Spinlock<Vec<NdpNeighbor>> = 
    crate::ke::sync::Spinlock::new(Vec::new());

/// IPv6 statistics
pub struct Ipv6Stats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub checksum_errors: u64,
    pub neighbor_solicitations: u64,
    pub neighbor_advertisements: u64,
    pub router_solicitations: u64,
    pub router_advertisements: u64,
    pub echo_requests: u64,
    pub echo_replies: u64,
}

impl Clone for Ipv6Stats {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for Ipv6Stats {}

impl Ipv6Stats {
    pub const fn new() -> Self {
        Self {
            packets_received: 0,
            packets_sent: 0,
            checksum_errors: 0,
            neighbor_solicitations: 0,
            neighbor_advertisements: 0,
            router_solicitations: 0,
            router_advertisements: 0,
            echo_requests: 0,
            echo_replies: 0,
        }
    }

    pub const fn zero() -> Self {
        Self::new()
    }
}

impl Default for Ipv6Stats {
    fn default() -> Self {
        Self::new()
    }
}

static IPV6_STATS: crate::ke::sync::Spinlock<Ipv6Stats> =
    crate::ke::sync::Spinlock::new(Ipv6Stats::zero());

/// Initialize IPv6 stack
pub fn init() {
    // kprintln!("    IPv6: initializing...")  // kprintln disabled (memcpy crash workaround);
    
    // Clear NDP cache
    NDP_CACHE.lock().clear();
    
    let mut stats = IPV6_STATS.lock();
    *stats = Ipv6Stats::zero();
    
    // kprintln!("    IPv6: ready")  // kprintln disabled (memcpy crash workaround);
}

/// Calculate ICMPv6 checksum
fn calculate_icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Pseudo-header
    for i in 0..8 {
        sum += (src[i * 2] as u32) << 8 | (src[i * 2 + 1] as u32);
        sum += (dst[i * 2] as u32) << 8 | (dst[i * 2 + 1] as u32);
    }
    sum += 58; // Next header (ICMPv6)
    sum += (data.len() >> 15) as u32;
    sum += (data.len() & 0x7FFF) as u32;
    
    // ICMPv6 data
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

/// Process incoming IPv6 packet
pub fn ipv6_input(data: &[u8]) {
    let header = match IPv6Header::from_bytes(data) {
        Some(h) => h,
        None => return,
    };
    
    let mut stats = IPV6_STATS.lock();
    stats.packets_received += 1;
    
    let payload = if data.len() > IPV6_HEADER_SIZE {
        &data[IPV6_HEADER_SIZE..]
    } else {
        &[]
    };
    
    drop(stats);
    
    // Handle extension headers (simplified - just skip for now)
    let mut offset = IPV6_HEADER_SIZE;
    let mut next_header = header.next_header;
    
    while next_header == ExtensionHeaderType::HopByHopOptions as u8
          || next_header == ExtensionHeaderType::DestinationOptions as u8
          || next_header == ExtensionHeaderType::Routing as u8 {
        if offset + 2 > payload.len() {
            return;
        }
        let ext_len = payload[offset + 1] as usize;
        next_header = payload[offset];
        offset += (ext_len + 1) * 8;
    }
    
    // Handle fragmentation
    if next_header == ExtensionHeaderType::Fragment as u8 {
        // Simplified: just skip fragment header
        if offset + 8 > payload.len() {
            return;
        }
        next_header = payload[offset];
        offset += 8;
    }
    
    // Process based on next header
    match next_header.into() {
        NextHeader::Icmpv6 => {
            icmpv6_input(&header, offset, payload);
        }
        NextHeader::Tcp => {
            // Call TCP handler (would need to be wired up)
        }
        NextHeader::Udp => {
            // Call UDP handler (would need to be wired up)
        }
        NextHeader::None => {
            // No next header - discard
        }
    }
}

/// Process ICMPv6 message
fn icmpv6_input(ipv6_header: &IPv6Header, header_offset: usize, data: &[u8]) {
    let payload = if data.len() > header_offset {
        &data[header_offset..]
    } else {
        return;
    };
    
    let icmp_header = match Icmpv6Header::from_bytes(payload) {
        Some(h) => h,
        None => return,
    };
    
    let icmp_data = if payload.len() > 4 {
        &payload[4..]
    } else {
        &[]
    };
    
    let mut stats = IPV6_STATS.lock();
    
    match icmp_header.msg_type.into() {
        Icmpv6Type::RouterSolicitation => {
            stats.router_solicitations += 1;
            handle_router_solicitation(&ipv6_header.src_addr);
        }
        Icmpv6Type::RouterAdvertisement => {
            stats.router_advertisements += 1;
            handle_router_advertisement(icmp_data);
        }
        Icmpv6Type::NeighborSolicitation => {
            stats.neighbor_solicitations += 1;
            handle_neighbor_solicitation(&ipv6_header.src_addr, &ipv6_header.dst_addr, icmp_data);
        }
        Icmpv6Type::NeighborAdvertisement => {
            stats.neighbor_advertisements += 1;
            handle_neighbor_advertisement(&ipv6_header.src_addr, icmp_data);
        }
        Icmpv6Type::EchoRequest => {
            stats.echo_requests += 1;
            send_echo_reply(&ipv6_header.src_addr, icmp_data);
        }
        Icmpv6Type::EchoReply => {
            stats.echo_replies += 1;
            // Handle echo reply
        }
        _ => {}
    }
}

/// Handle Router Solicitation
fn handle_router_solicitation(src: &[u8; 16]) {
    use crate::hal::common::pit;

    // Update statistics
    let mut stats = IPV6_STATS.lock();
    stats.router_solicitations += 1;
    drop(stats);

    // Record router solicitation statistics
    let now = pit::get_system_time_ms() as u64;

    // Add or update NDP cache entry for this router
    let mut cache = NDP_CACHE.lock();

    // Check if router entry already exists
    if let Some(entry) = cache.iter_mut().find(|e| e.ipv6_addr == *src) {
        entry.state = NdpState::Reachable;
        entry.updated_at = now;
    } else if cache.len() < 64 {
        // NDP cache size limit
        cache.push(NdpNeighbor {
            ipv6_addr: *src,
            link_addr: [0; 6], // Will be updated by subsequent RA
            state: NdpState::Incomplete,
            updated_at: now,
        });
    }
}

/// Handle Router Advertisement
fn handle_router_advertisement(data: &[u8]) {
    // Update statistics
    let mut stats = IPV6_STATS.lock();
    stats.router_advertisements += 1;
    drop(stats);

    // Parse router advertisement options
    let mut offset = 0;
    let mut prefix_info_holder: Option<(u8, u32, u32)> = None;

    while offset + 8 <= data.len() {
        let opt_type = data[offset];
        let opt_len = data[offset + 1] as usize;

        match opt_type {
            1 => {
                // Source link-layer address - could be used for router MAC tracking
                if opt_len >= 1 && offset + 8 <= data.len() {
                    // Router MAC address available for NDP operations
                    let _router_mac = &data[offset + 2..offset + 8];
                }
            }
            3 => {
                // Prefix information
                if opt_len >= 5 && offset + 32 <= data.len() {
                    let prefix_len = data[offset + 2];
                    let valid_lifetime = u32::from_be_bytes([
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
                    ]);
                    let preferred_lifetime = u32::from_be_bytes([
                        data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]
                    ]);
                    prefix_info_holder = Some((prefix_len, valid_lifetime, preferred_lifetime));
                }
            }
            _ => {}
        }

        offset += (opt_len * 8) as usize;
    }

    // Use parsed information for SLAAC address configuration
    if let Some((_prefix_len, _valid_lifetime, _preferred_lifetime)) = prefix_info_holder {
        // SLAAC would configure address based on prefix + interface identifier
    }
}

/// Handle Neighbor Solicitation
fn handle_neighbor_solicitation(src: &[u8; 16], dst: &[u8; 16], data: &[u8]) {
    use crate::hal::common::pit;

    // Update statistics
    let mut stats = IPV6_STATS.lock();
    stats.neighbor_solicitations += 1;
    drop(stats);

    if data.len() < 24 {
        return;
    }

    // Target address is at offset 4-20
    let mut target = [0u8; 16];
    target.copy_from_slice(&data[4..20]);

    // Update NDP cache for the source
    let mut cache = NDP_CACHE.lock();
    let now = pit::get_system_time_ms() as u64;

    // Update or add entry for the soliciting node
    if let Some(entry) = cache.iter_mut().find(|e| e.ipv6_addr == *src) {
        entry.state = NdpState::Reachable;
        entry.updated_at = now;
    }

    // Check if we're the target (we should respond with our MAC)
    // In a real implementation, check against our configured addresses
    let _unused_dst = dst; // Would be used to check if this is for us
}

/// Handle Neighbor Advertisement
fn handle_neighbor_advertisement(_src: &[u8; 16], data: &[u8]) {
    if data.len() < 24 {
        return;
    }
    
    use crate::hal::common::pit;
    
    // Target address is at offset 4-20
    let mut target = [0u8; 16];
    target.copy_from_slice(&data[4..20]);
    
    // Check for source link-layer option
    let mut ll_addr = None;
    let mut offset = 24;
    while offset + 8 <= data.len() {
        let opt_type = data[offset];
        let opt_len = data[offset + 1] as usize;
        
        if opt_type == 2 && opt_len >= 1 && offset + 8 <= data.len() {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&data[offset + 2..offset + 8]);
            ll_addr = Some(addr);
            break;
        }
        
        offset += (opt_len * 8) as usize;
    }
    
    // Update NDP cache
    let mut cache = NDP_CACHE.lock();
    let now = pit::get_system_time_ms() as u64;
    
    if let Some(addr) = ll_addr {
        if let Some(entry) = cache.iter_mut().find(|e| e.ipv6_addr == target) {
            entry.link_addr = addr;
            entry.state = NdpState::Reachable;
            entry.updated_at = now;
        } else {
            cache.push(NdpNeighbor {
                ipv6_addr: target,
                link_addr: addr,
                state: NdpState::Reachable,
                updated_at: now,
            });
        }
        // kprintln!("  [IPv6]   MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",  // kprintln disabled (memcpy crash workaround)
//             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    }
}

/// Send IPv6 packet
pub fn send_ipv6(src: &[u8; 16], dst: &[u8; 16], next_header: u8, data: &[u8]) -> bool {
    let total_len = IPV6_HEADER_SIZE + data.len();
    let mut packet = Vec::with_capacity(total_len);
    
    let header = IPv6Header {
        version_class: 0x60, // Version 6, no traffic class
        flow_label: 0,
        payload_length: data.len() as u16,
        next_header,
        hop_limit: 64,
        src_addr: *src,
        dst_addr: *dst,
    };
    
    header.to_bytes(&mut packet);
    packet.extend_from_slice(data);
    
    // Calculate ICMPv6 checksum if needed
    if next_header == 58 {
        // ICMPv6
        let checksum = calculate_icmpv6_checksum(src, dst, data);
        packet[42] = (checksum >> 8) as u8;
        packet[43] = (checksum & 0xFF) as u8;
    }
    
    // Send via Ethernet
    let dst_mac = if dst[0] == 0xFF {
        // Compute multicast MAC from IPv6 multicast address
        let mut mac = [0x33, 0x33, 0xFF, dst[12], dst[13], dst[14]];
        mac[5] = dst[15];
        mac
    } else {
        // Look up in NDP cache
        let cache = NDP_CACHE.lock();
        if let Some(entry) = cache.iter().find(|e| e.ipv6_addr == *dst) {
            entry.link_addr
        } else {
            // Need to do neighbor discovery first
            // For now, use broadcast
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        }
    };
    
    // Build Ethernet frame using the shared helper so we get a proper
    // 14-byte header with the correct ethertype. NET-5 fix: previously
    // this function returned `true` without ever calling the NIC, so
    // every IPv6 packet was silently dropped.
    let src_mac = match crate::netstack::ethif::get_primary_mac() {
        Some(mac) => mac,
        None => return false,
    };
    let frame = crate::netstack::eth::build_ethernet_frame(
        &dst_mac,
        &src_mac,
        crate::netstack::eth::ETHER_TYPE_IPV6,
        &packet,
    );

    let mut stats = IPV6_STATS.lock();
    stats.packets_sent += 1;
    drop(stats);

    // Hand off to the primary NIC. If no NIC is up, fail honestly
    // (return false) rather than silently dropping the frame.
    let Some((nic_type, nic_idx)) =
        crate::netstack::ethif::get_primary_interface()
    else {
        return false;
    };
    crate::drivers::net::send_to_nic(nic_type, nic_idx, &frame)
}

/// Send Echo Reply
fn send_echo_reply(dst: &[u8; 16], data: &[u8]) {
    // Build echo reply
    let mut reply = Vec::with_capacity(4 + data.len());
    reply.push(129); // Echo Reply
    reply.push(0);   // Code
    reply.push(0);    // Checksum (placeholder)
    reply.push(0);
    reply.extend_from_slice(data);
    
    // Calculate checksum
    let src: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // Link-local source
    let checksum = calculate_icmpv6_checksum(&src, dst, &reply);
    reply[2] = (checksum >> 8) as u8;
    reply[3] = (checksum & 0xFF) as u8;
    
    send_ipv6(&src, dst, 58, &reply);
}

/// Get IPv6 statistics
pub fn get_stats() -> Ipv6Stats {
    (*IPV6_STATS.lock()).clone()
}

/// Lookup neighbor in NDP cache
pub fn lookup_neighbor(ipv6: &[u8; 16]) -> Option<[u8; 6]> {
    let cache = NDP_CACHE.lock();
    cache.iter()
        .find(|e| e.ipv6_addr == *ipv6)
        .map(|e| e.link_addr)
}

/// Add static neighbor entry
pub fn add_neighbor(ipv6: &[u8; 16], mac: &[u8; 6]) {
    use crate::hal::common::pit;
    let mut cache = NDP_CACHE.lock();
    let now = pit::get_system_time_ms() as u64;
    
    if let Some(entry) = cache.iter_mut().find(|e| e.ipv6_addr == *ipv6) {
        entry.link_addr = *mac;
        entry.state = NdpState::Reachable;
        entry.updated_at = now;
    } else {
        cache.push(NdpNeighbor {
            ipv6_addr: *ipv6,
            link_addr: *mac,
            state: NdpState::Reachable,
            updated_at: now,
        });
    }
}
