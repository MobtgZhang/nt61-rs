//! ICMP Protocol Implementation
//
//! Handles Internet control Message Protocol for IPv4.
//
//! Clean-room implementation based on RFC 792.

use crate::ke::sync::Spinlock;
use crate::netstack::ipif;
use crate::netstack::ipv4;
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
    /// r#type
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

    /// write to bytes
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

/// Per-probe echo-reply latches, keyed by `(identifier, sequence)`.
/// A fixed table keeps concurrent pings from clobbering each other,
/// which a single global slot could not do.
const ECHO_SLOTS: usize = 16;

#[derive(Clone, Copy, PartialEq)]
struct EchoProbe {
    id: u16,
    seq: u16,
    /// Set by `arm_echo_reply` and cleared again by `take_echo_reply`.
    armed: bool,
    /// Only a real echo reply (type 0) marks this; `take` refuses to
    /// hand out a result for a probe whose reply never arrived.
    replied: bool,
    time: u64,
    size: usize,
}

impl EchoProbe {
    const fn empty() -> Self {
        Self {
            id: 0,
            seq: 0,
            armed: false,
            replied: false,
            time: 0,
            size: 0,
        }
    }
}

static ECHO_PROBES: Spinlock<[EchoProbe; ECHO_SLOTS]> =
    Spinlock::new([EchoProbe::empty(); ECHO_SLOTS]);
static ECHO_CURSOR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

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
pub fn icmp_input(src_ip: u32, dst_ip: u32, data: &[u8]) {
    let header = match IcmpHeader::from_bytes(data) {
        Some(h) => h,
        None => return,
    };

    let icmp_type = header.icmp_type as u8;
    {
        let mut stats = ICMP_STATS.lock();
        stats.msg_in += 1;
        match icmp_type {
            0 => stats.echo_reply_out += 1,
            8 => stats.echo_request_in += 1,
            3 | 4 | 11 | 12 => stats.error_in += 1,
            _ => {}
        }
    }

    match icmp_type {
        0 => handle_echo_reply(header, &data[8..]),
        3 => {
            handle_dest_unreachable(header, &data[8..]);
        }
        4 => {}
        5 => {
            // Redirect
        }
        8 => {
            // Echo Request
            handle_echo_request(src_ip, dst_ip, header, &data[8..]);
        }
        11 => {}
        12 => {}
        _ => {}
    }
}

/// Register a probe for `(identifier, sequence)` before transmitting it.
pub fn arm_echo_reply(identifier: u16, sequence: u16) {
    let mut probes = ECHO_PROBES.lock();
    // Re-arming an existing (id, seq) probe resets it in place instead of
    // growing the table.
    if let Some(slot) = probes
        .iter_mut()
        .find(|p| p.armed && p.id == identifier && p.seq == sequence)
    {
        slot.replied = false;
        slot.time = 0;
        slot.size = 0;
        return;
    }
    if let Some(slot) = probes.iter_mut().find(|p| !p.armed) {
        *slot = EchoProbe {
            id: identifier,
            seq: sequence,
            armed: true,
            replied: false,
            time: 0,
            size: 0,
        };
        return;
    }
    // Table full: evict round-robin. Every slot is an armed probe, so
    // this drops the oldest claim; the matching take simply times out.
    let idx = ECHO_CURSOR.fetch_add(1, core::sync::atomic::Ordering::Relaxed) % ECHO_SLOTS;
    probes[idx] = EchoProbe {
        id: identifier,
        seq: sequence,
        armed: true,
        replied: false,
        time: 0,
        size: 0,
    };
}

/// Consume an echo reply matching `(identifier, sequence)`. Returns
/// `None` while the reply is still in flight, so callers that poll this
/// after `send_echo_request` observe real completion only.
pub fn take_echo_reply(identifier: u16, sequence: u16) -> Option<(u64, usize)> {
    let mut probes = ECHO_PROBES.lock();
    let slot = probes
        .iter_mut()
        .find(|p| p.armed && p.replied && p.id == identifier && p.seq == sequence)?;
    let result = (slot.time, slot.size);
    slot.armed = false;
    slot.replied = false;
    Some(result)
}

/// Send one ICMP echo request through the interface that owns the
/// route to `dst_ip`.
pub fn send_echo_request(dst_ip: u32, identifier: u16, sequence: u16) -> bool {
    let mut header = [0u8; 8];
    header[0] = IcmpType::EchoRequest as u8;
    header[4..6].copy_from_slice(&identifier.to_be_bytes());
    header[6..8].copy_from_slice(&sequence.to_be_bytes());

    let mut packet = Vec::with_capacity(8 + 32);
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&[0u8; 32]);
    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    let route = ipif::route_lookup(dst_ip);
    let src_ip = route
        .and_then(|route| ipif::get_interface(route.if_index))
        .or_else(|| ipif::get_default_interface().and_then(ipif::get_interface))
        .map(|interface| interface.address);
    let Some(src_ip) = src_ip else {
        return false;
    };
    ipv4::send_ipv4(src_ip, dst_ip, 1, &packet)
}

/// handle ICMP echo request
fn handle_echo_request(src_ip: u32, dst_ip: u32, header: IcmpHeader, data: &[u8]) {
    let identifier = u16::from_be_bytes([header.rest[0], header.rest[1]]);
    let sequence = u16::from_be_bytes([header.rest[2], header.rest[3]]);

    // Build echo reply
    send_echo_reply(dst_ip, src_ip, identifier, sequence, data);
}

/// handle ICMP echo reply
fn handle_echo_reply(header: IcmpHeader, data: &[u8]) {
    let identifier = u16::from_be_bytes([header.rest[0], header.rest[1]]);
    let sequence = u16::from_be_bytes([header.rest[2], header.rest[3]]);

    {
        let mut probes = ECHO_PROBES.lock();
        if let Some(slot) = probes
            .iter_mut()
            .find(|p| p.armed && p.id == identifier && p.seq == sequence)
        {
            slot.replied = true;
            slot.time = 0;
            slot.size = data.len().min(i32::MAX as usize);
        }
    }

    // Update statistics
    let mut stats = ICMP_STATS.lock();
    stats.echo_reply_out += 1;
}

/// handle ICMP destination unreachable
fn handle_dest_unreachable(header: IcmpHeader, data: &[u8]) {
    let code = header.code;

    // handle ICMP destination unreachable codes
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
pub fn send_echo_reply(src_ip: u32, dst_ip: u32, identifier: u16, sequence: u16, data: &[u8]) {
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
    let _ = ipv4::send_ipv4(src_ip, dst_ip, 1, &packet);
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
pub fn send_time_exceeded(src_ip: u32, dst_ip: u32, original_packet: &[u8]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn reply_header(id: u16, seq: u16) -> IcmpHeader {
        IcmpHeader {
            icmp_type: IcmpType::EchoReply as u8,
            code: 0,
            checksum: 0,
            rest: [(id >> 8) as u8, id as u8, (seq >> 8) as u8, seq as u8],
        }
    }

    #[test]
    fn echo_reply_only_completes_after_real_reply() {
        // Arming a probe must not let `take` fabricate a result.
        arm_echo_reply(0xA001, 7);
        assert_eq!(take_echo_reply(0xA001, 7), None);

        handle_echo_reply(reply_header(0xA001, 7), &[1, 2, 3, 4]);
        let (_, size) = take_echo_reply(0xA001, 7).expect("reply consumed");
        assert_eq!(size, 4);
        // Consumed once: a second take must fail.
        assert_eq!(take_echo_reply(0xA001, 7), None);
    }

    #[test]
    fn concurrent_probes_do_not_clobber_each_other() {
        arm_echo_reply(0xA002, 1);
        arm_echo_reply(0xA003, 2);

        // Reply to the second probe only.
        handle_echo_reply(reply_header(0xA003, 2), &[0xAA; 8]);

        assert_eq!(take_echo_reply(0xA002, 1), None);
        let (_, size) = take_echo_reply(0xA003, 2).expect("second probe reply");
        assert_eq!(size, 8);
    }

    #[test]
    fn mismatched_sequence_is_ignored() {
        arm_echo_reply(0xA004, 9);
        handle_echo_reply(reply_header(0xA004, 8), &[0xFF; 2]);
        assert_eq!(take_echo_reply(0xA004, 9), None);
    }
}
