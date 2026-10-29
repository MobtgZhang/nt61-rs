//! UDP Protocol Implementation
//
//! Handles User Datagram Protocol for connectionless data delivery.
//
//! Clean-room implementation based on RFC 768.

use crate::ke::sync::Spinlock;
use crate::netstack::ipv4;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// UDP header size
pub const UDP_HDR_SIZE: usize = 8;

/// UDP port
pub type Port = u16;

/// UDP header structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct UdpHeader {
    /// Source port (network byte order)
    pub src_port: u16,
    /// Destination port (network byte order)
    pub dst_port: u16,
    /// length (network byte order)
    pub length: u16,
    /// Checksum (network byte order)
    pub checksum: u16,
}

impl UdpHeader {
    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<UdpHeader> {
        if data.len() < UDP_HDR_SIZE {
            return None;
        }

        Some(UdpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    /// write to bytes
    pub fn to_bytes(&self, data: &mut [u8]) {
        if data.len() < UDP_HDR_SIZE {
            return;
        }

        data[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        data[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        data[4..6].copy_from_slice(&self.length.to_be_bytes());
        data[6..8].copy_from_slice(&self.checksum.to_be_bytes());
    }
}

/// UDP socket state
pub struct UdpSocket {
    /// Local port
    pub local_port: Port,
    /// Local IP (0 = any)
    pub local_ip: u32,
    /// Remote port (0 = unbound)
    pub remote_port: Port,
    /// Remote IP (0 = unbound)
    pub remote_ip: u32,
    /// Receive buffer (bounded, FIFO)
    pub rx_buf: VecDeque<UdpPacket>,
}

/// A received UDP packet
pub struct UdpPacket {
    pub src_ip: u32,
    pub src_port: Port,
    pub data: Vec<u8>,
}

/// Per-socket receive queue limit. Datagrams beyond this bound drop the
/// oldest queued packet so a silent reader cannot exhaust kernel memory.
pub const UDP_RX_QUEUE_MAX: usize = 64;

/// Global UDP socket table
static UDP_SOCKETS: Spinlock<Vec<UdpSocket>> = Spinlock::new(Vec::new());

/// UDP statistics
pub struct UdpStats {
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub datagrams_dropped: u64,
    pub checksum_errors: u64,
}

impl Clone for UdpStats {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for UdpStats {}

impl UdpStats {
    pub const fn new() -> Self {
        Self {
            datagrams_sent: 0,
            datagrams_received: 0,
            datagrams_dropped: 0,
            checksum_errors: 0,
        }
    }

    pub const fn zero() -> Self {
        Self {
            datagrams_sent: 0,
            datagrams_received: 0,
            datagrams_dropped: 0,
            checksum_errors: 0,
        }
    }
}

impl Default for UdpStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Global UDP statistics
static UDP_STATS: Spinlock<UdpStats> = Spinlock::new(UdpStats::zero());

/// Initialize the UDP module
pub fn init() {
    UDP_SOCKETS.lock().clear();
    let mut stats = UDP_STATS.lock();
    *stats = UdpStats::default();
}

/// Calculate UDP checksum (with pseudo-header)
fn calculate_checksum(src_ip: u32, dst_ip: u32, udp_data: &[u8]) -> u16 {
    let pseudo = [
        (src_ip >> 24) as u8,
        (src_ip >> 16) as u8,
        (src_ip >> 8) as u8,
        src_ip as u8,
        (dst_ip >> 24) as u8,
        (dst_ip >> 16) as u8,
        (dst_ip >> 8) as u8,
        dst_ip as u8,
        0,  // Reserved
        17, // UDP protocol number
        ((udp_data.len() >> 8) & 0xFF) as u8,
        (udp_data.len() & 0xFF) as u8,
    ];

    let mut sum: u32 = 0;

    // Sum pseudo-header
    for chunk in pseudo.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
    }

    // Sum the UDP datagram in 16-bit network-order words. Pad an odd
    // trailing byte explicitly with zero.
    let mut words = udp_data.chunks_exact(2);
    for chunk in words.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(byte) = words.remainder().first() {
        sum += u32::from(*byte) << 8;
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    if sum == 0 {
        0xFFFF
    } else {
        !sum as u16
    }
}

/// create a UDP socket and bind to a local port
pub fn create_socket(mut local_port: Port, local_ip: u32) -> Option<usize> {
    let mut sockets = UDP_SOCKETS.lock();

    // Kernel-assigned ports are drawn from the IANA dynamic range.
    // Allocate before the duplicate check so a caller can simply pass
    // zero and receive a port that no other UDP socket owns.
    if local_port == 0 {
        local_port = (49152..=u16::MAX)
            .find(|candidate| !sockets.iter().any(|socket| socket.local_port == *candidate))?;
    }

    // Check if port is already in use
    if sockets
        .iter()
        .any(|s| s.local_port == local_port && s.local_ip == local_ip)
    {
        return None;
    }

    let socket = UdpSocket {
        local_port,
        local_ip,
        remote_port: 0,
        remote_ip: 0,
        rx_buf: VecDeque::new(),
    };

    sockets.push(socket);
    Some(sockets.len() - 1)
}

/// Bind a UDP socket to a remote address
pub fn connect(socket_idx: usize, remote_ip: u32, remote_port: Port) -> bool {
    let mut sockets = UDP_SOCKETS.lock();

    if socket_idx >= sockets.len() {
        return false;
    }

    sockets[socket_idx].remote_ip = remote_ip;
    sockets[socket_idx].remote_port = remote_port;
    true
}

/// Send a UDP datagram
pub fn send(socket_idx: usize, dst_ip: u32, dst_port: Port, data: &[u8]) -> Option<usize> {
    // Extract socket info first to avoid borrow issues
    let (src_ip, local_port) = {
        let sockets = UDP_SOCKETS.lock();
        if socket_idx >= sockets.len() {
            return None;
        }
        let socket = &sockets[socket_idx];
        let src_ip = if dst_ip == 0xFFFF_FFFF && socket.local_ip == 0 {
            0
        } else if socket.local_ip != 0 {
            socket.local_ip
        } else {
            // Get primary IP
            crate::netstack::ipif::get_our_ip_addresses()
                .first()
                .copied()?
        };
        (src_ip, socket.local_port)
    };

    // Build UDP header
    let length = (UDP_HDR_SIZE + data.len()) as u16;

    let mut header = [0u8; UDP_HDR_SIZE];
    let udp_header = UdpHeader {
        src_port: local_port,
        dst_port,
        length,
        checksum: 0, // Checksum is optional for IPv4
    };
    udp_header.to_bytes(&mut header);

    // Build UDP packet
    let mut packet = Vec::with_capacity(UDP_HDR_SIZE + data.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(data);

    // Calculate checksum
    let checksum = calculate_checksum(src_ip, dst_ip, &packet);
    packet[6] = (checksum >> 8) as u8;
    packet[7] = checksum as u8;

    // Send via IPv4
    let sent = ipv4::send_ipv4(src_ip, dst_ip, 17, &packet);
    if sent {
        let mut stats = UDP_STATS.lock();
        stats.datagrams_sent += 1;
        return Some(data.len());
    }

    None
}

/// Send on connected socket
pub fn send_connected(socket_idx: usize, data: &[u8]) -> Option<usize> {
    let sockets = UDP_SOCKETS.lock();

    if socket_idx >= sockets.len() {
        return None;
    }

    let socket = &sockets[socket_idx];
    if socket.remote_port == 0 || socket.remote_ip == 0 {
        return None; // Not connected
    }

    let dst_ip = socket.remote_ip;
    let dst_port = socket.remote_port;

    drop(sockets);

    send(socket_idx, dst_ip, dst_port, data)
}

/// Process incoming UDP packet
/// Deliver a datagram to a bound socket.
///
/// Returns `true` when a socket accepted it. The caller (the IPv4 input path)
/// is responsible for the ICMP Port Unreachable because RFC 1122 requires the
/// error to quote the *internet header*, which only the IP layer has.
pub fn udp_input(src_ip: u32, dst_ip: u32, data: &[u8]) -> bool {
    let header = match UdpHeader::from_bytes(data) {
        Some(h) => h,
        None => return false,
    };

    let payload = if data.len() > UDP_HDR_SIZE {
        &data[UDP_HDR_SIZE..]
    } else {
        &[]
    };

    // RFC 768: a datagram is verified against its checksum unless the
    // sender left it 0 (legal only over IPv4). The recomputation runs
    // over the datagram *with* its checksum field included, so a valid
    // datagram folds to 0; anything else is corrupt and must not be
    // delivered as if it came from the claimed source.
    if header.checksum != 0 {
        let expected = calculate_checksum(src_ip, dst_ip, data);
        if expected != 0 {
            let mut stats = UDP_STATS.lock();
            stats.checksum_errors += 1;
            stats.datagrams_dropped += 1;
            return false;
        }
    }

    let mut stats = UDP_STATS.lock();
    stats.datagrams_received += 1;
    drop(stats);

    // Find matching socket and deliver to it
    let mut sockets_mut = UDP_SOCKETS.lock();

    // Look for exact match and deliver
    if let Some(idx) = sockets_mut
        .iter()
        .position(|s| s.local_port == header.dst_port && (s.local_ip == 0 || s.local_ip == dst_ip))
    {
        // Deliver to socket
        let packet = UdpPacket {
            src_ip,
            src_port: header.src_port,
            data: payload.to_vec(),
        };
        let queue = &mut sockets_mut[idx].rx_buf;
        if queue.len() >= UDP_RX_QUEUE_MAX {
            // Make room for the newest datagram; the dropped packet is
            // accounted as a drop rather than silently overwriting.
            queue.pop_front();
            let mut stats = UDP_STATS.lock();
            stats.datagrams_dropped += 1;
        }
        queue.push_back(packet);
        true
    } else {
        // No socket listening: the caller reports Port Unreachable.
        let mut stats = UDP_STATS.lock();
        stats.datagrams_dropped += 1;
        false
    }
}

/// Receive a UDP datagram
pub fn receive(socket_idx: usize, buffer: &mut [u8]) -> Option<(u32, Port, usize)> {
    let mut sockets = UDP_SOCKETS.lock();

    if socket_idx >= sockets.len() {
        return None;
    }

    let socket = &mut sockets[socket_idx];

    if socket.rx_buf.is_empty() {
        return None;
    }

    let packet = socket.rx_buf.pop_front()?;
    let copy_len = buffer.len().min(packet.data.len());
    buffer[..copy_len].copy_from_slice(&packet.data[..copy_len]);

    Some((packet.src_ip, packet.src_port, copy_len))
}

/// Receive without removing from buffer
pub fn peek(socket_idx: usize) -> Option<UdpPacket> {
    let sockets = UDP_SOCKETS.lock();

    if socket_idx >= sockets.len() {
        return None;
    }

    let socket = &sockets[socket_idx];
    let first = socket.rx_buf.front()?;
    Some(UdpPacket {
        src_ip: first.src_ip,
        src_port: first.src_port,
        data: first.data.clone(),
    })
}

/// Get socket count
pub fn socket_count() -> usize {
    UDP_SOCKETS.lock().len()
}

/// close a socket
pub fn close_socket(socket_idx: usize) {
    let mut sockets = UDP_SOCKETS.lock();
    if socket_idx < sockets.len() {
        sockets.remove(socket_idx);
    }
}

/// Get UDP statistics
pub fn get_stats() -> UdpStats {
    (*UDP_STATS.lock()).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(
        src_ip: u32,
        dst_ip: u32,
        src_port: Port,
        dst_port: Port,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = Vec::with_capacity(UDP_HDR_SIZE + payload.len());
        packet.resize(UDP_HDR_SIZE, 0);
        let header = UdpHeader {
            src_port,
            dst_port,
            length: (UDP_HDR_SIZE + payload.len()) as u16,
            checksum: 0,
        };
        header.to_bytes(&mut packet);
        packet.extend_from_slice(payload);
        let checksum = calculate_checksum(src_ip, dst_ip, &packet);
        packet[6] = (checksum >> 8) as u8;
        packet[7] = checksum as u8;
        packet
    }

    #[test]
    fn udp_input_checksum_and_bounded_queue() {
        // Serialised in one test because the socket table is a global.

        // -- valid checksum is delivered --
        let socket_idx = create_socket(0x5B01, 0).expect("bind");
        let packet = datagram(
            u32::from_be_bytes([10, 0, 0, 2]),
            u32::from_be_bytes([10, 0, 0, 1]),
            1234,
            0x5B01,
            b"hello udp",
        );
        assert!(udp_input(
            u32::from_be_bytes([10, 0, 0, 2]),
            u32::from_be_bytes([10, 0, 0, 1]),
            &packet
        ));
        let mut buf = [0u8; 64];
        let (_, src_port, len) = receive(socket_idx, &mut buf).expect("datagram");
        assert_eq!(src_port, 1234);
        assert_eq!(len, 9);
        assert_eq!(&buf[..len], b"hello udp");

        // -- corrupt checksum is rejected and counted --
        create_socket(0x5B02, 0).expect("bind");
        let mut bad = datagram(
            u32::from_be_bytes([10, 0, 0, 2]),
            u32::from_be_bytes([10, 0, 0, 1]),
            1234,
            0x5B02,
            b"payload",
        );
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(!udp_input(
            u32::from_be_bytes([10, 0, 0, 2]),
            u32::from_be_bytes([10, 0, 0, 1]),
            &bad
        ));
        let stats = get_stats();
        assert!(stats.checksum_errors >= 1, "checksum error must be counted");

        // -- rx queue is bounded and FIFO --
        let socket_idx = create_socket(0x5B03, 0).expect("bind");
        for i in 0..(UDP_RX_QUEUE_MAX + 8) {
            let packet = datagram(
                u32::from_be_bytes([10, 0, 0, 2]),
                u32::from_be_bytes([10, 0, 0, 1]),
                2000,
                0x5B03,
                &[i as u8; 4],
            );
            assert!(udp_input(
                u32::from_be_bytes([10, 0, 0, 2]),
                u32::from_be_bytes([10, 0, 0, 1]),
                &packet
            ));
        }
        let sockets = UDP_SOCKETS.lock();
        assert_eq!(sockets[socket_idx].rx_buf.len(), UDP_RX_QUEUE_MAX);
        // FIFO: the newest datagram must be at the back.
        let back = sockets[socket_idx].rx_buf.back().unwrap();
        assert_eq!(back.data, [((UDP_RX_QUEUE_MAX + 7) as u8); 4]);
        drop(sockets);
    }
}
