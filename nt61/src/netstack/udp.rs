//! UDP Protocol Implementation
//
//! Handles User Datagram Protocol for connectionless data delivery.
//
//! Clean-room implementation based on RFC 768.

use crate::netstack::ipv4;
use crate::ke::sync::Spinlock;
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
    /// Length (network byte order)
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

    /// Write to bytes
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
    /// Receive buffer
    pub rx_buf: Vec<UdpPacket>,
}

/// A received UDP packet
pub struct UdpPacket {
    pub src_ip: u32,
    pub src_port: Port,
    pub data: Vec<u8>,
}

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
static UDP_STATS: Spinlock<UdpStats> =
    Spinlock::new(UdpStats::zero());

/// Initialize the UDP module
pub fn init() {
    UDP_SOCKETS.lock().clear();
    let mut stats = UDP_STATS.lock();
    *stats = UdpStats::default();
}

/// Calculate UDP checksum (with pseudo-header)
fn calculate_checksum(src_ip: u32, dst_ip: u32, udp_data: &[u8]) -> u16 {
    let pseudo = [
        (src_ip >> 24) as u8, (src_ip >> 16) as u8, (src_ip >> 8) as u8, src_ip as u8,
        (dst_ip >> 24) as u8, (dst_ip >> 16) as u8, (dst_ip >> 8) as u8, dst_ip as u8,
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

    // Sum UDP data
    for chunk in udp_data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += chunk[0] as u32;
        }
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

/// Create a UDP socket and bind to a local port
pub fn create_socket(local_port: Port, local_ip: u32) -> Option<usize> {
    let mut sockets = UDP_SOCKETS.lock();

    // Check if port is already in use
    if sockets.iter().any(|s| s.local_port == local_port && s.local_ip == local_ip) {
        return None;
    }

    let socket = UdpSocket {
        local_port,
        local_ip,
        remote_port: 0,
        remote_ip: 0,
        rx_buf: Vec::new(),
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
pub fn send(
    socket_idx: usize,
    dst_ip: u32,
    dst_port: Port,
    data: &[u8],
) -> Option<usize> {
    // Extract socket info first to avoid borrow issues
    let (src_ip, local_port) = {
        let sockets = UDP_SOCKETS.lock();
        if socket_idx >= sockets.len() {
            return None;
        }
        let socket = &sockets[socket_idx];
        let src_ip = if socket.local_ip != 0 {
            socket.local_ip
        } else {
            // Get primary IP
            crate::netstack::ipif::get_our_ip_addresses().first().copied()?
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
    if ipv4::send_ipv4(src_ip, dst_ip, 17, &packet) {
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
pub fn udp_input(src_ip: u32, dst_ip: u32, data: &[u8]) {
    let header = match UdpHeader::from_bytes(data) {
        Some(h) => h,
        None => return,
    };

    let payload = if data.len() > UDP_HDR_SIZE {
        &data[UDP_HDR_SIZE..]
    } else {
        &[]
    };

    let mut stats = UDP_STATS.lock();
    stats.datagrams_received += 1;
    drop(stats);

    // Find matching socket and deliver to it
    let mut sockets_mut = UDP_SOCKETS.lock();

    // Look for exact match and deliver
    if let Some(idx) = sockets_mut.iter().position(|s| {
        s.local_port == header.dst_port
            && (s.local_ip == 0 || s.local_ip == dst_ip)
    }) {
        // Deliver to socket
        let packet = UdpPacket {
            src_ip,
            src_port: header.src_port,
            data: payload.to_vec(),
        };
        sockets_mut[idx].rx_buf.push(packet);
    } else {
        // No socket listening, send ICMP port unreachable
        // (simplified - actual implementation would send ICMP)
        let mut stats = UDP_STATS.lock();
        stats.datagrams_dropped += 1;
    }
}

/// Receive a UDP datagram
pub fn receive(
    socket_idx: usize,
    buffer: &mut [u8],
) -> Option<(u32, Port, usize)> {
    let mut sockets = UDP_SOCKETS.lock();

    if socket_idx >= sockets.len() {
        return None;
    }

    let socket = &mut sockets[socket_idx];

    if socket.rx_buf.is_empty() {
        return None;
    }

    let packet = socket.rx_buf.remove(0);
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
    let first = socket.rx_buf.first()?;
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

/// Close a socket
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
