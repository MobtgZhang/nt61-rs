//! TCP/IP Protocol Driver (tcpip.sys)
//
//! Implements the TCP/IP protocol driver. tcpip.sys is the Windows
//! NT 6.1 network protocol stack that provides TCP, UDP, IP, ICMP,
//! and ARP functionality. It sits above NDIS and below the Windows
//! Sockets (Winsock) layer.
//
//! This driver integrates with the existing netstack implementation
//! and exposes it through the standard Windows network stack interface.
//
//! Clean-room implementation. Spec source: RFC 793 (TCP), RFC 768 (UDP),
//! RFC 791 (IP), and Microsoft "Network Driver" reference.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::io::{DeviceObject, DeviceType, DriverObject};
use crate::ke::sync::Spinlock;

const MAX_INTERFACES: usize = 8;

const MAX_TCP_CONNECTIONS: usize = 128;

const MAX_UDP_SOCKETS: usize = 64;

#[derive(Clone, Copy)]
pub struct NetworkInterface {
    pub valid: bool,
    pub interface_index: u32,
    pub ip_address: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway: [u8; 4],
    pub mac_address: [u8; 6],
    pub mtu: u16,
    pub link_speed: u64,  // bits per second
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl NetworkInterface {
    pub const fn new() -> Self {
        Self {
            valid: false,
            interface_index: 0,
            ip_address: [0, 0, 0, 0],
            subnet_mask: [255, 255, 255, 0],
            gateway: [0, 0, 0, 0],
            mac_address: [0, 0, 0, 0, 0, 0],
            mtu: 1500,
            link_speed: 1_000_000_000,  // 1 Gbps
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
}

#[derive(Clone, Copy)]
pub struct TcpConnection {
    pub valid: bool,
    pub state: TcpState,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub window_size: u16,
    pub segments_sent: u64,
    pub segments_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl TcpConnection {
    pub const fn new() -> Self {
        Self {
            valid: false,
            state: TcpState::Closed,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            seq_num: 0,
            ack_num: 0,
            window_size: 8192,
            segments_sent: 0,
            segments_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct UdpSocket {
    pub valid: bool,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl UdpSocket {
    pub const fn new() -> Self {
        Self {
            valid: false,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            datagrams_sent: 0,
            datagrams_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

static mut INTERFACES: [NetworkInterface; MAX_INTERFACES] =
    [const { NetworkInterface::new() }; MAX_INTERFACES];
static mut TCP_CONNECTIONS: [TcpConnection; MAX_TCP_CONNECTIONS] =
    [const { TcpConnection::new() }; MAX_TCP_CONNECTIONS];
static mut UDP_SOCKETS: [UdpSocket; MAX_UDP_SOCKETS] =
    [const { UdpSocket::new() }; MAX_UDP_SOCKETS];

static TCPIP_LOCK: Spinlock<()> = Spinlock::new(());
static INTERFACE_COUNT: AtomicU32 = AtomicU32::new(0);
static TCP_CONNECTION_COUNT: AtomicU32 = AtomicU32::new(0);
static UDP_SOCKET_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn init() {
    let _g = TCPIP_LOCK.lock();
    unsafe {
        INTERFACES[0].valid = true;
        INTERFACES[0].interface_index = 1;
        INTERFACES[0].ip_address = [10, 0, 2, 15];  // Default QEMU address
        INTERFACES[0].subnet_mask = [255, 255, 255, 0];
        INTERFACES[0].gateway = [10, 0, 2, 2];
        INTERFACE_COUNT.store(1, Ordering::Relaxed);
    }

    crate::netstack::init();
}

pub fn register_interface(
    ip_addr: [u8; 4],
    subnet_mask: [u8; 4],
    gateway: [u8; 4],
    mac_addr: [u8; 6],
) -> Option<u32> {
    let _g = TCPIP_LOCK.lock();
    unsafe {
        for (idx, iface) in INTERFACES.iter_mut().enumerate() {
            if !iface.valid {
                iface.valid = true;
                iface.interface_index = (idx + 1) as u32;
                iface.ip_address = ip_addr;
                iface.subnet_mask = subnet_mask;
                iface.gateway = gateway;
                iface.mac_address = mac_addr;
                INTERFACE_COUNT.fetch_add(1, Ordering::Relaxed);
                return Some(iface.interface_index);
            }
        }
    }
    None
}

pub fn tcp_connect(
    local_addr: [u8; 4],
    local_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
) -> Option<usize> {
    let _g = TCPIP_LOCK.lock();
    unsafe {
        for (idx, conn) in TCP_CONNECTIONS.iter_mut().enumerate() {
            if !conn.valid {
                conn.valid = true;
                conn.state = TcpState::SynSent;
                conn.local_addr = local_addr;
                conn.local_port = local_port;
                conn.remote_addr = remote_addr;
                conn.remote_port = remote_port;
                conn.seq_num = 1000;  // Initial sequence number
                TCP_CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);
                return Some(idx);
            }
        }
    }
    None
}

pub fn tcp_close(connection_id: usize) -> bool {
    if connection_id >= MAX_TCP_CONNECTIONS {
        return false;
    }

    let _g = TCPIP_LOCK.lock();
    unsafe {
        let conn = &mut TCP_CONNECTIONS[connection_id];
        if conn.valid {
            conn.state = TcpState::FinWait1;
            conn.valid = false;
            true
        } else {
            false
        }
    }
}

pub fn tcp_send(connection_id: usize, data: &[u8]) -> Option<usize> {
    if connection_id >= MAX_TCP_CONNECTIONS {
        return None;
    }

    let _g = TCPIP_LOCK.lock();
    unsafe {
        let conn = &mut TCP_CONNECTIONS[connection_id];
        if !conn.valid || conn.state != TcpState::Established {
            return None;
        }

        let socket_id = connection_id as u32;
        let result = crate::netstack::tcp::send(
            socket_id,
            data,
        );

        if let Some(bytes_sent) = result {
            conn.segments_sent += 1;
            conn.bytes_sent += bytes_sent as u64;
        }

        result
    }
}

pub fn tcp_recv(connection_id: usize, buffer: &mut [u8]) -> Option<usize> {
    if connection_id >= MAX_TCP_CONNECTIONS {
        return None;
    }

    let _g = TCPIP_LOCK.lock();
    unsafe {
        let conn = &mut TCP_CONNECTIONS[connection_id];
        if !conn.valid || conn.state != TcpState::Established {
            return None;
        }

        None
    }
}

pub fn udp_bind(local_addr: [u8; 4], local_port: u16) -> Option<usize> {
    let _g = TCPIP_LOCK.lock();
    unsafe {
        for (idx, socket) in UDP_SOCKETS.iter_mut().enumerate() {
            if !socket.valid {
                socket.valid = true;
                socket.local_addr = local_addr;
                socket.local_port = local_port;
                UDP_SOCKET_COUNT.fetch_add(1, Ordering::Relaxed);
                return Some(idx);
            }
        }
    }
    None
}

pub fn udp_close(socket_id: usize) -> bool {
    if socket_id >= MAX_UDP_SOCKETS {
        return false;
    }

    let _g = TCPIP_LOCK.lock();
    unsafe {
        let socket = &mut UDP_SOCKETS[socket_id];
        if socket.valid {
            socket.valid = false;
            true
        } else {
            false
        }
    }
}

pub fn udp_sendto(
    socket_id: usize,
    remote_addr: [u8; 4],
    remote_port: u16,
    data: &[u8],
) -> Option<usize> {
    if socket_id >= MAX_UDP_SOCKETS {
        return None;
    }

    let _g = TCPIP_LOCK.lock();
    unsafe {
        let socket = &mut UDP_SOCKETS[socket_id];
        if !socket.valid {
            return None;
        }

        let remote_ip = u32::from_be_bytes(remote_addr);
        let result = crate::netstack::udp::send(
            socket_id as usize,
            remote_ip,
            remote_port,
            data,
        );

        if let Some(bytes_sent) = result {
            socket.datagrams_sent += 1;
            socket.bytes_sent += bytes_sent as u64;
        }

        result
    }
}

pub fn udp_recvfrom(
    socket_id: usize,
    buffer: &mut [u8],
) -> Option<(usize, [u8; 4], u16)> {
    if socket_id >= MAX_UDP_SOCKETS {
        return None;
    }

    let _g = TCPIP_LOCK.lock();
    unsafe {
        let socket = &mut UDP_SOCKETS[socket_id];
        if !socket.valid {
            return None;
        }

        let result = crate::netstack::udp::receive(socket_id, buffer);

        if let Some((src_ip, src_port, bytes_received)) = result {
            socket.datagrams_received += 1;
            socket.bytes_received += bytes_received as u64;
            let addr = [
                (src_ip >> 24) as u8,
                (src_ip >> 16) as u8,
                (src_ip >> 8) as u8,
                src_ip as u8,
            ];
            Some((bytes_received, addr, src_port))
        } else {
            None
        }
    }
}

pub fn interface_count() -> u32 {
    INTERFACE_COUNT.load(Ordering::Relaxed)
}

pub fn tcp_connection_count() -> u32 {
    TCP_CONNECTION_COUNT.load(Ordering::Relaxed)
}

pub fn udp_socket_count() -> u32 {
    UDP_SOCKET_COUNT.load(Ordering::Relaxed)
}

pub fn get_interface_stats(interface_index: u32) -> Option<NetworkInterface> {
    let _g = TCPIP_LOCK.lock();
    unsafe {
        for iface in INTERFACES.iter() {
            if iface.valid && iface.interface_index == interface_index {
                return Some(*iface);
            }
        }
    }
    None
}

pub fn DriverEntry(driver: *mut DriverObject) -> u32 {
    init();
    0 // STATUS_SUCCESS
}

pub mod dispatch {
    use super::*;
    use crate::io::{Irp, IoStackLocation};
    use crate::io::major::*;

    pub fn Create(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }

    pub fn Close(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }

    pub fn DeviceControl(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }
}
