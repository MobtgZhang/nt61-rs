//! BSD-Style Socket API
//
//! Provides a BSD-compatible socket interface for network applications.
//
//! Clean-room implementation.

use crate::netstack::tcp;
use crate::netstack::udp;
use crate::netstack::ipif;
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

/// Socket types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketType {
    Stream = 1,
    Dgram = 2,
    Raw = 3,
}

/// Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
    Icmp = 1,
    Raw = 0,
}

impl Protocol {
    pub fn from_socket_type(t: SocketType) -> Self {
        match t {
            SocketType::Stream => Protocol::Tcp,
            SocketType::Dgram => Protocol::Udp,
            SocketType::Raw => Protocol::Raw,
        }
    }
}

/// Socket state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Closed,
    Bound,
    Listening,
    Connected,
    Closing,
}

/// Socket address
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockAddr {
    pub family: u16,
    pub port: u16,
    pub addr: [u8; 4],
    pub zeros: [u8; 8],
}

impl SockAddr {
    pub fn new(family: u16, port: u16, ip: u32) -> Self {
        Self {
            family,
            port,
            addr: [(ip >> 0) as u8, (ip >> 8) as u8, (ip >> 16) as u8, (ip >> 24) as u8],
            zeros: [0; 8],
        }
    }

    pub fn ip(&self) -> u32 {
        u32::from_be_bytes(self.addr)
    }

    pub fn to_string(&self) -> alloc::string::String {
        alloc::format!(
            "{}:{}.{}.{}.{}:{}",
            if self.family == 2 { "AF_INET" } else { "AF_UNKNOWN" },
            self.addr[0], self.addr[1], self.addr[2], self.addr[3],
            u16::from_be(self.port)
        )
    }
}

/// Socket structure
pub struct Socket {
    pub socket_type: SocketType,
    pub protocol: Protocol,
    pub state: SocketState,
    pub local_addr: Option<SockAddr>,
    pub remote_addr: Option<SockAddr>,
    pub tcp_socket_id: Option<u32>,
    pub udp_socket_idx: Option<usize>,
    pub rx_buf: Vec<u8>,
    pub tx_buf: Vec<u8>,
    pub id: u32,
    pub bind_port: u16,
    /// Connections that have completed the 3-way handshake on this
    /// listening socket and are waiting to be returned by `accept`.
    /// Empty unless `state == SocketState::Listening`.
    pub accept_queue: Vec<u32>,
    /// Backlog hint from the most recent `listen()` call. Used to
    /// cap the length of `accept_queue`.
    pub listen_backlog: u32,
}

impl Socket {
    pub fn new(socket_type: SocketType) -> Self {
        Self {
            socket_type,
            protocol: Protocol::from_socket_type(socket_type),
            state: SocketState::Closed,
            local_addr: None,
            remote_addr: None,
            tcp_socket_id: None,
            udp_socket_idx: None,
            rx_buf: Vec::new(),
            tx_buf: Vec::new(),
            id: 0,
            bind_port: 0,
            accept_queue: Vec::new(),
            listen_backlog: 0,
        }
    }
}

/// Global socket table
static SOCKETS: Spinlock<Vec<Socket>> = Spinlock::new(Vec::new());

/// Next socket ID
static NEXT_SOCKET_ID: AtomicU32 = AtomicU32::new(1);

/// Socket error codes
#[derive(Debug)]
pub enum SocketError {
    WouldBlock,
    ConnectionRefused,
    ConnectionReset,
    NotConnected,
    InvalidSocket,
    AddressInUse,
    AddressNotAvailable,
    InvalidArgument,
    OutOfMemory,
}

impl SocketError {
    pub fn as_i32(&self) -> i32 {
        match self {
            SocketError::WouldBlock => -1,
            SocketError::ConnectionRefused => -2,
            SocketError::ConnectionReset => -3,
            SocketError::NotConnected => -4,
            SocketError::InvalidSocket => -5,
            SocketError::AddressInUse => -6,
            SocketError::AddressNotAvailable => -7,
            SocketError::InvalidArgument => -8,
            SocketError::OutOfMemory => -9,
        }
    }
}

pub fn init() {
    SOCKETS.lock().clear();
}

pub fn socket(socket_type: SocketType, protocol: Protocol) -> Option<u32> {
    let mut sockets = SOCKETS.lock();

    let socket_id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    let mut socket = Socket::new(socket_type);
    socket.id = socket_id;
    socket.protocol = protocol;

    sockets.push(socket);
    Some(socket_id)
}

pub fn socket_auto(socket_type: SocketType) -> Option<u32> {
    socket(socket_type, Protocol::from_socket_type(socket_type))
}

pub fn bind(socket_id: u32, addr: &SockAddr) -> Result<(), SocketError> {
    let mut sockets = SOCKETS.lock();

    let port = addr.port;

    // Check port conflicts first (before mutable borrow)
    let port_conflict = sockets.iter().any(|s| s.id != socket_id && s.bind_port == port && s.state != SocketState::Closed);
    if port_conflict {
        return Err(SocketError::AddressInUse);
    }

    let socket = sockets.iter_mut()
        .find(|s| s.id == socket_id)
        .ok_or(SocketError::InvalidSocket)?;

    socket.local_addr = Some(*addr);
    socket.bind_port = port;
    socket.state = SocketState::Bound;

    Ok(())
}

pub fn listen(socket_id: u32, backlog: u32) -> Result<(), SocketError> {
    let mut sockets = SOCKETS.lock();

    let socket = sockets.iter_mut()
        .find(|s| s.id == socket_id)
        .ok_or(SocketError::InvalidSocket)?;

    if socket.socket_type != SocketType::Stream {
        return Err(SocketError::InvalidArgument);
    }

    if socket.state != SocketState::Bound {
        return Err(SocketError::NotConnected);
    }

    // Reserve capacity for the accept queue up front so the 3-way
    // handshake path can push without reallocating.
    let cap = if backlog == 0 { 8 } else { backlog as usize };
    socket.accept_queue = Vec::with_capacity(cap);
    socket.listen_backlog = backlog;
    socket.state = SocketState::Listening;
    Ok(())
}

pub fn accept(socket_id: u32) -> Result<u32, SocketError> {
    let mut sockets = SOCKETS.lock();

    let socket = sockets.iter_mut()
        .find(|s| s.id == socket_id)
        .ok_or(SocketError::InvalidSocket)?;

    if socket.socket_type != SocketType::Stream {
        return Err(SocketError::InvalidArgument);
    }

    if socket.state != SocketState::Listening {
        return Err(SocketError::InvalidSocket);
    }

    // Pop the first fully-handshaken connection from the queue.
    // If empty, return WouldBlock so the caller can retry / sleep.
    match socket.accept_queue.first().copied() {
        Some(peer_id) => {
            socket.accept_queue.remove(0);
            Ok(peer_id)
        }
        None => Err(SocketError::WouldBlock),
    }
}

/// Enqueue a freshly accepted TCP connection onto the listening
/// socket's accept queue. Returns false if the queue is full (the
/// caller should drop the connection per RFC 793 §3.7 backlog).
pub fn enqueue_accept(listen_socket_id: u32, peer_tcp_id: u32) -> bool {
    let mut sockets = SOCKETS.lock();
    let Some(socket) = sockets.iter_mut().find(|s| s.id == listen_socket_id)
    else {
        return false;
    };
    if socket.state != SocketState::Listening {
        return false;
    }
    let cap = if socket.listen_backlog == 0 {
        8
    } else {
        socket.listen_backlog as usize
    };
    if socket.accept_queue.len() >= cap {
        return false;
    }
    socket.accept_queue.push(peer_tcp_id);
    true
}

pub fn connect(socket_id: u32, addr: &SockAddr) -> Result<(), SocketError> {
    let mut sockets = SOCKETS.lock();

    let socket = sockets.iter_mut()
        .find(|s| s.id == socket_id)
        .ok_or(SocketError::InvalidSocket)?;

    match socket.socket_type {
        SocketType::Stream => {
            let local_ip = ipif::get_our_ip_addresses().first().copied().unwrap_or(0);
            let local_port = 0;
            let remote_ip = addr.ip();
            let remote_port = addr.port;

            if let Some(tcp_id) = tcp::connect(local_ip, local_port, remote_ip, remote_port) {
                socket.tcp_socket_id = Some(tcp_id);
                socket.remote_addr = Some(*addr);
                socket.state = SocketState::Connected;
                Ok(())
            } else {
                Err(SocketError::ConnectionRefused)
            }
        }
        SocketType::Dgram => {
            let socket_idx = udp::create_socket(addr.port, addr.ip())
                .ok_or(SocketError::ConnectionRefused)?;
            socket.udp_socket_idx = Some(socket_idx);
            socket.remote_addr = Some(*addr);
            socket.state = SocketState::Connected;
            Ok(())
        }
        _ => Err(SocketError::InvalidArgument),
    }
}

pub fn send(socket_id: u32, data: &[u8]) -> Result<usize, SocketError> {
    let sockets = SOCKETS.lock();

    if let Some(s) = sockets.iter().find(|s| s.id == socket_id && s.state == SocketState::Connected) {
        match s.socket_type {
            SocketType::Stream => {
                if let Some(tcp_id) = s.tcp_socket_id {
                    drop(sockets);
                    tcp::send(tcp_id, data).map(|n| n as usize)
                        .ok_or(SocketError::ConnectionReset)
                } else {
                    Err(SocketError::NotConnected)
                }
            }
            SocketType::Dgram => {
                if let Some(udp_idx) = s.udp_socket_idx {
                    if let Some(remote) = s.remote_addr {
                        drop(sockets);
                        udp::send(udp_idx, remote.ip(), remote.port, data)
                            .map(|n| n as usize)
                            .ok_or(SocketError::WouldBlock)
                    } else {
                        Err(SocketError::NotConnected)
                    }
                } else {
                    Err(SocketError::NotConnected)
                }
            }
            _ => Err(SocketError::InvalidArgument),
        }
    } else {
        Err(SocketError::InvalidSocket)
    }
}

pub fn recv(socket_id: u32, buffer: &mut [u8]) -> Result<usize, SocketError> {
    let sockets = SOCKETS.lock();

    if let Some(s) = sockets.iter().find(|s| s.id == socket_id && s.state == SocketState::Connected) {
        match s.socket_type {
            SocketType::Stream => {
                if let Some(tcp_id) = s.tcp_socket_id {
                    drop(sockets);
                    tcp::receive(tcp_id, buffer)
                        .map(|n| n as usize)
                        .ok_or(SocketError::WouldBlock)
                } else {
                    Err(SocketError::NotConnected)
                }
            }
            SocketType::Dgram => {
                if let Some(udp_idx) = s.udp_socket_idx {
                    drop(sockets);
                    let result = udp::receive(udp_idx, buffer);
                    match result {
                        Some((_, _, n)) => Ok(n),
                        None => Err(SocketError::WouldBlock),
                    }
                } else {
                    Err(SocketError::NotConnected)
                }
            }
            _ => Err(SocketError::InvalidArgument),
        }
    } else {
        Err(SocketError::InvalidSocket)
    }
}

pub fn close(socket_id: u32) -> Result<(), SocketError> {
    let mut sockets = SOCKETS.lock();

    let socket = sockets.iter_mut()
        .find(|s| s.id == socket_id)
        .ok_or(SocketError::InvalidSocket)?;

    if let Some(tcp_id) = socket.tcp_socket_id.take() {
        tcp::close(tcp_id);
    }
    if let Some(udp_idx) = socket.udp_socket_idx.take() {
        udp::close_socket(udp_idx);
    }

    socket.state = SocketState::Closed;
    socket.bind_port = 0;
    socket.rx_buf.clear();
    socket.tx_buf.clear();

    Ok(())
}

pub fn get_state(socket_id: u32) -> Option<SocketState> {
    let sockets = SOCKETS.lock();
    sockets.iter().find(|s| s.id == socket_id).map(|s| s.state)
}

pub fn socket_count() -> usize {
    SOCKETS.lock().len()
}
