//! Winsock 2 types, constants, and structures
//!
//! This module defines the Windows Sockets 2.0 types and constants
//! that match the Microsoft Winsock 2 API specification for NT 6.1.

pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;

pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;

pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_ICMP: i32 = 1;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const IPPROTO_IPV6: i32 = 41;

pub const SOL_SOCKET: i32 = 0xFFFF;
pub const IPPROTO_IPV4: i32 = 4;

pub const SO_DEBUG: i32 = 0x0001;
pub const SO_ACCEPTCONN: i32 = 0x0002;
pub const SO_REUSEADDR: i32 = 0x0004;
pub const SO_KEEPALIVE: i32 = 0x0008;
pub const SO_DONTROUTE: i32 = 0x0010;
pub const SO_BROADCAST: i32 = 0x0020;
pub const SO_LINGER: i32 = 0x0080;
pub const SO_OOBINLINE: i32 = 0x0100;
pub const SO_SNDBUF: i32 = 0x1001;
pub const SO_RCVBUF: i32 = 0x1002;
pub const SO_SNDLOWAT: i32 = 0x1003;
pub const SO_RCVLOWAT: i32 = 0x1004;
pub const SO_SNDTIMEO: i32 = 0x1005;
pub const SO_RCVTIMEO: i32 = 0x1006;
pub const SO_ERROR: i32 = 0x1007;
pub const SO_TYPE: i32 = 0x1008;

pub const TCP_NODELAY: i32 = 0x0001;

pub const FIONREAD: i32 = 0x4004667F;
pub const FIONBIO: i32 = 0x8004667Eu32 as i32;
pub const FIOASYNC: i32 = 0x8004667Du32 as i32;

pub const SD_RECEIVE: i32 = 0;
pub const SD_SEND: i32 = 1;
pub const SD_BOTH: i32 = 2;

pub const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC8000006;
pub const SIO_KEEPALIVE_VALS: u32 = 0x98000004;
pub const SIO_RCVALL: u32 = 0x98000001;

pub const MSG_PEEK: i32 = 0x02;
pub const MSG_OOB: i32 = 0x01;
pub const MSG_DONTROUTE: i32 = 0x04;

pub const WSA_FLAG_OVERLAPPED: u32 = 0x01;
pub const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;

pub const FD_SETSIZE: usize = 64;

pub const INVALID_SOCKET: usize = !0;
pub const SOCKET_ERROR: i32 = -1;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

impl Default for sockaddr_in {
    fn default() -> Self {
        Self {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct sockaddr_storage {
    pub ss_family: u16,
    pub __ss_pad1: [u8; 6],
    pub __ss_align: i64,
    pub __ss_pad2: [u8; 112],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct linger {
    pub l_onoff: u16,
    pub l_linger: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct timeval {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

#[repr(C)]
pub struct fd_set {
    pub fd_count: u32,
    pub fd_array: [usize; FD_SETSIZE],
}

impl fd_set {
    pub fn new() -> Self {
        Self {
            fd_count: 0,
            fd_array: [0; FD_SETSIZE],
        }
    }

    pub fn clear(&mut self) {
        self.fd_count = 0;
    }

    pub fn isset(&self, socket: usize) -> bool {
        for i in 0..self.fd_count as usize {
            if self.fd_array[i] == socket {
                return true;
            }
        }
        false
    }

    pub fn set(&mut self, socket: usize) {
        if !self.isset(socket) && (self.fd_count as usize) < FD_SETSIZE {
            self.fd_array[self.fd_count as usize] = socket;
            self.fd_count += 1;
        }
    }

    pub fn clr(&mut self, socket: usize) {
        for i in 0..self.fd_count as usize {
            if self.fd_array[i] == socket {
                for j in i..(self.fd_count as usize - 1) {
                    self.fd_array[j] = self.fd_array[j + 1];
                }
                self.fd_count -= 1;
                break;
            }
        }
    }
}

impl Default for fd_set {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WSABUF {
    pub len: u32,
    pub buf: *mut u8,
}

#[repr(C)]
pub struct WSAOVERLAPPED {
    pub internal: usize,
    pub internal_high: usize,
    pub offset: u32,
    pub offset_high: u32,
    pub h_event: usize,
}

pub type LpwsaoverlappedCompletionRoutine = Option<
    unsafe extern "C" fn(
        dw_error: u32,
        cb_transferred: u32,
        lp_overlapped: *mut WSAOVERLAPPED,
        dw_flags: u32,
    ),
>;

pub use super::WSAData;

#[repr(C)]
pub struct addrinfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: usize,
    pub ai_canonname: *mut u8,
    pub ai_addr: *mut sockaddr,
    pub ai_next: *mut addrinfo,
}

pub const AI_PASSIVE: i32 = 0x01;
pub const AI_CANONNAME: i32 = 0x02;
pub const AI_NUMERICHOST: i32 = 0x04;
pub const AI_NUMERICSERV: i32 = 0x08;
pub const AI_ALL: i32 = 0x0100;
pub const AI_ADDRCONFIG: i32 = 0x0400;
pub const AI_V4MAPPED: i32 = 0x0800;

#[repr(C)]
pub struct hostent {
    pub h_name: *mut u8,
    pub h_aliases: *mut *mut u8,
    pub h_addrtype: i16,
    pub h_length: i16,
    pub h_addr_list: *mut *mut u8,
}

#[repr(C)]
pub struct WSANETWORKEVENTS {
    pub l_network_events: i32,
    pub i_error_code: [i32; 10],
}

pub const FD_READ: i32 = 0x01;
pub const FD_WRITE: i32 = 0x02;
pub const FD_OOB: i32 = 0x04;
pub const FD_ACCEPT: i32 = 0x08;
pub const FD_CONNECT: i32 = 0x10;
pub const FD_CLOSE: i32 = 0x20;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WSAPOLLFD {
    pub fd: usize,
    pub events: i16,
    pub revents: i16,
}

pub const POLLRDNORM: i16 = 0x0100;
pub const POLLRDBAND: i16 = 0x0200;
pub const POLLIN: i16 = POLLRDNORM | POLLRDBAND;
pub const POLLPRI: i16 = 0x0400;
pub const POLLWRNORM: i16 = 0x0010;
pub const POLLOUT: i16 = POLLWRNORM;
pub const POLLWRBAND: i16 = 0x0020;
pub const POLLERR: i16 = 0x0001;
pub const POLLHUP: i16 = 0x0002;
pub const POLLNVAL: i16 = 0x0004;

#[repr(C)]
pub struct WSAPROTOCOL_INFOW {
    pub dw_service_flags1: u32,
    pub dw_service_flags2: u32,
    pub dw_service_flags3: u32,
    pub dw_service_flags4: u32,
    pub dw_provider_flags: u32,
    pub provider_id: [u8; 16], // GUID
    pub dw_catalog_entry_id: u32,
    pub protocol_chain: WSAPROTOCOLCHAIN,
    pub i_version: i32,
    pub i_address_family: i32,
    pub i_max_sock_addr: i32,
    pub i_min_sock_addr: i32,
    pub i_socket_type: i32,
    pub i_protocol: i32,
    pub i_protocol_max_offset: i32,
    pub i_network_byte_order: i32,
    pub i_security_scheme: i32,
    pub dw_message_size: u32,
    pub dw_provider_reserved: u32,
    pub sz_protocol: [u16; 256],
}

#[repr(C)]
pub struct WSAPROTOCOLCHAIN {
    pub chain_len: i32,
    pub chain_entries: [u32; 7],
}

#[repr(C)]
pub struct QOS {
    pub sending_flowspec: FLOWSPEC,
    pub receiving_flowspec: FLOWSPEC,
    pub provider_specific: WSABUF,
}

#[repr(C)]
pub struct FLOWSPEC {
    pub token_rate: u32,
    pub token_bucket_size: u32,
    pub peak_bandwidth: u32,
    pub latency: u32,
    pub delay_variation: u32,
    pub service_type: u32,
    pub max_sdu_size: u32,
    pub minimum_policed_size: u32,
}
