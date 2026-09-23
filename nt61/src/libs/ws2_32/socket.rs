//! Core socket operations
//!
//! Implements the basic Winsock 2 socket functions: socket, bind, listen,
//! accept, connect, send, recv, sendto, recvfrom, closesocket, shutdown,
//! and socket options (setsockopt, getsockopt, ioctlsocket).

#![allow(non_snake_case)]

use super::types::*;
use super::error::*;
use crate::netstack::{socket, afd};
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

struct SocketEntry {
    kernel_socket_id: u32,
    afd_handle: u64,
    socket_type: i32,
    protocol: i32,
    nonblocking: bool,
}

static SOCKET_TABLE: Spinlock<Vec<Option<SocketEntry>>> = Spinlock::new(Vec::new());

fn alloc_socket_handle(kernel_socket_id: u32, socket_type: i32, protocol: i32) -> Option<usize> {
    let afd_handle = afd::create(kernel_socket_id)?;

    let mut table = SOCKET_TABLE.lock();

    for (idx, entry) in table.iter_mut().enumerate() {
        if entry.is_none() {
            *entry = Some(SocketEntry {
                kernel_socket_id,
                afd_handle,
                socket_type,
                protocol,
                nonblocking: false,
            });
            return Some(idx + 1); // 0 is invalid, so offset by 1
        }
    }

    table.push(Some(SocketEntry {
        kernel_socket_id,
        afd_handle,
        socket_type,
        protocol,
        nonblocking: false,
    }));
    Some(table.len())
}

fn get_kernel_socket_id(handle: usize) -> Option<u32> {
    if handle == 0 || handle == INVALID_SOCKET {
        return None;
    }
    let table = SOCKET_TABLE.lock();
    let idx = handle.wrapping_sub(1);
    table.get(idx)?.as_ref().map(|e| e.kernel_socket_id)
}

fn with_socket_entry<R, F>(handle: usize, f: F) -> Option<R>
where
    F: FnOnce(&mut SocketEntry) -> R,
{
    if handle == 0 || handle == INVALID_SOCKET {
        return None;
    }
    let mut table = SOCKET_TABLE.lock();
    let idx = handle.wrapping_sub(1);
    table.get_mut(idx)?.as_mut().map(f)
}

fn free_socket_handle(handle: usize) {
    if handle == 0 || handle == INVALID_SOCKET {
        return;
    }
    let mut table = SOCKET_TABLE.lock();
    let idx = handle.wrapping_sub(1);
    if let Some(entry) = table.get_mut(idx) {
        if let Some(e) = entry.take() {
            afd::close_handle(e.afd_handle);
        }
    }
}

pub fn socket(af: i32, socket_type: i32, protocol: i32) -> usize {
    if af != AF_INET as i32 {
        set_last_error(WSAEAFNOSUPPORT);
        return INVALID_SOCKET;
    }

    let sock_type = match socket_type {
        SOCK_STREAM => socket::SocketType::Stream,
        SOCK_DGRAM => socket::SocketType::Dgram,
        SOCK_RAW => socket::SocketType::Raw,
        _ => {
            set_last_error(WSAESOCKTNOSUPPORT);
            return INVALID_SOCKET;
        }
    };

    let proto = if protocol == IPPROTO_IP {
        socket::Protocol::from_socket_type(sock_type)
    } else {
        match protocol {
            IPPROTO_TCP => socket::Protocol::Tcp,
            IPPROTO_UDP => socket::Protocol::Udp,
            IPPROTO_ICMP => socket::Protocol::Icmp,
            _ => socket::Protocol::Raw,
        }
    };

    match socket::socket(sock_type, proto) {
        Some(kernel_id) => {
            match alloc_socket_handle(kernel_id, socket_type, protocol) {
                Some(handle) => {
                    set_last_error(0);
                    handle
                }
                None => {
                    socket::close(kernel_id).ok();
                    set_last_error(WSAENOBUFS);
                    INVALID_SOCKET
                }
            }
        }
        None => {
            set_last_error(WSAENOBUFS);
            INVALID_SOCKET
        }
    }
}

pub fn bind(s: usize, name: *const sockaddr, namelen: i32) -> i32 {
    if name.is_null() || namelen < core::mem::size_of::<sockaddr_in>() as i32 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    let addr_in = unsafe { &*(name as *const sockaddr_in) };

    if addr_in.sin_family != AF_INET {
        set_last_error(WSAEAFNOSUPPORT);
        return SOCKET_ERROR;
    }

    let sock_addr = socket::SockAddr::new(
        addr_in.sin_family,
        addr_in.sin_port,
        addr_in.sin_addr.s_addr,
    );

    match socket::bind(kernel_id, &sock_addr) {
        Ok(()) => {
            set_last_error(0);
            0
        }
        Err(e) => {
            set_last_error(socket_error_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub fn listen(s: usize, backlog: i32) -> i32 {
    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    let backlog = if backlog < 0 { 8 } else { backlog as u32 };

    match socket::listen(kernel_id, backlog) {
        Ok(()) => {
            set_last_error(0);
            0
        }
        Err(e) => {
            set_last_error(socket_error_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub fn accept(s: usize, addr: *mut sockaddr, addrlen: *mut i32) -> usize {
    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return INVALID_SOCKET;
        }
    };

    match socket::accept(kernel_id) {
        Ok(peer_id) => {
            match alloc_socket_handle(peer_id, SOCK_STREAM, IPPROTO_TCP) {
                Some(handle) => {
                    if !addr.is_null() && !addrlen.is_null() {
                        if let Some(peer_addr) = socket::get_remote_addr(peer_id) {
                            unsafe {
                                let addr_in = &mut *(addr as *mut sockaddr_in);
                                addr_in.sin_family = peer_addr.family;
                                addr_in.sin_port = peer_addr.port;
                                addr_in.sin_addr.s_addr = peer_addr.ip();
                                addr_in.sin_zero = [0; 8];
                                *addrlen = core::mem::size_of::<sockaddr_in>() as i32;
                            }
                        }
                    }
                    set_last_error(0);
                    handle
                }
                None => {
                    socket::close(peer_id).ok();
                    set_last_error(WSAENOBUFS);
                    INVALID_SOCKET
                }
            }
        }
        Err(socket::SocketError::WouldBlock) => {
            set_last_error(WSAEWOULDBLOCK);
            INVALID_SOCKET
        }
        Err(e) => {
            set_last_error(socket_error_to_wsa(&e));
            INVALID_SOCKET
        }
    }
}

pub fn connect(s: usize, name: *const sockaddr, namelen: i32) -> i32 {
    if name.is_null() || namelen < core::mem::size_of::<sockaddr_in>() as i32 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    let addr_in = unsafe { &*(name as *const sockaddr_in) };

    if addr_in.sin_family != AF_INET {
        set_last_error(WSAEAFNOSUPPORT);
        return SOCKET_ERROR;
    }

    let sock_addr = socket::SockAddr::new(
        addr_in.sin_family,
        addr_in.sin_port,
        addr_in.sin_addr.s_addr,
    );

    match socket::connect(kernel_id, &sock_addr) {
        Ok(()) => {
            set_last_error(0);
            0
        }
        Err(e) => {
            set_last_error(socket_error_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    if buf.is_null() || len < 0 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    let data = unsafe { core::slice::from_raw_parts(buf, len as usize) };

    match socket::send(kernel_id, data) {
        Ok(n) => {
            set_last_error(0);
            n as i32
        }
        Err(socket::SocketError::WouldBlock) => {
            set_last_error(WSAEWOULDBLOCK);
            SOCKET_ERROR
        }
        Err(e) => {
            set_last_error(socket_error_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32 {
    if buf.is_null() || len < 0 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    let buffer = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };

    match socket::recv(kernel_id, buffer) {
        Ok(n) => {
            set_last_error(0);
            n as i32
        }
        Err(socket::SocketError::WouldBlock) => {
            set_last_error(WSAEWOULDBLOCK);
            SOCKET_ERROR
        }
        Err(e) => {
            set_last_error(socket_error_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub fn sendto(s: usize, buf: *const u8, len: i32, flags: i32,
              to: *const sockaddr, tolen: i32) -> i32 {
    // For connected sockets or when to is NULL, just use send()
    if to.is_null() {
        return send(s, buf, len, flags);
    }

    if buf.is_null() || len < 0 || tolen < core::mem::size_of::<sockaddr_in>() as i32 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    send(s, buf, len, flags)
}

pub fn recvfrom(s: usize, buf: *mut u8, len: i32, flags: i32,
                from: *mut sockaddr, fromlen: *mut i32) -> i32 {
    if buf.is_null() || len < 0 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    let buffer = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };

    match socket::recv(kernel_id, buffer) {
        Ok(n) => {
            if !from.is_null() && !fromlen.is_null() {
                if let Some(remote_addr) = socket::get_remote_addr(kernel_id) {
                    unsafe {
                        let addr_in = &mut *(from as *mut sockaddr_in);
                        addr_in.sin_family = remote_addr.family;
                        addr_in.sin_port = remote_addr.port;
                        addr_in.sin_addr.s_addr = remote_addr.ip();
                        addr_in.sin_zero = [0; 8];
                        *fromlen = core::mem::size_of::<sockaddr_in>() as i32;
                    }
                }
            }
            set_last_error(0);
            n as i32
        }
        Err(socket::SocketError::WouldBlock) => {
            set_last_error(WSAEWOULDBLOCK);
            SOCKET_ERROR
        }
        Err(e) => {
            set_last_error(socket_error_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub fn closesocket(s: usize) -> i32 {
    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    match socket::close(kernel_id) {
        Ok(()) => {
            free_socket_handle(s);
            set_last_error(0);
            0
        }
        Err(e) => {
            set_last_error(socket_error_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub fn shutdown(s: usize, how: i32) -> i32 {
    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    match how {
        SD_RECEIVE | SD_SEND | SD_BOTH => {
            set_last_error(0);
            0
        }
        _ => {
            set_last_error(WSAEINVAL);
            SOCKET_ERROR
        }
    }
}

pub fn setsockopt(s: usize, level: i32, optname: i32,
                  optval: *const u8, optlen: i32) -> i32 {
    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    if optval.is_null() || optlen < 0 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR) |
        (SOL_SOCKET, SO_KEEPALIVE) |
        (SOL_SOCKET, SO_BROADCAST) |
        (SOL_SOCKET, SO_SNDBUF) |
        (SOL_SOCKET, SO_RCVBUF) |
        (SOL_SOCKET, SO_SNDTIMEO) |
        (SOL_SOCKET, SO_RCVTIMEO) => {
            set_last_error(0);
            0
        }
        (IPPROTO_TCP, TCP_NODELAY) => {
            set_last_error(0);
            0
        }
        _ => {
            set_last_error(WSAENOPROTOOPT);
            SOCKET_ERROR
        }
    }
}

pub fn getsockopt(s: usize, level: i32, optname: i32,
                  optval: *mut u8, optlen: *mut i32) -> i32 {
    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    if optval.is_null() || optlen.is_null() {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    match (level, optname) {
        (SOL_SOCKET, SO_TYPE) => {
            if unsafe { *optlen } >= 4 {
                unsafe {
                    *(optval as *mut i32) = with_socket_entry(s, |e| e.socket_type).unwrap_or(0);
                    *optlen = 4;
                }
                set_last_error(0);
                0
            } else {
                set_last_error(WSAEFAULT);
                SOCKET_ERROR
            }
        }
        (SOL_SOCKET, SO_ERROR) => {
            if unsafe { *optlen } >= 4 {
                unsafe {
                    *(optval as *mut i32) = 0; // No pending error
                    *optlen = 4;
                }
                set_last_error(0);
                0
            } else {
                set_last_error(WSAEFAULT);
                SOCKET_ERROR
            }
        }
        _ => {
            set_last_error(WSAENOPROTOOPT);
            SOCKET_ERROR
        }
    }
}

pub fn ioctlsocket(s: usize, cmd: i32, argp: *mut u32) -> i32 {
    let kernel_id = match get_kernel_socket_id(s) {
        Some(id) => id,
        None => {
            set_last_error(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
    };

    if argp.is_null() {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    match cmd {
        FIONBIO => {
            let nonblock = unsafe { *argp != 0 };
            with_socket_entry(s, |e| e.nonblocking = nonblock);
            set_last_error(0);
            0
        }
        FIONREAD => {
            unsafe { *argp = 0; }
            set_last_error(0);
            0
        }
        _ => {
            set_last_error(WSAEINVAL);
            SOCKET_ERROR
        }
    }
}

pub fn select(nfds: i32, readfds: *mut fd_set, writefds: *mut fd_set,
              exceptfds: *mut fd_set, timeout: *const timeval) -> i32 {
    let mut total = 0;

    if !readfds.is_null() {
        let read_set = unsafe { &mut *readfds };
        let mut ready_count = 0;
        let mut ready_sockets = [0usize; FD_SETSIZE];

        for i in 0..read_set.fd_count as usize {
            let s = read_set.fd_array[i];
            if let Some(kernel_id) = get_kernel_socket_id(s) {
                if let Some(state) = socket::get_state(kernel_id) {
                    if matches!(state, socket::SocketState::Connected | socket::SocketState::Listening) {
                        ready_sockets[ready_count] = s;
                        ready_count += 1;
                    }
                }
            }
        }

        read_set.fd_count = ready_count as u32;
        for i in 0..ready_count {
            read_set.fd_array[i] = ready_sockets[i];
        }
        total += ready_count;
    }

    if !writefds.is_null() {
        let write_set = unsafe { &mut *writefds };
        let mut ready_count = 0;
        let mut ready_sockets = [0usize; FD_SETSIZE];

        for i in 0..write_set.fd_count as usize {
            let s = write_set.fd_array[i];
            if let Some(kernel_id) = get_kernel_socket_id(s) {
                if let Some(state) = socket::get_state(kernel_id) {
                    if matches!(state, socket::SocketState::Connected) {
                        ready_sockets[ready_count] = s;
                        ready_count += 1;
                    }
                }
            }
        }

        write_set.fd_count = ready_count as u32;
        for i in 0..ready_count {
            write_set.fd_array[i] = ready_sockets[i];
        }
        total += ready_count;
    }

    if !exceptfds.is_null() {
        unsafe { (*exceptfds).fd_count = 0; }
    }

    set_last_error(0);
    total as i32
}

fn socket_error_to_wsa(err: &socket::SocketError) -> i32 {
    match err {
        socket::SocketError::WouldBlock => WSAEWOULDBLOCK,
        socket::SocketError::ConnectionRefused => WSAECONNREFUSED,
        socket::SocketError::ConnectionReset => WSAECONNRESET,
        socket::SocketError::NotConnected => WSAENOTCONN,
        socket::SocketError::InvalidSocket => WSAENOTSOCK,
        socket::SocketError::AddressInUse => WSAEADDRINUSE,
        socket::SocketError::AddressNotAvailable => WSAEADDRNOTAVAIL,
        socket::SocketError::InvalidArgument => WSAEINVAL,
        socket::SocketError::OutOfMemory => WSAENOBUFS,
    }
}
