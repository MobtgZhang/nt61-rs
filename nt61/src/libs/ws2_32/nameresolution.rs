//! name resolution functions
//!
//! Implements getaddrinfo, freeaddrinfo, getnameinfo, gethostbyname,
//! gethostbyaddr, and related DNS resolution functions.

use super::error::*;
use super::types::*;
use crate::netstack::dns;
use alloc::boxed::Box;
use alloc::string::{String, ToString};

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn getaddrinfo(
    nodename: *const u8,
    servname: *const u8,
    hints: *const addrinfo,
    res: *mut *mut addrinfo,
) -> i32 {
    if res.is_null() {
        set_last_error(WSAEFAULT);
        return WSAEFAULT;
    }

    let node = if nodename.is_null() {
        None
    } else {
        Some(unsafe { cstr_to_string(nodename) })
    };

    let port: u16 = if servname.is_null() {
        0
    } else {
        let service = unsafe { cstr_to_string(servname) };
        service.parse().unwrap_or(0)
    };

    let (family, socktype, protocol) = if hints.is_null() {
        (AF_INET as i32, SOCK_STREAM, IPPROTO_TCP)
    } else {
        unsafe {
            (
                (*hints).ai_family,
                (*hints).ai_socktype,
                (*hints).ai_protocol,
            )
        }
    };

    if family != AF_UNSPEC as i32 && family != AF_INET as i32 {
        set_last_error(WSAEAFNOSUPPORT);
        return WSAEAFNOSUPPORT;
    }

    let ip_addr = if let Some(ref hostname) = node {
        match dns::resolve(hostname) {
            Ok(ip) => ip,
            Err(dns::DnsError::AddrFamilyNotSupported) => {
                set_last_error(WSAEAFNOSUPPORT);
                return WSAEAFNOSUPPORT;
            }
            Err(dns::DnsError::NotFound) => {
                set_last_error(WSAHOST_NOT_FOUND);
                return WSAHOST_NOT_FOUND;
            }
            Err(dns::DnsError::Timeout) => {
                set_last_error(WSATRY_AGAIN);
                return WSATRY_AGAIN;
            }
            Err(_) => {
                set_last_error(WSANO_RECOVERY);
                return WSANO_RECOVERY;
            }
        }
    } else {
        0 // INADDR_ANY
    };

    let mut result = Box::new(addrinfo {
        ai_flags: 0,
        ai_family: AF_INET as i32,
        ai_socktype: socktype,
        ai_protocol: protocol,
        ai_addrlen: core::mem::size_of::<sockaddr_in>(),
        ai_canonname: core::ptr::null_mut(),
        ai_addr: core::ptr::null_mut(),
        ai_next: core::ptr::null_mut(),
    });

    let addr = Box::new(sockaddr_in {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: in_addr { s_addr: ip_addr },
        sin_zero: [0; 8],
    });

    result.ai_addr = Box::into_raw(addr) as *mut sockaddr;
    unsafe {
        *res = Box::into_raw(result);
    }

    set_last_error(0);
    0
}

pub fn freeaddrinfo(ai: *mut addrinfo) {
    if ai.is_null() {
        return;
    }

    unsafe {
        let mut current = ai;
        while !current.is_null() {
            let next = (*current).ai_next;

            if !(*current).ai_addr.is_null() {
                let _ = Box::from_raw((*current).ai_addr as *mut sockaddr_in);
            }

            if !(*current).ai_canonname.is_null() {
                let _ = Box::from_raw((*current).ai_canonname);
            }

            let _ = Box::from_raw(current);

            current = next;
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn getnameinfo(
    sa: *const sockaddr,
    salen: i32,
    host: *mut u8,
    hostlen: u32,
    serv: *mut u8,
    servlen: u32,
    _flags: i32,
) -> i32 {
    if sa.is_null() || salen < core::mem::size_of::<sockaddr_in>() as i32 {
        set_last_error(WSAEFAULT);
        return WSAEFAULT;
    }

    let addr_in = unsafe { &*(sa as *const sockaddr_in) };

    if addr_in.sin_family != AF_INET {
        set_last_error(WSAEAFNOSUPPORT);
        return WSAEAFNOSUPPORT;
    }

    if !host.is_null() && hostlen > 0 {
        let ip = addr_in.sin_addr.s_addr;
        let ip_string = alloc::format!(
            "{}.{}.{}.{}",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF
        );

        let bytes = ip_string.as_bytes();
        let copy_len = (bytes.len().min(hostlen as usize - 1)).min(bytes.len());
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), host, copy_len);
            *host.add(copy_len) = 0; // null terminate
        }
    }

    if !serv.is_null() && servlen > 0 {
        let port = u16::from_be(addr_in.sin_port);
        let port_string = alloc::format!("{}", port);
        let bytes = port_string.as_bytes();
        let copy_len = (bytes.len().min(servlen as usize - 1)).min(bytes.len());
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), serv, copy_len);
            *serv.add(copy_len) = 0; // null terminate
        }
    }

    set_last_error(0);
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// gethostbyname() - get host information by name (deprecated but still used)
pub unsafe fn gethostbyname(name: *const u8) -> *mut hostent {
    if name.is_null() {
        set_last_error(WSAEFAULT);
        return core::ptr::null_mut();
    }

    let hostname = unsafe { cstr_to_string(name) };

    match dns::resolve(&hostname) {
        Ok(ip) => {
            // A full implementation would use a thread-local buffer
            let mut h = Box::new(hostent {
                h_name: core::ptr::null_mut(),
                h_aliases: core::ptr::null_mut(),
                h_addrtype: AF_INET as i16,
                h_length: 4,
                h_addr_list: core::ptr::null_mut(),
            });

            let addr = Box::new(ip);
            let addr_list = Box::new([Box::into_raw(addr) as *mut u8, core::ptr::null_mut()]);
            h.h_addr_list = Box::into_raw(addr_list) as *mut *mut u8;

            set_last_error(0);
            Box::into_raw(h)
        }
        Err(dns::DnsError::NotFound) => {
            set_last_error(WSAHOST_NOT_FOUND);
            core::ptr::null_mut()
        }
        Err(dns::DnsError::Timeout) => {
            set_last_error(WSATRY_AGAIN);
            core::ptr::null_mut()
        }
        Err(_) => {
            set_last_error(WSANO_RECOVERY);
            core::ptr::null_mut()
        }
    }
}

/// gethostbyaddr() - get host information by address (deprecated but still used)
pub fn gethostbyaddr(addr: *const u8, len: i32, addr_type: i32) -> *mut hostent {
    if addr.is_null() || len < 4 || addr_type != AF_INET as i32 {
        set_last_error(WSAEFAULT);
        return core::ptr::null_mut();
    }

    let ip = unsafe { *(addr as *const u32) };

    let mut h = Box::new(hostent {
        h_name: core::ptr::null_mut(),
        h_aliases: core::ptr::null_mut(),
        h_addrtype: AF_INET as i16,
        h_length: 4,
        h_addr_list: core::ptr::null_mut(),
    });

    let addr_box = Box::new(ip);
    let addr_list = Box::new([Box::into_raw(addr_box) as *mut u8, core::ptr::null_mut()]);
    h.h_addr_list = Box::into_raw(addr_list) as *mut *mut u8;

    set_last_error(0);
    Box::into_raw(h)
}

pub fn getservbyname(_name: *const u8, _proto: *const u8) -> *mut servent {
    set_last_error(WSANO_DATA);
    core::ptr::null_mut()
}

pub fn getservbyport(_port: i32, _proto: *const u8) -> *mut servent {
    set_last_error(WSANO_DATA);
    core::ptr::null_mut()
}

#[repr(C)]
pub struct servent {
    pub s_name: *mut u8,
    pub s_aliases: *mut *mut u8,
    pub s_port: i16,
    pub s_proto: *mut u8,
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn cstr_to_string(ptr: *const u8) -> String {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 1024 {
            break; // Safety limit
        }
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    String::from_utf8_lossy(slice).to_string()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn wsaaddress_to_string_a(
    lpsa_address: *const sockaddr,
    _dw_address_length: u32,
    _lp_protocol_info: *const WSAPROTOCOL_INFOW,
    lpsz_address_string: *mut u8,
    lpdw_address_string_length: *mut u32,
) -> i32 {
    if lpsa_address.is_null()
        || lpsz_address_string.is_null()
        || lpdw_address_string_length.is_null()
    {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let addr_in = unsafe { &*(lpsa_address as *const sockaddr_in) };

    if addr_in.sin_family != AF_INET {
        set_last_error(WSAEAFNOSUPPORT);
        return SOCKET_ERROR;
    }

    let ip = addr_in.sin_addr.s_addr;
    let port = u16::from_be(addr_in.sin_port);
    let addr_str = alloc::format!(
        "{}.{}.{}.{}:{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
        port
    );

    let bytes = addr_str.as_bytes();
    let required = bytes.len() + 1;

    unsafe {
        if *lpdw_address_string_length < required as u32 {
            *lpdw_address_string_length = required as u32;
            set_last_error(WSAEFAULT);
            return SOCKET_ERROR;
        }

        core::ptr::copy_nonoverlapping(bytes.as_ptr(), lpsz_address_string, bytes.len());
        *lpsz_address_string.add(bytes.len()) = 0;
        *lpdw_address_string_length = required as u32;
    }

    set_last_error(0);
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn wsastring_to_address_a(
    address_string: *const u8,
    address_family: i32,
    _lp_protocol_info: *const WSAPROTOCOL_INFOW,
    lp_address: *mut sockaddr,
    lp_address_length: *mut i32,
) -> i32 {
    if address_string.is_null() || lp_address.is_null() || lp_address_length.is_null() {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if address_family != AF_INET as i32 {
        set_last_error(WSAEAFNOSUPPORT);
        return SOCKET_ERROR;
    }

    unsafe {
        if *lp_address_length < core::mem::size_of::<sockaddr_in>() as i32 {
            set_last_error(WSAEFAULT);
            return SOCKET_ERROR;
        }

        let addr_string = cstr_to_string(address_string);

        let (ip_str, port) = if let Some(colon_pos) = addr_string.rfind(':') {
            let (ip, port_str) = addr_string.split_at(colon_pos);
            let port = port_str[1..].parse::<u16>().unwrap_or(0);
            (ip.to_string(), port)
        } else {
            (addr_string, 0)
        };

        let ip = match dns::parse_ipv4_literal(&ip_str) {
            Some(addr) => addr,
            None => {
                set_last_error(WSAEINVAL);
                return SOCKET_ERROR;
            }
        };

        let addr_in = &mut *(lp_address as *mut sockaddr_in);
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = port.to_be();
        addr_in.sin_addr.s_addr = ip;
        addr_in.sin_zero = [0; 8];

        *lp_address_length = core::mem::size_of::<sockaddr_in>() as i32;
    }

    set_last_error(0);
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn inet_addr(cp: *const u8) -> u32 {
    if cp.is_null() {
        return 0xFFFFFFFF; // INADDR_NONE
    }

    let addr_string = unsafe { cstr_to_string(cp) };

    dns::parse_ipv4_literal(&addr_string).unwrap_or(0xFFFFFFFF)
}

pub fn inet_ntoa(_addr: in_addr) -> *const u8 {
    // Applications should use inet_ntop instead
    core::ptr::null()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn inet_pton(family: i32, psz_addr_string: *const u8, p_addr_buf: *mut u8) -> i32 {
    if psz_addr_string.is_null() || p_addr_buf.is_null() {
        set_last_error(WSAEFAULT);
        return -1;
    }

    if family != AF_INET as i32 {
        set_last_error(WSAEAFNOSUPPORT);
        return -1;
    }

    let addr_string = unsafe { cstr_to_string(psz_addr_string) };

    match dns::parse_ipv4_literal(&addr_string) {
        Some(ip) => {
            unsafe {
                *(p_addr_buf as *mut u32) = ip;
            }
            1 // Success
        }
        None => 0, // Invalid format
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn inet_ntop(
    family: i32,
    p_addr: *const u8,
    p_string_buf: *mut u8,
    string_buf_size: usize,
) -> *const u8 {
    if p_addr.is_null() || p_string_buf.is_null() || string_buf_size == 0 {
        set_last_error(WSAEFAULT);
        return core::ptr::null();
    }

    if family != AF_INET as i32 {
        set_last_error(WSAEAFNOSUPPORT);
        return core::ptr::null();
    }

    let ip = unsafe { *(p_addr as *const u32) };
    let ip_string = alloc::format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    );

    let bytes = ip_string.as_bytes();
    if bytes.len() >= string_buf_size {
        set_last_error(WSAEFAULT);
        return core::ptr::null();
    }

    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), p_string_buf, bytes.len());
        *p_string_buf.add(bytes.len()) = 0;
    }

    set_last_error(0);
    p_string_buf as *const u8
}
