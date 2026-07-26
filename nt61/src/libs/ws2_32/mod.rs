//! ws2_32.dll — the Winsock 2 user-mode entry points
//!
//! The user-mode side of NT 6.1 sockets. Most of these export
//! thin wrappers: a thread-local error code, the AFD handle
//! table, and a delegated IOCTL to `\\Device\\Afd`.
//!
//! Because this kernel has no working user-mode loader yet, the
//! `ws2_32` "exports" in this module are stubs that the
//! `kernel32` and `loader` layers can be wired to when SSH
//! bring-up reaches that point. The host-side tests cover the
//! state machine (WSAStartup / WSACleanup / WSAGetLastError)
//! without touching the kernel.

#![allow(non_snake_case, dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};

/// Per-DLL WSADATA version we report. NT 6.1 returns 0x0202
/// (Winsock 2.2). The high byte is the major version, the low
/// byte the minor.
pub const WSADESCRIPTION_LEN: usize = 256;
pub const WSASYS_STATUS_LEN: usize = 128;
pub const WSA_VERSION: u16 = 0x0202;

/// WSADATA structure passed to WSAStartup. The shape matches
/// Microsoft's documentation; we only need the version fields
/// for the OpenSSH probes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WSAData {
    pub w_version: u16,
    pub w_high_version: u16,
    pub sz_description: [u8; WSADESCRIPTION_LEN + 1],
    pub sz_system_status: [u8; WSASYS_STATUS_LEN + 1],
    pub i_max_sockets: u16,
    pub i_max_udp_dg: u16,
    pub lp_vendor_info: *const u8,
}

impl Default for WSAData {
    fn default() -> Self {
        Self {
            w_version: 0,
            w_high_version: 0,
            sz_description: [0; WSADESCRIPTION_LEN + 1],
            sz_system_status: [0; WSASYS_STATUS_LEN + 1],
            i_max_sockets: 0,
            i_max_udp_dg: 0,
            lp_vendor_info: core::ptr::null(),
        }
    }
}

/// Per-thread last-error code. Winsock maintains its own
/// `WSAGetLastError` separate from `GetLastError`.
static WSA_LAST_ERROR: AtomicU32 = AtomicU32::new(0);

/// WSAStartup: caller must request 0x0202 (or 0x0002). Returns
/// 0 on success, nonzero SOCKET_ERROR otherwise.
pub fn WSAStartup(version: u16, wsadata: &mut WSAData) -> i32 {
    if (version & 0xFF) > (WSA_VERSION & 0xFF) {
        WSA_LAST_ERROR.store(1 /* WSAVERNOTSUPPORTED */, Ordering::SeqCst);
        return -1;
    }
    wsadata.w_version = version;
    wsadata.w_high_version = WSA_VERSION;
    wsadata.i_max_sockets = 0; // NT 6.1 ignores these
    wsadata.i_max_udp_dg = 0;
    wsadata.lp_vendor_info = core::ptr::null();
    WSA_LAST_ERROR.store(0, Ordering::SeqCst);
    0
}

/// WSACleanup: terminate the per-process Winsock usage.
pub fn WSACleanup() -> i32 {
    WSA_LAST_ERROR.store(0, Ordering::SeqCst);
    0
}

/// WSAGetLastError: returns the per-thread last error.
pub fn WSAGetLastError() -> i32 {
    WSA_LAST_ERROR.load(Ordering::SeqCst) as i32
}

/// WSASetLastError: stores a per-thread last error.
pub fn WSASetLastError(code: i32) {
    WSA_LAST_ERROR.store(code as u32, Ordering::SeqCst);
}

/// ntohs / htons: byte order helpers. Winsock leaves these as
/// inline functions in the x64 ABI, but exporting them keeps
/// the loader symbol table honest.
pub fn htons(value: u16) -> u16 { value.to_be() }
pub fn ntohs(value: u16) -> u16 { u16::from_be(value) }
pub fn htonl(value: u32) -> u32 { value.to_be() }
pub fn ntohl(value: u32) -> u32 { u32::from_be(value) }

/// inet_ntoa: would require a static buffer; we expose the
/// function pointer so ws2_32 can be linked but the actual
/// implementation lives in the kernel's TCP stack once user-
/// mode loader is wired up.
pub fn inet_ntoa(_addr: u32) -> *const u8 { core::ptr::null() }

/// Standard Winsock error codes that the OpenSSH bring-up
/// task wants to recognise.
pub mod error {
    pub const WSAEINTR: i32 = 10004;
    pub const WSAEWOULDBLOCK: i32 = 10035;
    pub const WSAEINPROGRESS: i32 = 10036;
    pub const WSAEALREADY: i32 = 10037;
    pub const WSAENOTSOCK: i32 = 10038;
    pub const WSAEDESTADDRREQ: i32 = 10039;
    pub const WSAEMSGSIZE: i32 = 10040;
    pub const WSAEPROTOTYPE: i32 = 10041;
    pub const WSAENOPROTOOPT: i32 = 10042;
    pub const WSAEPROTONOSUPPORT: i32 = 10043;
    pub const WSAESOCKTNOSUPPORT: i32 = 10044;
    pub const WSAEOPNOTSUPP: i32 = 10045;
    pub const WSAEAFNOSUPPORT: i32 = 10047;
    pub const WSAEADDRINUSE: i32 = 10048;
    pub const WSAEADDRNOTAVAIL: i32 = 10049;
    pub const WSAECONNREFUSED: i32 = 10053;
    pub const WSAECONNRESET: i32 = 10054;
    pub const WSAENOTCONN: i32 = 10057;
    pub const WSAETIMEDOUT: i32 = 10060;
    pub const WSAEHOSTUNREACH: i32 = 10065;
    pub const WSAVERNOTSUPPORTED: i32 = 10092;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsa_startup_accepts_2_2() {
        let mut wsadata = WSAData::default();
        assert_eq!(WSAStartup(0x0202, &mut wsadata), 0);
        assert_eq!(wsadata.w_version, 0x0202);
        assert_eq!(wsadata.w_high_version, WSA_VERSION);
        assert_eq!(WSAGetLastError(), 0);
    }

    #[test]
    fn wsa_startup_rejects_future_version() {
        let mut wsadata = WSAData::default();
        // OpenSSH always asks for 0x0202; 0x0203 is higher than
        // what we support and must return SOCKET_ERROR.
        assert_eq!(WSAStartup(0x0203, &mut wsadata), -1);
        assert_eq!(WSAGetLastError(), error::WSAVERNOTSUPPORTED);
    }

    #[test]
    fn wsa_set_then_get_last_error() {
        WSASetLastError(error::WSAEWOULDBLOCK);
        assert_eq!(WSAGetLastError(), error::WSAEWOULDBLOCK);
        WSACleanup();
        assert_eq!(WSAGetLastError(), 0);
    }

    #[test]
    fn byte_order_helpers() {
        assert_eq!(htons(0x1234), 0x1234_u16.to_be());
        assert_eq!(ntohs(0x1234_u16.to_be()), 0x1234);
        assert_eq!(htonl(0xDEADBEEF), 0xDEADBEEF_u32.to_be());
        assert_eq!(ntohl(0xDEADBEEF_u32.to_be()), 0xDEADBEEF);
    }

    #[test]
    fn wsa_error_codes_match_documented_values() {
        // These specific values are part of the Winsock ABI:
        // changing them breaks every Winsock app on Earth.
        assert_eq!(error::WSAEWOULDBLOCK, 10035);
        assert_eq!(error::WSAECONNREFUSED, 10053);
        assert_eq!(error::WSAETIMEDOUT, 10060);
    }
}
