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
//! state machine (wsastartup / wsacleanup / wsaget_last_error)
//! without touching the kernel.

/// Per-DLL WSADATA version we report. NT 6.1 returns 0x0202
/// (Winsock 2.2). The high byte is the major version, the low
/// byte the minor.
pub const WSADESCRIPTION_LEN: usize = 256;
pub const WSASYS_STATUS_LEN: usize = 128;
pub const WSA_VERSION: u16 = 0x0202;

/// WSADATA structure passed to wsastartup. The shape matches
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
/// `wsaget_last_error` separate from `get_last_error`.

/// wsastartup: caller must request 0x0202 (or 0x0002). Returns
/// 0 on success, nonzero SOCKET_ERROR otherwise.
pub fn wsastartup(version: u16, wsadata: &mut WSAData) -> i32 {
    if (version & 0xFF) > (WSA_VERSION & 0xFF) {
        error::set_last_error(error::WSAVERNOTSUPPORTED);
        return -1;
    }
    wsadata.w_version = version;
    wsadata.w_high_version = WSA_VERSION;
    wsadata.i_max_sockets = 0; // NT 6.1 ignores these
    wsadata.i_max_udp_dg = 0;
    wsadata.lp_vendor_info = core::ptr::null();
    error::set_last_error(0);
    0
}

/// wsacleanup: terminate the per-process Winsock usage.
pub fn wsacleanup() -> i32 {
    error::set_last_error(0);
    0
}

/// wsaget_last_error: returns the per-thread last error.
pub fn wsaget_last_error() -> i32 {
    error::get_last_error()
}

/// wsaset_last_error: stores a per-thread last error.
pub fn wsaset_last_error(code: i32) {
    error::set_last_error(code);
}

/// ntohs / htons: byte order helpers. Winsock leaves these as
/// inline functions in the x64 ABI, but exporting them keeps
/// the loader symbol table honest.
pub fn htons(value: u16) -> u16 {
    value.to_be()
}
pub fn ntohs(value: u16) -> u16 {
    u16::from_be(value)
}
pub fn htonl(value: u32) -> u32 {
    value.to_be()
}
pub fn ntohl(value: u32) -> u32 {
    u32::from_be(value)
}

/// inet_ntoa: would require a static buffer; we expose the
/// function pointer so ws2_32 can be linked but the actual
/// implementation lives in the kernel's TCP stack once user-
/// mode loader is wired up.
pub fn inet_ntoa(_addr: u32) -> *const u8 {
    core::ptr::null()
}

/// Standard Winsock error codes that the OpenSSH bring-up
/// task wants to recognise.
pub mod error;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsa_startup_accepts_2_2() {
        let mut wsadata = WSAData::default();
        assert_eq!(wsastartup(0x0202, &mut wsadata), 0);
        assert_eq!(wsadata.w_version, 0x0202);
        assert_eq!(wsadata.w_high_version, WSA_VERSION);
        assert_eq!(wsaget_last_error(), 0);
    }

    #[test]
    fn wsa_startup_rejects_future_version() {
        let mut wsadata = WSAData::default();
        // OpenSSH always asks for 0x0202; 0x0203 is higher than
        // what we support and must return SOCKET_ERROR.
        assert_eq!(wsastartup(0x0203, &mut wsadata), -1);
        assert_eq!(wsaget_last_error(), error::WSAVERNOTSUPPORTED);
    }

    #[test]
    fn wsa_set_then_get_last_error() {
        wsaset_last_error(error::WSAEWOULDBLOCK);
        assert_eq!(wsaget_last_error(), error::WSAEWOULDBLOCK);
        wsacleanup();
        assert_eq!(wsaget_last_error(), 0);
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
        assert_eq!(error::WSAECONNREFUSED, 10061);
        assert_eq!(error::WSAETIMEDOUT, 10060);
    }
}

pub mod async_ops;
pub mod nameresolution;
pub mod socket;
pub mod types;
