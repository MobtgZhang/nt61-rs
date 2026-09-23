//! Winsock 2 error codes
//!
//! Comprehensive list of Windows Sockets error codes and helper functions.

#![allow(dead_code)]

use core::sync::atomic::{AtomicI32, Ordering};

static WSA_LAST_ERROR: AtomicI32 = AtomicI32::new(0);

pub fn set_last_error(code: i32) {
    WSA_LAST_ERROR.store(code, Ordering::SeqCst);
}

pub fn get_last_error() -> i32 {
    WSA_LAST_ERROR.load(Ordering::SeqCst)
}

pub fn clear_last_error() {
    WSA_LAST_ERROR.store(0, Ordering::SeqCst);
}

pub const WSAEINTR: i32 = 10004;
pub const WSAEBADF: i32 = 10009;
pub const WSAEACCES: i32 = 10013;
pub const WSAEFAULT: i32 = 10014;
pub const WSAEINVAL: i32 = 10022;
pub const WSAEMFILE: i32 = 10024;

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
pub const WSAEPFNOSUPPORT: i32 = 10046;
pub const WSAEAFNOSUPPORT: i32 = 10047;
pub const WSAEADDRINUSE: i32 = 10048;
pub const WSAEADDRNOTAVAIL: i32 = 10049;
pub const WSAENETDOWN: i32 = 10050;
pub const WSAENETUNREACH: i32 = 10051;
pub const WSAENETRESET: i32 = 10052;
pub const WSAECONNABORTED: i32 = 10053;
pub const WSAECONNRESET: i32 = 10054;
pub const WSAENOBUFS: i32 = 10055;
pub const WSAEISCONN: i32 = 10056;
pub const WSAENOTCONN: i32 = 10057;
pub const WSAESHUTDOWN: i32 = 10058;
pub const WSAETOOMANYREFS: i32 = 10059;
pub const WSAETIMEDOUT: i32 = 10060;
pub const WSAECONNREFUSED: i32 = 10061;
pub const WSAELOOP: i32 = 10062;
pub const WSAENAMETOOLONG: i32 = 10063;
pub const WSAEHOSTDOWN: i32 = 10064;
pub const WSAEHOSTUNREACH: i32 = 10065;
pub const WSAENOTEMPTY: i32 = 10066;
pub const WSAEPROCLIM: i32 = 10067;
pub const WSAEUSERS: i32 = 10068;
pub const WSAEDQUOT: i32 = 10069;
pub const WSAESTALE: i32 = 10070;
pub const WSAEREMOTE: i32 = 10071;

pub const WSASYSNOTREADY: i32 = 10091;
pub const WSAVERNOTSUPPORTED: i32 = 10092;
pub const WSANOTINITIALISED: i32 = 10093;
pub const WSAEDISCON: i32 = 10101;
pub const WSAENOMORE: i32 = 10102;
pub const WSAECANCELLED: i32 = 10103;
pub const WSAEINVALIDPROCTABLE: i32 = 10104;
pub const WSAEINVALIDPROVIDER: i32 = 10105;
pub const WSAEPROVIDERFAILEDINIT: i32 = 10106;
pub const WSASYSCALLFAILURE: i32 = 10107;
pub const WSASERVICE_NOT_FOUND: i32 = 10108;
pub const WSATYPE_NOT_FOUND: i32 = 10109;
pub const WSA_E_NO_MORE: i32 = 10110;
pub const WSA_E_CANCELLED: i32 = 10111;
pub const WSAEREFUSED: i32 = 10112;

pub const WSAHOST_NOT_FOUND: i32 = 11001;
pub const WSATRY_AGAIN: i32 = 11002;
pub const WSANO_RECOVERY: i32 = 11003;
pub const WSANO_DATA: i32 = 11004;

pub const WSA_QOS_RECEIVERS: i32 = 11005;
pub const WSA_QOS_SENDERS: i32 = 11006;
pub const WSA_QOS_NO_SENDERS: i32 = 11007;
pub const WSA_QOS_NO_RECEIVERS: i32 = 11008;
pub const WSA_QOS_REQUEST_CONFIRMED: i32 = 11009;
pub const WSA_QOS_ADMISSION_FAILURE: i32 = 11010;
pub const WSA_QOS_POLICY_FAILURE: i32 = 11011;
pub const WSA_QOS_BAD_STYLE: i32 = 11012;
pub const WSA_QOS_BAD_OBJECT: i32 = 11013;
pub const WSA_QOS_TRAFFIC_CTRL_ERROR: i32 = 11014;
pub const WSA_QOS_GENERIC_ERROR: i32 = 11015;
pub const WSA_QOS_ESERVICETYPE: i32 = 11016;
pub const WSA_QOS_EFLOWSPEC: i32 = 11017;
pub const WSA_QOS_EPROVSPECBUF: i32 = 11018;
pub const WSA_QOS_EFILTERSTYLE: i32 = 11019;
pub const WSA_QOS_EFILTERTYPE: i32 = 11020;
pub const WSA_QOS_EFILTERCOUNT: i32 = 11021;
pub const WSA_QOS_EOBJLENGTH: i32 = 11022;
pub const WSA_QOS_EFLOWCOUNT: i32 = 11023;
pub const WSA_QOS_EUNKOWNPSOBJ: i32 = 11024;
pub const WSA_QOS_EPOLICYOBJ: i32 = 11025;
pub const WSA_QOS_EFLOWDESC: i32 = 11026;
pub const WSA_QOS_EPSFLOWSPEC: i32 = 11027;
pub const WSA_QOS_EPSFILTERSPEC: i32 = 11028;
pub const WSA_QOS_ESDMODEOBJ: i32 = 11029;
pub const WSA_QOS_ESHAPERATEOBJ: i32 = 11030;
pub const WSA_QOS_RESERVED_PETYPE: i32 = 11031;

pub fn error_message(code: i32) -> &'static str {
    match code {
        0 => "No error",
        WSAEINTR => "Interrupted function call",
        WSAEBADF => "Bad file descriptor",
        WSAEACCES => "Permission denied",
        WSAEFAULT => "Bad address",
        WSAEINVAL => "Invalid argument",
        WSAEMFILE => "Too many open files",
        WSAEWOULDBLOCK => "Resource temporarily unavailable",
        WSAEINPROGRESS => "Operation now in progress",
        WSAEALREADY => "Operation already in progress",
        WSAENOTSOCK => "Socket operation on nonsocket",
        WSAEDESTADDRREQ => "Destination address required",
        WSAEMSGSIZE => "Message too long",
        WSAEPROTOTYPE => "Protocol wrong type for socket",
        WSAENOPROTOOPT => "Bad protocol option",
        WSAEPROTONOSUPPORT => "Protocol not supported",
        WSAESOCKTNOSUPPORT => "Socket type not supported",
        WSAEOPNOTSUPP => "Operation not supported",
        WSAEPFNOSUPPORT => "Protocol family not supported",
        WSAEAFNOSUPPORT => "Address family not supported by protocol family",
        WSAEADDRINUSE => "Address already in use",
        WSAEADDRNOTAVAIL => "Cannot assign requested address",
        WSAENETDOWN => "Network is down",
        WSAENETUNREACH => "Network is unreachable",
        WSAENETRESET => "Network dropped connection on reset",
        WSAECONNABORTED => "Software caused connection abort",
        WSAECONNRESET => "Connection reset by peer",
        WSAENOBUFS => "No buffer space available",
        WSAEISCONN => "Socket is already connected",
        WSAENOTCONN => "Socket is not connected",
        WSAESHUTDOWN => "Cannot send after socket shutdown",
        WSAETOOMANYREFS => "Too many references",
        WSAETIMEDOUT => "Connection timed out",
        WSAECONNREFUSED => "Connection refused",
        WSAELOOP => "Cannot translate name",
        WSAENAMETOOLONG => "Name too long",
        WSAEHOSTDOWN => "Host is down",
        WSAEHOSTUNREACH => "No route to host",
        WSAENOTEMPTY => "Directory not empty",
        WSAEPROCLIM => "Too many processes",
        WSAEUSERS => "User quota exceeded",
        WSAEDQUOT => "Disk quota exceeded",
        WSAESTALE => "Stale file handle reference",
        WSAEREMOTE => "Item is remote",
        WSASYSNOTREADY => "Network subsystem is unavailable",
        WSAVERNOTSUPPORTED => "Winsock.dll version out of range",
        WSANOTINITIALISED => "Successful WSAStartup not yet performed",
        WSAEDISCON => "Graceful shutdown in progress",
        WSAENOMORE => "No more results",
        WSAECANCELLED => "Call has been canceled",
        WSAEINVALIDPROCTABLE => "Procedure call table is invalid",
        WSAEINVALIDPROVIDER => "Service provider is invalid",
        WSAEPROVIDERFAILEDINIT => "Service provider failed to initialize",
        WSASYSCALLFAILURE => "System call failure",
        WSASERVICE_NOT_FOUND => "Service not found",
        WSATYPE_NOT_FOUND => "Class type not found",
        WSAHOST_NOT_FOUND => "Host not found",
        WSATRY_AGAIN => "Nonauthoritative host not found",
        WSANO_RECOVERY => "This is a nonrecoverable error",
        WSANO_DATA => "Valid name, no data record of requested type",
        _ => "Unknown error",
    }
}
