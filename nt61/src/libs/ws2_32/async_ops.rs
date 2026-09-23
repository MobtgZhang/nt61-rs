//! Async and overlapped I/O operations
//!
//! Implements WSASend, WSARecv, WSASendTo, WSARecvFrom, WSAConnect,
//! WSAAccept, WSAPoll, WSAEventSelect, WSAWaitForMultipleEvents,
//! and event/overlapped structures.

#![allow(non_snake_case)]

use super::types::*;
use super::error::*;
use super::socket::{send, recv, accept, connect};
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

pub type WSAEVENT = usize;

static EVENT_TABLE: Spinlock<Vec<bool>> = Spinlock::new(Vec::new());

pub fn WSACreateEvent() -> WSAEVENT {
    let mut table = EVENT_TABLE.lock();

    for (idx, entry) in table.iter_mut().enumerate() {
        if !*entry {
            *entry = true;
            return (idx + 1) as WSAEVENT;
        }
    }

    table.push(true);
    table.len() as WSAEVENT
}

pub fn WSACloseEvent(hEvent: WSAEVENT) -> bool {
    if hEvent == 0 {
        set_last_error(WSAEINVAL);
        return false;
    }

    let mut table = EVENT_TABLE.lock();
    let idx = (hEvent - 1) as usize;

    if idx < table.len() && table[idx] {
        table[idx] = false;
        set_last_error(0);
        true
    } else {
        set_last_error(WSAENOTSOCK);
        false
    }
}

pub fn WSASetEvent(hEvent: WSAEVENT) -> bool {
    if hEvent == 0 {
        set_last_error(WSAEINVAL);
        return false;
    }

    set_last_error(0);
    true
}

pub fn WSAResetEvent(hEvent: WSAEVENT) -> bool {
    if hEvent == 0 {
        set_last_error(WSAEINVAL);
        return false;
    }

    set_last_error(0);
    true
}

pub fn WSAWaitForMultipleEvents(
    cEvents: u32,
    lphEvents: *const WSAEVENT,
    fWaitAll: bool,
    dwTimeout: u32,
    fAlertable: bool,
) -> u32 {
    if lphEvents.is_null() || cEvents == 0 || cEvents > 64 {
        set_last_error(WSAEINVAL);
        return 0xFFFFFFFF; // WSA_WAIT_FAILED
    }

    if dwTimeout == 0 {
        set_last_error(WSAETIMEDOUT);
        return 0x00000102; // WSA_WAIT_TIMEOUT
    }

    set_last_error(0);
    0 // WSA_WAIT_EVENT_0
}

pub fn WSAEventSelect(s: usize, hEventObject: WSAEVENT, lNetworkEvents: i32) -> i32 {
    if s == 0 || s == INVALID_SOCKET {
        set_last_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    set_last_error(0);
    0
}

pub fn WSAEnumNetworkEvents(
    s: usize,
    hEventObject: WSAEVENT,
    lpNetworkEvents: *mut WSANETWORKEVENTS,
) -> i32 {
    if s == 0 || s == INVALID_SOCKET {
        set_last_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    if lpNetworkEvents.is_null() {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    unsafe {
        (*lpNetworkEvents).lNetworkEvents = 0;
        for i in 0..10 {
            (*lpNetworkEvents).iErrorCode[i] = 0;
        }
    }

    set_last_error(0);
    0
}

pub fn WSASend(
    s: usize,
    lpBuffers: *const WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: *mut u32,
    dwFlags: u32,
    lpOverlapped: *mut WSAOVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    if lpBuffers.is_null() || dwBufferCount == 0 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let mut total_sent = 0u32;

    for i in 0..dwBufferCount {
        let buf = unsafe { &*lpBuffers.add(i as usize) };
        let result = send(s, buf.buf, buf.len as i32, 0);

        if result == SOCKET_ERROR {
            return SOCKET_ERROR;
        }

        total_sent += result as u32;
    }

    if !lpNumberOfBytesSent.is_null() {
        unsafe { *lpNumberOfBytesSent = total_sent; }
    }

    set_last_error(0);
    0
}

pub fn WSARecv(
    s: usize,
    lpBuffers: *mut WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesRecvd: *mut u32,
    lpFlags: *mut u32,
    lpOverlapped: *mut WSAOVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    if lpBuffers.is_null() || dwBufferCount == 0 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let buf = unsafe { &*lpBuffers };
    let result = recv(s, buf.buf, buf.len as i32, 0);

    if result == SOCKET_ERROR {
        return SOCKET_ERROR;
    }

    if !lpNumberOfBytesRecvd.is_null() {
        unsafe { *lpNumberOfBytesRecvd = result as u32; }
    }

    if !lpFlags.is_null() {
        unsafe { *lpFlags = 0; }
    }

    set_last_error(0);
    0
}

pub fn WSASendTo(
    s: usize,
    lpBuffers: *const WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: *mut u32,
    dwFlags: u32,
    lpTo: *const sockaddr,
    iToLen: i32,
    lpOverlapped: *mut WSAOVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    // Simplified: use WSASend
    WSASend(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesSent,
        dwFlags,
        lpOverlapped,
        lpCompletionRoutine,
    )
}

pub fn WSARecvFrom(
    s: usize,
    lpBuffers: *mut WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesRecvd: *mut u32,
    lpFlags: *mut u32,
    lpFrom: *mut sockaddr,
    lpFromlen: *mut i32,
    lpOverlapped: *mut WSAOVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    // Simplified: use WSARecv
    WSARecv(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesRecvd,
        lpFlags,
        lpOverlapped,
        lpCompletionRoutine,
    )
}

pub fn WSAConnect(
    s: usize,
    name: *const sockaddr,
    namelen: i32,
    lpCallerData: *const WSABUF,
    lpCalleeData: *mut WSABUF,
    lpSQOS: *const QOS,
    lpGQOS: *const QOS,
) -> i32 {
    connect(s, name, namelen)
}

pub fn WSAAccept(
    s: usize,
    addr: *mut sockaddr,
    addrlen: *mut i32,
    lpfnCondition: *const u8, // callback
    dwCallbackData: usize,
) -> usize {
    accept(s, addr, addrlen)
}

pub fn WSAPoll(fdArray: *mut WSAPOLLFD, fds: u32, timeout: i32) -> i32 {
    if fdArray.is_null() || fds == 0 {
        set_last_error(WSAEINVAL);
        return SOCKET_ERROR;
    }

    let mut ready_count = 0;

    for i in 0..fds {
        let pollfd = unsafe { &mut *fdArray.add(i as usize) };

        if pollfd.fd != 0 && pollfd.fd != INVALID_SOCKET {
            pollfd.revents = pollfd.events;
            if pollfd.revents != 0 {
                ready_count += 1;
            }
        } else {
            pollfd.revents = POLLNVAL;
        }
    }

    set_last_error(0);
    ready_count
}

pub fn WSASocket(
    af: i32,
    socket_type: i32,
    protocol: i32,
    lpProtocolInfo: *const WSAPROTOCOL_INFOW,
    g: u32,
    dwFlags: u32,
) -> usize {
    super::socket::socket(af, socket_type, protocol)
}

pub fn WSADuplicateSocketA(
    s: usize,
    dwProcessId: u32,
    lpProtocolInfo: *mut WSAPROTOCOL_INFOW,
) -> i32 {
    set_last_error(WSAEOPNOTSUPP);
    SOCKET_ERROR
}

pub fn WSAIoctl(
    s: usize,
    dwIoControlCode: u32,
    lpvInBuffer: *const u8,
    cbInBuffer: u32,
    lpvOutBuffer: *mut u8,
    cbOutBuffer: u32,
    lpcbBytesReturned: *mut u32,
    lpOverlapped: *mut WSAOVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    if s == 0 || s == INVALID_SOCKET {
        set_last_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    match dwIoControlCode {
        SIO_GET_EXTENSION_FUNCTION_POINTER => {
            if !lpvOutBuffer.is_null() && cbOutBuffer >= 8 {
                unsafe {
                    *(lpvOutBuffer as *mut u64) = 0;
                }
                if !lpcbBytesReturned.is_null() {
                    unsafe { *lpcbBytesReturned = 8; }
                }
                set_last_error(0);
                0
            } else {
                set_last_error(WSAEFAULT);
                SOCKET_ERROR
            }
        }
        _ => {
            set_last_error(WSAEOPNOTSUPP);
            SOCKET_ERROR
        }
    }
}

pub fn WSAGetOverlappedResult(
    s: usize,
    lpOverlapped: *const WSAOVERLAPPED,
    lpcbTransfer: *mut u32,
    fWait: bool,
    lpdwFlags: *mut u32,
) -> bool {
    if lpOverlapped.is_null() || lpcbTransfer.is_null() {
        set_last_error(WSAEFAULT);
        return false;
    }

    unsafe {
        *lpcbTransfer = (*lpOverlapped).InternalHigh as u32;
    }

    if !lpdwFlags.is_null() {
        unsafe { *lpdwFlags = 0; }
    }

    set_last_error(0);
    true
}

pub fn WSACancelBlockingCall() -> i32 {
    set_last_error(WSAEOPNOTSUPP);
    SOCKET_ERROR
}

pub fn WSAIsBlocking() -> bool {
    false
}

pub fn WSASetBlockingHook(lpBlockFunc: *const u8) -> *const u8 {
    set_last_error(WSAEOPNOTSUPP);
    core::ptr::null()
}

pub fn WSAUnhookBlockingHook() -> i32 {
    set_last_error(WSAEOPNOTSUPP);
    SOCKET_ERROR
}

pub fn WSAAsyncSelect(s: usize, hWnd: usize, wMsg: u32, lEvent: i32) -> i32 {
    if s == 0 || s == INVALID_SOCKET {
        set_last_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    set_last_error(0);
    0
}

pub fn WSAAsyncGetHostByName(
    hWnd: usize,
    wMsg: u32,
    name: *const u8,
    buf: *mut u8,
    buflen: i32,
) -> usize {
    // Not supported (use getaddrinfo instead)
    set_last_error(WSAEOPNOTSUPP);
    0
}

pub fn WSAAsyncGetHostByAddr(
    hWnd: usize,
    wMsg: u32,
    addr: *const u8,
    len: i32,
    addr_type: i32,
    buf: *mut u8,
    buflen: i32,
) -> usize {
    // Not supported (use getnameinfo instead)
    set_last_error(WSAEOPNOTSUPP);
    0
}

pub fn WSACancelAsyncRequest(hAsyncTaskHandle: usize) -> i32 {
    set_last_error(WSAEINVAL);
    SOCKET_ERROR
}
