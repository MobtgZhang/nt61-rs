//! Async and overlapped I/O operations
//!
//! Implements wsasend, wsarecv, wsasend_to, wsarecv_from, wsaconnect,
//! wsaaccept, wsapoll, wsaevent_select, wsawait_for_multiple_events,
//! and event/overlapped structures.

use super::error::*;
use super::socket::{accept, connect, recv, send};
use super::types::*;
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

pub type WSAEVENT = usize;

static EVENT_TABLE: Spinlock<Vec<bool>> = Spinlock::new(Vec::new());

pub fn wsacreate_event() -> WSAEVENT {
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

pub fn wsaclose_event(h_event: WSAEVENT) -> bool {
    if h_event == 0 {
        set_last_error(WSAEINVAL);
        return false;
    }

    let mut table = EVENT_TABLE.lock();
    let idx = (h_event - 1) as usize;

    if idx < table.len() && table[idx] {
        table[idx] = false;
        set_last_error(0);
        true
    } else {
        set_last_error(WSAENOTSOCK);
        false
    }
}

pub fn wsaset_event(h_event: WSAEVENT) -> bool {
    if h_event == 0 {
        set_last_error(WSAEINVAL);
        return false;
    }

    set_last_error(0);
    true
}

pub fn wsareset_event(h_event: WSAEVENT) -> bool {
    if h_event == 0 {
        set_last_error(WSAEINVAL);
        return false;
    }

    set_last_error(0);
    true
}

pub fn wsawait_for_multiple_events(
    c_events: u32,
    lph_events: *const WSAEVENT,
    _f_wait_all: bool,
    dw_timeout: u32,
    _f_alertable: bool,
) -> u32 {
    if lph_events.is_null() || c_events == 0 || c_events > 64 {
        set_last_error(WSAEINVAL);
        return 0xFFFFFFFF; // WSA_WAIT_FAILED
    }

    if dw_timeout == 0 {
        set_last_error(WSAETIMEDOUT);
        return 0x00000102; // WSA_WAIT_TIMEOUT
    }

    set_last_error(0);
    0 // WSA_WAIT_EVENT_0
}

pub fn wsaevent_select(s: usize, _h_event_object: WSAEVENT, _l_network_events: i32) -> i32 {
    if s == 0 || s == INVALID_SOCKET {
        set_last_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    set_last_error(0);
    0
}

pub fn wsaenum_network_events(
    s: usize,
    _h_event_object: WSAEVENT,
    lp_network_events: *mut WSANETWORKEVENTS,
) -> i32 {
    if s == 0 || s == INVALID_SOCKET {
        set_last_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    if lp_network_events.is_null() {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    unsafe {
        (*lp_network_events).l_network_events = 0;
        for i in 0..10 {
            (*lp_network_events).i_error_code[i] = 0;
        }
    }

    set_last_error(0);
    0
}

pub fn wsasend(
    s: usize,
    lp_buffers: *const WSABUF,
    dw_buffer_count: u32,
    lp_number_of_bytes_sent: *mut u32,
    _dw_flags: u32,
    _lp_overlapped: *mut WSAOVERLAPPED,
    _lp_completion_routine: LpwsaoverlappedCompletionRoutine,
) -> i32 {
    if lp_buffers.is_null() || dw_buffer_count == 0 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let mut total_sent = 0u32;

    for i in 0..dw_buffer_count {
        let buf = unsafe { &*lp_buffers.add(i as usize) };
        let result = send(s, buf.buf, buf.len as i32, 0);

        if result == SOCKET_ERROR {
            return SOCKET_ERROR;
        }

        total_sent += result as u32;
    }

    if !lp_number_of_bytes_sent.is_null() {
        unsafe {
            *lp_number_of_bytes_sent = total_sent;
        }
    }

    set_last_error(0);
    0
}

pub fn wsarecv(
    s: usize,
    lp_buffers: *mut WSABUF,
    dw_buffer_count: u32,
    lp_number_of_bytes_recvd: *mut u32,
    lp_flags: *mut u32,
    _lp_overlapped: *mut WSAOVERLAPPED,
    _lp_completion_routine: LpwsaoverlappedCompletionRoutine,
) -> i32 {
    if lp_buffers.is_null() || dw_buffer_count == 0 {
        set_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let buf = unsafe { &*lp_buffers };
    let result = recv(s, buf.buf, buf.len as i32, 0);

    if result == SOCKET_ERROR {
        return SOCKET_ERROR;
    }

    if !lp_number_of_bytes_recvd.is_null() {
        unsafe {
            *lp_number_of_bytes_recvd = result as u32;
        }
    }

    if !lp_flags.is_null() {
        unsafe {
            *lp_flags = 0;
        }
    }

    set_last_error(0);
    0
}

pub fn wsasend_to(
    s: usize,
    lp_buffers: *const WSABUF,
    dw_buffer_count: u32,
    lp_number_of_bytes_sent: *mut u32,
    dw_flags: u32,
    _lp_to: *const sockaddr,
    _i_to_len: i32,
    lp_overlapped: *mut WSAOVERLAPPED,
    lp_completion_routine: LpwsaoverlappedCompletionRoutine,
) -> i32 {
    // Simplified: use wsasend
    wsasend(
        s,
        lp_buffers,
        dw_buffer_count,
        lp_number_of_bytes_sent,
        dw_flags,
        lp_overlapped,
        lp_completion_routine,
    )
}

pub fn wsarecv_from(
    s: usize,
    lp_buffers: *mut WSABUF,
    dw_buffer_count: u32,
    lp_number_of_bytes_recvd: *mut u32,
    lp_flags: *mut u32,
    _lp_from: *mut sockaddr,
    _lp_fromlen: *mut i32,
    lp_overlapped: *mut WSAOVERLAPPED,
    lp_completion_routine: LpwsaoverlappedCompletionRoutine,
) -> i32 {
    // Simplified: use wsarecv
    wsarecv(
        s,
        lp_buffers,
        dw_buffer_count,
        lp_number_of_bytes_recvd,
        lp_flags,
        lp_overlapped,
        lp_completion_routine,
    )
}

pub fn wsaconnect(
    s: usize,
    name: *const sockaddr,
    namelen: i32,
    _lp_caller_data: *const WSABUF,
    _lp_callee_data: *mut WSABUF,
    _lp_sqos: *const QOS,
    _lp_gqos: *const QOS,
) -> i32 {
    connect(s, name, namelen)
}

pub fn wsaaccept(
    s: usize,
    addr: *mut sockaddr,
    addrlen: *mut i32,
    _lpfn_condition: *const u8, // callback
    _dw_callback_data: usize,
) -> usize {
    accept(s, addr, addrlen)
}

pub fn wsapoll(fd_array: *mut WSAPOLLFD, fds: u32, _timeout: i32) -> i32 {
    if fd_array.is_null() || fds == 0 {
        set_last_error(WSAEINVAL);
        return SOCKET_ERROR;
    }

    let mut ready_count = 0;

    for i in 0..fds {
        let pollfd = unsafe { &mut *fd_array.add(i as usize) };

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

pub fn wsasocket(
    af: i32,
    socket_type: i32,
    protocol: i32,
    _lp_protocol_info: *const WSAPROTOCOL_INFOW,
    _g: u32,
    _dw_flags: u32,
) -> usize {
    super::socket::socket(af, socket_type, protocol)
}

pub fn wsaduplicate_socket_a(
    _s: usize,
    _dw_process_id: u32,
    _lp_protocol_info: *mut WSAPROTOCOL_INFOW,
) -> i32 {
    set_last_error(WSAEOPNOTSUPP);
    SOCKET_ERROR
}

pub fn wsaioctl(
    s: usize,
    dw_io_control_code: u32,
    _lpv_in_buffer: *const u8,
    _cb_in_buffer: u32,
    lpv_out_buffer: *mut u8,
    cb_out_buffer: u32,
    lpcb_bytes_returned: *mut u32,
    _lp_overlapped: *mut WSAOVERLAPPED,
    _lp_completion_routine: LpwsaoverlappedCompletionRoutine,
) -> i32 {
    if s == 0 || s == INVALID_SOCKET {
        set_last_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    match dw_io_control_code {
        SIO_GET_EXTENSION_FUNCTION_POINTER => {
            if !lpv_out_buffer.is_null() && cb_out_buffer >= 8 {
                unsafe {
                    *(lpv_out_buffer as *mut u64) = 0;
                }
                if !lpcb_bytes_returned.is_null() {
                    unsafe {
                        *lpcb_bytes_returned = 8;
                    }
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

pub fn wsaget_overlapped_result(
    _s: usize,
    lp_overlapped: *const WSAOVERLAPPED,
    lpcb_transfer: *mut u32,
    _f_wait: bool,
    lpdw_flags: *mut u32,
) -> bool {
    if lp_overlapped.is_null() || lpcb_transfer.is_null() {
        set_last_error(WSAEFAULT);
        return false;
    }

    unsafe {
        *lpcb_transfer = (*lp_overlapped).internal_high as u32;
    }

    if !lpdw_flags.is_null() {
        unsafe {
            *lpdw_flags = 0;
        }
    }

    set_last_error(0);
    true
}

pub fn wsacancel_blocking_call() -> i32 {
    set_last_error(WSAEOPNOTSUPP);
    SOCKET_ERROR
}

pub fn wsais_blocking() -> bool {
    false
}

pub fn wsaset_blocking_hook(_lp_block_func: *const u8) -> *const u8 {
    set_last_error(WSAEOPNOTSUPP);
    core::ptr::null()
}

pub fn wsaunhook_blocking_hook() -> i32 {
    set_last_error(WSAEOPNOTSUPP);
    SOCKET_ERROR
}

pub fn wsaasync_select(s: usize, _h_wnd: usize, _w_msg: u32, _l_event: i32) -> i32 {
    if s == 0 || s == INVALID_SOCKET {
        set_last_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    set_last_error(0);
    0
}

pub fn wsaasync_get_host_by_name(
    _h_wnd: usize,
    _w_msg: u32,
    _name: *const u8,
    _buf: *mut u8,
    _buflen: i32,
) -> usize {
    // Not supported (use getaddrinfo instead)
    set_last_error(WSAEOPNOTSUPP);
    0
}

pub fn wsaasync_get_host_by_addr(
    _h_wnd: usize,
    _w_msg: u32,
    _addr: *const u8,
    _len: i32,
    _addr_type: i32,
    _buf: *mut u8,
    _buflen: i32,
) -> usize {
    // Not supported (use getnameinfo instead)
    set_last_error(WSAEOPNOTSUPP);
    0
}

pub fn wsacancel_async_request(_h_async_task_handle: usize) -> i32 {
    set_last_error(WSAEINVAL);
    SOCKET_ERROR
}
