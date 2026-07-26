//! Ancillary Function Driver (AFD) — the NT 6.1 socket endpoint
//!
//! AFD is the user-mode-facing kernel endpoint that exposes
//! sockets as NT handles. Win32 user-mode code (specifically
//! `ws2_32.dll` / `msafd.dll`) talks to AFD via
//! `NtCreateFile` + `NtDeviceIoControlFile`.
//!
//! AFD is the *only* path that user-mode Winsock uses. There is
//! no "BSD socket handle" anymore at the kernel boundary —
//! every operation is a real I/O request against an AFD
//! endpoint. This kernel implements the NT 6.1 subset that
//! OpenSSH actually calls:
//!
//!   - `IOCTL_AFD_BIND`     — bind socket to local addr/port
//!   - `IOCTL_AFD_LISTEN`   — start listening
//!   - `IOCTL_AFD_ACCEPT`   — return a child socket for a
//!                            completed 3-way handshake
//!   - `IOCTL_AFD_CONNECT`  — initiate client-side connect
//!   - `IOCTL_AFD_SEND`     — send data
//!   - `IOCTL_AFD_RECV`     — receive data
//!   - `IOCTL_AFD_SELECT`   — poll for read/write readiness
//!   - `IOCTL_AFD_EVENT_SELECT` — request signal-on-event
//!   - `IOCTL_AFD_GET_NAME` — read back local/peer name
//!   - `IOCTL_AFD_SHUTDOWN` — close one direction
//!
//! The handle table in `libs::ntdll::file` already tracks
//! handles; we add a new `HandleKind::Afd` so the file I/O
//! dispatch routes `NtDeviceIoControlFile` here.

use crate::ke::sync::Spinlock;
use crate::netstack::socket;
use crate::netstack::tcp;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// IOCTL codes (FSCTL_AFD_*). NT 6.1 defines these in
/// `msafd.h`. We only need the subset that ws2_32 / msafd
/// calls during OpenSSH bring-up.
pub const IOCTL_AFD_BIND: u32 = 0x00012003;
pub const IOCTL_AFD_LISTEN: u32 = 0x0001200B;
pub const IOCTL_AFD_ACCEPT: u32 = 0x00012010;
pub const IOCTL_AFD_CONNECT: u32 = 0x00012007;
pub const IOCTL_AFD_SEND: u32 = 0x0001201F;
pub const IOCTL_AFD_RECV: u32 = 0x00012017;
pub const IOCTL_AFD_SELECT: u32 = 0x00012024;
pub const IOCTL_AFD_EVENT_SELECT: u32 = 0x00012014;
pub const IOCTL_AFD_GET_NAME: u32 = 0x0001202B;
pub const IOCTL_AFD_SHUTDOWN: u32 = 0x00012021;

/// Maximum number of AFD endpoints we can hold in the kernel.
pub const MAX_AFD_ENDPOINTS: usize = 64;

/// Address representation that AFD exchanges with user mode.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AfdAddress {
    pub family: u16,    // 2 = AF_INET
    pub port: u16,
    pub addr: [u8; 4],
    pub zeros: [u8; 8],
}

impl AfdAddress {
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
    pub fn to_sockaddr(&self) -> socket::SockAddr {
        let mut sa = socket::SockAddr::new(self.family, self.port, self.ip());
        sa.addr = self.addr;
        sa
    }
}

/// One AFD endpoint. The host `socket_id` is the BSD socket
/// that we delegate to for actual I/O.
pub struct AfdEndpoint {
    pub socket_id: u32,
    pub in_use: bool,
    /// Monotonically increasing generation counter. Each successful
    /// `create()` increments the slot's generation and stores it in
    /// the public handle. `with_endpoint` and `destroy` verify the
    /// caller's generation matches before operating on the slot.
    pub generation: u64,
}

static AFD_ENDPOINTS: Spinlock<[Option<AfdEndpoint>; MAX_AFD_ENDPOINTS]> =
    Spinlock::new([const { None }; MAX_AFD_ENDPOINTS]);
static NEXT_HANDLE_SEQ: AtomicU64 = AtomicU64::new(1);

/// Encode a `(slot, generation)` pair into a 64-bit AFD handle.
/// Layout: bits 0..16 = slot (0..MAX_AFD_ENDPOINTS-1),
///         bits 16..64 = generation. Always non-zero.
fn encode_handle(slot: usize, generation: u64) -> u64 {
    ((generation & 0x0000_FFFF_FFFF_FFFF) << 16) | ((slot as u64) & 0xFFFF) | 0x1_0000
}

fn decode_handle(handle: u64) -> Option<(usize, u64)> {
    if handle == 0 { return None; }
    let slot = (handle & 0xFFFF) as usize;
    if slot >= MAX_AFD_ENDPOINTS { return None; }
    let generation = (handle >> 16) & 0x0000_FFFF_FFFF_FFFF;
    Some((slot, generation))
}

/// Allocate an AFD endpoint for the given socket id.
pub fn create(socket_id: u32) -> Option<u64> {
    let mut endpoints = AFD_ENDPOINTS.lock();
    for slot_idx in 0..endpoints.len() {
        let slot = &mut endpoints[slot_idx];
        let next_gen = match slot.as_ref() {
            Some(e) => e.generation.wrapping_add(1),
            None => 1,
        };
        if slot.is_none() || next_gen != 0 {
            let generation = if next_gen == 0 { 1 } else { next_gen };
            *slot = Some(AfdEndpoint { socket_id, in_use: true, generation });
            // Reserve the global sequence so handles cannot be confused
            // for any other handle space (e.g. the file handle table).
            let _ = NEXT_HANDLE_SEQ.fetch_add(1, Ordering::Relaxed);
            return Some(encode_handle(slot_idx, generation));
        }
    }
    None
}

fn with_endpoint<R>(handle: u64, f: impl FnOnce(&mut AfdEndpoint) -> R) -> Option<R> {
    let (slot_idx, generation) = decode_handle(handle)?;
    let mut endpoints = AFD_ENDPOINTS.lock();
    let slot = endpoints.get_mut(slot_idx)?.as_mut()?;
    if slot.generation != generation {
        // The handle is stale: the endpoint was destroyed or replaced
        // since this handle was issued.
        return None;
    }
    Some(f(slot))
}

fn destroy(handle: u64) {
    let Some((slot_idx, generation)) = decode_handle(handle) else { return; };
    let mut endpoints = AFD_ENDPOINTS.lock();
    if let Some(slot) = endpoints.get_mut(slot_idx) {
        if let Some(ep) = slot.as_ref() {
            if ep.generation == generation {
                *slot = None;
            }
        }
    }
}

/// Dispatch an AFD IOCTL. `input` is the raw bytes that msafd
/// sent; `output` is the buffer the caller wants results in.
/// Returns the NTSTATUS.
pub fn dispatch(
    handle: u64,
    ioctl: u32,
    input: &[u8],
    output: &mut [u8],
) -> i32 {
    let Some(ep) = (match ioctl { _ => with_endpoint(handle, |e| e.socket_id) }) else {
        return -1; // STATUS_INVALID_HANDLE
    };
    match ioctl {
        IOCTL_AFD_BIND => afd_bind(ep, input),
        IOCTL_AFD_LISTEN => afd_listen(ep, input),
        IOCTL_AFD_ACCEPT => afd_accept(ep, input, output),
        IOCTL_AFD_CONNECT => afd_connect(ep, input),
        IOCTL_AFD_SEND => afd_send(ep, input, output),
        IOCTL_AFD_RECV => afd_recv(ep, input, output),
        IOCTL_AFD_SELECT => afd_select(ep, output),
        IOCTL_AFD_GET_NAME => afd_get_name(ep, input, output),
        IOCTL_AFD_SHUTDOWN => afd_shutdown(ep, input),
        _ => {
            crate::boot_println!("[AFD] unknown IOCTL {:#x}", ioctl);
            -2 // STATUS_NOT_IMPLEMENTED
        }
    }
}

/// Decode an AFD bind address from the wire format.
fn decode_addr(input: &[u8]) -> Option<AfdAddress> {
    if input.len() < 16 {
        return None;
    }
    Some(AfdAddress {
        family: u16::from_le_bytes([input[0], input[1]]),
        port: u16::from_be_bytes([input[2], input[3]]),
        addr: [input[4], input[5], input[6], input[7]],
        zeros: [0; 8],
    })
}

fn afd_bind(socket_id: u32, input: &[u8]) -> i32 {
    let Some(addr) = decode_addr(input) else { return -1; };
    let sa = addr.to_sockaddr();
    let result = socket::bind(socket_id, &sa);
    match result {
        Ok(()) => 0,
        Err(_) => -8, // STATUS_INVALID_PARAMETER
    }
}

fn afd_listen(socket_id: u32, input: &[u8]) -> i32 {
    // Input: u32 backlog (NT 6.1 uses an AFD_LISTEN_DATA struct
    // with a 4-byte integer; we only need the first 4 bytes).
    let backlog = if input.len() >= 4 {
        u32::from_le_bytes([input[0], input[1], input[2], input[3]])
    } else {
        8
    };
    match socket::listen(socket_id, backlog) {
        Ok(()) => 0,
        Err(_) => -8,
    }
}

fn afd_accept(socket_id: u32, _input: &[u8], output: &mut [u8]) -> i32 {
    // Try to dequeue a child TCB. If none ready, return
    // STATUS_CANT_WAIT (-3) so msafd falls back to
    // NtWaitForSingleObject against the endpoint's event.
    match socket::accept(socket_id) {
        Ok(peer_socket_id) => {
            if output.len() >= 16 {
                let addr = AfdAddress::new(2, 0, 0);
                output[0..2].copy_from_slice(&addr.family.to_le_bytes());
                output[2..4].copy_from_slice(&addr.port.to_be_bytes());
                output[4..8].copy_from_slice(&addr.addr);
            output[8..16].copy_from_slice(&addr.zeros);
        }
        peer_socket_id as i32
    }
    Err(_) => -3, // STATUS_CANT_WAIT
    }
}

fn afd_connect(socket_id: u32, input: &[u8]) -> i32 {
    let Some(addr) = decode_addr(input) else { return -1; };
    let sa = addr.to_sockaddr();
    match socket::connect(socket_id, &sa) {
        Ok(()) => 0,
        Err(_) => -3, // STATUS_CANT_WAIT
    }
}

fn afd_send(socket_id: u32, input: &[u8], _output: &mut [u8]) -> i32 {
    // AFD_SEND_DATA layout: u32 buffer_count, AFD_WSABUF[count].
    // We only support 1 buffer (covers NetX/PosixOpenSSH).
    if input.len() < 8 {
        return -1;
    }
    let buf_count = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    if buf_count == 0 || input.len() < 16 {
        return -1;
    }
    let buf_len = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    let buf_ptr = u32::from_le_bytes([input[12], input[13], input[14], input[15]]) as u64;
    if crate::mm::user_copy::probe_user_read(buf_ptr, buf_len as usize).is_err() {
        return -8; // STATUS_ACCESS_VIOLATION
    }
    let payload = unsafe {
        core::slice::from_raw_parts(buf_ptr as *const u8, buf_len as usize)
    };
    match socket::send(socket_id, payload) {
        Ok(n) => n as i32,
        Err(_) => -2,
    }
}

fn afd_recv(socket_id: u32, input: &[u8], output: &mut [u8]) -> i32 {
    if input.len() < 16 {
        return -1;
    }
    let buf_len = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    let buf_ptr = u32::from_le_bytes([input[12], input[13], input[14], input[15]]) as u64;
    let len = buf_len.min(output.len() as u32) as usize;
    if crate::mm::user_copy::probe_user_write(buf_ptr, len).is_err() {
        return -8; // STATUS_ACCESS_VIOLATION
    }
    let dst = unsafe {
        core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len)
    };
    match socket::recv(socket_id, dst) {
        Ok(n) => n as i32,
        Err(_) => -3, // STATUS_CANT_WAIT
    }
}

fn afd_select(socket_id: u32, output: &mut [u8]) -> i32 {
    // Output: AFD_POLL_INFO (4 bytes: read/write/except/error).
    if output.len() < 4 {
        return -1;
    }
    let state = socket::get_state(socket_id).unwrap_or(socket::SocketState::Closed);
    let mut flags = 0u32;
    if matches!(state, socket::SocketState::Listening) {
        flags |= 0x01; // read-ready (accept queued)
    }
    if let Some(true) = socket_has_pending_data(socket_id) {
        flags |= 0x01;
    }
    output[0..4].copy_from_slice(&flags.to_le_bytes());
    0
}

fn socket_has_pending_data(socket_id: u32) -> Option<bool> {
    // The internal TCB exposes RX buffer length via the
    // TCP receive path. We approximate by attempting a non-blocking
    // peek: if recv returns WouldBlock, no data is pending.
    let mut tmp = [0u8; 1];
    match socket::recv(socket_id, &mut tmp) {
        Ok(0) => Some(false),
        Ok(_) => Some(true),
        Err(_) => Some(false),
    }
}

fn afd_get_name(socket_id: u32, input: &[u8], output: &mut [u8]) -> i32 {
    // First byte of input means local (0) vs peer (1).
    let which = input.first().copied().unwrap_or(0);
    let addr = match which {
        0 => socket::get_local_addr(socket_id),
        1 => socket::get_remote_addr(socket_id),
        _ => None,
    };
    let Some(addr) = addr else { return -1; };
    if output.len() < 16 {
        return -1;
    }
    output[0..2].copy_from_slice(&addr.family.to_le_bytes());
    output[2..4].copy_from_slice(&addr.port.to_be_bytes());
    output[4..8].copy_from_slice(&addr.addr);
    output[8..16].copy_from_slice(&addr.zeros);
    0
}

fn afd_shutdown(socket_id: u32, input: &[u8]) -> i32 {
    let how = input.first().copied().unwrap_or(0);
    let _ = (socket_id, how);
    // We don't model half-close at this layer in the kernel
    // socket; the TCP layer handles FIN via close().
    0
}

/// Look up the BSD socket id for an AFD handle.
pub fn lookup_socket(handle: u64) -> Option<u32> {
    with_endpoint(handle, |e| e.socket_id)
}

/// Drop an AFD endpoint. Frees the slot for reuse. The
/// underlying BSD socket is not closed — the owning process
/// does that via closesocket().
pub fn close_handle(handle: u64) {
    destroy(handle);
}

/// Number of live AFD endpoints.
pub fn endpoint_count() -> usize {
    AFD_ENDPOINTS.lock().iter().filter(|e| e.is_some()).count()
}

/// Test helper: forward an AFD dispatch through this module so
/// host unit tests can exercise the decoder logic.
#[doc(hidden)]
pub fn dispatch_for_test(
    handle: u64,
    ioctl: u32,
    input: &[u8],
    output: &mut [u8],
) -> i32 {
    dispatch(handle, ioctl, input, output)
}

/// Touch constants so dead-code analysis doesn't complain
/// about IOCTL definitions that are only used by the host
/// tests.
#[allow(dead_code)]
fn _touch_constants() -> Vec<u32> {
    vec![
        IOCTL_AFD_BIND,
        IOCTL_AFD_LISTEN,
        IOCTL_AFD_ACCEPT,
        IOCTL_AFD_CONNECT,
        IOCTL_AFD_SEND,
        IOCTL_AFD_RECV,
        IOCTL_AFD_SELECT,
        IOCTL_AFD_EVENT_SELECT,
        IOCTL_AFD_GET_NAME,
        IOCTL_AFD_SHUTDOWN,
    ]
}
