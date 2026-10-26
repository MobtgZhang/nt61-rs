//! Client/Server Runtime Subsystem (CSRSS)
//
//! Implements the Win32 subsystem server. In real Windows this is a
//! regular user-mode process started by SMSS for each session
//! (Session 0 and Session 1+). The kernel-mode counterpart -
//! win32k.sys - provides the actual window manager, GDI, etc., and is
//! loaded by the I/O manager as a regular driver.
//
//! For the bootstrap we model CSRSS as a kernel thread that runs the
//! `csrss_main` loop and accepts LPC requests from user-mode clients
//! via the ALPC port created in `servers::smss`.

use crate::ke::sync::Spinlock;

extern crate alloc;

/// CSRSS per-session state.
#[derive(Clone, Copy)]
pub struct CsrsState {
    pub session_id: u32,
    pub in_session: u32,
    /// handle of the per-session `\Sessions\N\Windows\ApiPort` ALPC port.
    pub api_port: usize,
    pub active: bool,
}

impl CsrsState {
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            in_session: 0,
            api_port: 0,
            active: false,
        }
    }
}

/// Console object tracked by CSRSS (one per process, MSDN:
/// `alloc_console` / `set_console_mode` / `get_console_mode` / `free_console`).
#[derive(Clone, Copy)]
pub struct CsrsConsole {
    pub handle: usize,
    pub process_id: u32,
    pub session_id: u32,
    pub mode: u32,
    pub in_use: bool,
    pub screen_width: u16,
    pub screen_height: u16,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub attribute: u8,
    pub input_buffer: [u8; 64],
    pub input_head: usize,
    pub input_count: usize,
}

impl CsrsConsole {
    pub const fn new() -> Self {
        Self {
            handle: 0,
            process_id: 0,
            session_id: 0,
            mode: 0,
            in_use: false,
            screen_width: 80,
            screen_height: 25,
            cursor_x: 0,
            cursor_y: 0,
            attribute: 0x07,
            input_buffer: [0; 64],
            input_head: 0,
            input_count: 0,
        }
    }
}

/// Process record tracked by CSRSS for subsystem notifications.
#[derive(Clone, Copy)]
pub struct CsrsProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub image_name: [u16; 260],
    /// Whether the process is attached to the Win32 subsystem (win32k).
    pub connected: bool,
    pub in_use: bool,
}

impl CsrsProcess {
    pub const fn new() -> Self {
        Self {
            pid: 0,
            parent_pid: 0,
            session_id: 0,
            image_name: [0; 260],
            connected: false,
            in_use: false,
        }
    }
}

pub const MAX_SESSIONS: usize = 16;
pub const MAX_CONSOLES: usize = 64;
pub const MAX_PROCESSES: usize = 128;

/// Console mode bits (MSDN `set_console_mode`). Input and output modes share
/// the low bits, so the accepted union is validated against this mask.
pub const CONSOLE_MODE_VALID_BITS: u32 =
    0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x0040 | 0x0080 | 0x0100;

/// CSRSS ALPC port name (matches \Windows\ApiPort created by SMSS).
pub const CSRSS_API_PORT_NAME: &str = "\\Windows\\ApiPort";

/// CSRSS subsystem PID (matches SMSS PID_CSRSS).
pub const PID_CSRSS: u64 = 512;

/// ALPC protocol: subsystem identifier (payload bytes 0..4).
pub const CSRSS_SUBSYSTEM_CONSOLE: u32 = 1;
pub const CSRSS_SUBSYSTEM_PROCESS: u32 = 2;

/// ALPC protocol: console API function numbers (payload bytes 4..8).
pub const CONSOLE_API_ALLOC: u32 = 0;
pub const CONSOLE_API_FREE: u32 = 1;
pub const CONSOLE_API_SET_MODE: u32 = 2;
pub const CONSOLE_API_GET_MODE: u32 = 3;
pub const CONSOLE_API_WRITE_OUTPUT: u32 = 4;
pub const CONSOLE_API_READ_INPUT: u32 = 5;
pub const CONSOLE_API_SET_SCREEN_BUFFER_INFO: u32 = 6;
pub const CONSOLE_API_GET_SCREEN_BUFFER_INFO: u32 = 7;

/// ALPC protocol: process API function numbers.
pub const PROCESS_API_TERMINATED: u32 = 0;

/// ALPC protocol: reply status codes.
pub const CSRSS_STATUS_SUCCESS: u32 = 0;
pub const CSRSS_STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const CSRSS_STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const CSRSS_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// CSRSS global state.
pub struct CsrsGlobal {
    pub sessions: [CsrsState; MAX_SESSIONS],
    pub session_count: usize,
    pub consoles: [CsrsConsole; MAX_CONSOLES],
    pub console_count: usize,
    pub processes: [CsrsProcess; MAX_PROCESSES],
    pub process_count: usize,
    pub notifications: u32,
    pub next_handle: usize,
    pub initialized: bool,
}

impl CsrsGlobal {
    pub const fn new() -> Self {
        Self {
            sessions: [const { CsrsState::new() }; MAX_SESSIONS],
            consoles: [const { CsrsConsole::new() }; MAX_CONSOLES],
            processes: [const { CsrsProcess::new() }; MAX_PROCESSES],
            session_count: 0,
            console_count: 0,
            process_count: 0,
            notifications: 0,
            next_handle: 1,
            initialized: false,
        }
    }
}

pub static CSRS_STATE: Spinlock<CsrsGlobal> = Spinlock::new(CsrsGlobal::new());

fn copy_str(dest: &mut [u16], src: &str) {
    let max = dest.len() - 1;
    for (i, c) in src.chars().enumerate() {
        if i >= max {
            break;
        }
        dest[i] = c as u16;
    }
}

fn create_session_locked(state: &mut CsrsGlobal, session_id: u32) -> bool {
    if session_id >= MAX_SESSIONS as u32 {
        return false;
    }
    if state.session_count >= MAX_SESSIONS {
        return false;
    }
    for slot in 0..state.session_count {
        if state.sessions[slot].session_id == session_id {
            return false;
        }
    }
    let slot = state.session_count;
    state.sessions[slot] = CsrsState {
        session_id,
        in_session: 0,
        // The real ALPC port is created by SMSS (`servers::smss`); CSRSS
        // only keeps the handle it is notified about.
        api_port: state.next_handle,
        active: true,
    };
    state.next_handle += 1;
    state.session_count = slot + 1;
    true
}

fn find_session(state: &CsrsGlobal, session_id: u32) -> Option<usize> {
    for slot in 0..state.session_count {
        if state.sessions[slot].active && state.sessions[slot].session_id == session_id {
            return Some(slot);
        }
    }
    None
}

fn find_console(state: &CsrsGlobal, handle: usize) -> Option<usize> {
    for slot in 0..state.console_count {
        if state.consoles[slot].in_use && state.consoles[slot].handle == handle {
            return Some(slot);
        }
    }
    None
}

fn find_process(state: &CsrsGlobal, pid: u32) -> Option<usize> {
    for slot in 0..state.process_count {
        if state.processes[slot].in_use && state.processes[slot].pid == pid {
            return Some(slot);
        }
    }
    None
}

/// create a CSRSS session. Session 0 is the services session; interactive
/// sessions start at 1.
pub fn create_session(session_id: u32) -> bool {
    let mut state = CSRS_STATE.lock();
    create_session_locked(&mut state, session_id)
}

/// Look up a session by id.
pub fn get_session(session_id: u32) -> Option<CsrsState> {
    let state = CSRS_STATE.lock();
    find_session(&state, session_id).map(|slot| state.sessions[slot])
}

/// Destroy a session. Session 0 (the services session) is never destroyed
/// while the system is running.
pub fn destroy_session(session_id: u32) -> bool {
    let mut state = CSRS_STATE.lock();
    if session_id == 0 {
        return false;
    }
    let slot = match find_session(&state, session_id) {
        Some(slot) => slot,
        None => return false,
    };
    state.sessions[slot].active = false;
    true
}

/// Attach a console to a process (`alloc_console`). Returns the console
/// handle, or 0 when the process already has one or the table is full.
pub fn alloc_console(process_id: u32, session_id: u32) -> usize {
    let mut state = CSRS_STATE.lock();
    if find_session(&state, session_id).is_none() {
        return 0;
    }
    for slot in 0..state.console_count {
        if state.consoles[slot].in_use && state.consoles[slot].process_id == process_id {
            return state.consoles[slot].handle;
        }
    }
    if state.console_count >= MAX_CONSOLES {
        return 0;
    }
    let slot = state.console_count;
    state.consoles[slot] = CsrsConsole {
        handle: state.next_handle,
        process_id,
        session_id,
        mode: 0,
        in_use: true,
        screen_width: 80,
        screen_height: 25,
        cursor_x: 0,
        cursor_y: 0,
        attribute: 0x07,
        input_buffer: [0; 64],
        input_head: 0,
        input_count: 0,
    };
    state.next_handle += 1;
    state.console_count = slot + 1;
    state.consoles[slot].handle
}

/// Set the console mode (`set_console_mode`).
pub fn set_console_mode(handle: usize, mode: u32) -> bool {
    let mut state = CSRS_STATE.lock();
    let slot = match find_console(&state, handle) {
        Some(slot) => slot,
        None => return false,
    };
    if mode & !CONSOLE_MODE_VALID_BITS != 0 {
        return false;
    }
    state.consoles[slot].mode = mode;
    true
}

/// Get the console mode (`get_console_mode`).
pub fn get_console_mode(handle: usize) -> Option<u32> {
    let state = CSRS_STATE.lock();
    find_console(&state, handle).map(|slot| state.consoles[slot].mode)
}

/// Detach a process from its console (`free_console`).
pub fn free_console(handle: usize) -> bool {
    let mut state = CSRS_STATE.lock();
    let slot = match find_console(&state, handle) {
        Some(slot) => slot,
        None => return false,
    };
    state.consoles[slot].in_use = false;
    true
}
/// Write a byte to the console screen and advance the logical cursor.
fn console_write_byte_locked(state: &mut CsrsGlobal, slot: usize, byte: u8) {
    let con = &mut state.consoles[slot];
    if byte == b'\r' {
        con.cursor_x = 0;
        return;
    }
    if byte == b'\n' {
        con.cursor_x = 0;
        con.cursor_y = (con.cursor_y + 1).min(con.screen_height - 1);
        return;
    }
    crate::hal::text_console::put_byte(byte);
    con.cursor_x += 1;
    if con.cursor_x >= con.screen_width {
        con.cursor_x = 0;
        con.cursor_y = (con.cursor_y + 1).min(con.screen_height - 1);
    }
}

/// Push a byte into a console input ring buffer.
pub fn console_input_push_locked(state: &mut CsrsGlobal, slot: usize, byte: u8) -> bool {
    let con = &mut state.consoles[slot];
    if con.input_count >= con.input_buffer.len() {
        return false;
    }
    let tail = (con.input_head + con.input_count) % con.input_buffer.len();
    con.input_buffer[tail] = byte;
    con.input_count += 1;
    true
}

/// Pop one byte from a console input ring buffer, or fall back to HAL keyboard poll.
pub fn console_input_pop_locked(state: &mut CsrsGlobal, slot: usize) -> Option<u8> {
    let con = &mut state.consoles[slot];
    if con.input_count == 0 {
        return crate::hal::keyboard_input::try_read_byte();
    }
    let byte = con.input_buffer[con.input_head];
    con.input_head = (con.input_head + 1) % con.input_buffer.len();
    con.input_count -= 1;
    Some(byte)
}

/// Ensure the CSRSS ALPC API port exists.
fn ensure_api_port() -> Option<u32> {
    let mut name_buf = [0u16; crate::lpc::MAX_PORT_NAME];
    let mut len = 0usize;
    for (i, unit) in CSRSS_API_PORT_NAME.encode_utf16().enumerate() {
        if i >= crate::lpc::MAX_PORT_NAME - 1 {
            break;
        }
        name_buf[i] = unit;
        len = i + 1;
    }
    let name = &name_buf[..len];
    if let Some(existing) = crate::lpc::find_port_by_name(name) {
        return Some(existing);
    }
    crate::lpc::create_connection_port(name, PID_CSRSS)
}

/// CSRSS process-creation notification (win32k `Win32ProcessCreated`).
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    if offset + 4 > buf.len() {
        return 0;
    }
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    if offset + 4 <= buf.len() {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn build_reply(
    request: &crate::lpc::LpcMessage,
    status: u32,
    data: &[u8],
) -> crate::lpc::LpcMessage {
    let mut reply = crate::lpc::LpcMessage::empty();
    let copy_len = data.len().min(reply.data.len() - 4);
    write_u32(&mut reply.data, 0, status);
    reply.data[4..4 + copy_len].copy_from_slice(&data[..copy_len]);
    reply.data_len = (4 + copy_len) as u32;
    reply.header = crate::lpc::LpcMessageHeader::new(
        crate::lpc::LpcMessageType::Reply,
        reply.data_len,
        PID_CSRSS,
        0,
    );
    reply.header.client_pid = request.header.sender_pid;
    reply.header.client_tid = request.header.sender_tid;
    reply
}

fn alloc_console_locked(state: &mut CsrsGlobal, process_id: u32, session_id: u32) -> usize {
    let mut session_found = false;
    for slot in 0..state.session_count {
        if state.sessions[slot].active && state.sessions[slot].session_id == session_id {
            session_found = true;
            break;
        }
    }
    if !session_found {
        return 0;
    }
    for slot in 0..state.console_count {
        if state.consoles[slot].in_use && state.consoles[slot].process_id == process_id {
            return state.consoles[slot].handle;
        }
    }
    if state.console_count >= MAX_CONSOLES {
        return 0;
    }
    let slot = state.console_count;
    state.consoles[slot] = CsrsConsole {
        handle: state.next_handle,
        process_id,
        session_id,
        mode: 0,
        in_use: true,
        screen_width: 80,
        screen_height: 25,
        cursor_x: 0,
        cursor_y: 0,
        attribute: 0x07,
        input_buffer: [0; 64],
        input_head: 0,
        input_count: 0,
    };
    state.next_handle += 1;
    state.console_count = slot + 1;
    state.consoles[slot].handle
}

fn dispatch_csrss_message(msg: &crate::lpc::LpcMessage) -> Option<crate::lpc::LpcMessage> {
    if msg.data_len < 8 {
        return None;
    }
    let subsystem = read_u32(&msg.data, 0);
    let function = read_u32(&msg.data, 4);
    let sender_pid = msg.header.sender_pid as u32;
    let payload_end = (msg.data_len as usize).min(msg.data.len());
    if payload_end < 8 {
        return None;
    }
    let payload = &msg.data[8..payload_end];
    match subsystem {
        CSRSS_SUBSYSTEM_CONSOLE => dispatch_console_api(function, payload, sender_pid),
        CSRSS_SUBSYSTEM_PROCESS => dispatch_process_api(function, payload, sender_pid),
        _ => None,
    }
}

fn dispatch_console_api(
    function: u32,
    payload: &[u8],
    sender_pid: u32,
) -> Option<crate::lpc::LpcMessage> {
    let mut state = CSRS_STATE.lock();
    match function {
        CONSOLE_API_ALLOC => {
            let session_id = read_u32(payload, 0);
            let handle = alloc_console_locked(&mut state, sender_pid, session_id);
            let mut out = [0u8; 8];
            let status = if handle == 0 {
                CSRSS_STATUS_NO_MEMORY
            } else {
                CSRSS_STATUS_SUCCESS
            };
            write_u32(&mut out, 0, status);
            write_u32(&mut out, 4, handle as u32);
            let req = crate::lpc::LpcMessage::empty();
            Some(build_reply(&req, CSRSS_STATUS_SUCCESS, &out))
        }
        CONSOLE_API_FREE => {
            let handle = read_u32(payload, 0) as usize;
            let ok = free_console_locked(&mut state, handle);
            let status = if ok {
                CSRSS_STATUS_SUCCESS
            } else {
                CSRSS_STATUS_INVALID_HANDLE
            };
            let req = crate::lpc::LpcMessage::empty();
            Some(build_reply(&req, status, &[]))
        }
        CONSOLE_API_SET_MODE => {
            let handle = read_u32(payload, 0) as usize;
            let mode = read_u32(payload, 4);
            let ok = set_console_mode_locked(&mut state, handle, mode);
            let status = if ok {
                CSRSS_STATUS_SUCCESS
            } else {
                CSRSS_STATUS_INVALID_HANDLE
            };
            let req = crate::lpc::LpcMessage::empty();
            Some(build_reply(&req, status, &[]))
        }
        CONSOLE_API_GET_MODE => {
            let handle = read_u32(payload, 0) as usize;
            match get_console_mode_locked(&state, handle) {
                Some(mode) => {
                    let mut out = [0u8; 4];
                    write_u32(&mut out, 0, mode);
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_SUCCESS, &out))
                }
                None => {
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_INVALID_HANDLE, &[]))
                }
            }
        }
        CONSOLE_API_WRITE_OUTPUT => {
            let handle = read_u32(payload, 0) as usize;
            let slot = find_console(&state, handle);
            match slot {
                Some(slot) => {
                    let count = payload.len().saturating_sub(4);
                    for i in 0..count {
                        let byte = payload[4 + i];
                        console_write_byte_locked(&mut state, slot, byte);
                    }
                    let mut out = [0u8; 4];
                    write_u32(&mut out, 0, count as u32);
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_SUCCESS, &out))
                }
                None => {
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_INVALID_HANDLE, &[]))
                }
            }
        }
        CONSOLE_API_READ_INPUT => {
            let handle = read_u32(payload, 0) as usize;
            let slot = find_console(&state, handle);
            match slot {
                Some(slot) => match console_input_pop_locked(&mut state, slot) {
                    Some(byte) => {
                        let out = [byte, 0, 0, 0];
                        let req = crate::lpc::LpcMessage::empty();
                        Some(build_reply(&req, CSRSS_STATUS_SUCCESS, &out))
                    }
                    None => {
                        let req = crate::lpc::LpcMessage::empty();
                        Some(build_reply(&req, CSRSS_STATUS_SUCCESS, &[]))
                    }
                },
                None => {
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_INVALID_HANDLE, &[]))
                }
            }
        }
        CONSOLE_API_SET_SCREEN_BUFFER_INFO => {
            let handle = read_u32(payload, 0) as usize;
            let width = read_u32(payload, 4) as u16;
            let height = read_u32(payload, 6) as u16;
            let slot = find_console(&state, handle);
            match slot {
                Some(slot) => {
                    state.consoles[slot].screen_width = width;
                    state.consoles[slot].screen_height = height;
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_SUCCESS, &[]))
                }
                None => {
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_INVALID_HANDLE, &[]))
                }
            }
        }
        CONSOLE_API_GET_SCREEN_BUFFER_INFO => {
            let handle = read_u32(payload, 0) as usize;
            let slot = find_console(&state, handle);
            match slot {
                Some(slot) => {
                    let con = &state.consoles[slot];
                    let mut out = [0u8; 12];
                    write_u32(&mut out, 0, con.screen_width as u32);
                    write_u32(&mut out, 4, con.screen_height as u32);
                    write_u32(
                        &mut out,
                        8,
                        (con.cursor_x as u32) | ((con.cursor_y as u32) << 16),
                    );
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_SUCCESS, &out))
                }
                None => {
                    let req = crate::lpc::LpcMessage::empty();
                    Some(build_reply(&req, CSRSS_STATUS_INVALID_HANDLE, &[]))
                }
            }
        }
        _ => {
            let req = crate::lpc::LpcMessage::empty();
            Some(build_reply(&req, CSRSS_STATUS_INVALID_PARAMETER, &[]))
        }
    }
}

pub fn set_console_mode_locked(state: &mut CsrsGlobal, handle: usize, mode: u32) -> bool {
    let slot = match find_console(state, handle) {
        Some(slot) => slot,
        None => return false,
    };
    if mode & !CONSOLE_MODE_VALID_BITS != 0 {
        return false;
    }
    state.consoles[slot].mode = mode;
    true
}

pub fn get_console_mode_locked(state: &CsrsGlobal, handle: usize) -> Option<u32> {
    find_console(state, handle).map(|slot| state.consoles[slot].mode)
}

pub fn free_console_locked(state: &mut CsrsGlobal, handle: usize) -> bool {
    let slot = match find_console(state, handle) {
        Some(slot) => slot,
        None => return false,
    };
    state.consoles[slot].in_use = false;
    true
}

fn dispatch_process_api(
    function: u32,
    payload: &[u8],
    _sender_pid: u32,
) -> Option<crate::lpc::LpcMessage> {
    match function {
        PROCESS_API_TERMINATED => {
            let pid = read_u32(payload, 0);
            let _ = notify_process_terminated(pid);
            None
        }
        _ => None,
    }
}

/// Poll all ALPC server communication ports owned by CSRSS, dispatch
/// every pending message, and send replies back to the client. Returns
/// the number of messages dispatched so callers can distinguish a
/// drained port from real work.
fn poll_alpc_messages() -> usize {
    if ensure_api_port().is_none() {
        return 0;
    }
    let mut dispatched = 0usize;
    loop {
        match crate::lpc::receive_from_owner_server_port(PID_CSRSS) {
            Some((_port_idx, msg)) => {
                dispatched += 1;
                if let Some(reply) = dispatch_csrss_message(&msg) {
                    let _ = crate::lpc::send(_port_idx, &reply);
                }
            }
            None => break,
        }
    }
    dispatched
}

/// CSRSS server thread entry point.
pub extern "C" fn csrss_server_thread_entry(_context: u64) {
    loop {
        let dispatched = poll_alpc_messages();
        if dispatched == 0 {
            // No port-wait object exists yet; instead of busy-spinning
            // through the scheduler, park on the next interrupt (timer
            // or IPI) so idle periods stop burning the CPU.
            crate::arch::wait_for_interrupt();
        }
        crate::ke::scheduler::yield_();
    }
}

/// Idempotently start the CSRSS server thread.
pub fn start_server_thread() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::Acquire) {
        return;
    }
    let entry = csrss_server_thread_entry as *const () as u64;
    let _ = crate::ps::thread::ps_create_system_thread(entry, 0);
}

/// Clean up CSRSS state for a terminated process.
pub fn notify_process_terminated(pid: u32) -> bool {
    let mut state = CSRS_STATE.lock();
    let mut found = false;
    for slot in 0..state.process_count {
        if state.processes[slot].in_use && state.processes[slot].pid == pid {
            state.processes[slot].in_use = false;
            found = true;
            break;
        }
    }
    for slot in 0..state.console_count {
        if state.consoles[slot].in_use && state.consoles[slot].process_id == pid {
            state.consoles[slot].in_use = false;
        }
    }
    if found && state.process_count > 0 {
        state.notifications += 1;
    }
    found
}
pub fn notify_process_created(
    pid: u32,
    parent_pid: u32,
    session_id: u32,
    image_name: &str,
) -> bool {
    let mut state = CSRS_STATE.lock();
    let session_slot = match find_session(&state, session_id) {
        Some(slot) => slot,
        None => return false,
    };
    if state.process_count >= MAX_PROCESSES {
        return false;
    }
    let slot = state.process_count;
    let mut entry = CsrsProcess::new();
    entry.pid = pid;
    entry.parent_pid = parent_pid;
    entry.session_id = session_id;
    copy_str(&mut entry.image_name, image_name);
    entry.in_use = true;
    state.processes[slot] = entry;
    state.process_count = slot + 1;
    state.sessions[session_slot].in_session += 1;
    state.notifications += 1;
    true
}

/// CSRSS thread-creation notification.
pub fn notify_thread_created(pid: u32, tid: u32) -> bool {
    let mut state = CSRS_STATE.lock();
    let _slot = match find_process(&state, pid) {
        Some(slot) => slot,
        None => return false,
    };
    let _ = tid;
    state.notifications += 1;
    true
}

/// Attach a process to the Win32 subsystem (`win32k` connection).
pub fn connect_to_win32(pid: u32, session_id: u32) -> bool {
    let mut state = CSRS_STATE.lock();
    if find_session(&state, session_id).is_none() {
        return false;
    }
    let slot = match find_process(&state, pid) {
        Some(slot) => slot,
        None => return false,
    };
    state.processes[slot].connected = true;
    true
}

/// `(active sessions, notifications, api port handle)`.
pub fn get_statistics() -> (u32, u32, usize) {
    let state = CSRS_STATE.lock();
    let active = state
        .sessions
        .iter()
        .take(state.session_count)
        .filter(|s| s.active)
        .count() as u32;
    (
        active,
        state.notifications,
        state.next_handle.saturating_sub(1),
    )
}

/// Reset CSRSS state and create Session 0 (services) plus Session 1
/// (first interactive session), matching the Windows session layout.
pub fn init() {
    // kprintln!("    CSRSS subsystem: initialized");
    let mut state = CSRS_STATE.lock();
    state.sessions = [const { CsrsState::new() }; MAX_SESSIONS];
    state.consoles = [const { CsrsConsole::new() }; MAX_CONSOLES];
    state.processes = [const { CsrsProcess::new() }; MAX_PROCESSES];
    state.session_count = 0;
    state.console_count = 0;
    state.process_count = 0;
    state.notifications = 0;
    state.next_handle = 1;
    state.initialized = true;

    create_session_locked(&mut state, 0);
    create_session_locked(&mut state, 1);
}

/// CSRSS main loop - process LPC requests forever. In real Windows
/// the requests are multiplexed over an ALPC port named
/// `\\Sessions\\N\\Windows\\ApiPort`.
pub fn csrss_main() -> ! {
    // kprintln!("[CSRSS] Process started");
    loop {
        let dispatched = poll_alpc_messages();
        if dispatched == 0 {
            crate::arch::wait_for_interrupt();
        }
        crate::ke::scheduler::yield_();
    }
}
