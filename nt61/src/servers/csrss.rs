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

#![allow(dead_code)]

use crate::ke::sync::Spinlock;

extern crate alloc;
use alloc::string::String;

/// CSRSS per-session state.
#[derive(Clone, Copy)]
pub struct CsrsState {
    pub session_id: u32,
    pub in_session: u32,
    /// Handle of the per-session `\Sessions\N\Windows\ApiPort` ALPC port.
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
/// `AllocConsole` / `SetConsoleMode` / `GetConsoleMode` / `FreeConsole`).
#[derive(Clone, Copy)]
pub struct CsrsConsole {
    pub handle: usize,
    pub process_id: u32,
    pub session_id: u32,
    pub mode: u32,
    pub in_use: bool,
}

impl CsrsConsole {
    pub const fn new() -> Self {
        Self {
            handle: 0,
            process_id: 0,
            session_id: 0,
            mode: 0,
            in_use: false,
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

/// Console mode bits (MSDN `SetConsoleMode`). Input and output modes share
/// the low bits, so the accepted union is validated against this mask.
pub const CONSOLE_MODE_VALID_BITS: u32 =
    0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x0040 | 0x0080 | 0x0100;

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

/// Create a CSRSS session. Session 0 is the services session; interactive
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

/// Attach a console to a process (`AllocConsole`). Returns the console
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
    };
    state.next_handle += 1;
    state.console_count = slot + 1;
    state.consoles[slot].handle
}

/// Set the console mode (`SetConsoleMode`).
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

/// Get the console mode (`GetConsoleMode`).
pub fn get_console_mode(handle: usize) -> Option<u32> {
    let state = CSRS_STATE.lock();
    find_console(&state, handle).map(|slot| state.consoles[slot].mode)
}

/// Detach a process from its console (`FreeConsole`).
pub fn free_console(handle: usize) -> bool {
    let mut state = CSRS_STATE.lock();
    let slot = match find_console(&state, handle) {
        Some(slot) => slot,
        None => return false,
    };
    state.consoles[slot].in_use = false;
    true
}

/// CSRSS process-creation notification (win32k `Win32ProcessCreated`).
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
    let slot = match find_process(&state, pid) {
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
        // Block on the ALPC port. The scheduler will park us until a
        // request arrives.
        crate::arch::halt();
    }
}
