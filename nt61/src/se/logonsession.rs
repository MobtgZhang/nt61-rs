//! Logon Session Management
//!
//! Manages logon sessions (authentication IDs) for users. Each logon creates
//! a new authentication ID (LUID) that tracks:
//!   - User SID
//!   - Logon type (Interactive, Network, Batch, Service, etc.)
//!   - Logon time
//!   - Session statistics
//!
//! All tokens created for the same logon share the same authentication ID.
//!
//! References: Windows Internals, WRK LSA

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Lazy, Mutex};

use super::sid::sid;
use super::token::luid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogonType {
    Interactive = 2,              // Interactive logon
    Network = 3,                  // Network logon (e.g., SMB)
    Batch = 4,                    // Batch logon
    Service = 5,                  // Service logon
    Proxy = 6,                    // Proxy logon
    Unlock = 7,                   // Unlock workstation
    NetworkCleartext = 8,         // Network logon with cleartext credentials
    NewCredentials = 9,           // RunAs with alternate credentials
    RemoteInteractive = 10,       // RDP/Terminal Services
    CachedInteractive = 11,       // Cached domain credentials
    CachedRemoteInteractive = 12, // Cached RDP
    CachedUnlock = 13,            // Unlock with cached credentials
}

#[derive(Clone, Copy)]
pub struct LogonSession {
    pub authentication_id: luid,
    pub user_sid: sid,
    pub logon_type: LogonType,
    pub logon_time: u64,
    pub logon_server: [u8; 32],
    pub logon_domain: [u8; 64],
    pub session_id: u32,
    pub active: bool,
}

impl LogonSession {
    pub const fn new() -> Self {
        Self {
            authentication_id: luid::new(),
            user_sid: sid::new(),
            logon_type: LogonType::Interactive,
            logon_time: 0,
            logon_server: [0; 32],
            logon_domain: [0; 64],
            session_id: 0,
            active: false,
        }
    }
}

const MAX_LOGON_SESSIONS: usize = 64;

struct LogonSessionTable {
    sessions: [LogonSession; MAX_LOGON_SESSIONS],
}

impl LogonSessionTable {
    const fn new() -> Self {
        const INIT: LogonSession = LogonSession::new();
        Self {
            sessions: [INIT; MAX_LOGON_SESSIONS],
        }
    }
}

static LOGON_SESSIONS: Lazy<Mutex<LogonSessionTable>> =
    Lazy::new(|| Mutex::new(LogonSessionTable::new()));
static NEXT_LOGON_ID: AtomicU64 = AtomicU64::new(1000);

pub fn se_create_logon_session(
    logon_id: *mut luid,
    user_sid: &sid,
    logon_type: LogonType,
    session_id: u32,
) -> bool {
    if logon_id.is_null() {
        return false;
    }

    unsafe {
        let mut table = LOGON_SESSIONS.lock();
        let mut slot_index = None;
        for i in 0..MAX_LOGON_SESSIONS {
            if !table.sessions[i].active {
                slot_index = Some(i);
                break;
            }
        }

        let index = match slot_index {
            Some(i) => i,
            None => return false, // No free slots
        };

        let auth_id = luid::from_u64(NEXT_LOGON_ID.fetch_add(1, Ordering::Relaxed));

        table.sessions[index].authentication_id = auth_id;
        table.sessions[index].user_sid = *user_sid;
        table.sessions[index].logon_type = logon_type;
        table.sessions[index].logon_time = get_system_time();
        table.sessions[index].session_id = session_id;
        table.sessions[index].active = true;

        *logon_id = auth_id;

        true
    }
}

pub fn se_delete_logon_session(logon_id: &luid) -> bool {
    let mut table = LOGON_SESSIONS.lock();
    for i in 0..MAX_LOGON_SESSIONS {
        if table.sessions[i].active && table.sessions[i].authentication_id.equals(logon_id) {
            table.sessions[i].active = false;
            return true;
        }
    }
    false
}

pub fn se_lookup_logon_session(logon_id: &luid) -> Option<LogonSession> {
    let table = LOGON_SESSIONS.lock();
    for i in 0..MAX_LOGON_SESSIONS {
        if table.sessions[i].active && table.sessions[i].authentication_id.equals(logon_id) {
            return Some(table.sessions[i]);
        }
    }
    None
}

pub fn se_mark_logon_session_for_termination(logon_id: &luid) -> bool {
    se_lookup_logon_session(logon_id).is_some()
}

pub fn se_unregister_logon_session_terminated_routine() -> bool {
    true
}

pub fn se_query_logon_session_info(logon_id: &luid) -> Option<(sid, LogonType, u64, u32)> {
    let session = se_lookup_logon_session(logon_id)?;
    Some((
        session.user_sid,
        session.logon_type,
        session.logon_time,
        session.session_id,
    ))
}

pub fn se_enumerate_logon_sessions() -> Vec<luid> {
    let mut sessions = Vec::new();
    let table = LOGON_SESSIONS.lock();
    for i in 0..MAX_LOGON_SESSIONS {
        if table.sessions[i].active {
            sessions.push(table.sessions[i].authentication_id);
        }
    }
    sessions
}

fn get_system_time() -> u64 {
    crate::ke::time::get_system_time()
}

pub fn init_system_logon_session() -> luid {
    let system_sid = super::sid::sid::well_known(super::sid::WellKnownSid::LocalSystem);
    let mut logon_id = luid::new();

    se_create_logon_session(&mut logon_id, &system_sid, LogonType::Service, 0);

    logon_id
}

pub fn init() {
    init_system_logon_session();
}
