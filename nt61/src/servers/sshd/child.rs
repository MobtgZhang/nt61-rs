//! Child-process orchestration for sshd sessions.
//!
//! After a session reaches `SessionState::AuthAccepted`, the user
//! can request:
//!   - `exec <command>` — run a single command and return its exit code.
//!   - `shell` — start the user's login shell and pipe stdio.
//!   - `subsystem <name> <cmd>` — start a subsystem binary
//!     (OpenSSH uses this for `sftp-server.exe`).
//!
//! This module is the bring-up skeleton: it records the request
//! type and arguments, allocates pipes for stdin/stdout/stderr,
//! and provides a `mark_finished` path. The actual fork/exec
//! happens in `ps::create_process_w`.

use crate::ke::sync::Spinlock;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChildRequestKind {
    Exec,
    Shell,
    Subsystem,
}

#[derive(Debug, Clone)]
pub struct ChildRequest {
    pub kind: ChildRequestKind,
    pub command: String,
    /// For `Exec`, the parsed argv. For `Subsystem`, the binary path.
    /// For `Shell`, empty.
    pub argv: Vec<String>,
}

impl ChildRequest {
    pub fn exec(command: &str, argv: Vec<String>) -> Self {
        Self {
            kind: ChildRequestKind::Exec,
            command: String::from(command),
            argv,
        }
    }

    pub fn shell() -> Self {
        Self {
            kind: ChildRequestKind::Shell,
            command: String::new(),
            argv: Vec::new(),
        }
    }

    pub fn subsystem(name: &str, command: &str) -> Self {
        Self {
            kind: ChildRequestKind::Subsystem,
            command: String::from(command),
            argv: alloc::vec![String::from(name), String::from(command)],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ChildHandles {
    pub stdin_read: u64,
    pub stdin_write: u64,
    pub stdout_read: u64,
    pub stdout_write: u64,
    pub stderr_read: u64,
    pub stderr_write: u64,
}

impl ChildHandles {
    pub const fn empty() -> Self {
        Self {
            stdin_read: 0,
            stdin_write: 0,
            stdout_read: 0,
            stdout_write: 0,
            stderr_read: 0,
            stderr_write: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ChildRecord {
    pub pid: u32,
    pub exit_code: u32,
    pub finished: bool,
    pub handles: ChildHandles,
    pub kind: ChildRequestKind,
}

/// Per-sshd-instance record of children we've spawned. The
/// session layer appends here when a child is created and
/// updates `finished`/`exit_code` when the child reaps.
static CHILD_TABLE: Spinlock<Vec<ChildRecord>> = Spinlock::new(Vec::new());

const CHILD_TABLE_LIMIT: usize = 64;

/// Register a new child in the per-sshd table. Returns the
/// assigned slot index, or `None` if the table is full.
pub fn register_child(record: ChildRecord) -> Option<usize> {
    let mut table = CHILD_TABLE.lock();
    if table.len() >= CHILD_TABLE_LIMIT {
        return None;
    }
    table.push(record);
    Some(table.len() - 1)
}

/// Mark a previously-registered child as reaped, with the OS exit
/// code. No-op if the slot is out of range.
pub fn mark_finished(idx: usize, exit_code: u32) {
    let mut table = CHILD_TABLE.lock();
    if let Some(slot) = table.get_mut(idx) {
        slot.finished = true;
        slot.exit_code = exit_code;
    }
}

/// Read a single child's record. Returns `None` for bad indices.
pub fn child_at(idx: usize) -> Option<ChildRecord> {
    let table = CHILD_TABLE.lock();
    table.get(idx).copied()
}

/// Number of currently-registered children (for diagnostics).
pub fn child_count() -> usize {
    CHILD_TABLE.lock().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_request_round_trip() {
        let r = ChildRequest::exec("cmd.exe /c ver", alloc::vec!["cmd.exe".into(), "/c".into(), "ver".into()]);
        assert_eq!(r.kind, ChildRequestKind::Exec);
        assert_eq!(r.command, "cmd.exe /c ver");
        assert_eq!(r.argv.len(), 3);
    }

    #[test]
    fn shell_request_has_no_command() {
        let r = ChildRequest::shell();
        assert_eq!(r.kind, ChildRequestKind::Shell);
        assert!(r.command.is_empty());
    }

    #[test]
    fn subsystem_request_preserves_binary_path() {
        let r = ChildRequest::subsystem("sftp", "sftp-server.exe");
        assert_eq!(r.kind, ChildRequestKind::Subsystem);
        assert_eq!(r.argv[0], "sftp");
        assert_eq!(r.argv[1], "sftp-server.exe");
    }

    #[test]
    fn register_and_finish_child() {
        let record = ChildRecord {
            pid: 0x1000,
            exit_code: 0,
            finished: false,
            handles: ChildHandles::empty(),
            kind: ChildRequestKind::Subsystem,
        };
        let idx = register_child(record).unwrap();
        assert!(!child_at(idx).unwrap().finished);
        mark_finished(idx, 0);
        let after = child_at(idx).unwrap();
        assert!(after.finished);
        assert_eq!(after.exit_code, 0);
    }
}