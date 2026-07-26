//! Named-pipe server instances.
//!
//! A named-pipe server (the OpenSSH `sshd` privilege-separation
//! listener) calls `CreateNamedPipeW` to create the first instance
//! of a pipe name. Subsequent `CreateNamedPipeW` calls on the same
//! name create additional instances. Clients connect with
//! `CreateFileW("\\.\pipe\<name>")` (or via NT path).
//!
//! We don't actually need a filesystem entry — we just keep a
//! table of pipe names → slot indices. The actual byte transport
//! reuses the anonymous-pipe slot mechanism.
//!
//! Reference: MSDN "CreateNamedPipeW" / "Named Pipes".

use crate::ke::sync::Spinlock;
use crate::io::pipe;
use alloc::string::String;
use alloc::vec::Vec;

const MAX_NAMED_PIPES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeDirection {
    Inbound,
    Outbound,
    Duplex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeMode {
    ByteStream,
    Message,
}

#[derive(Debug, Clone)]
pub struct PipeInstance {
    pub slot: usize,
    pub read_id: u64,
    pub write_id: u64,
    pub name: String,
    pub direction: PipeDirection,
    pub mode: PipeMode,
    /// Number of allowed simultaneous instances. NT allows up to
    /// `PIPE_UNLIMITED_INSTANCES` (255).
    pub max_instances: u8,
    /// Whether `ConnectNamedPipe` has been issued on this server
    /// end. Until the client connects, writes from the server side
    /// will buffer (Duplex/Outbound) or be rejected (Inbound).
    pub listen_active: bool,
}

struct NamedPipeEntry {
    name: String,
    instances: Vec<PipeInstance>,
    /// Maximum number of instances allowed for this name.
    max_instances: u8,
}

static NAMED_PIPES: Spinlock<Vec<NamedPipeEntry>> = Spinlock::new(Vec::new());

/// Create the first instance of a named pipe. Returns
/// `Some((read_id, write_id))` on success, `None` if the table is
/// full or `max_instances` was reached.
///
/// `name` is the bare name (no leading `\\.\pipe\`). Direction
/// `Duplex` matches the Windows default.
pub fn create_named_pipe(
    name: &str,
    direction: PipeDirection,
    mode: PipeMode,
    max_instances: u8,
) -> Option<(u64, u64)> {
    let max_instances = if max_instances == 0 { 1 } else { max_instances };
    let mut table = NAMED_PIPES.lock();
    if table.len() >= MAX_NAMED_PIPES && !table.iter().any(|e| e.name == name) {
        return None;
    }
    let entry = if let Some(idx) = table.iter().position(|e| e.name == name) {
        if table[idx].instances.len() as u8 >= table[idx].max_instances {
            return None;
        }
        &mut table[idx]
    } else {
        table.push(NamedPipeEntry {
            name: String::from(name),
            instances: Vec::new(),
            max_instances,
        });
        table.last_mut().unwrap()
    };
    let (read_id, write_id) = pipe::create_anonymous()?;
    let slot = pipe::slot_for_id(read_id)?.0;
    let inst = PipeInstance {
        slot,
        read_id,
        write_id,
        name: String::from(name),
        direction,
        mode,
        max_instances,
        listen_active: false,
    };
    entry.instances.push(inst);
    Some((read_id, write_id))
}

/// Look up the next free instance of a named pipe. OpenSSH uses
/// this when a client connects — it picks an instance and reads
/// from it as the server end.
pub fn find_instance(name: &str) -> Option<PipeInstance> {
    let table = NAMED_PIPES.lock();
    table
        .iter()
        .find(|e| e.name == name)
        .and_then(|e| e.instances.first().cloned())
}

/// Number of registered pipe names (for diagnostics).
pub fn count_names() -> usize {
    let table = NAMED_PIPES.lock();
    table.len()
}

/// Drop all instances of a named pipe. The server uses this when
/// shutting down (e.g. `CloseHandle` on the last instance).
pub fn close_pipe(name: &str) -> bool {
    let mut table = NAMED_PIPES.lock();
    let pos = match table.iter().position(|e| e.name == name) {
        Some(p) => p,
        None => return false,
    };
    let entry = table.remove(pos);
    for inst in entry.instances.iter() {
        // Close both ends of the underlying anonymous pipe.
        pipe::close_end(inst.slot, true);
        pipe::close_end(inst.slot, false);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_lookup_named_pipe() {
        let _ = create_named_pipe("test_pipe_a", PipeDirection::Duplex, PipeMode::ByteStream, 1);
        let inst = find_instance("test_pipe_a");
        assert!(inst.is_some(), "newly-created named pipe must be visible");
        let inst = inst.unwrap();
        assert_eq!(inst.direction, PipeDirection::Duplex);
        assert_eq!(inst.mode, PipeMode::ByteStream);
        // Cleanup.
        close_pipe("test_pipe_a");
    }

    #[test]
    fn close_pipe_removes_entry() {
        let _ = create_named_pipe("test_pipe_b", PipeDirection::Inbound, PipeMode::Message, 1);
        assert!(close_pipe("test_pipe_b"));
        assert!(find_instance("test_pipe_b").is_none());
    }

    #[test]
    fn respects_max_instances() {
        let _ = create_named_pipe("test_pipe_c", PipeDirection::Duplex, PipeMode::ByteStream, 1);
        let second = create_named_pipe("test_pipe_c", PipeDirection::Duplex, PipeMode::ByteStream, 1);
        assert!(second.is_none(), "second instance beyond max=1 must fail");
        // Cleanup.
        close_pipe("test_pipe_c");
    }
}