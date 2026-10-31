//! LPC (Local Procedure Call) / ALPC (Advanced Local Procedure Call)
//
//! Windows NT 6.1 uses Advanced Local Procedure Call (ALPC) for
//! inter-process communication between user-mode and kernel-mode
//! components, between system services, and between threads in
//! different sessions. Examples:
//
//!   * `\\Windows\\ApiPort` - the Win32 / CSRSS API port used by
//!     every user-mode Win32 process to talk to CSRSS.
//!   * `\\Sessions\\N\\Windows\\ApiPort` - per-session variants.

// LPC/ALPC uses NT-driver naming (LPCP_*, PORT_*, ...).
//!   * SMSS uses ALPC to talk to CSRSS, wininit, and the SCM.
//
//!     The Windows 7 ALPC implementation is a port-based message
//!     passing system:
//
//!   * A **server port** is created by a kernel component (e.g.
//!     CSRSS); it has a global name and a queue of pending
//!     connection requests.
//!   * **Client ports** connect to a server port; each client has
//!     a back-pointer to the server and a per-port message queue.
//!   * **Communication ports** are bidirectional: a connected
//!     pair (server side, client side) sends and receives
//!     messages over a shared `LpcMessage` queue.
//!   * **Unconnected** ports (a.k.a. "connection ports") accept
//!     connection requests but do not participate in message
//!     exchange directly.
//
//!     Each message has an `LpcMessageHeader` that the receiver
//!     validates before dispatching. The header includes:
//!   * `data_length` - the size of the message body.
//!   * `total_length` - the size of the body plus any attached
//!     section / handle / attribute payloads.
//!   * `message_type` - one of `LpcMessageType` (request, reply,
//!     datagram, error, ...).
//!   * `sender_pid` / `sender_tid` - identifies the sender.
//!   * `client_pid` / `client_tid` - identifies the intended
//!     recipient (zero for connection-style messages).
//
//!     This module implements a minimal but correct ALPC surface
//!     (port registry, port creation, connection, send, receive).
//!     It is **not** a full port of `ntoskrnl`'s ALPC implementation
//!     (which is the most complex part of the NT executive) but it
//!     covers the on-the-wire contracts used by SMSS, CSRSS, and the
//!     SCM, and is enough to power the smoke test in this phase.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ke::sync::{DispatcherHeader, Event, EventType, Spinlock};

/// Maximum number of ALPC ports the bootstrap registry can hold.
/// Real NT uses a hash table; 32 is plenty for the bootstrap
/// (we only need a handful: ApiPort, SbApiPort, SmApiPort, plus
/// per-session variants).
pub const MAX_PORTS: usize = 32;
/// Maximum number of in-flight messages in a port queue.
pub const MAX_PORT_MESSAGES: usize = 64;
/// Maximum length of an ALPC port name (in UTF-16 code units,
/// not including the null terminator).
pub const MAX_PORT_NAME: usize = 128;

/// LPC port types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LpcPortType {
    /// No type assigned yet.
    Unknown = 0,
    /// Server-side connection port. Accepts connect requests;
    /// each accepted request creates a CommunicationPort.
    Connection = 1,
    /// Server-side communication port. Full duplex once
    /// connected to a client communication port.
    ServerCommunication = 2,
    /// Client-side communication port.
    ClientCommunication = 3,
    /// Unconnected sendable port; can send datagrams to a
    /// server's name.
    Unconnected = 4,
}

/// LPC message types. These are the wire-format values used by
/// Windows 7 ALPC; they must remain stable because they are
/// part of the message protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LpcMessageType {
    /// Reserved; never sent.
    NewConnection = 0,
    /// Client -> server: "please connect to me".
    ConnectionRequest = 1,
    /// Server -> client: "no, I will not connect to you".
    ConnectionRefused = 2,
    /// Server -> client: "we are now connected, here is your
    /// server communication port".
    ConnectionAccepted = 3,
    /// Either side: "the other end has disconnected".
    Disconnect = 4,
    /// Either side: a real payload.
    Data = 5,
    /// A reply to a previous Data message.
    Reply = 6,
    /// No more senders / port is being torn down.
    PortClosed = 7,
    /// Datagram: connectionless message. (LPC only; ALPC uses
    /// Data for everything.)
    Datagram = 8,
    /// The last valid LPC message type; sentinels and out-of-range
    /// values are treated as a protocol error.
    MaxMessageType = 9,
}

/// LPC message header. 40 bytes on the wire, in this exact
/// layout. Windows 7 ALPC includes more fields (extended header
/// info, attributes, etc.) but the first 40 bytes are
/// sufficient to identify the message and route it to the right
/// client.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LpcMessageHeader {
    /// length of the message body, in bytes.
    pub data_length: u32,
    /// Total length on the wire (body + any attached data).
    pub total_length: u32,
    /// One of `LpcMessageType`. Sender-validated by the receiver.
    pub message_type: u32,
    /// Sender's process id.
    pub sender_pid: u64,
    /// Sender's thread id.
    pub sender_tid: u64,
    /// Client (recipient) process id; 0 for connection-style
    /// messages.
    pub client_pid: u64,
    /// Client (recipient) thread id; 0 for connection-style
    /// messages.
    pub client_tid: u64,
}

impl LpcMessageHeader {
    /// Build a new header for a `Data` or `Reply` message.
    pub const fn new(
        message_type: LpcMessageType,
        data_length: u32,
        sender_pid: u64,
        sender_tid: u64,
    ) -> Self {
        Self {
            data_length,
            total_length: data_length,
            message_type: message_type as u32,
            sender_pid,
            sender_tid,
            client_pid: 0,
            client_tid: 0,
        }
    }
}

/// A message slot. We use a fixed-size ring buffer indexed by
/// `head` and `tail`; a slot is "valid" iff its index has been
/// pushed and not yet popped.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LpcMessage {
    pub header: LpcMessageHeader,
    /// Inline payload (first 256 bytes). Messages larger than
    /// this are out of scope for the bootstrap.
    pub data: [u8; 256],
    pub data_len: u32,
}

impl LpcMessage {
    pub const fn empty() -> Self {
        Self {
            header: LpcMessageHeader {
                data_length: 0,
                total_length: 0,
                message_type: 0,
                sender_pid: 0,
                sender_tid: 0,
                client_pid: 0,
                client_tid: 0,
            },
            data: [0u8; 256],
            data_len: 0,
        }
    }
}

/// Port object. The bootstrap keeps a fixed-size pool of these;
/// each port has its own message queue.
#[repr(C)]
pub struct LpcPort {
    /// The global name of the port (UTF-16, NUL-terminated).
    pub name: [u16; MAX_PORT_NAME],
    /// length of the name in code units (excluding the NUL).
    pub name_len: usize,
    /// Port type.
    pub port_type: LpcPortType,
    /// The owning process (PID 0 for the kernel / SMSS).
    pub owner_pid: u64,
    /// For communication ports, the PID of the peer.
    pub peer_pid: u64,
    /// The other side's port slot index (0 = none).
    pub peer_index: u32,
    /// The next free / assigned port id (unique per process).
    pub port_id: u32,
    /// Number of in-flight messages.
    pub pending: u32,
    /// Head of the message queue (insertion index).
    pub head: u32,
    /// Tail of the message queue (read index).
    pub tail: u32,
    /// Whether the port is currently connected.
    pub connected: bool,
    /// Lifecycle state of the port (ALPC port object state).
    pub state: port::PortState,
    /// Creation attributes (`NtAlpcCreatePort` PORT_ATTRIBUTES). Recorded so
    /// the message-size limit and flags can be enforced on later calls.
    pub attributes: port::PortAttributes,
}

impl LpcPort {
    pub const fn empty() -> Self {
        Self {
            name: [0u16; MAX_PORT_NAME],
            name_len: 0,
            port_type: LpcPortType::Unknown,
            owner_pid: 0,
            peer_pid: 0,
            peer_index: 0,
            port_id: 0,
            pending: 0,
            head: 0,
            tail: 0,
            connected: false,
            state: port::PortState::Initializing,
            attributes: port::PortAttributes::const_default(),
        }
    }
}

/// The port registry. The kernel owns one of these; user-mode
/// code accesses it via NtAlpcCreatePort / NtAlpcConnectPort.
pub struct LpcRegistry {
    /// The static pool of ports.
    pub ports: [LpcPort; MAX_PORTS],
    /// The static pool of in-flight messages (shared; we don't
    /// have per-port pools in the bootstrap because the message
    /// pool only needs to be big enough to drain ALPC traffic
    /// during the bootstrap).
    pub messages: [[LpcMessage; MAX_PORT_MESSAGES]; MAX_PORTS],
    /// Total number of ports that have been created.
    pub count: u32,
    /// Monotonically-increasing global port id.
    pub next_port_id: u32,
}

impl LpcRegistry {
    pub const fn new() -> Self {
        Self {
            ports: [const { LpcPort::empty() }; MAX_PORTS],
            messages: [const { [const { LpcMessage::empty() }; MAX_PORT_MESSAGES] }; MAX_PORTS],
            count: 0,
            next_port_id: 1,
        }
    }
}

impl Default for LpcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

static REGISTRY: Spinlock<*mut LpcRegistry> = Spinlock::new(core::ptr::null_mut());
static CONNECT_COUNT: AtomicU64 = AtomicU64::new(0);
static SEND_COUNT: AtomicU64 = AtomicU64::new(0);
static RECV_COUNT: AtomicU64 = AtomicU64::new(0);
static TOTAL_MESSAGES: AtomicU32 = AtomicU32::new(0);

/// Notification event signaled whenever a message is enqueued onto
/// a previously empty LPC port queue. Server threads wait on this
/// event instead of polling their port queues: on NT 6.1 an ALPC
/// receive attaches a wait to the port object and the senders
/// message-delivery path completes it.
static MESSAGE_EVENT: Spinlock<Option<Event>> = Spinlock::new(None);

/// Thread-safe access to the message event header. The event is
/// created on first use so no init-order dependency exists.
fn message_event_header() -> &'static mut DispatcherHeader {
    let mut guard = MESSAGE_EVENT.lock();
    if guard.is_none() {
        *guard = Some(Event::new(EventType::Notification));
    }
    // SAFETY: the Event is stored behind a static Spinlock, so the
    // DispatcherHeader outlives the guard. The caller uses the
    // reference immediately to signal / clear / wait and never
    // stores it.
    let event = guard.as_mut().unwrap();
    let header_ptr = &mut event.header as *mut DispatcherHeader;
    drop(guard);
    unsafe { &mut *header_ptr }
}

/// Signal the message event: wake every thread waiting for LPC
/// messages. Called from send when a port queue gains its first
/// pending message.
pub fn signal_message_event() {
    let header = message_event_header();
    header.signal_state = 1;
    crate::ke::sync::wake(header, true);
}

/// Clear the message event signal state. A server drains its port
/// queues and then resets the event before parking on it, so a send
/// that raced the drain re-signals the event and no wakeup is lost.
pub fn clear_message_event() {
    message_event_header().signal_state = 0;
}

/// Wait until the message event is signaled or the timeout (in ms)
/// expires. Returns true when the event was signaled.
pub fn wait_message_event(timeout_ms: u32) -> bool {
    let header = message_event_header();
    matches!(
        crate::ke::sync::wait_single(header, timeout_ms),
        crate::ke::sync::WaitResult::Success
    )
}

/// Initialize LPC subsystem.
pub fn init() {
    let mut guard = REGISTRY.lock();
    if !(*guard).is_null() {
        return;
    }

    // // kprintln!("    LPC subsystem: initialized (max_ports={}, max_msgs={})", MAX_PORTS, MAX_PORT_MESSAGES);
    // Allocate the registry out of the non-paged pool. A `static`
    // for the registry would land in the BSS / data section of
    // the kernel image, and the UEFI PE loader is known to
    // mis-initialise large arrays in BSS. The pool is WB and
    // gets explicitly zeroed on allocation.
    let reg = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<LpcRegistry>(),
    ) as *mut LpcRegistry;
    #[cfg(test)]
    let reg = if reg.is_null() {
        static mut TEST_REGISTRY: LpcRegistry = LpcRegistry::new();
        core::ptr::addr_of_mut!(TEST_REGISTRY)
    } else {
        reg
    };
    if !reg.is_null() {
        // The pool already zeroed the user region, so the
        // `[LpcPort; MAX_PORTS]` and `[LpcMessage; MAX_PORT_MESSAGES]`
        // fields are already in their `empty()` state. We only
        // need to set the scalar fields. (We tried `*reg = new_reg`
        // earlier; the compiler emitted a non-temporal SSE store
        // for the 30 KiB aggregate, which silently fails on UC
        // memory. Field-by-field init avoids that.)
        unsafe {
            (*reg).count = 0;
            (*reg).next_port_id = 1;
        }
        *guard = reg;
    }
}

/// Look up a port by name. Returns the port's slot index, or
/// `None` if no such port exists.
pub fn find_port_by_name(name: &[u16]) -> Option<u32> {
    let reg_guard = REGISTRY.lock();
    let reg_ptr = *reg_guard;
    if reg_ptr.is_null() {
        return None;
    }
    find_port_by_name_in(unsafe { &*reg_ptr }, name)
}

/// internal helper: do the actual name scan, given a held
/// reference to the registry. Used by `create_connection_port`
/// so we don't try to re-acquire the registry lock.
fn find_port_by_name_in(reg: &LpcRegistry, name: &[u16]) -> Option<u32> {
    for i in 0..reg.count as usize {
        if reg.ports[i].name_len == name.len() {
            // Compare UTF-16 code units one by one (no NUL
            // terminator in `name`; `name_len` is the exact
            // length).
            let mut match_ = true;
            for j in 0..name.len() {
                if reg.ports[i].name[j] != name[j] {
                    match_ = false;
                    break;
                }
            }
            if match_ {
                return Some(i as u32);
            }
        }
    }
    None
}

/// Acquire the registry guard and return a `&mut LpcRegistry`
/// if it has been initialised. Returns `None` if `init()` has
/// not been called yet. Holding the returned guard prevents any
/// other CPU from racing with us.
struct RegGuard {
    _reg_guard: crate::ke::sync::SpinlockGuard<'static, *mut LpcRegistry>,
    reg: &'static mut LpcRegistry,
}

fn lock_registry() -> Option<RegGuard> {
    // The pool-backed `LpcRegistry` is allocated once during `init()` and
    // lives for the rest of the kernel's lifetime. The `loop` used to be
    // a retry-on-race placeholder but, since init() runs single-threaded
    // before SMP is up, the slot is always populated on the first
    // observation; rewrite as a single attempt so clippy's
    // `never_loop` lint stops flagging it.
    let guard = REGISTRY.lock();
    let ptr = *guard;
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the pointer is set once during init() and is never freed
    // (the pool owns the memory for the rest of the kernel's lifetime).
    let reg = unsafe { &mut *ptr };
    Some(RegGuard {
        _reg_guard: guard,
        reg,
    })
}

/// create a server-side connection port. The port is registered
/// globally; clients can connect to it by name. Returns the new
/// port's slot index, or `None` if the registry is full or a port
/// with the same name already exists.
pub fn create_connection_port(name: &[u16], owner_pid: u64) -> Option<u32> {
    let g = lock_registry()?;
    let reg = &mut *g.reg;
    if (reg.count as usize) >= MAX_PORTS {
        return None;
    }
    if find_port_by_name_in(reg, name).is_some() {
        return None;
    }
    let idx = reg.count as usize;
    let port_id = reg.next_port_id;
    reg.next_port_id = reg.next_port_id.wrapping_add(1);
    // Populate the port. We do it field-by-field to avoid the
    // aggregate-write / UC-memory issue (see ke::timer::write_ktimer
    // for the rationale).
    let p = &mut reg.ports[idx];
    p.name_len = name.len();
    for (dst, src) in p.name.iter_mut().zip(name.iter()) {
        *dst = *src;
    }
    p.port_type = LpcPortType::Connection;
    p.owner_pid = owner_pid;
    p.peer_pid = 0;
    p.peer_index = 0;
    p.port_id = port_id;
    p.pending = 0;
    p.head = 0;
    p.tail = 0;
    p.connected = false;
    p.state = port::PortState::Initializing;
    reg.count += 1;
    Some(idx as u32)
}

/// Connect a client to a server connection port. Allocates a new
/// communication port for the client and a paired communication
/// port for the server. Returns the client's port index; the
/// server's port index is written into `*server_index`.
pub fn connect_port(server_index: u32, owner_pid: u64, server_index_out: &mut u32) -> Option<u32> {
    let g = lock_registry()?;
    let reg: &mut LpcRegistry = &mut *g.reg;
    if (reg.count as usize) + 2 > MAX_PORTS {
        return None;
    }
    if server_index as usize >= reg.count as usize {
        return None;
    }
    let server_owner_pid = reg.ports[server_index as usize].owner_pid;

    // Allocate the client communication port.
    let client_idx = reg.count as usize;
    let client_port_id = reg.next_port_id;
    reg.next_port_id = reg.next_port_id.wrapping_add(1);
    {
        let cp = &mut reg.ports[client_idx];
        cp.name_len = 0;
        cp.port_type = LpcPortType::ClientCommunication;
        cp.owner_pid = owner_pid;
        cp.peer_pid = server_owner_pid;
        cp.peer_index = 0;
        cp.port_id = client_port_id;
        cp.pending = 0;
        cp.head = 0;
        cp.tail = 0;
        cp.connected = true;
        cp.state = port::PortState::Active;
    }
    reg.count += 1;

    // Allocate the server-side communication port.
    let server_comm_idx = reg.count as usize;
    let server_port_id = reg.next_port_id;
    reg.next_port_id = reg.next_port_id.wrapping_add(1);
    {
        let sp = &mut reg.ports[server_comm_idx];
        sp.name_len = 0;
        sp.port_type = LpcPortType::ServerCommunication;
        sp.owner_pid = server_owner_pid;
        sp.peer_index = client_idx as u32;
        sp.port_id = server_port_id;
        sp.pending = 0;
        sp.head = 0;
        sp.tail = 0;
        sp.connected = true;
        sp.state = port::PortState::Active;
    }
    reg.ports[client_idx].peer_index = server_comm_idx as u32;
    reg.count += 1;

    // Link the connection port to the server communication port.
    reg.ports[server_index as usize].peer_index = server_comm_idx as u32;
    reg.ports[server_index as usize].connected = true;
    reg.ports[server_index as usize].state = port::PortState::Active;

    *server_index_out = server_comm_idx as u32;
    CONNECT_COUNT.fetch_add(1, Ordering::SeqCst);
    Some(client_idx as u32)
}

/// Send a message to a port. Returns the number of bytes
/// accepted, or `None` if the port is full / disconnected.
///
/// In real ALPC, `send` is a *local* operation: the message
/// is enqueued onto the *peer's* incoming queue. The caller
/// already has a `peer_index` on its local port, so the
/// implementation just routes the message to `ports[peer_index]`.
pub fn send(port_index: u32, msg: &LpcMessage) -> Option<usize> {
    let g = lock_registry()?;
    let reg: &mut LpcRegistry = &mut *g.reg;
    if (port_index as usize) >= reg.count as usize {
        return None;
    }
    // Look up the local port's peer.

    let p = &reg.ports[port_index as usize];
    let connected: bool = p.connected;
    let peer_index: u32 = p.peer_index;
    let max_message_length: u32 = p.attributes.max_message_length;
    if !connected {
        return None;
    }
    // `NtAlpcCreatePort` records the port's message-size limit; a larger body
    // must be rejected instead of being silently truncated to the inline buffer.
    if msg.data_len > max_message_length {
        return None;
    }
    if (peer_index as usize) >= reg.count as usize {
        return None;
    }
    // read the peer's head / pending so we can drop the message
    // onto the peer's queue.

    let p = &reg.ports[peer_index as usize];
    let pending: u32 = p.pending;
    let head: u32 = p.head;
    if (pending as usize) >= MAX_PORT_MESSAGES {
        return None;
    }
    let slot = (head as usize) % MAX_PORT_MESSAGES;

    let dst = &mut reg.messages[peer_index as usize][slot];
    dst.header.data_length = msg.header.data_length;
    dst.header.total_length = msg.header.total_length;
    dst.header.message_type = msg.header.message_type;
    dst.header.sender_pid = msg.header.sender_pid;
    dst.header.sender_tid = msg.header.sender_tid;
    dst.header.client_pid = msg.header.client_pid;
    dst.header.client_tid = msg.header.client_tid;
    let copy_len = core::cmp::min(msg.data_len as usize, dst.data.len());
    for i in 0..copy_len {
        dst.data[i] = msg.data[i];
    }
    dst.data_len = copy_len as u32;

    let p = &mut reg.ports[peer_index as usize];
    p.head = head.wrapping_add(1);
    p.pending = pending + 1;
    // Wake ALPC receivers when the peer queue gained its first
    // pending message; a queue that already had messages keeps its
    // signal until the receiver resets it after draining.
    let queue_was_empty = pending == 0;
    drop(g);
    if queue_was_empty {
        signal_message_event();
    }
    Some(copy_len)
}

/// Receive a message from a port. Returns the head message (or
/// `None` if the queue is empty).
pub fn receive(port_index: u32) -> Option<LpcMessage> {
    let g = lock_registry()?;
    let reg: &mut LpcRegistry = &mut *g.reg;
    if (port_index as usize) >= reg.count as usize {
        return None;
    }

    let p = &reg.ports[port_index as usize];
    let pending: u32 = p.pending;
    let tail: u32 = p.tail;
    if pending == 0 {
        return None;
    }
    let slot = (tail as usize) % MAX_PORT_MESSAGES;
    let mut msg = LpcMessage::empty();
    let src = &reg.messages[port_index as usize][slot];
    msg.header.data_length = src.header.data_length;
    msg.header.total_length = src.header.total_length;
    msg.header.message_type = src.header.message_type;
    msg.header.sender_pid = src.header.sender_pid;
    msg.header.sender_tid = src.header.sender_tid;
    msg.header.client_pid = src.header.client_pid;
    msg.header.client_tid = src.header.client_tid;
    let copy_len = core::cmp::min(src.data_len as usize, msg.data.len());
    for i in 0..copy_len {
        msg.data[i] = src.data[i];
    }
    msg.data_len = copy_len as u32;

    let p = &mut reg.ports[port_index as usize];
    p.tail = tail.wrapping_add(1);
    p.pending = pending - 1;
    RECV_COUNT.fetch_add(1, Ordering::SeqCst);
    Some(msg)
}

/// Poll every server communication port owned by owner_pid and return
/// the first (port_index, message) that has a pending message.
pub fn receive_from_owner_server_port(owner_pid: u64) -> Option<(u32, LpcMessage)> {
    let g = lock_registry()?;
    let reg: &LpcRegistry = g.reg;
    for i in 0..reg.count as usize {
        let p = &reg.ports[i];
        if p.port_type == LpcPortType::ServerCommunication
            && p.owner_pid == owner_pid
            && p.pending > 0
        {
            let idx = i as u32;
            drop(g);
            let msg = receive(idx)?;
            return Some((idx, msg));
        }
    }
    None
}

/// Counters for the smoke test.
pub fn connect_count() -> u64 {
    CONNECT_COUNT.load(Ordering::Relaxed)
}
pub fn send_count() -> u64 {
    SEND_COUNT.load(Ordering::Relaxed)
}
pub fn recv_count() -> u64 {
    RECV_COUNT.load(Ordering::Relaxed)
}
pub fn total_messages() -> u32 {
    TOTAL_MESSAGES.load(Ordering::Relaxed)
}
pub fn port_count() -> u32 {
    let g = match lock_registry() {
        Some(g) => g,
        None => return 0,
    };
    g.reg.count
}

/// Re-export of the LPC smoke test. The full implementation
/// lives in the `smoke` submodule; this re-export keeps the
/// call site readable as `lpc::smoke_test()`.
pub fn smoke_test() -> bool {
    smoke::smoke_test()
}

pub mod smoke;

pub mod api;
pub mod async_ops;
pub mod attributes;
pub mod callback;
pub mod connection;
pub mod direct;
pub mod port;
pub mod queue;
pub mod section;
pub mod security;
pub mod tests;
pub mod waitqueue;
