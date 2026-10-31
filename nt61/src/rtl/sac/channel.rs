//! SAC Channel Management

/// Maximum number of channels
pub const MAX_CHANNELS: usize = 16;

/// Channel ID type
pub type ChannelId = u32;

/// Channel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    Active,
    Inactive,
    Closed,
}

/// Channel information
#[derive(Debug, Clone, Copy)]
pub struct Channel {
    pub id: ChannelId,
    pub name: [u8; 32],
    pub name_len: u8,
    pub state: ChannelState,
    pub is_current: bool,
}

impl Default for Channel {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0u8; 32],
            name_len: 0,
            state: ChannelState::Inactive,
            is_current: false,
        }
    }
}

impl Channel {
    pub fn new(id: ChannelId, name: &[u8]) -> Self {
        let mut ch = Self::default();
        ch.id = id;
        let n = core::cmp::min(name.len(), 31);
        ch.name[..n].copy_from_slice(&name[..n]);
        ch.name_len = n as u8;
        ch.state = ChannelState::Active;
        ch.is_current = false;
        ch
    }

    /// Const-friendly zero constructor
    pub const fn zero() -> Self {
        Self {
            id: 0,
            name: [0u8; 32],
            name_len: 0,
            state: ChannelState::Inactive,
            is_current: false,
        }
    }
}

/// Channel manager
pub struct ChannelManager {
    pub channels: [Option<Channel>; MAX_CHANNELS],
    pub next_id: ChannelId,
    pub current_id: ChannelId,
}

impl ChannelManager {
    pub const fn new() -> Self {
        Self {
            channels: [const { None }; MAX_CHANNELS],
            next_id: 1,
            current_id: 0,
        }
    }

    pub fn create_channel(&mut self, name: &[u8]) -> Option<ChannelId> {
        // Find the first empty slot index first
        let mut empty_idx: Option<usize> = None;
        for (i, slot) in self.channels.iter().enumerate() {
            if slot.is_none() {
                empty_idx = Some(i);
                break;
            }
        }
        if let Some(idx) = empty_idx {
            let id = self.next_id;
            self.next_id += 1;
            let mut ch = Channel::new(id, name);
            // Deactivate all others then activate this one
            for c in self.channels.iter_mut().flatten() {
                c.is_current = false;
            }
            ch.is_current = true;
            self.current_id = id;
            self.channels[idx] = Some(ch);
            return Some(id);
        }
        None
    }

    pub fn delete_channel(&mut self, id: ChannelId) -> bool {
        for slot in self.channels.iter_mut() {
            if let Some(ch) = slot {
                if ch.id == id {
                    *slot = None;
                    if self.current_id == id {
                        if let Some(c) = self.channels.iter_mut().flatten().next() {
                            c.is_current = true;
                            self.current_id = c.id;
                            return true;
                        }
                    }
                    return true;
                }
            }
        }
        false
    }

    pub fn get_channel(&self, id: ChannelId) -> Option<&Channel> {
        self.channels
            .iter()
            .flatten()
            .find(|&ch| ch.id == id)
            .map(|v| v as _)
    }

    pub fn next_id(&self) -> ChannelId {
        self.next_id
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global channel manager. `ChannelManager::new` is `const`, so the
/// static starts valid without any `static mut` byte-buffer casting:
/// every access is a normal borrow of the lock-protected manager. This
/// replaces the former `static mut` storage + initialized-flag pattern
/// whose safety depended on every caller honouring an unchecked flag;
/// the lock now also serializes manager init and channel mutations.
static CHANNEL_MGR: crate::ke::sync::Spinlock<ChannelManager> =
    crate::ke::sync::Spinlock::new(ChannelManager::new());

/// create a new channel
pub fn create_channel(name: &[u8]) -> Option<ChannelId> {
    let mut mgr = CHANNEL_MGR.lock();
    mgr.create_channel(name)
}

/// Delete a channel
pub fn delete_channel(id: ChannelId) -> bool {
    let mut mgr = CHANNEL_MGR.lock();
    mgr.delete_channel(id)
}

/// Get the next available channel ID (for display purposes)
pub fn next_channel_id() -> ChannelId {
    let mgr = CHANNEL_MGR.lock();
    mgr.next_id()
}

/// Iterate over active channels by writing into a caller-supplied buffer.
/// Returns the number of channels written. If the buffer is too small,
/// only a prefix is returned.
pub fn list_channels(buf: &mut [Channel]) -> usize {
    let mgr = CHANNEL_MGR.lock();
    let mut n = 0;
    for ch in mgr.channels.iter().flatten() {
        if n < buf.len() {
            buf[n] = *ch;
            n += 1;
        }
    }
    n
}
