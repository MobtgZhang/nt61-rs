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
            if slot.is_none() { empty_idx = Some(i); break; }
        }
        if let Some(idx) = empty_idx {
            let id = self.next_id;
            self.next_id += 1;
            let mut ch = Channel::new(id, name);
            // Deactivate all others then activate this one
            for s in self.channels.iter_mut() {
                if let Some(c) = s { c.is_current = false; }
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
                        for s in self.channels.iter_mut() {
                            if let Some(c) = s {
                                c.is_current = true;
                                self.current_id = c.id;
                                return true;
                            }
                        }
                    }
                    return true;
                }
            }
        }
        false
    }

    pub fn get_channel(&self, id: ChannelId) -> Option<&Channel> {
        for slot in &self.channels {
            if let Some(ch) = slot { if ch.id == id { return Some(ch); } }
        }
        None
    }

    pub fn next_id(&self) -> ChannelId { self.next_id }
}

/// Global channel manager stored in a raw byte buffer.
/// ChannelManager is not Default+Copy safe for `static`, so we hold a buffer.
static mut CHANNEL_MGR_BUF: [u8; core::mem::size_of::<ChannelManager>()] =
    [0; core::mem::size_of::<ChannelManager>()];
static mut CHANNEL_MGR_INITIALIZED: bool = false;

unsafe fn channel_mgr() -> &'static mut ChannelManager {
    if !CHANNEL_MGR_INITIALIZED {
        let ptr = core::ptr::addr_of_mut!(CHANNEL_MGR_BUF).cast::<ChannelManager>();
        core::ptr::write(ptr, ChannelManager::new());
        CHANNEL_MGR_INITIALIZED = true;
    }
    &mut *core::ptr::addr_of_mut!(CHANNEL_MGR_BUF).cast::<ChannelManager>()
}

/// Create a new channel
pub fn create_channel(name: &[u8]) -> Option<ChannelId> {
    unsafe { channel_mgr().create_channel(name) }
}

/// Delete a channel
pub fn delete_channel(id: ChannelId) -> bool {
    unsafe { channel_mgr().delete_channel(id) }
}

/// Get the next available channel ID (for display purposes)
pub fn next_channel_id() -> ChannelId {
    unsafe { channel_mgr().next_id() }
}

/// Iterate over active channels by writing into a caller-supplied buffer.
/// Returns the number of channels written. If the buffer is too small,
/// only a prefix is returned.
pub fn list_channels(buf: &mut [Channel]) -> usize {
    unsafe {
        let mgr = channel_mgr();
        let mut n = 0;
        for slot in &mgr.channels {
            if let Some(ch) = slot {
                if n < buf.len() {
                    buf[n] = ch.clone();
                    n += 1;
                }
            }
        }
        n
    }
}
