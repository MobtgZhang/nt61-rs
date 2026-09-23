//! ALPC callback mechanism
//!
//! Windows 7 ALPC supports callback functions that are invoked when:
//! - A new connection request arrives
//! - A message is received
//! - A port is disconnected
//! - An error occurs

use core::sync::atomic::{AtomicU64, Ordering};

use super::{LpcMessage, LpcMessageHeader, LpcMessageType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CallbackEvent {
    ConnectionRequest = 0,
    MessageReceived = 1,
    Disconnected = 2,
    Error = 3,
}

#[repr(C)]
pub struct CallbackContext {
    pub port_index: u32,
    pub event: CallbackEvent,
    pub message: Option<LpcMessage>,
    pub error_code: u32,
}

pub type CallbackFn = fn(ctx: &CallbackContext);

pub const MAX_CALLBACKS_PER_PORT: usize = 4;

#[repr(C)]
pub struct CallbackEntry {
    pub port_index: u32,
    pub callback: Option<CallbackFn>,
    pub user_context: u64,
    pub active: bool,
}

impl CallbackEntry {
    pub const fn empty() -> Self {
        Self {
            port_index: 0,
            callback: None,
            user_context: 0,
            active: false,
        }
    }
}

pub struct CallbackRegistry {
    pub entries: [CallbackEntry; 32],
    pub count: u32,
}

impl CallbackRegistry {
    pub const fn new() -> Self {
        Self {
            entries: [const { CallbackEntry::empty() }; 32],
            count: 0,
        }
    }
}

static CALLBACK_INVOCATIONS: AtomicU64 = AtomicU64::new(0);

pub fn register_callback(
    port_index: u32,
    callback: CallbackFn,
    user_context: u64,
    registry: &mut CallbackRegistry,
) -> Option<u32> {
    for i in 0..registry.entries.len() {
        if !registry.entries[i].active {
            registry.entries[i].port_index = port_index;
            registry.entries[i].callback = Some(callback);
            registry.entries[i].user_context = user_context;
            registry.entries[i].active = true;
            registry.count = registry.count + 1;
            return Some(i as u32);
        }
    }
    None
}

pub fn unregister_callback(callback_id: u32, registry: &mut CallbackRegistry) -> bool {
    if (callback_id as usize) >= registry.entries.len() {
        return false;
    }

    if registry.entries[callback_id as usize].active {
        registry.entries[callback_id as usize].active = false;
        registry.entries[callback_id as usize].callback = None;
        registry.count = registry.count.saturating_sub(1);
        true
    } else {
        false
    }
}

pub fn invoke_callbacks(
    port_index: u32,
    event: CallbackEvent,
    message: Option<LpcMessage>,
    error_code: u32,
    registry: &CallbackRegistry,
) {
    let ctx = CallbackContext {
        port_index,
        event,
        message,
        error_code,
    };

    for entry in &registry.entries {
        if entry.active && entry.port_index == port_index {
            if let Some(cb) = entry.callback {
                cb(&ctx);
                CALLBACK_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub fn callback_invocations() -> u64 {
    CALLBACK_INVOCATIONS.load(Ordering::Relaxed)
}
