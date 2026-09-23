//! Registry Notification System
//!
//! Implements the Windows registry change notification mechanism.
//! Supports monitoring registry keys for changes with various filter options.

extern crate alloc;
use alloc::vec::Vec;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

use super::hive::HiveError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyFilter {
    pub name: bool,
    pub attributes: bool,
    pub last_set: bool,
    pub security: bool,
    pub subtree: bool,
    pub thread_agnostic: bool,
}

impl NotifyFilter {
    pub const CHANGE_NAME: u32 = 0x00000001;
    pub const CHANGE_ATTRIBUTES: u32 = 0x00000002;
    pub const CHANGE_LAST_SET: u32 = 0x00000004;
    pub const CHANGE_SECURITY: u32 = 0x00000008;
    pub const THREAD_AGNOSTIC: u32 = 0x10000000;

    pub fn from_flags(flags: u32, watch_subtree: bool) -> Self {
        Self {
            name: (flags & Self::CHANGE_NAME) != 0,
            attributes: (flags & Self::CHANGE_ATTRIBUTES) != 0,
            last_set: (flags & Self::CHANGE_LAST_SET) != 0,
            security: (flags & Self::CHANGE_SECURITY) != 0,
            subtree: watch_subtree,
            thread_agnostic: (flags & Self::THREAD_AGNOSTIC) != 0,
        }
    }

    pub fn to_flags(&self) -> u32 {
        let mut flags = 0;
        if self.name { flags |= Self::CHANGE_NAME; }
        if self.attributes { flags |= Self::CHANGE_ATTRIBUTES; }
        if self.last_set { flags |= Self::CHANGE_LAST_SET; }
        if self.security { flags |= Self::CHANGE_SECURITY; }
        if self.thread_agnostic { flags |= Self::THREAD_AGNOSTIC; }
        flags
    }

    pub fn is_empty(&self) -> bool {
        !self.name && !self.attributes && !self.last_set && !self.security
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    KeyCreated,
    KeyDeleted,
    KeyRenamed,
    ValueSet,
    ValueDeleted,
    SecurityChanged,
    AttributeChanged,
}

impl ChangeType {
    pub fn matches_filter(&self, filter: &NotifyFilter) -> bool {
        match self {
            ChangeType::KeyCreated | ChangeType::KeyDeleted | ChangeType::KeyRenamed => {
                filter.name
            }
            ChangeType::ValueSet | ChangeType::ValueDeleted => {
                filter.last_set
            }
            ChangeType::SecurityChanged => {
                filter.security
            }
            ChangeType::AttributeChanged => {
                filter.attributes
            }
        }
    }
}

pub struct NotifyRequest {
    pub id: u32,
    pub key_offset: u32,
    pub filter: NotifyFilter,
    triggered: AtomicBool,
    status: AtomicU32,
}

impl NotifyRequest {
    pub fn new(id: u32, key_offset: u32, filter: NotifyFilter) -> Self {
        Self {
            id,
            key_offset,
            filter,
            triggered: AtomicBool::new(false),
            status: AtomicU32::new(0),
        }
    }

    pub fn is_triggered(&self) -> bool {
        self.triggered.load(Ordering::Acquire)
    }

    pub fn trigger(&self, status: u32) {
        self.triggered.store(true, Ordering::Release);
        self.status.store(status, Ordering::Release);
    }

    pub fn status(&self) -> u32 {
        self.status.load(Ordering::Acquire)
    }

    /// Reset the notification (for reuse)
    pub fn reset(&self) {
        self.triggered.store(false, Ordering::Release);
        self.status.store(0, Ordering::Release);
    }
}

pub struct NotificationManager {
    requests: Vec<Arc<NotifyRequest>>,
    next_id: AtomicU32,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
            next_id: AtomicU32::new(1),
        }
    }

    pub fn register(
        &mut self,
        key_offset: u32,
        filter: NotifyFilter,
    ) -> Result<Arc<NotifyRequest>, HiveError> {
        if filter.is_empty() {
            return Err(HiveError::InvalidPointer);
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let request = Arc::new(NotifyRequest::new(id, key_offset, filter));
        self.requests.push(Arc::clone(&request));

        Ok(request)
    }

    pub fn unregister(&mut self, id: u32) -> Result<(), HiveError> {
        let pos = self.requests
            .iter()
            .position(|req| req.id == id)
            .ok_or(HiveError::InvalidPointer)?;

        self.requests.remove(pos);
        Ok(())
    }

    pub fn notify_change(
        &self,
        key_offset: u32,
        change_type: ChangeType,
        key_path: &[u32],
    ) {
        for request in &self.requests {
            if request.is_triggered() {
                continue;
            }

            if !change_type.matches_filter(&request.filter) {
                continue;
            }

            if request.filter.subtree {
                if is_descendant(request.key_offset, key_offset, key_path) {
                    request.trigger(0); // STATUS_SUCCESS
                }
            } else {
                if request.key_offset == key_offset {
                    request.trigger(0); // STATUS_SUCCESS
                }
            }
        }
    }

    pub fn get_triggered(&self) -> Vec<Arc<NotifyRequest>> {
        self.requests
            .iter()
            .filter(|req| req.is_triggered())
            .map(Arc::clone)
            .collect()
    }

    pub fn clear_completed(&mut self) {
        self.requests.retain(|req| !req.is_triggered());
    }

    pub fn active_count(&self) -> usize {
        self.requests.len()
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}

fn is_descendant(monitored_key: u32, target_key: u32, key_path: &[u32]) -> bool {
    if monitored_key == target_key {
        return true;
    }

    key_path.contains(&monitored_key)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyDelivery {
    Synchronous,
    Apc,
    Event,
}

pub struct NotifyContext {
    pub delivery: NotifyDelivery,
    pub event_handle: Option<u64>,
    pub apc_routine: Option<u64>,
    pub apc_context: Option<u64>,
}

impl NotifyContext {
    pub fn synchronous() -> Self {
        Self {
            delivery: NotifyDelivery::Synchronous,
            event_handle: None,
            apc_routine: None,
            apc_context: None,
        }
    }

    pub fn event(handle: u64) -> Self {
        Self {
            delivery: NotifyDelivery::Event,
            event_handle: Some(handle),
            apc_routine: None,
            apc_context: None,
        }
    }

    pub fn apc(routine: u64, context: u64) -> Self {
        Self {
            delivery: NotifyDelivery::Apc,
            event_handle: None,
            apc_routine: Some(routine),
            apc_context: Some(context),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_flags() {
        let filter = NotifyFilter::from_flags(
            NotifyFilter::CHANGE_NAME | NotifyFilter::CHANGE_LAST_SET,
            true,
        );

        assert!(filter.name);
        assert!(filter.last_set);
        assert!(!filter.security);
        assert!(filter.subtree);
    }

    #[test]
    fn test_notification_lifecycle() {
        let mut manager = NotificationManager::new();

        let filter = NotifyFilter::from_flags(NotifyFilter::CHANGE_NAME, false);
        let request = manager.register(0x1000, filter).unwrap();

        assert!(!request.is_triggered());

        manager.notify_change(0x1000, ChangeType::KeyCreated, &[]);

        assert!(request.is_triggered());
    }

    #[test]
    fn test_subtree_notification() {
        let manager = NotificationManager::new();

        let filter = NotifyFilter::from_flags(NotifyFilter::CHANGE_NAME, true);
        let request = NotifyRequest::new(1, 0x1000, filter);

        let key_path = vec![0x1000, 0x2000];

        assert!(is_descendant(request.key_offset, 0x3000, &key_path));
        assert!(!is_descendant(request.key_offset, 0x4000, &[]));
    }
}
