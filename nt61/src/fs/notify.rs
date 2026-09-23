//! File System Change Notification
//!
//! Implements Windows 7 directory change notification (FindFirstChangeNotification).
//! Allows applications to monitor directories for changes:
//! - File/directory creation
//! - File/directory deletion
//! - File/directory modification
//! - File/directory renaming
//! - Attribute changes
//! - Size changes
//! - Security descriptor changes
//!
//! ## Architecture
//!
//! The notification system maintains a list of watchers for each directory.
//! When file system operations occur, the FS driver calls notify_change()
//! which propagates events to all registered watchers.

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyFilter {
    pub bits: u32,
}

impl NotifyFilter {
    pub const FILE_NAME: Self = Self { bits: 0x00000001 };
    pub const DIR_NAME: Self = Self { bits: 0x00000002 };
    pub const ATTRIBUTES: Self = Self { bits: 0x00000004 };
    pub const SIZE: Self = Self { bits: 0x00000008 };
    pub const LAST_WRITE: Self = Self { bits: 0x00000010 };
    pub const LAST_ACCESS: Self = Self { bits: 0x00000020 };
    pub const CREATION: Self = Self { bits: 0x00000040 };
    pub const SECURITY: Self = Self { bits: 0x00000100 };

    pub const ALL: Self = Self { bits: 0xFFFFFFFF };

    pub fn contains(&self, other: NotifyFilter) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub fn matches(&self, action: NotifyAction) -> bool {
        match action {
            NotifyAction::Added => self.contains(NotifyFilter::FILE_NAME),
            NotifyAction::Removed => self.contains(NotifyFilter::FILE_NAME),
            NotifyAction::Modified => self.contains(NotifyFilter::LAST_WRITE),
            NotifyAction::RenamedOldName | NotifyAction::RenamedNewName => {
                self.contains(NotifyFilter::FILE_NAME)
            }
            NotifyAction::AttributesChanged => self.contains(NotifyFilter::ATTRIBUTES),
            NotifyAction::SizeChanged => self.contains(NotifyFilter::SIZE),
            NotifyAction::SecurityChanged => self.contains(NotifyFilter::SECURITY),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NotifyAction {
    Added = 1,
    Removed = 2,
    Modified = 3,
    RenamedOldName = 4,
    RenamedNewName = 5,
    AttributesChanged = 6,
    SizeChanged = 7,
    SecurityChanged = 8,
}

#[derive(Debug, Clone)]
pub struct NotifyEvent {
    pub action: NotifyAction,
    pub file_name: Vec<u16>,
    pub timestamp: u64,
}

impl NotifyEvent {
    pub fn new(action: NotifyAction, file_name: Vec<u16>) -> Self {
        Self {
            action,
            file_name,
            timestamp: current_time(),
        }
    }
}

pub struct DirectoryWatcher {
    pub id: u64,
    pub directory_id: u64,
    pub process_id: u32,
    pub filter: NotifyFilter,
    pub watch_subtree: bool,
    pub events: Vec<NotifyEvent>,
    pub max_events: usize,
    pub overflow: bool,
}

impl DirectoryWatcher {
    pub fn new(
        id: u64,
        directory_id: u64,
        process_id: u32,
        filter: NotifyFilter,
        watch_subtree: bool,
    ) -> Self {
        Self {
            id,
            directory_id,
            process_id,
            filter,
            watch_subtree,
            events: Vec::new(),
            max_events: 1024,
            overflow: false,
        }
    }

    pub fn add_event(&mut self, event: NotifyEvent) {
        if self.events.len() >= self.max_events {
            self.events.remove(0);
            self.overflow = true;
        }
        self.events.push(event);
    }

    pub fn get_events(&mut self) -> Vec<NotifyEvent> {
        let events = self.events.clone();
        self.events.clear();
        self.overflow = false;
        events
    }

    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }
}

pub struct NotifyManager {
    watchers: BTreeMap<u64, DirectoryWatcher>,
    directory_watchers: BTreeMap<u64, Vec<u64>>,
    events_posted: AtomicU64,
    events_dropped: AtomicU64,
}

impl NotifyManager {
    pub fn new() -> Self {
        Self {
            watchers: BTreeMap::new(),
            directory_watchers: BTreeMap::new(),
            events_posted: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
        }
    }

    pub fn register_watcher(
        &mut self,
        directory_id: u64,
        process_id: u32,
        filter: NotifyFilter,
        watch_subtree: bool,
    ) -> u64 {
        let watcher_id = self.generate_watcher_id();
        let watcher = DirectoryWatcher::new(
            watcher_id,
            directory_id,
            process_id,
            filter,
            watch_subtree,
        );

        self.watchers.insert(watcher_id, watcher);

        self.directory_watchers
            .entry(directory_id)
            .or_insert_with(Vec::new)
            .push(watcher_id);

        watcher_id
    }

    pub fn unregister_watcher(&mut self, watcher_id: u64) -> Result<(), ()> {
        if let Some(watcher) = self.watchers.remove(&watcher_id) {
            if let Some(watcher_list) = self.directory_watchers.get_mut(&watcher.directory_id) {
                watcher_list.retain(|&id| id != watcher_id);
                if watcher_list.is_empty() {
                    self.directory_watchers.remove(&watcher.directory_id);
                }
            }
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn notify_change(
        &mut self,
        directory_id: u64,
        action: NotifyAction,
        file_name: &[u16],
        parent_ids: &[u64], // For subtree watching
    ) {
        self.events_posted.fetch_add(1, Ordering::Relaxed);

        let event = NotifyEvent::new(action, file_name.to_vec());

        self.notify_directory(directory_id, &event);

        for &parent_id in parent_ids {
            if let Some(watcher_ids) = self.directory_watchers.get(&parent_id) {
                for &watcher_id in watcher_ids {
                    if let Some(watcher) = self.watchers.get_mut(&watcher_id) {
                        if watcher.watch_subtree && watcher.filter.matches(action) {
                            watcher.add_event(event.clone());
                        }
                    }
                }
            }
        }
    }

    fn notify_directory(&mut self, directory_id: u64, event: &NotifyEvent) {
        if let Some(watcher_ids) = self.directory_watchers.get(&directory_id).cloned() {
            for watcher_id in watcher_ids {
                if let Some(watcher) = self.watchers.get_mut(&watcher_id) {
                    if watcher.filter.matches(event.action) {
                        watcher.add_event(event.clone());
                    }
                }
            }
        }
    }

    pub fn get_events(&mut self, watcher_id: u64) -> Option<Vec<NotifyEvent>> {
        self.watchers
            .get_mut(&watcher_id)
            .map(|w| w.get_events())
    }

    pub fn has_events(&self, watcher_id: u64) -> bool {
        self.watchers
            .get(&watcher_id)
            .map(|w| w.has_events())
            .unwrap_or(false)
    }

    pub fn unregister_process(&mut self, process_id: u32) {
        let to_remove: Vec<u64> = self.watchers
            .iter()
            .filter(|(_, w)| w.process_id == process_id)
            .map(|(&id, _)| id)
            .collect();

        for watcher_id in to_remove {
            let _ = self.unregister_watcher(watcher_id);
        }
    }

    fn generate_watcher_id(&self) -> u64 {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    }

    pub fn statistics(&self) -> NotifyStatistics {
        NotifyStatistics {
            events_posted: self.events_posted.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            active_watchers: self.watchers.len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NotifyStatistics {
    pub events_posted: u64,
    pub events_dropped: u64,
    pub active_watchers: usize,
}

static NOTIFY_MANAGER: Spinlock<Option<NotifyManager>> = Spinlock::new(None);

pub fn init() {
    let mut guard = NOTIFY_MANAGER.lock();
    *guard = Some(NotifyManager::new());
}

pub fn watch_directory(
    directory_id: u64,
    process_id: u32,
    filter: NotifyFilter,
    watch_subtree: bool,
) -> Result<u64, ()> {
    let mut mgr = NOTIFY_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    Ok(mgr.register_watcher(directory_id, process_id, filter, watch_subtree))
}

pub fn unwatch_directory(watcher_id: u64) -> Result<(), ()> {
    let mut mgr = NOTIFY_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    mgr.unregister_watcher(watcher_id)
}

pub fn notify_change(
    directory_id: u64,
    action: NotifyAction,
    file_name: &[u16],
    parent_ids: &[u64],
) {
    let mut mgr = NOTIFY_MANAGER.lock();
    if let Some(mgr) = mgr.as_mut() {
        mgr.notify_change(directory_id, action, file_name, parent_ids);
    }
}

pub fn get_events(watcher_id: u64) -> Option<Vec<NotifyEvent>> {
    let mut mgr = NOTIFY_MANAGER.lock();
    mgr.as_mut().and_then(|m| m.get_events(watcher_id))
}

pub fn has_events(watcher_id: u64) -> bool {
    let mgr = NOTIFY_MANAGER.lock();
    mgr.as_ref()
        .map(|m| m.has_events(watcher_id))
        .unwrap_or(false)
}

pub fn unwatch_process(process_id: u32) {
    let mut mgr = NOTIFY_MANAGER.lock();
    if let Some(mgr) = mgr.as_mut() {
        mgr.unregister_process(process_id);
    }
}

pub fn statistics() -> Option<NotifyStatistics> {
    let mgr = NOTIFY_MANAGER.lock();
    mgr.as_ref().map(|m| m.statistics())
}

pub fn notify_file_created(directory_id: u64, file_name: &[u16], parent_ids: &[u64]) {
    notify_change(directory_id, NotifyAction::Added, file_name, parent_ids);
}

pub fn notify_file_deleted(directory_id: u64, file_name: &[u16], parent_ids: &[u64]) {
    notify_change(directory_id, NotifyAction::Removed, file_name, parent_ids);
}

pub fn notify_file_modified(directory_id: u64, file_name: &[u16], parent_ids: &[u64]) {
    notify_change(directory_id, NotifyAction::Modified, file_name, parent_ids);
}

pub fn notify_file_renamed(
    directory_id: u64,
    old_name: &[u16],
    new_name: &[u16],
    parent_ids: &[u64],
) {
    notify_change(directory_id, NotifyAction::RenamedOldName, old_name, parent_ids);
    notify_change(directory_id, NotifyAction::RenamedNewName, new_name, parent_ids);
}

fn current_time() -> u64 {
    // TODO: Use actual timer
    0
}
