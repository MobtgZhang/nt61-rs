//! File Locking Subsystem
//!
//! Implements Windows 7 file locking mechanisms:
//! - Byte-range locks (mandatory and advisory)
//! - Opportunistic locks (oplocks)
//! - Share access control
//!
//! ## Byte-Range Locks
//!
//! Allow processes to lock specific byte ranges within files for
//! exclusive or shared access. Windows supports both mandatory locks
//! (enforced by the system) and advisory locks (cooperative).
//!
//! ## Opportunistic Locks (Oplocks)
//!
//! Allow a client to cache file data locally while maintaining cache
//! coherency with the server. When another client accesses the file,
//! the server breaks the oplock and forces cache flush.

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LockType {
    Shared = 0,
    Exclusive = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OplockLevel {
    None = 0,
    Level1 = 1,
    Level2 = 2,
    Batch = 3,
    Filter = 4,
    Read = 5,
    ReadHandle = 6,
    ReadWrite = 7,
    ReadWriteHandle = 8,
}

#[derive(Debug, Clone)]
pub struct ByteRangeLock {
    pub file_id: u64,
    pub process_id: u32,
    pub offset: u64,
    pub length: u64,
    pub lock_type: LockType,
    pub mandatory: bool,
    pub key: u64,
}

impl ByteRangeLock {
    pub fn conflicts_with(&self, other: &ByteRangeLock) -> bool {
        if self.process_id == other.process_id {
            return false;
        }

        if !self.overlaps(other) {
            return false;
        }

        if self.lock_type == LockType::Shared && other.lock_type == LockType::Shared {
            return false;
        }

        true
    }

    pub fn overlaps(&self, other: &ByteRangeLock) -> bool {
        let self_end = self.offset.saturating_add(self.length);
        let other_end = other.offset.saturating_add(other.length);

        !(self.offset >= other_end || other.offset >= self_end)
    }

    pub fn covers(&self, offset: u64, length: u64) -> bool {
        let end = offset.saturating_add(length);
        let lock_end = self.offset.saturating_add(self.length);

        offset >= self.offset && end <= lock_end
    }
}

#[derive(Debug, Clone)]
pub struct OpportunisticLock {
    pub file_id: u64,
    pub process_id: u32,
    pub level: OplockLevel,
    pub breaking: bool,
    pub key: u64,
}

impl OpportunisticLock {
    pub fn blocks_access(&self, for_write: bool) -> bool {
        if self.breaking {
            return true; // Break in progress
        }

        match self.level {
            OplockLevel::Level1 | OplockLevel::Batch | OplockLevel::ReadWrite
            | OplockLevel::ReadWriteHandle => {
                true
            }
            OplockLevel::Level2 | OplockLevel::Read | OplockLevel::ReadHandle => {
                for_write
            }
            OplockLevel::Filter | OplockLevel::None => false,
        }
    }

    pub fn needs_break(&self, for_write: bool) -> bool {
        match self.level {
            OplockLevel::Level1 | OplockLevel::Batch => {
                true
            }
            OplockLevel::ReadWrite | OplockLevel::ReadWriteHandle => {
                true
            }
            OplockLevel::Level2 | OplockLevel::Read | OplockLevel::ReadHandle => {
                for_write
            }
            _ => false,
        }
    }
}

pub struct LockManager {
    locks: Vec<ByteRangeLock>,
    oplocks: BTreeMap<u64, OpportunisticLock>, // file_id -> oplock
    locks_granted: AtomicU64,
    locks_denied: AtomicU64,
    oplocks_granted: AtomicU64,
    oplocks_broken: AtomicU64,
}

impl LockManager {
    pub fn new() -> Self {
        Self {
            locks: Vec::new(),
            oplocks: BTreeMap::new(),
            locks_granted: AtomicU64::new(0),
            locks_denied: AtomicU64::new(0),
            oplocks_granted: AtomicU64::new(0),
            oplocks_broken: AtomicU64::new(0),
        }
    }

    pub fn acquire_lock(
        &mut self,
        file_id: u64,
        process_id: u32,
        offset: u64,
        length: u64,
        lock_type: LockType,
        mandatory: bool,
    ) -> Result<u64, ()> {
        let new_lock = ByteRangeLock {
            file_id,
            process_id,
            offset,
            length,
            lock_type,
            mandatory,
            key: self.generate_lock_key(),
        };

        for existing in &self.locks {
            if existing.file_id == file_id && existing.conflicts_with(&new_lock) {
                self.locks_denied.fetch_add(1, Ordering::Relaxed);
                return Err(());
            }
        }

        let key = new_lock.key;
        self.locks.push(new_lock);
        self.locks_granted.fetch_add(1, Ordering::Relaxed);
        Ok(key)
    }

    pub fn release_lock(&mut self, key: u64) -> Result<(), ()> {
        if let Some(pos) = self.locks.iter().position(|l| l.key == key) {
            self.locks.remove(pos);
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn is_locked(
        &self,
        file_id: u64,
        process_id: u32,
        offset: u64,
        length: u64,
        for_write: bool,
    ) -> bool {
        for lock in &self.locks {
            if lock.file_id != file_id {
                continue;
            }

            if lock.process_id == process_id {
                continue; // Same process
            }

            if !lock.covers(offset, length) {
                continue; // Doesn't cover this range
            }

            if lock.lock_type == LockType::Exclusive {
                return true; // Exclusive lock always blocks
            }

            if for_write && lock.lock_type == LockType::Shared {
                return true; // Shared lock blocks writes
            }
        }

        false
    }

    pub fn request_oplock(
        &mut self,
        file_id: u64,
        process_id: u32,
        level: OplockLevel,
    ) -> Result<u64, ()> {
        if let Some(existing) = self.oplocks.get(&file_id) {
            if level == OplockLevel::Level2 && existing.breaking {
            } else {
                return Err(()); // Can't grant oplock
            }
        }

        let oplock = OpportunisticLock {
            file_id,
            process_id,
            level,
            breaking: false,
            key: self.generate_lock_key(),
        };

        let key = oplock.key;
        self.oplocks.insert(file_id, oplock);
        self.oplocks_granted.fetch_add(1, Ordering::Relaxed);
        Ok(key)
    }

    pub fn break_oplock(&mut self, file_id: u64, for_write: bool) -> bool {
        if let Some(oplock) = self.oplocks.get_mut(&file_id) {
            if oplock.needs_break(for_write) {
                oplock.breaking = true;
                self.oplocks_broken.fetch_add(1, Ordering::Relaxed);

                let new_level = match oplock.level {
                    OplockLevel::Level1 | OplockLevel::Batch => {
                        if for_write {
                            OplockLevel::None
                        } else {
                            OplockLevel::Level2
                        }
                    }
                    OplockLevel::ReadWrite | OplockLevel::ReadWriteHandle => {
                        if for_write {
                            OplockLevel::None
                        } else {
                            OplockLevel::Read
                        }
                    }
                    _ => OplockLevel::None,
                };

                if new_level == OplockLevel::None {
                    self.oplocks.remove(&file_id);
                } else {
                    oplock.level = new_level;
                    oplock.breaking = false;
                }

                return true;
            }
        }
        false
    }

    pub fn acknowledge_oplock(&mut self, file_id: u64) {
        if let Some(oplock) = self.oplocks.get_mut(&file_id) {
            oplock.breaking = false;
        }
    }

    pub fn release_oplock(&mut self, key: u64) -> Result<(), ()> {
        let file_id = self.oplocks
            .iter()
            .find(|(_, oplock)| oplock.key == key)
            .map(|(fid, _)| *fid);

        if let Some(fid) = file_id {
            self.oplocks.remove(&fid);
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn release_process_locks(&mut self, process_id: u32) {
        self.locks.retain(|lock| lock.process_id != process_id);

        let to_remove: Vec<u64> = self.oplocks
            .iter()
            .filter(|(_, oplock)| oplock.process_id == process_id)
            .map(|(fid, _)| *fid)
            .collect();

        for fid in to_remove {
            self.oplocks.remove(&fid);
        }
    }

    pub fn release_file_locks(&mut self, file_id: u64) {
        self.locks.retain(|lock| lock.file_id != file_id);
        self.oplocks.remove(&file_id);
    }

    fn generate_lock_key(&self) -> u64 {
        static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
        NEXT_KEY.fetch_add(1, Ordering::Relaxed)
    }

    pub fn statistics(&self) -> LockStatistics {
        LockStatistics {
            locks_granted: self.locks_granted.load(Ordering::Relaxed),
            locks_denied: self.locks_denied.load(Ordering::Relaxed),
            oplocks_granted: self.oplocks_granted.load(Ordering::Relaxed),
            oplocks_broken: self.oplocks_broken.load(Ordering::Relaxed),
            active_locks: self.locks.len(),
            active_oplocks: self.oplocks.len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LockStatistics {
    pub locks_granted: u64,
    pub locks_denied: u64,
    pub oplocks_granted: u64,
    pub oplocks_broken: u64,
    pub active_locks: usize,
    pub active_oplocks: usize,
}

static LOCK_MANAGER: Spinlock<Option<LockManager>> = Spinlock::new(None);

pub fn init() {
    let mut guard = LOCK_MANAGER.lock();
    *guard = Some(LockManager::new());
}

pub fn lock_range(
    file_id: u64,
    process_id: u32,
    offset: u64,
    length: u64,
    exclusive: bool,
    mandatory: bool,
) -> Result<u64, ()> {
    let mut mgr = LOCK_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;

    let lock_type = if exclusive {
        LockType::Exclusive
    } else {
        LockType::Shared
    };

    mgr.acquire_lock(file_id, process_id, offset, length, lock_type, mandatory)
}

pub fn unlock_range(key: u64) -> Result<(), ()> {
    let mut mgr = LOCK_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    mgr.release_lock(key)
}

pub fn check_lock(
    file_id: u64,
    process_id: u32,
    offset: u64,
    length: u64,
    for_write: bool,
) -> bool {
    let mgr = LOCK_MANAGER.lock();
    if let Some(mgr) = mgr.as_ref() {
        mgr.is_locked(file_id, process_id, offset, length, for_write)
    } else {
        false
    }
}

pub fn request_oplock(
    file_id: u64,
    process_id: u32,
    level: OplockLevel,
) -> Result<u64, ()> {
    let mut mgr = LOCK_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    mgr.request_oplock(file_id, process_id, level)
}

pub fn break_oplock(file_id: u64, for_write: bool) -> bool {
    let mut mgr = LOCK_MANAGER.lock();
    if let Some(mgr) = mgr.as_mut() {
        mgr.break_oplock(file_id, for_write)
    } else {
        false
    }
}

pub fn release_oplock(key: u64) -> Result<(), ()> {
    let mut mgr = LOCK_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    mgr.release_oplock(key)
}

pub fn release_process_locks(process_id: u32) {
    let mut mgr = LOCK_MANAGER.lock();
    if let Some(mgr) = mgr.as_mut() {
        mgr.release_process_locks(process_id);
    }
}

pub fn statistics() -> Option<LockStatistics> {
    let mgr = LOCK_MANAGER.lock();
    mgr.as_ref().map(|m| m.statistics())
}
