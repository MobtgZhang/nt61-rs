//! NTFS Quota Management
//!
//! Implements NTFS disk quota tracking and enforcement.
//! Quotas limit the amount of disk space users can consume on a volume.
//!
//! ## Architecture
//!
//! - Per-user quota tracking
//! - Hard limits (enforced) and soft limits (warning)
//! - Quota exceeded events
//! - $Quota metadata file stores quota information

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaState {
    pub bits: u32,
}

impl QuotaState {
    pub const DISABLED: Self = Self { bits: 0x00000000 };
    pub const TRACKING: Self = Self { bits: 0x00000001 };
    pub const ENFORCED: Self = Self { bits: 0x00000002 };
    pub const REBUILDING: Self = Self { bits: 0x00000004 };

    pub fn is_enabled(&self) -> bool {
        self.bits != 0
    }

    pub fn is_enforced(&self) -> bool {
        (self.bits & Self::ENFORCED.bits) != 0
    }
}

/// Per-user quota entry
#[derive(Debug, Clone)]
pub struct QuotaEntry {
    pub sid: Vec<u8>,
    pub quota_limit: u64,
    pub quota_threshold: u64,
    /// Bytes used by this user

    pub quota_used: u64,
    pub exceeded: bool,
}

impl QuotaEntry {
    pub fn new(sid: Vec<u8>, limit: u64, threshold: u64) -> Self {
        Self {
            sid,
            quota_limit: limit,
            quota_threshold: threshold,
            quota_used: 0,
            exceeded: false,
        }
    }

    pub fn is_exceeded(&self) -> bool {
        self.quota_used >= self.quota_limit
    }

    pub fn is_threshold_exceeded(&self) -> bool {
        self.quota_used >= self.quota_threshold
    }

    pub fn would_exceed(&self, bytes: u64) -> bool {
        self.quota_used.saturating_add(bytes) > self.quota_limit
    }

    /// Allocate bytes to this user
    pub fn allocate(&mut self, bytes: u64) -> Result<(), ()> {
        if self.would_exceed(bytes) {
            self.exceeded = true;
            Err(())
        } else {
            self.quota_used += bytes;
            Ok(())
        }
    }

    /// Deallocate bytes from this user
    pub fn deallocate(&mut self, bytes: u64) {
        self.quota_used = self.quota_used.saturating_sub(bytes);
        if !self.is_exceeded() {
            self.exceeded = false;
        }
    }
}

pub struct QuotaManager {
    state: QuotaState,
    /// Default quota limit for new users
    default_limit: u64,
    /// Default quota threshold for new users
    default_threshold: u64,
    /// Per-user quota entries (SID hash -> entry)
    entries: BTreeMap<u64, QuotaEntry>,
    quota_exceeded_count: AtomicU64,
    threshold_exceeded_count: AtomicU64,
}

impl QuotaManager {
    pub fn new() -> Self {
        Self {
            state: QuotaState::DISABLED,
            default_limit: u64::MAX, // No limit by default
            default_threshold: u64::MAX,
            entries: BTreeMap::new(),
            quota_exceeded_count: AtomicU64::new(0),
            threshold_exceeded_count: AtomicU64::new(0),
        }
    }

    pub fn enable(&mut self, enforce: bool) {
        self.state = if enforce {
            QuotaState::ENFORCED
        } else {
            QuotaState::TRACKING
        };
    }

    pub fn disable(&mut self) {
        self.state = QuotaState::DISABLED;
    }

    pub fn set_defaults(&mut self, limit: u64, threshold: u64) {
        self.default_limit = limit;
        self.default_threshold = threshold;
    }

    /// Get or create quota entry for a user
    fn get_or_create_entry(&mut self, sid: &[u8]) -> &mut QuotaEntry {
        let sid_hash = hash_sid(sid);
        self.entries.entry(sid_hash).or_insert_with(|| {
            QuotaEntry::new(sid.to_vec(), self.default_limit, self.default_threshold)
        })
    }

    /// Set quota for a specific user
    pub fn set_user_quota(&mut self, sid: &[u8], limit: u64, threshold: u64) {
        let entry = self.get_or_create_entry(sid);
        entry.quota_limit = limit;
        entry.quota_threshold = threshold;
    }

    /// Allocate space for a user
    pub fn allocate(&mut self, sid: &[u8], bytes: u64) -> Result<(), ()> {
        if !self.state.is_enabled() {
            return Ok(()); // Quotas disabled
        }

        let is_enforced = self.state.is_enforced();
        let entry = self.get_or_create_entry(sid);

        if is_enforced {
            entry.allocate(bytes)?;
            let exceeded = entry.exceeded;
            let threshold_exceeded = entry.is_threshold_exceeded();

            if exceeded {
                self.quota_exceeded_count.fetch_add(1, Ordering::Relaxed);
            }

            if threshold_exceeded {
                self.threshold_exceeded_count.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            entry.quota_used += bytes;

            if entry.is_threshold_exceeded() {
                self.threshold_exceeded_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    /// Deallocate space for a user
    pub fn deallocate(&mut self, sid: &[u8], bytes: u64) {
        if !self.state.is_enabled() {
            return;
        }

        let sid_hash = hash_sid(sid);
        if let Some(entry) = self.entries.get_mut(&sid_hash) {
            entry.deallocate(bytes);
        }
    }

    /// Get quota information for a user
    pub fn get_quota(&self, sid: &[u8]) -> Option<QuotaEntry> {
        let sid_hash = hash_sid(sid);
        self.entries.get(&sid_hash).cloned()
    }

    pub fn list_quotas(&self) -> Vec<QuotaEntry> {
        self.entries.values().cloned().collect()
    }

    pub fn statistics(&self) -> QuotaStatistics {
        QuotaStatistics {
            state: self.state,
            total_users: self.entries.len(),
            quota_exceeded_count: self.quota_exceeded_count.load(Ordering::Relaxed),
            threshold_exceeded_count: self.threshold_exceeded_count.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuotaStatistics {
    pub state: QuotaState,
    pub total_users: usize,
    pub quota_exceeded_count: u64,
    pub threshold_exceeded_count: u64,
}

/// Hash a SID for use as a map key
fn hash_sid(sid: &[u8]) -> u64 {
    let mut hash = 0u64;
    for &byte in sid {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
    }
    hash
}

static QUOTA_MANAGERS: Spinlock<BTreeMap<u64, QuotaManager>> = Spinlock::new(BTreeMap::new());

pub fn init_volume(volume_id: u64) {
    let mut managers = QUOTA_MANAGERS.lock();
    managers.insert(volume_id, QuotaManager::new());
}

pub fn enable_quotas(volume_id: u64, enforce: bool) -> Result<(), ()> {
    let mut managers = QUOTA_MANAGERS.lock();
    let mgr = managers.get_mut(&volume_id).ok_or(())?;
    mgr.enable(enforce);
    Ok(())
}

pub fn disable_quotas(volume_id: u64) -> Result<(), ()> {
    let mut managers = QUOTA_MANAGERS.lock();
    let mgr = managers.get_mut(&volume_id).ok_or(())?;
    mgr.disable();
    Ok(())
}

pub fn set_default_quotas(volume_id: u64, limit: u64, threshold: u64) -> Result<(), ()> {
    let mut managers = QUOTA_MANAGERS.lock();
    let mgr = managers.get_mut(&volume_id).ok_or(())?;
    mgr.set_defaults(limit, threshold);
    Ok(())
}

/// Set quota for a specific user on a volume
pub fn set_user_quota(
    volume_id: u64,
    sid: &[u8],
    limit: u64,
    threshold: u64,
) -> Result<(), ()> {
    let mut managers = QUOTA_MANAGERS.lock();
    let mgr = managers.get_mut(&volume_id).ok_or(())?;
    mgr.set_user_quota(sid, limit, threshold);
    Ok(())
}

pub fn allocate_space(volume_id: u64, sid: &[u8], bytes: u64) -> Result<(), ()> {
    let mut managers = QUOTA_MANAGERS.lock();
    let mgr = managers.get_mut(&volume_id).ok_or(())?;
    mgr.allocate(sid, bytes)
}

pub fn deallocate_space(volume_id: u64, sid: &[u8], bytes: u64) {
    let mut managers = QUOTA_MANAGERS.lock();
    if let Some(mgr) = managers.get_mut(&volume_id) {
        mgr.deallocate(sid, bytes);
    }
}

/// Get quota information for a user
pub fn get_user_quota(volume_id: u64, sid: &[u8]) -> Option<QuotaEntry> {
    let managers = QUOTA_MANAGERS.lock();
    managers.get(&volume_id).and_then(|mgr| mgr.get_quota(sid))
}

pub fn list_quotas(volume_id: u64) -> Vec<QuotaEntry> {
    let managers = QUOTA_MANAGERS.lock();
    managers
        .get(&volume_id)
        .map(|mgr| mgr.list_quotas())
        .unwrap_or_default()
}

pub fn statistics(volume_id: u64) -> Option<QuotaStatistics> {
    let managers = QUOTA_MANAGERS.lock();
    managers.get(&volume_id).map(|mgr| mgr.statistics())
}
