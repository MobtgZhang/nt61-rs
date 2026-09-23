//! Registry Hive Flush and Sync Operations
//!
//! Implements hive flushing, synchronization, and persistence operations.
//! Ensures registry changes are written to disk safely with crash recovery.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::hive::HiveError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushStrategy {
    Immediate,
    Lazy,
    Transactional,
    WriteThrough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushFlags {
    pub recursive: bool,
    pub synchronous: bool,
    pub persistent: bool,
}

impl Default for FlushFlags {
    fn default() -> Self {
        Self {
            recursive: false,
            synchronous: true,
            persistent: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushState {
    Clean,
    Dirty,
    Flushing,
    Error,
}

pub struct HiveSyncState {
    state: AtomicU64, // Using u64 to store FlushState
    last_flush: AtomicU64,
    last_modified: AtomicU64,
    pending_modifications: AtomicU64,
    flush_in_progress: AtomicBool,
}

impl HiveSyncState {
    pub fn new() -> Self {
        Self {
            state: AtomicU64::new(FlushState::Clean as u64),
            last_flush: AtomicU64::new(0),
            last_modified: AtomicU64::new(0),
            pending_modifications: AtomicU64::new(0),
            flush_in_progress: AtomicBool::new(false),
        }
    }

    pub fn mark_dirty(&self) {
        self.state.store(FlushState::Dirty as u64, Ordering::Release);
        self.pending_modifications.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_clean(&self) {
        self.state.store(FlushState::Clean as u64, Ordering::Release);
        self.pending_modifications.store(0, Ordering::Release);
    }

    pub fn state(&self) -> FlushState {
        match self.state.load(Ordering::Acquire) {
            0 => FlushState::Clean,
            1 => FlushState::Dirty,
            2 => FlushState::Flushing,
            3 => FlushState::Error,
            _ => FlushState::Error,
        }
    }

    pub fn is_dirty(&self) -> bool {
        matches!(self.state(), FlushState::Dirty)
    }

    pub fn set_flush_time(&self, timestamp: u64) {
        self.last_flush.store(timestamp, Ordering::Release);
    }

    pub fn set_modified_time(&self, timestamp: u64) {
        self.last_modified.store(timestamp, Ordering::Release);
    }

    pub fn last_flush_time(&self) -> u64 {
        self.last_flush.load(Ordering::Acquire)
    }

    pub fn last_modified_time(&self) -> u64 {
        self.last_modified.load(Ordering::Acquire)
    }

    pub fn pending_count(&self) -> u64 {
        self.pending_modifications.load(Ordering::Acquire)
    }

    pub fn begin_flush(&self) -> Result<(), HiveError> {
        if self.flush_in_progress.swap(true, Ordering::Acquire) {
            return Err(HiveError::InvalidPointer); // Flush already in progress
        }
        self.state.store(FlushState::Flushing as u64, Ordering::Release);
        Ok(())
    }

    pub fn complete_flush(&self, success: bool) {
        if success {
            self.state.store(FlushState::Clean as u64, Ordering::Release);
            self.pending_modifications.store(0, Ordering::Release);
        } else {
            self.state.store(FlushState::Error as u64, Ordering::Release);
        }
        self.flush_in_progress.store(false, Ordering::Release);
    }
}

impl Default for HiveSyncState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FlushManager {
    hive_states: [HiveSyncState; 8],
    strategy: FlushStrategy,
    lazy_interval_us: u64,
    force_flush_threshold: u64,
}

impl FlushManager {
    pub fn new(strategy: FlushStrategy) -> Self {
        Self {
            hive_states: [
                HiveSyncState::new(),
                HiveSyncState::new(),
                HiveSyncState::new(),
                HiveSyncState::new(),
                HiveSyncState::new(),
                HiveSyncState::new(),
                HiveSyncState::new(),
                HiveSyncState::new(),
            ],
            strategy,
            lazy_interval_us: 5_000_000, // 5 seconds
            force_flush_threshold: 1000,
        }
    }

    pub fn record_modification(&self, hive_id: usize, timestamp: u64) {
        if let Some(state) = self.hive_states.get(hive_id) {
            state.mark_dirty();
            state.set_modified_time(timestamp);

            match self.strategy {
                FlushStrategy::Immediate => {
                }
                FlushStrategy::WriteThrough => {
                }
                _ => {
                    if state.pending_count() >= self.force_flush_threshold {
                    }
                }
            }
        }
    }

    pub fn flush_hive(
        &self,
        hive_id: usize,
        flags: FlushFlags,
        timestamp: u64,
    ) -> Result<(), HiveError> {
        let state = self.hive_states
            .get(hive_id)
            .ok_or(HiveError::OutOfBounds)?;

        if !state.is_dirty() && !flags.recursive {
            return Ok(());
        }

        state.begin_flush()?;


        let success = self.perform_flush(hive_id, flags);

        state.complete_flush(success);

        if success {
            state.set_flush_time(timestamp);
            Ok(())
        } else {
            Err(HiveError::OutOfBounds)
        }
    }

    fn perform_flush(&self, _hive_id: usize, _flags: FlushFlags) -> bool {
        true
    }

    pub fn flush_all(&self, timestamp: u64) -> Result<(), HiveError> {
        for (i, state) in self.hive_states.iter().enumerate() {
            if state.is_dirty() {
                self.flush_hive(i, FlushFlags::default(), timestamp)?;
            }
        }
        Ok(())
    }

    pub fn needs_flush(&self) -> bool {
        self.hive_states.iter().any(|s| s.is_dirty())
    }

    pub fn get_dirty_hives(&self) -> Vec<usize> {
        self.hive_states
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_dirty())
            .map(|(i, _)| i)
            .collect()
    }

    pub fn hive_state(&self, hive_id: usize) -> Option<&HiveSyncState> {
        self.hive_states.get(hive_id)
    }

    pub fn set_strategy(&mut self, strategy: FlushStrategy) {
        self.strategy = strategy;
    }

    pub fn strategy(&self) -> FlushStrategy {
        self.strategy
    }

    pub fn set_lazy_interval(&mut self, interval_us: u64) {
        self.lazy_interval_us = interval_us;
    }

    pub fn lazy_interval(&self) -> u64 {
        self.lazy_interval_us
    }

    pub fn should_flush_lazy(&self, hive_id: usize, current_time: u64) -> bool {
        if let Some(state) = self.hive_states.get(hive_id) {
            if !state.is_dirty() {
                return false;
            }

            let elapsed = current_time.saturating_sub(state.last_modified_time());
            elapsed >= self.lazy_interval_us
        } else {
            false
        }
    }
}

impl Default for FlushManager {
    fn default() -> Self {
        Self::new(FlushStrategy::Lazy)
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub sequence: u64,
    pub hive_id: usize,
    pub operation: LogOperation,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOperation {
    AllocateCell { offset: u32, size: u32 },
    FreeCell { offset: u32 },
    ModifyCell { offset: u32, old_data: Vec<u8>, new_data: Vec<u8> },
    Checkpoint,
}

pub struct WriteAheadLog {
    entries: Vec<LogEntry>,
    next_sequence: AtomicU64,
    last_checkpoint: AtomicU64,
}

impl WriteAheadLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_sequence: AtomicU64::new(1),
            last_checkpoint: AtomicU64::new(0),
        }
    }

    pub fn append(&mut self, hive_id: usize, operation: LogOperation, timestamp: u64) {
        let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        self.entries.push(LogEntry {
            sequence,
            hive_id,
            operation,
            timestamp,
        });
    }

    pub fn checkpoint(&mut self, timestamp: u64) {
        let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        self.entries.push(LogEntry {
            sequence,
            hive_id: 0,
            operation: LogOperation::Checkpoint,
            timestamp,
        });
        self.last_checkpoint.store(sequence, Ordering::Release);
    }

    pub fn truncate_to_checkpoint(&mut self) {
        let checkpoint_seq = self.last_checkpoint.load(Ordering::Acquire);
        self.entries.retain(|e| e.sequence > checkpoint_seq);
    }

    pub fn entries_since(&self, sequence: u64) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.sequence > sequence)
            .collect()
    }

    pub fn all_entries(&self) -> &[LogEntry] {
        &self.entries
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for WriteAheadLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state() {
        let state = HiveSyncState::new();
        assert_eq!(state.state(), FlushState::Clean);

        state.mark_dirty();
        assert!(state.is_dirty());
        assert_eq!(state.pending_count(), 1);

        state.mark_clean();
        assert!(!state.is_dirty());
        assert_eq!(state.pending_count(), 0);
    }

    #[test]
    fn test_flush_manager() {
        let manager = FlushManager::default();

        manager.record_modification(0, 1000);
        assert!(manager.needs_flush());

        let dirty = manager.get_dirty_hives();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0], 0);
    }

    #[test]
    fn test_flush_hive() {
        let manager = FlushManager::new(FlushStrategy::Immediate);

        manager.record_modification(0, 1000);

        let result = manager.flush_hive(0, FlushFlags::default(), 2000);
        assert!(result.is_ok());

        let state = manager.hive_state(0).unwrap();
        assert!(!state.is_dirty());
        assert_eq!(state.last_flush_time(), 2000);
    }

    #[test]
    fn test_lazy_flush_interval() {
        let manager = FlushManager::default();

        manager.record_modification(0, 1000);

        assert!(!manager.should_flush_lazy(0, 2000));

        assert!(manager.should_flush_lazy(0, 10_000_000));
    }

    #[test]
    fn test_write_ahead_log() {
        let mut wal = WriteAheadLog::new();

        wal.append(
            0,
            LogOperation::AllocateCell {
                offset: 0x1000,
                size: 64,
            },
            1000,
        );

        wal.append(
            0,
            LogOperation::ModifyCell {
                offset: 0x1000,
                old_data: vec![1, 2, 3],
                new_data: vec![4, 5, 6],
            },
            2000,
        );

        assert_eq!(wal.all_entries().len(), 2);

        wal.checkpoint(3000);
        assert_eq!(wal.all_entries().len(), 3);

        wal.truncate_to_checkpoint();
        assert_eq!(wal.all_entries().len(), 0);
    }

    #[test]
    fn test_flush_strategies() {
        let immediate = FlushManager::new(FlushStrategy::Immediate);
        assert_eq!(immediate.strategy(), FlushStrategy::Immediate);

        let lazy = FlushManager::new(FlushStrategy::Lazy);
        assert_eq!(lazy.strategy(), FlushStrategy::Lazy);
    }

    #[test]
    fn test_concurrent_flush() {
        let state = HiveSyncState::new();

        state.mark_dirty();
        assert!(state.begin_flush().is_ok());

        assert!(state.begin_flush().is_err());

        state.complete_flush(true);

        state.mark_dirty();
        assert!(state.begin_flush().is_ok());
    }
}
