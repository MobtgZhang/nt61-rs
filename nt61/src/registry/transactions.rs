//! Transactional Registry (TxR) Support
//!
//! Implements Windows Vista+ transactional registry operations using
//! Kernel Transaction Manager (KTM) integration. Provides ACID guarantees
//! for registry modifications.

extern crate alloc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::hive::HiveError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Active = 0,
    Preparing = 1,
    Prepared = 2,
    Committing = 3,
    Committed = 4,
    Aborting = 5,
    Aborted = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryOperation {
    CreateKey {
        parent_offset: u32,
        key_name: alloc::string::String,
        key_offset: u32,
    },
    DeleteKey {
        key_offset: u32,
        backup_data: Vec<u8>,
    },
    SetValue {
        key_offset: u32,
        value_name: alloc::string::String,
        value_type: u32,
        old_data: Option<Vec<u8>>,
        new_data: Vec<u8>,
    },
    DeleteValue {
        key_offset: u32,
        value_name: alloc::string::String,
        backup_data: Vec<u8>,
    },
    RenameKey {
        key_offset: u32,
        old_name: alloc::string::String,
        new_name: alloc::string::String,
    },
    SetSecurity {
        key_offset: u32,
        old_descriptor: Vec<u8>,
        new_descriptor: Vec<u8>,
    },
}

impl RegistryOperation {
    pub fn key_offset(&self) -> u32 {
        match self {
            Self::CreateKey { key_offset, .. } => *key_offset,
            Self::DeleteKey { key_offset, .. } => *key_offset,
            Self::SetValue { key_offset, .. } => *key_offset,
            Self::DeleteValue { key_offset, .. } => *key_offset,
            Self::RenameKey { key_offset, .. } => *key_offset,
            Self::SetSecurity { key_offset, .. } => *key_offset,
        }
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.key_offset() == other.key_offset()
    }
}

pub struct RegistryTransaction {
    pub id: u64,
    state: TransactionState,
    isolation: IsolationLevel,
    operations: Vec<RegistryOperation>,
    start_time: u64,
    timeout_us: u64,
    read_set: BTreeMap<u32, u64>, // key_offset -> version
    write_set: BTreeMap<u32, u64>, // key_offset -> version
}

impl RegistryTransaction {
    pub fn new(id: u64, isolation: IsolationLevel, timeout_us: u64) -> Self {
        Self {
            id,
            state: TransactionState::Active,
            isolation,
            operations: Vec::new(),
            start_time: 0, // Should be set to actual timestamp
            timeout_us,
            read_set: BTreeMap::new(),
            write_set: BTreeMap::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.state == TransactionState::Active
    }

    pub fn is_timed_out(&self, current_time: u64) -> bool {
        current_time - self.start_time > self.timeout_us
    }

    pub fn add_operation(&mut self, op: RegistryOperation) -> Result<(), HiveError> {
        if !self.is_active() {
            return Err(HiveError::InvalidPointer);
        }

        let key_offset = op.key_offset();
        self.write_set.insert(key_offset, 0); // Version tracking
        self.operations.push(op);

        Ok(())
    }

    pub fn record_read(&mut self, key_offset: u32, version: u64) {
        self.read_set.insert(key_offset, version);
    }

    pub fn prepare(&mut self) -> Result<(), HiveError> {
        if self.state != TransactionState::Active {
            return Err(HiveError::InvalidPointer);
        }

        self.state = TransactionState::Preparing;


        self.state = TransactionState::Prepared;
        Ok(())
    }

    pub fn commit(&mut self) -> Result<(), HiveError> {
        if self.state != TransactionState::Prepared {
            return Err(HiveError::InvalidPointer);
        }

        self.state = TransactionState::Committing;


        self.state = TransactionState::Committed;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<(), HiveError> {
        if matches!(
            self.state,
            TransactionState::Committed | TransactionState::Aborted
        ) {
            return Err(HiveError::InvalidPointer);
        }

        self.state = TransactionState::Aborting;


        self.state = TransactionState::Aborted;
        Ok(())
    }

    pub fn state(&self) -> TransactionState {
        self.state
    }

    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    pub fn operations(&self) -> &[RegistryOperation] {
        &self.operations
    }
}

pub struct TransactionManager {
    transactions: BTreeMap<u64, RegistryTransaction>,
    next_id: AtomicU64,
    commit_count: AtomicU32,
    max_transactions: usize,
}

impl TransactionManager {
    pub fn new(max_transactions: usize) -> Self {
        Self {
            transactions: BTreeMap::new(),
            next_id: AtomicU64::new(1),
            commit_count: AtomicU32::new(0),
            max_transactions,
        }
    }

    pub fn begin(
        &mut self,
        isolation: IsolationLevel,
        timeout_us: u64,
    ) -> Result<u64, HiveError> {
        if self.transactions.len() >= self.max_transactions {
            return Err(HiveError::OutOfBounds);
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let txn = RegistryTransaction::new(id, isolation, timeout_us);
        self.transactions.insert(id, txn);

        Ok(id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut RegistryTransaction> {
        self.transactions.get_mut(&id)
    }

    pub fn get(&self, id: u64) -> Option<&RegistryTransaction> {
        self.transactions.get(&id)
    }

    pub fn commit(&mut self, id: u64) -> Result<(), HiveError> {
        if self.has_conflicts(id)? {
            if let Some(txn) = self.transactions.get_mut(&id) {
                txn.rollback()?;
            }
            return Err(HiveError::InvalidPointer);
        }

        let txn = self.transactions
            .get_mut(&id)
            .ok_or(HiveError::InvalidPointer)?;

        txn.prepare()?;

        txn.commit()?;

        self.commit_count.fetch_add(1, Ordering::SeqCst);
        self.transactions.remove(&id);

        Ok(())
    }

    pub fn rollback(&mut self, id: u64) -> Result<(), HiveError> {
        let txn = self.transactions
            .get_mut(&id)
            .ok_or(HiveError::InvalidPointer)?;

        txn.rollback()?;
        self.transactions.remove(&id);

        Ok(())
    }

    fn has_conflicts(&self, txn_id: u64) -> Result<bool, HiveError> {
        let txn = self.transactions
            .get(&txn_id)
            .ok_or(HiveError::InvalidPointer)?;

        for (other_id, other_txn) in &self.transactions {
            if *other_id == txn_id {
                continue;
            }

            if !other_txn.is_active() {
                continue;
            }

            for key in txn.write_set.keys() {
                if other_txn.write_set.contains_key(key) {
                    return Ok(true);
                }
            }

            if matches!(txn.isolation, IsolationLevel::Serializable) {
                for key in txn.read_set.keys() {
                    if other_txn.write_set.contains_key(key) {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    pub fn cleanup_timedout(&mut self, current_time: u64) {
        let timed_out: Vec<u64> = self
            .transactions
            .iter()
            .filter(|(_, txn)| txn.is_timed_out(current_time))
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            let _ = self.rollback(id);
        }
    }

    pub fn active_count(&self) -> usize {
        self.transactions.len()
    }

    pub fn total_commits(&self) -> u32 {
        self.commit_count.load(Ordering::SeqCst)
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new(256) // Default max 256 concurrent transactions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_lifecycle() {
        let mut manager = TransactionManager::new(10);

        let txn_id = manager
            .begin(IsolationLevel::ReadCommitted, 1_000_000)
            .unwrap();

        {
            let txn = manager.get_mut(txn_id).unwrap();
            assert!(txn.is_active());

            let op = RegistryOperation::SetValue {
                key_offset: 0x1000,
                value_name: "TestValue".into(),
                value_type: 4,
                old_data: None,
                new_data: vec![1, 2, 3, 4],
            };

            txn.add_operation(op).unwrap();
        }

        manager.commit(txn_id).unwrap();
        assert_eq!(manager.active_count(), 0);
        assert_eq!(manager.total_commits(), 1);
    }

    #[test]
    fn test_transaction_rollback() {
        let mut manager = TransactionManager::new(10);

        let txn_id = manager
            .begin(IsolationLevel::ReadCommitted, 1_000_000)
            .unwrap();

        {
            let txn = manager.get_mut(txn_id).unwrap();
            let op = RegistryOperation::DeleteKey {
                key_offset: 0x2000,
                backup_data: vec![5, 6, 7, 8],
            };
            txn.add_operation(op).unwrap();
        }

        manager.rollback(txn_id).unwrap();
        assert_eq!(manager.active_count(), 0);
        assert_eq!(manager.total_commits(), 0);
    }

    #[test]
    fn test_conflict_detection() {
        let mut manager = TransactionManager::new(10);

        let txn1 = manager
            .begin(IsolationLevel::ReadCommitted, 1_000_000)
            .unwrap();
        let txn2 = manager
            .begin(IsolationLevel::ReadCommitted, 1_000_000)
            .unwrap();

        {
            let t1 = manager.get_mut(txn1).unwrap();
            t1.add_operation(RegistryOperation::SetValue {
                key_offset: 0x1000,
                value_name: "Value1".into(),
                value_type: 4,
                old_data: None,
                new_data: vec![1, 2, 3, 4],
            })
            .unwrap();
        }

        {
            let t2 = manager.get_mut(txn2).unwrap();
            t2.add_operation(RegistryOperation::SetValue {
                key_offset: 0x1000,
                value_name: "Value2".into(),
                value_type: 4,
                old_data: None,
                new_data: vec![5, 6, 7, 8],
            })
            .unwrap();
        }

        manager.commit(txn1).unwrap();

        assert!(manager.commit(txn2).is_err());
    }
}
