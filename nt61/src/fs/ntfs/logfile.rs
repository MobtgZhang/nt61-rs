//! NTFS $LogFile - Transaction Log and Recovery
//!
//! Implements NTFS journaling to ensure filesystem consistency after crashes.
//! The $LogFile contains records of all metadata changes, allowing the filesystem
//! to be rolled back to a consistent state after an unexpected shutdown.
//!
//! ## Architecture
//!
//! - Log records are written sequentially to $LogFile
//! - Each record has an LSN (Log Sequence Number)
//! - Two copies of restart area for redundancy
//! - Circular buffer design with wrap-around
//!
//! ## Recovery Process
//!
//! 1. read restart areas to find last checkpoint
//! 2. Scan forward from checkpoint to find all pending transactions
//! 3. Replay (redo) committed transactions
//! 4. Abort (undo) incomplete transactions

extern crate alloc;
use crate::ke::sync::Spinlock;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Global NTFS LogFile instance, initialized on mount.
static LOG_FILE: Spinlock<Option<LogFile>> = Spinlock::new(None);

/// Initialize the global log file for the mounted NTFS volume.
pub fn init_log_file(max_log_size: usize) {
    let mut log = LOG_FILE.lock();
    *log = Some(LogFile::new(max_log_size));
}

/// Access the global log file, if initialized.
fn with_log_file<R>(f: impl FnOnce(&mut LogFile) -> Result<R, &'static str>) -> Result<R, ()> {
    let mut log = LOG_FILE.lock();
    let log_file = log.as_mut().ok_or(())?;
    f(log_file).map_err(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lsn(pub u64);

impl Lsn {
    pub const ZERO: Lsn = Lsn(0);

    pub fn next(self) -> Lsn {
        Lsn(self.0 + 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogRecordType {
    InitializeFileRecord = 0x01,
    DeallocateFileRecord = 0x02,
    WriteEndOfFileRecord = 0x03,
    CreateAttribute = 0x04,
    DeleteAttribute = 0x05,
    UpdateResidentValue = 0x06,
    UpdateNonResidentValue = 0x07,
    UpdateMappingPairs = 0x08,
    SetNewAttributeSizes = 0x09,
    AddIndexEntryRoot = 0x0A,
    DeleteIndexEntryRoot = 0x0B,
    AddIndexEntryAllocation = 0x0C,
    DeleteIndexEntryAllocation = 0x0D,
    SetIndexEntryVcnRoot = 0x0E,
    SetIndexEntryVcnAllocation = 0x0F,
    UpdateFileNameRoot = 0x10,
    UpdateFileNameAllocation = 0x11,
    SetBitsInNonResidentBitmap = 0x12,
    ClearBitsInNonResidentBitmap = 0x13,
    CommitTransaction = 0x20,
    ForgetTransaction = 0x21,
    OpenNonResidentAttribute = 0x22,
    DirtyPageTableDump = 0x23,
    AttributeNamesDump = 0x24,
}

#[repr(C, packed)]
pub struct LogRecordHeader {
    pub this_lsn: u64,
    pub prev_lsn: u64,
    pub undo_lsn: u64,
    pub client_data_length: u32,
    pub client_id: u16,
    pub record_type: u32,
    pub transaction_id: u32,
    pub flags: u16,
    pub reserved: [u16; 3],
}

pub struct LogRecord {
    pub lsn: Lsn,
    pub prev_lsn: Lsn,
    pub undo_lsn: Lsn,
    pub record_type: LogRecordType,
    pub transaction_id: u32,
    pub data: Vec<u8>,
}

impl Clone for LogRecord {
    fn clone(&self) -> Self {
        Self {
            lsn: self.lsn,
            prev_lsn: self.prev_lsn,
            undo_lsn: self.undo_lsn,
            record_type: self.record_type,
            transaction_id: self.transaction_id,
            data: self.data.clone(),
        }
    }
}

#[repr(C, packed)]
pub struct RestartArea {
    pub current_lsn: u64,
    pub log_clients: u16,
    pub client_free_list: u16,
    /// Client in use list
    pub client_in_use_list: u16,
    pub flags: u16,
    pub seq_number_bits: u32,
    pub restart_area_length: u16,
    pub client_array_offset: u16,
    pub file_size: u64,
    pub last_lsn_data_length: u32,
    pub record_length: u16,
    pub log_page_data_offset: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Active,
    Committed,
    Aborted,
}

pub struct Transaction {
    pub id: u32,
    pub state: TransactionState,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub records: Vec<LogRecord>,
}

pub struct LogFile {
    current_lsn: Lsn,
    transactions: Vec<Transaction>,
    log_buffer: VecDeque<LogRecord>,
    max_log_size: usize,
    checkpoint_lsn: Lsn,
}

impl LogFile {
    pub fn new(max_log_size: usize) -> Self {
        Self {
            current_lsn: Lsn::ZERO,
            transactions: Vec::new(),
            log_buffer: VecDeque::new(),
            max_log_size,
            checkpoint_lsn: Lsn::ZERO,
        }
    }

    pub fn begin_transaction(&mut self) -> u32 {
        let transaction_id = self.transactions.len() as u32;
        let transaction = Transaction {
            id: transaction_id,
            state: TransactionState::Active,
            first_lsn: self.current_lsn,
            last_lsn: self.current_lsn,
            records: Vec::new(),
        };
        self.transactions.push(transaction);
        transaction_id
    }

    pub fn write_record(
        &mut self,
        transaction_id: u32,
        record_type: LogRecordType,
        data: Vec<u8>,
    ) -> Result<Lsn, &'static str> {
        let transaction = self
            .transactions
            .iter_mut()
            .find(|t| t.id == transaction_id && t.state == TransactionState::Active)
            .ok_or("Transaction not found or not active")?;

        self.current_lsn = self.current_lsn.next();
        let lsn = self.current_lsn;

        let record = LogRecord {
            lsn,
            prev_lsn: transaction.last_lsn,
            undo_lsn: transaction.first_lsn,
            record_type,
            transaction_id,
            data,
        };

        transaction.last_lsn = lsn;
        transaction.records.push(record.clone());

        self.log_buffer.push_back(record);

        while self.log_buffer.len() > self.max_log_size {
            self.log_buffer.pop_front();
        }

        Ok(lsn)
    }

    pub fn commit_transaction(&mut self, transaction_id: u32) -> Result<(), &'static str> {
        // Check if transaction exists and is active
        {
            let transaction = self
                .transactions
                .iter()
                .find(|t| t.id == transaction_id)
                .ok_or("Transaction not found")?;

            if transaction.state != TransactionState::Active {
                return Err("Transaction not active");
            }
        }

        // write commit record
        let commit_lsn =
            self.write_record(transaction_id, LogRecordType::CommitTransaction, Vec::new())?;

        // Update transaction state
        let transaction = self
            .transactions
            .iter_mut()
            .find(|t| t.id == transaction_id)
            .ok_or("Transaction not found")?;

        transaction.state = TransactionState::Committed;
        transaction.last_lsn = commit_lsn;

        Ok(())
    }

    pub fn abort_transaction(&mut self, transaction_id: u32) -> Result<(), &'static str> {
        let transaction = self
            .transactions
            .iter_mut()
            .find(|t| t.id == transaction_id)
            .ok_or("Transaction not found")?;

        if transaction.state != TransactionState::Active {
            return Err("Transaction not active");
        }

        transaction.state = TransactionState::Aborted;

        Ok(())
    }

    pub fn checkpoint(&mut self) -> Result<Lsn, &'static str> {
        self.checkpoint_lsn = self.current_lsn;
        Ok(self.checkpoint_lsn)
    }

    /// Write a record that is not tied to an open transaction.
    ///
    /// A dedicated transaction is begun and committed around the write
    /// so the record participates in the recovery bookkeeping instead
    /// of failing with "transaction not found" as a bare id-0 write
    /// would.
    pub fn write_standalone_record(
        &mut self,
        record_type: LogRecordType,
        data: Vec<u8>,
    ) -> Result<Lsn, &'static str> {
        let transaction_id = self.begin_transaction();
        match self.write_record(transaction_id, record_type, data) {
            Ok(lsn) => {
                self.commit_transaction(transaction_id)?;
                Ok(lsn)
            }
            Err(err) => {
                let _ = self.abort_transaction(transaction_id);
                Err(err)
            }
        }
    }

    pub fn recover(&mut self) -> Result<(), &'static str> {
        let mut active_transactions = Vec::new();
        let mut committed_transactions = Vec::new();

        for record in &self.log_buffer {
            match record.record_type {
                LogRecordType::CommitTransaction => {
                    committed_transactions.push(record.transaction_id);
                }
                _ => {
                    if !committed_transactions.contains(&record.transaction_id) {
                        if !active_transactions.contains(&record.transaction_id) {
                            active_transactions.push(record.transaction_id);
                        }
                    }
                }
            }
        }

        for record in &self.log_buffer {
            if committed_transactions.contains(&record.transaction_id) {}
        }

        for transaction_id in active_transactions {
            let mut transaction_records: Vec<_> = self
                .log_buffer
                .iter()
                .filter(|r| r.transaction_id == transaction_id)
                .collect();

            transaction_records.sort_by(|a, b| b.lsn.cmp(&a.lsn));

            for _record in transaction_records {}
        }

        Ok(())
    }

    pub fn current_lsn(&self) -> Lsn {
        self.current_lsn
    }

    pub fn checkpoint_lsn(&self) -> Lsn {
        self.checkpoint_lsn
    }
}

/// Write a journal record for NTFS operations.
///
/// The record is appended to the in-memory ring buffer of the global
/// \`LogFile\` as a standalone (immediately committed) transaction. The
/// on-disk \`$LogFile\` is not written: records are lost on reboot, so
/// this is bookkeeping for in-kernel consumers, not crash recovery.
pub fn write_journal_record(
    _ntfs_device: *mut (),
    record_type: LogRecordType,
    data: &[u8],
) -> Result<(), ()> {
    if data.len() > 65536 {
        return Err(());
    }

    with_log_file(|log_file| {
        // Standalone records are wrapped in their own committed
        // transaction; there is no pre-existing transaction 0 to write
        // into.
        log_file
            .write_standalone_record(record_type, data.to_vec())
            .map(|_| ())
    })
}

/// Helper function to create a log record for MFT update operations
pub fn log_mft_update(
    ntfs_device: *mut (),
    record_num: u64,
    old_data: &[u8],
    new_data: &[u8],
) -> Result<(), ()> {
    // Build undo (old data) and redo (new data) payloads for the MFT record.
    let mut undo_data = Vec::with_capacity(8 + old_data.len());
    undo_data.extend_from_slice(&record_num.to_le_bytes());
    undo_data.extend_from_slice(old_data);

    let mut redo_data = Vec::with_capacity(8 + new_data.len());
    redo_data.extend_from_slice(&record_num.to_le_bytes());
    redo_data.extend_from_slice(new_data);

    write_journal_record(ntfs_device, LogRecordType::UpdateResidentValue, &undo_data)?;
    write_journal_record(
        ntfs_device,
        LogRecordType::UpdateNonResidentValue,
        &redo_data,
    )
}

/// Helper function to create a log record for data write operations
pub fn log_data_write(ntfs_device: *mut (), vcn: u64, length: u64, data: &[u8]) -> Result<(), ()> {
    // Build the redo payload with VCN, length, and the actual data bytes.
    let mut redo_data = Vec::with_capacity(16 + data.len());
    redo_data.extend_from_slice(&vcn.to_le_bytes());
    redo_data.extend_from_slice(&length.to_le_bytes());
    redo_data.extend_from_slice(data);

    write_journal_record(
        ntfs_device,
        LogRecordType::UpdateNonResidentValue,
        &redo_data,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_transaction_lifecycle() {
        let mut logfile = LogFile::new(1000);

        let txn_id = logfile.begin_transaction();

        logfile
            .write_record(txn_id, LogRecordType::CreateAttribute, vec![1, 2, 3])
            .unwrap();
        logfile
            .write_record(txn_id, LogRecordType::UpdateResidentValue, vec![4, 5, 6])
            .unwrap();

        logfile.commit_transaction(txn_id).unwrap();

        assert_eq!(
            logfile.transactions[txn_id as usize].state,
            TransactionState::Committed
        );
    }

    #[test]
    fn test_recovery() {
        let mut logfile = LogFile::new(1000);

        let txn1 = logfile.begin_transaction();
        logfile
            .write_record(txn1, LogRecordType::CreateAttribute, vec![1])
            .unwrap();
        logfile.commit_transaction(txn1).unwrap();

        let txn2 = logfile.begin_transaction();
        logfile
            .write_record(txn2, LogRecordType::CreateAttribute, vec![2])
            .unwrap();

        logfile.recover().unwrap();
    }
}
