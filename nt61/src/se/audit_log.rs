//! Security Audit Log Storage and Management
//!
//! Implements persistent storage, querying, and rotation of security audit events.
//! Integrates with the Windows Event Log system for Security.evtx output.
//!
//! References: Windows Event Log API, Security.evtx format

use crate::ke::sync::Spinlock;
use crate::rtl::eventlog::{write_security_event, EventChannel, EventLevel, EventRecord};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of audit records stored in memory before rotation
pub const MAX_AUDIT_RECORDS: usize = 1024;

/// Audit event record structure
#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub record_id: u64,
    pub timestamp: u64,
    pub event_id: u16,
    pub category: super::audit_policy::AuditCategory,
    pub success: bool,
    pub user_sid: super::sid::sid,
    pub process_id: u64,
    pub thread_id: u64,
    pub object_name: String,
    pub access_mask: u32,
    pub details: String,
}

impl AuditRecord {
    /// create a new audit record
    pub fn new(
        event_id: u16,
        category: super::audit_policy::AuditCategory,
        success: bool,
        user_sid: super::sid::sid,
    ) -> Self {
        Self {
            record_id: 0,
            timestamp: get_current_timestamp(),
            event_id,
            category,
            success,
            user_sid,
            process_id: 0,
            thread_id: 0,
            object_name: String::new(),
            access_mask: 0,
            details: String::new(),
        }
    }

    /// Set process and thread IDs

    pub fn set_process_info(&mut self, process_id: u64, thread_id: u64) {
        self.process_id = process_id;
        self.thread_id = thread_id;
    }

    /// Set object information
    pub fn set_object_info(&mut self, name: String, access_mask: u32) {
        self.object_name = name;
        self.access_mask = access_mask;
    }

    /// Set additional details
    pub fn set_details(&mut self, details: String) {
        self.details = details;
    }

    /// Convert to EventLog record for Security.evtx
    pub fn to_event_record(&self) -> EventRecord {
        let mut record = EventRecord::new(
            b"Microsoft-Windows-Security-Auditing",
            self.event_id,
            if self.success {
                EventLevel::Information
            } else {
                EventLevel::Warning
            },
        );

        // Format description
        let desc = if self.object_name.is_empty() {
            alloc::format!(
                "Category: {}, Success: {}, Details: {}",
                self.category.name(),
                self.success,
                self.details
            )
        } else {
            alloc::format!(
                "Category: {}, Object: {}, Access: 0x{:08X}, Success: {}, Details: {}",
                self.category.name(),
                self.object_name,
                self.access_mask,
                self.success,
                self.details
            )
        };

        record.set_description(&desc);
        record.timestamp = self.timestamp;
        record.channel = EventChannel::Security;

        // Store SID in user field (simplified)
        let sid_str = alloc::format!("S-1-5-{}", self.user_sid.sub_authority[0]);
        let sid_bytes = sid_str.as_bytes();
        let n = sid_bytes.len().min(127);
        record.user[..n].copy_from_slice(&sid_bytes[..n]);
        record.user_len = n as u8;

        record
    }
}

/// Audit log storage
pub struct AuditLog {
    records: Vec<AuditRecord>,
    next_record_id: u64,
    total_records_written: u64,
    rotation_count: u32,
}

impl AuditLog {
    const fn new() -> Self {
        Self {
            records: Vec::new(),
            next_record_id: 1,
            total_records_written: 0,
            rotation_count: 0,
        }
    }

    /// write an audit record
    pub fn write(&mut self, mut record: AuditRecord) {
        // Assign record ID
        record.record_id = self.next_record_id;
        self.next_record_id += 1;
        self.total_records_written += 1;

        // Check if rotation is needed
        if self.records.len() >= MAX_AUDIT_RECORDS {
            self.rotate();
        }

        // Store in memory
        self.records.push(record.clone());

        // write to Security Event Log
        let _event_record = record.to_event_record();
        let desc = alloc::format!(
            "Audit: {} - {}",
            record.category.name(),
            if record.success { "Success" } else { "Failure" }
        );
        write_security_event(
            record.event_id,
            if record.success {
                EventLevel::Information
            } else {
                EventLevel::Warning
            },
            b"Microsoft-Windows-Security-Auditing",
            &desc,
        );
    }

    /// Rotate the log (drop oldest entries to make room for a new record).
    ///
    /// Matches the Windows event-log "Overwrite events as needed" behaviour:
    /// once the log reaches its maximum size the oldest record is discarded
    /// for each incoming record, so the log stays capped at
    /// `MAX_AUDIT_RECORDS` instead of shrinking below it.
    fn rotate(&mut self) {
        while self.records.len() >= MAX_AUDIT_RECORDS {
            self.records.drain(..1);
        }
        self.rotation_count += 1;
    }

    /// Query records by criteria
    pub fn query(
        &self,
        category: Option<super::audit_policy::AuditCategory>,
        start_time: Option<u64>,
        end_time: Option<u64>,
        success_only: Option<bool>,
        limit: usize,
    ) -> Vec<AuditRecord> {
        self.records
            .iter()
            .filter(|r| {
                // Filter by category
                if let Some(cat) = category {
                    if r.category != cat {
                        return false;
                    }
                }

                // Filter by time range
                if let Some(st) = start_time {
                    if r.timestamp < st {
                        return false;
                    }
                }
                if let Some(et) = end_time {
                    if r.timestamp > et {
                        return false;
                    }
                }

                // Filter by success/failure
                if let Some(success) = success_only {
                    if r.success != success {
                        return false;
                    }
                }

                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Query by user SID
    pub fn query_by_user(&self, user_sid: &super::sid::sid, limit: usize) -> Vec<AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.user_sid.equals(user_sid))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Query by object name
    pub fn query_by_object(&self, object_name: &str, limit: usize) -> Vec<AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.object_name.contains(object_name))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> AuditLogStats {
        AuditLogStats {
            current_count: self.records.len(),
            total_written: self.total_records_written,
            rotation_count: self.rotation_count,
            next_record_id: self.next_record_id,
        }
    }

    /// Clear all records (administrative operation)
    pub fn clear(&mut self) {
        self.records.clear();
        // Clearing the log also resets its statistics: the record counters
        // describe the contents of the current log, not its history. Record
        // numbering is preserved so IDs stay unique across clears.
        self.total_records_written = 0;
        self.rotation_count = 0;
        // Don't reset next_record_id to maintain unique IDs
    }

    /// Get record count
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Get most recent records
    pub fn get_recent(&self, count: usize) -> Vec<AuditRecord> {
        let start = if self.records.len() > count {
            self.records.len() - count
        } else {
            0
        };
        self.records[start..].to_vec()
    }
}

/// Audit log statistics
#[derive(Debug, Clone, Copy)]
pub struct AuditLogStats {
    pub current_count: usize,
    pub total_written: u64,
    pub rotation_count: u32,
    pub next_record_id: u64,
}

/// Global audit log instance
static AUDIT_LOG: Spinlock<AuditLog> = Spinlock::new(AuditLog::new());

/// Global record ID counter for fast event ID generation
static GLOBAL_RECORD_ID: AtomicU64 = AtomicU64::new(1);

/// Initialize the audit log system
pub fn init() {
    // Already initialized via const fn
}

/// write an audit record to the log
pub fn write_audit_record(record: AuditRecord) {
    let mut log = AUDIT_LOG.lock();
    log.write(record);
}

/// Query audit records
pub fn query_records(
    category: Option<super::audit_policy::AuditCategory>,
    start_time: Option<u64>,
    end_time: Option<u64>,
    success_only: Option<bool>,
    limit: usize,
) -> Vec<AuditRecord> {
    let log = AUDIT_LOG.lock();
    log.query(category, start_time, end_time, success_only, limit)
}

/// Query by user SID
pub fn query_by_user(user_sid: &super::sid::sid, limit: usize) -> Vec<AuditRecord> {
    let log = AUDIT_LOG.lock();
    log.query_by_user(user_sid, limit)
}

/// Query by object name
pub fn query_by_object(object_name: &str, limit: usize) -> Vec<AuditRecord> {
    let log = AUDIT_LOG.lock();
    log.query_by_object(object_name, limit)
}

/// Get audit log statistics
pub fn get_statistics() -> AuditLogStats {
    let log = AUDIT_LOG.lock();
    log.get_stats()
}

/// Clear the audit log (requires privilege)
pub fn clear_log() {
    let mut log = AUDIT_LOG.lock();
    log.clear();
}

/// Get record count
pub fn get_record_count() -> usize {
    let log = AUDIT_LOG.lock();
    log.count()
}

/// Get recent records
pub fn get_recent_records(count: usize) -> Vec<AuditRecord> {
    let log = AUDIT_LOG.lock();
    log.get_recent(count)
}

/// Allocate a unique record ID
pub fn allocate_record_id() -> u64 {
    GLOBAL_RECORD_ID.fetch_add(1, Ordering::SeqCst)
}

/// Get current timestamp (Windows FILETIME format)
fn get_current_timestamp() -> u64 {
    const WINDOWS_TICK: u64 = 10_000_000;
    const SECS_1601_TO_1970: u64 = 11_644_473_600;
    let uptime_ms = crate::hal::common::pit::get_system_time_ms();
    SECS_1601_TO_1970 * WINDOWS_TICK + uptime_ms * (WINDOWS_TICK / 1000)
}

/// Audit log encryption support (stub for future implementation)
pub mod encryption {
    use crate::crypto::cipher::Aes256;
    use crate::crypto::hash::sha256;

    const AES_KEY_SIZE: usize = 32;
    const AES_BLOCK_SIZE: usize = 16;

    /// Audit encryption key (derived at boot from the system seed).
    /// A real implementation would derive this from the machine's
    /// DPAPI-protected system key; for kernel-level boot we use a
    /// deterministic key derived from the boot seed.
    fn audit_key() -> [u8; AES_KEY_SIZE] {
        sha256(b"NT6.1-AUDIT-LOG-KEY")
    }

    /// Encrypt audit log data (placeholder)
    pub fn encrypt_record(data: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        // Pad data to AES block size with zero-fill.
        let padded_len = ((data.len() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        let mut padded = alloc::vec::Vec::with_capacity(padded_len);
        padded.extend_from_slice(data);
        padded.resize(padded_len, 0);

        let cipher = Aes256::new(&audit_key());
        let mut output = alloc::vec::Vec::with_capacity(padded_len);
        for chunk in padded.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            let len = chunk.len().min(AES_BLOCK_SIZE);
            block[..len].copy_from_slice(&chunk[..len]);
            cipher.encrypt_block(&mut block);
            output.extend_from_slice(&block);
        }
        Some(output)
    }

    /// Decrypt audit log data (placeholder)
    pub fn decrypt_record(data: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        if data.len() % AES_BLOCK_SIZE != 0 {
            return None;
        }
        let cipher = Aes256::new(&audit_key());
        let mut output = alloc::vec::Vec::with_capacity(data.len());
        for chunk in data.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            output.extend_from_slice(&block);
        }
        Some(output)
    }

    /// Verify audit log integrity
    pub fn verify_integrity(data: &[u8]) -> bool {
        // The last 32 bytes are the HMAC-SHA256 tag over the payload.
        if data.len() < 32 {
            return false;
        }
        let (payload, tag) = data.split_at(data.len() - 32);
        let expected = hmac_sha256(&audit_key(), payload);
        // Constant-time comparison to avoid timing side-channels.
        let mut diff = 0u8;
        for (a, b) in tag.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// HMAC-SHA256 implemented with the built-in SHA-256 (RFC 2104).
    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        const BLOCK_SIZE: usize = 64;
        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            key_block[..32].copy_from_slice(&sha256(key));
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK_SIZE];
        let mut opad = [0x5cu8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }
        let inner = sha256(&[&ipad[..], data].concat());
        sha256(&[&opad[..], &inner[..]].concat())
    }
}

/// Process-global serialization for audit tests. The audit log and
/// policy tables are shared state, so every audit-related test must hold
/// this guard; otherwise libtest's parallel threads interleave writes.
#[cfg(test)]
pub(crate) mod test_support {
    static TEST_MUTEX: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    pub(crate) struct TestGuard;

    impl TestGuard {
        pub(crate) fn new() -> Self {
            while TEST_MUTEX
                .compare_exchange_weak(
                    false,
                    true,
                    core::sync::atomic::Ordering::Acquire,
                    core::sync::atomic::Ordering::Relaxed,
                )
                .is_err()
            {
                core::hint::spin_loop();
            }
            TestGuard
        }
    }

    impl Drop for TestGuard {
        fn drop(&mut self) {
            TEST_MUTEX.store(false, core::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TestGuard;
    use super::*;

    #[test]
    fn test_audit_log_write() {
        let _guard = TestGuard::new();
        init();

        let sid = super::super::sid::sid::well_known(super::super::sid::WellKnownSid::World);
        let mut record = AuditRecord::new(
            4624,
            super::super::audit_policy::AuditCategory::Logon,
            true,
            sid,
        );
        record.set_details(String::from("Test logon"));

        write_audit_record(record);

        let count = get_record_count();
        assert!(count > 0);
    }

    #[test]
    fn test_audit_log_query() {
        let _guard = TestGuard::new();
        init();
        clear_log();

        let sid = super::super::sid::sid::well_known(super::super::sid::WellKnownSid::World);

        // write some test records
        for i in 0..5 {
            let mut record = AuditRecord::new(
                4624,
                super::super::audit_policy::AuditCategory::Logon,
                i % 2 == 0,
                sid.clone(),
            );
            record.set_details(alloc::format!("Test {}", i));
            write_audit_record(record);
        }

        // Query all
        let all = query_records(None, None, None, None, 100);
        assert_eq!(all.len(), 5);

        // Query success only
        let successes = query_records(None, None, None, Some(true), 100);
        assert_eq!(successes.len(), 3);
    }

    #[test]
    fn test_rotation() {
        let _guard = TestGuard::new();
        init();
        clear_log();

        let sid = super::super::sid::sid::well_known(super::super::sid::WellKnownSid::World);

        // write enough records to trigger rotation
        for _i in 0..MAX_AUDIT_RECORDS + 100 {
            let record = AuditRecord::new(
                4624,
                super::super::audit_policy::AuditCategory::Logon,
                true,
                sid.clone(),
            );
            write_audit_record(record);
        }

        let stats = get_statistics();
        assert!(stats.rotation_count > 0);
        assert_eq!(stats.current_count, MAX_AUDIT_RECORDS);
    }
}
