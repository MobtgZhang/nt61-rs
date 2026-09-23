//! Security Audit Log Storage and Management
//!
//! Implements persistent storage, querying, and rotation of security audit events.
//! Integrates with the Windows Event Log system for Security.evtx output.
//!
//! References: Windows Event Log API, Security.evtx format

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::ke::sync::Spinlock;
use crate::rtl::eventlog::{EventRecord, EventLevel, EventChannel, write_security_event};

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
    pub user_sid: super::sid::Sid,
    pub process_id: u64,
    pub thread_id: u64,
    pub object_name: String,
    pub access_mask: u32,
    pub details: String,
}

impl AuditRecord {
    /// Create a new audit record
    pub fn new(
        event_id: u16,
        category: super::audit_policy::AuditCategory,
        success: bool,
        user_sid: super::sid::Sid,
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

    /// Write an audit record
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

        // Write to Security Event Log
        let event_record = record.to_event_record();
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

    /// Rotate the log (remove oldest entries)
    fn rotate(&mut self) {
        // Remove oldest 25% of records
        let remove_count = MAX_AUDIT_RECORDS / 4;
        self.records.drain(0..remove_count);
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
    pub fn query_by_user(
        &self,
        user_sid: &super::sid::Sid,
        limit: usize,
    ) -> Vec<AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.user_sid.equals(user_sid))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Query by object name
    pub fn query_by_object(
        &self,
        object_name: &str,
        limit: usize,
    ) -> Vec<AuditRecord> {
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

/// Write an audit record to the log
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
pub fn query_by_user(user_sid: &super::sid::Sid, limit: usize) -> Vec<AuditRecord> {
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
    // TODO: Integrate with HAL timer
    // For now, return a placeholder
    // In real implementation, this would call into the HAL's time services
    const WINDOWS_TICK: u64 = 10_000_000;
    const SECS_1601_TO_1970: u64 = 11_644_473_600;
    SECS_1601_TO_1970 * WINDOWS_TICK
}

/// Audit log encryption support (stub for future implementation)
pub mod encryption {
    /// Encrypt audit log data (placeholder)
    pub fn encrypt_record(_data: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        // TODO: Implement using crypto subsystem
        None
    }

    /// Decrypt audit log data (placeholder)
    pub fn decrypt_record(_data: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        // TODO: Implement using crypto subsystem
        None
    }

    /// Verify audit log integrity
    pub fn verify_integrity(_data: &[u8]) -> bool {
        // TODO: Implement HMAC verification
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_write() {
        init();

        let sid = super::super::sid::Sid::well_known(super::super::sid::WellKnownSid::World);
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
        init();
        clear_log();

        let sid = super::super::sid::Sid::well_known(super::super::sid::WellKnownSid::World);

        // Write some test records
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
        init();
        clear_log();

        let sid = super::super::sid::Sid::well_known(super::super::sid::WellKnownSid::World);

        // Write enough records to trigger rotation
        for i in 0..MAX_AUDIT_RECORDS + 100 {
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
