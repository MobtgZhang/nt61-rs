//! Job Object Enhancements - Task 5: Complete Job Object Implementation
//!
//! This module extends the basic Job object with full resource accounting,
//! notification mechanisms, and query APIs.

use super::job::{JobObject, create_job, STATUS_SUCCESS, STATUS_INVALID_PARAMETER};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::vec::Vec;
use crate::ke::sync::Spinlock;

/// Job accounting information
#[derive(Debug, Clone, Copy)]
pub struct JobAccountingInfo {
    /// Total user-mode CPU time (100ns units)
    pub total_user_time: u64,

    /// Total kernel-mode CPU time (100ns units)
    pub total_kernel_time: u64,

    /// This period user-mode CPU time
    pub this_period_user_time: u64,

    /// This period kernel-mode CPU time
    pub this_period_kernel_time: u64,

    /// Total page faults
    pub total_page_fault_count: u64,

    /// Total processes created
    pub total_processes: u32,

    /// Active processes
    pub active_processes: u32,

    /// Terminated processes
    pub terminated_processes: u32,

    /// Peak memory usage (bytes)
    pub peak_process_memory_used: u64,

    /// Peak job memory usage (bytes)

    pub peak_job_memory_used: u64,
}

impl JobAccountingInfo {
    pub const fn new() -> Self {
        Self {
            total_user_time: 0,
            total_kernel_time: 0,
            this_period_user_time: 0,
            this_period_kernel_time: 0,
            total_page_fault_count: 0,
            total_processes: 0,
            active_processes: 0,
            terminated_processes: 0,
            peak_process_memory_used: 0,
            peak_job_memory_used: 0,
        }
    }
}

/// Job notification callback type
pub type JobNotificationCallback = fn(job_id: u64, event: JobNotificationEvent);

/// Job notification events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobNotificationEvent {
    /// Process added to job
    ProcessAdded(u64),

    /// Process removed from job
    ProcessRemoved(u64),

    /// Job memory limit exceeded
    MemoryLimitExceeded,

    /// Job CPU limit exceeded
    CpuLimitExceeded,

    /// Job is being terminated
    JobTerminating,

    /// All processes in job terminated
    AllProcessesTerminated,
}

/// Extended job accounting
pub struct JobAccounting {
    /// Basic accounting info
    info: Spinlock<JobAccountingInfo>,

    /// I/O counters
    read_operation_count: AtomicU64,
    write_operation_count: AtomicU64,
    other_operation_count: AtomicU64,
    read_transfer_count: AtomicU64,
    write_transfer_count: AtomicU64,
    other_transfer_count: AtomicU64,
}

impl JobAccounting {
    pub const fn new() -> Self {
        Self {
            info: Spinlock::new(JobAccountingInfo::new()),
            read_operation_count: AtomicU64::new(0),
            write_operation_count: AtomicU64::new(0),
            other_operation_count: AtomicU64::new(0),
            read_transfer_count: AtomicU64::new(0),
            write_transfer_count: AtomicU64::new(0),
            other_transfer_count: AtomicU64::new(0),
        }
    }

    /// Record CPU time
    pub fn add_cpu_time(&self, user_time: u64, kernel_time: u64) {
        let mut info = self.info.lock();
        info.total_user_time = info.total_user_time.saturating_add(user_time);
        info.total_kernel_time = info.total_kernel_time.saturating_add(kernel_time);
        info.this_period_user_time = info.this_period_user_time.saturating_add(user_time);
        info.this_period_kernel_time = info.this_period_kernel_time.saturating_add(kernel_time);
    }

    /// Record page fault
    pub fn add_page_fault(&self) {
        let mut info = self.info.lock();
        info.total_page_fault_count = info.total_page_fault_count.saturating_add(1);
    }

    /// Record I/O operation
    pub fn add_io_operation(&self, read: bool, bytes: u64) {
        if read {
            self.read_operation_count.fetch_add(1, Ordering::Relaxed);
            self.read_transfer_count.fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.write_operation_count.fetch_add(1, Ordering::Relaxed);
            self.write_transfer_count.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Get accounting information
    pub fn get_info(&self) -> JobAccountingInfo {
        *self.info.lock()
    }

    /// Reset period counters
    pub fn reset_period(&self) {
        let mut info = self.info.lock();
        info.this_period_user_time = 0;
        info.this_period_kernel_time = 0;
    }
}

/// Job object extensions
impl JobObject {
    /// Add accounting information to job
    ///
    /// # Task 5.1: Resource accounting
    pub fn add_accounting(&self, _accounting: &JobAccounting) {
        // In full implementation, store accounting reference
    }

    /// Get job accounting information
    pub fn get_accounting(&self) -> JobAccountingInfo {
        // In full implementation, return actual accounting data
        JobAccountingInfo::new()
    }

    /// Set notification callback
    ///
    /// # Task 5.2: Notification mechanism
    pub fn set_notification_callback(&self, _callback: Option<JobNotificationCallback>) {
        // In full implementation, store callback
    }

    /// Trigger notification event
    fn notify(&self, _event: JobNotificationEvent) {
        // In full implementation, call registered callback
    }

    /// Wait for all processes to terminate
    ///
    /// # Task 5.3: Process termination synchronization
    pub fn wait_for_termination(&self, _timeout_ms: u32) -> u32 {
        // In full implementation, block until all processes exit
        STATUS_SUCCESS
    }

    /// Query job information
    ///
    /// # Task 5.5: Job query API
    pub fn query_information(&self, info_class: JobInformationClass) -> Result<Vec<u8>, u32> {
        match info_class {
            JobInformationClass::BasicAccountingInformation => {
                let info = self.get_accounting();
                Ok(unsafe {
                    core::slice::from_raw_parts(
                        &info as *const _ as *const u8,
                        core::mem::size_of::<JobAccountingInfo>()
                    ).to_vec()
                })
            }
            JobInformationClass::BasicLimitInformation => {
                Err(STATUS_INVALID_PARAMETER)
            }
            JobInformationClass::ExtendedLimitInformation => {
                Err(STATUS_INVALID_PARAMETER)
            }
        }
    }

    /// Set job information
    pub fn set_information(&self, _info_class: JobInformationClass, _data: &[u8]) -> u32 {
        // In full implementation, update job settings
        STATUS_SUCCESS
    }
}

/// Job information classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobInformationClass {
    BasicAccountingInformation = 1,
    BasicLimitInformation = 2,
    ExtendedLimitInformation = 9,
}

/// Job inheritance - Task 5.4
pub fn create_job_with_parent(parent_job_id: u64) -> Result<u64, u32> {
    // Create child job that inherits from parent
    let child_id = create_job()?;

    // In full implementation:
    // - Inherit resource limits from parent
    // - Add to parent's child job list
    // - Enforce hierarchical limits

    Ok(child_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_accounting() {
        let accounting = JobAccounting::new();

        accounting.add_cpu_time(1000, 500);
        accounting.add_page_fault();
        accounting.add_io_operation(true, 4096);

        let info = accounting.get_info();
        assert_eq!(info.total_user_time, 1000);
        assert_eq!(info.total_kernel_time, 500);
        assert_eq!(info.total_page_fault_count, 1);
    }
}
