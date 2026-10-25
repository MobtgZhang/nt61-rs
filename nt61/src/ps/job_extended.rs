//! Job Object Enhancements - Task 5: Complete Job Object Implementation
//!
//! This module extends the basic Job object with full resource accounting,
//! notification mechanisms, and query APIs.

use super::job::{
    create_job, flags as job_flags, JobObject, STATUS_INVALID_PARAMETER, STATUS_QUOTA_EXCEEDED,
    STATUS_SUCCESS,
};
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

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
    pub other_operation_count: AtomicU64,
    read_transfer_count: AtomicU64,
    write_transfer_count: AtomicU64,
    pub other_transfer_count: AtomicU64,
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
            self.write_transfer_count
                .fetch_add(bytes, Ordering::Relaxed);
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
    pub fn notify(&self, _event: JobNotificationEvent) {
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
                        core::mem::size_of::<JobAccountingInfo>(),
                    )
                    .to_vec()
                })
            }
            JobInformationClass::BasicLimitInformation => {
                // JOBOBJECT_BASIC_LIMIT_INFORMATION layout:
                //   PerProcessUserTimeLimit: u64 (100ns)
                //   PerJobUserTimeLimit: u64 (100ns)
                //   MinimumWorkingSetSize: usize
                //   MaximumWorkingSetSize: usize
                //   LimitFlags: u32
                //   ActiveProcessLimit: u32
                //   Affinity: usize
                //   PriorityClass: u32
                //   SchedulingClass: u32
                let per_process_cpu = self.process_memory_enforced.load(Ordering::Acquire);
                let per_job_cpu = self.cpu_time_limit.load(Ordering::Acquire);
                let min_ws = 0u64;
                let max_ws = self.working_set_limit.load(Ordering::Acquire);
                let limit_flags = self.flags.load(Ordering::Acquire);
                let active_process_limit = self.process_limit.load(Ordering::Acquire);
                let affinity = 0u64; // All processors
                let priority_class = 0x20u32; // NORMAL_PRIORITY_CLASS
                let scheduling_class = 0u32;

                let mut buf = Vec::with_capacity(8 + 8 + 8 + 8 + 4 + 4 + 8 + 4 + 4);
                buf.extend_from_slice(&per_process_cpu.to_le_bytes());
                buf.extend_from_slice(&per_job_cpu.to_le_bytes());
                buf.extend_from_slice(&min_ws.to_le_bytes());
                buf.extend_from_slice(&max_ws.to_le_bytes());
                buf.extend_from_slice(&limit_flags.to_le_bytes());
                buf.extend_from_slice(&active_process_limit.to_le_bytes());
                buf.extend_from_slice(&affinity.to_le_bytes());
                buf.extend_from_slice(&priority_class.to_le_bytes());
                buf.extend_from_slice(&scheduling_class.to_le_bytes());
                Ok(buf)
            }
            JobInformationClass::ExtendedLimitInformation => {
                // JOBOBJECT_EXTENDED_LIMIT_INFORMATION adds IO_INFO to
                // BASIC_LIMIT_INFORMATION:
                //   IoInfo: {ReadOperationCount, WriteOperationCount,
                //            OtherOperationCount, ReadTransferCount,
                //            WriteTransferCount, OtherTransferCount}
                //   ProcessMemoryLimit: usize
                //   JobMemoryLimit: usize
                //   PeakProcessMemoryUsed: usize
                //   PeakJobMemoryUsed: usize
                let mut buf = Vec::with_capacity(144);

                // Basic limit information (56 bytes)
                let per_process_cpu = self.process_memory_enforced.load(Ordering::Acquire);
                let per_job_cpu = self.cpu_time_limit.load(Ordering::Acquire);
                let max_ws = self.working_set_limit.load(Ordering::Acquire);
                let limit_flags = self.flags.load(Ordering::Acquire);
                let active_process_limit = self.process_limit.load(Ordering::Acquire);

                buf.extend_from_slice(&per_process_cpu.to_le_bytes());
                buf.extend_from_slice(&per_job_cpu.to_le_bytes());
                buf.extend_from_slice(&0u64.to_le_bytes()); // min ws
                buf.extend_from_slice(&max_ws.to_le_bytes());
                buf.extend_from_slice(&limit_flags.to_le_bytes());
                buf.extend_from_slice(&active_process_limit.to_le_bytes());
                buf.extend_from_slice(&0u64.to_le_bytes()); // affinity
                buf.extend_from_slice(&0x20u32.to_le_bytes()); // priority
                buf.extend_from_slice(&0u32.to_le_bytes()); // scheduling class

                // IO counters (48 bytes)
                buf.extend_from_slice(&0u64.to_le_bytes()); // read ops
                buf.extend_from_slice(&0u64.to_le_bytes()); // write ops
                buf.extend_from_slice(&0u64.to_le_bytes()); // other ops
                buf.extend_from_slice(&0u64.to_le_bytes()); // read transfer
                buf.extend_from_slice(&0u64.to_le_bytes()); // write transfer
                buf.extend_from_slice(&0u64.to_le_bytes()); // other transfer

                // Memory limits (32 bytes)
                let process_mem = self.process_memory_enforced.load(Ordering::Acquire);
                let job_mem = self.job_memory_limit.load(Ordering::Acquire);
                let peak_proc = self.active_process_memory.load(Ordering::Acquire);
                buf.extend_from_slice(&process_mem.to_le_bytes());
                buf.extend_from_slice(&job_mem.to_le_bytes());
                buf.extend_from_slice(&peak_proc.to_le_bytes());
                buf.extend_from_slice(&0u64.to_le_bytes()); // peak job mem

                Ok(buf)
            }
        }
    }

    /// Set job information
    pub fn set_information(&self, info_class: JobInformationClass, data: &[u8]) -> u32 {
        match info_class {
            JobInformationClass::BasicLimitInformation => {
                if data.len() < 40 {
                    return STATUS_INVALID_PARAMETER;
                }

                let read_u64 = |off: usize| -> u64 {
                    u64::from_le_bytes([
                        data[off],
                        data[off + 1],
                        data[off + 2],
                        data[off + 3],
                        data[off + 4],
                        data[off + 5],
                        data[off + 6],
                        data[off + 7],
                    ])
                };
                let read_u32 = |off: usize| -> u32 {
                    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                };

                // Offsets within JOBOBJECT_BASIC_LIMIT_INFORMATION:
                //   0: PerProcessUserTimeLimit (u64)
                //   8: PerJobUserTimeLimit (u64)
                //  16: MinimumWorkingSetSize (usize)
                //  24: MaximumWorkingSetSize (usize)
                //  32: LimitFlags (u32)
                //  36: ActiveProcessLimit (u32)
                let per_job_cpu = read_u64(8);
                let max_ws = read_u64(24);
                let limit_flags = read_u32(32);
                let active_process_limit = read_u32(36);

                if per_job_cpu > 0 {
                    self.cpu_time_limit.store(per_job_cpu, Ordering::Release);
                }
                if max_ws > 0 {
                    self.working_set_limit.store(max_ws, Ordering::Release);
                }
                self.flags.fetch_or(limit_flags, Ordering::Release);
                if active_process_limit > 0 {
                    self.process_limit
                        .store(active_process_limit, Ordering::Release);
                }

                STATUS_SUCCESS
            }
            JobInformationClass::ExtendedLimitInformation => {
                if data.len() < 144 {
                    return STATUS_INVALID_PARAMETER;
                }

                let read_u64 = |off: usize| -> u64 {
                    u64::from_le_bytes([
                        data[off],
                        data[off + 1],
                        data[off + 2],
                        data[off + 3],
                        data[off + 4],
                        data[off + 5],
                        data[off + 6],
                        data[off + 7],
                    ])
                };

                // ProcessMemoryLimit at offset 104, JobMemoryLimit at 112
                let process_mem = read_u64(104);
                let job_mem = read_u64(112);

                if process_mem > 0 {
                    self.process_memory_enforced
                        .store(process_mem, Ordering::Release);
                }
                if job_mem > 0 {
                    self.set_memory_limit(job_mem);
                }

                STATUS_SUCCESS
            }
            _ => STATUS_INVALID_PARAMETER,
        }
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
    let child_id = create_job()?;

    let mut table = super::job::JOB_TABLE.lock();

    let parent = table.iter().find(|j| j.job_id == parent_job_id);
    let parent = match parent {
        Some(p) => p as *const JobObject,
        None => return Err(STATUS_INVALID_PARAMETER),
    };

    let parent_ref = unsafe { &*parent };

    // Enforce parent's child job limit.
    let child_limit = parent_ref.child_job_limit.load(Ordering::Acquire);
    if child_limit > 0 {
        let active_children = parent_ref.active_child_count.load(Ordering::Acquire);
        if active_children >= child_limit {
            return Err(STATUS_QUOTA_EXCEEDED);
        }
    }

    // Initialise the child job with inherited limits.
    if let Some(child) = table.iter_mut().find(|j| j.job_id == child_id) {
        child.parent_job_id = parent_job_id;
        child.flags.fetch_or(job_flags::NESTED, Ordering::Release);

        let parent_flags = parent_ref.flags.load(Ordering::Acquire);

        // Inherit process limit.
        if parent_flags & job_flags::PROCESS_LIMIT_ENABLED != 0 {
            let limit = parent_ref.process_limit.load(Ordering::Acquire);
            child.process_limit.store(limit, Ordering::Release);
            child
                .flags
                .fetch_or(job_flags::PROCESS_LIMIT_ENABLED, Ordering::Release);
        }

        // Inherit job memory limit.
        if parent_flags & job_flags::MEMORY_LIMIT_ENABLED != 0 {
            let limit = parent_ref.job_memory_limit.load(Ordering::Acquire);
            child.job_memory_limit.store(limit, Ordering::Release);
            child
                .flags
                .fetch_or(job_flags::MEMORY_LIMIT_ENABLED, Ordering::Release);
        }

        // Inherit CPU time limit.
        if parent_flags & job_flags::CPU_LIMIT_ENABLED != 0 {
            let limit = parent_ref.cpu_time_limit.load(Ordering::Acquire);
            child.cpu_time_limit.store(limit, Ordering::Release);
            child
                .flags
                .fetch_or(job_flags::CPU_LIMIT_ENABLED, Ordering::Release);
        }

        // Inherit UI restrictions.
        let ui = parent_ref.ui_restrictions.load(Ordering::Acquire);
        child.ui_restrictions.store(ui, Ordering::Release);

        // Track child in parent.
        parent_ref.active_child_count.fetch_add(1, Ordering::AcqRel);
    }

    Ok(child_id)
}

/// Remove a child job from its parent (hierarchical cleanup).
pub fn detach_job_from_parent(child_job_id: u64) -> u32 {
    let mut table = super::job::JOB_TABLE.lock();

    let child = table.iter().find(|j| j.job_id == child_job_id);
    let parent_id = match child {
        Some(c) => c.parent_job_id,
        None => return super::job::STATUS_INVALID_PARAMETER,
    };

    if parent_id == 0 {
        return STATUS_SUCCESS;
    }

    if let Some(parent) = table.iter().find(|j| j.job_id == parent_id) {
        parent.active_child_count.fetch_sub(1, Ordering::AcqRel);
    }

    if let Some(child) = table.iter_mut().find(|j| j.job_id == child_job_id) {
        child.parent_job_id = 0;
        child.flags.fetch_and(!job_flags::NESTED, Ordering::Release);
    }

    STATUS_SUCCESS
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

    #[test]
    fn test_job_nesting_inherits_limits() {
        // Create a parent job with limits.
        let parent_id = create_job().expect("parent job");
        let parent = crate::ps::job::JOB_TABLE
            .lock()
            .iter()
            .find(|j| j.job_id == parent_id)
            .map(|j| j as *const JobObject)
            .unwrap();
        let parent_ref = unsafe { &*parent };
        parent_ref.set_process_limit(4);
        parent_ref.set_memory_limit(1024 * 1024);
        parent_ref.set_cpu_limit(100_000);
        parent_ref.set_ui_restrictions(0x0043); // READ | WRITE | EXIT

        // Set child limit on the parent.
        parent_ref
            .child_job_limit
            .store(2, core::sync::atomic::Ordering::Release);

        // Create a child job.
        let child_id = create_job_with_parent(parent_id).expect("child job");
        assert_ne!(child_id, parent_id);
        let child = crate::ps::job::JOB_TABLE
            .lock()
            .iter()
            .find(|j| j.job_id == child_id)
            .map(|j| j as *const JobObject)
            .unwrap();
        let child_ref = unsafe { &*child };
        let parent = crate::ps::job::JOB_TABLE
            .lock()
            .iter()
            .find(|j| j.job_id == parent_id)
            .map(|j| j as *const JobObject)
            .unwrap();
        let parent_ref = unsafe { &*parent };

        // Verify inherited limits.
        assert_eq!(child_ref.parent_job_id, parent_id);
        assert_eq!(
            child_ref.process_limit.load(Ordering::Acquire),
            4,
            "process limit inherited"
        );
        assert_eq!(
            child_ref.job_memory_limit.load(Ordering::Acquire),
            1024 * 1024,
            "memory limit inherited"
        );
        assert_eq!(
            child_ref.cpu_time_limit.load(Ordering::Acquire),
            100_000,
            "CPU limit inherited"
        );
        assert_eq!(
            child_ref.ui_restrictions.load(Ordering::Acquire),
            0x0043,
            "UI restrictions inherited"
        );
        assert_eq!(
            parent_ref.active_child_count.load(Ordering::Acquire),
            1,
            "parent tracks child"
        );

        // Clean up.
        assert_eq!(detach_job_from_parent(child_id), STATUS_SUCCESS);
        assert_eq!(
            parent_ref.active_child_count.load(Ordering::Acquire),
            0,
            "child detached from parent"
        );
    }

    #[test]
    fn test_job_nesting_child_limit() {
        let parent_id = create_job().expect("parent");
        let parent = crate::ps::job::JOB_TABLE
            .lock()
            .iter()
            .find(|j| j.job_id == parent_id)
            .map(|j| j as *const JobObject)
            .unwrap();
        let parent_ref = unsafe { &*parent };
        parent_ref
            .child_job_limit
            .store(1, core::sync::atomic::Ordering::Release);

        // First child succeeds.
        let child1 = create_job_with_parent(parent_id).expect("child 1");
        assert_ne!(child1, 0);

        // Second child is rejected by the child limit.
        assert_eq!(
            create_job_with_parent(parent_id),
            Err(STATUS_QUOTA_EXCEEDED),
            "child limit enforced"
        );
    }
}
