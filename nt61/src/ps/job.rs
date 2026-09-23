//! Job Objects
//!
//! Job objects provide process group management in Windows 7. A job object
//! allows groups of processes to be managed as a single unit with shared
//! resource limits, security boundaries, and termination behavior.
//!
//! # P1-4 Implementation
//! This module implements the basic Job object infrastructure required for
//! Windows 7 compatibility. Full job accounting and limits will be added
//! in future phases.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use alloc::vec::Vec;
use crate::ke::sync::Spinlock;

/// Job object structure (EJOB in Windows terminology)
///
/// Represents a container for a group of processes that can be managed
/// as a single unit.
#[repr(C)]
pub struct JobObject {
    /// Unique job ID
    pub job_id: u64,

    /// Job name (optional)
    pub name: [u8; 256],

    /// List of process IDs in this job
    pub process_list: Spinlock<Vec<u64>>,

    /// Job state flags
    pub flags: AtomicU32,

    /// Active process count
    pub active_process_count: AtomicU32,

    /// Total process count (including terminated)
    pub total_process_count: AtomicU32,

    /// CPU time limit (in 100ns units, 0 = unlimited)
    pub cpu_time_limit: AtomicU64,

    /// Total CPU time used by all processes in this job
    pub total_cpu_time: AtomicU64,

    /// Working set limit (bytes, 0 = unlimited)
    pub working_set_limit: AtomicU64,

    /// Process memory limit (bytes, 0 = unlimited)
    pub process_memory_limit: AtomicU64,

    /// Job memory limit (bytes, 0 = unlimited)
    pub job_memory_limit: AtomicU64,

    /// Active processes memory usage
    pub active_process_memory: AtomicU64,
}

/// Job object flags

pub mod flags {
    /// Job has active processes
    pub const ACTIVE: u32 = 0x0001;

    /// Job is being terminated
    pub const TERMINATING: u32 = 0x0002;

    /// Job enforces CPU time limits
    pub const CPU_LIMIT_ENABLED: u32 = 0x0004;

    /// Job enforces memory limits
    pub const MEMORY_LIMIT_ENABLED: u32 = 0x0008;

    /// Processes in job cannot break away
    pub const NO_BREAKAWAY: u32 = 0x0010;

    /// Processes in job run in a sandbox
    pub const SECURITY_RESTRICTED: u32 = 0x0020;
}

/// NTSTATUS codes for job operations
pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
pub const STATUS_QUOTA_EXCEEDED: u32 = 0xC0000044;

impl JobObject {
    /// Create a new job object
    ///
    /// # Safety
    /// This function allocates a job object and initializes it.
    pub fn new(job_id: u64) -> Self {
        Self {
            job_id,
            name: [0u8; 256],
            process_list: Spinlock::new(Vec::new()),
            flags: AtomicU32::new(flags::ACTIVE),
            active_process_count: AtomicU32::new(0),
            total_process_count: AtomicU32::new(0),
            cpu_time_limit: AtomicU64::new(0), // 0 = unlimited
            total_cpu_time: AtomicU64::new(0),
            working_set_limit: AtomicU64::new(0),
            process_memory_limit: AtomicU64::new(0),
            job_memory_limit: AtomicU64::new(0),
            active_process_memory: AtomicU64::new(0),
        }
    }

    /// Add a process to this job
    ///
    /// # Safety
    /// The caller must ensure the process_id is valid.
    pub fn add_process(&self, process_id: u64) -> u32 {
        let flags = self.flags.load(Ordering::Acquire);

        // Check if job is terminating
        if flags & flags::TERMINATING != 0 {
            return STATUS_ACCESS_DENIED;
        }

        let mut list = self.process_list.lock();

        // Check if process is already in the job
        if list.contains(&process_id) {
            return STATUS_SUCCESS;
        }

        list.push(process_id);
        self.active_process_count.fetch_add(1, Ordering::Release);
        self.total_process_count.fetch_add(1, Ordering::Release);

        STATUS_SUCCESS
    }

    /// Remove a process from this job (when it terminates)
    ///
    /// # Safety
    /// The caller must ensure the process_id is valid.
    pub fn remove_process(&self, process_id: u64) -> u32 {
        let mut list = self.process_list.lock();

        if let Some(pos) = list.iter().position(|&id| id == process_id) {
            list.remove(pos);
            self.active_process_count.fetch_sub(1, Ordering::Release);
            return STATUS_SUCCESS;
        }

        STATUS_INVALID_PARAMETER
    }

    /// Check if a process is in this job
    pub fn contains_process(&self, process_id: u64) -> bool {
        let list = self.process_list.lock();
        list.contains(&process_id)
    }

    /// Get the number of active processes in this job
    pub fn active_process_count(&self) -> u32 {
        self.active_process_count.load(Ordering::Acquire)
    }

    /// Terminate all processes in this job
    ///
    /// # Safety
    /// This is a privileged operation that forcefully terminates processes.
    pub fn terminate_all(&self, exit_code: u32) -> u32 {
        // Set terminating flag
        self.flags.fetch_or(flags::TERMINATING, Ordering::Release);

        let list = self.process_list.lock();

        // In a full implementation, we would call PsTerminateProcess for each
        // process in the list. For now, this is a framework placeholder.
        for &_process_id in list.iter() {
            // TODO: Call PsTerminateProcess(process_id, exit_code)
        }

        STATUS_SUCCESS
    }

    /// Set CPU time limit for this job
    pub fn set_cpu_limit(&self, limit_100ns: u64) {
        self.cpu_time_limit.store(limit_100ns, Ordering::Release);
        if limit_100ns > 0 {
            self.flags.fetch_or(flags::CPU_LIMIT_ENABLED, Ordering::Release);
        } else {
            self.flags.fetch_and(!flags::CPU_LIMIT_ENABLED, Ordering::Release);
        }
    }

    /// Set memory limit for this job
    pub fn set_memory_limit(&self, limit_bytes: u64) {
        self.job_memory_limit.store(limit_bytes, Ordering::Release);
        if limit_bytes > 0 {
            self.flags.fetch_or(flags::MEMORY_LIMIT_ENABLED, Ordering::Release);
        } else {
            self.flags.fetch_and(!flags::MEMORY_LIMIT_ENABLED, Ordering::Release);
        }
    }

    /// Check if adding memory would exceed job limit
    pub fn check_memory_limit(&self, additional_bytes: u64) -> bool {
        let limit = self.job_memory_limit.load(Ordering::Acquire);
        if limit == 0 {
            return true; // No limit
        }

        let current = self.active_process_memory.load(Ordering::Acquire);
        current + additional_bytes <= limit
    }
}

/// Global job object table (simplified implementation)
static JOB_TABLE: Spinlock<Vec<JobObject>> = Spinlock::new(Vec::new());
static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

/// Create a new job object
///
/// # Safety
/// This function is safe to call but allocates memory.
pub fn create_job() -> Result<u64, u32> {
    let job_id = NEXT_JOB_ID.fetch_add(1, Ordering::Release);
    let job = JobObject::new(job_id);

    let mut table = JOB_TABLE.lock();
    table.push(job);

    Ok(job_id)
}

/// Open an existing job object by ID
///
/// # Safety
/// Returns a reference to the job if it exists.
pub fn open_job(job_id: u64) -> Option<*const JobObject> {
    let table = JOB_TABLE.lock();
    table.iter().find(|j| j.job_id == job_id).map(|j| j as *const JobObject)
}

/// Assign a process to a job
///
/// # Safety
/// The caller must ensure both job_id and process_id are valid.
pub fn assign_process_to_job(job_id: u64, process_id: u64) -> u32 {
    let table = JOB_TABLE.lock();

    if let Some(job) = table.iter().find(|j| j.job_id == job_id) {
        return job.add_process(process_id);
    }

    STATUS_INVALID_PARAMETER
}

/// Terminate a job and all its processes
///
/// # Safety
/// This is a privileged operation.
pub fn terminate_job(job_id: u64, exit_code: u32) -> u32 {
    let table = JOB_TABLE.lock();

    if let Some(job) = table.iter().find(|j| j.job_id == job_id) {
        return job.terminate_all(exit_code);
    }

    STATUS_INVALID_PARAMETER
}

/// Initialize the job object subsystem
pub fn init() {
    crate::hal::serial::write_string("[PS] Job object subsystem initialized\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_creation() {
        let job = JobObject::new(1);
        assert_eq!(job.job_id, 1);
        assert_eq!(job.active_process_count(), 0);
    }

    #[test]
    fn test_add_process() {
        let job = JobObject::new(1);
        let result = job.add_process(100);
        assert_eq!(result, STATUS_SUCCESS);
        assert_eq!(job.active_process_count(), 1);
        assert!(job.contains_process(100));
    }

    #[test]
    fn test_remove_process() {
        let job = JobObject::new(1);
        job.add_process(100);
        let result = job.remove_process(100);
        assert_eq!(result, STATUS_SUCCESS);
        assert_eq!(job.active_process_count(), 0);
        assert!(!job.contains_process(100));
    }
}
