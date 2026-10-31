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

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

    // === Job nesting (Windows 7 hierarchical job support) ===
    /// Parent job ID (0 = root job, no parent)
    pub parent_job_id: u64,

    /// Maximum number of active processes (0 = unlimited)
    pub process_limit: AtomicU32,

    /// Maximum number of child jobs (0 = unlimited)
    pub child_job_limit: AtomicU32,

    /// Active child job count
    pub active_child_count: AtomicU32,

    /// Per-process memory limit (bytes, 0 = unlimited)
    pub process_memory_enforced: AtomicU64,

    // === UI restrictions (JOBOBJECT_UI_RESTRICTIONS) ===
    /// UI restriction flags for processes in this job
    pub ui_restrictions: AtomicU32,

    /// Security limit flags (JOB_OBJECT_SECURITY_*)
    pub security_limit_flags: AtomicU32,
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

    /// Job enforces a process count limit
    pub const PROCESS_LIMIT_ENABLED: u32 = 0x0040;

    /// Job is nested under a parent job
    pub const NESTED: u32 = 0x0080;
}

/// Job UI restriction flags (JOB_OBJECT_UI_RESTRICTIONS).
/// Reference: Windows Internals, Win32 API documentation.
pub mod ui_restrictions {
    /// No UI restrictions
    pub const NONE: u32 = 0x0000;
    /// Processes cannot read from the clipboard
    pub const READ_CLIPBOARD: u32 = 0x0001;
    /// Processes cannot write to the clipboard
    pub const WRITE_CLIPBOARD: u32 = 0x0002;
    /// Processes cannot change system parameters
    pub const SYSTEM_PARAMETERS: u32 = 0x0004;
    /// Processes cannot change display settings
    pub const DISPLAY_SETTINGS: u32 = 0x0008;
    /// Processes cannot access global atoms
    pub const GLOBAL_ATOMS: u32 = 0x0010;
    /// Processes cannot access desktops other than the job's
    pub const DESKTOP: u32 = 0x0020;
    /// Processes cannot call ExitWindows / ExitWindowsEx
    pub const EXIT_WINDOWS: u32 = 0x0040;
    /// Processes cannot open handles outside the job
    pub const HANDLES: u32 = 0x0080;
}

/// Job security limit flags (JOB_OBJECT_SECURITY_LIMIT).
/// Reference: Win32 API documentation.
pub mod security_limits {
    /// Processes cannot run as Administrator
    pub const NO_ADMIN: u32 = 0x0001;
    /// Processes cannot run with Local System privileges
    pub const NO_LOCALGROUP: u32 = 0x0002;
    /// Processes run with a restricted token
    pub const LIMITED: u32 = 0x0004;
}

/// NTSTATUS codes for job operations
pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
pub const STATUS_QUOTA_EXCEEDED: u32 = 0xC0000044;

impl JobObject {
    /// create a new job object
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
            parent_job_id: 0,
            process_limit: AtomicU32::new(0),
            child_job_limit: AtomicU32::new(0),
            active_child_count: AtomicU32::new(0),
            process_memory_enforced: AtomicU64::new(0),
            ui_restrictions: AtomicU32::new(ui_restrictions::NONE),
            security_limit_flags: AtomicU32::new(0),
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

        // Enforce the process count limit (JOB_OBJECT_PROCESS_LIMIT).
        let limit = self.process_limit.load(Ordering::Acquire);
        if limit > 0 {
            let current = self.active_process_count.load(Ordering::Acquire);
            if current >= limit {
                return STATUS_QUOTA_EXCEEDED;
            }
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
    pub fn terminate_all(&self, _exit_code: u32) -> u32 {
        // Set terminating flag
        self.flags.fetch_or(flags::TERMINATING, Ordering::Release);

        let list = self.process_list.lock();

        for &_process_id in list.iter() {
            // Terminate each process in the job with the specified exit code.
            let _ = crate::ps::process_mgmt::terminate_process_by_pid(_process_id, true);
        }

        STATUS_SUCCESS
    }

    /// Set CPU time limit for this job
    pub fn set_cpu_limit(&self, limit_100ns: u64) {
        self.cpu_time_limit.store(limit_100ns, Ordering::Release);
        if limit_100ns > 0 {
            self.flags
                .fetch_or(flags::CPU_LIMIT_ENABLED, Ordering::Release);
        } else {
            self.flags
                .fetch_and(!flags::CPU_LIMIT_ENABLED, Ordering::Release);
        }
    }

    /// Set memory limit for this job
    pub fn set_memory_limit(&self, limit_bytes: u64) {
        self.job_memory_limit.store(limit_bytes, Ordering::Release);
        if limit_bytes > 0 {
            self.flags
                .fetch_or(flags::MEMORY_LIMIT_ENABLED, Ordering::Release);
        } else {
            self.flags
                .fetch_and(!flags::MEMORY_LIMIT_ENABLED, Ordering::Release);
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

    /// Check whether the job's CPU time limit has been exceeded.
    /// Returns `true` if usage is within the limit (or no limit is set).
    pub fn check_cpu_limit(&self) -> bool {
        if self.flags.load(Ordering::Acquire) & flags::CPU_LIMIT_ENABLED == 0 {
            return true;
        }
        let limit = self.cpu_time_limit.load(Ordering::Acquire);
        if limit == 0 {
            return true;
        }
        let used = self.total_cpu_time.load(Ordering::Acquire);
        used <= limit
    }

    /// Record CPU time consumed by a process in this job.
    /// Returns `false` if the job's CPU time limit is exceeded.
    pub fn add_cpu_time(&self, delta_100ns: u64) -> bool {
        self.total_cpu_time.fetch_add(delta_100ns, Ordering::AcqRel);
        self.check_cpu_limit()
    }

    /// Check whether adding memory would exceed the per-process limit.
    pub fn check_process_memory_limit(&self, additional_bytes: u64) -> bool {
        let limit = self.process_memory_enforced.load(Ordering::Acquire);
        if limit == 0 {
            return true;
        }
        additional_bytes <= limit
    }

    /// Check whether adding memory would exceed both the job-level
    /// and per-process limits.
    pub fn check_all_memory_limits(&self, additional_bytes: u64) -> bool {
        if !self.check_process_memory_limit(additional_bytes) {
            return false;
        }
        self.check_memory_limit(additional_bytes)
    }

    /// Set the process count limit (0 = unlimited).
    pub fn set_process_limit(&self, limit: u32) {
        self.process_limit.store(limit, Ordering::Release);
        if limit > 0 {
            self.flags
                .fetch_or(flags::PROCESS_LIMIT_ENABLED, Ordering::Release);
        } else {
            self.flags
                .fetch_and(!flags::PROCESS_LIMIT_ENABLED, Ordering::Release);
        }
    }

    /// Set the per-process memory limit (0 = unlimited).
    pub fn set_process_memory_limit(&self, limit_bytes: u64) {
        self.process_memory_enforced
            .store(limit_bytes, Ordering::Release);
    }

    /// Set the working set limit (0 = unlimited).
    pub fn set_working_set_limit(&self, limit_bytes: u64) {
        self.working_set_limit.store(limit_bytes, Ordering::Release);
    }

    /// Set UI restrictions for processes in this job.
    pub fn set_ui_restrictions(&self, restrictions: u32) {
        self.ui_restrictions.store(restrictions, Ordering::Release);
    }

    /// Get the current UI restriction flags.
    pub fn get_ui_restrictions(&self) -> u32 {
        self.ui_restrictions.load(Ordering::Acquire)
    }

    /// Check if a specific UI restriction is active.
    pub fn is_ui_restricted(&self, restriction: u32) -> bool {
        (self.ui_restrictions.load(Ordering::Acquire) & restriction) != 0
    }

    /// Set security limit flags.
    pub fn set_security_limits(&self, limit_flags: u32) {
        self.security_limit_flags
            .store(limit_flags, Ordering::Release);
        if limit_flags & security_limits::LIMITED != 0 {
            self.flags
                .fetch_or(flags::SECURITY_RESTRICTED, Ordering::Release);
        }
    }
}

/// Global job object table (simplified implementation)
pub(crate) static JOB_TABLE: Spinlock<Vec<JobObject>> = Spinlock::new(Vec::new());
pub(crate) static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

/// create a new job object
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
    table
        .iter()
        .find(|j| j.job_id == job_id)
        .map(|j| j as &JobObject as *const JobObject)
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

    #[test]
    fn test_process_limit_enforcement() {
        let job = JobObject::new(1);
        job.set_process_limit(2);

        assert_eq!(job.add_process(1), STATUS_SUCCESS);
        assert_eq!(job.add_process(2), STATUS_SUCCESS);
        assert_eq!(job.add_process(3), STATUS_QUOTA_EXCEEDED);

        // Remove one and try again.
        let _ = job.remove_process(1);
        assert_eq!(job.add_process(3), STATUS_SUCCESS);
    }

    #[test]
    fn test_memory_limit_enforcement() {
        let job = JobObject::new(1);
        job.set_memory_limit(1024);

        assert!(job.check_memory_limit(512));
        assert!(job.check_memory_limit(1024));
        assert!(!job.check_memory_limit(2048));
    }

    #[test]
    fn test_process_memory_limit() {
        let job = JobObject::new(1);
        job.set_process_memory_limit(512);

        assert!(job.check_process_memory_limit(256));
        assert!(job.check_process_memory_limit(512));
        assert!(!job.check_process_memory_limit(1024));

        // Combined check: process limit passes but job limit would fail.
        job.set_memory_limit(256);
        assert!(job.check_process_memory_limit(200));
        // Job limit 256: 0 + 200 = 200 <= 256, so this passes.
        assert!(job.check_all_memory_limits(200));
        // But 0 + 300 = 300 > 256, so this fails.
        assert!(!job.check_all_memory_limits(300));
    }

    #[test]
    fn test_cpu_limit_enforcement() {
        let job = JobObject::new(1);

        // No limit: always passes.
        assert!(job.check_cpu_limit());

        // Set a limit.
        job.set_cpu_limit(1000);
        assert!(job.add_cpu_time(500));
        assert!(job.check_cpu_limit());

        // Exceed the limit.
        assert!(!job.add_cpu_time(1000));
        assert!(!job.check_cpu_limit());
    }

    #[test]
    fn test_ui_restrictions() {
        let job = JobObject::new(1);

        // Default: no restrictions.
        assert_eq!(job.get_ui_restrictions(), 0);
        assert!(!job.is_ui_restricted(ui_restrictions::READ_CLIPBOARD));

        // Set restrictions.
        job.set_ui_restrictions(ui_restrictions::READ_CLIPBOARD | ui_restrictions::WRITE_CLIPBOARD);
        assert!(job.is_ui_restricted(ui_restrictions::READ_CLIPBOARD));
        assert!(job.is_ui_restricted(ui_restrictions::WRITE_CLIPBOARD));
        assert!(!job.is_ui_restricted(ui_restrictions::EXIT_WINDOWS));
    }
}
