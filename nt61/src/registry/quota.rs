//! Registry Quota Management
//!
//! Implements registry quota tracking and enforcement to prevent
//! unbounded registry growth. Follows Windows registry quota system.

extern crate alloc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::hive::HiveError;

#[derive(Debug, Clone, Copy)]
pub struct QuotaLimits {
    pub max_registry_size: u64,
    pub max_hive_size: u64,
    /// Maximum size per user
    pub max_user_size: u64,
    pub warning_threshold: u8,
}

impl QuotaLimits {
    pub fn windows7_defaults() -> Self {
        Self {
            max_registry_size: 512 * 1024 * 1024,  // 512 MB
            max_hive_size: 256 * 1024 * 1024,      // 256 MB
            max_user_size: 64 * 1024 * 1024,       // 64 MB
            warning_threshold: 95,                  // 95%
        }
    }

    pub fn warning_size(&self) -> u64 {
        (self.max_registry_size * self.warning_threshold as u64) / 100
    }
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self::windows7_defaults()
    }
}

#[derive(Debug)]
pub struct QuotaUsage {
    /// Total bytes used

    used: AtomicU64,
    peak: AtomicU64,
    key_count: AtomicU64,
    value_count: AtomicU64,
    allocation_count: AtomicU64,
}

impl QuotaUsage {
    pub fn new() -> Self {
        Self {
            used: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            key_count: AtomicU64::new(0),
            value_count: AtomicU64::new(0),
            allocation_count: AtomicU64::new(0),
        }
    }

    pub fn record_allocation(&self, size: u64) {
        let old_used = self.used.fetch_add(size, Ordering::SeqCst);
        let new_used = old_used + size;

        let mut peak = self.peak.load(Ordering::Acquire);
        while new_used > peak {
            match self.peak.compare_exchange_weak(
                peak,
                new_used,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => peak = current,
            }
        }

        self.allocation_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_deallocation(&self, size: u64) {
        self.used.fetch_sub(size, Ordering::SeqCst);
    }

    pub fn record_key(&self) {
        self.key_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn remove_key(&self) {
        self.key_count.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn record_value(&self) {
        self.value_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn remove_value(&self) {
        self.value_count.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }

    pub fn peak(&self) -> u64 {
        self.peak.load(Ordering::Acquire)
    }

    pub fn key_count(&self) -> u64 {
        self.key_count.load(Ordering::Acquire)
    }

    pub fn value_count(&self) -> u64 {
        self.value_count.load(Ordering::Acquire)
    }

    pub fn allocation_count(&self) -> u64 {
        self.allocation_count.load(Ordering::Acquire)
    }

    pub fn usage_percent(&self, limit: u64) -> u8 {
        if limit == 0 {
            return 0;
        }
        let used = self.used();
        ((used * 100) / limit).min(100) as u8
    }

    pub fn is_at_warning(&self, limits: &QuotaLimits) -> bool {
        self.used() >= limits.warning_size()
    }

    pub fn is_exceeded(&self, limit: u64) -> bool {
        self.used() >= limit
    }
}

impl Default for QuotaUsage {
    fn default() -> Self {
        Self::new()
    }
}

pub struct QuotaManager {
    limits: QuotaLimits,
    global_usage: QuotaUsage,
    hive_usage: [QuotaUsage; 8],
    enforcement_enabled: bool,
}

impl QuotaManager {
    pub fn new(limits: QuotaLimits) -> Self {
        Self {
            limits,
            global_usage: QuotaUsage::new(),
            hive_usage: [
                QuotaUsage::new(),
                QuotaUsage::new(),
                QuotaUsage::new(),
                QuotaUsage::new(),
                QuotaUsage::new(),
                QuotaUsage::new(),
                QuotaUsage::new(),
                QuotaUsage::new(),
            ],
            enforcement_enabled: true,
        }
    }

    pub fn check_allocation(
        &self,
        hive_id: usize,
        size: u64,
    ) -> Result<(), HiveError> {
        if !self.enforcement_enabled {
            return Ok(());
        }

        if self.global_usage.used() + size > self.limits.max_registry_size {
            return Err(HiveError::OutOfBounds);
        }

        if hive_id < self.hive_usage.len() {
            if self.hive_usage[hive_id].used() + size > self.limits.max_hive_size {
                return Err(HiveError::OutOfBounds);
            }
        }

        Ok(())
    }

    pub fn record_allocation(&self, hive_id: usize, size: u64) {
        self.global_usage.record_allocation(size);

        if hive_id < self.hive_usage.len() {
            self.hive_usage[hive_id].record_allocation(size);
        }
    }

    pub fn record_deallocation(&self, hive_id: usize, size: u64) {
        self.global_usage.record_deallocation(size);

        if hive_id < self.hive_usage.len() {
            self.hive_usage[hive_id].record_deallocation(size);
        }
    }

    pub fn record_key(&self, hive_id: usize, created: bool) {
        if created {
            self.global_usage.record_key();
            if hive_id < self.hive_usage.len() {
                self.hive_usage[hive_id].record_key();
            }
        } else {
            self.global_usage.remove_key();
            if hive_id < self.hive_usage.len() {
                self.hive_usage[hive_id].remove_key();
            }
        }
    }

    pub fn record_value(&self, hive_id: usize, created: bool) {
        if created {
            self.global_usage.record_value();
            if hive_id < self.hive_usage.len() {
                self.hive_usage[hive_id].record_value();
            }
        } else {
            self.global_usage.remove_value();
            if hive_id < self.hive_usage.len() {
                self.hive_usage[hive_id].remove_value();
            }
        }
    }

    pub fn global_usage(&self) -> &QuotaUsage {
        &self.global_usage
    }

    pub fn hive_usage(&self, hive_id: usize) -> Option<&QuotaUsage> {
        self.hive_usage.get(hive_id)
    }

    pub fn limits(&self) -> &QuotaLimits {
        &self.limits
    }

    pub fn set_enforcement(&mut self, enabled: bool) {
        self.enforcement_enabled = enabled;
    }

    pub fn is_enforcement_enabled(&self) -> bool {
        self.enforcement_enabled
    }

    pub fn report(&self) -> QuotaReport {
        QuotaReport {
            limits: self.limits,
            global_used: self.global_usage.used(),
            global_peak: self.global_usage.peak(),
            global_percent: self.global_usage.usage_percent(self.limits.max_registry_size),
            total_keys: self.global_usage.key_count(),
            total_values: self.global_usage.value_count(),
            total_allocations: self.global_usage.allocation_count(),
            enforcement_enabled: self.enforcement_enabled,
            at_warning: self.global_usage.is_at_warning(&self.limits),
            exceeded: self.global_usage.is_exceeded(self.limits.max_registry_size),
        }
    }
}

impl Default for QuotaManager {
    fn default() -> Self {
        Self::new(QuotaLimits::default())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuotaReport {
    pub limits: QuotaLimits,
    pub global_used: u64,
    pub global_peak: u64,
    pub global_percent: u8,
    pub total_keys: u64,
    pub total_values: u64,
    pub total_allocations: u64,
    pub enforcement_enabled: bool,
    pub at_warning: bool,
    pub exceeded: bool,
}

impl QuotaReport {
    pub fn format_used(&self) -> alloc::string::String {
        format_bytes(self.global_used)
    }

    pub fn format_peak(&self) -> alloc::string::String {
        format_bytes(self.global_peak)
    }

    pub fn format_limit(&self) -> alloc::string::String {
        format_bytes(self.limits.max_registry_size)
    }
}

fn format_bytes(bytes: u64) -> alloc::string::String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        alloc::format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        alloc::format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        alloc::format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        alloc::format!("{} bytes", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_usage() {
        let usage = QuotaUsage::new();

        usage.record_allocation(1024);
        assert_eq!(usage.used(), 1024);

        usage.record_allocation(2048);
        assert_eq!(usage.used(), 3072);
        assert_eq!(usage.peak(), 3072);

        usage.record_deallocation(1024);
        assert_eq!(usage.used(), 2048);
        assert_eq!(usage.peak(), 3072); // Peak stays
    }

    #[test]
    fn test_quota_limits() {
        let limits = QuotaLimits::windows7_defaults();
        assert_eq!(limits.max_registry_size, 512 * 1024 * 1024);
        assert_eq!(limits.warning_threshold, 95);
    }

    #[test]
    fn test_quota_manager() {
        let mut manager = QuotaManager::default();

        assert!(manager.check_allocation(0, 1024).is_ok());

        manager.record_allocation(0, 1024);
        assert_eq!(manager.global_usage().used(), 1024);

        let huge_size = manager.limits().max_registry_size + 1;
        assert!(manager.check_allocation(0, huge_size).is_err());

        manager.set_enforcement(false);
        assert!(manager.check_allocation(0, huge_size).is_ok());
    }

    #[test]
    fn test_warning_threshold() {
        let limits = QuotaLimits::windows7_defaults();
        let usage = QuotaUsage::new();

        usage.record_allocation(limits.max_registry_size / 2);
        assert!(!usage.is_at_warning(&limits));

        usage.record_allocation(limits.max_registry_size / 2);
        assert!(usage.is_at_warning(&limits));
    }

    #[test]
    fn test_per_hive_quota() {
        let manager = QuotaManager::default();

        manager.record_allocation(0, 1024);
        assert_eq!(manager.hive_usage(0).unwrap().used(), 1024);
        assert_eq!(manager.global_usage().used(), 1024);

        manager.record_allocation(1, 2048);
        assert_eq!(manager.hive_usage(1).unwrap().used(), 2048);
        assert_eq!(manager.global_usage().used(), 3072);
    }

    #[test]
    fn test_key_value_tracking() {
        let manager = QuotaManager::default();

        manager.record_key(0, true);
        manager.record_value(0, true);
        manager.record_value(0, true);

        assert_eq!(manager.global_usage().key_count(), 1);
        assert_eq!(manager.global_usage().value_count(), 2);

        manager.record_value(0, false);
        assert_eq!(manager.global_usage().value_count(), 1);
    }

    #[test]
    fn test_quota_report() {
        let manager = QuotaManager::default();

        manager.record_allocation(0, 10 * 1024 * 1024); // 10 MB

        let report = manager.report();
        assert_eq!(report.global_used, 10 * 1024 * 1024);
        assert!(!report.exceeded);
        assert!(!report.at_warning);
        assert!(report.enforcement_enabled);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(512), "512 bytes");
    }
}
