//! Security Audit Policy Management
//!
//! Manages system-wide audit policies that control which security events
//! are logged. Implements Windows-style audit policy categories with
//! separate success/failure tracking.
//!
//! References: Windows SDK, WRK security audit, auditpol.exe

use core::sync::atomic::{AtomicU32, Ordering};
use alloc::vec::Vec;

/// Audit policy categories matching Windows audit policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditCategory {
    System = 0,
    Logon = 1,
    ObjectAccess = 2,
    PrivilegeUse = 3,
    DetailedTracking = 4,
    PolicyChange = 5,
    AccountManagement = 6,
    DirectoryServiceAccess = 7,
    AccountLogon = 8,
}

impl AuditCategory {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(AuditCategory::System),
            1 => Some(AuditCategory::Logon),
            2 => Some(AuditCategory::ObjectAccess),
            3 => Some(AuditCategory::PrivilegeUse),
            4 => Some(AuditCategory::DetailedTracking),
            5 => Some(AuditCategory::PolicyChange),
            6 => Some(AuditCategory::AccountManagement),
            7 => Some(AuditCategory::DirectoryServiceAccess),
            8 => Some(AuditCategory::AccountLogon),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AuditCategory::System => "System",
            AuditCategory::Logon => "Logon/Logoff",
            AuditCategory::ObjectAccess => "Object Access",
            AuditCategory::PrivilegeUse => "Privilege Use",
            AuditCategory::DetailedTracking => "Detailed Tracking",
            AuditCategory::PolicyChange => "Policy Change",
            AuditCategory::AccountManagement => "Account Management",
            AuditCategory::DirectoryServiceAccess => "DS Access",
            AuditCategory::AccountLogon => "Account Logon",
        }
    }
}

/// Audit policy settings for a single category

#[derive(Debug, Clone, Copy, Default)]
pub struct CategoryPolicy {
    pub success_enabled: bool,
    pub failure_enabled: bool,
}

impl CategoryPolicy {
    pub const fn new(success: bool, failure: bool) -> Self {
        Self {
            success_enabled: success,
            failure_enabled: failure,
        }
    }

    pub fn is_enabled_for_success(&self) -> bool {
        self.success_enabled
    }

    pub fn is_enabled_for_failure(&self) -> bool {
        self.failure_enabled
    }

    pub fn is_any_enabled(&self) -> bool {
        self.success_enabled || self.failure_enabled
    }
}

/// Packed audit policy state (2 bits per category: success + failure)
/// Stored as atomic u32 for lock-free access
static AUDIT_POLICY_STATE: AtomicU32 = AtomicU32::new(0);

/// Default policy: Enable Logon and AccountLogon events (both success + failure)
const DEFAULT_POLICY: u32 =
    (0b11 << (AuditCategory::Logon as u32 * 2)) |
    (0b11 << (AuditCategory::AccountLogon as u32 * 2));

/// Initialize audit policy with defaults
pub fn init() {
    AUDIT_POLICY_STATE.store(DEFAULT_POLICY, Ordering::Release);
}

/// Get the current policy for a category
pub fn get_category_policy(category: AuditCategory) -> CategoryPolicy {
    let state = AUDIT_POLICY_STATE.load(Ordering::Acquire);
    let shift = (category as u32) * 2;
    let bits = (state >> shift) & 0b11;

    CategoryPolicy {
        success_enabled: (bits & 0b01) != 0,
        failure_enabled: (bits & 0b10) != 0,
    }
}

/// Set policy for a specific category
pub fn set_category_policy(category: AuditCategory, policy: CategoryPolicy) {
    loop {
        let current = AUDIT_POLICY_STATE.load(Ordering::Acquire);
        let shift = (category as u32) * 2;
        let mask = !(0b11 << shift);
        let new_bits = ((policy.success_enabled as u32) | ((policy.failure_enabled as u32) << 1)) << shift;
        let new_state = (current & mask) | new_bits;

        match AUDIT_POLICY_STATE.compare_exchange(
            current,
            new_state,
            Ordering::Release,
            Ordering::Acquire
        ) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
}

/// Check if auditing is enabled for a specific category and outcome
pub fn is_enabled(category: AuditCategory, success: bool) -> bool {
    let policy = get_category_policy(category);
    if success {
        policy.success_enabled
    } else {
        policy.failure_enabled
    }
}

/// Enable both success and failure auditing for a category
pub fn enable_category(category: AuditCategory) {
    set_category_policy(category, CategoryPolicy::new(true, true));
}

/// Disable all auditing for a category
pub fn disable_category(category: AuditCategory) {
    set_category_policy(category, CategoryPolicy::new(false, false));
}

/// Enable only success auditing
pub fn enable_success_only(category: AuditCategory) {
    set_category_policy(category, CategoryPolicy::new(true, false));
}

/// Enable only failure auditing
pub fn enable_failure_only(category: AuditCategory) {
    set_category_policy(category, CategoryPolicy::new(false, true));
}

/// Get all category policies (for enumeration/display)
pub fn get_all_policies() -> [(AuditCategory, CategoryPolicy); 9] {
    [
        (AuditCategory::System, get_category_policy(AuditCategory::System)),
        (AuditCategory::Logon, get_category_policy(AuditCategory::Logon)),
        (AuditCategory::ObjectAccess, get_category_policy(AuditCategory::ObjectAccess)),
        (AuditCategory::PrivilegeUse, get_category_policy(AuditCategory::PrivilegeUse)),
        (AuditCategory::DetailedTracking, get_category_policy(AuditCategory::DetailedTracking)),
        (AuditCategory::PolicyChange, get_category_policy(AuditCategory::PolicyChange)),
        (AuditCategory::AccountManagement, get_category_policy(AuditCategory::AccountManagement)),
        (AuditCategory::DirectoryServiceAccess, get_category_policy(AuditCategory::DirectoryServiceAccess)),
        (AuditCategory::AccountLogon, get_category_policy(AuditCategory::AccountLogon)),
    ]
}

/// Check if any auditing is enabled system-wide
pub fn is_any_enabled() -> bool {
    AUDIT_POLICY_STATE.load(Ordering::Acquire) != 0
}

/// Subcategories for finer-grained control (Windows Vista+)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditSubcategory {
    // Logon/Logoff subcategories
    LogonSubcat = 0x0C00,
    LogoffSubcat = 0x0C01,
    AccountLockoutSubcat = 0x0C02,

    // Object Access subcategories
    FileSystemSubcat = 0x0C03,
    RegistrySubcat = 0x0C04,
    KernelObjectSubcat = 0x0C05,

    // Privilege Use subcategories
    SensitivePrivilegeUseSubcat = 0x0C06,
    NonSensitivePrivilegeUseSubcat = 0x0C07,

    // Process Tracking subcategories
    ProcessCreationSubcat = 0x0C08,
    ProcessTerminationSubcat = 0x0C09,
}

impl AuditSubcategory {
    pub fn parent_category(&self) -> AuditCategory {
        match self {
            AuditSubcategory::LogonSubcat |
            AuditSubcategory::LogoffSubcat |
            AuditSubcategory::AccountLockoutSubcat => AuditCategory::Logon,

            AuditSubcategory::FileSystemSubcat |
            AuditSubcategory::RegistrySubcat |
            AuditSubcategory::KernelObjectSubcat => AuditCategory::ObjectAccess,

            AuditSubcategory::SensitivePrivilegeUseSubcat |
            AuditSubcategory::NonSensitivePrivilegeUseSubcat => AuditCategory::PrivilegeUse,

            AuditSubcategory::ProcessCreationSubcat |
            AuditSubcategory::ProcessTerminationSubcat => AuditCategory::DetailedTracking,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AuditSubcategory::LogonSubcat => "Logon",
            AuditSubcategory::LogoffSubcat => "Logoff",
            AuditSubcategory::AccountLockoutSubcat => "Account Lockout",
            AuditSubcategory::FileSystemSubcat => "File System",
            AuditSubcategory::RegistrySubcat => "Registry",
            AuditSubcategory::KernelObjectSubcat => "Kernel Object",
            AuditSubcategory::SensitivePrivilegeUseSubcat => "Sensitive Privilege Use",
            AuditSubcategory::NonSensitivePrivilegeUseSubcat => "Non Sensitive Privilege Use",
            AuditSubcategory::ProcessCreationSubcat => "Process Creation",
            AuditSubcategory::ProcessTerminationSubcat => "Process Termination",
        }
    }
}

/// Preset audit policy profiles
pub mod presets {
    use super::*;

    /// Minimal auditing (logon events only)
    pub fn apply_minimal() {
        for i in 0..9 {
            if let Some(cat) = AuditCategory::from_u32(i) {
                disable_category(cat);
            }
        }
        enable_category(AuditCategory::Logon);
        enable_category(AuditCategory::AccountLogon);
    }

    /// Recommended baseline (logon + privilege use + policy changes)
    pub fn apply_baseline() {
        apply_minimal();
        enable_category(AuditCategory::PrivilegeUse);
        enable_category(AuditCategory::PolicyChange);
        enable_category(AuditCategory::AccountManagement);
    }

    /// Comprehensive auditing (all categories)
    pub fn apply_comprehensive() {
        for i in 0..9 {
            if let Some(cat) = AuditCategory::from_u32(i) {
                enable_category(cat);
            }
        }
    }

    /// Troubleshooting profile (detailed tracking enabled)
    pub fn apply_troubleshooting() {
        apply_comprehensive();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_get_set() {
        init();

        let cat = AuditCategory::ObjectAccess;
        let policy = CategoryPolicy::new(true, false);
        set_category_policy(cat, policy);

        let retrieved = get_category_policy(cat);
        assert!(retrieved.success_enabled);
        assert!(!retrieved.failure_enabled);
    }

    #[test]
    fn test_is_enabled() {
        init();
        enable_category(AuditCategory::System);

        assert!(is_enabled(AuditCategory::System, true));
        assert!(is_enabled(AuditCategory::System, false));
    }

    #[test]
    fn test_presets() {
        presets::apply_minimal();
        assert!(is_enabled(AuditCategory::Logon, true));
        assert!(!is_enabled(AuditCategory::ObjectAccess, true));

        presets::apply_comprehensive();
        assert!(is_enabled(AuditCategory::ObjectAccess, true));
    }
}
