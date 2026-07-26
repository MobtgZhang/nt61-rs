//! Probe-orchestration semantics for the e2e runner, ported to host.
//!
//! These are pure logic tests; the actual ssh/scp/sftp probes run
//! against a live QEMU guest via scripts/openssh-e2e.sh.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCategory {
    Ssh,
    Scp,
    Sftp,
    Concurrent,
    Restart,
}

impl ProbeCategory {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ssh" => Some(Self::Ssh),
            "scp" => Some(Self::Scp),
            "sftp" => Some(Self::Sftp),
            "concurrent" => Some(Self::Concurrent),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub category: ProbeCategory,
    pub description: String,
    pub passed: bool,
    pub exit_code: Option<i32>,
}

/// Track probe failures for the summary report. The real runner
/// uses a bash array; here we use a `Vec` so the same logic is
/// testable in Rust.
#[derive(Debug, Default, Clone)]
pub struct ProbeReport {
    pub results: Vec<ProbeResult>,
    pub failures_by_category: std::collections::BTreeMap<String, usize>,
}

impl ProbeReport {
    pub fn record(&mut self, r: ProbeResult) {
        if !r.passed {
            *self.failures_by_category
                .entry(format!("{:?}", r.category))
                .or_insert(0) += 1;
        }
        self.results.push(r);
    }

    pub fn total_failures(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    pub fn passed(&self) -> bool {
        self.total_failures() == 0
    }

    /// Sanity-check: failure counts add up to total failures.
    pub fn failure_breakdown_is_consistent(&self) -> bool {
        let sum: usize = self.failures_by_category.values().sum();
        sum == self.total_failures()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passed(category: ProbeCategory, desc: &str) -> ProbeResult {
        ProbeResult {
            category,
            description: desc.into(),
            passed: true,
            exit_code: Some(0),
        }
    }

    fn failed(category: ProbeCategory, desc: &str, code: i32) -> ProbeResult {
        ProbeResult {
            category,
            description: desc.into(),
            passed: false,
            exit_code: Some(code),
        }
    }

    #[test]
    fn empty_report_passes() {
        let r = ProbeReport::default();
        assert!(r.passed());
        assert_eq!(r.total_failures(), 0);
    }

    #[test]
    fn all_pass_report_passes() {
        let mut r = ProbeReport::default();
        r.record(passed(ProbeCategory::Ssh, "echo"));
        r.record(passed(ProbeCategory::Scp, "round-trip"));
        assert!(r.passed());
    }

    #[test]
    fn mixed_pass_fail_reports_correctly() {
        let mut r = ProbeReport::default();
        r.record(passed(ProbeCategory::Ssh, "ok"));
        r.record(failed(ProbeCategory::Ssh, "boom", 1));
        r.record(failed(ProbeCategory::Scp, "no host key", 255));
        assert!(!r.passed());
        assert_eq!(r.total_failures(), 2);
        assert_eq!(r.failures_by_category.get("Ssh"), Some(&1));
        assert_eq!(r.failures_by_category.get("Scp"), Some(&1));
        assert!(r.failure_breakdown_is_consistent());
    }

    #[test]
    fn category_parsing() {
        assert_eq!(ProbeCategory::from_str("ssh"), Some(ProbeCategory::Ssh));
        assert_eq!(ProbeCategory::from_str("sftp"), Some(ProbeCategory::Sftp));
        assert_eq!(ProbeCategory::from_str("bogus"), None);
    }

    #[test]
    fn failure_with_no_exit_code_still_counts() {
        let mut r = ProbeReport::default();
        r.record(ProbeResult {
            category: ProbeCategory::Restart,
            description: "watchdog".into(),
            passed: false,
            exit_code: None,
        });
        assert_eq!(r.total_failures(), 1);
    }
}