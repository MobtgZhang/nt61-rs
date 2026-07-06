//! BCD Mailbox Extension for Diagnostics
//
//! Extends the BCD mailbox with memory diagnostic parameters.

#![allow(dead_code)]

/// Diagnostic mode for Windows Memory Diagnostic
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum DiagnosticMode {
    /// No diagnostic requested
    None = 0,
    /// Quick memory test
    QuickTest = 1,
    /// Full memory test
    FullTest = 2,
    /// Extended memory test
    Extended = 3,
    /// Scheduled test (run on next boot)
    Scheduled = 4,
}

/// BCD Mailbox structure (extends existing)
#[repr(C, packed)]
pub struct BcdMailbox {
    /// Signature: "BCDE"
    pub signature: [u8; 4],
    /// Version (0x00000003 for Windows 7)
    pub version: u32,
    /// Length of mailbox structure
    pub length: u32,
    /// Boot entry GUID
    pub entry_guid: [u8; 16],
    /// Reserved boot options
    pub boot_options: [u8; 224],
    /// Diagnostic mode
    pub diagnostic_mode: u32,
    /// Diagnostic flags
    pub diagnostic_flags: u32,
    /// Memory test start address (physical)
    pub test_start_addr: u64,
    /// Memory test end address (physical)
    pub test_end_addr: u64,
    /// Reserved
    _reserved: [u64; 4],
}

impl BcdMailbox {
    /// Check if mailbox signature is valid
    pub fn is_valid(&self) -> bool {
        &self.signature == b"BCDE"
    }
    
    /// Get diagnostic mode
    pub fn get_diagnostic_mode(&self) -> DiagnosticMode {
        match self.diagnostic_mode {
            0 => DiagnosticMode::None,
            1 => DiagnosticMode::QuickTest,
            2 => DiagnosticMode::FullTest,
            3 => DiagnosticMode::Extended,
            4 => DiagnosticMode::Scheduled,
            _ => DiagnosticMode::None,
        }
    }
    
    /// Set diagnostic mode
    pub fn set_diagnostic_mode(&mut self, mode: DiagnosticMode) {
        self.diagnostic_mode = mode as u32;
    }
    
    /// Check if diagnostic is requested
    pub fn is_diagnostic_requested(&self) -> bool {
        self.diagnostic_mode != 0
    }
    
    /// Get memory test range
    pub fn get_test_range(&self) -> (u64, u64) {
        (self.test_start_addr, self.test_end_addr)
    }
    
    /// Set memory test range
    pub fn set_test_range(&mut self, start: u64, end: u64) {
        self.test_start_addr = start;
        self.test_end_addr = end;
    }
}

/// Diagnostic flags
pub mod flags {
    use bitflags::bitflags;
    
    bitflags! {
        pub struct DiagnosticFlags: u32 {
            const NONE = 0;
            /// Run test at boot time
            const RUN_AT_BOOT = 1 << 0;
            /// Show results on screen
            const SHOW_RESULTS = 1 << 1;
            /// Log results to serial
            const LOG_TO_SERIAL = 1 << 2;
            /// Test in extended mode
            const EXTENDED = 1 << 3;
            /// Test using specific patterns
            const PATTERN_TEST = 1 << 4;
            /// Skip failed regions
            const SKIP_FAILED = 1 << 5;
        }
    }
}

/// Memory test patterns
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum TestPattern {
    /// All zeros
    AllZeros = 0,
    /// All ones
    AllOnes = 1,
    /// Alternating bits (1010...)
    Alternating = 2,
    /// Inverse alternating
    InverseAlternating = 3,
    /// 8-bit checkerboard
    Checkerboard8 = 4,
    /// 16-bit checkerboard
    Checkerboard16 = 5,
    /// Random patterns
    Random = 6,
}

/// Default mailbox (zero-initialized)
impl Default for BcdMailbox {
    fn default() -> Self {
        Self {
            signature: *b"BCDE",
            version: 0x00000003,
            length: core::mem::size_of::<Self>() as u32,
            entry_guid: [0u8; 16],
            boot_options: [0u8; 224],
            diagnostic_mode: 0,
            diagnostic_flags: 0,
            test_start_addr: 0,
            test_end_addr: 0,
            _reserved: [0u64; 4],
        }
    }
}

/// Write diagnostic mode to mailbox
pub fn write_diagnostic_mode(mode: DiagnosticMode) {
    let mailbox = BCD_MAILBOX_VIRT as *mut BcdMailbox;
    unsafe {
        (*mailbox).set_diagnostic_mode(mode);
    }
}

/// Read diagnostic mode from mailbox
pub fn read_diagnostic_mode() -> DiagnosticMode {
    let mailbox = BCD_MAILBOX_VIRT as *const BcdMailbox;
    unsafe {
        (*mailbox).get_diagnostic_mode()
    }
}

/// Check if diagnostic should run
pub fn should_run_diagnostic() -> bool {
    let mode = read_diagnostic_mode();
    mode != DiagnosticMode::None
}

/// Clear diagnostic mode
pub fn clear_diagnostic_mode() {
    write_diagnostic_mode(DiagnosticMode::None);
}

/// BCD Mailbox virtual address (mapped from 0x10_1000)
/// This must match the physical address defined in boot/main.rs
pub const BCD_MAILBOX_VIRT: u64 = 0xFFFF_8000_0010_1000;

/// Maximum memory to test (default 256MB)
pub const DEFAULT_TEST_SIZE: u64 = 256 * 1024 * 1024;

/// Test pattern configurations
pub const TEST_PATTERNS: &[u64] = &[
    0x0000_0000_0000_0000, // All zeros
    0xFFFF_FFFF_FFFF_FFFF, // All ones
    0xAAAA_AAAA_AAAA_AAAA, // Alternating bits
    0x5555_5555_5555_5555, // Inverse alternating
    0x00FF_00FF_00FF_00FF, // 16-bit blocks
    0x0F0F_0F0F_0F0F_0F0F, // 8-bit blocks
];
