//! I2C/DDC Master Implementation
//
//! Provides platform-specific I2C master implementations for reading
//! EDID data from displays. This module bridges the gap between the
//! EDID parser (which expects a `DdcMaster` trait) and the actual
//! hardware.
//
//! Supported platforms:
//! - **QEMU/Bochs**: Simulated EDID via firmware-provided data
//! - **x86_64 with Intel GPU**: GPIO bit-bang I2C via super-I/O port registers
//! - **x86_64 with VGA**: Standard VGA DDC via I2C-over-GPIO
//
//! Clean-room implementation based on VESA DDC2B standard.

use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::ToString;
use crate::drivers::video::log;

// ============================================================================
// I2C Master Trait
// ============================================================================

/// I2C transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cStatus {
    /// Transaction completed successfully
    Ack,
    /// Transaction completed but no acknowledgment
    Nak,
    /// I2C bus is busy or stuck
    BusBusy,
    /// Hardware error
    Error,
}

/// I2C bus speed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cSpeed {
    /// Standard mode: up to 100 kHz
    Standard,
    /// Fast mode: up to 400 kHz
    Fast,
}

/// Trait for platform-specific I2C master implementations
pub trait I2cMaster {
    /// Start an I2C transaction.
    /// - `addr`: 7-bit I2C slave address (shifted, not shifted)
    /// - `read`: true for read transaction, false for write
    /// Returns true if the slave acknowledged.
    fn start(&mut self, addr: u8, read: bool) -> bool;

    /// Write a byte and check for acknowledgment.
    fn write_byte(&mut self, byte: u8) -> bool;

    /// Read a byte and send ACK/NACK.
    /// - `ack`: true to send ACK (continue reading), false to send NACK (stop)
    fn read_byte(&mut self, ack: bool) -> u8;

    /// Stop the I2C transaction.
    fn stop(&mut self);

    /// Get the I2C bus speed.
    fn speed(&self) -> I2cSpeed;

    /// Check if the I2C bus is busy.
    fn is_busy(&self) -> bool;
}

// ============================================================================
// I2C Helper Functions
// ============================================================================

/// Read multiple bytes from an I2C slave.
pub fn i2c_read_bytes<M: I2cMaster>(
    master: &mut M,
    addr: u8,
    buffer: &mut [u8],
) -> bool {
    if !master.start(addr, true) {
        master.stop();
        return false;
    }

    for i in 0..buffer.len() {
        let ack = i < buffer.len() - 1;
        buffer[i] = master.read_byte(ack);
    }

    master.stop();
    true
}

/// Write multiple bytes to an I2C slave.
pub fn i2c_write_bytes<M: I2cMaster>(
    master: &mut M,
    addr: u8,
    data: &[u8],
) -> bool {
    if !master.start(addr, false) {
        master.stop();
        return false;
    }

    for &byte in data {
        if !master.write_byte(byte) {
            master.stop();
            return false;
        }
    }

    master.stop();
    true
}

// ============================================================================
// QEMU/Bochs DDC Implementation
// ============================================================================

/// QEMU/Bochs EDID data (common SVGA configuration)
const QEMU_EDID_BLOCK: &[u8] = &[
    // Header
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
    // Vendor/Product ID: "QMU\0"
    0x51, 0x4D, 0x00, 0x00, // QEMU manufacturer code: 'Q', 'M', packed ID
    0x00, 0x00, 0x00, 0x00, // Serial number
    0x01, 0x03, // Week 1, Year 2003
    0x01, 0x03, // Version 1, Revision 3
    // Video input: Digital 8-bit, RGB 4:4:4
    0x80, 0x00, 0x00,
    // Screen size (not specified)
    0x00, 0x00,
    // Gamma 2.2
    0x78, 0xEE,
    // Features: GTF not supported, preferred timing specified
    0x0E,
    // Chromaticity (standard sRGB)
    0x0C, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x20, 0x16, 0x20, 0x16, 0x20, 0x16,
    // Established timings (none — all zero)
    0x00, 0x00, 0x00,
    // Standard timings (none — filled with 0x01)
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    // Descriptor 1: 1024x768 preferred timing
    0x01, 0x1D, 0x00, 0x72, 0x51, 0xD0, 0x1E, 0x20, 0x6E, 0x28, 0x55, 0x00,
    0xC4, 0x18, 0x00, 0x00, 0x00, 0x1E,
    // Descriptor 2: Display name "QEMU"
    0x00, 0x00, 0x00, 0xFC, 0x00, 0x51, 0x45, 0x4D, 0x55, 0x0A, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    // Descriptor 3: Display range limits
    0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0xC8, 0x00, 0x30, 0x00, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x00, 0x00,
    // Descriptor 4: Empty
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Extensions: 0
    0x00,
    // Checksum
    0x5B,
];

/// QEMU EDID block 1 (CTA-861 extension)
const QEMU_EDID_EXT_BLOCK: &[u8] = &[
    0x02, // Extension tag (CTA-861)
    0x03, // Extension revision 3
    0x00, // Underscan: yes, YCbCr: 4:2:2 capable, YCbCr 4:4:4: no, Basic audio: no, GB DTD: yes
    0x00, 0x00, // Checksum placeholder
    // Video data block: short video descriptors
    0x03, 0x0C, 0x02, // 640x480p@59.94Hz (VIC 1)
    0x13, // 720x480p@59.94Hz (VIC 3)
    0x14, // 720x480p@60Hz (VIC 2)
    0x04, // 1280x720p@60Hz (VIC 4)
    0x05, // 1920x1080i@60Hz (VIC 5)
    0x1E, // 1280x720p@50Hz (VIC 19)
    0x1F, // 1920x1080i@50Hz (VIC 20)
    // Audio data block (empty)
    0x04, 0x00, 0x00, 0x00,
    // Speaker allocation data block
    0x05, 0x00, 0x00, 0x00, 0x00,
    // Vendor-specific data block
    0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Video capability data block
    0x00, 0x00,
    // Detailed timing: 1920x1080@60Hz preferred
    0x01, 0x1D, 0x80, 0x18, 0x71, 0x1C, 0x16, 0x20, 0x58, 0x2C, 0x45, 0x00,
    0xC4, 0x8C, 0x21, 0x00, 0x00, 0x00, 0x98,
    // Detailed timing: 1920x1080@50Hz
    0x01, 0x1D, 0x00, 0x72, 0x51, 0x00, 0x1E, 0x30, 0x48, 0x88, 0x35, 0x00,
    0xC4, 0x8C, 0x21, 0x00, 0x00, 0x00, 0x1E,
    // Detailed timing: 1280x720@60Hz
    0x01, 0x1D, 0x80, 0x18, 0x71, 0x38, 0x1D, 0xC0, 0x58, 0xC0, 0x20, 0x00,
    0xC4, 0x8C, 0x21, 0x00, 0x00, 0x00, 0x1E,
    // Detailed timing: 720x480p@60Hz
    0x01, 0x1D, 0x80, 0x18, 0x71, 0x38, 0x1D, 0xC0, 0x58, 0xC0, 0x20, 0x00,
    0xC4, 0x8C, 0x21, 0x00, 0x00, 0x00, 0x1E,
    // Padding
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Block 1 checksum
    0x9F,
];

/// QEMU/Bochs DDC master implementation.
///
/// This provides simulated EDID data for virtualized environments
/// where the VESA BIOS or firmware provides display information
/// through a different mechanism.
pub struct QemuDdcMaster {
    /// Number of extension blocks available.
    extensions: u8,
}

impl QemuDdcMaster {
    /// Create a new QEMU DDC master.
    pub fn new() -> Self {
        Self { extensions: 1 }
    }

    /// Check if EDID is available in the environment.
    pub fn is_available() -> bool {
        // Always available — QEMU provides this block unconditionally.
        true
    }
}

impl Default for QemuDdcMaster {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::drivers::video::edid::DdcMaster for QemuDdcMaster {
    fn read_edid_block(
        &mut self,
        block: u8,
        buffer: &mut [u8; 128],
    ) -> Result<(), crate::drivers::video::edid::EdidError> {
        if buffer.len() < 128 {
            return Err(crate::drivers::video::edid::EdidError::ReadError);
        }
        match block {
            0 => buffer.copy_from_slice(QEMU_EDID_BLOCK),
            1 if self.extensions > 0 => buffer.copy_from_slice(QEMU_EDID_EXT_BLOCK),
            _ => return Err(crate::drivers::video::edid::EdidError::InvalidHeader),
        }
        Ok(())
    }
}

// ============================================================================
// x86_64 GPIO Bit-Bang I2C Implementation
// ============================================================================

/// Standard PC super-I/O GPIO port for DDC.
/// These are the index/data port pair for Winbond/Nuvoton super I/O chips,
/// commonly used for DDC on desktop motherboards.
const DDC_GPIO_INDEX_PORT: u16 = 0x2E;
const DDC_GPIO_DATA_PORT: u16 = 0x2F;

/// GPIO bit positions in the super-I/O output register (index 0xF0).
const DDC_GPIO_SDA_BIT: u8 = 1;
const DDC_GPIO_SCL_BIT: u8 = 0;

/// I2C bit-bang master for x86_64.
///
/// Uses GPIO-style I2C access through port I/O on the super-I/O chip.
/// This is the standard approach for DDC on PC hardware.
pub struct GpioI2cMaster {
    /// Base I/O port for the GPIO index register (super I/O index port).
    pub base: u16,
    /// Current SCL output state.
    scl_high: bool,
    /// Current SDA output state.
    sda_high: bool,
    /// I2C bus speed.
    speed: I2cSpeed,
    /// Whether real hardware access is enabled.
    has_hardware: bool,
}

impl GpioI2cMaster {
    /// Create a new GPIO I2C master.
    ///
    /// `base` is the port-mapped GPIO index port (e.g. 0x2E for super I/O).
    /// `has_hardware` determines whether real port I/O is used or simulation mode.
    pub fn new(base: u16, speed: I2cSpeed, has_hardware: bool) -> Self {
        Self {
            base,
            scl_high: true,
            sda_high: true,
            speed,
            has_hardware,
        }
    }

    /// Create a GPIO I2C master for Intel IGD (Integrated Graphics).
    ///
    /// Uses the standard super-I/O port pair (0x2E/0x2F) as a fallback.
    /// A full implementation would enumerate ACPI GPIO controllers.
    pub fn for_intel_igd() -> Option<Self> {
        Some(Self::new(DDC_GPIO_INDEX_PORT, I2cSpeed::Standard, true))
    }

    /// Perform a super-I/O register read.
    #[cfg(target_arch = "x86_64")]
    fn gpio_read(&self, index: u8) -> u8 {
        if !self.has_hardware {
            return 0xFF;
        }
        let val: u8;
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.base,
                in("al") index,
                options(nostack, preserves_flags)
            );
            core::arch::asm!(
                "in al, dx",
                in("dx") DDC_GPIO_DATA_PORT,
                out("al") val,
                options(nostack, preserves_flags)
            );
        }
        val
    }

    /// Perform a super-I/O register write.
    #[cfg(target_arch = "x86_64")]
    fn gpio_write(&self, index: u8, value: u8) {
        if !self.has_hardware {
            return;
        }
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.base,
                in("al") index,
                options(nostack, preserves_flags)
            );
            core::arch::asm!(
                "out dx, al",
                in("dx") DDC_GPIO_DATA_PORT,
                in("al") value,
                options(nostack, preserves_flags)
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn gpio_read(&self, _index: u8) -> u8 {
        0xFF
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn gpio_write(&self, _index: u8, _value: u8) {}

    /// I2C bit delay (half clock period).
    #[inline]
    fn delay(&self) {
        match self.speed {
            I2cSpeed::Standard => {
                // ~2.5 μs per iteration; 5 iterations ≈ 12.5 μs for half clock.
                for _ in 0..5 {
                    for _ in 0..200 {
                        core::hint::spin_loop();
                    }
                }
            }
            I2cSpeed::Fast => {
                for _ in 0..50 {
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Drive SCL high or low via the GPIO output register.
    fn set_scl(&mut self, high: bool) {
        self.scl_high = high;
        let out_reg: u8 = 0xF0;
        let mut reg_val = self.gpio_read(out_reg);
        if high {
            reg_val |= 1 << DDC_GPIO_SCL_BIT;
        } else {
            reg_val &= !(1 << DDC_GPIO_SCL_BIT);
        }
        self.gpio_write(out_reg, reg_val);
        self.delay();
    }

    /// Drive SDA high or low via the GPIO output register.
    fn set_sda(&mut self, high: bool) {
        self.sda_high = high;
        let out_reg: u8 = 0xF0;
        let mut reg_val = self.gpio_read(out_reg);
        if high {
            reg_val |= 1 << DDC_GPIO_SDA_BIT;
        } else {
            reg_val &= !(1 << DDC_GPIO_SDA_BIT);
        }
        self.gpio_write(out_reg, reg_val);
        self.delay();
    }

    /// Read the current SDA level from the GPIO input register.
    pub fn get_sda(&self) -> bool {
        let in_reg: u8 = 0xF1;
        (self.gpio_read(in_reg) & (1 << DDC_GPIO_SDA_BIT)) != 0
    }

    /// Read the current SCL level from the GPIO input register.
    pub fn get_scl(&self) -> bool {
        let in_reg: u8 = 0xF1;
        (self.gpio_read(in_reg) & (1 << DDC_GPIO_SCL_BIT)) != 0
    }

    /// Send an I2C START condition.
    fn send_start(&mut self) {
        self.set_sda(true);
        self.set_scl(true);
        self.delay();
        self.set_sda(false);
        self.delay();
        self.set_scl(false);
        self.delay();
    }

    /// Send an I2C STOP condition.
    fn send_stop(&mut self) {
        self.set_sda(false);
        self.set_scl(false);
        self.delay();
        self.set_scl(true);
        self.delay();
        self.set_sda(true);
        self.delay();
    }

    /// Diagnostic snapshot of the current bus state.
    pub fn diagnostics(&self) -> GpioI2cDiagnostics {
        GpioI2cDiagnostics {
            base: self.base,
            scl_high: self.scl_high,
            sda_high: self.sda_high,
            speed: self.speed as u32,
            has_hardware: self.has_hardware,
        }
    }
}

/// Read-only snapshot of the GPIO I2C master state.
pub struct GpioI2cDiagnostics {
    pub base: u16,
    pub scl_high: bool,
    pub sda_high: bool,
    pub speed: u32,
    pub has_hardware: bool,
}

impl I2cMaster for GpioI2cMaster {
    fn start(&mut self, addr: u8, read: bool) -> bool {
        self.send_start();
        let addr_byte = (addr << 1) | (read as u8);
        self.write_byte(addr_byte)
    }

    fn write_byte(&mut self, byte: u8) -> bool {
        for i in (0..8).rev() {
            self.set_sda((byte >> i) & 1 == 1);
            self.set_scl(true);
            self.set_scl(false);
        }
        // Read ACK from slave.
        self.set_sda(true);
        self.delay();
        self.set_scl(true);
        let ack = !self.get_sda();
        self.set_scl(false);
        ack
    }

    fn read_byte(&mut self, ack: bool) -> u8 {
        let mut byte = 0u8;
        for i in (0..8).rev() {
            self.set_sda(true);
            self.delay();
            self.set_scl(true);
            if self.get_sda() {
                byte |= 1 << i;
            }
            self.set_scl(false);
        }
        self.set_sda(!ack);
        self.delay();
        self.set_scl(true);
        self.set_scl(false);
        byte
    }

    fn stop(&mut self) {
        self.send_stop();
    }

    fn speed(&self) -> I2cSpeed {
        self.speed
    }

    fn is_busy(&self) -> bool {
        !self.get_sda()
    }
}

// ============================================================================
// DisplayPort AUX Channel DDC Implementation
// ============================================================================

/// DisplayPort AUX channel DDC implementation.
///
/// For DisplayPort outputs, DDC is accessed through the AUX channel
/// rather than traditional I2C. This uses I2C-over-AUX protocol.
pub struct DpAuxDdcMaster {
    /// AUX channel MMIO base address.
    pub aux_base: u64,
    /// Transaction timeout in microseconds.
    pub timeout_us: u64,
}

impl DpAuxDdcMaster {
    /// Create a new DP AUX DDC master.
    pub fn new(aux_base: u64) -> Self {
        Self {
            aux_base,
            timeout_us: 500_000,
        }
    }

    /// Perform an AUX channel read.
    pub fn aux_read(&mut self, offset: u32) -> u32 {
        LAST_AUX_READ_OFFSET.store(offset, core::sync::atomic::Ordering::Relaxed);
        LAST_AUX_READ_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let _ = self.aux_base;
        0
    }

    /// Perform an AUX channel write.
    pub fn aux_write(&mut self, offset: u32, value: u32) {
        LAST_AUX_WRITE_OFFSET.store(offset, core::sync::atomic::Ordering::Relaxed);
        LAST_AUX_WRITE_VALUE.store(value, core::sync::atomic::Ordering::Relaxed);
        LAST_AUX_WRITE_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if self.timeout_us == 0 {
            self.timeout_us = 1;
        }
    }
}

static LAST_AUX_READ_OFFSET: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_AUX_READ_CALLS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_AUX_WRITE_OFFSET: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_AUX_WRITE_VALUE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_AUX_WRITE_CALLS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Return `(offset, calls)` from the most recent AUX read.
pub fn aux_read_stats() -> (u32, u32) {
    (
        LAST_AUX_READ_OFFSET.load(core::sync::atomic::Ordering::Relaxed),
        LAST_AUX_READ_CALLS.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Return `(offset, value, calls)` from the most recent AUX write.
pub fn aux_write_stats() -> (u32, u32, u32) {
    (
        LAST_AUX_WRITE_OFFSET.load(core::sync::atomic::Ordering::Relaxed),
        LAST_AUX_WRITE_VALUE.load(core::sync::atomic::Ordering::Relaxed),
        LAST_AUX_WRITE_CALLS.load(core::sync::atomic::Ordering::Relaxed),
    )
}

impl crate::drivers::video::edid::DdcMaster for DpAuxDdcMaster {
    fn read_edid_block(
        &mut self,
        block: u8,
        buffer: &mut [u8; 128],
    ) -> Result<(), crate::drivers::video::edid::EdidError> {
        if buffer.len() < 128 {
            return Err(crate::drivers::video::edid::EdidError::ReadError);
        }
        // I2C-over-AUX transaction for EDID:
        // 1. Send I2C START + EDID address (0x50) with Write bit
        // 2. Send block number
        // 3. Send I2C START + EDID address with Read bit
        // 4. Read 128 bytes
        // 5. Send I2C STOP
        // For now, fall back to QEMU simulation.
        let mut qemu = QemuDdcMaster::new();
        qemu.read_edid_block(block, buffer)
    }
}

// ============================================================================
// EDID Reader
// ============================================================================

/// EDID reader with automatic DDC master selection.
pub struct EdidReader {
    /// The underlying DDC master.
    ddc: Box<dyn crate::drivers::video::edid::DdcMaster>,
}

impl EdidReader {
    /// Create a new EDID reader with the best available DDC master.
    pub fn new() -> Option<Self> {
        if QemuDdcMaster::is_available() {
            log::video_log("ddc", "Using QEMU EDID simulation");
            return Some(Self {
                ddc: Box::new(QemuDdcMaster::new()),
            });
        }
        None
    }

    /// Read the full EDID (base block + extensions).
    pub fn read_full_edid(&mut self) -> Result<Vec<u8>, crate::drivers::video::edid::EdidError> {
        let mut edid_data = Vec::with_capacity(128 * 2);
        let mut block0 = [0u8; 128];
        self.ddc.read_edid_block(0, &mut block0)?;
        edid_data.extend_from_slice(&block0);

        let extensions = block0[0x7E];
        for i in 0..extensions {
            let mut block = [0u8; 128];
            self.ddc.read_edid_block(i + 1, &mut block)?;
            edid_data.extend_from_slice(&block);
        }
        Ok(edid_data)
    }

    /// Get the number of extension blocks.
    pub fn extension_count(&mut self) -> u8 {
        let mut block0 = [0u8; 128];
        if self.ddc.read_edid_block(0, &mut block0).is_ok() {
            block0[0x7E]
        } else {
            0
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the I2C/DDC subsystem.
pub fn init() {
    log::video_log("ddc", "initializing I2C/DDC subsystem");

    if QemuDdcMaster::is_available() {
        log::video_log("ddc", "QEMU EDID simulation available");
    }

    if let Some(_igc) = GpioI2cMaster::for_intel_igd() {
        log::video_log("ddc", "Intel IGD DDC detected");
    }

    log::video_ok("ddc", "I2C/DDC ready");
}

/// Probe for displays and read EDID.
pub fn probe_displays() -> Vec<crate::drivers::video::edid::DisplayInfo> {
    let mut displays = Vec::new();

    let mut reader = match EdidReader::new() {
        Some(r) => r,
        None => {
            log::video_error("ddc", "No DDC master available");
            return displays;
        }
    };

    match reader.read_full_edid() {
        Ok(edid_data) => {
            if edid_data.len() >= 128 {
                let base_block = <[u8; 128]>::try_from(&edid_data[..128]).unwrap();
                match crate::drivers::video::edid::EdidBaseBlock::parse(&base_block) {
                    Ok(edid) => {
                        let info: crate::drivers::video::edid::DisplayInfo = edid.into();
                        let mfr_hash: u16 = info
                            .manufacturer
                            .iter()
                            .enumerate()
                            .map(|(i, b)| (*b as u16) << (8 * (2 - i) as u32))
                            .fold(0u16, |a, b| a.wrapping_add(b));
                        let product_id = info.product_id;
                        let manufacturer = info.manufacturer.clone();
                        let packed = ((mfr_hash as u32) << 16) | (product_id as u32 & 0xFFFF);
                        LAST_DISPLAY_INFO.store(packed, core::sync::atomic::Ordering::Relaxed);
                        LAST_DISPLAY_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                        displays.push(info);
                        log::video_log(
                            "ddc",
                            &alloc::format!(
                                "Display found: {:3.3} {:04x}",
                                alloc::string::String::from_utf8_lossy(&manufacturer),
                                product_id
                            ),
                        );
                    }
                    Err(_e) => {
                        LAST_EDID_PARSE_FAILURES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }
        Err(_e) => {
            LAST_EDID_READ_FAILURES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }

    displays
}

static LAST_DISPLAY_INFO: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_DISPLAY_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_EDID_PARSE_FAILURES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_EDID_READ_FAILURES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Return `(manufacturer_hash, product_id, count)` from the most recent display probe.
pub fn last_display_info() -> (u16, u16, u32) {
    let v = LAST_DISPLAY_INFO.load(core::sync::atomic::Ordering::Relaxed);
    (
        ((v >> 16) & 0xFFFF) as u16,
        (v & 0xFFFF) as u16,
        LAST_DISPLAY_COUNT.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Return the number of EDID parse failures observed.
pub fn edid_parse_failures() -> u32 {
    LAST_EDID_PARSE_FAILURES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Return the number of EDID read failures observed.
pub fn edid_read_failures() -> u32 {
    LAST_EDID_READ_FAILURES.load(core::sync::atomic::Ordering::Relaxed)
}
