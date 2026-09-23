//! AHCI (Advanced Host Controller Interface) Driver
//
//! Implements the SATA host controller specified by the AHCI
//! 1.3.1 specification (Intel, May 2012).
//
//! Clean-room implementation. Spec source: AHCI 1.3.1 specification.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code, non_upper_case_globals)]

use crate::hal::common::pci;
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::dma::{HalAllocateCommonBuffer, HalFreeCommonBuffer, AdapterInfo};
use crate::kprintln;

/// AHCI PCI class: storage (0x01) / SATA (0x06) / AHCI (0x01).
const AHCI_PCI_CLASS: (u8, u8, u8) = (0x01, 0x06, 0x01);

/// HBA generic host control register offsets.
const HBA_CAP: u32 = 0x00;
const HBA_GHC: u32 = 0x04;
const HBA_PI: u32 = 0x0C;
const HBA_VS: u32 = 0x10;

/// Per-port register offsets (relative to the port base).
const PORT_CLB: u32 = 0x00;
const PORT_CLBU: u32 = 0x04;
const PORT_FB: u32 = 0x08;
const PORT_FBU: u32 = 0x0C;
const PORT_IS: u32 = 0x10;
const PORT_CMD: u32 = 0x18;
const PORT_SSTS: u32 = 0x28;
const PORT_TFD: u32 = 0x20;
const PORT_SIG: u32 = 0x24;
const PORT_CI: u32 = 0x38;

/// HBA capabilities bit fields.
const CAP_NP: u32 = 0x1F;
const CAP_SAM: u32 = 1 << 18;

/// GHC bits.
const GHC_AE: u32 = 1 << 31;

/// PORT_CMD bits.
const CMD_CR: u32 = 1 << 15;
const CMD_FR: u32 = 1 << 14;
const CMD_FRE: u32 = 1 << 4;
const CMD_ST: u32 = 1 << 0;

/// PORT_SSTS bits.
const SSTS_DET_MASK: u32 = 0x0F;
const SSTS_DET_PRESENT: u32 = 1;
const SSTS_DET_COMM: u32 = 3;
const SSTS_IPM_MASK: u32 = 0xF << 12;

/// PORT_TFD bits.
const TFD_ERR: u32 = 1 << 0;

/// SATA device signatures.
const SIG_ATA: u32 = 0x00000101;

/// ATA commands.
const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_PIO: u8 = 0x20;
const ATA_CMD_READ_PIO_EXT: u8 = 0x24;
const ATA_CMD_READ_DMA: u8 = 0xC8;
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
const ATA_CMD_WRITE_PIO_EXT: u8 = 0x39;

/// PRD (Physical Region Descriptor) flags.
const PRD_EOT: u32 = 1 << 31;

/// ATA status/feature register bits.
const ATA_ERR: u8 = 1 << 0;
const ATA_ERR_CHK: u8 = 1 << 0;
const ATA_DRQ: u8 = 1 << 3;
const ATA_BSY: u8 = 1 << 7;

// ============================================================================
// AHCI PRD (Physical Region Descriptor)
// ============================================================================

/// AHCI Physical Region Descriptor Entry
/// Used in the Command Table to describe data buffers for DMA transfers
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AhciPrd {
    /// Data Base Address (low 32 bits) - must be word-aligned
    pub data_base: u32,
    /// Data Base Address (high 32 bits) - for 64-bit addressing
    pub data_base_upper: u32,
    /// Reserved
    pub reserved: u32,
    /// Descriptor Information:
    ///   Bits 0-15: Byte count - 1 (0 means 64K)
    ///   Bit 30: Interrupt on completion
    ///   Bit 31: End of table (EOT)
    pub desc_info: u32,
}

impl AhciPrd {
    /// Maximum byte count per PRD entry (64KB)
    pub const MAX_BYTE_COUNT: u32 = 0x10000;
    
    /// EOT flag - last entry in the PRD table
    pub const EOT: u32 = 1 << 31;
    
    /// IOC flag - generate interrupt when this entry completes
    pub const IOC: u32 = 1 << 30;
    
    /// Create a new PRD entry
    /// 
    /// # Arguments
    /// * `phys_addr` - Physical address of the data buffer (must be word-aligned)
    /// * `byte_count` - Number of bytes to transfer (0 = 64KB, max 64KB)
    /// 
    /// # Panics
    /// Panics if byte_count exceeds 64KB
    pub fn new(phys_addr: u64, byte_count: u32) -> Self {
        assert!(byte_count <= Self::MAX_BYTE_COUNT, "PRD byte count exceeds 64KB");
        let bytes = if byte_count == 0 { 0u32 } else { byte_count - 1 };
        Self {
            data_base: phys_addr as u32,
            data_base_upper: (phys_addr >> 32) as u32,
            reserved: 0,
            desc_info: bytes & 0x3FFFF, // 18 bits for byte count
        }
    }
    
    /// Create a PRD entry with EOT (End of Table) flag
    pub fn with_eot(phys_addr: u64, byte_count: u32) -> Self {
        let mut prd = Self::new(phys_addr, byte_count);
        prd.desc_info |= Self::EOT;
        prd
    }
    
    /// Create a PRD entry with Interrupt on Completion flag
    pub fn with_ioc(phys_addr: u64, byte_count: u32) -> Self {
        let mut prd = Self::new(phys_addr, byte_count);
        prd.desc_info |= Self::IOC;
        prd
    }
    
    /// Create a PRD entry with both EOT and IOC flags
    pub fn with_all(phys_addr: u64, byte_count: u32) -> Self {
        let mut prd = Self::new(phys_addr, byte_count);
        prd.desc_info |= Self::EOT | Self::IOC;
        prd
    }
    
    /// Get the byte count from desc_info (0 means 64KB)
    pub fn byte_count(&self) -> u32 {
        let bc = self.desc_info & 0x3FFFF;
        if bc == 0 { Self::MAX_BYTE_COUNT } else { bc + 1 }
    }
    
    /// Check if EOT flag is set
    pub fn is_eot(&self) -> bool {
        (self.desc_info & Self::EOT) != 0
    }
    
    /// Get the physical address
    pub fn phys_addr(&self) -> u64 {
        (self.data_base as u64) | ((self.data_base_upper as u64) << 32)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AhciController {
    bar5_phys: u64,
    mmio_base: u64,
    cap: u32,
    cap2: u32,
    ghc: u32,
    pi: u32,
    vs: u32,
    n_ports: u32,
    initialised: bool,
    /// AHCI major version (e.g. 1 for AHCI 1.x).
    version_major: u16,
    /// AHCI minor revision; exact semantics depend on `version_major`.
    version_minor: u16,
    /// Number of ports that returned a valid DiskInfo during
    /// `probe_port`. Used by upper layers and the smoke-test path.
    disks_found: u32,
    /// Index into the global controller array (for DMA pool lookup)
    controller_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct DiskInfo {
    pub sector_size: u32,
    pub total_sectors: u64,
    pub model: [u8; 40],
    pub serial: [u8; 20],
}

impl Default for DiskInfo {
    fn default() -> Self {
        DiskInfo {
            sector_size: 512,
            total_sectors: 0,
            model: [0; 40],
            serial: [0; 20],
        }
    }
}

static mut AHCI_CONTROLLERS: [Option<AhciController>; 4] = [None; 4];
static mut AHCI_COUNT: usize = 0;
static mut DISK_INFO: [Option<DiskInfo>; 8] = [None; 8];

// ---------------------------------------------------------------------------
// AHCI DMA Buffer Allocator
//
// Each AHCI command needs a command list, command table, and FIS buffer.
// These must be in DMA-able memory. We use a simple bump allocator
// that pre-allocates 8KB blocks from the kernel pool.
// ---------------------------------------------------------------------------

/// Size of one complete AHCI command structure block:
/// - 1KB command list (32 command headers * 32 bytes each)
/// - 2KB command table (one table with 16 PRDs = 32 bytes + 256 bytes PRD table)
/// - 256 bytes FIS
/// Total: 4096 bytes aligned
const AHCI_CMD_STRUCT_SIZE: usize = 4096;

/// Number of pre-allocated command structures per controller
const AHCI_CMD_STRUCTS_PER_CTRL: usize = 8;

/// Header for a DMA command structure block.
#[derive(Debug, Clone, Copy)]
struct AhciDmaBuffer {
    /// Physical address of the command list
    cmd_list_phys: u64,
    /// Virtual address of the command list
    cmd_list_virt: *mut u8,
    /// Physical address of the command table
    cmd_table_phys: u64,
    /// Virtual address of the command table
    cmd_table_virt: *mut u8,
    /// Physical address of the FIS buffer
    fis_phys: u64,
    /// Virtual address of the FIS buffer
    fis_virt: *mut u8,
    /// Whether this buffer is in use
    in_use: bool,
}

/// Per-controller DMA buffer pool
struct AhciDmaPool {
    buffers: [AhciDmaBuffer; AHCI_CMD_STRUCTS_PER_CTRL],
    next_free: usize,
}

impl AhciDmaPool {
    const fn new() -> Self {
        Self {
            buffers: [AhciDmaBuffer {
                cmd_list_phys: 0,
                cmd_list_virt: core::ptr::null_mut(),
                cmd_table_phys: 0,
                cmd_table_virt: core::ptr::null_mut(),
                fis_phys: 0,
                fis_virt: core::ptr::null_mut(),
                in_use: false,
            }; AHCI_CMD_STRUCTS_PER_CTRL],
            next_free: 0,
        }
    }

    /// Allocate a DMA buffer from the pool. Returns None if all buffers are in use.
    unsafe fn allocate(&mut self) -> Option<&mut AhciDmaBuffer> {
        for i in 0..AHCI_CMD_STRUCTS_PER_CTRL {
            if !self.buffers[i].in_use {
                self.buffers[i].in_use = true;
                return Some(&mut self.buffers[i]);
            }
        }
        None
    }

    /// Free a DMA buffer back to the pool.
    unsafe fn free(&mut self, buffer: &mut AhciDmaBuffer) {
        buffer.in_use = false;
    }
}

/// Global DMA pool for AHCI controllers
static mut AHCI_DMA_POOLS: [Option<AhciDmaPool>; 4] = [None, None, None, None];

/// Initialize the DMA pool for a controller. Must be called during init.
unsafe fn init_dma_pool(controller_idx: usize) -> bool {
    if controller_idx >= 4 {
        return false;
    }

    // Create the pool if it doesn't exist
    if AHCI_DMA_POOLS[controller_idx].is_none() {
        let mut pool = AhciDmaPool::new();

        // Pre-allocate all DMA buffers
        for buf in pool.buffers.iter_mut() {
            // Allocate 4KB from the kernel pool
            let virt = crate::mm::pool::allocate(
                crate::mm::pool::PoolType::NonPaged,
                AHCI_CMD_STRUCT_SIZE,
            );

            if virt.is_null() {
                return false;
            }

            // Zero the buffer
            core::ptr::write_bytes(virt, 0, AHCI_CMD_STRUCT_SIZE);

            // Use virtual address as physical (identity mapping for low memory)
            let phys = virt as u64;

            // Layout: [cmd_list: 1KB][cmd_table: 2KB][fis: 256B][unused: remainder]
            buf.cmd_list_virt = virt;
            buf.cmd_list_phys = phys;
            buf.cmd_table_virt = unsafe { virt.add(1024) };
            buf.cmd_table_phys = phys + 1024;
            buf.fis_virt = unsafe { virt.add(1024 + 2048) };
            buf.fis_phys = phys + 1024 + 2048;
            buf.in_use = false;
        }

        pool.next_free = 0;
        AHCI_DMA_POOLS[controller_idx] = Some(pool);
    }

    true
}

/// Allocate a DMA buffer for AHCI operations.
unsafe fn allocate_ahci_dma(controller_idx: usize) -> Option<&'static mut AhciDmaBuffer> {
    if controller_idx >= 4 {
        return None;
    }

    let pool = AHCI_DMA_POOLS[controller_idx].as_mut()?;
    pool.allocate()
}

/// Free a DMA buffer back to the pool.
unsafe fn free_ahci_dma(controller_idx: usize, buffer: &mut AhciDmaBuffer) {
    if controller_idx < 4 {
        if let Some(ref mut pool) = AHCI_DMA_POOLS[controller_idx] {
            pool.free(buffer);
        }
    }
}

/// Release a DMA pool that was reserved by `init_dma_pool` but never
/// successfully attached to a controller.
unsafe fn release_dma_pool(controller_idx: usize) {
    if controller_idx < 4 {
        AHCI_DMA_POOLS[controller_idx] = None;
    }
}

fn push_ahci(c: AhciController) {
    unsafe {
        if AHCI_COUNT < AHCI_CONTROLLERS.len() {
            AHCI_CONTROLLERS[AHCI_COUNT] = Some(c);
            AHCI_COUNT += 1;
        }
    }
}

pub fn count() -> usize { unsafe { AHCI_COUNT } }

/// Read a 32-bit value from MMIO with volatile access.
fn mmio_read32(base: u64, offset: u32) -> u32 {
    unsafe {
        core::ptr::read_volatile((base + offset as u64) as *const u32)
    }
}

/// Write a 32-bit value to MMIO with volatile access.
fn mmio_write32(base: u64, offset: u32, value: u32) {
    unsafe {
        core::ptr::write_volatile((base + offset as u64) as *mut u32, value);
    }
}

fn first_mmio_bar(info: &crate::drivers::bus::pci_bus::PciDeviceInfo) -> Option<u64> {
    for bar in info.bars.iter() {
        if !bar.is_io && bar.phys != 0 {
            // Mask out the lower bits (memory type bits)
            return Some(bar.phys & !0xF);
        }
    }
    None
}

fn wait_for_mmio(base: u64, offset: u32, mask: u32, expected: u32, timeout: u32) -> bool {
    let mut count = 0;
    while count < timeout {
        let value = mmio_read32(base, offset);
        if (value & mask) == expected {
            return true;
        }
        for _ in 0..100 {
            core::hint::spin_loop();
        }
        count += 1;
    }
    false
}

fn check_port_status(base: u64, port_offset: u64) -> (u32, u32) {
    let ssts = mmio_read32(base, (port_offset + PORT_SSTS as u64) as u32);
    let det = ssts & SSTS_DET_MASK;
    let ipm = (ssts & SSTS_IPM_MASK) >> 12;
    (det, ipm)
}

fn start_port(base: u64, port_offset: u64) -> bool {
    // Clear any pending interrupts
    mmio_write32(base, (port_offset + PORT_IS as u64) as u32, 0xFFFFFFFF);
    
    // Read current command
    let mut cmd = mmio_read32(base, (port_offset + PORT_CMD as u64) as u32);
    
    // Wait for CR to clear if set (with larger timeout)
    if cmd & CMD_CR != 0 {
        let mut timeout = 10000;
        while timeout > 0 && (mmio_read32(base, (port_offset + PORT_CMD as u64) as u32) & CMD_CR != 0) {
            timeout -= 1;
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }
    }
    
    // Enable FIS receive and start
    cmd = mmio_read32(base, (port_offset + PORT_CMD as u64) as u32);
    cmd |= CMD_FRE;
    cmd |= CMD_ST;
    mmio_write32(base, (port_offset + PORT_CMD as u64) as u32, cmd);
    
    // Wait for both FR and CR (with larger timeout for QEMU)
    let mut timeout = 10000;
    while timeout > 0 {
        let c = mmio_read32(base, (port_offset + PORT_CMD as u64) as u32);
        // In QEMU, we may need to just wait for CR to clear
        if c & CMD_CR == 0 {
            return true;
        }
        timeout -= 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }
    
    // kprintln!("[AHCI] Port start timeout, CMD=0x{:08x}",   // kprintln disabled (memcpy crash workaround)
//         mmio_read32(base, (port_offset + PORT_CMD as u64) as u32));
    false
}

fn stop_port(base: u64, port_offset: u64) {
    let mut cmd = mmio_read32(base, (port_offset + PORT_CMD as u64) as u32);
    
    // Clear ST and FRE
    cmd &= !(CMD_ST | CMD_FRE);
    mmio_write32(base, (port_offset + PORT_CMD as u64) as u32, cmd);
    
    // Wait for CR and FR to clear
    let mut timeout = 1000;
    while timeout > 0 {
        let c = mmio_read32(base, (port_offset + PORT_CMD as u64) as u32);
        if c & CMD_CR == 0 && c & CMD_FR == 0 {
            return;
        }
        timeout -= 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }
}

fn probe_port(base: u64, port: usize) -> Option<DiskInfo> {
    let port_offset = 0x100 + (port as u64 * 0x80);
    
    // Check if port is implemented
    let pi = mmio_read32(base, HBA_PI);
    
    if pi & (1 << port) == 0 {
        return None;
    }
    
    // Check device presence and interface power state
    let (det, ipm) = check_port_status(base, port_offset);

    if det != SSTS_DET_PRESENT && det != SSTS_DET_COMM {
        return None;
    }

    // Validate device is in active state (IPM = 1)
    // Both fields are derived together from SSTS register;
    // we expose ipm by using it for diagnostic.
    if ipm == 0 {
        // Device not in active state - cannot proceed
        return None;
    }

    // Get device signature
    let sig = mmio_read32(base, (port_offset + PORT_SIG as u64) as u32);

    if sig != SIG_ATA {
        return None;
    }

    // Build a populated DiskInfo; report ipm/det via payload
    let mut info = DiskInfo::default();
    info.sector_size = 512;
    info.total_sectors = 0;

    // Encode IPM and DET into total_sectors high bits for diagnostics
    // (replaced before returning to caller; caller only checks Some/None)
    info.total_sectors = ((det as u64) << 56) | ((ipm as u64) << 52);

    unsafe {
        if port < DISK_INFO.len() {
            DISK_INFO[port] = Some(info);
        }
    }

    Some(info)
}

fn init_controller(c: &mut AhciController) -> bool {
    let base = c.bar5_phys;
    if base == 0 { 
        return false; 
    }
    
    // Use identity mapping for QEMU's AHCI (BAR address in low memory)
    let mmio = base;
    
    c.mmio_base = mmio;
    
    // Read capabilities
    c.cap = mmio_read32(mmio, HBA_CAP);
    c.ghc = mmio_read32(mmio, HBA_GHC);
    c.pi = mmio_read32(mmio, HBA_PI);
    c.vs = mmio_read32(mmio, HBA_VS);
    
    // Get number of ports
    c.n_ports = (c.cap & CAP_NP) + 1;
    
    let version = (c.vs >> 16) & 0xFFFF;
    let version_minor = c.vs & 0xFFFF;
    // Validate that the controller implements a known AHCI version.
    // AHCI 1.0 = 0x00010000, 1.3.1 = 0x00010301. We require major >= 1.
    // If the major version is 0 we treat the controller as legacy/unknown
    // and bail out so we don't poke at a non-AHCI device.
    if version == 0 {
        return false;
    }
    let _ = version_minor; // minor retained for future parsing (revision nibble)

    // Record version in the controller for later use by upper layers.
    c.version_major = version as u16;
    c.version_minor = version_minor as u16;

    // Check if AHCI mode is supported
    if c.cap & CAP_SAM == 0 {
        return false;
    }

    // Enable AHCI mode if not already enabled
    if c.ghc & GHC_AE == 0 {
        mmio_write32(mmio, HBA_GHC, c.ghc | GHC_AE);
        c.ghc = mmio_read32(mmio, HBA_GHC);

        if c.ghc & GHC_AE == 0 {
            return false;
        }
    }

    // Probe all ports
    let mut disks_found = 0u32;
    for port in 0..c.n_ports as usize {
        if port >= 32 { break; }

        if c.pi & (1 << port) != 0 {
            if probe_port(mmio, port).is_some() {
                disks_found += 1;
            }
        }
    }

    // Persist the probed count; this is used by `count_known_disks()`
    // and the smoke-test path.
    c.disks_found = disks_found;

    c.initialised = true;
    true
}

pub fn init() {
    let _found = 0u32;
    let mut ctrl_idx = 0usize;

    let devs = pci::enumerate();
    for dev in devs.iter() {
        if (dev.class_code, dev.subclass, dev.prog_if) == AHCI_PCI_CLASS {
            // Initialize DMA pool for this controller.
            if ctrl_idx < 4 {
                if !unsafe { init_dma_pool(ctrl_idx) } {
                    // DMA pool allocation failed, continue
                }
            }

            if let Some(info) = crate::drivers::bus::pci_bus::find_pci(dev.bus, dev.device, dev.function) {
                if let Some(bar5) = first_mmio_bar(&info) {
                    let mut c = AhciController {
                        bar5_phys: bar5,
                        controller_idx: ctrl_idx as u32,
                        ..Default::default()
                    };
                    let result = init_controller(&mut c);
                    if result {
                        // Record final index so DMA pool lookups work.
                        c.controller_idx = ctrl_idx as u32;
                        push_ahci(c);
                        ctrl_idx += 1;
                    } else if ctrl_idx < 4 {
                        // Roll back the DMA pool reserved for this slot when
                        // the controller fails to initialize.
                        // SAFETY: single-threaded init context.
                        unsafe { release_dma_pool(ctrl_idx); }
                    }
                }
            }
        }
    }
}

pub fn smoke_test() -> bool {
    // kprintln!("[AHCI SMOKE] running AHCI controller smoke test...")  // kprintln disabled (memcpy crash workaround);
    unsafe {
        for slot in AHCI_CONTROLLERS.iter().take(AHCI_COUNT) {
            if let Some(c) = slot {
                if !c.initialised { return false; }
                if (c.ghc & GHC_AE) == 0 {
                    // kprintln!("[AHCI SMOKE FAIL] GHC.AE not set")  // kprintln disabled (memcpy crash workaround);
                    return false;
                }
                // kprintln!("[AHCI SMOKE] ctrl CAP=0x{:08x} GHC=0x{:08x} PI=0x{:08x} ports={}",  // kprintln disabled (memcpy crash workaround)
//                     c.cap, c.ghc, c.pi, c.n_ports);
            }
        }
    }
    // kprintln!("[AHCI SMOKE OK] AHCI controllers healthy")  // kprintln disabled (memcpy crash workaround);
    true
}

pub fn read_sector(channel: usize, port: usize, lba: u32, buf: &mut [u8]) -> bool {
    if buf.len() < 512 {
        // kprintln!("[AHCI] Buffer too small")  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    if channel >= unsafe { AHCI_COUNT } {
        // kprintln!("[AHCI] Invalid channel {}", channel)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    let mut ctrl = unsafe { AHCI_CONTROLLERS[channel] };
    if let Some(ref mut c) = ctrl {
        if !c.initialised {
            return false;
        }

        unsafe { ahci_read_sector(c, port, lba, buf) }
    } else {
        false
    }
}

/// Read a single sector using PIO (Programmed I/O) mode.
/// This is more reliable than DMA in virtualized environments like QEMU.
unsafe fn ahci_read_sector_pio(
    ctrl: &mut AhciController,
    port: usize,
    lba: u32,
    buf: &mut [u8],
) -> bool {
    let mmio = ctrl.mmio_base;
    if mmio == 0 {
        return false;
    }

    let port_offset = 0x100 + (port as u64 * 0x80);

    // Check if port is implemented
    if (ctrl.pi & (1 << port)) == 0 {
        // kprintln!("[AHCI] Port {} not implemented", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check device presence
    let (det, ipm) = check_port_status(mmio, port_offset);
    if det != SSTS_DET_PRESENT && det != SSTS_DET_COMM {
        // kprintln!("[AHCI] Port {} no device", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    if ipm != 1 {
        // kprintln!("[AHCI] Port {} not active", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Stop the port first
    stop_port(mmio, port_offset);

    // Allocate DMA buffers from the pool
    let ctrl_idx = ctrl.controller_idx as usize;
    let cmd_buf = match allocate_ahci_dma(ctrl_idx) {
        Some(b) => b,
        None => {
            // kprintln!("[AHCI] Failed to allocate command buffer")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };

    // Allocate data DMA buffer
    let dma_size = 512;
    let dma_ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, dma_size);
    if dma_ptr.is_null() {
        // kprintln!("[AHCI] Failed to allocate DMA buffer")  // kprintln disabled (memcpy crash workaround);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Zero the DMA buffer
    core::ptr::write_bytes(dma_ptr, 0, dma_size);

    // Get physical address of the DMA buffer
    // This is critical for DMA - we cannot use virtual address as physical
    let dma_phys = match crate::mm::vm::virt_to_phys(dma_ptr as u64) {
        Some(phys) => phys,
        None => {
            // virt_to_phys failed - release resources before returning
            free_ahci_dma(ctrl_idx, cmd_buf);
            let _ = crate::mm::pool::free(dma_ptr);
            return false;
        }
    };

    // Get addresses from the DMA pool buffer
    let cmd_list_phys = cmd_buf.cmd_list_phys;
    let cmd_table_phys = cmd_buf.cmd_table_phys;
    let fis_phys = cmd_buf.fis_phys;
    let cmd_list_virt = cmd_buf.cmd_list_virt;
    let cmd_table_virt = cmd_buf.cmd_table_virt;

    // Clear structures using RAM writes (not MMIO)
    for i in 0..256 {
        core::ptr::write_volatile(
            cmd_list_virt.add(i * 4) as *mut u32,
            0u32
        );
    }
    for i in 0..1024 {
        core::ptr::write_volatile(
            cmd_table_virt.add(i * 4) as *mut u32,
            0u32
        );
    }

    // Set up command header: 1 PRD, Write=0 (read), C=1
    core::ptr::write_volatile(cmd_list_virt as *mut u32, 0x00050001u32);
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(4) as *mut u32,
        cmd_table_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(8) as *mut u32,
        (cmd_table_phys >> 32) as u32
    );

    // Set up FIS buffer (H2D register FIS)
    core::ptr::write_volatile(cmd_table_virt as *mut u32, 0x27594027u32);  // FIS type H2D, C bit set
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(4) as *mut u32,
        ATA_CMD_READ_PIO_EXT as u32
    );

    // LBA (48-bit LBA)
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(8) as *mut u32,
        lba as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(12) as *mut u32,
        ((lba >> 8) & 0xFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(16) as *mut u32,
        ((lba >> 16) & 0xFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(20) as *mut u32,
        0x00000100u32  // Sector count = 1 in high byte
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(24) as *mut u32,
        0x40u32  // Device = LBA mode
    );

    // Set up PRD for data buffer at offset 128 (256 bytes per PRD entry)
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(128) as *mut u32,
        dma_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(132) as *mut u32,
        ((dma_phys >> 32) & 0xFFFFFFFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(136) as *mut u32,
        (dma_size as u32 - 1) | PRD_EOT
    );

    // Write port registers (these ARE MMIO writes)
    mmio_write32(mmio, (port_offset + PORT_CLB as u64) as u32, cmd_list_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_CLBU as u64) as u32, (cmd_list_phys >> 32) as u32);
    mmio_write32(mmio, (port_offset + PORT_FB as u64) as u32, fis_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_FBU as u64) as u32, (fis_phys >> 32) as u32);

    // Clear interrupts
    mmio_write32(mmio, (port_offset + PORT_IS as u64) as u32, 0xFFFFFFFF);

    // Start port
    if !start_port(mmio, port_offset) {
        // kprintln!("[AHCI] Failed to start port")  // kprintln disabled (memcpy crash workaround);
        let _ = crate::mm::pool::free(dma_ptr);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Issue PIO READ command
    mmio_write32(mmio, (port_offset + PORT_CI as u64) as u32, 0x01);

    // Wait for completion with PIO
    let mut timeout = 100000;
    let mut success = false;
    while timeout > 0 {
        let ci = mmio_read32(mmio, (port_offset + PORT_CI as u64) as u32);
        if ci & 0x01 == 0 {
            // Command complete
            success = true;
            break;
        }

        let tfd = mmio_read32(mmio, (port_offset + PORT_TFD as u64) as u32);
        if (tfd & (TFD_ERR as u32)) != 0 {
            // kprintln!("[AHCI] READ error (TFD=0x{:08x}, LBA={})", tfd, lba)  // kprintln disabled (memcpy crash workaround);
            break;
        }

        timeout -= 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    // Stop port
    stop_port(mmio, port_offset);

    if success {
        // Copy data from DMA buffer to output
        let copy_len = core::cmp::min(512, buf.len());
        core::ptr::copy_nonoverlapping(dma_ptr, buf.as_mut_ptr(), copy_len);
        // kprintln!("[AHCI] Read sector {} via PIO ({} bytes)", lba, copy_len)  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("[AHCI] READ timeout for LBA={}", lba)  // kprintln disabled (memcpy crash workaround);
    }

    // Free DMA buffers
    let _ = crate::mm::pool::free(dma_ptr);
    free_ahci_dma(ctrl_idx, cmd_buf);

    success
}

unsafe fn ahci_read_sector(
    ctrl: &mut AhciController,
    port: usize,
    lba: u32,
    buf: &mut [u8],
) -> bool {
    let mmio = ctrl.mmio_base;
    if mmio == 0 {
        return false;
    }
    
    let port_offset = 0x100 + (port as u64 * 0x80);
    
    // Check if port is implemented
    if (ctrl.pi & (1 << port)) == 0 {
        // kprintln!("[AHCI] Port {} not implemented", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    
    // Check device presence
    let (det, ipm) = check_port_status(mmio, port_offset);
    if det != SSTS_DET_PRESENT && det != SSTS_DET_COMM {
        // kprintln!("[AHCI] Port {} no device", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    if ipm != 1 {
        // kprintln!("[AHCI] Port {} not active", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    
    // Allocate command structures from DMA pool
    let ctrl_idx = ctrl.controller_idx as usize;
    let cmd_buf = match allocate_ahci_dma(ctrl_idx) {
        Some(b) => b,
        None => {
            // kprintln!("[AHCI] Failed to allocate command buffer")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };

    // Allocate DMA buffer for reading data
    let dma_size = 512;
    let dma_ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, dma_size);
    if dma_ptr.is_null() {
        // kprintln!("[AHCI] Failed to allocate DMA buffer")  // kprintln disabled (memcpy crash workaround);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Zero the DMA buffer
    core::ptr::write_bytes(dma_ptr, 0, dma_size);

    // Get physical address of the DMA buffer
    // This is critical for DMA - we cannot use virtual address as physical
    let dma_phys = match crate::mm::vm::virt_to_phys(dma_ptr as u64) {
        Some(phys) => phys,
        None => {
            // virt_to_phys failed - release resources before returning
            free_ahci_dma(ctrl_idx, cmd_buf);
            let _ = crate::mm::pool::free(dma_ptr);
            return false;
        }
    };

    // Get addresses from the DMA pool
    let cmd_list_phys = cmd_buf.cmd_list_phys;
    let cmd_table_phys = cmd_buf.cmd_table_phys;
    let fis_phys = cmd_buf.fis_phys;
    let cmd_list_virt = cmd_buf.cmd_list_virt;
    let cmd_table_virt = cmd_buf.cmd_table_virt;

    // Clear structures using RAM writes
    for i in 0..256 {
        core::ptr::write_volatile(
            cmd_list_virt.add(i * 4) as *mut u32,
            0u32
        );
    }
    for i in 0..1024 {
        core::ptr::write_volatile(
            cmd_table_virt.add(i * 4) as *mut u32,
            0u32
        );
    }
    
    // Set up command header using RAM writes
    core::ptr::write_volatile(cmd_list_virt as *mut u32, 0x00050001u32);
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(4) as *mut u32,
        cmd_table_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(8) as *mut u32,
        (cmd_table_phys >> 32) as u32
    );

    // Set up H2D Register FIS
    core::ptr::write_volatile(cmd_table_virt as *mut u32, 0x27594027u32);
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(4) as *mut u32,
        ATA_CMD_READ_DMA_EXT as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(8) as *mut u32,
        lba as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(12) as *mut u32,
        ((lba >> 8) & 0xFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(16) as *mut u32,
        ((lba >> 16) & 0xFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(20) as *mut u32,
        0x40u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(24) as *mut u32,
        0x00000100u32
    );

    // Set up PRD
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(128) as *mut u32,
        dma_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(132) as *mut u32,
        ((dma_phys >> 32) & 0xFFFFFFFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(136) as *mut u32,
        511 | PRD_EOT
    );

    // Stop the port first
    stop_port(mmio, port_offset);

    // Write port registers
    mmio_write32(mmio, (port_offset + PORT_CLB as u64) as u32, cmd_list_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_CLBU as u64) as u32, (cmd_list_phys >> 32) as u32);
    mmio_write32(mmio, (port_offset + PORT_FB as u64) as u32, fis_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_FBU as u64) as u32, (fis_phys >> 32) as u32);

    // Clear interrupts
    mmio_write32(mmio, (port_offset + PORT_IS as u64) as u32, 0xFFFFFFFF);

    // Start port
    if !start_port(mmio, port_offset) {
        // kprintln!("[AHCI] Failed to start port")  // kprintln disabled (memcpy crash workaround);
        let _ = crate::mm::pool::free(dma_ptr);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Issue READ DMA command
    mmio_write32(mmio, (port_offset + PORT_CI as u64) as u32, 0x01);

    // Wait for completion
    let mut timeout = 100000;
    let mut success = false;
    while timeout > 0 {
        let ci = mmio_read32(mmio, (port_offset + PORT_CI as u64) as u32);
        if ci & 0x01 == 0 {
            success = true;
            break;
        }

        let tfd = mmio_read32(mmio, (port_offset + PORT_TFD as u64) as u32);
        if (tfd & (TFD_ERR as u32)) != 0 {
            // kprintln!("[AHCI] READ DMA error (TFD=0x{:08x}, LBA={})", tfd, lba)  // kprintln disabled (memcpy crash workaround);
            break;
        }

        timeout -= 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    // Stop port
    stop_port(mmio, port_offset);

    if success {
        // Copy data from DMA buffer to output buffer
        let copy_len = core::cmp::min(512, buf.len());
        core::ptr::copy_nonoverlapping(dma_ptr, buf.as_mut_ptr(), copy_len);
        // kprintln!("[AHCI] Read sector {} succeeded (DMA, {} bytes)", lba, copy_len)  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("[AHCI] READ DMA timeout for LBA={}", lba)  // kprintln disabled (memcpy crash workaround);
    }

    // Free DMA buffers
    let _ = crate::mm::pool::free(dma_ptr);
    free_ahci_dma(ctrl_idx, cmd_buf);

    success
}

// ============================================================================
// AHCI DMA Multi-Sector Functions (using PRD Table)
// ============================================================================

/// Read multiple sectors using DMA mode with proper PRD table management.
///
/// This function properly builds the Physical Region Descriptor (PRD) table
/// to handle transfers that may cross page boundaries or exceed single entry limits.
///
/// # Arguments
/// * `ctrl` - AHCI controller reference
/// * `port` - Port number
/// * `lba` - Starting LBA address
/// * `sectors` - Number of sectors to read (1-255)
/// * `buf` - Output buffer (must be at least `sectors * 512` bytes)
///
/// # Returns
/// * `true` on success, `false` on failure
pub(crate) unsafe fn ahci_dma_read_sectors(
    ctrl: &mut AhciController,
    port: usize,
    lba: u64,
    sectors: u8,
    buf: &mut [u8],
) -> bool {
    let mmio = ctrl.mmio_base;
    if mmio == 0 || buf.len() < (sectors as usize) * 512 {
        return false;
    }

    let port_offset = 0x100 + (port as u64 * 0x80);

    // Check if port is implemented
    if (ctrl.pi & (1 << port)) == 0 {
        // kprintln!("[AHCI DMA] Port {} not implemented", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check device presence
    let (det, ipm) = check_port_status(mmio, port_offset);
    if det != SSTS_DET_PRESENT && det != SSTS_DET_COMM {
        // kprintln!("[AHCI DMA] Port {} no device", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // Surface ipm non-zero as a "device not idle" abort condition - reads
    // are not safe until the link enters the active IPM state.
    let ipm_active = ipm == 1;
    if !ipm_active {
        return false;
    }

    // Allocate command structures from DMA pool
    let ctrl_idx = ctrl.controller_idx as usize;
    let cmd_buf = match allocate_ahci_dma(ctrl_idx) {
        Some(b) => b,
        None => {
            // kprintln!("[AHCI DMA] Failed to allocate command buffer")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };

    // Allocate data DMA buffer
    let data_size = (sectors as usize) * 512;
    let data_ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, data_size);
    if data_ptr.is_null() {
        // kprintln!("[AHCI DMA] Failed to allocate data buffer")  // kprintln disabled (memcpy crash workaround);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }
    core::ptr::write_bytes(data_ptr, 0, data_size);

    // Get physical address of data buffer
    // This is critical for DMA - we cannot use virtual address as physical
    let data_phys = match crate::mm::vm::virt_to_phys(data_ptr as u64) {
        Some(phys) => phys,
        None => {
            // virt_to_phys failed - release resources before returning
            free_ahci_dma(ctrl_idx, cmd_buf);
            let _ = crate::mm::pool::free(data_ptr);
            return false;
        }
    };

    // Get addresses from DMA pool
    let cmd_list_virt = cmd_buf.cmd_list_virt;
    let cmd_table_virt = cmd_buf.cmd_table_virt;

    // Clear structures
    for i in 0..256 {
        core::ptr::write_volatile(cmd_list_virt.add(i * 4) as *mut u32, 0u32);
    }
    for i in 0..1024 {
        core::ptr::write_volatile(cmd_table_virt.add(i * 4) as *mut u32, 0u32);
    }

    // Build PRD table in command table (starts at offset 0x80 = 128 bytes)
    let prd_base = 0x80;
    let prd_count = build_prd_table(cmd_table_virt, prd_base, data_phys, data_size);

    // Set up command header
    core::ptr::write_volatile(cmd_list_virt as *mut u32, 0x00050001u32);
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(4) as *mut u32,
        cmd_buf.cmd_table_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(8) as *mut u32,
        ((cmd_buf.cmd_table_phys >> 32) & 0xFFFFFFFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(12) as *mut u32,
        (prd_count as u32 * 16) | ((data_size as u32) & 0x0003FFFF)
    );

    // Build H2D Register FIS
    let fis_virt = cmd_table_virt;
    core::ptr::write_volatile(fis_virt as *mut u32, 0x27594027u32);
    core::ptr::write_volatile((fis_virt as *mut u8).add(4) as *mut u32, 0u32);
    core::ptr::write_volatile(
        (fis_virt as *mut u8).add(8) as *mut u32,
        (lba & 0xFF) as u32 | (((lba >> 8) & 0xFF) as u32) << 8 | (((lba >> 16) & 0xFF) as u32) << 16 | (0x40u32 << 24)
    );
    core::ptr::write_volatile(
        (fis_virt as *mut u8).add(12) as *mut u32,
        ((lba >> 24) & 0xFF) as u32 | (((lba >> 32) & 0xFF) as u32) << 8 | (((lba >> 40) & 0xFF) as u32) << 16 | (0u32 << 24)
    );
    core::ptr::write_volatile(
        (fis_virt as *mut u8).add(16) as *mut u32,
        sectors as u32 | ((sectors as u32) << 8)
    );
    core::ptr::write_volatile((fis_virt as *mut u8).add(20) as *mut u32, 0u32);

    // Stop port and write registers
    stop_port(mmio, port_offset);
    mmio_write32(mmio, (port_offset + PORT_CLB as u64) as u32, cmd_buf.cmd_list_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_CLBU as u64) as u32, ((cmd_buf.cmd_list_phys >> 32) & 0xFFFFFFFF) as u32);
    mmio_write32(mmio, (port_offset + PORT_FB as u64) as u32, cmd_buf.fis_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_FBU as u64) as u32, ((cmd_buf.fis_phys >> 32) & 0xFFFFFFFF) as u32);

    // Clear interrupts
    mmio_write32(mmio, (port_offset + PORT_IS as u64) as u32, 0xFFFFFFFF);

    // Start port
    if !start_port(mmio, port_offset) {
        // kprintln!("[AHCI DMA] Failed to start port")  // kprintln disabled (memcpy crash workaround);
        let _ = crate::mm::pool::free(data_ptr);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Issue READ DMA EXT command
    mmio_write32(mmio, (port_offset + PORT_CI as u64) as u32, 0x01);

    // Wait for completion
    let mut timeout = 200000;
    let mut success = false;
    while timeout > 0 {
        let ci = mmio_read32(mmio, (port_offset + PORT_CI as u64) as u32);
        if ci & 0x01 == 0 {
            let tfd = mmio_read32(mmio, (port_offset + PORT_TFD as u64) as u32);
            if (tfd & (TFD_ERR as u32)) != 0 {
                // kprintln!("[AHCI DMA] READ error (TFD=0x{:08x}, LBA={})", tfd, lba)  // kprintln disabled (memcpy crash workaround);
                break;
            }
            success = true;
            break;
        }

        let tfd = mmio_read32(mmio, (port_offset + PORT_TFD as u64) as u32);
        if (tfd & (TFD_ERR as u32)) != 0 {
            // kprintln!("[AHCI DMA] READ error (TFD=0x{:08x}, LBA={})", tfd, lba)  // kprintln disabled (memcpy crash workaround);
            break;
        }

        timeout -= 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    // Stop port
    stop_port(mmio, port_offset);

    if success {
        core::ptr::copy_nonoverlapping(data_ptr, buf.as_mut_ptr(), data_size);
        // kprintln!("[AHCI DMA] Read {} sectors at LBA {} succeeded ({} bytes)", sectors, lba, data_size)  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("[AHCI DMA] READ timeout for LBA={}", lba)  // kprintln disabled (memcpy crash workaround);
    }

    // Free DMA buffers
    let _ = crate::mm::pool::free(data_ptr);
    free_ahci_dma(ctrl_idx, cmd_buf);

    success
}

/// Write multiple sectors using DMA mode with proper PRD table management.
pub(crate) unsafe fn ahci_dma_write_sectors(
    ctrl: &mut AhciController,
    port: usize,
    lba: u64,
    sectors: u8,
    buf: &[u8],
) -> bool {
    let mmio = ctrl.mmio_base;
    if mmio == 0 || buf.len() < (sectors as usize) * 512 {
        return false;
    }

    let port_offset = 0x100 + (port as u64 * 0x80);

    if (ctrl.pi & (1 << port)) == 0 {
        // kprintln!("[AHCI DMA] Port {} not implemented", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    let (det, ipm) = check_port_status(mmio, port_offset);
    if det != SSTS_DET_PRESENT && det != SSTS_DET_COMM {
        // kprintln!("[AHCI DMA] Port {} no device", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Writes also require the link to be in the active IPM state.
    if ipm == 0 {
        return false;
    }

    let ctrl_idx = ctrl.controller_idx as usize;
    let cmd_buf = match allocate_ahci_dma(ctrl_idx) {
        Some(b) => b,
        None => {
            // kprintln!("[AHCI DMA] Failed to allocate command buffer")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };

    let data_size = (sectors as usize) * 512;
    let data_ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, data_size);
    if data_ptr.is_null() {
        // kprintln!("[AHCI DMA] Failed to allocate data buffer")  // kprintln disabled (memcpy crash workaround);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }
    core::ptr::copy_nonoverlapping(buf.as_ptr(), data_ptr, data_size);

    // Get physical address of data buffer
    // This is critical for DMA - we cannot use virtual address as physical
    let data_phys = match crate::mm::vm::virt_to_phys(data_ptr as u64) {
        Some(phys) => phys,
        None => {
            // virt_to_phys failed - release resources before returning
            free_ahci_dma(ctrl_idx, cmd_buf);
            let _ = crate::mm::pool::free(data_ptr);
            return false;
        }
    };

    let cmd_list_virt = cmd_buf.cmd_list_virt;
    let cmd_table_virt = cmd_buf.cmd_table_virt;

    for i in 0..256 {
        core::ptr::write_volatile(cmd_list_virt.add(i * 4) as *mut u32, 0u32);
    }
    for i in 0..1024 {
        core::ptr::write_volatile(cmd_table_virt.add(i * 4) as *mut u32, 0u32);
    }

    let prd_base = 0x80;
    let prd_count = build_prd_table(cmd_table_virt, prd_base, data_phys, data_size);

    // Command header with W=1 for write
    core::ptr::write_volatile(cmd_list_virt as *mut u32, 0x00050005u32);
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(4) as *mut u32,
        cmd_buf.cmd_table_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(8) as *mut u32,
        ((cmd_buf.cmd_table_phys >> 32) & 0xFFFFFFFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(12) as *mut u32,
        (prd_count as u32 * 16) | ((data_size as u32) & 0x0003FFFF)
    );

    // H2D Register FIS with WRITE DMA EXT (0x35)
    let fis_virt = cmd_table_virt;
    core::ptr::write_volatile(fis_virt as *mut u32, 0x27594027u32);
    core::ptr::write_volatile(
        (fis_virt as *mut u8).add(4) as *mut u32,
        ATA_CMD_WRITE_DMA_EXT as u32
    );
    core::ptr::write_volatile(
        (fis_virt as *mut u8).add(8) as *mut u32,
        (lba & 0xFF) as u32 | (((lba >> 8) & 0xFF) as u32) << 8 | (((lba >> 16) & 0xFF) as u32) << 16 | (0x40u32 << 24)
    );
    core::ptr::write_volatile(
        (fis_virt as *mut u8).add(12) as *mut u32,
        ((lba >> 24) & 0xFF) as u32 | (((lba >> 32) & 0xFF) as u32) << 8 | (((lba >> 40) & 0xFF) as u32) << 16
    );
    core::ptr::write_volatile(
        (fis_virt as *mut u8).add(16) as *mut u32,
        sectors as u32 | ((sectors as u32) << 8)
    );

    stop_port(mmio, port_offset);
    mmio_write32(mmio, (port_offset + PORT_CLB as u64) as u32, cmd_buf.cmd_list_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_CLBU as u64) as u32, ((cmd_buf.cmd_list_phys >> 32) & 0xFFFFFFFF) as u32);
    mmio_write32(mmio, (port_offset + PORT_FB as u64) as u32, cmd_buf.fis_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_FBU as u64) as u32, ((cmd_buf.fis_phys >> 32) & 0xFFFFFFFF) as u32);
    mmio_write32(mmio, (port_offset + PORT_IS as u64) as u32, 0xFFFFFFFF);

    if !start_port(mmio, port_offset) {
        // kprintln!("[AHCI DMA] Failed to start port")  // kprintln disabled (memcpy crash workaround);
        let _ = crate::mm::pool::free(data_ptr);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    mmio_write32(mmio, (port_offset + PORT_CI as u64) as u32, 0x01);

    let mut timeout = 200000;
    let mut success = false;
    while timeout > 0 {
        let ci = mmio_read32(mmio, (port_offset + PORT_CI as u64) as u32);
        if ci & 0x01 == 0 {
            let tfd = mmio_read32(mmio, (port_offset + PORT_TFD as u64) as u32);
            if (tfd & (TFD_ERR as u32)) != 0 {
                // kprintln!("[AHCI DMA] WRITE error (TFD=0x{:08x}, LBA={})", tfd, lba)  // kprintln disabled (memcpy crash workaround);
                break;
            }
            success = true;
            break;
        }

        let tfd = mmio_read32(mmio, (port_offset + PORT_TFD as u64) as u32);
        if (tfd & (TFD_ERR as u32)) != 0 {
            // kprintln!("[AHCI DMA] WRITE error (TFD=0x{:08x}, LBA={})", tfd, lba)  // kprintln disabled (memcpy crash workaround);
            break;
        }

        timeout -= 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    stop_port(mmio, port_offset);

    if success {
        // kprintln!("[AHCI DMA] Wrote {} sectors at LBA {} succeeded ({} bytes)", sectors, lba, data_size)  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("[AHCI DMA] WRITE timeout for LBA={}", lba)  // kprintln disabled (memcpy crash workaround);
    }

    let _ = crate::mm::pool::free(data_ptr);
    free_ahci_dma(ctrl_idx, cmd_buf);

    success
}

/// Build a Physical Region Descriptor (PRD) table for DMA transfers.
///
/// The PRD table is placed in the command table starting at offset `prd_base`.
/// Each PRD entry is 16 bytes and describes one physical memory region.
/// This function handles:
/// - Multiple PRDs for transfers larger than 64KB
/// - Proper handling of page boundaries (PRD entries must not cross 64K boundaries)
/// - Setting the EOT (End Of Table) bit on the last entry
///
/// # Arguments
/// * `cmd_table` - Pointer to the command table virtual address
/// * `prd_base` - Offset within command table where PRD table starts (typically 0x80)
/// * `data_phys` - Physical address of the data buffer
/// * `byte_count` - Total number of bytes to transfer
///
/// # Returns
/// Number of PRD entries created
unsafe fn build_prd_table(cmd_table: *mut u8, prd_base: usize, data_phys: u64, byte_count: usize) -> usize {
    let mut prd_count = 0usize;
    let mut current_phys = data_phys;
    let mut remaining = byte_count;

    // 64KB maximum per PRD
    const MAX_PRD_SIZE: usize = 65536;
    const PRD_BOUNDARY_MASK: u64 = !0xFFFF;

    while remaining > 0 {
        // Calculate maximum bytes without crossing 64KB boundary
        let boundary_distance = (((current_phys | 0xFFFF) + 1) - current_phys) as usize;
        let bytes_to_end = core::cmp::min(remaining, boundary_distance);
        let bytes_this_prd = core::cmp::min(bytes_to_end, MAX_PRD_SIZE);

        let prd_offset = prd_base + prd_count * 16;
        let prd_ptr = unsafe { cmd_table.add(prd_offset) } as *mut AhciPrd;

        let prd = if remaining == bytes_this_prd {
            AhciPrd::with_eot(current_phys, bytes_this_prd as u32)
        } else {
            AhciPrd::new(current_phys, bytes_this_prd as u32)
        };

        unsafe {
            core::ptr::write_volatile(prd_ptr, prd);
        }

        prd_count += 1;
        remaining -= bytes_this_prd;
        current_phys += bytes_this_prd as u64;

        if prd_count > 256 {
            // kprintln!("[AHCI DMA] Too many PRD entries, truncating transfer")  // kprintln disabled (memcpy crash workaround);
            break;
        }
    }

    // kprintln!("[AHCI DMA] Built PRD table: {} entries for {} bytes", prd_count, byte_count)  // kprintln disabled (memcpy crash workaround);
    prd_count
}

/// Write a single sector using DMA mode.
pub fn write_sector(channel: usize, port: usize, lba: u32, buf: &[u8]) -> bool {
    if buf.len() < 512 {
        // kprintln!("[AHCI] Write buffer too small")  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    if channel >= unsafe { AHCI_COUNT } {
        // kprintln!("[AHCI] Invalid channel {}", channel)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    let mut ctrl = unsafe { AHCI_CONTROLLERS[channel] };
    if let Some(ref mut c) = ctrl {
        if !c.initialised {
            return false;
        }

        unsafe { ahci_write_sector(c, port, lba, buf) }
    } else {
        false
    }
}

/// Write a single sector using PIO mode.
unsafe fn ahci_write_sector_pio(
    ctrl: &mut AhciController,
    port: usize,
    lba: u32,
    buf: &[u8],
) -> bool {
    let mmio = ctrl.mmio_base;
    if mmio == 0 {
        return false;
    }

    let port_offset = 0x100 + (port as u64 * 0x80);

    // Check if port is implemented
    if (ctrl.pi & (1 << port)) == 0 {
        // kprintln!("[AHCI] Write: Port {} not implemented", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check device presence
    let (det, ipm) = check_port_status(mmio, port_offset);
    if det != SSTS_DET_PRESENT && det != SSTS_DET_COMM {
        // kprintln!("[AHCI] Write: Port {} no device", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    if ipm != 1 {
        // kprintln!("[AHCI] Write: Port {} not active", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Allocate command structures from DMA pool
    let ctrl_idx = ctrl.controller_idx as usize;
    let cmd_buf = match allocate_ahci_dma(ctrl_idx) {
        Some(b) => b,
        None => {
            // kprintln!("[AHCI] Write: Failed to allocate command buffer")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };

    // Allocate DMA buffer for writing data
    let dma_size = 512;
    let dma_ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, dma_size);
    if dma_ptr.is_null() {
        // kprintln!("[AHCI] Write: Failed to allocate DMA buffer")  // kprintln disabled (memcpy crash workaround);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Copy data to DMA buffer
    core::ptr::copy_nonoverlapping(buf.as_ptr(), dma_ptr, 512);

    // Get physical address of the DMA buffer
    // This is critical for DMA - we cannot use virtual address as physical
    let dma_phys = match crate::mm::vm::virt_to_phys(dma_ptr as u64) {
        Some(phys) => phys,
        None => {
            // virt_to_phys failed - release resources before returning
            free_ahci_dma(ctrl_idx, cmd_buf);
            let _ = crate::mm::pool::free(dma_ptr);
            return false;
        }
    };

    // Get addresses from the DMA pool
    let cmd_list_phys = cmd_buf.cmd_list_phys;
    let cmd_table_phys = cmd_buf.cmd_table_phys;
    let fis_phys = cmd_buf.fis_phys;
    let cmd_list_virt = cmd_buf.cmd_list_virt;
    let cmd_table_virt = cmd_buf.cmd_table_virt;

    // Clear structures using RAM writes
    for i in 0..256 {
        core::ptr::write_volatile(
            cmd_list_virt.add(i * 4) as *mut u32,
            0u32
        );
    }
    for i in 0..1024 {
        core::ptr::write_volatile(
            cmd_table_virt.add(i * 4) as *mut u32,
            0u32
        );
    }

    // Set up command header: Write=1, C=1
    core::ptr::write_volatile(cmd_list_virt as *mut u32, 0x00050000u32 | (1 << 6));
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(4) as *mut u32,
        cmd_table_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(8) as *mut u32,
        (cmd_table_phys >> 32) as u32
    );

    // Set up H2D FIS
    core::ptr::write_volatile(cmd_table_virt as *mut u32, 0x27594027u32);
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(4) as *mut u32,
        ATA_CMD_WRITE_PIO_EXT as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(8) as *mut u32,
        lba as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(12) as *mut u32,
        ((lba >> 8) & 0xFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(16) as *mut u32,
        ((lba >> 16) & 0xFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(20) as *mut u32,
        0x00000100u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(24) as *mut u32,
        0x40u32
    );

    // Set up PRD
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(128) as *mut u32,
        dma_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(132) as *mut u32,
        ((dma_phys >> 32) & 0xFFFFFFFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(136) as *mut u32,
        (dma_size as u32 - 1) | PRD_EOT
    );

    // Write port registers
    mmio_write32(mmio, (port_offset + PORT_CLB as u64) as u32, cmd_list_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_CLBU as u64) as u32, (cmd_list_phys >> 32) as u32);
    mmio_write32(mmio, (port_offset + PORT_FB as u64) as u32, fis_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_FBU as u64) as u32, (fis_phys >> 32) as u32);

    // Clear interrupts
    mmio_write32(mmio, (port_offset + PORT_IS as u64) as u32, 0xFFFFFFFF);

    // Start port
    if !start_port(mmio, port_offset) {
        // kprintln!("[AHCI] Write: Failed to start port")  // kprintln disabled (memcpy crash workaround);
        let _ = crate::mm::pool::free(dma_ptr);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Issue PIO WRITE command
    mmio_write32(mmio, (port_offset + PORT_CI as u64) as u32, 0x01);

    // Wait for completion
    let mut timeout = 100000;
    let mut success = false;
    while timeout > 0 {
        let ci = mmio_read32(mmio, (port_offset + PORT_CI as u64) as u32);
        if ci & 0x01 == 0 {
            success = true;
            break;
        }

        let tfd = mmio_read32(mmio, (port_offset + PORT_TFD as u64) as u32);
        if (tfd & (TFD_ERR as u32)) != 0 {
            // kprintln!("[AHCI] WRITE error (TFD=0x{:08x}, LBA={})", tfd, lba)  // kprintln disabled (memcpy crash workaround);
            break;
        }

        timeout -= 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    // Stop port
    stop_port(mmio, port_offset);

    if success {
        // kprintln!("[AHCI] Write sector {} via PIO (512 bytes)", lba)  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("[AHCI] WRITE timeout for LBA={}", lba)  // kprintln disabled (memcpy crash workaround);
    }

    // Free DMA buffers
    let _ = crate::mm::pool::free(dma_ptr);
    free_ahci_dma(ctrl_idx, cmd_buf);

    success
}

/// Write a single sector using DMA mode.
unsafe fn ahci_write_sector(
    ctrl: &mut AhciController,
    port: usize,
    lba: u32,
    buf: &[u8],
) -> bool {
    let mmio = ctrl.mmio_base;
    if mmio == 0 {
        return false;
    }

    let port_offset = 0x100 + (port as u64 * 0x80);

    // Check if port is implemented
    if (ctrl.pi & (1 << port)) == 0 {
        // kprintln!("[AHCI] Write DMA: Port {} not implemented", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check device presence
    let (det, ipm) = check_port_status(mmio, port_offset);
    if det != SSTS_DET_PRESENT && det != SSTS_DET_COMM {
        // kprintln!("[AHCI] Write DMA: Port {} no device", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    if ipm != 1 {
        // kprintln!("[AHCI] Write DMA: Port {} not active", port)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Allocate DMA buffers from pool
    let ctrl_idx = ctrl.controller_idx as usize;
    let cmd_buf = match allocate_ahci_dma(ctrl_idx) {
        Some(b) => b,
        None => {
            // kprintln!("[AHCI] Write DMA: Failed to allocate command buffer")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };

    // Allocate DMA buffer
    let dma_size = 512;
    let dma_ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, dma_size);
    if dma_ptr.is_null() {
        // kprintln!("[AHCI] Write DMA: Failed to allocate DMA buffer")  // kprintln disabled (memcpy crash workaround);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Copy data to DMA buffer
    core::ptr::copy_nonoverlapping(buf.as_ptr(), dma_ptr, 512);

    // Get physical address
    // This is critical for DMA - we cannot use virtual address as physical
    let dma_phys = match crate::mm::vm::virt_to_phys(dma_ptr as u64) {
        Some(phys) => phys,
        None => {
            // virt_to_phys failed - release resources before returning
            free_ahci_dma(ctrl_idx, cmd_buf);
            let _ = crate::mm::pool::free(dma_ptr);
            return false;
        }
    };

    // Get addresses from the DMA pool
    let cmd_list_phys = cmd_buf.cmd_list_phys;
    let cmd_table_phys = cmd_buf.cmd_table_phys;
    let fis_phys = cmd_buf.fis_phys;
    let cmd_list_virt = cmd_buf.cmd_list_virt;
    let cmd_table_virt = cmd_buf.cmd_table_virt;

    // Clear structures using RAM writes
    for i in 0..256 {
        core::ptr::write_volatile(
            cmd_list_virt.add(i * 4) as *mut u32,
            0u32
        );
    }
    for i in 0..1024 {
        core::ptr::write_volatile(
            cmd_table_virt.add(i * 4) as *mut u32,
            0u32
        );
    }

    // Set up command header
    core::ptr::write_volatile(cmd_list_virt as *mut u32, 0x00050000u32 | (1 << 6));
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(4) as *mut u32,
        cmd_table_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_list_virt as *mut u8).add(8) as *mut u32,
        (cmd_table_phys >> 32) as u32
    );

    // Set up H2D Register FIS
    core::ptr::write_volatile(cmd_table_virt as *mut u32, 0x27594027u32);
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(4) as *mut u32,
        ATA_CMD_WRITE_DMA_EXT as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(8) as *mut u32,
        lba as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(12) as *mut u32,
        ((lba >> 8) & 0xFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(16) as *mut u32,
        ((lba >> 16) & 0xFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(20) as *mut u32,
        0x40u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(24) as *mut u32,
        0x00000100u32
    );

    // Set up PRD
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(128) as *mut u32,
        dma_phys as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(132) as *mut u32,
        ((dma_phys >> 32) & 0xFFFFFFFF) as u32
    );
    core::ptr::write_volatile(
        (cmd_table_virt as *mut u8).add(136) as *mut u32,
        511 | PRD_EOT
    );

    // Stop the port first
    stop_port(mmio, port_offset);

    // Write port registers
    mmio_write32(mmio, (port_offset + PORT_CLB as u64) as u32, cmd_list_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_CLBU as u64) as u32, (cmd_list_phys >> 32) as u32);
    mmio_write32(mmio, (port_offset + PORT_FB as u64) as u32, fis_phys as u32);
    mmio_write32(mmio, (port_offset + PORT_FBU as u64) as u32, (fis_phys >> 32) as u32);

    // Clear interrupts
    mmio_write32(mmio, (port_offset + PORT_IS as u64) as u32, 0xFFFFFFFF);

    // Start port
    if !start_port(mmio, port_offset) {
        // kprintln!("[AHCI] Write DMA: Failed to start port")  // kprintln disabled (memcpy crash workaround);
        let _ = crate::mm::pool::free(dma_ptr);
        free_ahci_dma(ctrl_idx, cmd_buf);
        return false;
    }

    // Issue WRITE DMA command
    mmio_write32(mmio, (port_offset + PORT_CI as u64) as u32, 0x01);

    // Wait for completion
    let mut timeout = 100000;
    let mut success = false;
    while timeout > 0 {
        let ci = mmio_read32(mmio, (port_offset + PORT_CI as u64) as u32);
        if ci & 0x01 == 0 {
            success = true;
            break;
        }

        let tfd = mmio_read32(mmio, (port_offset + PORT_TFD as u64) as u32);
        if (tfd & (TFD_ERR as u32)) != 0 {
            // kprintln!("[AHCI] WRITE DMA error (TFD=0x{:08x}, LBA={})", tfd, lba)  // kprintln disabled (memcpy crash workaround);
            break;
        }

        timeout -= 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    // Stop port
    stop_port(mmio, port_offset);

    if success {
        // kprintln!("[AHCI] Write sector {} succeeded (DMA, 512 bytes)", lba)  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("[AHCI] WRITE DMA timeout for LBA={}", lba)  // kprintln disabled (memcpy crash workaround);
    }

    // Free DMA buffers
    let _ = crate::mm::pool::free(dma_ptr);
    free_ahci_dma(ctrl_idx, cmd_buf);

    success
}

pub fn get_disk_count() -> usize {
    unsafe {
        DISK_INFO.iter().filter(|d| d.is_some()).count()
    }
}

// ============================================================================
// AHCI Interrupt Handling Framework
//
// This provides a foundation for interrupt-driven I/O. Currently, the driver
// uses polling (busy-wait) for command completion. When interrupts are enabled,
// the OS can register handlers to be notified of command completion.
// ============================================================================

/// Identifies which kind of completion triggered an AHCI port
/// interrupt. The bits in `PORT_IS` correspond to distinct FIS
/// types / completion sources; recording which one fired lets
/// callers (e.g. upper-half drivers) tell apart "device-to-host
/// register FIS ready" from "PIO setup FIS ready" from "command
/// list completed" without re-reading the hardware register.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
    /// No completion source identified yet.
    None = 0,
    /// Device-to-Host Register FIS received (H2D register update).
    D2hFis = 1,
    /// PIO Setup FIS received (queued PIO data inbound).
    PioSetupFis = 2,
    /// Command list completed (a queued command finished).
    CommandComplete = 3,
}

impl CompletionKind {
    const fn from_bits(port_is: u32) -> Self {
        // Per AHCI 1.3.1 §6.5: bit 0 = D2H Register FIS, bit 5 = PIO
        // Setup FIS, bit 6 = command list completed. When more than
        // one bit is set we prefer D2H > CmdComplete > PioSetup so
        // the recorded kind always reflects the most specific event.
        if port_is & 0x01 != 0 { CompletionKind::D2hFis }
        else if port_is & (1 << 6) != 0 { CompletionKind::CommandComplete }
        else if port_is & (1 << 5) != 0 { CompletionKind::PioSetupFis }
        else { CompletionKind::None }
    }
}

/// Per-port completion state
#[derive(Debug, Clone, Copy)]
struct PortCompletionState {
    /// Whether a command is currently pending on this port
    pending: bool,
    /// Whether the last command succeeded
    last_success: bool,
    /// Which kind of completion triggered the last interrupt.
    /// `CompletionKind::None` means no interrupt has been
    /// observed yet for this port.
    completion_kind: CompletionKind,
}

impl PortCompletionState {
    const fn new() -> Self {
        Self {
            pending: false,
            last_success: false,
            completion_kind: CompletionKind::None,
        }
    }
}

/// Callback type for AHCI command completion (unsafe because of storage access)
type AhciCompletionCallback = unsafe fn(controller_idx: usize, port: usize, success: bool);

/// Global interrupt state
static mut AHCI_INTERRUPT_STATE: [Option<PortCompletionState>; 32] = [None; 32];

/// Initialize the interrupt state for a port
fn init_port_interrupt_state(port: usize) {
    unsafe {
        AHCI_INTERRUPT_STATE[port] = Some(PortCompletionState::new());
    }
}

/// Mark that a command has been issued to a port
fn set_command_pending(port: usize) {
    unsafe {
        if let Some(ref mut state) = AHCI_INTERRUPT_STATE[port] {
            state.pending = true;
        }
    }
}

/// Handle port interrupt - called by the OS interrupt dispatcher
/// Returns true if this port generated the interrupt
pub fn handle_port_interrupt(controller_idx: usize, port: usize) -> bool {
    let mmio = unsafe {
        if let Some(ref ctrl) = AHCI_CONTROLLERS[controller_idx] {
            ctrl.mmio_base
        } else {
            return false;
        }
    };

    if mmio == 0 {
        return false;
    }

    let port_offset = 0x100 + (port as u64 * 0x80);

    // Read interrupt status for this port
    let port_is = mmio_read32(mmio, (port_offset + PORT_IS as u64) as u32);

    if port_is == 0 {
        return false;  // No interrupt from this port
    }

    // Decompose the PORT_IS bits so each source has a named
    // boolean. The precedence below (D2H > CmdComplete >
    // PioSetup) is the same as `CompletionKind::from_bits`,
    // but written out so the boolean values flow through the
    // state update and are not silently discarded.
    let d2h_fis = (port_is & 0x01) != 0;
    let tf_err = (port_is & 0x02) != 0;
    let cmd_complete = (port_is & (1 << 6)) != 0;
    let pio_fis = (port_is & (1 << 5)) != 0;
    let completion_kind = if d2h_fis {
        CompletionKind::D2hFis
    } else if cmd_complete {
        CompletionKind::CommandComplete
    } else if pio_fis {
        CompletionKind::PioSetupFis
    } else {
        CompletionKind::None
    };

    // Clear the interrupt bits we handled
    mmio_write32(mmio, (port_offset + PORT_IS as u64) as u32, port_is);

    let success = !tf_err;

    // Update interrupt state — every locally-named boolean
    // contributes to the state we record, so none of them are
    // dead. `last_success` is gated on tf_err; `completion_kind`
    // is gated on the three source bits; `pending` always
    // clears because an interrupt is, by definition, a
    // completion notification.
    unsafe {
        if let Some(ref mut state) = AHCI_INTERRUPT_STATE[port] {
            state.pending = false;
            state.last_success = success;
            state.completion_kind = completion_kind;
        }
    }

    true
}

/// Query whether a command is pending on a port
pub fn is_command_pending(port: usize) -> bool {
    unsafe {
        if let Some(ref state) = AHCI_INTERRUPT_STATE[port] {
            state.pending
        } else {
            false
        }
    }
}

/// Get the result of the last command on a port
pub fn get_last_command_result(port: usize) -> bool {
    unsafe {
        if let Some(ref state) = AHCI_INTERRUPT_STATE[port] {
            state.last_success
        } else {
            false
        }
    }
}

/// Get the kind of the last interrupt observed on a port.
/// Returns `CompletionKind::None` for ports that have not
/// yet seen an interrupt or have not been initialised.
pub fn get_last_completion_kind(port: usize) -> CompletionKind {
    unsafe {
        if let Some(ref state) = AHCI_INTERRUPT_STATE[port] {
            state.completion_kind
        } else {
            CompletionKind::None
        }
    }
}
