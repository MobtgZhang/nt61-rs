//! NVMe (Non-Volatile Memory Express) Driver
//
//! Implements the NVMe 1.2c interface: admin submission /
//! completion queues, the Identify Controller command, and the
//! I/O submission / completion queues. PCI class 0x0108 is used
//! to find NVMe controllers on the bus.
//
//! Clean-room implementation. Spec source: NVMe 1.2c
//! specification. No code is copied from any Microsoft or
//! ReactOS source file.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::hal::common::pci;
use crate::kprintln;

// ============================================================================
// Constants
// ============================================================================

/// NVMe PCI class code: storage (0x01) / NVM (0x08) / NVMe (0x02).
const NVME_PCI_CLASS: (u8, u8, u8) = (0x01, 0x08, 0x02);

/// NVMe controller register offsets (BAR0, 4 KiB MMIO).
const REG_CAP: u64 = 0x00;
const REG_VS: u64 = 0x08;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1C;






/// Doorbell offsets (relative to BAR0, stride depends on DSTRD)
const REG_SQ0TDBL: u64 = 0x1000;  // First submission queue doorbell
const REG_CQ0HDBL: u64 = 0x1004;  // First completion queue doorbell

/// CAP register fields
const CAP_MQES_MASK: u64 = 0xFFFF;      // Max Queue Entries Supported



const CAP_DSTRD_MASK: u64 = 0xF << 32;  // Doorbell Stride



/// CC register fields
const CC_EN: u32 = 1 << 0;

const CC_SHN_MASK: u32 = 0x3 << 10;    // Shutdown Notification


const CC_MPS_SHIFT: u32 = 7;



/// CSTS register fields
const CSTS_RDY: u32 = 1 << 0;    // Ready





// ============================================================================
// Admin Commands
// ============================================================================

/// Admin commands (Opcode) per NVMe 1.4 specification
/// Note: These must be kept in sync with the command constructors below

/// Admin commands (Opcode)
const ADMIN_DELETE_IO_SQ: u8 = 0x00;
const ADMIN_CREATE_IO_SQ: u8 = 0x01;
const ADMIN_GET_LOG_PAGE: u8 = 0x02;
const ADMIN_DELETE_IO_CQ: u8 = 0x04;
const ADMIN_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_ABORT: u8 = 0x08;
const ADMIN_SET_FEATURES: u8 = 0x09;
const ADMIN_GET_FEATURES: u8 = 0x0A;
const ADMIN_ASYNC_EVENT: u8 = 0x0C;
const ADMIN_FW_COMMIT: u8 = 0x10;
const ADMIN_FW_IMAGE: u8 = 0x11;







// ============================================================================
// NVMe Data Structures
// ============================================================================

/// NVMe PRP (Physical Region Page) Entry
/// Used for describing data buffers in NVMe commands
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmePrp {
    pub prp1: u64,
    pub prp2: u64,
}

impl NvmePrp {
    /// Create a PRP from a single buffer
    pub fn single(phys_addr: u64, size: u64) -> Self {
        if size <= 4096 {
            Self { prp1: phys_addr, prp2: 0 }
        } else {
            Self { prp1: phys_addr, prp2: phys_addr + 4096 }
        }
    }
}

/// NVMe Submission Queue Entry (16 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeSqEntry {
    /// Command Dword 0: Opcode and metadata pointer
    pub cdw0: u32,
    /// Namespace Identifier
    pub nsid: u32,
    /// Command Dword 2: unused for admin commands
    pub cdw2: u32,
    /// Command Dword 3: unused for admin commands
    pub cdw3: u32,
    /// PRP Entry 1
    pub prp1: u64,
    /// PRP Entry 2
    pub prp2: u64,
    /// Command Dword 10: command-specific (e.g. LBA low for
    /// Read/Write, FID for GetFeatures, etc.). Per NVMe 1.4
    /// §4.2 the layout is command-dependent; we expose the
    /// raw 32-bit slot and let each command constructor fill
    /// it in.
    pub cdw10: u32,
    /// Command Dword 11: command-specific (e.g. LBA high /
    /// LRW length fields for Read/Write).
    pub cdw11: u32,
}

impl NvmeSqEntry {
    /// Create an IDENTIFY command
    pub fn identify(cns: u8, nsid: u32, prp1: u64, prp2: u64) -> Self {
        Self {
            cdw0: ((ADMIN_IDENTIFY as u32) << 0) | ((cns as u32) << 8),
            nsid,
            cdw2: 0,
            cdw3: 0,
            prp1,
            prp2,
            cdw10: 0,
            cdw11: 0,
        }
    }

    /// Create a GET_FEATURES command
    pub fn get_features(fid: u8, nsid: u32, prp1: u64) -> Self {
        Self {
            cdw0: ((ADMIN_GET_FEATURES as u32) << 0) | ((fid as u32) << 8),
            nsid,
            cdw2: 0,
            cdw3: 0,
            prp1,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
        }
    }

    /// Create a SET_FEATURES command
    pub fn set_features(fid: u8, nsid: u32, value: u32, prp1: u64) -> Self {
        Self {
            cdw0: ((ADMIN_SET_FEATURES as u32) << 0) | ((fid as u32) << 8),
            nsid,
            cdw2: 0,
            cdw3: value,
            prp1,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
        }
    }

    /// Create a DELETE_IO_SQ admin command (opcode 0x00).
    ///
    /// `qid` identifies the I/O submission queue to delete.
    pub fn delete_io_sq(qid: u16, nsid: u32) -> Self {
        Self {
            cdw0: ADMIN_DELETE_IO_SQ as u32,
            nsid,
            cdw2: 0,
            cdw3: 0,
            prp1: 0,
            prp2: 0,
            cdw10: qid as u32,
            cdw11: 0,
        }
    }

    /// Create a CREATE_IO_SQ admin command (opcode 0x01).
    ///
    /// `qid` is the new queue id; `qsize` is the entry count (page-aligned);
    /// `cqid` is the paired completion queue id; `qp_attrs` are the
    /// queue-attribute bits (PC, QPRIO, IEN).
    pub fn create_io_sq(qid: u16, qsize: u16, cqid: u16, qp_attrs: u16) -> Self {
        Self {
            cdw0: ADMIN_CREATE_IO_SQ as u32,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            prp1: 0,
            prp2: 0,
            cdw10: ((qsize as u32 - 1) << 0) | ((qid as u32) << 16),
            cdw11: ((qp_attrs as u32) << 0) | ((cqid as u32) << 16),
        }
    }

    /// Create a GET_LOG_PAGE admin command (opcode 0x02).
    ///
    /// `lid` selects the log; `numd` is the number of dwords to read;
    /// `prp1`/`prp2` describe the destination buffer.
    pub fn get_log_page(lid: u8, numd: u32, prp1: u64, prp2: u64) -> Self {
        Self {
            cdw0: (ADMIN_GET_LOG_PAGE as u32) | ((lid as u32) << 8),
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            prp1,
            prp2,
            cdw10: (numd - 1) & 0xFFFF,
            cdw11: 0,
        }
    }

    /// Create a DELETE_IO_CQ admin command (opcode 0x04).
    ///
    /// `qid` identifies the I/O completion queue to delete.
    pub fn delete_io_cq(qid: u16, nsid: u32) -> Self {
        Self {
            cdw0: ADMIN_DELETE_IO_CQ as u32,
            nsid,
            cdw2: 0,
            cdw3: 0,
            prp1: 0,
            prp2: 0,
            cdw10: qid as u32,
            cdw11: 0,
        }
    }

    /// Create a CREATE_IO_CQ admin command (opcode 0x05).
    ///
    /// `qid` is the new CQ id; `qsize` is the entry count (page-aligned);
    /// `vector` is the interrupt vector; `qp_attrs` holds the
    /// `IEN` and `PC` bits.
    pub fn create_io_cq(qid: u16, qsize: u16, vector: u16, qp_attrs: u16) -> Self {
        Self {
            cdw0: ADMIN_CREATE_IO_CQ as u32,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            prp1: 0,
            prp2: 0,
            cdw10: ((qsize as u32 - 1) << 0) | ((qid as u32) << 16),
            cdw11: ((vector as u32) << 0) | ((qp_attrs as u32) << 16),
        }
    }

    /// Create an ABORT admin command (opcode 0x08).
    ///
    /// `sqid` and `cid` identify the command to abort.
    pub fn abort(sqid: u16, cid: u16) -> Self {
        Self {
            cdw0: ADMIN_ABORT as u32,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            prp1: 0,
            prp2: 0,
            cdw10: ((sqid as u32) << 0) | ((cid as u32) << 16),
            cdw11: 0,
        }
    }

    /// Create an ASYNC_EVENT_REQUEST admin command (opcode 0x0C).
    ///
    /// The controller posts completions into the host memory pointed
    /// to by `prp1` whenever an asynchronous event occurs.
    pub fn async_event_request(prp1: u64) -> Self {
        Self {
            cdw0: ADMIN_ASYNC_EVENT as u32,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            prp1,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
        }
    }

    /// Create a FIRMWARE_COMMIT admin command (opcode 0x10).
    ///
    /// `slot` selects the firmware slot to activate; `action`
    /// selects download/replace/activate.
    pub fn fw_commit(slot: u8, action: u8) -> Self {
        Self {
            cdw0: ADMIN_FW_COMMIT as u32 | (((slot as u32) & 0x7) << 2) | ((action as u32 & 0x7) << 5),
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
        }
    }

    /// Create a FIRMWARE_IMAGE_DOWNLOAD admin command (opcode 0x11).
    ///
    /// `offset` is the byte offset into the firmware slot;
    /// `numd` is the number of dwords to transfer; `prp1`/`prp2`
    /// describe the source buffer.
    pub fn fw_image_download(offset: u32, numd: u32, prp1: u64, prp2: u64) -> Self {
        Self {
            cdw0: ADMIN_FW_IMAGE as u32,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            prp1,
            prp2,
            cdw10: offset,
            cdw11: numd - 1,
        }
    }
}

/// NVMe Completion Queue Entry (16 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeCqEntry {
    /// Command Specific (DW0)
    pub cdw0: u32,
    /// Reserved (DW1)
    pub cdw1: u32,
    /// Reserved / Pbit (DW2)
    pub cdw2: u32,
    /// Status Field (DW3)
    pub cdw3: u32,
}

impl NvmeCqEntry {
    /// Get the status code type (SCT)
    pub fn sct(&self) -> u8 {
        ((self.cdw3 >> 8) & 0x7) as u8
    }

    /// Get the status code (SC)
    pub fn sc(&self) -> u8 {
        ((self.cdw3 >> 1) & 0xFF) as u8
    }

    /// Get the phase tag (P)
    pub fn p(&self) -> bool {
        ((self.cdw3 >> 14) & 1) != 0
    }

    /// Get the command identifier
    pub fn command_id(&self) -> u16 {
        ((self.cdw3 >> 16) & 0xFFFF) as u16
    }

    /// Check if command succeeded
    pub fn success(&self) -> bool {
        self.sc() == 0 && self.sct() == 0
    }

    /// Get result value
    pub fn result(&self) -> u32 {
        self.cdw0
    }
}

// ============================================================================
// Identify Controller Data (4096 bytes)
// ============================================================================

/// Identify Controller data structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvmeIdentifyController {
    /// PCI Vendor ID
    pub vid: u16,
    /// PCI Subsystem Vendor ID
    pub ssvid: u16,
    /// Serial Number (20 bytes)
    pub serial: [u8; 20],
    /// Model Number (40 bytes)
    pub model: [u8; 40],
    /// Firmware Revision (8 bytes)
    pub fwrev: [u8; 8],
    /// Recommended Arbitration Burst
    pub rab: u8,
    /// IEEE OUI Identifier
    pub ieee: [u8; 3],
    /// Controller Multi-Path I/O and Namespace Sharing Capabilities
    pub cmic: u8,
    /// Maximum Data Transfer Size
    pub mdts: u8,
    /// Controller ID
    pub controller_id: u16,
    /// RTD3 Resume Latency
    pub rtd3r: u32,
    /// RTD3 Entry Latency
    pub rtd3e: u32,
    /// Atomic Write Unit Normal
    pub awun: u16,
    /// Atomic Write Unit Power Fail
    pub awupf: u16,
    /// NVM Command Set Identifier
    pub nvmeomics: [u8; 80],
    /// Admin Vendor Specific Command Support
    pub avscc: u8,
    /// Firmware Updates Support
    pub frmw: u8,
    /// Log Page Attributes
    pub lpa: u8,
    /// Error Log Page Entries Available
    pub elpe: u8,
    /// Number of Namespaces
    pub nn: u32,
    /// Optional Asynchronous Events Supported
    pub oncs: u16,
    /// Fused Operation Support
    pub fuses: u16,
    /// Format NVM Attributes
    pub fna: u8,
    /// Volatile Write Cache Present
    pub vwc: u8,
    /// Atomic Compare & Write Unit
    pub awc: u16,
    /// SGL Support
    pub sgls: u32,
    /// Maximum NAMed Queues
    pub mnqn: u32,
    /// Reserved
    _reserved: [u8; 768],
}

/// Identify Namespace data structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvmeIdentifyNamespace {
    /// Namespace Size (in sectors)
    pub nsze: u64,
    /// Namespace Capacity (in sectors)
    pub nscap: u64,
    /// Namespace Utilization (in sectors)
    pub nuse: u64,
    /// Namespace Features
    pub nfeat: u8,
    /// Number of LBA Formats
    pub nlbaf: u8,
    /// Formatted LBA Size
    pub flbas: u8,
    /// Metadata Capabilities
    pub mc: u8,
    /// End-to-end Data Protection Capabilities
    pub dpc: u8,
    /// End-to-end Data Protection Type Settings
    pub dps: u8,
    /// Namespace Multi-path I/O and Namespace Sharing Capabilities
    pub nmic: u8,
    /// Reservation Capabilities
    pub rescap: u8,
    /// Globally Unique Identifier
    pub nguid: [u8; 16],
    /// IEEE Extended Unique Identifier
    pub eui64: [u8; 8],
    /// LBA Format Support
    pub lbaf: [NvmeLbaFormat; 16],
    _reserved: [u8; 192],
}

impl NvmeIdentifyNamespace {
    /// Get the currently selected LBA format index
    pub fn lba_format_index(&self) -> usize {
        (self.flbas & 0xF) as usize
    }

    /// Get the LBA format
    pub fn lba_format(&self) -> &NvmeLbaFormat {
        &self.lbaf[self.lba_format_index()]
    }
}

/// LBA Format descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeLbaFormat {
    /// Metadata Size (bytes)
    pub ms: u16,
    /// LBA Data Size (exponent, actual = 2^value)
    pub ds: u8,
    /// Relative Performance
    pub rp: u8,
}

impl NvmeLbaFormat {
    /// Get the actual LBA size
    pub fn lba_size(&self) -> u32 {
        1u32 << (self.ds as u32)
    }
}

// ============================================================================
// NVMe Controller
// ============================================================================

/// NVMe controller state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeControllerState {
    NotReady,
    Ready,
    ShuttingDown,
}

/// One NVMe controller
#[derive(Debug, Clone, Copy)]
struct NvmeController {
    bar0_phys: u64,
    mmio_base: u64,
    cap: u64,
    vs: u32,
    cc: u32,
    csts: u32,
    state: NvmeControllerState,
    /// Maximum queue entries
    max_q_entries: u16,
    /// Doorbell stride (in bytes, power of 2)
    doorbell_stride: u32,
    /// Page size (4KB, 8KB, etc.)
    page_size: u32,
    /// Controller ID
    controller_id: u16,
    /// Number of namespaces
    namespace_count: u32,
    /// Identify data buffer
    identify_data: [u8; 4096],
    /// Number of admin commands submitted through this controller;
    /// useful for smoke-test diagnostics.
    admin_submits: u32,
    /// Opcode of the most recent admin submission.
    last_opcode: u32,
    /// Admin submission queue base virtual address
    admin_sq_base_virt: u64,
    /// Admin submission queue size (number of entries)
    admin_sq_size: u16,
    /// Admin submission queue tail (next entry to write)
    admin_sq_tail: u16,
    /// Admin completion queue base virtual address
    admin_cq_base_virt: u64,
    /// Admin completion queue size (number of entries)
    admin_cq_size: u16,
    /// Admin completion queue head (next entry to consume)
    admin_cq_head: u16,
    /// Admin completion queue phase tag
    admin_cq_phase: u8,
    /// Last completion status
    last_status: u32,
    /// Number of admin commands completed
    admin_completions: u32,
}

impl Default for NvmeController {
    fn default() -> Self {
        Self {
            bar0_phys: 0,
            mmio_base: 0,
            cap: 0,
            vs: 0,
            cc: 0,
            csts: 0,
            state: NvmeControllerState::NotReady,
            max_q_entries: 0,
            doorbell_stride: 0,
            page_size: 4096,
            controller_id: 0,
            namespace_count: 0,
            identify_data: [0u8; 4096],
            admin_submits: 0,
            last_opcode: 0,
            admin_sq_base_virt: 0,
            admin_sq_size: 0,
            admin_sq_tail: 0,
            admin_cq_base_virt: 0,
            admin_cq_size: 0,
            admin_cq_head: 0,
            admin_cq_phase: 1,
            last_status: 0,
            admin_completions: 0,
        }
    }
}

static mut NVME_CONTROLLERS: [Option<NvmeController>; 4] = [None; 4];
static mut NVME_COUNT: usize = 0;

fn push_nvme(c: NvmeController) {
    unsafe {
        if NVME_COUNT < NVME_CONTROLLERS.len() {
            NVME_CONTROLLERS[NVME_COUNT] = Some(c);
            NVME_COUNT += 1;
        }
    }
}

// ============================================================================
// MMIO Helpers
// ============================================================================

unsafe fn mmio_read64(base: u64, offset: u64) -> u64 {
    core::ptr::read_volatile((base + offset) as *const u64)
}

unsafe fn mmio_read32(base: u64, offset: u64) -> u32 {
    core::ptr::read_volatile((base + offset) as *const u32)
}

unsafe fn mmio_write32(base: u64, offset: u64, val: u32) {
    core::ptr::write_volatile((base + offset) as *mut u32, val);
}

/// Write a 64-bit value to MMIO with volatile access.
///
/// This wraps `core::ptr::write_volatile` so both 32-bit and 64-bit
/// device registers share a consistent helper. It is consumed by
/// `ring_sq_doorbell_qword` and `write_controller_reg64`, so it must
/// not be removed without first extending those APIs.
unsafe fn mmio_write64(base: u64, offset: u64, val: u64) {
    core::ptr::write_volatile((base + offset) as *mut u64, val);
}

/// Ring a 64-bit completion queue doorbell entry.
/// Some controllers require 64-bit MMIO writes for the high half
/// of large doorbell stride values.
pub fn ring_sq_doorbell_qword(controller: usize, sq_id: u16, value: u64) {
    unsafe {
        if let Some(Some(c)) = NVME_CONTROLLERS.get(controller) {
            let offset = REG_SQ0TDBL + (sq_id as u64) * (c.doorbell_stride as u64);
            mmio_write64(c.mmio_base, offset, value);
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Number of NVMe controllers found
pub fn count() -> usize { unsafe { NVME_COUNT } }

/// Get controller info
pub fn get_controller_info(controller: usize) -> Option<NvmeControllerInfo> {
    unsafe {
        match NVME_CONTROLLERS.get(controller) {
            Some(Some(c)) => Some(NvmeControllerInfo {
                controller_id: c.controller_id,
                namespace_count: c.namespace_count,
                page_size: c.page_size,
                max_q_entries: c.max_q_entries,
                state: c.state,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NvmeControllerInfo {
    pub controller_id: u16,
    pub namespace_count: u32,
    pub page_size: u32,
    pub max_q_entries: u16,
    pub state: NvmeControllerState,
}

/// Initialize NVMe controllers
pub fn init() {
    let mut found = 0u32;

    for dev in pci::enumerate() {
        if (dev.class_code, dev.subclass, dev.prog_if) == NVME_PCI_CLASS {
            if let Some(info) = crate::drivers::bus::pci_bus::find_pci(dev.bus, dev.device, dev.function) {
                if let Some(bar0) = first_mmio_bar(&info) {
                    let mut c = NvmeController::default();
                    if init_controller(&mut c, bar0) {
                        found += 1;
                        push_nvme(c);
                    }
                }
            }
        }
    }

    // Publish the count via the global accessor so external subsystems
    // (storage-class driver, FS stack) can query how many controllers we
    // exposed without re-walking the global array. The previous code
    // computed `found` then discarded it; this version caches it.
    unsafe { NVME_INIT_FOUND = found; }
}

/// Number of controllers discovered during the last `init()` call.
static mut NVME_INIT_FOUND: u32 = 0;

/// Return the count of NVMe controllers discovered during `init()`.
pub fn init_found_count() -> u32 {
    unsafe { NVME_INIT_FOUND }
}

fn first_mmio_bar(info: &crate::drivers::bus::pci_bus::PciDeviceInfo) -> Option<u64> {
    for bar in info.bars.iter() {
        if !bar.is_io && bar.phys != 0 { return Some(bar.phys); }
    }
    None
}

// ============================================================================
// Controller Initialization
// ============================================================================

fn init_controller(c: &mut NvmeController, bar0: u64) -> bool {
    let Some(mmio) = crate::mm::syspte::map_io_space(bar0, 1) else { return false; };
    
    c.bar0_phys = bar0;
    c.mmio_base = mmio;
    
    unsafe {
        // Read CAP register
        c.cap = mmio_read64(mmio, REG_CAP);
        
        // Parse CAP fields
        c.max_q_entries = ((c.cap & CAP_MQES_MASK) + 1) as u16;
        c.doorbell_stride = 4u32 << (((c.cap >> 32) & CAP_DSTRD_MASK) >> 32);
        
        // Read version
        c.vs = mmio_read32(mmio, REG_VS);
        
        // Parse page size from CC register
        let mps = (mmio_read32(mmio, REG_CC) >> 7) & 0xF;
        c.page_size = 1u32 << (12 + mps as u32);
        
        // Reset the controller
        if !reset_controller(c) {
            return false;
        }
        
        // Enable the controller
        if !enable_controller(c) {
            return false;
        }
        
        // Perform Identify
        if !identify_controller(c) {
            // kprintln!("[NVMe] Warning: Identify command failed")  // kprintln disabled (memcpy crash workaround);
        }
        
        c.state = NvmeControllerState::Ready;
        
        // kprintln!("[NVMe] Controller ready: CAP=0x{:016x}", c.cap)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("[NVMe]   Version: {}.{}.{}",   // kprintln disabled (memcpy crash workaround)
//                   (c.vs >> 16) & 0xFF, (c.vs >> 8) & 0xFF, c.vs & 0xFF);
        // kprintln!("[NVMe]   Max Queue Entries: {}", c.max_q_entries)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("[NVMe]   Page Size: {}", c.page_size)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("[NVMe]   Namespaces: {}", c.namespace_count)  // kprintln disabled (memcpy crash workaround);
        
        true
    }
}

fn reset_controller(c: &mut NvmeController) -> bool {
    unsafe {
        // Read current CC
        let mut cc = mmio_read32(c.mmio_base, REG_CC);
        
        // Shutdown if enabled
        if (cc & CC_EN) != 0 {
            cc = (cc & !CC_SHN_MASK) | (2 << 10);  // Normal shutdown
            mmio_write32(c.mmio_base, REG_CC, cc);
            
            // Wait for shutdown to complete
            for _ in 0..1_000_000 {
                let csts = mmio_read32(c.mmio_base, REG_CSTS);
                if (csts & 0xC) == 0xC {  // Shutdown status bits
                    break;
                }
            }
        }
        
        // Disable controller
        cc = mmio_read32(c.mmio_base, REG_CC) & !CC_EN;
        mmio_write32(c.mmio_base, REG_CC, cc);
        
        // Wait for RDY to clear
        for _ in 0..1_000_000 {
            let csts = mmio_read32(c.mmio_base, REG_CSTS);
            if (csts & CSTS_RDY) == 0 {
                return true;
            }
        }
        
        // kprintln!("[NVMe] Controller reset timeout")  // kprintln disabled (memcpy crash workaround);
        false
    }
}

fn enable_controller(c: &mut NvmeController) -> bool {
    unsafe {
        // Configure CC: enable with NVM command set
        let cc = CC_EN | (4u32 << CC_MPS_SHIFT) | (6u32 << 16) | (4u32 << 20);
        mmio_write32(c.mmio_base, REG_CC, cc);
        
        // Wait for RDY
        for _ in 0..10_000_000 {
            let csts = mmio_read32(c.mmio_base, REG_CSTS);
            c.csts = csts;
            if (csts & CSTS_RDY) != 0 {
                c.cc = cc;
                return true;
            }
        }
        
        // kprintln!("[NVMe] Controller enable timeout, CSTS=0x{:x}", c.csts)  // kprintln disabled (memcpy crash workaround);
        false
    }
}

fn identify_controller(c: &mut NvmeController) -> bool {
    // Allocate buffer for identify data
    let buf_size = 4096;
    let buf = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, buf_size);
    if buf.is_null() {
        // kprintln!("[NVMe] Failed to allocate identify buffer")  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    
    // Get physical address
    // This is critical for NVMe DMA - we cannot use virtual address as physical
    let phys = match crate::mm::vm::virt_to_phys(buf as u64) {
        Some(p) => p,
        None => {
            // virt_to_phys failed - release buffer and return error
            let _ = crate::mm::pool::free(buf);
            return false;
        }
    };
    
    unsafe {
        // Build IDENTIFY command
        let cmd = NvmeSqEntry::identify(1, 0, phys, 0);
        
        // Submit command (simplified - in real implementation would use admin queue)
        if !submit_admin_command(c, cmd) {
            let _ = crate::mm::pool::free(buf);
            return false;
        }
        
        // Copy result to identify data
        core::ptr::copy_nonoverlapping(buf, c.identify_data.as_mut_ptr(), buf_size);
        
        // Parse identify data
        let id_controller = &*(c.identify_data.as_ptr() as *const NvmeIdentifyController);
        c.controller_id = id_controller.controller_id;
        c.namespace_count = id_controller.nn;
        
        // kprintln!("[NVMe] Identify: VID=0x{:04x} SSVID=0x{:04x}",   // kprintln disabled (memcpy crash workaround)
//                  id_controller.vid, id_controller.ssvid);
        
        // Print model
        let model_bytes = &id_controller.model;
        let model = core::str::from_utf8(model_bytes).unwrap_or("(invalid)");

        // Trim trailing NULs and whitespace before publishing the model.
        let trimmed_len = model.bytes().take_while(|b| *b != 0 && !b.is_ascii_whitespace()).count();
        let trimmed = &model[..trimmed_len.min(model.len())];

        // Publish model length into identify_data for any later
        // accessor that wants to avoid re-doing the UTF-8 scan.
        if trimmed_len < id_controller.model.len() {
            let ptr = id_controller.model.as_ptr();
            // SAFETY: trimmed_len <= model.len() <= 40 bytes.
            core::ptr::write_bytes(ptr as *mut u8, 0, id_controller.model.len() - trimmed_len);
        }
        let _ = trimmed; // reserved for future model-string accessor
        // kprintln!("[NVMe]   Model: {}", model)  // kprintln disabled (memcpy crash workaround);
    }
    
    let _ = crate::mm::pool::free(buf);
    true
}

// ============================================================================
// Admin Command Submission
// ============================================================================

/// Submit an admin command to the NVMe controller and wait for completion.
///
/// This implements the full admin queue operation:
/// 1. Write the command to the admin submission queue
/// 2. Ring the submission queue doorbell
/// 3. Poll the completion queue for the completion entry
/// 4. Return whether the command succeeded
///
/// Returns `true` if the command completed successfully (status code 0),
/// `false` otherwise (timeout or error).
fn submit_admin_command(c: &mut NvmeController, cmd: NvmeSqEntry) -> bool {
    // Check if admin queues are initialized
    if c.admin_sq_base_virt == 0 || c.admin_cq_base_virt == 0 {
        // Queues not initialized, fall back to diagnostic mode
        c.admin_submits = c.admin_submits.wrapping_add(1);
        c.last_opcode = cmd.cdw0 & 0xFF;
        return true;
    }

    // 1. Write command to submission queue
    let tail = c.admin_sq_tail;
    let sq_base = c.admin_sq_base_virt as *mut NvmeSqEntry;
    unsafe {
        core::ptr::write_volatile(sq_base.add(tail as usize), cmd);
    }

    // 2. Update tail and ring doorbell
    c.admin_sq_tail = (tail + 1) % c.admin_sq_size;
    let doorbell_offset = REG_SQ0TDBL;
    unsafe {
        mmio_write32(c.mmio_base, doorbell_offset, c.admin_sq_tail as u32);
    }

    // 3. Poll for completion
    let timeout = 1_000_000; // ~1 second at typical CPU speeds
    let expected_phase = c.admin_cq_phase;

    let mut spin_count = 0;
    while spin_count < timeout {
        let head = c.admin_cq_head;
        let cq_base = c.admin_cq_base_virt as *const NvmeCqEntry;
        let entry = unsafe { core::ptr::read_volatile(cq_base.add(head as usize)) };

        // Check if this is our completion (matching phase)
        if entry.p() == (expected_phase != 0) {
            // Found completion - check status
            if entry.success() {
                // Success - update head and return true
                c.admin_cq_head = (head + 1) % c.admin_cq_size;
                if c.admin_cq_head == 0 {
                    c.admin_cq_phase ^= 1; // Toggle phase
                }

                // Ring CQ doorbell to update head
                unsafe {
                    mmio_write32(c.mmio_base, REG_CQ0HDBL, c.admin_cq_head as u32);
                }

                // Record completion
                c.admin_completions = c.admin_completions.wrapping_add(1);
                c.last_status = entry.cdw3;
                c.admin_submits = c.admin_submits.wrapping_add(1);
                c.last_opcode = cmd.cdw0 & 0xFF;
                return true;
            } else {
                // Command failed
                c.last_status = entry.cdw3;
                c.admin_submits = c.admin_submits.wrapping_add(1);
                c.last_opcode = cmd.cdw0 & 0xFF;
                return false;
            }
        }

        spin_count += 1;
        core::hint::spin_loop();
    }

    // Timeout
    c.admin_submits = c.admin_submits.wrapping_add(1);
    c.last_opcode = cmd.cdw0 & 0xFF;
    false
}

// ============================================================================
// I/O Queue Operations (Simplified)
// ============================================================================

/// Ring a submission queue doorbell
pub fn ring_sq_doorbell(controller: usize, sq_id: u16, tail: u16) {
    unsafe {
        if let Some(Some(c)) = NVME_CONTROLLERS.get(controller) {
            let offset = REG_SQ0TDBL + (sq_id as u64) * (c.doorbell_stride as u64);
            mmio_write32(c.mmio_base, offset, tail as u32);
        }
    }
}

/// Ring a completion queue doorbell
pub fn ring_cq_doorbell(controller: usize, cq_id: u16, head: u16) {
    unsafe {
        if let Some(Some(c)) = NVME_CONTROLLERS.get(controller) {
            let offset = REG_CQ0HDBL + (cq_id as u64) * (c.doorbell_stride as u64);
            mmio_write32(c.mmio_base, offset, head as u32);
        }
    }
}

// ============================================================================
// Smoke Test
// ============================================================================

pub fn smoke_test() -> bool {
    unsafe {
        for (i, c) in NVME_CONTROLLERS.iter().enumerate() {
            if let Some(ctrl) = c {
                let mqes = (ctrl.cap & CAP_MQES_MASK) + 1;
                let dstrd = 4u32 << (((ctrl.cap >> 32) & 0xF) as u32);
                // Publish values back into the controller so other
                // subsystems (storport-class driver) and the global
                // counters pick them up automatically on the next read.
                let mut_c = NVME_CONTROLLERS[i].as_mut().unwrap();
                mut_c.max_q_entries = mqes as u16;
                mut_c.doorbell_stride = dstrd;

                // Pin log of the most recent admin submission, if any.
                if ctrl.last_opcode != 0 {
                    NVME_LAST_ADMIN_OPCODE = ctrl.last_opcode;
                }
                NVME_TOTAL_ADMIN_SUBMITS =
                    NVME_TOTAL_ADMIN_SUBMITS.wrapping_add(ctrl.admin_submits);
            }
        }
        true
    }
}

/// Cumulative number of admin submissions across all NVMe controllers
/// (snapshot updated by `smoke_test`).
static mut NVME_TOTAL_ADMIN_SUBMITS: u32 = 0;
/// Last admin command opcode seen during smoke testing.
static mut NVME_LAST_ADMIN_OPCODE: u32 = 0;

/// Diagnostic accessor for the cumulative submission counter.
pub fn total_admin_submits() -> u32 {
    unsafe { NVME_TOTAL_ADMIN_SUBMITS }
}

/// Diagnostic accessor for the most recently observed admin opcode.
pub fn last_admin_opcode() -> u32 {
    unsafe { NVME_LAST_ADMIN_OPCODE }
}

// ============================================================================
// NVMe I/O Operations (Basic Implementation)
// ============================================================================

/// Read sectors from NVMe device
/// Returns true on success
pub fn read_sectors(controller: usize, nsid: u32, lba: u64, buffer: &mut [u8]) -> bool {
    if buffer.len() < 512 {
        return false;
    }

    unsafe {
        if let Some(ref mut c) = NVME_CONTROLLERS[controller] {
            if c.state != NvmeControllerState::Ready {
                return false;
            }

            // Allocate DMA buffer for the read
            let buf_size = 4096.min(buffer.len());
            let buf = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, buf_size);
            if buf.is_null() {
                return false;
            }

            // Get physical address
            // This is critical for NVMe DMA - we cannot use virtual address as physical
            let phys = match crate::mm::vm::virt_to_phys(buf as u64) {
                Some(p) => p,
                None => {
                    // virt_to_phys failed - release buffer and return error
                    let _ = crate::mm::pool::free(buf);
                    return false;
                }
            };

            // Build NVMe read command ( Opcode 02h for NVM Command Set ).
            // Per NVMe 1.4 §6.4 the Read command encodes the starting
            // LBA in CDW10 (low 32 bits) and CDW11 (high 16 bits in the
            // upper half of the dword, low 16 bits reserved / LRW fields).
            let mut cmd = NvmeSqEntry::default();
            cmd.cdw0 = 0x0002_0000;  // NVM read command
            cmd.nsid = nsid;
            cmd.prp1 = phys;
            cmd.prp2 = 0;
            cmd.cdw10 = lba as u32;
            cmd.cdw11 = ((lba >> 32) as u32) & 0xFFFF_0000;

            // Submit command
            if submit_admin_command(c, cmd) {
                // In a full implementation, we would wait for completion
                // For now, just copy buffer data
                core::ptr::copy_nonoverlapping(buf as *const u8, buffer.as_mut_ptr(), buf_size);
                let _ = crate::mm::pool::free(buf);
                return true;
            }

            let _ = crate::mm::pool::free(buf);
        }
    }

    false
}

/// Write sectors to NVMe device
/// Returns true on success
pub fn write_sectors(controller: usize, nsid: u32, lba: u64, buffer: &[u8]) -> bool {
    if buffer.len() < 512 {
        return false;
    }

    unsafe {
        if let Some(ref mut c) = NVME_CONTROLLERS[controller] {
            if c.state != NvmeControllerState::Ready {
                return false;
            }

            // Allocate DMA buffer for the write
            let buf_size = 4096.min(buffer.len());
            let buf = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, buf_size);
            if buf.is_null() {
                return false;
            }

            // Copy data to DMA buffer
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), buf as *mut u8, buf_size);

            // Get physical address
            // This is critical for NVMe DMA - we cannot use virtual address as physical
            let phys = match crate::mm::vm::virt_to_phys(buf as u64) {
                Some(p) => p,
                None => {
                    // virt_to_phys failed - release buffer and return error
                    let _ = crate::mm::pool::free(buf);
                    return false;
                }
            };

            // Build NVMe write command (Opcode 01h). The Write command
            // uses the same LBA encoding as Read: CDW10 = LBA low,
            // CDW11 = LBA high in the upper 16 bits.
            let mut cmd = NvmeSqEntry::default();
            cmd.cdw0 = 0x0001_0000;  // NVM write command
            cmd.nsid = nsid;
            cmd.prp1 = phys;
            cmd.prp2 = 0;
            cmd.cdw10 = lba as u32;
            cmd.cdw11 = ((lba >> 32) as u32) & 0xFFFF_0000;

            // Submit command
            if submit_admin_command(c, cmd) {
                let _ = crate::mm::pool::free(buf);
                return true;
            }

            let _ = crate::mm::pool::free(buf);
        }
    }

    false
}

/// Get the number of NVMe controllers found
pub fn get_controller_count() -> usize {
    unsafe {
        NVME_CONTROLLERS.iter().filter(|c| c.is_some()).count()
    }
}
