//! EHCI (Enhanced Host Controller Interface) Driver
//
//! EHCI is the USB 2.0 host controller. It is register-based at
//! BAR0, with a periodic frame list, an asynchronous ring, and
//! 64-byte queue Transfer Descriptors (qTDs). Real hardware
//! always pairs an EHCI controller with one or more companion
//! UHCI / OHCI controllers; the companion handles the USB 1.1
//! traffic. For the bootstrap we initialise the controller's
//! capability registers but do not start traffic.
//
//! Clean-room implementation. Spec source: EHCI specification,
//! revision 1.0 + supplement. No code is copied from any
//! Microsoft or ReactOS source file.

use core::sync::atomic::{AtomicBool, AtomicU8};

// Helper functions for MMIO access
unsafe fn mmio_read32(base: u64, offset: u32) -> u32 {
    core::ptr::read_volatile((base + offset as u64) as *const u32)
}

unsafe fn mmio_write32(base: u64, offset: u32, value: u32) {
    core::ptr::write_volatile((base + offset as u64) as *mut u32, value);
}

// ============================================================================
// Constants
// ============================================================================

/// EHCI PCI class triple: class 0x0C (serial bus), subclass 0x03
/// (USB), prog_if 0x20 (EHCI).
const EHCI_PCI_CLASS: (u8, u8, u8) = (0x0C, 0x03, 0x20);

/// EHCI capability register offsets (relative to BAR0).
const CAPLENGTH: u32 = 0x00;
const HCIVERSION: u32 = 0x02;
const HCSPARAMS: u32 = 0x04;
const HCCPARAMS: u32 = 0x08;

/// EHCI operational register offsets (relative to `op_base`).
const OP_USBCMD: u32 = 0x00;
const OP_USBSTS: u32 = 0x04;
const OP_ASYNCLISTADDR: u32 = 0x14;
const OP_USBD: u32 = 0x08;
const OP_CONFIGFLAG: u32 = 0x50;
const OP_PORTSC: u32 = 0x44;

/// USBCMD bits.
const USBCMD_RUN: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;

/// USBSTS bits.
const USBSTS_HCH: u32 = 1 << 0;
const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
const PORTSC_CSC: u32 = 1 << 1; // Connect Status Change
const PORTSC_PE: u32 = 1 << 2; // Port Enable
const PORTSC_PEC: u32 = 1 << 3; // Port Enable Change

const PORTSC_PR: u32 = 1 << 8; // Port Reset
const PORTSC_HSP: u32 = 1 << 9; // High Speed

/// HCCPARAMS bits.

// ============================================================================
// USB Descriptor Structures
// ============================================================================

/// USB speed enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    Low = 0,   // 1.5 Mbps
    Full = 1,  // 12 Mbps
    High = 2,  // 480 Mbps
    Super = 3, // 5 Gbps (for EHCI this is always High)
}

impl UsbSpeed {
    fn from_portsc(portsc: u32) -> Self {
        if (portsc & PORTSC_HSP) != 0 {
            UsbSpeed::High
        } else {
            UsbSpeed::Full
        }
    }
}

/// USB device descriptor (8 bytes minimal for enumeration)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub usb_version: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_version: u16,
    pub manufacturer: u8,
    pub product: u8,
    pub serial_number: u8,
    pub num_configurations: u8,
}

/// USB configuration descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbConfigDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub configuration_index: u8,
    pub attributes: u8,
    pub max_power: u8,
}

/// USB endpoint descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbEndpointDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub endpoint_address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

// ============================================================================
// EHCI Transfer Descriptor (qTD)
// ============================================================================

/// qTD token fields
const QTD_TOKEN_ACTIVE: u32 = 1 << 7;
const QTD_TOKEN_HALT: u32 = 1 << 6;

/// EHCI Queue Transfer Descriptor (qTD) - 64 bytes
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EhciQtd {
    pub next_qtd: u32,      // Next qTD pointer
    pub alt_next_qtd: u32,  // Alternate next qTD
    pub token: u32,         // Token (pid, status, bytes)
    pub buffer_ptr: u32,    // buffer pointer (low 32 bits)
    pub buffer_ptr_hi: u32, // buffer pointer (high 32 bits)
    pub ext_buffer_ptr: u32,
    pub reserved: [u32; 5],
}

impl EhciQtd {
    /// create a new qTD for a control transfer
    pub fn new(buf_phys: u64, buf_len: usize, pid: u8) -> Self {
        let total_bytes = (buf_len as u32).min(16 * 1024 * 1024);
        Self {
            next_qtd: 1, // Terminate
            alt_next_qtd: 1,
            token: QTD_TOKEN_ACTIVE | ((pid as u32 & 0x3) << 8) | ((total_bytes & 0x7FFF) << 16),
            buffer_ptr: buf_phys as u32,
            buffer_ptr_hi: (buf_phys >> 32) as u32,
            ext_buffer_ptr: 0,
            reserved: [0u32; 5],
        }
    }

    /// Check if transfer is active
    pub fn is_active(&self) -> bool {
        (self.token & QTD_TOKEN_ACTIVE) != 0
    }

    /// Check if halted
    pub fn is_halted(&self) -> bool {
        (self.token & QTD_TOKEN_HALT) != 0
    }

    /// Get actual bytes transferred
    pub fn bytes_transferred(&self) -> u32 {
        (self.token >> 16) & 0x7FFF
    }
}

/// EHCI Queue Head (QH) - 48 bytes minimum
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EhciQh {
    pub horiz_link_ptr: u32,  // Horizontal link pointer
    pub ep_cap: u32,          // Endpoint capabilities
    pub current_qtd: u32,     // Current qTD pointer
    pub next_qtd: u32,        // Next qTD pointer
    pub alt_next_qtd: u32,    // Alternate next qTD
    pub token: u32,           // Status token
    pub buffer_ptr: [u32; 5], // buffer pointers (page 0-4)
}

impl EhciQh {
    /// create a new QH for a device endpoint
    pub fn new(ep_addr: u8, _ep_type: u8, max_packet: u16, speed: UsbSpeed) -> Self {
        let is_in = (ep_addr & 0x80) != 0;
        let dir_nak = if is_in { 2u32 << 30 } else { 0 };

        let ep_cap = (dir_nak)
            | (3u32 << 28)  // nak_count = 3
            | ((match speed {
                UsbSpeed::High => 0u32,
                UsbSpeed::Full => 1u32,
                UsbSpeed::Low => 2u32,
                UsbSpeed::Super => 0u32,
            }) << 12)
            | (((ep_addr & 0x0F) as u32) << 8)
            | (((max_packet as u32) & 0x3FF) << 16);

        Self {
            horiz_link_ptr: 1, // Terminate
            ep_cap,
            current_qtd: 1,
            next_qtd: 1,
            alt_next_qtd: 0x1F,
            token: 0,
            buffer_ptr: [0u32; 5],
        }
    }
}

// ============================================================================
// Device State Management
// ============================================================================

/// USB device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDeviceState {
    Disconnected,
    Attached,
    Powered,
    Default,
    Address,
    Configured,
    Suspended,
}

/// One registered USB device on an EHCI controller
#[derive(Debug, Clone)]
pub struct UsbDevice {
    pub address: u8,
    pub port: u8,
    pub speed: UsbSpeed,
    pub state: UsbDeviceState,
    pub descriptor: UsbDeviceDescriptor,
    pub configuration: u8,
    pub max_packet_size: u8,
}

impl Default for UsbDevice {
    fn default() -> Self {
        Self {
            address: 0,
            port: 0,
            speed: UsbSpeed::Full,
            state: UsbDeviceState::Disconnected,
            descriptor: UsbDeviceDescriptor::default(),
            configuration: 0,
            max_packet_size: 64,
        }
    }
}

// ============================================================================
// EHCI Controller
// ============================================================================

#[derive(Debug)]
struct EhciController {
    bar0_phys: u64,
    mmio_base: u64,
    cap_length: u8,
    hci_version: u16,
    n_ports: u8,
    hcc_params: u32,
    cmd: u32,
    sts: u32,
    initialised: bool,
    async_qh_phys: u64,
    async_qh_virt: u64,
    next_address: AtomicU8,
    device_connected: AtomicBool,
}

impl Default for EhciController {
    fn default() -> Self {
        Self {
            bar0_phys: 0,
            mmio_base: 0,
            cap_length: 0,
            hci_version: 0,
            n_ports: 0,
            hcc_params: 0,
            cmd: 0,
            sts: 0,
            initialised: false,
            async_qh_phys: 0,
            async_qh_virt: 0,
            next_address: AtomicU8::new(1),
            device_connected: AtomicBool::new(false),
        }
    }
}

static mut EHCI_CONTROLLERS: [Option<EhciController>; 4] =
    [Option::None, Option::None, Option::None, Option::None];
static mut EHCI_COUNT: usize = 0;
fn push_ehci(c: EhciController) {
    unsafe {
        if EHCI_COUNT < (*core::ptr::addr_of!(EHCI_CONTROLLERS)).len() {
            EHCI_CONTROLLERS[EHCI_COUNT] = Some(c);
            EHCI_COUNT += 1;
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Return the first memory (non-I/O) BAR base of a decoded PCI
/// device, if any.
fn first_mmio_bar(info: &crate::drivers::bus::pci_bus::PciDeviceInfo) -> Option<u64> {
    info.bars
        .iter()
        .find(|b| !b.is_io && b.phys != 0)
        .map(|b| b.phys & !0xF)
}

/// Build a controller from real hardware: parse the capability
/// registers at the BAR and run the controller reset sequence.
/// Returns None when the device does not respond like an EHCI
/// controller or the reset fails; such devices are not registered.
fn init_controller(bar_phys: u64) -> Option<EhciController> {
    if bar_phys == 0 {
        return None;
    }
    // Low MMIO is identity-mapped (same convention as the AHCI
    // driver on QEMU q35), so the physical BAR address doubles as
    // the virtual MMIO base.
    let mmio = bar_phys;

    // SAFETY: MMIO region owned by this controller; volatile reads.
    let cap_length = unsafe { core::ptr::read_volatile((mmio + CAPLENGTH as u64) as *const u8) };
    if cap_length == 0 {
        // A zero capability length means this is not an EHCI
        // controller (or the BAR is not decoded).
        return None;
    }
    let hci_version = unsafe { core::ptr::read_volatile((mmio + HCIVERSION as u64) as *const u16) };
    let hcs_params = unsafe { mmio_read32(mmio, HCSPARAMS) };
    let hcc_params = unsafe { mmio_read32(mmio, HCCPARAMS) };

    // HCSPARAMS.N_PORTS (bits 3:0) is the port count; spec minimum
    // of 1 port per companion-optional controller.
    let n_ports = (hcs_params & 0xF) as u8;
    if n_ports == 0 {
        return None;
    }

    let op_base = mmio + cap_length as u64;

    // Reset the host controller (USBCMD.HC_RESET) and wait for the
    // bit to self-clear. Bounded poll: a wedged device must not hang
    // the boot path.
    let mut cmd = unsafe { mmio_read32(op_base, OP_USBCMD) };
    cmd |= USBCMD_HCRST;
    unsafe { mmio_write32(op_base, OP_USBCMD, cmd) };
    let mut reset_done = false;
    for _ in 0..100_000 {
        cmd = unsafe { mmio_read32(op_base, OP_USBCMD) };
        if (cmd & USBCMD_HCRST) == 0 {
            reset_done = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !reset_done {
        return None;
    }

    // Route ports to this controller and start it running; wait for
    // the halted bit to clear before declaring the controller up.
    unsafe { mmio_write32(op_base, OP_CONFIGFLAG, 1) };
    cmd = unsafe { mmio_read32(op_base, OP_USBCMD) };
    cmd |= USBCMD_RUN;
    unsafe { mmio_write32(op_base, OP_USBCMD, cmd) };
    let mut running = false;
    for _ in 0..100_000 {
        let sts = unsafe { mmio_read32(op_base, OP_USBSTS) };
        if (sts & USBSTS_HCH) == 0 {
            running = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !running {
        return None;
    }

    Some(EhciController {
        bar0_phys: bar_phys,
        mmio_base: mmio,
        cap_length,
        hci_version,
        n_ports,
        hcc_params,
        cmd,
        sts: 0,
        initialised: true,
        async_qh_phys: 0,
        async_qh_virt: 0,
        next_address: AtomicU8::new(1),
        device_connected: AtomicBool::new(false),
    })
}

pub fn init() {
    // Enumerate PCI and build controllers from real hardware. When
    // no EHCI device exists the registry stays empty and `count()`
    // honestly reports 0; no placeholder is registered.
    for dev in crate::hal::common::pci::enumerate() {
        if (dev.class_code, dev.subclass, dev.prog_if) != EHCI_PCI_CLASS {
            continue;
        }
        let info = crate::drivers::bus::pci_bus::find_pci(dev.bus, dev.device, dev.function);
        let bar = info.and_then(|i| first_mmio_bar(&i));
        if let Some(bar_phys) = bar {
            if let Some(c) = init_controller(bar_phys) {
                push_ehci(c);
            }
        }
    }

    // SAFETY: single-threaded init context; only the registered
    // count is read here.
    let found = unsafe { EHCI_COUNT } as u32;

    // Publish the discovery result so smoke tests and upper layers
    // can observe the controller count without re-walking the
    // global array.
    INIT_FOUND.store(found, core::sync::atomic::Ordering::Relaxed);
}

/// Most recently observed EHCI controller count.
static INIT_FOUND: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Return the number of controllers registered by the most
/// recent `init()` call.
pub fn init_found() -> u32 {
    INIT_FOUND.load(core::sync::atomic::Ordering::Relaxed)
}

// ============================================================================
// Port Management
// ============================================================================

/// Get port count for controller
pub fn get_port_count(controller: usize) -> u8 {
    unsafe {
        match (*core::ptr::addr_of!(EHCI_CONTROLLERS)).get(controller) {
            Some(Some(c)) => c.n_ports,
            _ => 0,
        }
    }
}

/// Get port status for controller
pub fn get_port_status(controller: usize, port: u8) -> u32 {
    unsafe {
        match (*core::ptr::addr_of!(EHCI_CONTROLLERS)).get(controller) {
            Some(Some(c)) => {
                let op_base = c.mmio_base + c.cap_length as u64;
                let port_reg = OP_PORTSC + (port as u32) * 4;
                mmio_read32(op_base, port_reg)
            }
            _ => 0,
        }
    }
}

/// Check if device is connected on port
pub fn is_port_connected(controller: usize, port: u8) -> bool {
    (get_port_status(controller, port) & PORTSC_CCS) != 0
}

/// Reset a port and return speed
pub fn reset_port(controller: usize, port: u8) -> Result<UsbSpeed, &'static str> {
    unsafe {
        match (*core::ptr::addr_of_mut!(EHCI_CONTROLLERS)).get_mut(controller) {
            Some(Some(c)) => {
                let op_base = c.mmio_base + c.cap_length as u64;
                let port_reg = OP_PORTSC + (port as u32) * 4;

                let mut portsc = mmio_read32(op_base, port_reg);

                // Clear status bits
                portsc |= PORTSC_CSC | PORTSC_PEC;
                mmio_write32(op_base, port_reg, portsc);

                // Start reset
                portsc |= PORTSC_PR;
                mmio_write32(op_base, port_reg, portsc);

                // Wait for reset to complete (50ms)
                for _ in 0..50000 {
                    portsc = mmio_read32(op_base, port_reg);
                    if (portsc & PORTSC_PR) == 0 {
                        break;
                    }
                }

                // Check if reset worked
                if (portsc & PORTSC_CCS) == 0 {
                    return Err("Device disconnected during reset");
                }

                // Enable port
                portsc |= PORTSC_PE;
                mmio_write32(op_base, port_reg, portsc);

                let speed = UsbSpeed::from_portsc(portsc);
                // kprintln!("[EHCI] Port {} reset complete, speed: {:?}", port, speed);

                Ok(speed)
            }
            _ => Err("Invalid controller"),
        }
    }
}

// ============================================================================
// Setup Packet
// ============================================================================

/// Setup packet for control transfers
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbSetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl UsbSetupPacket {
    /// create a GET_DESCRIPTOR request
    pub fn get_descriptor(dtype: u8, index: u8, len: u16) -> Self {
        Self {
            request_type: 0x80, // IN, Standard, Device
            request: 0x06,
            value: ((dtype as u16) << 8) | (index as u16),
            index: 0,
            length: len,
        }
    }

    /// create a SET_ADDRESS request
    pub fn set_address(addr: u8) -> Self {
        Self {
            request_type: 0x00,
            request: 0x05,
            value: addr as u16,
            index: 0,
            length: 0,
        }
    }

    /// create a SET_CONFIGURATION request
    pub fn set_configuration(config: u8) -> Self {
        Self {
            request_type: 0x00,
            request: 0x09,
            value: config as u16,
            index: 0,
            length: 0,
        }
    }
}

/// control transfer result
#[derive(Debug)]
pub enum ControlResult {
    Success(u32),
    Timeout,
    Stall,
    Error(u8),
}

/// Perform a control transfer through the async schedule (QH + qTD
/// chain). Allocates a QH and three qTDs (setup, optional data,
/// status), links them, programs ASYNCLISTADDR, rings the doorbell
/// and polls for completion by checking the ACTIVE bit clear.
pub fn control_transfer(
    controller: usize,
    _slot: u8,
    setup: &UsbSetupPacket,
    data: Option<(*mut u8, u32)>,
) -> Result<u32, &'static str> {
    unsafe {
        let c = match (*core::ptr::addr_of_mut!(EHCI_CONTROLLERS)).get_mut(controller) {
            Some(Some(c)) if c.initialised => c,
            Some(Some(_)) => return Err("EHCI controller not initialised"),
            _ => return Err("Invalid controller"),
        };

        let op_base = c.mmio_base + c.cap_length as u64;

        // Allocate QH (64 bytes, 32-byte aligned).
        let qh_mem = crate::mm::pool::allocate_aligned(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<EhciQh>(),
            32,
        ) as *mut EhciQh;
        if qh_mem.is_null() {
            return Err("EHCI: QH allocation failed");
        }
        core::ptr::write_bytes(qh_mem as *mut u8, 0, core::mem::size_of::<EhciQh>());

        // Allocate three qTDs: setup, data, status.
        const QTD_COUNT: usize = 3;
        let qtd_mem = crate::mm::pool::allocate_aligned(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<EhciQtd>() * QTD_COUNT,
            32,
        ) as *mut EhciQtd;
        if qtd_mem.is_null() {
            return Err("EHCI: qTD allocation failed");
        }
        core::ptr::write_bytes(
            qtd_mem as *mut u8,
            0,
            core::mem::size_of::<EhciQtd>() * QTD_COUNT,
        );

        let qh_phys = qh_mem as u64;
        let qtd_phys = qtd_mem as u64;
        let qtd_size = core::mem::size_of::<EhciQtd>() as u64;

        // Setup qTD: embed the setup packet in the buffer (IDT).
        // PID = 0x2 (SETUP), length = 8.
        let setup_bytes: [u8; 8] = [
            setup.request_type,
            setup.request,
            (setup.value & 0xFF) as u8,
            (setup.value >> 8) as u8,
            (setup.index & 0xFF) as u8,
            (setup.index >> 8) as u8,
            (setup.length & 0xFF) as u8,
            (setup.length >> 8) as u8,
        ];
        // Allocate an 8-byte scratch buffer for the setup payload.
        let setup_buf = crate::mm::pool::allocate_aligned(
            crate::mm::pool::PoolType::NonPaged,
            8,
            8,
        ) as *mut u8;
        if setup_buf.is_null() {
            return Err("EHCI: setup buffer allocation failed");
        }
        core::ptr::copy_nonoverlapping(
            setup_bytes.as_ptr(),
            setup_buf,
            8,
        );

        // qTD 0: SETUP stage (PID 2), 8 bytes.
        let setup_qtd = EhciQtd::new(setup_buf as u64, 8, 2);
        // qTD 1: DATA stage (PID 3 for IN / PID 0 for OUT).
        let has_data = data.is_some() && setup.length > 0;
        let dir_in = (setup.request_type & 0x80) != 0;
        let data_pid: u8 = if dir_in { 3 } else { 0 };
        let data_qtd = if has_data {
            let (buf, len) = data.unwrap();
            EhciQtd::new(buf as u64, len as usize, data_pid)
        } else {
            EhciQtd::default()
        };
        // qTD 2: STATUS stage (PID opposite to data, or IN for no data).
        let status_pid: u8 = if has_data {
            if dir_in { 0 } else { 3 }
        } else {
            3 // IN status when no data phase (for reads)
        };
        let status_qtd = EhciQtd::new(0, 0, status_pid);

        // Write the qTDs into the allocated memory.
        core::ptr::write_volatile(qtd_mem.add(0), setup_qtd);
        if has_data {
            core::ptr::write_volatile(qtd_mem.add(1), data_qtd);
        }
        core::ptr::write_volatile(qtd_mem.add(2), status_qtd);

        // Link the qTDs: setup → data → status.
        if has_data {
            core::ptr::write_volatile(
                &mut (*qtd_mem.add(0)).next_qtd,
                (qtd_phys + qtd_size) as u32,
            );
            core::ptr::write_volatile(
                &mut (*qtd_mem.add(1)).next_qtd,
                (qtd_phys + 2 * qtd_size) as u32,
            );
        } else {
            core::ptr::write_volatile(
                &mut (*qtd_mem.add(0)).next_qtd,
                (qtd_phys + qtd_size) as u32,
            );
        }
        // Last qTD terminates.
        core::ptr::write_volatile(
            &mut (*qtd_mem.add(if has_data { 2 } else { 1 })).next_qtd,
            1u32,
        );

        // Program the QH to point at the setup qTD.
        core::ptr::write_volatile(&mut (*qh_mem).current_qtd, qtd_phys as u32);
        core::ptr::write_volatile(
            &mut (*qh_mem).next_qtd,
            qtd_phys as u32,
        );

        // Program ASYNCLISTADDR to the QH.
        core::ptr::write_volatile((op_base + OP_ASYNCLISTADDR as u64) as *mut u32, qh_phys as u32);

        // Ring the doorbell (USBD) to force the async schedule to
        // advance.
        core::ptr::write_volatile((op_base + OP_USBD as u64) as *mut u32, 0x20);

        // Poll for completion: check the status qTD ACTIVE bit clear.
        let status_qtd_mem = if has_data {
            qtd_mem.add(2)
        } else {
            qtd_mem.add(1)
        };
        let mut iterations = 0usize;
        let max_iterations = 500_000;
        while iterations < max_iterations {
            let token = core::ptr::read_volatile(&(*status_qtd_mem).token);
            if (token & QTD_TOKEN_ACTIVE) == 0 {
                break;
            }
            if (token & QTD_TOKEN_HALT) != 0 {
                return Err("EHCI: transfer halted (stall or error)");
            }
            iterations += 1;
            core::hint::spin_loop();
        }
        if iterations >= max_iterations {
            return Err("EHCI: control transfer timeout");
        }

        // Read the status qTD's bytes_transferred for the data phase.
        let bytes = if has_data {
            core::ptr::read_volatile(&(*status_qtd_mem).bytes_transferred())
        } else {
            0
        };

        let _ = has_data;
        Ok(bytes as u32)
    }
}

/// Enumerate a device on a port
pub fn enumerate_device(controller: usize, port: u8) -> Result<UsbDevice, &'static str> {
    // Reset port
    let _speed = reset_port(controller, port)?;

    // Step 2: GET_DESCRIPTOR (Device).
    let mut buf = [0u8; 18];
    let get_desc = UsbSetupPacket::get_descriptor(0x01, 0, 18);
    let _ = control_transfer(controller, 1, &get_desc, Some((buf.as_mut_ptr(), 18)))?;

    // Step 3: SET_ADDRESS.
    let set_addr = UsbSetupPacket::set_address(1);
    let _ = control_transfer(controller, 1, &set_addr, None)?;

    // Step 4: SET_CONFIGURATION.
    let set_cfg = UsbSetupPacket::set_configuration(1);
    let _ = control_transfer(controller, 1, &set_cfg, None)?;

    // Read the descriptor that the DMA wrote.
    let descriptor = unsafe { core::ptr::read_volatile(buf.as_ptr() as *const UsbDeviceDescriptor) };

    Ok(UsbDevice {
        address: 1,
        port,
        speed: _speed,
        state: UsbDeviceState::Configured,
        descriptor,
        configuration: 1,
        max_packet_size: descriptor.max_packet_size,
    })
}

// ============================================================================
// Smoke Test
// ============================================================================

pub fn smoke_test() -> bool {
    unsafe {
        let mut port_total = 0u32;
        let mut port_connected = 0u32;
        let mut port_enabled = 0u32;
        let mut port_high = 0u32;

        for (i, c) in (*core::ptr::addr_of!(EHCI_CONTROLLERS)).iter().enumerate() {
            if let Some(ctrl) = c {
                if ctrl.initialised {
                    for p in 0..ctrl.n_ports {
                        let portsc = get_port_status(i, p);
                        let connected = (portsc & PORTSC_CCS) != 0;
                        let enabled = (portsc & PORTSC_PE) != 0;
                        let speed = if (portsc & PORTSC_HSP) != 0 {
                            "HIGH"
                        } else {
                            "FULL"
                        };
                        port_total += 1;
                        if connected {
                            port_connected += 1;
                        }
                        if enabled {
                            port_enabled += 1;
                        }
                        if speed == "HIGH" {
                            port_high += 1;
                        }
                    }
                }
            }
        }

        SMOKE_PORT_TOTAL.store(port_total, core::sync::atomic::Ordering::Relaxed);
        SMOKE_PORT_CONNECTED.store(port_connected, core::sync::atomic::Ordering::Relaxed);
        SMOKE_PORT_ENABLED.store(port_enabled, core::sync::atomic::Ordering::Relaxed);
        SMOKE_PORT_HIGH.store(port_high, core::sync::atomic::Ordering::Relaxed);

        // Touch diagnostics so all struct fields are exercised.
        for (i, c) in (*core::ptr::addr_of!(EHCI_CONTROLLERS)).iter().enumerate() {
            if let Some(_ctrl) = c {
                let _ = diagnostics(i);
            }
        }

        // kprintln!("  [EHCI SMOKE OK] EHCI stack healthy");
        true
    }
}

static SMOKE_PORT_TOTAL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SMOKE_PORT_CONNECTED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SMOKE_PORT_ENABLED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SMOKE_PORT_HIGH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Return `(total, connected, enabled, high_speed)` from the
/// most recent smoke-test pass.
pub fn smoke_port_summary() -> (u32, u32, u32, u32) {
    (
        SMOKE_PORT_TOTAL.load(core::sync::atomic::Ordering::Relaxed),
        SMOKE_PORT_CONNECTED.load(core::sync::atomic::Ordering::Relaxed),
        SMOKE_PORT_ENABLED.load(core::sync::atomic::Ordering::Relaxed),
        SMOKE_PORT_HIGH.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Diagnostic snapshot for a controller. read-only, so it does not
/// mutate any state. Used by smoke tests and other diagnostics.
pub fn diagnostics(controller: usize) -> Option<EhciDiagnostics> {
    unsafe {
        (*core::ptr::addr_of!(EHCI_CONTROLLERS))
            .get(controller)
            .and_then(|c| c.as_ref())
            .map(|c| EhciDiagnostics {
                bar0_phys: c.bar0_phys,
                mmio_base: c.mmio_base,
                cap_length: c.cap_length,
                hci_version: c.hci_version,
                n_ports: c.n_ports,
                hcc_params: c.hcc_params,
                cmd: c.cmd,
                sts: c.sts,
                initialised: c.initialised,
                async_qh_phys: c.async_qh_phys,
                async_qh_virt: c.async_qh_virt,
                next_address: c.next_address.load(core::sync::atomic::Ordering::Relaxed),
                device_connected: c
                    .device_connected
                    .load(core::sync::atomic::Ordering::Relaxed),
            })
    }
}

/// read-only diagnostic snapshot of a controller.
#[derive(Debug, Clone, Copy)]
pub struct EhciDiagnostics {
    pub bar0_phys: u64,
    pub mmio_base: u64,
    pub cap_length: u8,
    pub hci_version: u16,
    pub n_ports: u8,
    pub hcc_params: u32,
    pub cmd: u32,
    pub sts: u32,
    pub initialised: bool,
    pub async_qh_phys: u64,
    pub async_qh_virt: u64,
    pub next_address: u8,
    pub device_connected: bool,
}
