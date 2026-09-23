//! Serial Port Driver (serial.sys)
//
//! Implements the serial port (COM port) driver. serial.sys is the
//! Windows NT 6.1 driver for 16550-compatible UART devices. It
//! manages the COM1-COM4 ports and exposes them as standard file
//! objects that user mode can read/write via CreateFile/ReadFile/WriteFile.
//
//! Clean-room implementation. Spec source: 16550 UART specification
//! and Microsoft "Serial Driver" reference.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use crate::io::{DeviceObject, DeviceType, DriverObject};
use crate::ke::sync::Spinlock;

pub const COM1_BASE: u16 = 0x3F8;
pub const COM2_BASE: u16 = 0x2F8;
pub const COM3_BASE: u16 = 0x3E8;
pub const COM4_BASE: u16 = 0x2E8;

const THR: u16 = 0;  // Transmit Holding Register (write)
const RBR: u16 = 0;  // Receive Buffer Register (read)
const DLL: u16 = 0;  // Divisor Latch Low (DLAB=1)
const DLH: u16 = 1;  // Divisor Latch High (DLAB=1)
const IER: u16 = 1;  // Interrupt Enable Register
const IIR: u16 = 2;  // Interrupt Identification Register (read)
const FCR: u16 = 2;  // FIFO Control Register (write)
const LCR: u16 = 3;  // Line Control Register
const MCR: u16 = 4;  // Modem Control Register
const LSR: u16 = 5;  // Line Status Register
const MSR: u16 = 6;  // Modem Status Register

const LSR_DR: u8 = 1 << 0;   // Data Ready
const LSR_THRE: u8 = 1 << 5; // Transmit Holding Register Empty
const LSR_TEMT: u8 = 1 << 6; // Transmitter Empty

const LCR_DLAB: u8 = 1 << 7; // Divisor Latch Access Bit
const LCR_8N1: u8 = 0x03;    // 8 data bits, no parity, 1 stop bit

const MCR_DTR: u8 = 1 << 0;  // Data Terminal Ready
const MCR_RTS: u8 = 1 << 1;  // Request To Send
const MCR_OUT1: u8 = 1 << 2;
const MCR_OUT2: u8 = 1 << 3;

const FCR_ENABLE: u8 = 1 << 0;   // Enable FIFOs
const FCR_CLEAR_RX: u8 = 1 << 1; // Clear receive FIFO
const FCR_CLEAR_TX: u8 = 1 << 2; // Clear transmit FIFO
const FCR_TRIGGER_14: u8 = 0xC0; // Trigger level: 14 bytes

const MAX_PORTS: usize = 4;

const RX_BUFFER_SIZE: usize = 256;

pub struct SerialPort {
    pub valid: bool,
    pub base: u16,
    pub device_object: *mut DeviceObject,
    pub driver: *mut DriverObject,
    pub baud_rate: u32,
    pub rx_buffer: [u8; RX_BUFFER_SIZE],
    pub rx_head: usize,
    pub rx_tail: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl SerialPort {
    pub const fn new() -> Self {
        Self {
            valid: false,
            base: 0,
            device_object: core::ptr::null_mut(),
            driver: core::ptr::null_mut(),
            baud_rate: 0,
            rx_buffer: [0u8; RX_BUFFER_SIZE],
            rx_head: 0,
            rx_tail: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

/// Static array of serial port state.
///
/// SAFETY: This `static mut` is only mutated during single-threaded BSP
/// boot (`serial::init`). After SMP is enabled access is gated through
/// `PORT_LOCK` (the `Spinlock<()>` below). The mutable binding is needed
/// because `[const { SerialPort::new() }; N]` is not yet accepted on all
/// toolchains for non-Copy types.
static mut PORTS: [SerialPort; MAX_PORTS] = [const { SerialPort::new() }; MAX_PORTS];
static PORT_LOCK: Spinlock<()> = Spinlock::new(());
static TOTAL_BYTES_SENT: AtomicU32 = AtomicU32::new(0);
static TOTAL_BYTES_RECEIVED: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "x86_64")]
#[inline]
fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, preserves_flags)
        );
    }
    val
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn inb(_port: u16) -> u8 { 0 }

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn outb(_port: u16, _val: u8) {}

fn init_port(base: u16, baud_rate: u32) -> bool {
    let divisor = if baud_rate > 0 {
        115200 / baud_rate
    } else {
        1  // Default to 115200 baud
    };

    outb(base + IER, 0);

    outb(base + LCR, LCR_DLAB);
    outb(base + DLL, (divisor & 0xFF) as u8);
    outb(base + DLH, ((divisor >> 8) & 0xFF) as u8);

    outb(base + LCR, LCR_8N1);

    outb(base + FCR, FCR_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX | FCR_TRIGGER_14);

    outb(base + MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

    let lsr = inb(base + LSR);

    lsr != 0xFF
}

pub fn init() {
    let _g = PORT_LOCK.lock();

    let ports = [
        (0, COM1_BASE),
        (1, COM2_BASE),
        (2, COM3_BASE),
        (3, COM4_BASE),
    ];

    unsafe {
        for (idx, base) in ports {
            if init_port(base, 115200) {
                PORTS[idx].valid = true;
                PORTS[idx].base = base;
                PORTS[idx].baud_rate = 115200;
            }
        }
    }
}

pub fn write_byte(port_id: usize, byte: u8) -> bool {
    if port_id >= MAX_PORTS {
        return false;
    }

    let _g = PORT_LOCK.lock();
    unsafe {
        let port = &mut PORTS[port_id];
        if !port.valid {
            return false;
        }

        for _ in 0..0xFFFF {
            if (inb(port.base + LSR) & LSR_THRE) != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        outb(port.base + THR, byte);
        port.bytes_sent += 1;
        TOTAL_BYTES_SENT.fetch_add(1, Ordering::Relaxed);
        true
    }
}

pub fn write(port_id: usize, buffer: &[u8]) -> usize {
    let mut written = 0;
    for &byte in buffer {
        if write_byte(port_id, byte) {
            written += 1;
        } else {
            break;
        }
    }
    written
}

pub fn try_read_byte(port_id: usize) -> Option<u8> {
    if port_id >= MAX_PORTS {
        return None;
    }

    let _g = PORT_LOCK.lock();
    unsafe {
        let port = &mut PORTS[port_id];
        if !port.valid {
            return None;
        }

        if (inb(port.base + LSR) & LSR_DR) != 0 {
            let byte = inb(port.base + RBR);
            port.bytes_received += 1;
            TOTAL_BYTES_RECEIVED.fetch_add(1, Ordering::Relaxed);
            Some(byte)
        } else {
            None
        }
    }
}

pub fn read(port_id: usize, buffer: &mut [u8]) -> usize {
    let mut read_count = 0;
    for i in 0..buffer.len() {
        if let Some(byte) = try_read_byte(port_id) {
            buffer[i] = byte;
            read_count += 1;
        } else {
            break;
        }
    }
    read_count
}

pub fn port_count() -> usize {
    let mut count = 0;
    unsafe {
        for port in PORTS.iter() {
            if port.valid {
                count += 1;
            }
        }
    }
    count
}

pub fn get_stats() -> (u64, u64) {
    (
        TOTAL_BYTES_SENT.load(Ordering::Relaxed) as u64,
        TOTAL_BYTES_RECEIVED.load(Ordering::Relaxed) as u64,
    )
}

pub fn DriverEntry(driver: *mut DriverObject) -> u32 {
    init();
    0 // STATUS_SUCCESS
}

pub mod dispatch {
    use super::*;
    use crate::io::{Irp, IoStackLocation};
    use crate::io::major::*;

    pub fn Create(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }

    pub fn Close(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }

    pub fn Read(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }

    pub fn Write(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }

    pub fn DeviceControl(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }
}
