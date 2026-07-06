//! Serial Port Driver
//
//! UART serial port driver for x86_64
//! Outputs to QEMU serial port

/// UART registers (COM1 at I/O port 0x3F8)
pub const COM1_PORT: u16 = 0x3F8;
pub const COM2_PORT: u16 = 0x2F8;

/// UART register offsets
pub const UART_REG_DATA: u16 = 0;
pub const UART_REG_IER: u16 = 1;
pub const UART_REG_FCR: u16 = 2;
pub const UART_REG_LCR: u16 = 3;
pub const UART_REG_MCR: u16 = 4;
pub const UART_REG_LSR: u16 = 5;

/// LSR bits
pub const LSR_DATA_READY: u8 = 1 << 0;
pub const LSR_TRANSMIT_EMPTY: u8 = 1 << 5;

/// Initialize serial port
pub fn init() {
    init_port(COM1_PORT);
    super::mark_serial_initialized();
    // TEMP: Skip kprintln! to isolate the crash
    // // crate::kprintln!("    Serial port (COM1) initialized at I/O 0x3F8")  // kprintln disabled (memcpy crash workaround);
}

/// Alias for init (used by legacy arch/ code)
pub fn serial_init() {
    init();
}

/// Initialize a specific port
pub fn init_port(port: u16) {
    // Disable interrupts
    outb(port + UART_REG_IER, 0x00);
    
    // Set DLAB
    outb(port + UART_REG_LCR, 0x80);
    
    // Set divisor (baud rate = 115200 / divisor)
    outb(port + 0, 0x03); // LSB
    outb(port + 1, 0x00); // MSB (divisor 3 = 38400 baud)
    
    // 8 bits, no parity, one stop bit
    outb(port + UART_REG_LCR, 0x03);
    
    // Enable FIFO
    outb(port + UART_REG_FCR, 0x01);
    
    // Set MCR (RTS/DSR)
    outb(port + UART_REG_MCR, 0x03);
    
    // Loopback mode test
    outb(port + UART_REG_MCR, 0x1F);
    
    // Check loopback
    outb(port + 0, 0xAE);
    
    // Verify
    if inb(port + 0) != 0xAE {
        // Port not responding
        return;
    }
    
    // Back to normal mode
    outb(port + UART_REG_MCR, 0x0F);
}

/// Write character to serial port
#[inline(never)]
pub fn write_char(c: u8) {
    write_char_port(COM1_PORT, c);
}

/// Write character to specific port
pub fn write_char_port(port: u16, c: u8) {
    // Wait for transmit buffer to be empty
    while (inb(port + UART_REG_LSR) & LSR_TRANSMIT_EMPTY) == 0 {}
    
    // Send character
    outb(port + UART_REG_DATA, c);
}

/// Write string to serial port
#[inline(never)]
pub fn write_string(s: &str) {
    for c in s.bytes() {
        write_char(c);
    }
}

/// Hex-dump a 64-bit value to the serial port. The other
/// architectures (`aarch64`, `riscv64`, `loongarch64`) define
/// a native `write_hex_u64`; this x86_64 shim mirrors the
/// same format (`"0xDEADBEEFCAFEBABE"`, no leading zeros) so
/// log output is uniform across the kernel.
#[inline(never)]
pub fn write_hex_u64(v: u64) {
    write_string("0x");
    // Print in 16 nibbles, MSB-first. We can't use
    // `format!` here (no `alloc`), so emit nibble by nibble.
    for i in (0..16).rev() {
        let nib = ((v >> (i * 4)) & 0xF) as u8;
        let c = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        write_char(c);
    }
}

/// Alias for write_string (used by legacy code)
#[inline(always)]
pub fn serial_puts(s: &str) {
    write_string(s);
}

/// Write string with newline
pub fn write_line(s: &str) {
    write_string(s);
    write_string("\r\n");
}

/// Write a 64-bit value as 16 hex digits with no leading "0x".
pub fn write_u64_hex(val: u64) {
    let hex = b"0123456789ABCDEF";
    for i in (0..16).rev() {
        write_char(hex[((val >> (i * 4)) & 0xF) as usize]);
    }
}

/// Write a usize value as hex digits (adapts to pointer size).
pub fn write_usize_hex(val: usize) {
    let hex = b"0123456789ABCDEF";
    let bits = core::mem::size_of::<usize>() * 8;
    for i in (0..bits / 4).rev() {
        write_char(hex[((val >> (i * 4)) & 0xF) as usize]);
    }
}

/// Write a 32-bit value as 8 hex digits with no leading "0x".
pub fn write_u32_hex(val: u32) {
    let hex = b"0123456789ABCDEF";
    for i in (0..8).rev() {
        write_char(hex[((val >> (i * 4)) & 0xF) as usize]);
    }
}

/// Read character from serial port (non-blocking)
pub fn read_char() -> Option<u8> {
    read_char_port(COM1_PORT)
}

/// Read character from specific port
pub fn read_char_port(port: u16) -> Option<u8> {
    if (inb(port + UART_REG_LSR) & LSR_DATA_READY) != 0 {
        Some(inb(port + UART_REG_DATA))
    } else {
        None
    }
}

/// Check if data is available
pub fn data_available() -> bool {
    data_available_port(COM1_PORT)
}

/// Check port for data
pub fn data_available_port(port: u16) -> bool {
    (inb(port + UART_REG_LSR) & LSR_DATA_READY) != 0
}

// I/O port operations
#[inline]
fn inb(port: u16) -> u8 {
    let value: u8;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        value = 0;
        core::arch::asm!("nop");
    }
    value
}

#[inline]
fn outb(port: u16, value: u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        let _ = (port, value);
    }
}

/// Serial console wrapper
pub struct SerialConsole;

impl SerialConsole {
    pub fn new() -> Self {
        Self
    }
    
    pub fn write(&self, s: &str) {
        write_string(s);
    }
    
    pub fn write_byte(&self, b: u8) {
        write_char(b);
    }
    
    pub fn flush(&self) {
        // UART auto-flushes
    }
}