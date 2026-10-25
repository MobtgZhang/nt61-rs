//! Architecture-independent panic reporting shared by every kernel binary.

#[cfg_attr(
    all(feature = "binary_panic", not(test), not(target_os = "linux")),
    allow(dead_code)
)]
struct PanicFormatter {
    buf: [u8; 256],
    len: usize,
}

#[cfg_attr(
    all(feature = "binary_panic", not(test), not(target_os = "linux")),
    allow(dead_code)
)]
impl PanicFormatter {
    const fn new() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("kernel panic")
    }
}

impl core::fmt::Write for PanicFormatter {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = byte;
                self.len += 1;
            }
        }
        Ok(())
    }
}

#[cfg_attr(
    all(feature = "binary_panic", not(test), not(target_os = "linux")),
    panic_handler
)]
#[allow(dead_code)]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    let mut formatter = PanicFormatter::new();
    let _ =
        core::fmt::Write::write_fmt(&mut formatter, core::format_args!("KERNEL PANIC: {}", info));
    let rendered = formatter.as_str();
    crate::hal::serial::write_string_always(rendered);
    crate::hal::serial::write_string_always("\r\n");
    crate::drivers::bootvid::bugcheck_screen(0x000000E2, rendered);
    loop {
        crate::arch::halt();
    }
}
