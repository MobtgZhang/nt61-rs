//! riscv64 backend for the abstract text console.
//!
//! Mirrors the aarch64 backend: serial sink + log ring. The
//! riscv64 QEMU virt machine exposes a 16550A UART at the
//! standard port, and `hal::riscv64::serial` already has the
//! init / put_char / write_string helpers we need.

use core::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
static LINE_COUNT: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
#[derive(Clone, Copy)]
struct Line {
    bytes: [u8; super::COLS],
    attr: u8,
    len: u8,
}

impl Line {
    const fn empty() -> Self {
        Self {
            bytes: [0u8; super::COLS],
            attr: super::ATTR_DEFAULT,
            len: 0,
        }
    }
}

static mut RING: [Line; super::LOG_RING_LINES] = [const { Line::empty() }; super::LOG_RING_LINES];

static mut CUR_BYTES: [u8; super::COLS] = [0u8; super::COLS];
static mut CUR_LEN: u8 = 0;
static mut CUR_ATTR: u8 = super::ATTR_DEFAULT;

/// Serializes ring and cursor updates. Reentrant on the owning CPU
/// so a fault handler that logs while the faulting context holds the
/// lock cannot spin against itself (audit hal_rtl P0-2).
static RING_LOCK: crate::hal::common::relock::ReentrantLock =
    crate::hal::common::relock::ReentrantLock::new();

pub fn init() {
    let _guard = RING_LOCK.lock();
    NEXT.store(0, Ordering::Release);
    LINE_COUNT.store(0, Ordering::Release);
    unsafe {
        CUR_LEN = 0;
        CUR_ATTR = super::ATTR_DEFAULT;
    }
}

pub fn set_attr(attr: u8) {
    let _guard = RING_LOCK.lock();
    unsafe {
        CUR_ATTR = attr;
    }
}

pub fn put_byte(b: u8) {
    // 1. Mirror to the cross-arch LFB if it is active. This is
    //    the GUI-visible sink after the serial-suppress gate is
    //    flipped on by `kernel_main`.
    if crate::hal::common::framebuffer::is_active() {
        crate::drivers::bootvid::put_byte_to_active_console(b);
    }

    // 2. Mirror to the serial port so headless debug
    //    installations (the canonical riscv64 deployment on
    //    QEMU virt) actually see the byte. The serial gate
    //    is honoured here — once `kernel_main` flips it on, the
    //    byte is silently dropped.
    if !crate::hal::common::serial_disable::is_disabled() {
        crate::hal::riscv64::serial::put_char(b);
    }

    // 3. Accumulate into the half-built line and commit on
    //    newline / line overflow. This is what the SafeBootMode
    //    CMD shell's log display pane reads from when it paints
    //    its scrollback window on shell entry.
    let _guard = RING_LOCK.lock();
    unsafe {
        match b {
            b'\n' | b'\r' => {
                commit_line();
            }
            0x08 | 0x7F => {
                if CUR_LEN > 0 {
                    CUR_LEN -= 1;
                }
            }
            b => {
                if (CUR_LEN as usize) < super::COLS {
                    CUR_BYTES[CUR_LEN as usize] = b;
                    CUR_LEN += 1;
                } else {
                    commit_line();
                    CUR_BYTES[0] = b;
                    CUR_LEN = 1;
                }
            }
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn commit_line() {
    let slot = NEXT.load(Ordering::Acquire);
    let dst = &mut RING[slot];
    let len = CUR_LEN as usize;
    dst.bytes[..len].copy_from_slice(&CUR_BYTES[..len]);
    dst.len = CUR_LEN;
    dst.attr = CUR_ATTR;
    // Wrap at the ACTIVE window, not the compile-time capacity,
    // so log_ring_set_lines takes effect on the next write.
    NEXT.store((slot + 1) % super::log_ring_lines(), Ordering::Release);
    LINE_COUNT.fetch_add(1, Ordering::Release);
    CUR_LEN = 0;
}

pub fn clear() {
    // Paint the LFB black and home the bootvid cursor so the
    // GUI-visible sink matches the serial terminal after the
    // clear.
    if crate::hal::common::framebuffer::is_active() {
        crate::drivers::bootvid::vid_clear_black();
    }
    // ANSI: ESC [ 2 J   clear entire screen
    //        ESC [ H     move cursor to (0, 0)
    crate::hal::riscv64::serial::write_string("\x1b[2J\x1b[H\r\n[screen cleared]\r\n");
    let _guard = RING_LOCK.lock();
    unsafe {
        commit_line();
        commit_line();
    }
}

pub fn set_cursor(x: u8, y: u8) {
    // Position the LFB cursor. bootvid addresses the framebuffer
    // in pixels; the text facade works in glyph cells, so the
    // shared cell-metric constants convert cell -> pixel here.
    if crate::hal::common::framebuffer::is_active() {
        let x_px = (x as u32) * super::FONT_CELL_WIDTH_PX;
        let y_px = (y as u32) * super::FONT_LINE_HEIGHT_PX;
        crate::drivers::bootvid::vid_set_cursor_position(x_px as u16, y_px as u16);
    }
    // ANSI: ESC [ <row> ; <col> H
    let mut buf = [0u8; 16];
    let s = format_ansi_cup(&mut buf, x as u32 + 1, y as u32 + 1);
    crate::hal::riscv64::serial::write_string(s);
}

fn format_ansi_cup<'a>(buf: &'a mut [u8; 16], row: u32, col: u32) -> &'a str {
    let mut p = 0;
    buf[p] = 0x1b;
    p += 1;
    buf[p] = b'[';
    p += 1;
    let mut tmp = [0u8; 8];
    let mut n = 0;
    let mut v = row;
    if v == 0 {
        tmp[n] = b'0';
        n += 1;
    } else {
        while v > 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        for i in 0..n / 2 {
            tmp.swap(i, n - 1 - i);
        }
    }
    for i in 0..n {
        buf[p] = tmp[i];
        p += 1;
    }
    buf[p] = b';';
    p += 1;
    n = 0;
    v = col;
    if v == 0 {
        tmp[n] = b'0';
        n += 1;
    } else {
        while v > 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        for i in 0..n / 2 {
            tmp.swap(i, n - 1 - i);
        }
    }
    for i in 0..n {
        buf[p] = tmp[i];
        p += 1;
    }
    buf[p] = b'H';
    p += 1;
    core::str::from_utf8(&buf[..p]).unwrap_or("")
}

pub fn log_line_count() -> usize {
    LINE_COUNT.load(Ordering::Acquire)
}

pub fn read_log_lines(buf: &mut [[u8; super::COLS + 2]]) -> usize {
    let _guard = RING_LOCK.lock();
    let n = buf.len().min(super::log_ring_lines());
    let next = NEXT.load(Ordering::Acquire);
    unsafe {
        for i in 0..n {
            let slot = (next + i) % super::LOG_RING_LINES;
            let src = &RING[slot];
            let dst = &mut buf[i];
            dst[..super::COLS].copy_from_slice(&src.bytes);
            dst[super::COLS] = src.attr;
            dst[super::COLS + 1] = src.len;
        }
    }
    n
}
