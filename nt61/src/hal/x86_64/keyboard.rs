//! PS/2 Keyboard Controller
//
//! A 8042-compatible controller driving either a single PS/2
//! keyboard or a PS/2 keyboard + mouse pair. We use the legacy
//! 0x60/0x64 I/O port pair, decode set-1 scancodes into a 256-byte
//! ASCII ring buffer, and offer `hal_display_string` /
//! `hal_query_display_string` which mirror the `hal.dll` exports of
//! the same name.
//
//! The set-1 decode table is the same as Windows 6.1's
//! `i8042prt` driver; we cover digits, letters, the basic
//! punctuation set, the standard modifiers, and the navigation
//! cluster (arrows, insert/delete/home/end/pageup/pagedown).

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{read_port_uchar, write_port_uchar};

const KBD_DATA_PORT: u16 = 0x60;
const KBD_STATUS_PORT: u16 = 0x64;
const KBD_COMMAND_PORT: u16 = 0x64;

const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;
pub const STATUS_AUX_OUTPUT_FULL: u8 = 1 << 5;
const STATUS_TIMEOUT: u8 = 1 << 6;
const STATUS_PARITY: u8 = 1 << 7;

const CMD_READ_CMDBYTE: u8 = 0x20;
const CMD_WRITE_CMDBYTE: u8 = 0x60;
const CMD_DISABLE_AUX: u8 = 0xA7;
pub const CMD_ENABLE_AUX: u8 = 0xA8;
const CMD_DISABLE_KBD: u8 = 0xAD;
const CMD_ENABLE_KBD: u8 = 0xAE;
pub const CMD_RESET_CPU: u8 = 0xFE;

const BUF_SIZE: usize = 256;

static BUF: [AtomicU8; BUF_SIZE] = [const { AtomicU8::new(0) }; BUF_SIZE];
static HEAD: AtomicUsize = AtomicUsize::new(0);
static TAIL: AtomicUsize = AtomicUsize::new(0);
static SHIFT_DOWN: AtomicBool = AtomicBool::new(false);
static CTRL_DOWN: AtomicBool = AtomicBool::new(false);
static ALT_DOWN: AtomicBool = AtomicBool::new(false);
static CAPS_LOCK: AtomicBool = AtomicBool::new(false);
static EXTENDED_PREFIX: AtomicBool = AtomicBool::new(false);

/// read the controller status port.
#[inline]
fn status() -> u8 {
    read_port_uchar(KBD_STATUS_PORT)
}

/// Block until the controller's input buffer is empty. We need
/// this before every command write, because writing while the
/// input buffer is full silently drops the byte.
fn wait_input_empty() {
    for _ in 0..100_000 {
        if status() & STATUS_INPUT_FULL == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Block until the controller has produced an output byte.
fn wait_output_full() -> Option<u8> {
    for _ in 0..100_000 {
        let s = status();
        if s & STATUS_OUTPUT_FULL != 0 {
            // Parity / timeout errors drop the byte.
            if s & (STATUS_PARITY | STATUS_TIMEOUT) != 0 {
                return None;
            }
            return Some(read_port_uchar(KBD_DATA_PORT));
        }
        core::hint::spin_loop();
    }
    None
}

fn send_command(cmd: u8) {
    wait_input_empty();
    write_port_uchar(KBD_COMMAND_PORT, cmd);
}

fn send_data(data: u8) {
    wait_input_empty();
    write_port_uchar(KBD_DATA_PORT, data);
}

/// read the controller's command byte.
fn read_command_byte() -> u8 {
    send_command(CMD_READ_CMDBYTE);
    wait_output_full().unwrap_or(0)
}

/// write the controller's command byte.
fn write_command_byte(value: u8) {
    send_command(CMD_WRITE_CMDBYTE);
    wait_input_empty();
    write_port_uchar(KBD_DATA_PORT, value);
}

fn push_byte(b: u8) {
    let head = HEAD.load(Ordering::Relaxed);
    let next = (head + 1) % BUF_SIZE;
    let tail = TAIL.load(Ordering::Relaxed);
    if next == tail {
        return;
    } // full
    BUF[head].store(b, Ordering::Relaxed);
    HEAD.store(next, Ordering::Relaxed);
    // Wake console readers parked on the input event (NT 6.1:
    // the console input queue signals its event on every input
    // record). Safe from the IRQ handler - the wake path only
    // touches dispatcher wait-list state.
    crate::hal::common::keyboard_input::signal_input_available();
}

/// read a single decoded ASCII byte from the buffer. Returns
/// -1 if the buffer is empty.
pub fn getc() -> i16 {
    let tail = TAIL.load(Ordering::Relaxed);
    let head = HEAD.load(Ordering::Relaxed);
    if tail == head {
        return -1;
    }
    let b = BUF[tail].load(Ordering::Relaxed);
    TAIL.store((tail + 1) % BUF_SIZE, Ordering::Relaxed);
    b as i16
}

/// Enqueue a character into the input buffer.
/// Used by USB HID keyboard to inject keystrokes into the
/// shared keyboard input queue.
pub fn enqueue_char(c: u8) {
    push_byte(c);
}

/// read one raw scancode byte from the controller. Returns -1
/// if no scancode is pending. The low 7 bits are the make code;
/// bit 7 indicates a release.
pub fn read_scancode() -> i16 {
    if status() & STATUS_OUTPUT_FULL == 0 {
        return -1;
    }
    read_port_uchar(KBD_DATA_PORT) as i16
}

/// Convert a set-1 make code to a single ASCII byte. Returns
/// `None` if the scancode does not produce a printable character
/// (e.g. modifier alone, function key, navigation key).
pub fn scancode_to_ascii(sc: u8, shift: bool, caps: bool) -> Option<u8> {
    let mut ascii: u8 = match sc {
        0x02 => b'1',
        0x03 => b'2',
        0x04 => b'3',
        0x05 => b'4',
        0x06 => b'5',
        0x07 => b'6',
        0x08 => b'7',
        0x09 => b'8',
        0x0A => b'9',
        0x0B => b'0',
        0x0C => b'-',
        0x0D => b'=',
        0x0E => b'\x08', // backspace
        0x0F => b'\t',
        0x10 => b'q',
        0x11 => b'w',
        0x12 => b'e',
        0x13 => b'r',
        0x14 => b't',
        0x15 => b'y',
        0x16 => b'u',
        0x17 => b'i',
        0x18 => b'o',
        0x19 => b'p',
        0x1A => b'[',
        0x1B => b']',
        0x1C => b'\n',
        0x1E => b'a',
        0x1F => b's',
        0x20 => b'd',
        0x21 => b'f',
        0x22 => b'g',
        0x23 => b'h',
        0x24 => b'j',
        0x25 => b'k',
        0x26 => b'l',
        0x27 => b';',
        0x28 => b'\'',
        0x29 => b'`',
        0x2B => b'\\',
        0x2C => b'z',
        0x2D => b'x',
        0x2E => b'c',
        0x2F => b'v',
        0x30 => b'b',
        0x31 => b'n',
        0x32 => b'm',
        0x33 => b',',
        0x34 => b'.',
        0x35 => b'/',
        0x39 => b' ',
        // Numpad cluster (NumLock off → navigation; on → digits).
        0x47 => b'7',
        0x48 => b'8',
        0x49 => b'9',
        0x4B => b'4',
        0x4C => b'5',
        0x4D => b'6',
        0x4F => b'1',
        0x50 => b'2',
        0x51 => b'3',
        0x52 => b'0',
        0x53 => b'.',
        _ => return None,
    };

    // Apply Shift / CapsLock to letters.
    if ascii.is_ascii_alphabetic() {
        let upper = if shift { !caps } else { caps };
        if upper {
            ascii = ascii.to_ascii_uppercase();
        }
    } else if shift {
        // Punctuation shift map.
        ascii = match sc {
            0x02 => b'!',
            0x03 => b'@',
            0x04 => b'#',
            0x05 => b'$',
            0x06 => b'%',
            0x07 => b'^',
            0x08 => b'&',
            0x09 => b'*',
            0x0A => b'(',
            0x0B => b')',
            0x0C => b'_',
            0x0D => b'+',
            0x1A => b'{',
            0x1B => b'}',
            0x27 => b':',
            0x28 => b'"',
            0x29 => b'~',
            0x2B => b'|',
            0x33 => b'<',
            0x34 => b'>',
            0x35 => b'?',
            _ => ascii,
        };
    }
    Some(ascii)
}

/// Process one raw Set-1 scancode byte (after 8042 translation).
///
/// This is the single shared decoder used by both the IRQ handler
/// and the polled path. It maintains the shared modifier state and
/// pushes decoded ASCII (or ANSI escape sequences for arrow keys)
/// into the ring buffer.
pub fn process_scancode(sc: u8) {
    let release = (sc & 0x80) != 0;
    let code = (sc & 0x7F) as u8;

    // Handle the 0xE0 extended prefix (arrow keys, navigation).
    if EXTENDED_PREFIX.load(Ordering::Relaxed) {
        EXTENDED_PREFIX.store(false, Ordering::Relaxed);
        if release {
            return;
        }
        match code {
            0x48 => push_ansi_escape(b'A'),
            0x50 => push_ansi_escape(b'B'),
            0x4B => push_ansi_escape(b'D'),
            0x4D => push_ansi_escape(b'C'),
            _ => {}
        }
        return;
    }

    if code == 0xE0 {
        EXTENDED_PREFIX.store(true, Ordering::Relaxed);
        return;
    }

    match code {
        0x2A | 0x36 => SHIFT_DOWN.store(!release, Ordering::Relaxed),
        0x1D => CTRL_DOWN.store(!release, Ordering::Relaxed),
        0x38 => ALT_DOWN.store(!release, Ordering::Relaxed),
        0x3A => {
            if !release {
                CAPS_LOCK.store(!CAPS_LOCK.load(Ordering::Relaxed), Ordering::Relaxed);
            }
        }
        _ => {
            if !release {
                let shift = SHIFT_DOWN.load(Ordering::Relaxed);
                let caps = CAPS_LOCK.load(Ordering::Relaxed);
                if let Some(c) = scancode_to_ascii(code, shift, caps) {
                    push_byte(if c == b'\n' { b'\r' } else { c });
                }
            }
        }
    }
}

/// Push an ANSI escape sequence for an arrow key into the buffer.
fn push_ansi_escape(direction: u8) {
    push_byte(0x1B);
    push_byte(b'[');
    push_byte(direction);
}

/// IRQ1 handler. Drains the controller and pushes decodable
/// bytes into the ring buffer. Wired into the IDT by
/// `arch::x86_64::dispatch`.
pub extern "C" fn irq_handler() {
    loop {
        let sc = read_scancode();
        if sc < 0 {
            break;
        }
        process_scancode(sc as u8);
    }
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::pic::send_eoi(1);
}

/// Complete keyboard reset sequence for SafeModeCmd polling mode.
///
/// This performs a full hardware reset of the PS/2 keyboard controller
/// and keyboard device:
/// 1. Disable keyboard and mouse devices
/// 2. Flush output buffer
/// 3. Send keyboard reset command (0xFF)
/// 4. Wait for BAT completion code (0xAA)
/// 5. Configure 8042 command byte (disable all interrupts)
/// 6. Final buffer flush
///
/// Call this instead of `init()` when entering SafeModeCmd to ensure
/// the keyboard is in a known, clean state for polling I/O.
pub fn full_reset_for_poll() {
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::read_port_uchar;
    use core::sync::atomic::Ordering;

    // Reset static state
    HEAD.store(0, Ordering::SeqCst);
    TAIL.store(0, Ordering::SeqCst);
    SHIFT_DOWN.store(false, Ordering::SeqCst);
    CTRL_DOWN.store(false, Ordering::SeqCst);
    ALT_DOWN.store(false, Ordering::SeqCst);
    CAPS_LOCK.store(false, Ordering::SeqCst);
    EXTENDED_PREFIX.store(false, Ordering::SeqCst);

    // Step 1: Disable keyboard and mouse
    send_command(CMD_DISABLE_KBD);
    send_command(CMD_DISABLE_AUX);

    // Step 2: Flush output buffer (drain any stale bytes)
    for _ in 0..64 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let _ = read_port_uchar(KBD_DATA_PORT);
    }

    // Step 3: Send keyboard reset command (0xFF)
    // The keyboard will respond with 0xFA (ACK), then 0xAA (BAT success) or 0xFC (BAT failure)
    send_data(0xFF);

    // Step 4: Wait for ACK (0xFA) from keyboard
    let mut got_ack = false;
    for _ in 0..10000 {
        let s = status();
        if s & STATUS_OUTPUT_FULL != 0 {
            let b = read_port_uchar(KBD_DATA_PORT);
            if b == 0xFA {
                got_ack = true;
                break;
            }
            // Any other byte, keep waiting
        }
        core::hint::spin_loop();
    }

    if !got_ack {
        // No ACK received, keyboard might not be present or not responding
        // Continue anyway to try the BAT wait
    }

    // Wait for BAT completion (0xAA = success, 0xFC = failure)
    for _ in 0..10000 {
        let s = status();
        if s & STATUS_OUTPUT_FULL != 0 {
            let b = read_port_uchar(KBD_DATA_PORT);
            if b == 0xAA {
                // BAT success: keyboard is healthy and self-test passed.
                break;
            }
            if b == 0xFC {
                // BAT failure, keyboard error.
                break;
            }
        }
        core::hint::spin_loop();
    }

    // Step 5: Configure 8042 command byte - disable interrupts but KEEP translate mode
    // Translate mode (bit 6) converts QEMU's internal Set 3 scancodes to Set 1,
    // which is what our scancode_to_ascii() table expects. Disabling translation
    // would expose raw Set 3 codes and break the ASCII mapping.
    let cb = read_command_byte();
    // Clear bit 0: disable keyboard interrupt
    // Clear bit 1: disable mouse interrupt
    // Force translation mode on. QEMU resets the controller with
    // whatever translation state firmware selected; a closed bit 6
    // exposes raw Set 2 codes that the Set 1 decoder cannot accept.
    let new_cb = (cb & !(0x01 | 0x02)) | 0x40;
    write_command_byte(new_cb);

    // Step 6: Enable keyboard, keep mouse disabled
    send_command(CMD_ENABLE_KBD);
    send_command(CMD_DISABLE_AUX);
    // NOTE: We do NOT call select_scan_code_set1() here. The 8042
    // translation mode (bit 6 of the command byte, forced above)
    // already converts the keyboard device's default Set-2 scan
    // codes into Set-1. If we also told the device to emit Set-1
    // the controller would try to "translate" Set-1 codes as if
    // they were Set-2, producing the garbled input the shell saw.

    // Final buffer flush
    for _ in 0..64 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let _ = read_port_uchar(KBD_DATA_PORT);
    }
}

/// Initialize the 8042 controller for **polling-only mode** (no interrupts).
/// This is the safe initialization for SafeModeCmd where interrupts are disabled.
///
/// Unlike `init()`, this function:
/// - Disables keyboard interrupts in the 8042 controller (command byte bit 0 = 0)
/// - Does NOT unmask IRQ1 on the PIC
/// - Only enables keyboard data reporting (translate mode bit 6 = 1)
///
/// Call this when you plan to read the keyboard via polling (status port + data port)
/// rather than via IRQ-driven interrupts.
pub fn safe_init_for_poll() {
    // Reset state
    HEAD.store(0, Ordering::SeqCst);
    TAIL.store(0, Ordering::SeqCst);
    SHIFT_DOWN.store(false, Ordering::SeqCst);
    CTRL_DOWN.store(false, Ordering::SeqCst);
    ALT_DOWN.store(false, Ordering::SeqCst);
    CAPS_LOCK.store(false, Ordering::SeqCst);
    EXTENDED_PREFIX.store(false, Ordering::SeqCst);

    // Disable both devices so we can write the command byte safely.
    send_command(CMD_DISABLE_KBD);
    send_command(CMD_DISABLE_AUX);

    // Flush the output buffer - drain any stale bytes.
    for _ in 0..32 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let _ = read_port_uchar(KBD_DATA_PORT);
    }

    // read current command byte and modify it.
    let mut cb = read_command_byte();
    // Clear bits:
    //   bit 0: disable keyboard interrupt (0 = no IRQ)
    //   bit 1: disable mouse interrupt (0 = no IRQ)
    // Force translation mode on so the keyboard driver always sees
    // Set 1 make/release codes, independent of firmware state.
    cb = (cb & !(0x01 | 0x02)) | 0x40;
    write_command_byte(cb);

    // Enable keyboard, keep mouse disabled.
    send_command(CMD_ENABLE_KBD);
    send_command(CMD_DISABLE_AUX);
    // NOTE: No select_scan_code_set1() here either — same
    // double-translation reasoning as full_reset_for_poll().

    // Final flush of any bytes that appeared during configuration.
    for _ in 0..32 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let _ = read_port_uchar(KBD_DATA_PORT);
    }
}

/// Initialise the 8042 controller. The interrupt subsystem is
/// assumed to be alive — this routine only touches the keyboard
/// half of the controller, leaving the mouse disabled.
pub fn init() {
    HEAD.store(0, Ordering::SeqCst);
    TAIL.store(0, Ordering::SeqCst);
    SHIFT_DOWN.store(false, Ordering::SeqCst);
    CTRL_DOWN.store(false, Ordering::SeqCst);
    ALT_DOWN.store(false, Ordering::SeqCst);
    CAPS_LOCK.store(false, Ordering::SeqCst);
    EXTENDED_PREFIX.store(false, Ordering::SeqCst);

    // Disable both devices so we can write the command byte
    // without race.
    send_command(CMD_DISABLE_KBD);
    send_command(CMD_DISABLE_AUX);

    // Flush the output buffer.
    for _ in 0..16 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let _ = read_port_uchar(KBD_DATA_PORT);
    }

    let mut cb = read_command_byte();
    // Enable keyboard IRQ while preserving the Set 2 to Set 1
    // translation required by `scancode_to_ascii()`.
    cb = (cb & !(0x20 | 0x10)) | (0x40 | 0x01);
    write_command_byte(cb);

    send_command(CMD_ENABLE_KBD);
    send_command(CMD_DISABLE_AUX);
    // NOTE: No select_scan_code_set1() here — the 8042 translation
    // mode handles Set-2 → Set-1 conversion; the device must stay
    // in its default Set-2 mode.
}

/// Enable the keyboard's IRQ line on the master PIC (IRQ1 → vector
/// 0x21). Called by `arch::init_hardware()` AFTER the 8042 has been
/// fully reset and AFTER the IDT has loaded the IRQ dispatcher stub.
///
/// Why this exists: `pic::init_and_mask_all()` finishes by writing
/// 0xFF to both PIC data ports, leaving *every* IRQ masked. The
/// IRQ for the keyboard therefore stays masked even when `sti`
/// later flips IF=1. The dispatcher at vector 0x21 never runs.
/// `servers::cmd::read_command()` then spins forever in
/// `keyboard_unified::ps2_poll_char` (which uses port-I/O, not
/// interrupts), and a user pressing a key on the QEMU window
/// produces no feedback — and on some OVMF/QEMU combinations an
/// unhandled 8042 output-buffer byte eventually causes the
/// firmware to assert a CPU reset, which is what the user
/// perceives as "QEMU exits".
///
/// Unmasking IRQ1 lets the keystroke reach `irq_handler()`, which
/// drains the 8042 and pushes the decoded byte into the ring
/// buffer consumed by `getc()`.
///
/// Safe to call multiple times — `unmask_irq` is idempotent.
pub fn enable_irq() {
    // Drain any residual scancodes so a stale byte cannot trigger
    // an unexpected IRQ as soon as we un-mask the line. OVMF's
    // 8042 emulation occasionally leaves the BAT (Basic Assurance
    // Test) completion byte 0xAA queued in the output buffer.
    for _ in 0..16 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let _ = read_port_uchar(KBD_DATA_PORT);
    }
    // Unmask IRQ1 (master PIC line 1). IRQ2 (cascade, already
    // masked) and IRQ12 (mouse, masked) stay disabled so we don't
    // get spurious interrupts from the PS/2 mouse channel.
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::pic::unmask_irq(1);
}

/// Disable the keyboard's IRQ line on the master PIC (IRQ1 → vector
/// 0x21) AND disable the keyboard interrupt in the 8042 controller.
///
/// This is the inverse of `enable_irq()`. Call this before entering
/// `servers::cmd::run_shell()` in SafeModeCmd to ensure the 8042
/// never attempts to raise IRQ1 while the PIC has the line masked.
///
/// Why this matters: `keyboard::init()` sets command byte bit 0 = 1,
/// which enables keyboard-generated IRQs. In SafeModeCmd the PIC mask is
/// 0xFFFF (all lines masked) to prevent PIT IRQ0 from firing.
/// If a key is pressed while the 8042 interrupt is still enabled but
/// the PIC line is masked, the 8042 may enter an inconsistent state,
/// causing the CPU to triple-fault when the next keyboard read is attempted.
pub fn disable_irq() {
    // First mask IRQ1 on the PIC so no IRQ fires even if the 8042
    // still has interrupts briefly enabled.
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::pic::mask_irq(1);

    // Now disable keyboard interrupts in the 8042 controller itself.
    // We must read the current command byte, clear bit 0, and write it back.
    let cb = read_command_byte();
    // Clear bit 0: disable keyboard interrupt.
    // Preserve all other bits (translate mode, mouse settings, etc.).
    write_command_byte(cb & !0x01);

    // Drain any residual bytes in the 8042 output buffer so a stale
    // scancode cannot confuse the polling loop.
    for _ in 0..16 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let _ = read_port_uchar(KBD_DATA_PORT);
    }
}

/// Print a single character to the kernel log. The `hal.dll`
/// `hal_display_string` export writes to the bootstrap display; on
/// the PC that means the Bochs/QEMU debug-port (0xE9) plus the
/// serial port.
pub fn hal_display_string(s: &str) {
    // 0xE9 debug port: Bochs and QEMU -debugcon log this byte to
    // the host console.
    for b in s.bytes() {
        write_port_uchar(0xE9, b);
    }
    // Mirror to the serial port so headless serial consoles see
    // the same output.
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string(s);
}

/// Copy the last character we wrote (hal_display_string is one-way
/// on real hardware, so this is a debug-only stub). Returns the
/// number of bytes copied.
pub fn hal_query_display_string(buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    buf[0] = 0;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scancode_decode_letters() {
        assert_eq!(scancode_to_ascii(0x1E, false, false), Some(b'a'));
        assert_eq!(scancode_to_ascii(0x1E, true, false), Some(b'A'));
        assert_eq!(scancode_to_ascii(0x1E, false, true), Some(b'A'));
        assert_eq!(scancode_to_ascii(0x1E, true, true), Some(b'a'));
    }

    #[test]
    fn scancode_decode_punctuation() {
        assert_eq!(scancode_to_ascii(0x02, false, false), Some(b'1'));
        assert_eq!(scancode_to_ascii(0x02, true, false), Some(b'!'));
    }
}
