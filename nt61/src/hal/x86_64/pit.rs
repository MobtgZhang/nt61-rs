//! 8253 / 8254 Programmable Interval Timer (PIT)
//
//! Three counters, six modes. The kernel uses channel 0 in mode 2
//! (rate generator) as the legacy timer interrupt source. Channel
//! 2 is connected to the PC speaker; we drive that for
//! `HalMakeBeep`.

#![cfg(target_arch = "x86_64")]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{READ_PORT_UCHAR, WRITE_PORT_UCHAR};

/// PIT input frequency. The 8253/8254 is fed by a 1.19318 MHz
/// crystal on every PC since the original IBM PC.
pub const PIT_FREQUENCY: u64 = 1_193_180;

/// Channel 0 data port (system timer).
pub const PIT_CHANNEL0: u16 = 0x40;
/// Channel 1 data port (DRAM refresh; unused in modern systems).
pub const PIT_CHANNEL1: u16 = 0x41;
/// Channel 2 data port (PC speaker).
pub const PIT_CHANNEL2: u16 = 0x42;
/// Mode/command register.
pub const PIT_COMMAND: u16 = 0x43;

/// 8254 mode bits for the mode/command register.
pub mod mode {
    /// Channel select (bits 7..6).
    pub const SEL_CHAN0: u8 = 0b00_000_000;
    pub const SEL_CHAN1: u8 = 0b01_000_000;
    pub const SEL_CHAN2: u8 = 0b10_000_000;
    pub const READ_BACK: u8 = 0b11_000_000;
    /// Access mode (bits 5..4). 0=latch, 1=lo, 2=hi, 3=lo/hi.
    pub const ACCESS_LATCH: u8 = 0b00_000_000;
    pub const ACCESS_LO: u8 = 0b00_010_000;
    pub const ACCESS_HI: u8 = 0b00_100_000;
    pub const ACCESS_LOHI: u8 = 0b00_110_000;
    /// Operating mode (bits 3..1).
    pub const MODE_0: u8 = 0b000_00_0_0; // interrupt on terminal count
    pub const MODE_1: u8 = 0b000_00_0_1; // hardware re-triggerable one-shot
    pub const MODE_2: u8 = 0b000_00_1_0; // rate generator
    pub const MODE_3: u8 = 0b000_00_1_1; // square wave
    pub const MODE_4: u8 = 0b000_01_0_0; // software triggered strobe
    pub const MODE_5: u8 = 0b000_01_0_1; // hardware triggered strobe
    /// BCD / binary.
    pub const BINARY: u8 = 0b0000_0_0_0;
    pub const BCD: u8 = 0b0000_0_0_1;
}

/// 8042 keyboard controller / system command port. The speaker
/// enable gates (bits 0 and 1) live here.
const PORT_B_SYS: u16 = 0x61;

static PIT_HZ: AtomicU32 = AtomicU32::new(0);
static PIT_TICKS: AtomicU64 = AtomicU64::new(0);

/// Get the current PIT tick count
pub fn get_ticks() -> u64 {
    PIT_TICKS.load(Ordering::Relaxed)
}

/// Increment the PIT tick count (called from PIT interrupt handler)
pub fn increment_ticks() {
    PIT_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Get system time in milliseconds since PIT initialization
pub fn get_system_time_ms() -> u64 {
    let ticks = PIT_TICKS.load(Ordering::Relaxed);
    let hz = PIT_HZ.load(Ordering::Relaxed);
    if hz > 0 {
        ticks * 1000 / (hz as u64)
    } else {
        0
    }
}

/// Get system time in microseconds since PIT initialization
pub fn get_system_time_us() -> u64 {
    let ticks = PIT_TICKS.load(Ordering::Relaxed);
    let hz = PIT_HZ.load(Ordering::Relaxed);
    if hz > 0 {
        ticks * 1_000_000 / (hz as u64)
    } else {
        0
    }
}

#[inline]
fn io_wait() {
    unsafe { asm!("out 0x80, al", in("al") 0u8, options(nomem, nostack)); }
}

/// Set the rate generator on channel 0 to `hz` interrupts per
    /// second. Returns `true` on success.
pub fn init(hz: u32) -> bool {
    if hz == 0 { return false; }
    let divisor = (PIT_FREQUENCY / hz as u64) as u16;
    if divisor == 0 { return false; }

    // BRING-UP WORKAROUND: do NOT actually program the PIT.
    // Earlier boot paths left the PIT running at 18.2 Hz (or the
    // OVMF-default 1000 Hz after a prior `pit::init(1000)`), and
    // the periodic IRQ 0 was arriving during the first user-mode
    // syscall handler invocation. Even with IST-based IRQ
    // handlers, the PIT was racing the kernel's trap-frame
    // restoration and corrupting the user RIP slot, which made
    // sysretq jump to a low-memory BCDE region and crash.
    //
    // We return `false` here so callers (which usually ignore the
    // boolean anyway) know the timer is not actually ticking. The
    // proper fix is to size the IST stack for deep nesting and
    // verify the IRQ handlers are re-entrant; once that lands the
    // PIT programming block that lived below this comment can be
    // reinstated verbatim.
    false
}

/// Read the current programmed frequency in Hz.
pub fn pit_freq_hz() -> u32 {
    PIT_HZ.load(Ordering::Acquire)
}

/// Read the 16-bit counter value of channel 0. The PIT
/// "read-back" command latches the value, so we issue the latch
/// command first and then read lo/hi.
pub fn pit_counter() -> u16 {
    // Latch channel 0.
    WRITE_PORT_UCHAR(PIT_COMMAND, mode::SEL_CHAN0 | mode::ACCESS_LATCH);
    let lo = READ_PORT_UCHAR(PIT_CHANNEL0);
    let hi = READ_PORT_UCHAR(PIT_CHANNEL0);
    ((hi as u16) << 8) | (lo as u16)
}

/// Program channel 2 with a divisor for the supplied frequency.
/// `freq` is the tone frequency in Hz; returns the divisor.
fn pit2_program(freq: u32) -> u16 {
    let freq = freq.max(1) as u64;
    let divisor = (PIT_FREQUENCY / freq).max(1) as u16;
    let cmd = mode::SEL_CHAN2
            | mode::ACCESS_LOHI
            | mode::MODE_3
            | mode::BINARY;
    WRITE_PORT_UCHAR(PIT_COMMAND, cmd);
    WRITE_PORT_UCHAR(PIT_CHANNEL2, (divisor & 0xFF) as u8);
    io_wait();
    WRITE_PORT_UCHAR(PIT_CHANNEL2, ((divisor >> 8) & 0xFF) as u8);
    io_wait();
    divisor
}

/// Make the PC speaker emit a tone at `frequency` Hz for
/// `duration` milliseconds. Matches the surface of
/// `hal.dll`'s `HalMakeBeep(frequency, duration)` export.
///
/// Returns `true` if the tone was scheduled, `false` if the
/// supplied arguments were out of range.
pub fn HalMakeBeep(frequency: u32, duration: u32) -> bool {
    if frequency < 20 || frequency > 20_000 {
        return false;
    }
    pit2_program(frequency);

    // Read the current value of port 0x61, set bits 0 and 1 to
    // enable the speaker gate and the timer channel 2 output.
    let prev = READ_PORT_UCHAR(PORT_B_SYS);
    WRITE_PORT_UCHAR(PORT_B_SYS, prev | 0x03);
    // Busy-wait the duration. We use a calibrated spin because
    // the kernel has no millisecond-resolution scheduler yet.
    let hz = pit_freq_hz().max(18) as u64;
    let iter = (duration as u64) * hz / 1000;
    for _ in 0..iter {
        core::hint::spin_loop();
    }
    // Disable the speaker.
    WRITE_PORT_UCHAR(PORT_B_SYS, prev & !0x03);
    true
}

/// Initialise the PIT but leave channel 0 masked at the PIC
/// (i.e. the IRQ0 line will not deliver interrupts). This is the
/// legacy behaviour when the system is using a different timer
/// source (HPET or LAPIC).
pub fn init_masked(hz: u32) -> bool {
    if !init(hz) { return false; }
    // Mask IRQ0 at the master PIC. 0x21 bit 0 = 1 disables IRQ0.
    let mask = READ_PORT_UCHAR(0x21);
    WRITE_PORT_UCHAR(0x21, mask | 0x01);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divisor_calculation() {
        // 100 Hz should give divisor 11931 (rounded down).
        let d = (PIT_FREQUENCY / 100) as u16;
        assert_eq!(d, 11931);

        // 1000 Hz should give 1193.
        let d = (PIT_FREQUENCY / 1000) as u16;
        assert_eq!(d, 1193);
    }
}
