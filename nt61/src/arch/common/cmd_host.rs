//! Common host services used by the Ring-3 `cmd.exe` shell.
//!
//! The user-mode shell has one small private ABI (`0x0202`–`0x0216`)
//! that talks to kernel-side filesystem state. Keeping the kernel
//! implementation here lets every ISA's trap handler translate only
//! its own register frame once, while console and keyboard access go
//! through the shared HAL facades.

pub const SYS_PUTCHAR: u32 = 0x0202;
pub const SYS_POLL_KEY: u32 = 0x0203;
pub const SYS_GET_KEY: u32 = 0x0204;
pub const SYS_CLEARSCREEN: u32 = 0x0205;
pub const SYS_READ_LINE: u32 = 0x0211;
pub const SYS_RETURN_TO_FIRMWARE: u32 = 0x0214;
pub const SYS_CMD_EXECUTE: u32 = 0x0215;
pub const SYS_PRINT_PROMPT: u32 = 0x0216;

pub const STATUS_SUCCESS: u64 = 0;
pub const STATUS_NO_DATA: u64 = 0xC000_0011;
pub const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;

pub fn putchar(byte: u8) -> u64 {
    crate::hal::text_console::put_byte(byte);
    STATUS_SUCCESS
}

pub fn poll_key() -> Option<u8> {
    crate::hal::keyboard_input::poll();
    crate::hal::keyboard_input::try_read_byte()
}

pub fn get_key() -> u8 {
    loop {
        if let Some(byte) = poll_key() {
            return byte;
        }
        core::hint::spin_loop();
    }
}

pub fn clear_screen() -> u64 {
    crate::hal::text_console::clear();
    STATUS_SUCCESS
}

/// Read one editable line from the unified keyboard backend.
///
/// Returns the number of bytes written, excluding the required NUL.
///
/// # Safety
///
/// `buffer` must be writable user memory covering `length` bytes.
pub unsafe fn read_line(buffer: *mut u8, length: usize) -> Option<usize> {
    if buffer.is_null() || length == 0 {
        return None;
    }
    let slice = core::slice::from_raw_parts_mut(buffer, length);
    Some(super::line_edit::read_line(slice, length))
}

pub fn return_to_firmware() -> ! {
    crate::arch::halt_loop()
}

pub fn execute_command(buffer: *const u8, length: usize) -> Result<bool, &'static str> {
    crate::servers::cmd::execute_command_from_user_ptr(buffer, length)
}

pub fn print_prompt() -> u64 {
    crate::servers::cmd::print_ring3_prompt();
    STATUS_SUCCESS
}
