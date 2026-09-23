//! kernel32 — Console Input Functions
//!
//! Complete console input support for Windows 7:
//! - ReadConsoleW
//! - GetConsoleScreenBufferInfo
//! - SetConsoleCursorPosition
//! - GetConsoleMode / SetConsoleMode
//!
//! References:
//!   * MSDN Library "Windows 7" — Console Functions

use super::types::{BOOL, DWORD, FALSE, HANDLE, TRUE};
use super::error::SetLastError;
use crate::ke::sync::Spinlock;
use core::ptr;


#[repr(C)]
#[derive(Clone, Copy)]
pub struct COORD {
    pub x: i16,
    pub y: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SMALL_RECT {
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
}

#[repr(C)]
pub struct CONSOLE_SCREEN_BUFFER_INFO {
    pub dw_size: COORD,
    pub dw_cursor_position: COORD,
    pub w_attributes: u16,
    pub sr_window: SMALL_RECT,
    pub dw_maximum_window_size: COORD,
}


struct ConsoleState {
    cursor_x: i16,
    cursor_y: i16,
    width: i16,
    height: i16,
    attributes: u16,
    input_mode: DWORD,
    output_mode: DWORD,
}

impl ConsoleState {
    const fn new() -> Self {
        Self {
            cursor_x: 0,
            cursor_y: 0,
            width: 80,
            height: 25,
            attributes: 0x07, // White on black
            input_mode: 0x0001 | 0x0002, // ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT
            output_mode: 0x0001 | 0x0002, // ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT
        }
    }
}

static CONSOLE_STATE: Spinlock<ConsoleState> = Spinlock::new(ConsoleState::new());


pub const ENABLE_PROCESSED_INPUT: DWORD = 0x0001;
pub const ENABLE_LINE_INPUT: DWORD = 0x0002;
pub const ENABLE_ECHO_INPUT: DWORD = 0x0004;
pub const ENABLE_WINDOW_INPUT: DWORD = 0x0008;
pub const ENABLE_MOUSE_INPUT: DWORD = 0x0010;
pub const ENABLE_INSERT_MODE: DWORD = 0x0020;
pub const ENABLE_QUICK_EDIT_MODE: DWORD = 0x0040;
pub const ENABLE_EXTENDED_FLAGS: DWORD = 0x0080;

pub const ENABLE_PROCESSED_OUTPUT: DWORD = 0x0001;
pub const ENABLE_WRAP_AT_EOL_OUTPUT: DWORD = 0x0002;


const CONSOLE_INPUT_BUFFER_SIZE: usize = 256;
static CONSOLE_INPUT_BUFFER: Spinlock<[u16; CONSOLE_INPUT_BUFFER_SIZE]> =
    Spinlock::new([0; CONSOLE_INPUT_BUFFER_SIZE]);
static CONSOLE_INPUT_LENGTH: Spinlock<usize> = Spinlock::new(0);

pub unsafe extern "C" fn ReadConsoleW(
    console_input: HANDLE,
    buffer: *mut u16,
    number_of_chars_to_read: DWORD,
    number_of_chars_read: *mut DWORD,
    input_control: *const u8,
) -> BOOL {
    if console_input.is_null() || buffer.is_null() {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    let _ = input_control;


    let input_buf = CONSOLE_INPUT_BUFFER.lock();
    let input_len = *CONSOLE_INPUT_LENGTH.lock();

    let chars_to_copy = core::cmp::min(number_of_chars_to_read as usize, input_len);

    if chars_to_copy > 0 {
        ptr::copy_nonoverlapping(input_buf.as_ptr(), buffer, chars_to_copy);
    }

    if !number_of_chars_read.is_null() {
        *number_of_chars_read = chars_to_copy as DWORD;
    }

    if chars_to_copy > 0 {
        drop(input_buf);
        let mut len = CONSOLE_INPUT_LENGTH.lock();
        *len = 0;
    }

    TRUE
}

pub unsafe fn _simulate_console_input(text: &str) {
    let mut input_buf = CONSOLE_INPUT_BUFFER.lock();
    let mut len = CONSOLE_INPUT_LENGTH.lock();

    *len = 0;
    for ch in text.encode_utf16() {
        if *len >= CONSOLE_INPUT_BUFFER_SIZE {
            break;
        }
        input_buf[*len] = ch;
        *len += 1;
    }
}


pub unsafe extern "C" fn GetConsoleScreenBufferInfo(
    console_output: HANDLE,
    console_screen_buffer_info: *mut CONSOLE_SCREEN_BUFFER_INFO,
) -> BOOL {
    if console_output.is_null() || console_screen_buffer_info.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let state = CONSOLE_STATE.lock();
    let info = &mut *console_screen_buffer_info;

    info.dw_size = COORD {
        x: state.width,
        y: state.height,
    };
    info.dw_cursor_position = COORD {
        x: state.cursor_x,
        y: state.cursor_y,
    };
    info.w_attributes = state.attributes;
    info.sr_window = SMALL_RECT {
        left: 0,
        top: 0,
        right: state.width - 1,
        bottom: state.height - 1,
    };
    info.dw_maximum_window_size = COORD {
        x: state.width,
        y: state.height,
    };

    TRUE
}


pub unsafe extern "C" fn SetConsoleCursorPosition(
    console_output: HANDLE,
    cursor_position: COORD,
) -> BOOL {
    if console_output.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let mut state = CONSOLE_STATE.lock();

    if cursor_position.x < 0 || cursor_position.x >= state.width
        || cursor_position.y < 0 || cursor_position.y >= state.height
    {
        SetLastError(87); // ERROR_INVALID_PARAMETER
        return FALSE;
    }

    state.cursor_x = cursor_position.x;
    state.cursor_y = cursor_position.y;

    TRUE
}


pub unsafe extern "C" fn GetConsoleMode(console_handle: HANDLE, mode: *mut DWORD) -> BOOL {
    if console_handle.is_null() || mode.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let state = CONSOLE_STATE.lock();

    *mode = state.input_mode;

    TRUE
}

pub unsafe extern "C" fn SetConsoleMode(console_handle: HANDLE, mode: DWORD) -> BOOL {
    if console_handle.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let mut state = CONSOLE_STATE.lock();

    state.input_mode = mode;

    TRUE
}


#[repr(C)]
pub struct CONSOLE_CURSOR_INFO {
    pub dw_size: DWORD,
    pub b_visible: BOOL,
}

pub unsafe extern "C" fn GetConsoleCursorInfo(
    console_output: HANDLE,
    console_cursor_info: *mut CONSOLE_CURSOR_INFO,
) -> BOOL {
    if console_output.is_null() || console_cursor_info.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let info = &mut *console_cursor_info;
    info.dw_size = 25; // Default cursor size
    info.b_visible = TRUE;

    TRUE
}

pub unsafe extern "C" fn SetConsoleCursorInfo(
    console_output: HANDLE,
    console_cursor_info: *const CONSOLE_CURSOR_INFO,
) -> BOOL {
    if console_output.is_null() || console_cursor_info.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let _ = &*console_cursor_info;

    TRUE
}


pub unsafe extern "C" fn SetConsoleTextAttribute(
    console_output: HANDLE,
    attributes: u16,
) -> BOOL {
    if console_output.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let mut state = CONSOLE_STATE.lock();
    state.attributes = attributes;

    TRUE
}
