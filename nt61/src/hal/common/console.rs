//! Console Support

/// VGA text mode console
pub const VGA_WIDTH: usize = 80;
pub const VGA_HEIGHT: usize = 25;

/// VGA color
#[derive(Debug, Clone, Copy)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

/// Console character
pub struct ConsoleChar {
    pub character: u8,
    pub color: u8,
}

/// Initialize console
pub fn init() {
    // Initialize VGA console
}

/// Print character
#[allow(dead_code)]
pub fn put_char(_c: char) {
    // Print to console
}

/// Print string
pub fn puts(s: &str) {
    for c in s.chars() {
        put_char(c);
    }
}
