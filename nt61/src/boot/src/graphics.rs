//! Graphics support for UEFI
//
//! Provides basic graphics functionality for boot interfaces.

#![allow(dead_code)]

/// Trigonometry constants
const PI: f32 = 3.14159265358979323846;

/// Fast sine approximation
pub fn fast_sin(x: f32) -> f32 {
    let x = x % (2.0 * PI);
    let x = if x < 0.0 { x + 2.0 * PI } else { x };
    
    let b = 4.0 / PI * x;
    let y = 2.0 - b * b.abs();
    y * y * y
}

/// Fast cosine approximation
pub fn fast_cos(x: f32) -> f32 {
    fast_sin(x + PI / 2.0)
}

/// Framebuffer information
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

/// Display mode information
#[derive(Debug, Clone, Copy)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
}

impl DisplayMode {
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }
}
