//! x86_64 backend for the abstract text console.
//!
//! Thin wrapper around `crate::hal::x86_64::text_console` so the
//! unified `hal::text_console` facade has a per-arch backend on
//! x86_64. The actual VGA / bootvid logic lives in the existing
//! `x86_64::text_console` module and is exposed verbatim.
//!
//! A handful of x86_64-only helpers (`put_byte_vga_only`,
//! `put_byte_vga_only_str`, `put_rstr`, `is_ready`) are also
//! re-exported through the abstract facade so existing call
//! sites in `rtl::klog` and `servers::cmd` keep compiling.
//! Their counterparts on the other architectures either
//! forward to `put_byte` directly (aarch64/riscv64/loongarch64
//! don't have a separate VGA-only path) or are no-ops.

pub use crate::hal::x86_64::text_console::{
    init, set_attr, put_byte, clear, set_cursor,
};

// x86_64-only helpers — exposed here so call sites in the
// kernel that previously referenced
// `crate::hal::x86_64::text_console::*` through the unified
// facade continue to work without modification.
pub use crate::hal::x86_64::text_console::{
    put_byte_vga_only,
    put_byte_vga_only_str,
    put_rstr,
    is_ready,
};

/// x86_64 has a real text framebuffer (the 0xB8000 buffer plus
/// its bootvid LFB mirror), so the log IS the screen and there
/// is no separate log ring. `log_line_count` returns 0 and
/// `read_log_lines` writes nothing.
pub fn log_line_count() -> usize { 0 }

pub fn read_log_lines(_buf: &mut [[u8; super::COLS + 2]]) -> usize { 0 }