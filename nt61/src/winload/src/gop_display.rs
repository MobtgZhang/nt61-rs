//! UEFI GOP display driver for `winload.efi`.
//
//! The Windows 7 OS Loader (winload.efi) draws a small graphical
//! "Windows is loading..." panel on top of the boot manager's
//! animation. Once `ExitBootServices()` is called, the GOP protocol
//! becomes unavailable; the firmware keeps scan-out going on the
//! last frame, and the kernel's BOOTVID.DLL takes over.
//
//! In this build we drive the GOP framebuffer directly through
//! `Blt()` with a small embedded 8x16 bitmap font for ASCII.
//! Every phase that does meaningful work paints a progress bar
//! segment on the bottom of the screen so the operator can see
//! that something is happening.

#![allow(dead_code)]
#![allow(static_mut_refs)]

use uefi::proto::console::gop::{BltOp, BltPixel, GraphicsOutput};
use uefi::proto::console::gop::PixelFormat;

/// 8x16 bitmap font for printable ASCII (0x20..0x7E).
/// 95 glyphs × 16 rows × 1 byte/row.
/// Each byte is a column-major bitmap: bit 7 = topmost pixel.
const FONT: [[u8; 16]; 95] = build_font();

const fn build_font() -> [[u8; 16]; 95] {
    let mut f = [[0u8; 16]; 95];
    f[0]  = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f[1]  = [0x18,0x3C,0x3C,0x3C,0x18,0x18,0x18,0,0x18,0x18,0,0,0,0,0,0];
    f[2]  = [0x6C,0x6C,0x6C,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f[3]  = [0x6C,0x6C,0xFE,0x6C,0x6C,0x6C,0xFE,0x6C,0x6C,0,0,0,0,0,0,0];
    f[4]  = [0x18,0x7E,0xC0,0x7C,0x06,0xFC,0x18,0,0,0,0,0,0,0,0,0];
    f[5]  = [0xC6,0xCC,0x18,0x30,0x66,0xC6,0,0,0,0,0,0,0,0,0,0];
    f[6]  = [0x38,0x6C,0x6C,0x38,0x76,0xDC,0xCC,0,0x76,0,0,0,0,0,0,0];
    f[7]  = [0x18,0x18,0x18,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f[8]  = [0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0,0,0,0,0,0,0,0,0];
    f[9]  = [0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0,0,0,0,0,0,0,0,0];
    f[10] = [0,0x66,0x3C,0xFF,0x3C,0x66,0,0,0,0,0,0,0,0,0,0];
    f[11] = [0,0x18,0x18,0x7E,0x18,0x18,0,0,0,0,0,0,0,0,0,0];
    f[12] = [0,0,0,0,0,0x18,0x18,0x30,0,0,0,0,0,0,0,0];
    f[13] = [0,0,0,0,0x7E,0,0,0,0,0,0,0,0,0,0,0];
    f[14] = [0,0,0,0,0,0,0,0x18,0x18,0,0,0,0,0,0,0];
    f[15] = [0x06,0x0C,0x18,0x30,0x60,0xC0,0,0,0,0,0,0,0,0,0,0];
    f[16] = [0x7C,0xC6,0xCE,0xDE,0xF6,0xE6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[17] = [0x18,0x38,0x78,0x18,0x18,0x18,0x18,0x7E,0,0,0,0,0,0,0,0];
    f[18] = [0x7C,0xC6,0x06,0x0C,0x18,0x30,0x60,0xFE,0,0,0,0,0,0,0,0];
    f[19] = [0x7C,0xC6,0x06,0x3C,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[20] = [0x0C,0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x0C,0,0,0,0,0,0,0,0];
    f[21] = [0xFE,0xC0,0xC0,0xFC,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[22] = [0x3C,0x60,0xC0,0xFC,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[23] = [0xFE,0x06,0x0C,0x18,0x30,0x30,0x30,0x30,0,0,0,0,0,0,0,0];
    f[24] = [0x7C,0xC6,0xC6,0x7C,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[25] = [0x7C,0xC6,0xC6,0xC6,0x7E,0x06,0x0C,0x78,0,0,0,0,0,0,0,0];
    f[26] = [0,0,0x18,0x18,0,0x18,0x18,0,0,0,0,0,0,0,0,0];
    f[27] = [0,0,0x18,0x18,0,0x18,0x18,0x30,0,0,0,0,0,0,0,0];
    f[28] = [0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0,0,0,0,0,0,0,0,0];
    f[29] = [0,0,0x7E,0,0x7E,0,0,0,0,0,0,0,0,0,0,0];
    f[30] = [0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0,0,0,0,0,0,0,0,0];
    f[31] = [0x7C,0xC6,0x0C,0x18,0x18,0,0x18,0,0,0,0,0,0,0,0,0];
    f[32] = [0x7C,0xC6,0xC6,0xDE,0xDE,0xDC,0xC0,0x7C,0,0,0,0,0,0,0,0];
    f[33] = [0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[34] = [0xFC,0xC6,0xC6,0xFC,0xC6,0xC6,0xC6,0xFC,0,0,0,0,0,0,0,0];
    f[35] = [0x7C,0xC6,0xC0,0xC0,0xC0,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[36] = [0xF8,0xCC,0xC6,0xC6,0xC6,0xC6,0xCC,0xF8,0,0,0,0,0,0,0,0];
    f[37] = [0xFE,0xC0,0xC0,0xF8,0xC0,0xC0,0xC0,0xFE,0,0,0,0,0,0,0,0];
    f[38] = [0xFE,0xC0,0xC0,0xF8,0xC0,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0];
    f[39] = [0x7C,0xC6,0xC0,0xC0,0xDE,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[40] = [0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[41] = [0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0,0,0,0,0,0,0,0];
    f[42] = [0x3E,0x0C,0x0C,0x0C,0x0C,0x0C,0xCC,0x78,0,0,0,0,0,0,0,0];
    f[43] = [0xC6,0xCC,0xD8,0xF0,0xE0,0xF0,0xD8,0xCC,0xC6,0,0,0,0,0,0,0];
    f[44] = [0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xFE,0,0,0,0,0,0,0,0];
    f[45] = [0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[46] = [0xC6,0xE6,0xF6,0xFE,0xDE,0xCE,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[47] = [0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[48] = [0xFC,0xC6,0xC6,0xC6,0xFC,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0];
    f[49] = [0x7C,0xC6,0xC6,0xC6,0xC6,0xF6,0xDE,0x7C,0x06,0,0,0,0,0,0,0];
    f[50] = [0xFC,0xC6,0xC6,0xC6,0xFC,0xF0,0xD8,0xCC,0xC6,0,0,0,0,0,0,0];
    f[51] = [0x7C,0xC6,0xC0,0x7C,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[52] = [0xFF,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0,0,0,0,0,0,0,0];
    f[53] = [0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[54] = [0xC6,0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0,0,0,0,0,0,0,0];
    f[55] = [0xC6,0xC6,0xD6,0xD6,0xFE,0x6C,0x6C,0,0,0,0,0,0,0,0,0];
    f[56] = [0xC6,0xC6,0x6C,0x38,0x38,0x6C,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[57] = [0xC3,0xC3,0x66,0x3C,0x18,0x18,0x18,0x18,0,0,0,0,0,0,0,0];
    f[58] = [0xFE,0x06,0x0C,0x18,0x30,0x60,0xC0,0xFE,0,0,0,0,0,0,0,0];
    f[59] = [0x3C,0x30,0x30,0x30,0x30,0x30,0x30,0x3C,0,0,0,0,0,0,0,0];
    f[60] = [0xC0,0x60,0x30,0x18,0x0C,0x06,0,0,0,0,0,0,0,0,0,0];
    f[61] = [0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0,0,0,0,0,0,0,0];
    f[62] = [0x10,0x38,0x6C,0xC6,0,0,0,0,0,0,0,0,0,0,0,0];
    f[63] = [0,0,0,0,0,0,0,0,0xFE,0,0,0,0,0,0,0];
    f[64] = [0x18,0x18,0x0C,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f[65] = [0,0,0x7C,0x06,0x7E,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0];
    f[66] = [0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0xFC,0,0,0,0,0,0,0,0];
    f[67] = [0,0,0x7C,0xC6,0xC0,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[68] = [0x06,0x06,0x7E,0xC6,0xC6,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0];
    f[69] = [0,0,0x7C,0xC6,0xFE,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[70] = [0x3C,0x66,0x60,0xF8,0x60,0x60,0x60,0xF0,0,0,0,0,0,0,0,0];
    f[71] = [0,0,0x7E,0xC6,0xC6,0x7E,0x06,0x7C,0,0,0,0,0,0,0,0];
    f[72] = [0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[73] = [0x18,0,0x38,0x18,0x18,0x18,0x18,0x3C,0,0,0,0,0,0,0,0];
    f[74] = [0x0C,0,0x1C,0x0C,0x0C,0x0C,0xCC,0x78,0,0,0,0,0,0,0,0];
    f[75] = [0xC0,0xC0,0xC6,0xCC,0xF8,0xCC,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[76] = [0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0,0,0,0,0,0,0,0];
    f[77] = [0,0,0xEC,0xFE,0xFE,0xD6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[78] = [0,0,0xFC,0xC6,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[79] = [0,0,0x7C,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[80] = [0,0,0xFC,0xC6,0xC6,0xFC,0xC0,0xC0,0,0,0,0,0,0,0,0];
    f[81] = [0,0,0x7E,0xC6,0xC6,0x7E,0x06,0x06,0,0,0,0,0,0,0,0];
    f[82] = [0,0,0xFC,0xC6,0xC0,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0];
    f[83] = [0,0,0x7E,0xC0,0x7C,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[84] = [0x30,0x30,0xFC,0x30,0x30,0x30,0x36,0x1C,0,0,0,0,0,0,0,0];
    f[85] = [0,0,0xC6,0xC6,0xC6,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0];
    f[86] = [0,0,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0,0,0,0,0,0,0,0];
    f[87] = [0,0,0xC6,0xC6,0xD6,0xD6,0xFE,0x6C,0,0,0,0,0,0,0,0];
    f[88] = [0,0,0xC6,0x6C,0x38,0x38,0x6C,0xC6,0,0,0,0,0,0,0,0];
    f[89] = [0,0,0xC6,0xC6,0xC6,0x7E,0x06,0x7C,0,0,0,0,0,0,0,0];
    f[90] = [0,0,0xFE,0x0C,0x38,0x60,0xC0,0xFE,0,0,0,0,0,0,0,0];
    f[91] = [0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0,0,0,0,0,0,0,0,0];
    f[92] = [0x18,0x18,0x18,0,0x18,0x18,0x18,0,0,0,0,0,0,0,0,0];
    f[93] = [0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0,0,0,0,0,0,0,0,0];
    f[94] = [0x76,0xDC,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f
}

/// Pure-data description of the cached GOP. We don't store the
/// `ScopedProtocol` itself in a `static mut` (it owns a handle
/// guard that wants to be dropped at well-defined points); we
/// store the sized mode info and call back into the cached `gop`
/// field through a writer helper that takes `&mut GraphicsOutput`.
pub struct GopState {
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    #[allow(dead_code)]
    pub format: PixelFormat,
    pub total_phases: u32,
}

static mut GOP_STATE: Option<GopState> = None;

/// Call `f` with `&mut GraphicsOutput` from the caller-provided
/// `gop`. We don't store the protocol reference in a static to
/// avoid double-drop / exclusive-borrow concerns; instead each
/// `init` is followed by free-function calls that re-open the
/// protocol through `open_protocol_exclusive` each time.
///
/// Use `init_with_protocol` for that.
pub fn init_with_protocol<F>(gop: &mut GraphicsOutput, total_phases: u32, f: F)
where
    F: FnOnce(&mut GraphicsOutput, &GopState),
{
    let mode = gop.current_mode_info();
    let (width, height) = mode.resolution();
    let stride = mode.stride();
    let format = mode.pixel_format();
    let _ = gop.blt(BltOp::VideoFill {
        color: BltPixel::new(0xD8, 0x98, 0x70),
        dest: (0, 0),
        dims: (width, height),
    });
    let state = GopState { width, height, stride, format, total_phases };
    unsafe { GOP_STATE = Some(state); }
    f(gop, unsafe { GOP_STATE.as_ref().unwrap() });
    uefi::println!("[GOP] display initialised ({}x{}, {} phases)",
        width, height, total_phases);
}

/// Variant of `draw_text_centered` that uses the cached state.
pub fn draw_text_centered_global(text: &str, y: u32, r: u8, g: u8, b: u8, gop: &mut GraphicsOutput) {
    let state = unsafe { GOP_STATE.as_ref() };
    let state = match state {
        Some(s) => s,
        None => return,
    };
    let width_px = text.len() as u32 * 8;
    if width_px >= state.width as u32 { return; }
    let x = (state.width as u32 - width_px) / 2;
    let mut cur_x = x;
    for &ch in text.as_bytes() {
        let idx = (ch as usize).saturating_sub(0x20).min(94);
        draw_glyph(gop, cur_x, y, idx, r, g, b);
        cur_x += 8;
    }
}

/// Draw `text` starting at pixel `(x, y)` using 8x16 bitmap glyphs.
pub fn draw_text_global(text: &str, x: u32, y: u32, gop: &mut GraphicsOutput) {
    let state = unsafe { GOP_STATE.as_ref() };
    let state = match state {
        Some(s) => s,
        None => return,
    };
    let mut cur_x = x;
    let mut cur_y = y;
    for &b in text.as_bytes() {
        if b == b'\n' {
            cur_x = x;
            cur_y += 16;
            continue;
        }
        if b == b'\r' { continue; }
        let idx = (b as usize).saturating_sub(0x20).min(94);
        draw_glyph(gop, cur_x, cur_y, idx, 0xFF, 0xFF, 0xFF);
        cur_x += 8;
        if cur_x + 8 > state.width as u32 {
            cur_x = x;
            cur_y += 16;
        }
    }
}

/// Update the progress bar.
pub fn mark_phase_global(current_phase: u32, gop: &mut GraphicsOutput) {
    let state = unsafe { GOP_STATE.as_ref() };
    let state = match state {
        Some(s) => s,
        None => return,
    };
    let (width, height, total) = (state.width, state.height, state.total_phases);
    let bar_y0 = height - 60;
    let bar_h = 16;
    let pad = 40usize;
    let bar_x0 = pad;
    let bar_w = width.saturating_sub(2 * pad);
    let filled = if total == 0 {
        bar_w
    } else {
        ((current_phase as usize + 1) * bar_w) / (total as usize)
    };
    let _ = gop.blt(BltOp::VideoFill {
        color: BltPixel::new(0x60, 0x50, 0x40),
        dest: (bar_x0, bar_y0),
        dims: (bar_w, bar_h),
    });
    if filled > 0 {
        let _ = gop.blt(BltOp::VideoFill {
            color: BltPixel::new(0xFF, 0xE0, 0xC0),
            dest: (bar_x0, bar_y0),
            dims: (filled, bar_h),
        });
    }
    let border = BltPixel::new(0xFF, 0xFF, 0xFF);
    let _ = gop.blt(BltOp::VideoFill {
        color: border,
        dest: (bar_x0, bar_y0),
        dims: (bar_w, 1),
    });
    let _ = gop.blt(BltOp::VideoFill {
        color: border,
        dest: (bar_x0, bar_y0 + bar_h - 1),
        dims: (bar_w, 1),
    });
    let _ = gop.blt(BltOp::VideoFill {
        color: border,
        dest: (bar_x0, bar_y0),
        dims: (1, bar_h),
    });
    let _ = gop.blt(BltOp::VideoFill {
        color: border,
        dest: (bar_x0 + bar_w - 1, bar_y0),
        dims: (1, bar_h),
    });
}

/// Stroke the 1-pixel outline of the bottom progress bar.
pub fn draw_progress_border_global(gop: &mut GraphicsOutput) {
    let state = unsafe { GOP_STATE.as_ref() };
    let state = match state {
        Some(s) => s,
        None => return,
    };
    let (width, height) = (state.width, state.height);
    let bar_y0 = height - 60;
    let bar_h = 16;
    let pad = 40usize;
    let bar_x0 = pad;
    let bar_w = width.saturating_sub(2 * pad);
    let border = BltPixel::new(0xFF, 0xFF, 0xFF);
    let _ = gop.blt(BltOp::VideoFill {
        color: border,
        dest: (bar_x0, bar_y0),
        dims: (bar_w, 1),
    });
    let _ = gop.blt(BltOp::VideoFill {
        color: border,
        dest: (bar_x0, bar_y0 + bar_h - 1),
        dims: (bar_w, 1),
    });
    let _ = gop.blt(BltOp::VideoFill {
        color: border,
        dest: (bar_x0, bar_y0),
        dims: (1, bar_h),
    });
    let _ = gop.blt(BltOp::VideoFill {
        color: border,
        dest: (bar_x0 + bar_w - 1, bar_y0),
        dims: (1, bar_h),
    });
}

/// Draw a single ASCII glyph into the framebuffer at pixel
/// coordinates `(px, py)`. Background pixels use the loader blue.
fn draw_glyph(gop: &mut GraphicsOutput, px: u32, py: u32, idx: usize, r: u8, g: u8, b: u8) {
    let glyph = &FONT[idx];
    let mut buf: [BltPixel; 8 * 16] = [BltPixel::new(0, 0, 0); 128];
    for row in 0..16u32 {
        let bits = glyph[row as usize];
        for col in 0..8u32 {
            let on = (bits >> (7 - col)) & 1 != 0;
            let px_idx = (row * 8 + col) as usize;
            buf[px_idx] = if on {
                BltPixel::new(r, g, b)
            } else {
                BltPixel::new(0xD8, 0x98, 0x70) // bootloader blue background
            };
        }
    }
    let _ = gop.blt(BltOp::BufferToVideo {
        buffer: &buf[..],
        src: uefi::proto::console::gop::BltRegion::Full,
        dest: (px as usize, py as usize),
        dims: (8, 16),
    });
}

/// Drop any cached state at end-of-winload. Currently a no-op
/// because we never stored the protocol handle; left in place so
/// future features have a single clean shutdown point.
pub fn shutdown() {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(GOP_STATE), None);
    }
}
