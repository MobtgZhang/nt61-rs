//! GDI Operations
//
//! Implements core GDI drawing operations: BitBlt, PatBlt, rectangle drawing,
//! ellipse drawing, polygon filling, and raster operations (ROP).
//
//! Reference: ReactOS win32ss/gdi/gdi32_objects

extern crate alloc;

use crate::kprintln;
use crate::libs::win32k::objects::{Rect, GdiBrush, GdiPen};
use crate::libs::win32k::dc::DcObject;
use crate::libs::win32k::surface::{GdiSurface, PIXEL_FORMAT_32BPP, PIXEL_FORMAT_32BPP_ARGB};
use alloc::vec::Vec;

/// Raster operation codes
pub const SRCCOPY: u32 = 0x00CC0020;
pub const SRCPAINT: u32 = 0x00EE0086;
pub const SRCAND: u32 = 0x008800C6;
pub const SRCINVERT: u32 = 0x00660046;
pub const SRCERASE: u32 = 0x00440328;
pub const NOTSRCCOPY: u32 = 0x00330008;
pub const NOTSRCERASE: u32 = 0x001100A6;
pub const MERGECOPY: u32 = 0x00C000CA;
pub const MERGEPAINT: u32 = 0x00BB0226;
pub const PATCOPY: u32 = 0x00F00021;
pub const PATPAINT: u32 = 0x00FB0A09;
pub const PATINVERT: u32 = 0x005A0049;
pub const DSTINVERT: u32 = 0x00550009;
pub const BLACKNESS: u32 = 0x00000042;
pub const WHITENESS: u32 = 0x00FF0062;

// =============================================================================
// Raster Operations (ROP)
// =============================================================================

/// Apply a raster operation to a single pixel
#[inline(always)]
pub fn apply_rop(dest: u32, src: u32, pat: u32, rop: u32) -> u32 {
    match rop {
        SRCCOPY => src,
        SRCPAINT => dest | src,
        SRCAND => dest & src,
        SRCINVERT => dest ^ src,
        SRCERASE => dest & !src,
        NOTSRCCOPY => !src,
        NOTSRCERASE => !(dest | src),
        MERGECOPY => dest & pat,
        MERGEPAINT => dest | !src,
        PATCOPY => pat,
        PATPAINT => dest | pat | !src,
        PATINVERT => dest ^ pat,
        DSTINVERT => !dest,
        BLACKNESS => 0,
        WHITENESS => 0x00FFFFFF,
        _ => src,
    }
}

/// Apply SRCCOPY ROP (fast path)
#[inline(always)]
pub fn rop_srccopy(dest: u32, src: u32, pat: u32) -> u32 {
    let _ = dest;
    let _ = pat;
    src
}

/// Apply SRCPAINT ROP
#[inline(always)]
pub fn rop_srcpaint(dest: u32, src: u32, pat: u32) -> u32 {
    let _ = pat;
    dest | src
}

/// Apply SRCAND ROP
#[inline(always)]
pub fn rop_srcand(dest: u32, src: u32, pat: u32) -> u32 {
    let _ = pat;
    dest & src
}

/// Apply SRCINVERT ROP
#[inline(always)]
pub fn rop_srcinvert(dest: u32, src: u32, pat: u32) -> u32 {
    let _ = pat;
    dest ^ src
}

// =============================================================================
// BitBlt (Block Transfer)
// =============================================================================

/// Get DC's surface
fn get_dc_surface(dc: &DcObject) -> *mut GdiSurface {
    if dc.surface != 0 {
        dc.surface as *mut GdiSurface
    } else {
        crate::libs::win32k::surface::get_primary_surface()
    }
}

/// BitBlt - Block Transfer
pub fn GreBitBlt(
    dst_dc: &mut DcObject,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_dc: Option<&DcObject>,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {
    if width == 0 || height == 0 {
        return true;
    }

    let dst_surface = get_dc_surface(dst_dc);

    let _ = &dst_surface;
    let _ = &dst_surface;
    if dst_surface.is_null() {
        return false;
    }

    // For SRCCOPY with a source DC, use the fast copy path
    if rop == SRCCOPY {
        if let Some(src) = src_dc {
            let src_surface = get_dc_surface(src);
            let _ = &src_surface;
            let _ = &src_surface;
            if !src_surface.is_null() {
                return bitblt_copy(dst_surface, dst_x, dst_y, width, height,
                                   src_surface, src_x, src_y);
            }
        }
        return false;
    }

    // Handle operations without source
    match rop {
        BLACKNESS => {
            return fill_rect_solid(dst_surface, dst_x, dst_y, width, height, 0x00000000);
        }
        WHITENESS => {
            return fill_rect_solid(dst_surface, dst_x, dst_y, width, height, 0x00FFFFFF);
        }
        DSTINVERT => {
            return invert_rect(dst_surface, dst_x, dst_y, width, height);
        }
        PATCOPY => {
            // Get pattern (brush) from DC
            let color = if dst_dc.brush != 0 {
                crate::libs::win32k::objects::GdiGetBrushColor(dst_dc.brush)
            } else {
                0
            };
            let _ = &color;
            return fill_rect_solid(dst_surface, dst_x, dst_y, width, height, color);
        }
        _ => {}
    }

    // Generic per-pixel ROP (slow path)
    if let Some(src) = src_dc {
        let src_surface = get_dc_surface(src);
        let _ = &src_surface;
        let _ = &src_surface;
        if !src_surface.is_null() {
            return bitblt_generic(dst_surface, dst_x, dst_y, width, height,
                               src_surface, src_x, src_y, rop, dst_dc);
        }
    }

    false
}

/// Fast copy BitBlt
fn bitblt_copy(
    dst: *mut GdiSurface,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src: *mut GdiSurface,
    src_x: i32,
    src_y: i32,
) -> bool {
    if dst.is_null() || src.is_null() {
        return false;
    }

    let dst_surf = unsafe { &*dst };

    let _ = &dst_surf;
    let _ = &dst_surf;
    let src_surf = unsafe { &*src };
    let _ = &src_surf;
    let _ = &src_surf;

    if dst_surf.bits.is_null() || src_surf.bits.is_null() {
        return false;
    }

    // Clip to surfaces
    let dst_width = dst_surf.width;
    let _ = &dst_width;
    let _ = &dst_width;
    let dst_height = dst_surf.height;
    let _ = &dst_height;
    let _ = &dst_height;
    let src_width = src_surf.width;
    let _ = &src_width;
    let _ = &src_width;
    let src_height = src_surf.height;
    let _ = &src_height;
    let _ = &src_height;

    // Ensure we're in bounds
    if dst_x >= dst_width || dst_y >= dst_height ||
       src_x >= src_width || src_y >= src_height {
        return false;
    }

    let actual_width = width.min(dst_width - dst_x).min(src_width - src_x);

    let _ = &actual_width;
    let _ = &actual_width;
    let actual_height = height.min(dst_height - dst_y).min(src_height - src_y);
    let _ = &actual_height;
    let _ = &actual_height;

    if actual_width <= 0 || actual_height <= 0 {
        return true;
    }

    let dst_pitch = dst_surf.pitch;

    let _ = &dst_pitch;
    let _ = &dst_pitch;
    let src_pitch = src_surf.pitch;
    let _ = &src_pitch;
    let _ = &src_pitch;

    unsafe {
        for y in 0..actual_height {
            let dst_row = dst_surf.bits.add(((dst_y + y) * dst_pitch) as usize);
            let _ = &dst_row;
            let _ = &dst_row;
            let src_row = src_surf.bits.add(((src_y + y) * src_pitch) as usize);
            let _ = &src_row;
            let _ = &src_row;

            core::ptr::copy_nonoverlapping(
                src_row.add((src_x * 4) as usize),
                dst_row.add((dst_x * 4) as usize),
                (actual_width * 4) as usize,
            );
        }
    }

    // kprintln!("[win32k] bitblt_copy: {}x{} from ({},{}) to ({},{})",  // kprintln disabled (memcpy crash workaround)
//               actual_width, actual_height, src_x, src_y, dst_x, dst_y);

    true
}

/// Generic BitBlt with ROP
fn bitblt_generic(
    dst: *mut GdiSurface,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src: *mut GdiSurface,
    src_x: i32,
    src_y: i32,
    rop: u32,
    dc: &DcObject,
) -> bool {
    let _ = dc;
    if dst.is_null() || src.is_null() {
        return false;
    }

    let dst_surf = unsafe { &*dst };

    let _ = &dst_surf;
    let _ = &dst_surf;
    let src_surf = unsafe { &*src };
    let _ = &src_surf;
    let _ = &src_surf;

    if dst_surf.bits.is_null() || src_surf.bits.is_null() {
        return false;
    }

    // Clip
    let actual_width = width.min(dst_surf.width - dst_x).min(src_surf.width - src_x);
    let _ = &actual_width;
    let _ = &actual_width;
    let actual_height = height.min(dst_surf.height - dst_y).min(src_surf.height - src_y);
    let _ = &actual_height;
    let _ = &actual_height;

    if actual_width <= 0 || actual_height <= 0 {
        return true;
    }

    let dst_pitch = dst_surf.pitch;

    let _ = &dst_pitch;
    let _ = &dst_pitch;
    let src_pitch = src_surf.pitch;
    let _ = &src_pitch;
    let _ = &src_pitch;

    unsafe {
        for y in 0..actual_height {
            for x in 0..actual_width {
                let dst_offset = ((dst_y + y) * dst_pitch + (dst_x + x) * 4) as isize;
                let _ = &dst_offset;
                let _ = &dst_offset;
                let src_offset = ((src_y + y) * src_pitch + (src_x + x) * 4) as isize;
                let _ = &src_offset;
                let _ = &src_offset;

                let dst_pixel = core::ptr::read_unaligned(dst_surf.bits.offset(dst_offset) as *const u32);

                let _ = &dst_pixel;
                let _ = &dst_pixel;
                let src_pixel = core::ptr::read_unaligned(src_surf.bits.offset(src_offset) as *const u32);
                let _ = &src_pixel;
                let _ = &src_pixel;

                let result = apply_rop(dst_pixel, src_pixel, 0, rop);

                let _ = &result;
                let _ = &result;

                core::ptr::write_unaligned(dst_surf.bits.offset(dst_offset) as *mut u32, result);
            }
        }
    }

    // kprintln!("[win32k] bitblt_generic: {}x{} at ({},{}) rop=0x{:08x}",  // kprintln disabled (memcpy crash workaround)
//               actual_width, actual_height, dst_x, dst_y, rop);

    true
}

// =============================================================================
// PatBlt (Pattern Blt)
// =============================================================================

/// PatBlt - Pattern Block Transfer
pub fn GrePatBlt(
    dc: &mut DcObject,
    left: i32,
    top: i32,
    width: i32,
    height: i32,
    rop: u32,
) -> bool {
    let surface = get_dc_surface(dc);
    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    // Get brush color
    let color = if dc.brush != 0 {
        crate::libs::win32k::objects::GdiGetBrushColor(dc.brush)
    } else {
        0
    };
    let _ = &color;

    match rop & 0xFF {
        0x00 => fill_rect_solid(surface, left, top, width, height, 0),
        0xFF => fill_rect_solid(surface, left, top, width, height, 0x00FFFFFF),
        _ => {
            if rop == PATCOPY {
                fill_rect_solid(surface, left, top, width, height, color)
            } else {
                // For complex ROPs, use generic path
                fill_rect_solid(surface, left, top, width, height, color)
            }
        }
    }
}

// =============================================================================
// Rectangle Operations
// =============================================================================

/// Fill rectangle with solid color
fn fill_rect_solid(surface: *mut GdiSurface, x: i32, y: i32, width: i32, height: i32, color: u32) -> bool {
    if surface.is_null() {
        return false;
    }

    let surf = unsafe { &mut *surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return false;
    }

    // Clip to surface bounds
    let left = x.max(0);
    let _ = &left;
    let _ = &left;
    let top = y.max(0);
    let _ = &top;
    let _ = &top;
    let right = (x + width).min(surf.width);
    let _ = &right;
    let _ = &right;
    let bottom = (y + height).min(surf.height);
    let _ = &bottom;
    let _ = &bottom;

    if left >= right || top >= bottom {
        return true;
    }

    let actual_width = right - left;

    let _ = &actual_width;
    let _ = &actual_width;
    let actual_height = bottom - top;
    let _ = &actual_height;
    let _ = &actual_height;

    // Check for 32bpp surface
    if surf.format != PIXEL_FORMAT_32BPP && surf.format != PIXEL_FORMAT_32BPP_ARGB {
        // For other formats, we'd need conversion - for now, skip
        return true;
    }

    unsafe {
        for row in top..bottom {
            let line_ptr = surf.bits.add((row * surf.pitch) as usize);
            let _ = &line_ptr;
            let _ = &line_ptr;
            for col in left..right {
                core::ptr::write_unaligned(
                    line_ptr.add((col * 4) as usize) as *mut u32,
                    color,
                );
            }
        }
    }

    // kprintln!("[win32k] fill_rect_solid: {}x{} at ({},{}) color=0x{:08x}",  // kprintln disabled (memcpy crash workaround)
//               actual_width, actual_height, left, top, color);

    true
}

/// Invert rectangle
fn invert_rect(surface: *mut GdiSurface, x: i32, y: i32, width: i32, height: i32) -> bool {
    if surface.is_null() {
        return false;
    }

    let surf = unsafe { &mut *surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return false;
    }

    // Clip
    let left = x.max(0);
    let _ = &left;
    let _ = &left;
    let top = y.max(0);
    let _ = &top;
    let _ = &top;
    let right = (x + width).min(surf.width);
    let _ = &right;
    let _ = &right;
    let bottom = (y + height).min(surf.height);
    let _ = &bottom;
    let _ = &bottom;

    if left >= right || top >= bottom {
        return true;
    }

    if surf.format != PIXEL_FORMAT_32BPP && surf.format != PIXEL_FORMAT_32BPP_ARGB {
        return true;
    }

    unsafe {
        for row in top..bottom {
            let line_ptr = surf.bits.add((row * surf.pitch) as usize);
            let _ = &line_ptr;
            let _ = &line_ptr;
            for col in left..right {
                let pixel = core::ptr::read_unaligned(
                    line_ptr.add((col * 4) as usize) as *const u32
                );
                let _ = &pixel;
                core::ptr::write_unaligned(
                    line_ptr.add((col * 4) as usize) as *mut u32,
                    !pixel,
                );
            }
        }
    }

    true
}

/// GreRectangle - Draw rectangle outline
pub fn GreRectangle(
    dc: &mut DcObject,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> bool {
    let surface = get_dc_surface(dc);
    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    let pen_color = if dc.pen != 0 {
        crate::libs::win32k::objects::GdiGetPenColor(dc.pen)
    } else {
        0
    };

    let _ = &pen_color;

    let width = right - left;

    let _ = &width;
    let _ = &width;
    let height = bottom - top;
    let _ = &height;
    let _ = &height;

    // Draw outline
    draw_line(surface, left, top, right - 1, top, pen_color);           // Top
    draw_line(surface, left, bottom - 1, right - 1, bottom - 1, pen_color); // Bottom
    draw_line(surface, left, top, left, bottom - 1, pen_color);       // Left
    draw_line(surface, right - 1, top, right - 1, bottom - 1, pen_color);   // Right

    // Fill with brush if present
    if dc.brush != 0 {
        let brush_color = crate::libs::win32k::objects::GdiGetBrushColor(dc.brush);
        let _ = &brush_color;
        let _ = &brush_color;
        fill_rect_solid(surface, left + 1, top + 1, width - 1, height - 1, brush_color);
    }

    // kprintln!("[win32k] GreRectangle: ({},{})-({},{}) pen=0x{:x} brush=0x{:x}",  // kprintln disabled (memcpy crash workaround)
//               left, top, right, bottom, dc.pen, dc.brush);

    true
}

/// GreRoundRect - Draw rounded rectangle
pub fn GreRoundRect(
    dc: &mut DcObject,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    width: i32,
    height: i32,
) -> bool {
    let _ = (width, height);
    // For simplicity, just draw a regular rectangle
    // Full implementation would draw arcs at corners
    GreRectangle(dc, left, top, right, bottom)
}

// =============================================================================
// Line Drawing
// =============================================================================

/// Draw a line on a surface
pub fn draw_line(surface: *mut GdiSurface, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) -> bool {
    if surface.is_null() {
        return false;
    }

    let surf = unsafe { &*surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return false;
    }

    // Bresenham's line algorithm
    let dx = (x2 - x1).abs();
    let _ = &dx;
    let _ = &dx;
    let dy = -(y2 - y1).abs();
    let _ = &dy;
    let _ = &dy;
    let sx = if x1 < x2 { 1 } else { -1 };
    let _ = &sx;
    let _ = &sx;
    let sy = if y1 < y2 { 1 } else { -1 };
    let _ = &sy;
    let _ = &sy;
    let mut err = dx + dy;
    let mut x = x1;
    let mut y = y1;

    loop {
        // Draw pixel if in bounds
        if x >= 0 && x < surf.width && y >= 0 && y < surf.height {
            let offset = (y * surf.pitch + x * 4) as isize;
            let _ = &offset;
            let _ = &offset;
            unsafe {
                core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
            }
        }

        if x == x2 && y == y2 {
            break;
        }

        let e2 = 2 * err;

        let _ = &e2;
        let _ = &e2;
        if e2 >= dy {
            if x == x2 {
                break;
            }
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            if y == y2 {
                break;
            }
            err += dx;
            y += sy;
        }
    }

    true
}

/// Draw a line with specified width (rounded caps)
pub fn draw_line_width(surface: *mut GdiSurface, x1: i32, y1: i32, x2: i32, y2: i32, 
                       width: i32, color: u32) -> bool {
    if surface.is_null() || width <= 0 {
        return false;
    }

    if width == 1 {
        // Fast path for single-pixel width
        return draw_line(surface, x1, y1, x2, y2, color);
    }

    let half_w = width / 2;

    let _ = &half_w;
    let _ = &half_w;

    // For thick lines, we draw multiple parallel lines along the main line
    // This creates a "fat" line effect
    let dx = x2 - x1;
    let _ = &dx;
    let _ = &dx;
    let dy = y2 - y1;
    let _ = &dy;
    let _ = &dy;
    let len = isqrt((dx * dx + dy * dy) as u64) as i32;
    let _ = &len;
    let _ = &len;

    if len == 0 {
        // Single point - draw a filled rectangle
        let surf = unsafe { &*surface };
        let _ = &surf;
        let _ = &surf;
        for py in (y1 - half_w)..=(y1 + half_w) {
            for px in (x1 - half_w)..=(x1 + half_w) {
                if px >= 0 && px < surf.width && py >= 0 && py < surf.height {
                    let offset = (py * surf.pitch + px * 4) as isize;
                    let _ = &offset;
                    let _ = &offset;
                    unsafe {
                        core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
                    }
                }
            }
        }
        return true;
    }

    // Draw perpendicular offsets to create thick line
    // Normal vector (perpendicular to line direction)
    let nx = -dy;
    let _ = &nx;
    let _ = &nx;
    let ny = dx;
    let _ = &ny;
    let _ = &ny;

    // Draw line segments at each offset
    for offset in (-half_w)..=half_w {
        let offset_f = offset as f32;
        let _ = &offset_f;
        let _ = &offset_f;
        let len_f = len as f32;
        let _ = &len_f;
        let _ = &len_f;
        
        // Normalized perpendicular offset
        let ox = (nx as f32 / len_f) * offset_f;
        let _ = &ox;
        let _ = &ox;
        let oy = (ny as f32 / len_f) * offset_f;
        let _ = &oy;
        let _ = &oy;

        let sx = (x1 as f32 + ox) as i32;

        let _ = &sx;
        let _ = &sx;
        let sy = (y1 as f32 + oy) as i32;
        let _ = &sy;
        let _ = &sy;
        let ex = (x2 as f32 + ox) as i32;
        let _ = &ex;
        let _ = &ex;
        let ey = (y2 as f32 + oy) as i32;
        let _ = &ey;
        let _ = &ey;

        draw_line(surface, sx, sy, ex, ey, color);
    }

    // kprintln!("[win32k] draw_line_width: ({},{})-({},{}), width={}",   // kprintln disabled (memcpy crash workaround)
//               x1, y1, x2, y2, width);
    true
}

/// GreLineTo - Draw line to point using pen width
pub fn GreLineTo(
    dc: &mut DcObject,
    end_x: i32,
    end_y: i32,
) -> bool {
    let surface = get_dc_surface(dc);
    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    let pen_color = if dc.pen != 0 {
        crate::libs::win32k::objects::GdiGetPenColor(dc.pen)
    } else {
        0
    };

    let _ = &pen_color;

    // Get pen width from pen object
    let pen_width = if dc.pen != 0 {
        crate::libs::win32k::objects::GdiGetPenWidth(dc.pen)
    } else {
        1
    };
    let _ = &pen_width;

    // Current position is stored in DC - for now assume (0, 0)
    // Full implementation would track current position
    let start_x = 0;
    let _ = &start_x;
    let _ = &start_x;
    let start_y = 0;
    let _ = &start_y;
    let _ = &start_y;

    if pen_width > 1 {
        draw_line_width(surface, start_x, start_y, end_x, end_y, pen_width, pen_color);
    } else {
        draw_line(surface, start_x, start_y, end_x, end_y, pen_color);
    }

    // kprintln!("[win32k] GreLineTo: ({},{})-({},{}), pen_width={}",   // kprintln disabled (memcpy crash workaround)
//               start_x, start_y, end_x, end_y, pen_width);

    true
}

/// GreMoveTo - Set current position (stub)
pub fn GreMoveTo(
    dc: &mut DcObject,
    x: i32,
    y: i32,
) {
    let _ = dc;
    let _ = x;
    let _ = y;
    // Would store current position in DC
    // kprintln!("[win32k] GreMoveTo: ({},{})", x, y)  // kprintln disabled (memcpy crash workaround);
}

// =============================================================================
// Ellipse and Arc
// =============================================================================

/// Maximum allowed ellipse radius to prevent overflow
const MAX_ELLIPSE_DIMENSION: i32 = 16384;

/// Draw ellipse using midpoint algorithm with overflow protection
fn draw_ellipse_midpoint(surface: *mut GdiSurface, cx: i32, cy: i32, rx: i32, ry: i32, color: u32) {
    if surface.is_null() || rx <= 0 || ry <= 0 {
        return;
    }

    let surf = unsafe { &*surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return;
    }

    // Overflow protection: clamp dimensions to prevent i32 overflow
    let rx = rx.min(MAX_ELLIPSE_DIMENSION);
    let _ = &rx;
    let _ = &rx;
    let ry = ry.min(MAX_ELLIPSE_DIMENSION);
    let _ = &ry;
    let _ = &ry;

    // Check if dimensions might cause overflow in calculations
    // (rx * rx) fits in i32 only if rx <= 46340 (sqrt(i32::MAX))
    if rx > 46340 || ry > 46340 {
        // kprintln!("[win32k] draw_ellipse_midpoint: dimensions too large, rx={}, ry={}", rx, ry)  // kprintln disabled (memcpy crash workaround);
        return;
    }

    // Use i64 for all intermediate calculations to prevent overflow
    let rx2 = (rx as i64) * (rx as i64);
    let _ = &rx2;
    let _ = &rx2;
    let ry2 = (ry as i64) * (ry as i64);
    let _ = &ry2;
    let _ = &ry2;
    let two_rx2 = 2i64 * rx2;
    let _ = &two_rx2;
    let _ = &two_rx2;
    let two_ry2 = 2i64 * ry2;
    let _ = &two_ry2;
    let _ = &two_ry2;

    let mut x = 0i64;
    let mut y = ry as i64;
    let mut px = 0i64;
    let mut py = two_rx2 * y;

    // Region 1: p = ry^2 - rx^2*ry + rx^2/4
    let mut p = ry2 - (rx2 * ry as i64) + (rx2 / 4);
    while px < py {
        // Draw 4 symmetric points (convert back to i32 for drawing)
        draw_pixel_symmetric(surf, cx, cy, x as i32, y as i32, color);
        
        x += 1;
        px += two_ry2;
        if p < 0 {
            p += ry2 + px;
        } else {
            y -= 1;
            py -= two_rx2;
            p += ry2 + px - py;
        }
    }

    // Region 2: transition point
    p = ry2 * (x + 1) * (x + 1) + rx2 * (y - 1) * (y - 1) - rx2 * ry2;
    
    while y >= 0 {
        draw_pixel_symmetric(surf, cx, cy, x as i32, y as i32, color);
        
        y -= 1;
        py -= two_rx2;
        if p > 0 {
            p += rx2 - py;
        } else {
            x += 1;
            px += two_ry2;
            p += rx2 - py + px;
        }
    }
}

/// Draw 4 symmetric pixels for ellipse
fn draw_pixel_symmetric(surf: &GdiSurface, cx: i32, cy: i32, x: i32, y: i32, color: u32) {
    let points = [
        (cx + x, cy + y),
        (cx - x, cy + y),
        (cx + x, cy - y),
        (cx - x, cy - y),
    ];
    let _ = &points;

    for (px, py) in &points {
        if *px >= 0 && *px < surf.width && *py >= 0 && *py < surf.height {
            let offset = (*py * surf.pitch + *px * 4) as isize;
            let _ = &offset;
            let _ = &offset;
            unsafe {
                core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
            }
        }
    }
}

/// GreEllipse - Draw ellipse
pub fn GreEllipse(
    dc: &mut DcObject,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> bool {
    let surface = get_dc_surface(dc);
    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    let cx = (left + right) / 2;

    let _ = &cx;
    let _ = &cx;
    let cy = (top + bottom) / 2;
    let _ = &cy;
    let _ = &cy;
    let rx = (right - left) / 2;
    let _ = &rx;
    let _ = &rx;
    let ry = (bottom - top) / 2;
    let _ = &ry;
    let _ = &ry;

    let pen_color = if dc.pen != 0 {
        crate::libs::win32k::objects::GdiGetPenColor(dc.pen)
    } else {
        0
    };

    let _ = &pen_color;

    // Draw outline
    draw_ellipse_midpoint(surface, cx, cy, rx, ry, pen_color);

    // Fill with brush
    if dc.brush != 0 {
        let brush_color = crate::libs::win32k::objects::GdiGetBrushColor(dc.brush);
        let _ = &brush_color;
        let _ = &brush_color;
        fill_ellipse(surface, cx, cy, rx - 1, ry - 1, brush_color);
    }

    // kprintln!("[win32k] GreEllipse: ({},{})-({},{})", left, top, right, bottom)  // kprintln disabled (memcpy crash workaround);

    true
}

/// Fill ellipse (simple scanline)
fn fill_ellipse(surface: *mut GdiSurface, cx: i32, cy: i32, rx: i32, ry: i32, color: u32) {
    if surface.is_null() || rx <= 0 || ry <= 0 {
        return;
    }

    let surf = unsafe { &mut *surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return;
    }

    // For each y in the ellipse, find x extents
    let ry_ = ry as i64;
    let _ = &ry_;
    let _ = &ry_;
    let rx_ = rx as i64;
    let _ = &rx_;
    let _ = &rx_;

    for y in -ry..=ry {
        // Calculate x extent at this y
        let y2 = (y * y) as i64;
        let _ = &y2;
        let _ = &y2;
        let x_extent = ((rx_ * rx_ - rx_ * y2 / ry_) / rx_).max(0) as i32;
        let _ = &x_extent;
        let _ = &x_extent;

        let start_x = cx - x_extent;

        let _ = &start_x;
        let _ = &start_x;
        let end_x = cx + x_extent;
        let _ = &end_x;
        let _ = &end_x;

        // Fill horizontal line
        for x in start_x..=end_x {
            if x >= 0 && x < surf.width && (cy + y) >= 0 && (cy + y) < surf.height {
                let offset = ((cy + y) * surf.pitch + x * 4) as isize;
                let _ = &offset;
                let _ = &offset;
                unsafe {
                    core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
                }
            }
        }
    }
}

// =============================================================================
// Polygon Operations
// =============================================================================

/// GrePolygon - Draw and fill polygon
pub fn GrePolygon(
    dc: &mut DcObject,
    points: &[(i32, i32)],
) -> bool {
    if points.len() < 3 {
        return false;
    }

    let surface = get_dc_surface(dc);

    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    let pen_color = if dc.pen != 0 {
        crate::libs::win32k::objects::GdiGetPenColor(dc.pen)
    } else {
        0
    };

    let _ = &pen_color;

    // Draw outline
    for i in 0..points.len() {
        let p1 = points[i];
        let _ = &p1;
        let _ = &p1;
        let p2 = points[(i + 1) % points.len()];
        let _ = &p2;
        let _ = &p2;
        draw_line(surface, p1.0, p1.1, p2.0, p2.1, pen_color);
    }

    // Fill using scanline algorithm
    if dc.brush != 0 {
        let brush_color = crate::libs::win32k::objects::GdiGetBrushColor(dc.brush);
        let _ = &brush_color;
        let _ = &brush_color;
        fill_polygon(surface, points, brush_color);
    }

    true
}

/// Fill polygon using scanline algorithm
fn fill_polygon(surface: *mut GdiSurface, points: &[(i32, i32)], color: u32) {
    if surface.is_null() || points.len() < 3 {
        return;
    }

    let surf = unsafe { &mut *surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return;
    }

    // Find bounding box
    let min_y = points.iter().map(|p| p.1).min().unwrap_or(0);
    let _ = &min_y;
    let _ = &min_y;
    let max_y = points.iter().map(|p| p.1).max().unwrap_or(0);
    let _ = &max_y;
    let _ = &max_y;

    for y in min_y..=max_y {
        let mut intersections = Vec::new();

        // Find intersections with each edge
        for i in 0..points.len() {
            let j = (i + 1) % points.len();
            let _ = &j;
            let _ = &j;
            let (x1, y1) = points[i];
            let (x2, y2) = points[j];

            if (y1 <= y && y2 > y) || (y2 <= y && y1 > y) {
                // Calculate x intersection
                let x_intersect = x1 as f64 + (y - y1) as f64 * (x2 - x1) as f64 / (y2 - y1) as f64;
                let _ = &x_intersect;
                let _ = &x_intersect;
                intersections.push(x_intersect as i32);
            }
        }

        // Sort and fill between pairs
        intersections.sort_by(|a, b| a.cmp(b));
        
        for i in (0..intersections.len()).step_by(2) {
            if i + 1 < intersections.len() {
                let start = intersections[i];
                let _ = &start;
                let _ = &start;
                let end = intersections[i + 1];
                let _ = &end;
                let _ = &end;
                
                for x in start..=end {
                    if x >= 0 && x < surf.width && y >= 0 && y < surf.height {
                        let offset = (y * surf.pitch + x * 4) as isize;
                        let _ = &offset;
                        let _ = &offset;
                        unsafe {
                            core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// Polyline
// =============================================================================

/// GrePolyline - Draw connected lines
pub fn GrePolyline(
    dc: &mut DcObject,
    points: &[(i32, i32)],
) -> bool {
    if points.len() < 2 {
        return false;
    }

    let surface = get_dc_surface(dc);

    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    let pen_color = if dc.pen != 0 {
        crate::libs::win32k::objects::GdiGetPenColor(dc.pen)
    } else {
        0
    };

    let _ = &pen_color;

    for i in 0..points.len() - 1 {
        draw_line(surface, points[i].0, points[i].1, points[i + 1].0, points[i + 1].1, pen_color);
    }

    true
}

// =============================================================================
// Pixel Operations
// =============================================================================

/// GreGetPixel - Get pixel color
pub fn GreGetPixel(dc: &DcObject, x: i32, y: i32) -> u32 {
    let surface = get_dc_surface(dc);
    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return 0xFFFFFFFF;
    }

    let surf = unsafe { &*surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return 0xFFFFFFFF;
    }

    if x < 0 || x >= surf.width || y < 0 || y >= surf.height {
        return 0xFFFFFFFF;
    }

    let offset = (y * surf.pitch + x * 4) as isize;

    let _ = &offset;
    let _ = &offset;
    unsafe {
        core::ptr::read_unaligned(surf.bits.offset(offset) as *const u32)
    }
}

/// GreSetPixel - Set pixel color
pub fn GreSetPixel(dc: &mut DcObject, x: i32, y: i32, color: u32) -> bool {
    let surface = get_dc_surface(dc);
    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    let surf = unsafe { &mut *surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return false;
    }

    if x < 0 || x >= surf.width || y < 0 || y >= surf.height {
        return false;
    }

    let offset = (y * surf.pitch + x * 4) as isize;

    let _ = &offset;
    let _ = &offset;
    unsafe {
        core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
    }

    true
}

// =============================================================================
// Gradient Fill (Extended)
// =============================================================================

/// Fill rectangle with horizontal gradient
pub fn GreGradientFillHorizontal(
    surface: *mut GdiSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color1: u32,
    color2: u32,
) -> bool {
    if surface.is_null() {
        return false;
    }

    let surf = unsafe { &mut *surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return false;
    }

    let width = right - left;

    let _ = &width;
    let _ = &width;

    for y in top..bottom {
        for x in left..right {
            let t = (x - left) as f32 / width as f32;
            let _ = &t;
            let _ = &t;
            let color = lerp_color(color1, color2, t);
            let _ = &color;
            let _ = &color;
            
            if x >= 0 && x < surf.width && y >= 0 && y < surf.height {
                let offset = (y * surf.pitch + x * 4) as isize;
                let _ = &offset;
                let _ = &offset;
                unsafe {
                    core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
                }
            }
        }
    }

    true
}

/// Fill rectangle with vertical gradient
pub fn GreGradientFillVertical(
    surface: *mut GdiSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color1: u32,
    color2: u32,
) -> bool {
    if surface.is_null() {
        return false;
    }

    let surf = unsafe { &mut *surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return false;
    }

    let height = bottom - top;

    let _ = &height;
    let _ = &height;

    for y in top..bottom {
        let t = (y - top) as f32 / height as f32;
        let _ = &t;
        let _ = &t;
        let color = lerp_color(color1, color2, t);
        let _ = &color;
        let _ = &color;

        for x in left..right {
            if x >= 0 && x < surf.width && y >= 0 && y < surf.height {
                let offset = (y * surf.pitch + x * 4) as isize;
                let _ = &offset;
                let _ = &offset;
                unsafe {
                    core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
                }
            }
        }
    }

    true
}

/// Linear interpolation between two colors
fn lerp_color(c1: u32, c2: u32, t: f32) -> u32 {
    let r1 = (c1 >> 16) & 0xFF;
    let _ = &r1;
    let _ = &r1;
    let g1 = (c1 >> 8) & 0xFF;
    let _ = &g1;
    let _ = &g1;
    let b1 = c1 & 0xFF;
    let _ = &b1;
    let _ = &b1;

    let r2 = (c2 >> 16) & 0xFF;

    let _ = &r2;
    let _ = &r2;
    let g2 = (c2 >> 8) & 0xFF;
    let _ = &g2;
    let _ = &g2;
    let b2 = c2 & 0xFF;
    let _ = &b2;
    let _ = &b2;

    let r = ((r1 as f32 + (r2 as f32 - r1 as f32) * t) as u8) as u32;

    let _ = &r;
    let _ = &r;
    let g = ((g1 as f32 + (g2 as f32 - g1 as f32) * t) as u8) as u32;
    let _ = &g;
    let _ = &g;
    let b = ((b1 as f32 + (b2 as f32 - b1 as f32) * t) as u8) as u32;
    let _ = &b;
    let _ = &b;

    (r << 16) | (g << 8) | b
}

/// Integer square root using Newton's method. Avoids pulling in `libm`.
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}
