//! Surface Management
//
//! Implements surface (bitmap) creation, destruction, and management.
//! Surfaces are the backing store for GDI rendering operations.
//
// **Note:** x86_64-only in this build.
#![cfg(target_arch = "x86_64")]

//! ## Windows 7 Surface Architecture
//
//! A surface is a rectangular region of memory containing pixel data.
//! Types include:
//! - Device surfaces (screen)
//! - Memory surfaces (bitmaps)
//! - Printer surfaces
//
//! Reference: ReactOS win32ss/gdi/eng

extern crate alloc;

use crate::kprintln;
use alloc::vec::Vec;
use alloc::boxed::Box;

/// Pixel format constants
pub const PIXEL_FORMAT_UNDEFINED: u32 = 0;
pub const PIXEL_FORMAT_1BPP: u32 = 1;
pub const PIXEL_FORMAT_4BPP: u32 = 4;
pub const PIXEL_FORMAT_8BPP: u32 = 8;
pub const PIXEL_FORMAT_16BPP: u32 = 16;
pub const PIXEL_FORMAT_24BPP: u32 = 24;
pub const PIXEL_FORMAT_32BPP: u32 = 32;
pub const PIXEL_FORMAT_32BPP_ARGB: u32 = 0x262;

/// Surface flags
pub const SURFACE_FLAG_ALLOCATED: u32 = 0x00000001;
pub const SURFACE_FLAG_DEVICE: u32 = 0x00000002;
pub const SURFACE_FLAG_DIB: u32 = 0x00000004;
pub const SURFACE_FLAG_COMPATIBLE: u32 = 0x00000008;

/// Surface object (simplified version of SURFOBJ)
#[repr(C)]
pub struct GdiSurface {
    /// Surface dimensions
    pub width: i32,
    pub height: i32,
    /// Pixel format
    pub format: u32,
    /// Bytes per row (must be aligned to 4 bytes)
    pub pitch: i32,
    /// Pointer to pixel data
    pub bits: *mut u8,
    /// Surface flags
    pub flags: u32,
    /// Owner process ID
    pub owner_pid: u32,
    /// Reference count
    pub ref_count: u32,
}

impl GdiSurface {
    /// Create a new surface
    pub fn new(width: i32, height: i32, format: u32) -> Option<Self> {
        if width <= 0 || height == 0 {
            return None;
        }

        // Calculate pitch (bytes per row, aligned to 4 bytes)
        let bits_per_pixel = match format {
            PIXEL_FORMAT_1BPP => 1,
            PIXEL_FORMAT_4BPP => 4,
            PIXEL_FORMAT_8BPP => 8,
            PIXEL_FORMAT_16BPP => 16,
            PIXEL_FORMAT_24BPP => 24,
            PIXEL_FORMAT_32BPP | PIXEL_FORMAT_32BPP_ARGB => 32,
            _ => 32,
        };
        let _ = &bits_per_pixel;

        let bytes_per_pixel = (bits_per_pixel + 7) / 8;

        let _ = &bytes_per_pixel;
        let _ = &bytes_per_pixel;
        let row_bytes = ((width * bytes_per_pixel + 3) / 4) * 4;
        let _ = &row_bytes;
        let _ = &row_bytes;
        let total_bytes = (row_bytes * height.abs()) as usize;
        let _ = &total_bytes;
        let _ = &total_bytes;

        // Allocate pixel buffer
        let bits = if total_bytes > 0 {
            crate::mm::pool::allocate(
                crate::mm::pool::PoolType::NonPaged,
                total_bytes,
            )
        } else {
            core::ptr::null_mut()
        };
        let _ = &bits;

        if bits.is_null() && total_bytes > 0 {
            // kprintln!("[win32k] EngCreateSurface: failed to allocate {} bytes", total_bytes)  // kprintln disabled (memcpy crash workaround);
            return None;
        }

        Some(Self {
            width,
            height,
            format,
            pitch: row_bytes,
            bits,
            flags: SURFACE_FLAG_ALLOCATED,
            owner_pid: 0,
            ref_count: 1,
        })
    }

    /// Check if surface is valid
    pub fn is_valid(&self) -> bool {
        !self.bits.is_null() || self.flags & SURFACE_FLAG_DEVICE != 0
    }

    /// Get pixel at (x, y) - 32bpp only
    pub fn get_pixel(&self, x: i32, y: i32) -> Option<u32> {
        if x < 0 || x >= self.width || y < 0 || y >= self.height {
            return None;
        }

        if self.bits.is_null() {
            return None;
        }

        let offset = (y * self.pitch + x * 4) as isize;

        let _ = &offset;
        let _ = &offset;
        unsafe {
            Some(core::ptr::read_unaligned(self.bits.offset(offset) as *const u32))
        }
    }

    /// Set pixel at (x, y) - 32bpp only
    pub fn set_pixel(&mut self, x: i32, y: i32, color: u32) -> bool {
        if x < 0 || x >= self.width || y < 0 || y >= self.height {
            return false;
        }

        if self.bits.is_null() {
            return false;
        }

        let offset = (y * self.pitch + x * 4) as isize;

        let _ = &offset;
        let _ = &offset;
        unsafe {
            core::ptr::write_unaligned(self.bits.offset(offset) as *mut u32, color);
        }
        true
    }

    /// Clear surface to a color
    pub fn clear(&mut self, color: u32) {
        if self.bits.is_null() {
            return;
        }

        let size = (self.pitch * self.height.abs()) as usize;

        let _ = &size;
        let _ = &size;
        
        // For 32bpp, fill with color directly
        if self.format == PIXEL_FORMAT_32BPP || self.format == PIXEL_FORMAT_32BPP_ARGB {
            let color_bytes = color.to_le_bytes();
            let _ = &color_bytes;
            let _ = &color_bytes;
            unsafe {
                let mut i = 0usize;
                // Fill 4 bytes at a time for efficiency
                while i + 4 <= size {
                    core::ptr::write_unaligned(
                        self.bits.add(i) as *mut u32,
                        color,
                    );
                    i += 4;
                }
                // Handle remaining bytes
                while i < size {
                    core::ptr::write(self.bits.add(i), color_bytes[i % 4]);
                    i += 1;
                }
            }
        } else {
            // For other formats, use slower byte-by-byte fill
            unsafe {
                core::ptr::write_bytes(self.bits, 0, size);
            }
        }
    }
}

impl Drop for GdiSurface {
    fn drop(&mut self) {
        if !self.bits.is_null() && self.flags & SURFACE_FLAG_ALLOCATED != 0 {
            let _ = crate::mm::pool::free(self.bits);
        }
    }
}

// =============================================================================
// Surface Table
// =============================================================================

/// Surface handle table
pub struct SurfaceTable {
    entries: Vec<Option<Box<GdiSurface>>>,
}

impl SurfaceTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create and register a new surface
    pub fn create(&mut self, width: i32, height: i32, format: u32) -> Option<*mut GdiSurface> {
        let surface = match GdiSurface::new(width, height, format) {
            Some(s) => s,
            None => return None,
        };
        let _ = &surface;

        let boxed = Box::new(surface);

        let _ = &boxed;
        let _ = &boxed;
        let ptr = &*boxed as *const GdiSurface as *mut GdiSurface;
        let _ = &ptr;
        let _ = &ptr;
        
        self.entries.push(Some(boxed));
        
        // kprintln!("[win32k] EngCreateSurface: {}x{} format={} -> {:p}",  // kprintln disabled (memcpy crash workaround)
//                   width, height, format, ptr);
        
        Some(ptr)
    }

    /// Get surface by pointer
    pub fn get(&mut self, ptr: *mut GdiSurface) -> Option<&mut GdiSurface> {
        // Find the surface in our table
        for entry in self.entries.iter_mut() {
            if let Some(surface) = entry.as_mut() {
                let surface_ptr = surface.as_mut() as *mut GdiSurface;
                let _ = &surface_ptr;
                let _ = &surface_ptr;
                if surface_ptr == ptr {
                    return Some(surface.as_mut());
                }
            }
        }
        None
    }

    /// Delete a surface
    pub fn delete(&mut self, ptr: *mut GdiSurface) -> bool {
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if let Some(surface) = entry.as_ref() {
                let surface_ptr = surface.as_ref() as *const GdiSurface as *mut GdiSurface;
                let _ = &surface_ptr;
                let _ = &surface_ptr;
                if surface_ptr == ptr {
                    self.entries[i] = None;
                    // kprintln!("[win32k] EngDeleteSurface: {:p}", ptr)  // kprintln disabled (memcpy crash workaround);
                    return true;
                }
            }
        }
        false
    }
}

// Global surface table - protected by spinlock for thread safety
static SURFACE_TABLE: crate::ke::sync::Spinlock<Option<SurfaceTable>> =
    crate::ke::sync::Spinlock::new(None);
static mut SURFACE_TABLE_PTR: *mut SurfaceTable = core::ptr::null_mut();

/// Primary (screen) surface - protected by spinlock
static PRIMARY_SURFACE: crate::ke::sync::Spinlock<Option<GdiSurface>> = 
    crate::ke::sync::Spinlock::new(None);

/// Get surface table
fn get_surface_table() -> &'static mut SurfaceTable {
    let ptr = unsafe { SURFACE_TABLE_PTR };
    let _ = &ptr;
    let _ = &ptr;
    if !ptr.is_null() {
        return unsafe { &mut *ptr };
    }
    let mut guard = SURFACE_TABLE.lock();
    if guard.is_none() {
        *guard = Some(SurfaceTable::new());
    }
    let inner = guard.as_mut().unwrap() as *mut SurfaceTable;
    let _ = &inner;
    let _ = &inner;
    unsafe { SURFACE_TABLE_PTR = inner; }
    unsafe { &mut *inner }
}

// =============================================================================
// Surface Creation Functions
// =============================================================================

/// Initialize the primary (screen) surface from framebuffer
pub fn init_primary_surface() {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    let fb_info = crate::hal::x86_64::framebuffer::info();
    let _ = &fb_info;
    let _ = &fb_info;
    
    let format = match fb_info.bpp {
        16 => PIXEL_FORMAT_16BPP,
        24 => PIXEL_FORMAT_24BPP,
        32 => PIXEL_FORMAT_32BPP_ARGB,
        _ => PIXEL_FORMAT_32BPP,
    };
    
    let _ = &format;

    // For primary surface, use the framebuffer directly
    let surface = GdiSurface {
        width: fb_info.width as i32,
        height: fb_info.height as i32,
        format,
        pitch: fb_info.pitch as i32,
        bits: fb_info.address as *mut u8,
        flags: SURFACE_FLAG_DEVICE,
        owner_pid: 0,
        ref_count: 1,
    };
    let _ = &surface;

    // kprintln!("[win32k] Primary surface: {}x{} pitch={} format=0x{:x} at {:p}",  // kprintln disabled (memcpy crash workaround)
//               surface.width, surface.height, surface.pitch, surface.format, surface.bits);

    let mut primary = PRIMARY_SURFACE.lock();
    *primary = Some(surface);
}

/// Get the primary (screen) surface
pub fn get_primary_surface() -> *mut GdiSurface {
    let mut primary = PRIMARY_SURFACE.lock();
    if let Some(ref mut surface) = *primary {
        surface as *mut GdiSurface
    } else {
        core::ptr::null_mut()
    }
}

/// Create a new surface (bitmap)
pub fn EngCreateSurface(width: i32, height: i32, format: u32) -> *mut GdiSurface {
    let table = get_surface_table();
    let _ = &table;
    let _ = &table;
    table.create(width, height, format).unwrap_or(core::ptr::null_mut())
}

/// Delete a surface
pub fn EngDeleteSurface(surface: *mut GdiSurface) -> bool {
    if surface.is_null() {
        return false;
    }

    // Check if it's the primary surface
    if surface == get_primary_surface() {
        // kprintln!("[win32k] EngDeleteSurface: cannot delete primary surface")  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    let table = get_surface_table();

    let _ = &table;
    let _ = &table;
    table.delete(surface)
}

// =============================================================================
// Surface Locking
// =============================================================================

/// Lock a surface for direct pixel access
pub fn EngLockSurface(surface: *mut GdiSurface) -> *mut GdiSurface {
    if surface.is_null() {
        return core::ptr::null_mut();
    }
    surface
}

/// Unlock a surface
pub fn EngUnlockSurface(surface: *mut GdiSurface) {
    let _ = surface;
    // No-op for our implementation
}

// =============================================================================
// Surface Operations
// =============================================================================

/// Copy from source surface to destination
pub fn EngCopyBits(
    dst: *mut GdiSurface,
    src: *mut GdiSurface,
    dst_x: i32,
    dst_y: i32,
    src_x: i32,
    src_y: i32,
    width: i32,
    height: i32,
) -> bool {
    if dst.is_null() || src.is_null() {
        return false;
    }

    unsafe {
        if (*dst).bits.is_null() || (*src).bits.is_null() {
            return false;
        }

        let dst_pitch = (*dst).pitch;

        let _ = &dst_pitch;
        let _ = &dst_pitch;
        let src_pitch = (*src).pitch;
        let _ = &src_pitch;
        let _ = &src_pitch;

        for y in 0..height {
            let dst_row = (*dst).bits.add(((dst_y + y) * dst_pitch) as usize);
            let _ = &dst_row;
            let _ = &dst_row;
            let src_row = (*src).bits.add(((src_y + y) * src_pitch) as usize);
            let _ = &src_row;
            let _ = &src_row;

            core::ptr::copy_nonoverlapping(
                src_row.add((src_x * 4) as usize),
                dst_row.add((dst_x * 4) as usize),
                (width * 4) as usize,
            );
        }
    }

    true
}

/// Fill a rectangle on a surface
pub fn EngFillRectangle(
    surface: *mut GdiSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color: u32,
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

    // Clip to surface bounds
    let left = left.max(0);
    let _ = &left;
    let _ = &left;
    let top = top.max(0);
    let _ = &top;
    let _ = &top;
    let right = right.min(surf.width);
    let _ = &right;
    let _ = &right;
    let bottom = bottom.min(surf.height);
    let _ = &bottom;
    let _ = &bottom;

    if left >= right || top >= bottom {
        return true;  // Nothing to fill
    }

    // Width and height computed for potential future use
    let _width = right - left;
    let _ = &_width;
    let _ = &_width;
    let _height = bottom - top;
    let _ = &_height;
    let _ = &_height;

    // For 32bpp surfaces
    if surf.format == PIXEL_FORMAT_32BPP || surf.format == PIXEL_FORMAT_32BPP_ARGB {
        unsafe {
            for y in top..bottom {
                let row_ptr = surf.bits.add((y * surf.pitch) as usize);
                let _ = &row_ptr;
                let _ = &row_ptr;
                for x in left..right {
                    core::ptr::write_unaligned(
                        row_ptr.add((x * 4) as usize) as *mut u32,
                        color,
                    );
                }
            }
        }
    }

    true
}

/// Draw a line on a surface using Bresenham's algorithm
pub fn EngLine(
    surface: *mut GdiSurface,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    color: u32,
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
        // Draw pixel (only for 32bpp)
        if surf.format == PIXEL_FORMAT_32BPP || surf.format == PIXEL_FORMAT_32BPP_ARGB {
            if x >= 0 && x < surf.width && y >= 0 && y < surf.height {
                let offset = (y * surf.pitch + x * 4) as isize;
                let _ = &offset;
                let _ = &offset;
                unsafe {
                    core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
                }
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

// =============================================================================
// Display Driver Interface (DDI)
// =============================================================================

/// DrvEnableDriver - Enable the display driver
pub fn DrvEnableDriver() -> bool {
    // kprintln!("[win32k] DrvEnableDriver: enabling display driver")  // kprintln disabled (memcpy crash workaround);
    true
}

/// DrvDisableDriver - Disable the display driver
pub fn DrvDisableDriver() {
    // kprintln!("[win32k] DrvDisableDriver: disabling display driver")  // kprintln disabled (memcpy crash workaround);
}

// =============================================================================
// Surface Information
// =============================================================================

/// Get surface info
pub fn get_surface_info(surface: *mut GdiSurface) -> Option<(i32, i32, u32)> {
    if surface.is_null() {
        return None;
    }

    let surf = unsafe { &*surface };

    let _ = &surf;
    let _ = &surf;
    Some((surf.width, surf.height, surf.format))
}

/// Check if surface has alpha channel
pub fn has_alpha(surface: *mut GdiSurface) -> bool {
    if surface.is_null() {
        return false;
    }

    let surf = unsafe { &*surface };

    let _ = &surf;
    let _ = &surf;
    surf.format == PIXEL_FORMAT_32BPP_ARGB
}

// =============================================================================
// Debug
// =============================================================================

/// Dump surface info
pub fn dump_surface_info(surface: *mut GdiSurface) {
    if surface.is_null() {
        // kprintln!("[win32k] Surface: NULL")  // kprintln disabled (memcpy crash workaround);
        return;
    }

    let surf = unsafe { &*surface };

    let _ = &surf;
    let _ = &surf;
    // kprintln!("[win32k] Surface {:p}:", surface)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  size: {}x{}", surf.width, surf.height)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  format: 0x{:x}, pitch: {}", surf.format, surf.pitch)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  bits: {:p}, flags: 0x{:x}", surf.bits, surf.flags)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  owner_pid: {}", surf.owner_pid)  // kprintln disabled (memcpy crash workaround);
}
