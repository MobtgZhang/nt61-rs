//! WM_PAINT and Coordinate System for win32k.sys
//
//! Implements the painting subsystem including BeginPaint, EndPaint,
//! InvalidateRect, and coordinate transformations.

#![allow(non_snake_case)]

use core::sync::atomic::AtomicU64;
use crate::kprintln;

// =============================================================================
// Coordinate Systems
// =============================================================================

/// Point in screen coordinates
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct POINT {
    pub x: i32,
    pub y: i32,
}

impl POINT {
    pub fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

/// Paint structure for BeginPaint/EndPaint
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PAINTSTRUCT {
    /// Handle to the device context
    pub hdc: u64,
    /// Whether the background needs erasing
    pub fErase: bool,
    /// Rectangle that needs updating
    pub rcPaint_left: i32,
    pub rcPaint_top: i32,
    pub rcPaint_right: i32,
    pub rcPaint_bottom: i32,
    /// Reserved
    pub fRestore: bool,
    pub fIncUpdate: bool,
    pub rgbReserved: [u8; 32],
}

/// Update region flags as a bitmask wrapper.
/// These are bitmask values matching Windows RDW_* constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct UpdateRegionFlags(u32);

impl UpdateRegionFlags {
    pub const RDW_INVALIDATE: u32 = 0x0001;
    pub const RDW_INTERNALPAINT: u32 = 0x0002;
    pub const RDW_ERASE: u32 = 0x0004;
    pub const RDW_VALIDATE: u32 = 0x0008;
    pub const RDW_NOINTERNALPAINT: u32 = 0x0010;
    pub const RDW_NOERASE: u32 = 0x0020;
    pub const RDW_NOCHILDREN: u32 = 0x0040;
    pub const RDW_ALLCHILDREN: u32 = 0x0080;
    pub const RDW_UPDATENOW: u32 = 0x0100;
    pub const RDW_ERASENOW: u32 = 0x0200;
    pub const RDW_FRAME: u32 = 0x0400;
    pub const RDW_NOFRAME: u32 = 0x0800;

    pub const fn new(bits: u32) -> Self { Self(bits) }
    pub const fn bits(&self) -> u32 { self.0 }
    pub fn set(&mut self, flag: u32) { self.0 |= flag; }
    pub fn contains(&self, flag: u32) -> bool { (self.0 & flag) == flag }
}

// =============================================================================
// Window Coordinate Transformations
// =============================================================================

/// Coordinate space types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CoordinateSpace {
    /// Device units (pixels)
    DEVICE = 0,
    /// Logical units (dependent on mapping mode)
    LOGICAL = 1,
    /// Page units (1/96 inch in MM_TEXT)
    PAGE = 2,
    /// World coordinates (transformed)
    WORLD = 3,
}

/// Transform logical points to device points using DC's mapping mode.
/// Windows mapping modes:
/// - MM_TEXT: 1 logical unit = 1 pixel (default)
/// - MM_LOMETRIC: 1 logical unit = 0.1 mm
/// - MM_HIMETRIC: 1 logical unit = 0.01 mm
/// - MM_LOENGLISH: 1 logical unit = 0.01 inch
/// - MM_HIENGLISH: 1 logical unit = 0.001 inch
/// Formula: Device = (Logical - WindowOrg) * (ViewportExt / WindowExt) + ViewportOrg
pub fn lp_to_dp(hdc: u64, points: &mut [POINT]) -> bool {
    let table = crate::libs::win32k::dc::get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(hdc) {
        let vx = dc.viewport_ext.cx as f32;
        let _ = &vx;
        let _ = &vx;
        let vy = dc.viewport_ext.cy as f32;
        let _ = &vy;
        let _ = &vy;
        let wx = dc.window_ext.cx as f32;
        let _ = &wx;
        let _ = &wx;
        let wy = dc.window_ext.cy as f32;
        let _ = &wy;
        let _ = &wy;
        let pox = dc.viewport_org.x as f32;
        let _ = &pox;
        let _ = &pox;
        let poy = dc.viewport_org.y as f32;
        let _ = &poy;
        let _ = &poy;
        let wox = dc.window_org.x as f32;
        let _ = &wox;
        let _ = &wox;
        let woy = dc.window_org.y as f32;
        let _ = &woy;
        let _ = &woy;

        // Avoid division by zero
        let scale_x = if wx != 0.0 { vx / wx } else { 1.0 };
        let _ = &scale_x;
        let _ = &scale_x;
        let scale_y = if wy != 0.0 { vy / wy } else { 1.0 };
        let _ = &scale_y;
        let _ = &scale_y;

        for pt in points.iter_mut() {
            // Formula: D = (L - WO) * (VE / WE) + VO
            let dx = ((pt.x as f32 - wox) * scale_x + pox) as i32;
            let _ = &dx;
            let _ = &dx;
            let dy = ((pt.y as f32 - woy) * scale_y + poy) as i32;
            let _ = &dy;
            let _ = &dy;
            pt.x = dx;
            pt.y = dy;
        }
        // kprintln!("[win32k] lp_to_dp: hdc={:#x}, {} points, scale=({:.2},{:.2})",  // kprintln disabled (memcpy crash workaround)
//             hdc, points.len(), scale_x, scale_y);
        true
    } else {
        // kprintln!("[win32k] lp_to_dp: hdc={:#x} not found", hdc)  // kprintln disabled (memcpy crash workaround);
        false
    }
}

/// Transform device points to logical points using DC's mapping mode.
/// Formula: Logical = (Device - ViewportOrg) * (WindowExt / ViewportExt) + WindowOrg
pub fn dp_to_lp(hdc: u64, points: &mut [POINT]) -> bool {
    let table = crate::libs::win32k::dc::get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(hdc) {
        let vx = dc.viewport_ext.cx as f32;
        let _ = &vx;
        let _ = &vx;
        let vy = dc.viewport_ext.cy as f32;
        let _ = &vy;
        let _ = &vy;
        let wx = dc.window_ext.cx as f32;
        let _ = &wx;
        let _ = &wx;
        let wy = dc.window_ext.cy as f32;
        let _ = &wy;
        let _ = &wy;
        let pox = dc.viewport_org.x as f32;
        let _ = &pox;
        let _ = &pox;
        let poy = dc.viewport_org.y as f32;
        let _ = &poy;
        let _ = &poy;
        let wox = dc.window_org.x as f32;
        let _ = &wox;
        let _ = &wox;
        let woy = dc.window_org.y as f32;
        let _ = &woy;
        let _ = &woy;

        // Avoid division by zero
        let scale_x = if vx != 0.0 { wx / vx } else { 1.0 };
        let _ = &scale_x;
        let _ = &scale_x;
        let scale_y = if vy != 0.0 { wy / vy } else { 1.0 };
        let _ = &scale_y;
        let _ = &scale_y;

        for pt in points.iter_mut() {
            // Formula: L = (D - VO) * (WE / VE) + WO
            let lx = ((pt.x as f32 - pox) * scale_x + wox) as i32;
            let _ = &lx;
            let _ = &lx;
            let ly = ((pt.y as f32 - poy) * scale_y + woy) as i32;
            let _ = &ly;
            let _ = &ly;
            pt.x = lx;
            pt.y = ly;
        }
        // kprintln!("[win32k] dp_to_lp: hdc={:#x}, {} points, scale=({:.2},{:.2})",  // kprintln disabled (memcpy crash workaround)
//             hdc, points.len(), scale_x, scale_y);
        true
    } else {
        // kprintln!("[win32k] dp_to_lp: hdc={:#x} not found", hdc)  // kprintln disabled (memcpy crash workaround);
        false
    }
}

/// Transform a rectangle from logical to device coordinates
pub fn rect_lp_to_dp(hdc: u64, rect: &mut crate::libs::win32k::window::Rect) -> bool {
    let mut points = [
        POINT::new(rect.left, rect.top),
        POINT::new(rect.right, rect.bottom),
    ];
    
    if lp_to_dp(hdc, &mut points) {
        // Get new bounds
        let left = points[0].x.min(points[1].x);
        let _ = &left;
        let _ = &left;
        let top = points[0].y.min(points[1].y);
        let _ = &top;
        let _ = &top;
        let right = points[0].x.max(points[1].x);
        let _ = &right;
        let _ = &right;
        let bottom = points[0].y.max(points[1].y);
        let _ = &bottom;
        let _ = &bottom;
        
        rect.left = left;
        rect.top = top;
        rect.right = right;
        rect.bottom = bottom;
        
        // kprintln!("[win32k] rect_lp_to_dp: hdc={:#x}, ({},{})-({},{}) -> ({},{})-({},{})",  // kprintln disabled (memcpy crash workaround)
//             hdc, rect.left, rect.top, rect.right, rect.bottom,
//             rect.left, rect.top, rect.right, rect.bottom);
        true
    } else {
        false
    }
}

/// Transform a rectangle from device to logical coordinates
pub fn rect_dp_to_lp(hdc: u64, rect: &mut crate::libs::win32k::window::Rect) -> bool {
    let mut points = [
        POINT::new(rect.left, rect.top),
        POINT::new(rect.right, rect.bottom),
    ];
    
    if dp_to_lp(hdc, &mut points) {
        let left = points[0].x.min(points[1].x);
        let _ = &left;
        let _ = &left;
        let top = points[0].y.min(points[1].y);
        let _ = &top;
        let _ = &top;
        let right = points[0].x.max(points[1].x);
        let _ = &right;
        let _ = &right;
        let bottom = points[0].y.max(points[1].y);
        let _ = &bottom;
        let _ = &bottom;
        
        rect.left = left;
        rect.top = top;
        rect.right = right;
        rect.bottom = bottom;
        
        // kprintln!("[win32k] rect_dp_to_lp: hdc={:#x}, ({},{})-({},{}) -> ({},{})-({},{})",  // kprintln disabled (memcpy crash workaround)
//             hdc, rect.left, rect.top, rect.right, rect.bottom,
//             rect.left, rect.top, rect.right, rect.bottom);
        true
    } else {
        false
    }
}

// =============================================================================
// BeginPaint / EndPaint
// =============================================================================

/// BeginPaint result with PAINTSTRUCT
#[derive(Debug, Clone, Copy)]
pub struct BeginPaintResult {
    pub hdc: u64,
    pub paint_struct: PAINTSTRUCT,
}

/// BeginPaint - Prepare a window for painting.
/// Returns a DC with the update region selected and the clipping region set.
pub fn begin_paint(hwnd: u64) -> Option<BeginPaintResult> {
    // kprintln!("[win32k] BeginPaint: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);

    // Get the window's DC
    let hdc = crate::libs::win32k::dc::GreCreateDisplayDC();
    let _ = &hdc;
    let _ = &hdc;
    if hdc == 0 {
        // kprintln!("[win32k] BeginPaint: failed to create DC")  // kprintln disabled (memcpy crash workaround);
        return None;
    }

    // Get window rectangle
    let window_rect = crate::libs::win32k::window::get_window_rect_internal(hwnd)?;
    let _ = &window_rect;
    let _ = &window_rect;
    let client_rect = crate::libs::win32k::window::get_client_rect_internal(hwnd)?;
    let _ = &client_rect;
    let _ = &client_rect;

    let paint_struct = PAINTSTRUCT {
        hdc,
        fErase: true, // Assume background needs erasing
        rcPaint_left: client_rect.left,
        rcPaint_top: client_rect.top,
        rcPaint_right: client_rect.right,
        rcPaint_bottom: client_rect.bottom,
        fRestore: false,
        fIncUpdate: false,
        rgbReserved: [0; 32],
    };
    let _ = &paint_struct;

    // kprintln!("[win32k] BeginPaint: hdc={:#x}, rect=({},{})-({},{})",  // kprintln disabled (memcpy crash workaround)
//         hdc, client_rect.left, client_rect.top, client_rect.right, client_rect.bottom);

    Some(BeginPaintResult { hdc, paint_struct })
}

/// EndPaint - End a paint operation.
/// Releases the DC and validates the update region.
pub fn end_paint(hwnd: u64, hdc: u64) -> bool {
    // kprintln!("[win32k] EndPaint: hwnd={:#x}, hdc={:#x}", hwnd, hdc)  // kprintln disabled (memcpy crash workaround);

    // Release the DC
    let _ = crate::libs::win32k::dc::GreDeleteDC(hdc);

    // Mark update region as validated
    let mut wm = crate::libs::win32k::window::WINDOW_MANAGER.lock();
    if let Some(window) = wm.get_window_mut(hwnd) {
        window.dirty = false;
        window.dirty_rects.clear();
    }

    true
}

// =============================================================================
// InvalidateRect / ValidateRect
// =============================================================================

/// InvalidateRect - Add a rectangle to the update region.
/// Causes WM_PAINT to be posted.
pub fn invalidate_rect(hwnd: u64, rect: Option<crate::libs::win32k::window::Rect>, erase: bool) -> bool {
    // kprintln!("[win32k] InvalidateRect: hwnd={:#x}, rect={:?}, erase={}",  // kprintln disabled (memcpy crash workaround)
//         hwnd, rect, erase);

    // Add the rectangle to the window's dirty list
    crate::libs::win32k::window::invalidate_rect_internal(hwnd, rect);

    // If erase is requested, mark for background erase
    if erase {
        // Would set a flag to erase background in WM_PAINT
    }

    // Post WM_PAINT if not already posted
    crate::libs::win32k::message::post_message(hwnd, 0x000F, 0, 0);

    true
}

/// ValidateRect - Remove a rectangle from the update region.
/// Prevents WM_PAINT from being generated for this area.
pub fn validate_rect(hwnd: u64, rect: Option<crate::libs::win32k::window::Rect>) -> bool {
    // kprintln!("[win32k] ValidateRect: hwnd={:#x}, rect={:?}", hwnd, rect)  // kprintln disabled (memcpy crash workaround);

    // In a full implementation, this would remove the rect from the update region
    // For now, just mark the window as not dirty
    if rect.is_none() {
        // Validate entire window
        let mut wm = crate::libs::win32k::window::WINDOW_MANAGER.lock();
        if let Some(window) = wm.get_window_mut(hwnd) {
            window.dirty = false;
            window.dirty_rects.clear();
        }
    }

    true
}

// =============================================================================
// RedrawWindow / UpdateWindow
// =============================================================================

/// UpdateWindow - Send WM_PAINT directly to a window.
/// Unlike InvalidateRect, this sends WM_PAINT immediately.
pub fn update_window(hwnd: u64) -> bool {
    // kprintln!("[win32k] UpdateWindow: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
    crate::libs::win32k::window::update_window_internal(hwnd)
}

/// RedrawWindow - Redraw all or part of a window.
/// More powerful than InvalidateRect.
pub fn redraw_window(
    hwnd: u64,
    rect: Option<crate::libs::win32k::window::Rect>,
    rgn: u64,
    flags: u32,
) -> bool {
    let _ = (hwnd, rect, rgn, flags);
    // kprintln!("[win32k] RedrawWindow: hwnd={:#x}, flags={:#x}", hwnd, flags)  // kprintln disabled (memcpy crash workaround);

    let flags = UpdateRegionFlags::new(flags);

    let _ = &flags;
    let _ = &flags;

    if flags.contains(UpdateRegionFlags::RDW_INVALIDATE) {
        invalidate_rect(hwnd, rect, flags.contains(UpdateRegionFlags::RDW_ERASE));
    }

    if flags.contains(UpdateRegionFlags::RDW_VALIDATE) {
        validate_rect(hwnd, rect);
    }

    if flags.contains(UpdateRegionFlags::RDW_UPDATENOW) {
        update_window(hwnd);
    }

    if flags.contains(UpdateRegionFlags::RDW_ERASENOW) {
        // Would send WM_ERASEBKGND
    }

    true
}

use crate::libs::win32k::window::Rect;

// =============================================================================
// Coordinate Conversion Helpers
// =============================================================================

/// Convert client coordinates to screen coordinates
pub fn client_to_screen(hwnd: u64, point: &mut POINT) -> bool {
    if let Some(client_rect) = crate::libs::win32k::window::get_window_rect_internal(hwnd) {
        point.x += client_rect.left;
        point.y += client_rect.top;
        // kprintln!("[win32k] ClientToScreen: hwnd={:#x}, ({},{}) -> ({},{})",  // kprintln disabled (memcpy crash workaround)
//             hwnd, point.x - client_rect.left, point.y - client_rect.top, point.x, point.y);
        true
    } else {
        false
    }
}

/// Convert screen coordinates to client coordinates
pub fn screen_to_client(hwnd: u64, point: &mut POINT) -> bool {
    if let Some(client_rect) = crate::libs::win32k::window::get_window_rect_internal(hwnd) {
        point.x -= client_rect.left;
        point.y -= client_rect.top;
        // kprintln!("[win32k] ScreenToClient: hwnd={:#x}, ({},{}) -> ({},{})",  // kprintln disabled (memcpy crash workaround)
//             hwnd, point.x + client_rect.left, point.y + client_rect.top, point.x, point.y);
        true
    } else {
        false
    }
}

/// Map window coordinates to screen coordinates
pub fn map_window_points(hwnd_src: u64, hwnd_dst: u64, points: &mut [POINT]) -> bool {
    // Get source window position
    let src_rect = match crate::libs::win32k::window::get_window_rect_internal(hwnd_src) {
        Some(r) => r,
        None => return false,
    };
    let _ = &src_rect;

    // Get destination window position
    let _dst_rect = match crate::libs::win32k::window::get_window_rect_internal(hwnd_dst) {
        Some(r) => r,
        None => return false,
    };
    let _ = &_dst_rect;

    // Transform from source to screen, then to destination
    for point in points.iter_mut() {
        point.x += src_rect.left;
        point.y += src_rect.top;
        // Then subtract destination rect (not implemented)
    }

    true
}

// =============================================================================
// FillRect helper
// =============================================================================

/// Fill a rectangle with a brush.
/// Common helper used by WM_ERASEBKGND and other handlers.
pub fn fill_rect(hdc: u64, rect: &Rect, hbr: u64) -> i32 {
    // kprintln!("[win32k] FillRect: hdc={:#x}, rect={:?}, hbr={:#x}",  // kprintln disabled (memcpy crash workaround)
//         hdc, rect, hbr);

    // Get the brush color/style
    if hbr == 0 {
        // Stock NULL_BRUSH
        return 0;
    }

    // Fill the rectangle
    if let Some(mut dc) = crate::libs::win32k::dc::get_dc(hdc) {
        let _ = crate::libs::win32k::gdi_ops::GreRectangle(
            &mut dc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
        );
        1
    } else {
        0
    }
}

/// Get the system background brush for a window class
pub fn get_class_long_ptr(hwnd: u64, index: i32) -> u64 {
    let _ = hwnd;
    // In a full implementation, look up the window class
    match index {
        -16 => 0, // GCLP_HBRBACKGROUND
        -12 => 0, // GCLP_HCURSOR
        -14 => 0, // GCLP_HICON
        -24 => 0, // GCLP_WNDPROC
        _ => 0,
    }
}
