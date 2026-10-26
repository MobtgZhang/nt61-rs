//! win32k.sys — Windows Subsystem Kernel Driver
//
//! win32k.sys is the kernel-mode part of the Win32 subsystem. It provides:
//!   - GDI (Graphics Device Interface) functions
//!   - USER (Window/Input Management) functions
//!   - Graphics rendering via GDI handles
//!   - Window management and message processing
//
//! This is the bridge between the user-mode Win32 API (kernel32, gdi32, user32)
//! and the kernel graphics subsystem.
//
//! ## Architecture
//
//! ```text
//! user32.dll/gdi32.dll
//!      |
//!      v
//! win32k.sys (kernel-mode)
//!      |
//!      +-- GDI handles (pens, brushes, bitmaps, DCs)
//!      +-- USER handles (windows, menus, classes)
//!      +-- Graphics engine (Eng* functions)
//!      +-- Display drivers (video miniport)
//! ```
//
//! ## Logging Convention
//
//! All `kprintln!` calls use a consistent format:
//
//! | Component | Format | Example |
//! |-----------|--------|---------|
//! | Win32k module | `[win32k]` | `[win32k] CreateWindow: hwnd=0x100` |
//! | GDI sub-system | `[win32k GDI]` | `[win32k GDI] create_pen: ...` |
//! | USER sub-system | `[win32k USER]` | `[win32k USER] CreateWindow: ...` |
//! | Message queue | `[msgq]` | `[msgq] PostMessage: msg=0x0100` |
//
//! All handles are printed as hex: `0x{:016x}`
//! All colors are printed as hex: `0x{:08x}`
//! Status indicators: `[OK]`, `[FAIL]`, `[DEBUG]`
//
//! ## Module Structure
//
//! - `objects.rs` - GDI object management (pens, brushes, fonts, bitmaps, regions)
//! - `dc.rs` - Device Context management
//! - `surface.rs` - Surface/bitmap management
//! - `gdi_ops.rs` - GDI operations (bit_blt, fill_rect, etc.)
//! - `text.rs` - Text rendering with fonts
//! - `region.rs` - Region and clipping operations
//! - `syscall.rs` - Shadow SSDT syscall handlers

extern crate alloc;

use alloc::vec::Vec;

// Submodules
pub mod clipboard;
pub mod dc;
pub mod gdi_ops;
pub mod message;
pub mod objects;
pub mod paint;
pub mod region;
pub mod surface;
pub mod syscall;
pub mod text;
pub mod user_state;
pub mod window;

/// win32k.sys version
pub const WIN32K_VERSION: u32 = 0x0601_0001;

/// GDI handle types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdiHandleType {
    DC = 1,
    Bitmap = 2,
    Palette = 3,
    Font = 4,
    Pen = 5,
    ExtPen = 6,
    Brushed = 7,
    Region = 8,
    Metafile = 9,
    MetafileDC = 10,
    EnhancedMetafileDC = 11,
}

/// USER handle types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserHandleType {
    Window = 1,
    Menu = 2,
    Cursor = 3,
    Class = 4,
    Desktop = 5,
    Hook = 6,
    DataTable = 7,
    Process = 8,
    Thread = 9,
    Task = 10,
    InputMethod = 11,
    Timer = 12,
    Icon = 13,
}

/// GDI handle entry
#[repr(C)]
pub struct GdiHandleEntry {
    pub handle_type: u8,
    pub flags: u8,
    pub process_id: u32,
    pub thread_id: u32,
    pub kernel_address: u64,
}

impl GdiHandleEntry {
    pub fn new(htype: GdiHandleType, pid: u32, tid: u32) -> Self {
        let _ = (&htype, &pid, &tid);

        Self {
            handle_type: htype as u8,
            flags: 0,
            process_id: pid,
            thread_id: tid,
            kernel_address: 0,
        }
    }
}

/// USER handle entry
#[repr(C)]
pub struct UserHandleEntry {
    pub handle_type: u8,
    pub flags: u8,
    pub process_id: u32,
    pub thread_id: u32,
    pub kernel_address: u64,
}

impl UserHandleEntry {
    pub fn new(htype: UserHandleType, pid: u32, tid: u32) -> Self {
        let _ = (&htype, &pid, &tid);

        Self {
            handle_type: htype as u8,
            flags: 0,
            process_id: pid,
            thread_id: tid,
            kernel_address: 0,
        }
    }
}

// =============================================================================
// GDI Subsystem (Graphics Device Interface)
// =============================================================================

/// Device Context (DC) state
#[derive(Debug, Clone, Copy)]
pub struct DCState {
    /// DC type (DC, memDC, etc.)
    pub dc_type: GdiHandleType,
    /// Surface/bitmap associated with this DC
    pub surface: u64,
    /// Clipping region
    pub clip_region: u64,
    /// Current pen
    pub pen: u64,
    /// Current brush
    pub brush: u64,
    /// Current palette
    pub palette: u64,
    /// Current font
    pub font: u64,
    /// Background color (BGR)
    pub background_color: u32,
    /// Text color (BGR)
    pub text_color: u32,
    /// ROP (Raster Operation) mode
    pub rop_mode: u32,
    /// Stretch mode
    pub stretch_mode: u32,
}

impl DCState {
    pub fn new() -> Self {
        Self {
            dc_type: GdiHandleType::DC,
            surface: 0,
            clip_region: 0,
            pen: 0,
            brush: 0,
            palette: 0,
            font: 0,
            background_color: 0x00FFFFFF, // White
            text_color: 0x00000000,       // Black
            rop_mode: 0xCC,               // SRCCOPY
            stretch_mode: 0,              // BLACKONWHITE
        }
    }
}

/// Bitmap info header (BITMAPINFOHEADER)
#[repr(C)]
pub struct BitmapInfoHeader {
    pub size: u32,
    pub width: i32,
    pub height: i32,
    pub planes: u16,
    pub bit_count: u16,
    pub compression: u32,
    pub image_size: u32,
    pub x_pels_per_meter: i32,
    pub y_pels_per_meter: i32,
    pub colors_used: u32,
    pub colors_important: u32,
}

impl BitmapInfoHeader {
    pub fn new(width: i32, height: i32, bit_count: u16) -> Self {
        let _ = (&width, &height, &bit_count);

        Self {
            size: 40,
            width,
            height,
            planes: 1,
            bit_count,
            compression: 0, // BI_RGB
            image_size: ((width.abs() * height.abs() * bit_count as i32) / 8) as u32,
            x_pels_per_meter: 0,
            y_pels_per_meter: 0,
            colors_used: 0,
            colors_important: 0,
        }
    }
}

/// Palette entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PaletteEntry {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
    pub flags: u8,
}

// =============================================================================
// USER Subsystem (Window/Input Management)
// =============================================================================

/// Window message types - re-exported from window.rs
pub use crate::libs::win32k::window::WindowMessage;

/// Window class styles
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum WindowClassStyle {
    VREDRAW = 0x0001,
    HREDRAW = 0x0002,
    OWNDC = 0x0020,
    CLASSDCE = 0x0040,
    PARENTDC = 0x0080,
    NOKEYBOARD = 0x0100,
    NESTEDATAPIC = 0x0200,
    GLOBALCLASS = 0x0400,
}

/// Window styles
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum WindowStyle {
    OVERLAPPED = 0x00000000,
    POPUP = 0x80000000,
    CHILD = 0x40000000,
    MINIMIZE = 0x20000000,
    VISIBLE = 0x10000000,
    DISABLED = 0x08000000,
    CLIPSIBLINGS = 0x04000000,
    CLIPCHILDREN = 0x02000000,
    MAXIMIZE = 0x01000000,
    CAPTION = 0x00C00000,
    SYSMENU = 0x00080000,
    THICKFRAME = 0x00040000,
    MINIMIZEBOX = 0x00020000,
    MAXIMIZEBOX = 0x00010000,
}

/// Window info
#[derive(Debug, Clone, Copy)]
pub struct WindowInfo {
    pub handle: u64,
    pub parent: u64,
    pub owner: u64,
    pub style: u32,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub client_x: i32,
    pub client_y: i32,
    pub client_width: i32,
    pub client_height: i32,
}

impl WindowInfo {
    pub fn new(hwnd: u64) -> Self {
        let _ = (&hwnd,);

        Self {
            handle: hwnd,
            parent: 0,
            owner: 0,
            style: 0,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            client_x: 0,
            client_y: 0,
            client_width: 800,
            client_height: 600,
        }
    }
}

/// Window class info
#[derive(Debug, Clone, Copy)]
pub struct WindowClass {
    pub name: [u16; 256],
    pub style: u32,
    pub proc: u64,
    pub instance: u64,
    pub background: u64,
    pub cursor: u64,
    pub icon: u64,
}

impl WindowClass {
    pub fn new() -> Self {
        Self {
            name: [0; 256],
            style: 0,
            proc: 0,
            instance: 0,
            background: 0,
            cursor: 0,
            icon: 0,
        }
    }
}

// =============================================================================
// Graphics Engine (Eng* functions)
// =============================================================================

/// Surface description
#[repr(C)]
pub struct EngSurface {
    pub width: i32,
    pub height: i32,
    pub format: u32,
    pub pitch: i32,
    pub bits: *mut u8,
}

impl EngSurface {
    pub fn new(width: i32, height: i32, format: u32) -> Self {
        let _ = (&width, &height, &format);

        let pitch = (width + 3) & !3; // 4-byte aligned
        let _ = &pitch;
        Self {
            width,
            height,
            format,
            pitch,
            bits: core::ptr::null_mut(),
        }
    }
}

/// Driver functions table (DRIVERFN)
pub struct DriverFunctions {
    pub version: u32,
    pub caps: u32,
}

// =============================================================================
// Initialization
// =============================================================================

static WIN32K_INITIALIZED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Initialize win32k.sys
pub fn init() {
    // kprintln!("    [win32k] Initializing win32k.sys...");
    // kprintln!("      version: 0x{:08x}", WIN32K_VERSION);

    // Initialize surface management (primary framebuffer)
    surface::init_primary_surface();
    // kprintln!("      Surface management initialized");

    // Initialize GDI objects
    objects::init_stock_objects();
    // kprintln!("      Stock GDI objects initialized");

    // Initialize display driver
    surface::drv_enable_driver();
    // kprintln!("      Display driver enabled");

    // Initialize window management
    window::init();
    // kprintln!("      Window manager initialized");

    // Message queue subsystem uses thread-local initialization
    // kprintln!("      Message queue subsystem ready");

    // Register Shadow SSDT services (using correct masked indices)
    unsafe { crate::ke::shadow_ssdt::init_shadow_services() };

    // kprintln!("      Shadow SSDT services registered");
    // kprintln!("    [win32k] win32k.sys ready");
    WIN32K_INITIALIZED.store(true, core::sync::atomic::Ordering::SeqCst);
}

/// Check if win32k is initialized
pub fn is_initialized() -> bool {
    WIN32K_INITIALIZED.load(core::sync::atomic::Ordering::SeqCst)
}

// =============================================================================
// GDI Functions
// =============================================================================

/// create a device context
pub fn create_dc() -> Option<DCState> {
    let mut dc = DCState::new();
    dc.dc_type = GdiHandleType::DC;
    Some(dc)
}

/// create a compatible DC
pub fn create_compatible_dc() -> Option<DCState> {
    let mut dc = DCState::new();
    dc.dc_type = GdiHandleType::EnhancedMetafileDC;
    Some(dc)
}

/// Delete a DC
pub fn delete_dc(dc: &DCState) -> bool {
    let _ = (&dc,);

    // In a full implementation, this would free DC resources
    true
}

// =============================================================================
// GDI Object Management (Simplified for Bootstrap)
// =============================================================================

/// Allocate a GDI handle (simplified)
pub fn allocate_gdi_handle(htype: GdiHandleType, pid: u32) -> u64 {
    let _ = (&htype, &pid);

    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(0x4000_0000);

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let _ = &handle;
    // kprintln!("[win32k] Allocated GDI handle 0x{:x} type={:?} pid={}", handle, htype, pid);
    handle
}

/// Free a GDI handle (simplified)
pub fn free_gdi_handle(handle: u64) -> bool {
    let _ = (&handle,);

    // kprintln!("[win32k] Freed GDI handle 0x{:x}", handle);
    true
}

// =============================================================================
// Bitmap Functions
// =============================================================================

/// create a bitmap
pub fn create_bitmap_info(width: i32, height: i32, bit_count: u16) -> BitmapInfoHeader {
    let _ = (&width, &height, &bit_count);

    BitmapInfoHeader::new(width, height, bit_count)
}

// =============================================================================
// Pen Functions
// =============================================================================

/// Pen styles
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum PenStyle {
    Solid = 0,
    Dash = 1,
    Dot = 2,
    DashDot = 3,
    DashDotDot = 4,
}

/// create a pen
pub fn create_pen(style: PenStyle, width: i32, color: u32) -> bool {
    let _ = (&style, &width, &color);

    // kprintln!("[win32k] create_pen style={:?} width={} color=0x{:08x}", style, width, color);
    true
}

/// Select a pen into DC
pub fn select_pen(dc: &mut DCState, pen: u64) -> u64 {
    let _ = (&dc, &pen);

    let old_pen = dc.pen;
    let _ = &old_pen;
    dc.pen = pen;
    old_pen
}

// =============================================================================
// Brush Functions
// =============================================================================

/// Hatch styles
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum HatchStyle {
    Horizontal = 0,
    Vertical = 1,
    FDiagonal = 2,
    BDiagonal = 3,
    Cross = 4,
    DiagonalCross = 5,
}

/// create a solid brush
pub fn create_solid_brush(color: u32) -> bool {
    let _ = (&color,);

    // kprintln!("[win32k] create_solid_brush color=0x{:08x}", color);
    true
}

/// create a hatched brush
pub fn create_hatch_brush(style: HatchStyle, color: u32) -> bool {
    let _ = (&style, &color);

    // kprintln!("[win32k] create_hatch_brush style={:?} color=0x{:08x}", style, color);
    true
}

/// Select a brush into DC
pub fn select_brush(dc: &mut DCState, brush: u64) -> u64 {
    let _ = (&dc, &brush);

    let old_brush = dc.brush;
    let _ = &old_brush;
    dc.brush = brush;
    old_brush
}

// =============================================================================
// Surface Functions
// =============================================================================

/// Allocate a surface (bitmap buffer)
pub fn allocate_surface(width: i32, height: i32, format: u32) -> Option<EngSurface> {
    let _ = (&width, &height, &format);

    let mut surface = EngSurface::new(width, height, format);
    let pitch = (width + 3) & !3;
    let _ = &pitch;
    let size = (pitch * height.abs()) as usize;
    let _ = &size;

    // Allocate buffer from pool
    let buffer = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, size);

    if buffer.is_null() {
        return None;
    }

    surface.bits = buffer;
    surface.pitch = pitch;

    // kprintln!("[win32k] Allocated surface {}x{} format=0x{:x}", width, height, format);
    Some(surface)
}

/// Free a surface
pub fn free_surface(surface: &EngSurface) {
    let _ = (&surface,);

    if !surface.bits.is_null() {
        let _ = crate::mm::pool::free(surface.bits);
    }
}

/// Copy bits between surfaces (Eng* style)
pub fn eng_bit_blt(
    dst_surface: &EngSurface,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_surface: &EngSurface,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {
    let _ = (
        &dst_surface,
        &dst_x,
        &dst_y,
        &width,
        &height,
        &src_surface,
        &src_x,
        &src_y,
        &rop,
    );

    if dst_surface.bits.is_null() || src_surface.bits.is_null() {
        return false;
    }

    let dst_pitch = dst_surface.pitch;
    let _ = &dst_pitch;
    let src_pitch = src_surface.pitch;
    let _ = &src_pitch;

    for y in 0..height {
        let dst_row = unsafe { dst_surface.bits.add(((dst_y + y) * dst_pitch) as usize) };
        let _ = &dst_row;
        let src_row = unsafe { src_surface.bits.add(((src_y + y) * src_pitch) as usize) };
        let _ = &src_row;

        unsafe {
            core::ptr::copy_nonoverlapping(
                src_row.add(src_x as usize),
                dst_row.add(dst_x as usize),
                width as usize,
            );
        }
    }

    // kprintln!("[win32k] EngBitBlt surface {}x{} from ({},{}) to ({},{}) rop=0x{:08x}",
    //         width, height, src_x, src_y, dst_x, dst_y, rop);
    true
}

/// create a bitmap info structure
pub fn create_bitmap(width: i32, height: i32, bit_count: u16) -> Option<BitmapInfoHeader> {
    let _ = (&width, &height, &bit_count);

    if width <= 0 || height == 0 {
        return None;
    }
    Some(BitmapInfoHeader::new(width, height, bit_count))
}

// =============================================================================
// USER Functions
// =============================================================================

/// create a window
pub fn create_window(
    class_name: &[u16],
    title: &[u16],
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> WindowInfo {
    let _ = (&class_name, &title, &x, &y, &width, &height);

    let mut info = WindowInfo::new(0);
    info.x = x;
    info.y = y;
    info.width = width;
    info.height = height;
    info.client_width = width;
    info.client_height = height;
    info.style = WindowStyle::CAPTION as u32
        | WindowStyle::THICKFRAME as u32
        | WindowStyle::MINIMIZEBOX as u32
        | WindowStyle::MAXIMIZEBOX as u32;
    info
}

// =============================================================================
// Smoke Test
// =============================================================================

/// Run win32k.sys smoke test
pub fn smoke_test() -> bool {
    let mut all_ok = true;

    // kprintln!("    [win32k SMOKE] Testing GDI subsystem...");

    // Test DC creation
    let dc = create_dc();
    let _ = &dc;
    if dc.is_some() {
        // kprintln!("      [OK] CreateDC");
    } else {
        // kprintln!("      [FAIL] CreateDC");
        all_ok = false;
    }

    // Test CompatibleDC creation
    let comp_dc = create_compatible_dc();
    let _ = &comp_dc;
    if comp_dc.is_some() {
        // kprintln!("      [OK] create_compatible_dc");
    } else {
        // kprintln!("      [FAIL] create_compatible_dc");
        all_ok = false;
    }

    // Test bitmap creation
    let _bitmap = create_bitmap_info(800, 600, 32);
    let _ = &_bitmap;
    // kprintln!("      [OK] CreateBitmapInfo");

    // Test surface allocation
    let surface = allocate_surface(640, 480, 0x263);
    let _ = &surface;
    if surface.is_some() {
        // kprintln!("      [OK] AllocateSurface");
        // Free the surface
        if let Some(s) = surface {
            free_surface(&s);
            // kprintln!("      [OK] FreeSurface");
        }
    } else {
        // kprintln!("      [FAIL] AllocateSurface");
        all_ok = false;
    }

    // Test surface operations
    let test_surface = allocate_surface(100, 100, 0x263);
    let _ = &test_surface;
    if let Some(ref surf) = test_surface {
        // Clear surface
        clear_surface(surf, 0x00000000);
        // kprintln!("      [OK] ClearSurface");

        // Fill rectangle
        fill_rect_solid(surf, 10, 10, 90, 90, 0x00FF0000);
        // kprintln!("      [OK] FillRectSolid");

        // Draw line
        draw_line_bresenham(surf, 0, 0, 99, 99, 0x0000FF00);
        // kprintln!("      [OK] DrawLineBresenham");

        // Draw ellipse
        draw_ellipse(surf, 50, 50, 30, 20, 0x000000FF);
        // kprintln!("      [OK] DrawEllipse");

        // Test get/set pixel
        set_pixel_on_surface(surf, 5, 5, 0x00FF00FF);
        if let Some(pixel) = get_pixel_from_surface(surf, 5, 5) {
            if pixel == 0x00FF00FF {
                // kprintln!("      [OK] GetSetPixel");
            } else {
                // kprintln!("      [FAIL] GetSetPixel (got 0x{:08x})", pixel);
            }
        }

        // Test text rendering
        draw_text(surf, 5, 5, b"Hello", 0x00FFFFFF, 0x00000000);
        // kprintln!("      [OK] DrawText");

        // Free the surface
        free_surface(surf);
    }

    // Test GDI handle allocation
    let handle = allocate_gdi_handle(GdiHandleType::DC, 0);
    let _ = &handle;
    if handle != 0 {
        // kprintln!("      [OK] AllocateGdiHandle");
        free_gdi_handle(handle);
        // kprintln!("      [OK] FreeGdiHandle");
    } else {
        // kprintln!("      [FAIL] AllocateGdiHandle");
        all_ok = false;
    }

    // Test hatch brush
    let _ = create_hatch_brush(HatchStyle::Cross, 0x00FF00);
    // kprintln!("      [OK] create_hatch_brush");

    // kprintln!("    [win32k SMOKE] Testing USER subsystem...");

    // Test window creation
    let window = create_window(&[0u16, 0], &[0u16, 0], 100, 100, 640, 480);
    let _ = &window;
    if window.width == 640 && window.height == 480 {
        // kprintln!("      [OK] CreateWindow");
    } else {
        // kprintln!("      [FAIL] CreateWindow");
        all_ok = false;
    }

    // Test ROP operations
    let _ = apply_rop(0x12345678, 0xABCDEF00, RasterOp::SRCCOPY as u32);
    // kprintln!("      [OK] RasterOps");

    if all_ok {
        // kprintln!("    [win32k SMOKE] ALL PASSED");
    } else {
        // kprintln!("    [win32k SMOKE] SOME FAILED");
    }

    all_ok
}

// =============================================================================
// Graphics Engine Functions (Eng*)
// =============================================================================

/// Graphics engine function table.
pub struct GraphicsEngine {
    pub version: u32,
}

impl GraphicsEngine {
    pub fn new() -> Self {
        Self {
            version: WIN32K_VERSION,
        }
    }
}

/// Line drawing mode.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum LineMode {
    Solid = 0,
    Dash = 1,
    Dot = 2,
    DashDot = 3,
    DashDotDot = 4,
}

/// Point structure for graphics operations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

/// Rectangle structure - unified from objects.rs
pub use crate::libs::win32k::objects::Rect;

/// Draw a line between two points.
pub fn draw_line(dc: u64, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) {
    let _ = (&dc, &x1, &y1, &x2, &y2, &color);

    // For actual rendering, we would need the DC's associated surface
    // For now, use Bresenham line drawing directly
    // kprintln!(
    //         "[win32k] eng_line: DC=0x{:x} ({},{}) -> ({},{}) color=0x{:x}",
    //         dc, x1, y1, x2, y2, color
    //     );
    // If surface is associated with DC, draw on it
    // This is a simplified version that just logs for kernel boot testing
}

/// Draw a line on a surface
pub fn draw_line_on_surface(surface: &EngSurface, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) {
    let _ = (&surface, &x1, &y1, &x2, &y2, &color);

    draw_line_bresenham(surface, x1, y1, x2, y2, color);
}

/// Fill a rectangle.
pub fn fill_rect(dc: u64, rect: &Rect, color: u32) {
    let _ = (&dc, &rect, &color);

    // kprintln!(
    //         "[win32k] EngFillRect: DC=0x{:x} rect={:?} color=0x{:x}",
    //         dc, rect, color
    //     );
}

/// Fill a rectangle on a surface
pub fn fill_rect_on_surface(
    surface: &EngSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color: u32,
) {
    let _ = (&surface, &left, &top, &right, &bottom, &color);

    fill_rect_solid(surface, left, top, right, bottom, color);
}

/// Bit block transfer (Blt) - USER/GDI style.
pub fn bit_blt(
    dst_dc: u64,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_dc: u64,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {
    let _ = (
        &dst_dc, &dst_x, &dst_y, &width, &height, &src_dc, &src_x, &src_y, &rop,
    );

    // For actual rendering, we would look up the DC's surface
    // This is a simplified version for kernel boot testing
    // kprintln!(
    //         "[win32k] bit_blt: dst=0x{:x} ({},{}) {}x{} <- src=0x{:x} ({},{}) rop=0x{:08x}",
    //         dst_dc, dst_x, dst_y, width, height, src_dc, src_x, src_y, rop
    //     );
    true
}

/// bit_blt with surface pointers (internal use)
pub fn bit_blt_surfaces(
    dst_surface: &EngSurface,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_surface: &EngSurface,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {
    let _ = (
        &dst_surface,
        &dst_x,
        &dst_y,
        &width,
        &height,
        &src_surface,
        &src_x,
        &src_y,
        &rop,
    );

    bit_blt_with_rop(
        dst_surface,
        dst_x,
        dst_y,
        width,
        height,
        src_surface,
        src_x,
        src_y,
        rop,
    )
}

/// Stretch blt.
pub fn stretch_blt(dst_dc: u64, dst_rect: &Rect, src_dc: u64, src_rect: &Rect, rop: u32) -> bool {
    let _ = (&dst_dc, &dst_rect, &src_dc, &src_rect, &rop);

    // kprintln!(
    //         "[win32k] EngStretchBlt: dst=0x{:x} {:?} <- src=0x{:x} {:?} rop=0x{:x}",
    //         dst_dc, dst_rect, src_dc, src_rect, rop
    //     );
    true
}

/// PlgBlt (parallelogram block transfer).
pub fn plg_blt(
    dst_dc: u64,
    dst_points: &[Point; 3],
    src_dc: u64,
    src_rect: &Rect,
    rop: u32,
) -> bool {
    let _ = (&dst_dc, &dst_points, &src_dc, &src_rect, &rop);

    // kprintln!(
    //         "[win32k] EngPlgBlt: dst=0x{:x} <- src=0x{:x} rop=0x{:x}",
    //         dst_dc, src_dc, rop
    //     );
    true
}

/// Text out.
pub fn text_out(dc: u64, x: i32, y: i32, text: &[u16]) {
    let _ = (&dc, &x, &y, &text);

    // kprintln!(
    //         "[win32k] EngTextOut: DC=0x{:x} ({},{}) text_len={}",
    //         dc, x, y, text.len()
    //     );
}

// =============================================================================
// Pixel Operations
// =============================================================================

/// Pixel format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    Indexed1 = 1,
    Indexed4 = 4,
    Indexed8 = 8,
    Rgb16 = 16,
    Rgb24 = 24,
    Rgb32 = 32,
}

/// Convert RGB to BGR (Windows color format)
#[inline(always)]
pub fn rgb_to_bgr(r: u8, g: u8, b: u8) -> u32 {
    let _ = (&r, &g, &b);

    ((b as u32) << 16) | ((g as u32) << 8) | (r as u32)
}

/// Get pixel from surface at (x, y)
pub fn get_pixel_from_surface(surface: &EngSurface, x: i32, y: i32) -> Option<u32> {
    let _ = (&surface, &x, &y);

    if surface.bits.is_null() {
        return None;
    }
    if x < 0 || x >= surface.width || y < 0 || y >= surface.height {
        return None;
    }

    let offset = (y * surface.pitch + x * 4) as isize;
    let _ = &offset;
    unsafe {
        let pixel = *(surface.bits.offset(offset) as *const u32);
        let _ = &pixel;
        Some(pixel)
    }
}

/// Set pixel on surface at (x, y)
pub fn set_pixel_on_surface(surface: &EngSurface, x: i32, y: i32, color: u32) -> bool {
    let _ = (&surface, &x, &y, &color);

    if surface.bits.is_null() {
        return false;
    }
    if x < 0 || x >= surface.width || y < 0 || y >= surface.height {
        return false;
    }

    let offset = (y * surface.pitch + x * 4) as isize;
    let _ = &offset;
    unsafe {
        *(surface.bits.offset(offset) as *mut u32) = color;
    }
    true
}

/// Clear surface to a solid color
pub fn clear_surface(surface: &EngSurface, color: u32) {
    let _ = (&surface, &color);

    if surface.bits.is_null() {
        return;
    }

    let size = (surface.pitch * surface.height.abs()) as usize;
    let _ = &size;
    let color_bytes = color.to_le_bytes();
    let _ = &color_bytes;

    unsafe {
        let mut i = 0usize;
        // Fill 4 bytes at a time for efficiency
        while i + 4 <= size {
            core::ptr::write_unaligned(surface.bits.add(i) as *mut u32, color);
            i += 4;
        }
        // handle remaining bytes
        while i < size {
            core::ptr::write(surface.bits.add(i), color_bytes[i % 4]);
            i += 1;
        }
    }
}

/// Copy rectangle from source to destination surface
pub fn copy_rect(
    dst_surface: &EngSurface,
    dst_x: i32,
    dst_y: i32,
    src_surface: &EngSurface,
    src_x: i32,
    src_y: i32,
    width: i32,
    height: i32,
) -> bool {
    let _ = (
        &dst_surface,
        &dst_x,
        &dst_y,
        &src_surface,
        &src_x,
        &src_y,
        &width,
        &height,
    );

    if dst_surface.bits.is_null() || src_surface.bits.is_null() {
        return false;
    }

    let dst_pitch = dst_surface.pitch;
    let _ = &dst_pitch;
    let src_pitch = src_surface.pitch;
    let _ = &src_pitch;

    for y in 0..height {
        let dst_row_ptr = unsafe { dst_surface.bits.add(((dst_y + y) * dst_pitch) as usize) };
        let _ = &dst_row_ptr;
        let src_row_ptr = unsafe { src_surface.bits.add(((src_y + y) * src_pitch) as usize) };
        let _ = &src_row_ptr;

        unsafe {
            core::ptr::copy_nonoverlapping(
                src_row_ptr.add((src_x * 4) as usize),
                dst_row_ptr.add((dst_x * 4) as usize),
                (width * 4) as usize,
            );
        }
    }
    true
}

// =============================================================================
// Raster Operations (ROP)
// =============================================================================

/// Raster operation codes
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum RasterOp {
    SRCCOPY = 0x00CC0020,   // dest = source
    SRCPAINT = 0x00EE0086,  // dest = source OR dest
    SRCAND = 0x008800C6,    // dest = source AND dest
    SRCINVERT = 0x00660046, // dest = source XOR dest
    DSTINVERT = 0x00550009, // dest = NOT dest
    BLACKNESS = 0x00000042, // dest = BLACK
    WHITENESS = 0x00FF0062, // dest = WHITE
}

/// Apply raster operation to a single pixel
#[inline(always)]
pub fn apply_rop(pixel: u32, color: u32, rop: u32) -> u32 {
    let _ = (&pixel, &color, &rop);

    match rop {
        0x00CC0020 => color,         // SRCCOPY
        0x00EE0086 => pixel | color, // SRCPAINT
        0x008800C6 => pixel & color, // SRCAND
        0x00660046 => pixel ^ color, // SRCINVERT
        0x00550009 => !pixel,        // DSTINVERT
        0x00000042 => 0,             // BLACKNESS
        0x00FF0062 => 0x00FFFFFF,    // WHITENESS
        _ => color,                  // Default to SRCCOPY
    }
}

/// Perform bit_blt with ROP support
pub fn bit_blt_with_rop(
    dst_surface: &EngSurface,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_surface: &EngSurface,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {
    let _ = (
        &dst_surface,
        &dst_x,
        &dst_y,
        &width,
        &height,
        &src_surface,
        &src_x,
        &src_y,
        &rop,
    );

    if dst_surface.bits.is_null() {
        return false;
    }
    if !src_surface.bits.is_null() && rop == RasterOp::SRCCOPY as u32 {
        return copy_rect(
            dst_surface,
            dst_x,
            dst_y,
            src_surface,
            src_x,
            src_y,
            width,
            height,
        );
    }

    let dst_pitch = dst_surface.pitch;
    let _ = &dst_pitch;
    let src_pitch = if src_surface.bits.is_null() {
        0
    } else {
        src_surface.pitch
    };
    let _ = &src_pitch;

    for y in 0..height {
        for x in 0..width {
            let dst_offset = ((dst_y + y) * dst_pitch + (dst_x + x) * 4) as isize;
            let _ = &dst_offset;
            let dst_pixel = if src_surface.bits.is_null() {
                0
            } else {
                let src_offset = ((src_y + y) * src_pitch + (src_x + x) * 4) as isize;
                let _ = &src_offset;
                unsafe { *(src_surface.bits.offset(src_offset) as *const u32) }
            };

            let result = if src_surface.bits.is_null() {
                // For operations that don't need source (BLACKNESS, WHITENESS, DSTINVERT)
                apply_rop(0, 0, rop)
            } else {
                unsafe {
                    let current = *(dst_surface.bits.offset(dst_offset) as *const u32);
                    let _ = &current;
                    apply_rop(current, dst_pixel, rop)
                }
            };

            unsafe {
                *(dst_surface.bits.offset(dst_offset) as *mut u32) = result;
            }
        }
    }

    // kprintln!("[win32k] BitBltWithROP {}x{} from ({},{}) to ({},{}) rop=0x{:08x}",
    //         width, height, src_x, src_y, dst_x, dst_y, rop);
    true
}

// =============================================================================
// Bresenham Line Drawing Algorithm
// =============================================================================

/// Draw a line using Bresenham's algorithm
pub fn draw_line_bresenham(surface: &EngSurface, x0: i32, y0: i32, x1: i32, y1: i32, color: u32) {
    let _ = (&surface, &x0, &y0, &x1, &y1, &color);

    if surface.bits.is_null() {
        return;
    }

    let dx = (x1 - x0).abs();
    let _ = &dx;
    let dy = -(y1 - y0).abs();
    let _ = &dy;
    let sx = if x0 < x1 { 1 } else { -1 };
    let _ = &sx;
    let sy = if y0 < y1 { 1 } else { -1 };
    let _ = &sy;
    let mut err = dx + dy;
    let mut x = x0;
    let mut y = y0;

    loop {
        set_pixel_on_surface(surface, x, y, color);

        if x == x1 && y == y1 {
            break;
        }

        let e2 = 2 * err;
        let _ = &e2;
        if e2 >= dy {
            if x == x1 {
                break;
            }
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            if y == y1 {
                break;
            }
            err += dx;
            y += sy;
        }
    }
}

/// Draw anti-aliased line (Wu's algorithm - simplified)
pub fn draw_line_antialiased(surface: &EngSurface, x0: i32, y0: i32, x1: i32, y1: i32, color: u32) {
    let _ = (&surface, &x0, &y0, &x1, &y1, &color);

    // For simplicity, use Bresenham with intensity variation
    draw_line_bresenham(surface, x0, y0, x1, y1, color);
}

// =============================================================================
// Rectangle Filling
// =============================================================================

/// Fill a rectangle with a solid color
pub fn fill_rect_solid(
    surface: &EngSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color: u32,
) {
    let _ = (&surface, &left, &top, &right, &bottom, &color);

    if surface.bits.is_null() {
        return;
    }

    let pitch = surface.pitch;
    let _ = &pitch;

    // Clip to surface bounds
    let left = left.max(0);
    let _ = &left;
    let top = top.max(0);
    let _ = &top;
    let right = right.min(surface.width);
    let _ = &right;
    let bottom = bottom.min(surface.height);
    let _ = &bottom;

    if left >= right || top >= bottom {
        return;
    }

    for y in top..bottom {
        let row_ptr = unsafe { surface.bits.add((y * pitch) as usize) };
        let _ = &row_ptr;
        for x in left..right {
            unsafe {
                core::ptr::write_unaligned(row_ptr.add((x * 4) as usize) as *mut u32, color);
            }
        }
    }
}

/// Fill rectangle using brush pattern
pub fn fill_rect_with_brush(
    surface: &EngSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color: u32,
    hatch_style: HatchStyle,
) {
    let _ = (&surface, &left, &top, &right, &bottom, &color, &hatch_style);

    if surface.bits.is_null() {
        return;
    }

    let width = right - left;
    let _ = &width;
    let height = bottom - top;
    let _ = &height;

    for y in 0..height {
        for x in 0..width {
            let should_fill = match hatch_style {
                HatchStyle::Horizontal => y % 2 == 0,
                HatchStyle::Vertical => x % 2 == 0,
                HatchStyle::FDiagonal => (x + y) % 2 == 0,
                HatchStyle::BDiagonal => (x + y) % 2 == 0,
                HatchStyle::Cross => x % 2 == 0 || y % 2 == 0,
                HatchStyle::DiagonalCross => x % 2 == 0 && y % 2 == 0,
            };

            if should_fill {
                set_pixel_on_surface(surface, left + x, top + y, color);
            }
        }
    }
}

// =============================================================================
// Text Rendering (Basic Bitmap Font)
// =============================================================================

/// Simple 8x8 bitmap font data (5x7 printable ASCII characters 32-126)
/// Each character is 7 bytes (rows), bit 7 is padding
/// Data format: MSB first, each row is one byte
const FONT_DATA: &[u8] = &[
    // Space ' '
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // '!' (exclamation)
    0x18, 0x3E, 0x3E, 0x3E, 0x18, 0x00, 0x18, // '"' (quote)
    0x6C, 0x6C, 0x24, 0x00, 0x00, 0x00, 0x00, // '#'
    0x24, 0x7E, 0x24, 0x24, 0x7E, 0x24, 0x00, // '$'
    0x04, 0x2E, 0x68, 0x3C, 0x0E, 0x7B, 0x00, // '%'
    0x60, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x06, // '&'
    0x3C, 0x66, 0x3C, 0x38, 0x67, 0x66, 0x3F, // '''
    0x18, 0x18, 0x08, 0x00, 0x00, 0x00, 0x00, // '('
    0x08, 0x10, 0x20, 0x20, 0x20, 0x10, 0x08, // ')'
    0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08, // '*'
    0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, // '+'
    0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, // ','
    0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x10, // '-'
    0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, // '.'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, // '/'
    0x00, 0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, // '0'
    0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, // '1'
    0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, // '2'
    0x3C, 0x66, 0x06, 0x1C, 0x30, 0x60, 0x7E, // '3'
    0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, // '4'
    0x06, 0x0E, 0x1E, 0x66, 0x7F, 0x06, 0x06, // '5'
    0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, // '6'
    0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C, // '7'
    0x7E, 0x66, 0x0C, 0x18, 0x18, 0x18, 0x18, // '8'
    0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, // '9'
    0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, // ':'
    0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, // ';'
    0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x10, // '<'
    0x08, 0x10, 0x20, 0x40, 0x20, 0x10, 0x08, // '='
    0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, // '>'
    0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08, // '?'
    0x3C, 0x66, 0x06, 0x1C, 0x18, 0x00, 0x18, // '@'
    0x3C, 0x66, 0x6E, 0x6E, 0x60, 0x62, 0x3C, // 'A'
    0x18, 0x24, 0x42, 0x42, 0x7E, 0x42, 0x42, // 'B'
    0x7C, 0x42, 0x42, 0x7C, 0x42, 0x42, 0x7C, // 'C'
    0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, // 'D'
    0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, // 'E'
    0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, // 'F'
    0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, // 'G'
    0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3E, // 'H'
    0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, // 'I'
    0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, // 'J'
    0x1F, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, // 'K'
    0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, // 'L'
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, // 'M'
    0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, // 'N'
    0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, // 'O'
    0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, // 'P'
    0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, // 'Q'
    0x3C, 0x66, 0x66, 0x66, 0x66, 0x6F, 0x3D, // 'R'
    0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, // 'S'
    0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, // 'T'
    0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, // 'U'
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, // 'V'
    0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, // 'W'
    0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, // 'X'
    0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, // 'Y'
    0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, // 'Z'
    0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, // '['
    0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, // '\'
    0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00, // ']'
    0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, // '^'
    0x18, 0x24, 0x42, 0x00, 0x00, 0x00, 0x00, // '_'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, // 'a'
    0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, // 'b'
    0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, // 'c'
    0x00, 0x00, 0x3C, 0x66, 0x60, 0x66, 0x3C, // 'd'
    0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, // 'e'
    0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, // 'f'
    0x0C, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x18, // 'g'
    0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x3C, // 'h'
    0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, // 'i'
    0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, // 'j'
    0x0C, 0x00, 0x1C, 0x0C, 0x0C, 0x6C, 0x38, // 'k'
    0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, // 'l'
    0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, // 'm'
    0x00, 0x00, 0x6E, 0x7F, 0x6B, 0x63, 0x63, // 'n'
    0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, // 'o'
    0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, // 'p'
    0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, // 'q'
    0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06, // 'r'
    0x00, 0x00, 0x6E, 0x76, 0x60, 0x60, 0x60, // 's'
    0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, // 't'
    0x18, 0x18, 0x3C, 0x18, 0x18, 0x1A, 0x0C, // 'u'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, // 'v'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, // 'w'
    0x00, 0x00, 0x63, 0x6B, 0x7F, 0x77, 0x63, // 'x'
    0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, // 'y'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C, // 'z'
    0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, // '{'
    0x0E, 0x18, 0x18, 0x30, 0x18, 0x18, 0x0E, // '|'
    0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, // '}'
    0x70, 0x18, 0x18, 0x0C, 0x18, 0x18, 0x70, // '~'
    0x00, 0x76, 0x3C, 0x00, 0x00, 0x00, 0x00,
];

/// Number of characters in the font
const FONT_CHAR_COUNT: usize = 95;

/// Bytes per character in font data
const FONT_CHAR_SIZE: usize = 7;

/// Draw a single character using bitmap font
pub fn draw_char(surface: &EngSurface, x: i32, y: i32, ch: u8, color: u32, bg_color: u32) {
    let _ = (&surface, &x, &y, &ch, &color, &bg_color);

    if surface.bits.is_null() {
        return;
    }

    // Convert ASCII to font index (space to tilde = 0-94)
    let idx = ch.wrapping_sub(b' ') as usize;
    let _ = &idx;
    if idx >= FONT_CHAR_COUNT {
        return;
    }

    let char_base = idx * FONT_CHAR_SIZE;
    let _ = &char_base;

    for row in 0i32..8 {
        let row_data = if row < FONT_CHAR_SIZE as i32 {
            FONT_DATA[char_base + row as usize]
        } else {
            0
        };

        for col in 0i32..8 {
            let bit = (row_data >> (7 - col)) & 1;
            let _ = &bit;
            let pixel_color = if bit != 0 { color } else { bg_color };
            let _ = &pixel_color;
            set_pixel_on_surface(surface, x + col, y + row, pixel_color);
        }
    }
}

/// Draw text string
pub fn draw_text(
    surface: &EngSurface,
    x: i32,
    y: i32,
    text: &[u8],
    color: u32,
    bg_color: u32,
) -> i32 {
    let _ = (&surface, &x, &y, &text, &color, &bg_color);

    let mut cursor_x = x;

    for &ch in text {
        draw_char(surface, cursor_x, y, ch, color, bg_color);
        cursor_x += 8; // 8 pixels per character
    }

    cursor_x - x
}

// =============================================================================
// Ellipse and Circle Drawing
// =============================================================================

/// Draw an ellipse using midpoint algorithm (simplified, integer-only)
pub fn draw_ellipse(surface: &EngSurface, cx: i32, cy: i32, rx: i32, ry: i32, color: u32) {
    let _ = (&surface, &cx, &cy, &rx, &ry, &color);

    if surface.bits.is_null() || rx <= 0 || ry <= 0 {
        return;
    }

    // Simplified circle algorithm using Bresenham's method
    // For true ellipse, we'll approximate with symmetric circles
    let mut x = 0i32;
    let mut y = ry as i32;
    let mut d1 = (ry as i32) * (ry as i32) - (rx as i32) * (rx as i32) * (ry as i32)
        + ((rx as i32) * (rx as i32) / 4);

    while (ry as i32) * (ry as i32) * x <= (rx as i32) * (rx as i32) * y {
        // Draw symmetric points
        set_pixel_on_surface(surface, cx + x, cy + y, color);
        set_pixel_on_surface(surface, cx - x, cy + y, color);
        set_pixel_on_surface(surface, cx + x, cy - y, color);
        set_pixel_on_surface(surface, cx - x, cy - y, color);

        x += 1;
        if d1 < 0 {
            d1 += (ry as i32) * (ry as i32) * (2 * x + 1);
        } else {
            y -= 1;
            d1 += (ry as i32) * (ry as i32) * (2 * x + 1) - 2 * (rx as i32) * (rx as i32) * y;
        }
    }

    let mut d2 = ((ry as i32) * (ry as i32)) * ((x - 1) * (x - 1))
        + ((rx as i32) * (rx as i32)) * ((y - 1) * (y - 1))
        - ((rx as i32) * (rx as i32)) * ((ry as i32) * (ry as i32));

    while y >= 0 {
        set_pixel_on_surface(surface, cx + x, cy + y, color);
        set_pixel_on_surface(surface, cx - x, cy + y, color);
        set_pixel_on_surface(surface, cx + x, cy - y, color);
        set_pixel_on_surface(surface, cx - x, cy - y, color);

        y -= 1;
        if d2 > 0 {
            d2 += (rx as i32) * (rx as i32) - 2 * (rx as i32) * (rx as i32) * y;
        } else {
            x += 1;
            d2 += (ry as i32) * (ry as i32) * (2 * x - 1) - 2 * (rx as i32) * (rx as i32) * y;
        }
    }
}

/// Draw a circle (special case of ellipse)
pub fn draw_circle(surface: &EngSurface, cx: i32, cy: i32, r: i32, color: u32) {
    let _ = (&surface, &cx, &cy, &r, &color);

    draw_ellipse(surface, cx, cy, r, r, color);
}

// =============================================================================
// Arc and Pie Drawing (Simplified)
// =============================================================================

/// Draw a horizontal line (arc approximation)
pub fn draw_arc_horizontal(surface: &EngSurface, x1: i32, x2: i32, y: i32, color: u32) {
    let _ = (&surface, &x1, &x2, &y, &color);

    if surface.bits.is_null() {
        return;
    }
    for x in x1..=x2 {
        set_pixel_on_surface(surface, x, y, color);
    }
}

/// Draw a vertical line (arc approximation)
pub fn draw_arc_vertical(surface: &EngSurface, x: i32, y1: i32, y2: i32, color: u32) {
    let _ = (&surface, &x, &y1, &y2, &color);

    if surface.bits.is_null() {
        return;
    }
    for y in y1..=y2 {
        set_pixel_on_surface(surface, x, y, color);
    }
}

/// Fill a triangle (simple scanline fill)
pub fn fill_triangle(
    surface: &EngSurface,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    x3: i32,
    y3: i32,
    color: u32,
) {
    let _ = (&surface, &x1, &y1, &x2, &y2, &x3, &y3, &color);

    // Find bounding box
    let min_y = y1.min(y2).min(y3);
    let _ = &min_y;
    let max_y = y1.max(y2).max(y3);
    let _ = &max_y;

    for y in min_y..=max_y {
        // Find intersections with each edge
        let mut intersections = Vec::new();

        // Edge 1-2
        if let Some(x) = line_intersection_y(y, x1, y1, x2, y2) {
            intersections.push(x);
        }
        // Edge 2-3
        if let Some(x) = line_intersection_y(y, x2, y2, x3, y3) {
            intersections.push(x);
        }
        // Edge 3-1
        if let Some(x) = line_intersection_y(y, x3, y3, x1, y1) {
            intersections.push(x);
        }

        // Sort and fill between pairs
        if intersections.len() >= 2 {
            intersections.sort();
            for x in intersections[0]..=intersections[1] {
                set_pixel_on_surface(surface, x, y, color);
            }
        }
    }
}

/// Find x intersection of a line with a horizontal line at y
fn line_intersection_y(y: i32, x1: i32, y1: i32, x2: i32, y2: i32) -> Option<i32> {
    let _ = (&y, &x1, &y1, &x2, &y2);

    if y1 == y2 {
        return None; // Horizontal line
    }

    if y < y1.min(y2) || y > y1.max(y2) {
        return None;
    }

    // Linear interpolation
    let t = (y - y1) as f64 / (y2 - y1) as f64;
    let _ = &t;
    Some((x1 as f64 + t * (x2 - x1) as f64) as i32)
}

// =============================================================================
// Polygon Filling
// =============================================================================

/// Fill a polygon using scanline algorithm
pub fn fill_polygon(surface: &EngSurface, points: &[(i32, i32)], color: u32) {
    if surface.bits.is_null() || points.len() < 3 {
        return;
    }

    // Find bounding box
    let min_y = points.iter().map(|p| p.1).min().unwrap_or(0);
    let _ = &min_y;
    let max_y = points.iter().map(|p| p.1).max().unwrap_or(0);
    let _ = &max_y;

    for y in min_y..=max_y {
        let mut intersections = Vec::new();

        // Find intersections with each edge
        for i in 0..points.len() {
            let j = (i + 1) % points.len();
            let _ = &j;
            let (x1, y1) = points[i];
            let (x2, y2) = points[j];

            if let Some(x) = line_intersection_y(y, x1, y1, x2, y2) {
                intersections.push(x);
            }
        }

        // Sort intersections and fill between pairs
        if intersections.len() >= 2 {
            intersections.sort();
            let mut i = 0;
            while i + 1 < intersections.len() {
                for x in intersections[i]..=intersections[i + 1] {
                    set_pixel_on_surface(surface, x, y, color);
                }
                i += 2;
            }
        }
    }
}

// =============================================================================
// Gradient Filling
// =============================================================================

/// Fill rectangle with horizontal gradient
pub fn fill_rect_gradient_horizontal(
    surface: &EngSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color1: u32,
    color2: u32,
) {
    let _ = (&surface, &left, &top, &right, &bottom, &color1, &color2);

    if surface.bits.is_null() {
        return;
    }

    let width = right - left;
    let _ = &width;

    for y in top..bottom {
        for x in left..right {
            let t = (x - left) as f32 / width as f32;
            let _ = &t;
            let color = lerp_color(color1, color2, t);
            let _ = &color;
            set_pixel_on_surface(surface, x, y, color);
        }
    }
}

/// Fill rectangle with vertical gradient
pub fn fill_rect_gradient_vertical(
    surface: &EngSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color1: u32,
    color2: u32,
) {
    let _ = (&surface, &left, &top, &right, &bottom, &color1, &color2);

    if surface.bits.is_null() {
        return;
    }

    let height = bottom - top;
    let _ = &height;

    for y in top..bottom {
        for x in left..right {
            let t = (y - top) as f32 / height as f32;
            let _ = &t;
            let color = lerp_color(color1, color2, t);
            let _ = &color;
            set_pixel_on_surface(surface, x, y, color);
        }
    }
}

/// Linear interpolation between two colors
fn lerp_color(c1: u32, c2: u32, t: f32) -> u32 {
    let _ = (&c1, &c2, &t);

    let r1 = (c1 >> 16) & 0xFF;
    let _ = &r1;
    let g1 = (c1 >> 8) & 0xFF;
    let _ = &g1;
    let b1 = c1 & 0xFF;
    let _ = &b1;

    let r2 = (c2 >> 16) & 0xFF;
    let _ = &r2;
    let g2 = (c2 >> 8) & 0xFF;
    let _ = &g2;
    let b2 = c2 & 0xFF;
    let _ = &b2;

    let r = ((r1 as f32 + (r2 as f32 - r1 as f32) * t) as u8) as u32;
    let _ = &r;
    let g = ((g1 as f32 + (g2 as f32 - g1 as f32) * t) as u8) as u32;
    let _ = &g;
    let b = ((b1 as f32 + (b2 as f32 - b1 as f32) * t) as u8) as u32;
    let _ = &b;

    (r << 16) | (g << 8) | b
}

/// Get pixel.
pub fn get_pixel(dc: u64, x: i32, y: i32) -> u32 {
    let _ = (&dc, &x, &y);

    // kprintln!("[win32k] EngGetPixel: DC=0x{:x} ({},{})", dc, x, y);
    0
}

/// Set pixel.
pub fn set_pixel(dc: u64, x: i32, y: i32, color: u32) -> u32 {
    let _ = (&dc, &x, &y, &color);

    // kprintln!(
    //         "[win32k] EngSetPixel: DC=0x{:x} ({},{}) = 0x{:x}",
    //         dc, x, y, color
    //     );
    color
}

// =============================================================================
// Shadow SSDT Service Handlers
// =============================================================================
//
// These are the syscall handlers registered with the Shadow SSDT.
// They follow the Windows x64 calling convention and receive
// arguments via registers/stack as passed by the syscall dispatcher.

use crate::arch::common::syscall_frame::SyscallFrame;

/// GDI: get_dc handler
pub extern "C" fn gdi_get_dc_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_GDI_GET_DC called");
    0 // Return NULL DC for now
}

/// GDI: release_dc handler
pub extern "C" fn gdi_release_dc_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_GDI_RELEASE_DC called");
    1 // Return TRUE
}

/// GDI: delete_object handler
pub extern "C" fn gdi_delete_object_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_GDI_DELETE_OBJECT called");
    1 // Return TRUE
}

/// GDI: bit_blt handler
pub extern "C" fn gdi_bit_blt_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_GDI_BIT_BLT called");
    1 // Return TRUE
}

/// GDI: Rectangle handler
pub extern "C" fn gdi_rectangle_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_GDI_RECTANGLE called");
    1 // Return TRUE
}

/// USER: CreateWindow handler
pub extern "C" fn user_create_window_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NtUserCreateWindow called");
    0 // Return NULL HWND for now
}

/// USER: destroy_window handler
pub extern "C" fn user_destroy_window_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_USER_DESTROY_WINDOW called");
    1 // Return TRUE
}

/// USER: show_window handler
pub extern "C" fn user_show_window_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_USER_SHOW_WINDOW called");
    1 // Return TRUE
}

/// USER: SetWindowPos handler
pub extern "C" fn user_set_window_pos_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_USER_SET_WINDOW_POS called");
    1 // Return TRUE
}

/// USER: GetMessage handler
pub extern "C" fn user_get_message_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_USER_GET_MESSAGE called");
    0 // Return WmQuit = 0
}

/// USER: PostMessage handler
pub extern "C" fn user_post_message_handler(frame: &SyscallFrame) -> u64 {
    let _ = (&frame,);

    // kprintln!("[win32k] NT_USER_POST_MESSAGE called");
    1 // Return TRUE
}

// =============================================================================
// Menu System (P2 Enhancement)
// =============================================================================

/// Menu item type constants
pub const MFT_STRING: u32 = 0x00000000;
pub const MFT_BITMAP: u32 = 0x00000004;
pub const MFT_MENUBARBREAK: u32 = 0x00000020;
pub const MFT_MENUBREAK: u32 = 0x00000040;
pub const MFT_OWNERDRAW: u32 = 0x00000100;
pub const MFT_POPUP: u32 = 0x00000010;
pub const MFT_SEPARATOR: u32 = 0x00000800;
pub const MFT_RADIOCHECK: u32 = 0x00000002;

/// Menu item state constants
pub const MFS_GRAYED: u32 = 0x00000003;
pub const MFS_DISABLED: u32 = 0x00000003;
pub const MFS_ENABLED: u32 = 0x00000000;
pub const MFS_CHECKED: u32 = 0x00000008;
pub const MFS_UNCHECKED: u32 = 0x00000000;
pub const MFS_DEFAULT: u32 = 0x00001000;

/// Menu flags
pub const MF_BYCOMMAND: u32 = 0x00000000;
pub const MF_BYPOSITION: u32 = 0x00000400;
pub const MF_ENABLED: u32 = 0x00000000;
pub const MF_GRAYED: u32 = 0x00000001;
pub const MF_DISABLED: u32 = 0x00000002;
pub const MF_CHECKED: u32 = 0x00000008;
pub const MF_UNCHECKED: u32 = 0x00000000;
pub const MF_POPUP: u32 = 0x00000010;
pub const MF_SEPARATOR: u32 = 0x00000800;
pub const MF_STRING: u32 = 0x00000000;
pub const MF_OWNERDRAW: u32 = 0x00000100;

/// Menu item structure (simplified)
#[repr(C)]
#[derive(Clone, Debug)]
pub struct MenuItem {
    pub fmask: u32,
    pub itype: u32,
    pub state: u32,
    pub id: u32,
    pub submenu: u64,
    pub hbmp_checked: u64,
    pub hbmp_unchecked: u64,
    pub dw_item_data: u64,
    pub text: alloc::vec::Vec<u16>,
    pub hbmp_item: u64,
}

impl MenuItem {
    pub fn new() -> Self {
        Self {
            fmask: 0,
            itype: MFT_STRING,
            state: MFS_ENABLED,
            id: 0,
            submenu: 0,
            hbmp_checked: 0,
            hbmp_unchecked: 0,
            dw_item_data: 0,
            text: alloc::vec::Vec::new(),
            hbmp_item: 0,
        }
    }
}

/// Menu structure (simplified)
#[derive(Clone, Debug)]
pub struct Menu {
    pub style: u32,
    pub flags: u32,
    pub id: u32,
    pub window: u64,
    pub items: alloc::vec::Vec<MenuItem>,
    pub help_id: u32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Menu {
    pub fn new(style: u32) -> Self {
        let _ = (&style,);

        Self {
            style,
            flags: 0,
            id: 0,
            window: 0,
            items: alloc::vec::Vec::new(),
            help_id: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }
    }
}

/// Menu handle table
use core::sync::atomic::{AtomicU64, Ordering};
static MENU_NEXT_HANDLE: AtomicU64 = AtomicU64::new(0x00010000);
use core::sync::atomic::AtomicUsize;
pub static MENU_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Allocate a menu handle
pub fn allocate_menu_handle() -> u64 {
    MENU_NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

/// Get menu item count
pub fn get_menu_item_count(menu: &Menu) -> u32 {
    let _ = (&menu,);

    menu.items.len() as u32
}

/// Find menu item by position or ID
pub fn find_menu_item(menu: &Menu, id_or_pos: u32, by_position: bool) -> Option<usize> {
    let _ = (&menu, &id_or_pos, &by_position);

    if by_position {
        let pos = id_or_pos as usize;
        let _ = &pos;
        if pos < menu.items.len() {
            Some(pos)
        } else {
            None
        }
    } else {
        menu.items.iter().position(|item| item.id == id_or_pos)
    }
}

// =============================================================================
// Dialog System (P2 Enhancement)
// =============================================================================

/// Dialog constants
pub const IDOK: u32 = 1;
pub const IDCANCEL: u32 = 2;
pub const IDABORT: u32 = 3;
pub const IDRETRY: u32 = 4;
pub const IDIGNORE: u32 = 5;
pub const IDYES: u32 = 6;
pub const IDNO: u32 = 7;
pub const IDCLOSE: u32 = 8;
pub const IDHELP: u32 = 9;

/// MessageBox types
pub const MB_OK: u32 = 0x00000000;
pub const MB_OKCANCEL: u32 = 0x00000001;
pub const MB_ABORTRETRYIGNORE: u32 = 0x00000002;
pub const MB_YESNOCANCEL: u32 = 0x00000003;
pub const MB_YESNO: u32 = 0x00000004;
pub const MB_RETRYCANCEL: u32 = 0x00000005;
pub const MB_ICONHAND: u32 = 0x00000010;
pub const MB_ICONQUESTION: u32 = 0x00000020;
pub const MB_ICONEXCLAMATION: u32 = 0x00000030;
pub const MB_ICONINFORMATION: u32 = 0x00000040;

/// Dialog box template header (simplified)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlgTemplate {
    pub style: u32,
    pub dw_extended_style: u32,
    pub cdit: i16,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
}

impl DlgTemplate {
    pub fn new() -> Self {
        Self {
            style: 0,
            dw_extended_style: 0,
            cdit: 0,
            x: 0,
            y: 0,
            cx: 0,
            cy: 0,
        }
    }
}

/// Dialog structure
#[derive(Clone, Debug)]
pub struct Dialog {
    pub hwnd_owner: u64,
    pub hwnd_template: u64,
    pub instance: u64,
    pub proc: u64,
    pub data: Vec<u8>,
    pub result: i64,
}

impl Dialog {
    pub fn new() -> Self {
        Self {
            hwnd_owner: 0,
            hwnd_template: 0,
            instance: 0,
            proc: 0,
            data: Vec::new(),
            result: 0,
        }
    }
}

// =============================================================================
// Hook System (P2 Enhancement)
// =============================================================================

/// Hook type constants
pub const WH_MIN: i32 = -1;
pub const WH_MSGFILTER: i32 = -1;
pub const WH_JOURNALRECORD: i32 = 0;
pub const WH_JOURNALPLAYBACK: i32 = 1;
pub const WH_KEYBOARD: i32 = 2;
pub const WH_GETMESSAGE: i32 = 3;
pub const WH_CALLWNDPROC: i32 = 4;
pub const WH_CBT: i32 = 5;
pub const WH_SYSMSGFILTER: i32 = 6;
pub const WH_MOUSE: i32 = 7;
pub const WH_HARDWARE: i32 = 8;
pub const WH_DEBUG: i32 = 9;
pub const WH_SHELL: i32 = 10;
pub const WH_FOREGROUNDIDLE: i32 = 11;
pub const WH_CALLWNDPROCRET: i32 = 12;
pub const WH_KEYBOARD_LL: i32 = 13;
pub const WH_MOUSE_LL: i32 = 14;
pub const WH_MAX: i32 = 14;

/// Hook flags
pub const HF_GLOBAL: u32 = 0x0001;
pub const HF_ANCHOR: u32 = 0x0010;
pub const HF_HOOKED: u32 = 0x0004;

/// Hook structure
#[derive(Clone, Debug)]
pub struct Hook {
    pub hook_type: i32,
    pub hook_proc: u64,
    pub module: u64,
    pub thread_id: u32,
    pub flags: u32,
    pub next: u64,
}

impl Hook {
    pub fn new(hook_type: i32, hook_proc: u64, thread_id: u32) -> Self {
        let _ = (&hook_type, &hook_proc, &thread_id);

        Self {
            hook_type,
            hook_proc,
            module: 0,
            thread_id,
            flags: if thread_id == 0 { HF_GLOBAL } else { 0 },
            next: 0,
        }
    }
}

/// Hook handle table
static HOOK_NEXT_HANDLE: AtomicU64 = AtomicU64::new(0x00020000);
use alloc::boxed::Box;
use spin::RwLock;

/// Global hook chains (one per hook type) - initialized empty, expanded on demand
static HOOK_CHAINS: RwLock<alloc::vec::Vec<alloc::vec::Vec<u64>>> =
    RwLock::new(alloc::vec::Vec::new());

/// Hook handle map
static HOOK_HANDLES: RwLock<Vec<Option<Box<Hook>>>> = RwLock::new(Vec::new());

/// Allocate a hook handle
pub fn allocate_hook_handle() -> u64 {
    HOOK_NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

/// Install a hook
pub fn install_hook(hook_type: i32, hook_proc: u64, thread_id: u32) -> Option<u64> {
    let _ = (&hook_type, &hook_proc, &thread_id);

    if hook_type < WH_MIN || hook_type > WH_MAX {
        return None;
    }

    let mut handles = HOOK_HANDLES.write();
    let handle = allocate_hook_handle();
    let _ = &handle;
    let idx = handles.len();
    let _ = &idx;

    let hook = Box::new(Hook::new(hook_type, hook_proc, thread_id));
    let _ = &hook;
    handles.push(Some(hook));

    // Add to chain
    let chain_idx = (hook_type - WH_MIN) as usize;
    let _ = &chain_idx;
    let mut chains = HOOK_CHAINS.write();
    // Ensure we have enough capacity
    while chains.len() <= chain_idx {
        chains.push(alloc::vec::Vec::new());
    }
    chains[chain_idx].push(handle);

    // kprintln!("[win32k] Installed hook type={}, handle={:#x}", hook_type, handle);
    Some(handle)
}

/// Remove a hook
pub fn remove_hook(handle: u64) -> bool {
    let _ = (&handle,);

    let handles = HOOK_HANDLES.read();
    let _ = &handles;
    let mut found_idx = None;

    for i in 0..handles.len() {
        if let Some(ref hook) = handles[i] {
            if hook.hook_proc != 0 {
                found_idx = Some((i, (hook.hook_type - WH_MIN) as usize));
                break;
            }
        }
    }
    drop(handles);

    if let Some((idx, chain_idx)) = found_idx {
        // Remove from handle map
        let mut handles = HOOK_HANDLES.write();
        handles[idx] = None;

        // Remove from chain
        let mut chains = HOOK_CHAINS.write();
        if chain_idx < chains.len() {
            chains[chain_idx].retain(|&h| h != handle);
        }

        // kprintln!("[win32k] Removed hook handle={:#x}", handle);
        true
    } else {
        false
    }
}

/// Call hook chain
pub fn call_hook_chain(hook_type: i32, code: i32, wparam: u64, lparam: i64) -> i64 {
    let _ = (&hook_type, &code, &wparam, &lparam);

    if hook_type < WH_MIN || hook_type > WH_MAX {
        return 0;
    }

    let chain_idx = (hook_type - WH_MIN) as usize;
    let _ = &chain_idx;
    let handles = HOOK_HANDLES.read();
    let _ = &handles;
    let chains = HOOK_CHAINS.read();
    let _ = &chains;

    if chain_idx >= chains.len() {
        return 0;
    }

    for &handle in chains[chain_idx].iter() {
        if let Some(Some(ref hook)) = handles.get(handle as usize & 0xFFFF) {
            if hook.hook_proc != 0 {
                // Call the hook procedure
                // In a full implementation, this would call the actual hook procedure
                // kprintln!("[win32k] Calling hook type={}, proc={:#x}", hook_type, hook.hook_proc);
            }
        }
    }

    0
}

// =============================================================================
// Timer System (P2 Enhancement)
// =============================================================================

/// Timer flags
pub const TMR_TIMER: u32 = 0x0001;
pub const TMR_PERIODIC: u32 = 0x0002;

/// Timer structure
#[derive(Clone, Debug)]
pub struct UserTimer {
    pub hwnd: u64,
    pub n_id: u32,
    pub u_elapse: u32,
    pub timer_proc: u64,
    pub flags: u32,
}

impl UserTimer {
    pub fn new(hwnd: u64, n_id: u32, u_elapse: u32, timer_proc: u64) -> Self {
        let _ = (&hwnd, &n_id, &u_elapse, &timer_proc);

        Self {
            hwnd,
            n_id,
            u_elapse,
            timer_proc,
            flags: TMR_TIMER,
        }
    }
}

/// Timer handle table
static TIMER_NEXT_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
static TIMER_HANDLES: RwLock<Vec<Option<UserTimer>>> = RwLock::new(Vec::new());
static WINDOW_TIMERS: RwLock<alloc::collections::BTreeMap<u64, Vec<u32>>> =
    RwLock::new(alloc::collections::BTreeMap::new());

/// Allocate a timer ID
pub fn allocate_timer_id() -> u32 {
    TIMER_NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

/// create a timer
pub fn create_timer(hwnd: u64, n_id_event: u32, u_elapse: u32, timer_proc: u64) -> Option<u32> {
    let _ = (&hwnd, &n_id_event, &u_elapse, &timer_proc);

    let timer_id = if n_id_event == 0 {
        allocate_timer_id()
    } else {
        n_id_event
    };

    let mut handles = TIMER_HANDLES.write();
    let idx = handles.len();
    let _ = &idx;

    let timer = UserTimer::new(hwnd, timer_id, u_elapse, timer_proc);
    let _ = &timer;
    handles.push(Some(timer));

    // Add to window's timer list
    if hwnd != 0 {
        let mut window_timers = WINDOW_TIMERS.write();
        window_timers
            .entry(hwnd)
            .or_insert_with(Vec::new)
            .push(timer_id);
    }

    // kprintln!("[win32k] Created timer id={}, hwnd={:#x}, interval={}ms", timer_id, hwnd, u_elapse);
    Some(timer_id)
}

/// Kill a timer
pub fn kill_timer(hwnd: u64, n_id_event: u32) -> bool {
    let _ = (&hwnd, &n_id_event);

    let mut handles = TIMER_HANDLES.write();

    for i in 0..handles.len() {
        if let Some(ref timer) = handles[i] {
            if timer.hwnd == hwnd && (n_id_event == 0 || timer.n_id == n_id_event) {
                let timer_n_id = timer.n_id;
                let _ = &timer_n_id;
                handles[i] = None;

                // Remove from window's timer list
                if hwnd != 0 {
                    let mut window_timers = WINDOW_TIMERS.write();
                    if let Some(ids) = window_timers.get_mut(&hwnd) {
                        ids.retain(|&id| id != timer_n_id);
                    }
                }

                // kprintln!("[win32k] Killed timer id={}", timer_n_id);
                return true;
            }
        }
    }

    false
}

/// Get timer info
pub fn get_timer(timer_id: u32) -> Option<UserTimer> {
    let _ = (&timer_id,);

    let handles = TIMER_HANDLES.read();
    let _ = &handles;
    for timer in handles.iter() {
        if let Some(ref t) = timer {
            if t.n_id == timer_id {
                return Some(t.clone());
            }
        }
    }
    None
}

/// Timer DPC callback (for DPC-based timer implementation)
pub fn timer_dpc_callback(context: *mut u8) {
    let _ = (&context,);

    let timer_id = context as u32;
    let _ = &timer_id;
    if let Some(timer) = get_timer(timer_id) {
        if timer.hwnd != 0 && timer.timer_proc != 0 {
            // Send WmTimer message
            // kprintln!("[win32k] Timer callback: id={}, hwnd={:#x}", timer_id, timer.hwnd);
            // In a full implementation, this would queue a message to the window
        }
    }
}
