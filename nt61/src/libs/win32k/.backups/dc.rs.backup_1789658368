//! Device Context (DC) Management
//
//! Implements DC object allocation, attribute management, and DC state.
//! DC is the fundamental abstraction for GDI rendering operations.
//
//! ## Windows 7 DC Architecture
//
//! A DC encapsulates:
//! - The destination surface (screen, memory, printer)
//! - Current GDI objects (pen, brush, font, palette, region)
//! - Drawing attributes (colors, modes, transformations)
//! - Clipping regions
//
//! ## Magic Numbers and Constants
//
//! | Constant | Value | Description |
//! |----------|-------|-------------|
//! | `DC_TYPE_WINDOW` | 0x00000001 | Window DC type |
//! | `DC_TYPE_MEMORY` | 0x00000002 | Memory DC type |
//! | `DC_TYPE_METAFILE` | 0x00000004 | Metafile DC type |
//! | `DC_TYPE_PRINTER` | 0x00000008 | Printer DC type |
//! | `DC_TYPE_DISPLAY` | 0x00000001 | Display DC (alias of window) |
//
//! | Mapping Mode | Value | Description |
//! |--------------|-------|-------------|
//! | `MM_TEXT` | 1 | 1 logical unit = 1 pixel |
//! | `MM_LOMETRIC` | 2 | 1 logical unit = 0.1 mm |
//! | `MM_HIMETRIC` | 3 | 1 logical unit = 0.01 mm |
//! | `MM_LOENGLISH` | 4 | 1 logical unit = 0.01 inch |
//! | `MM_HIENGLISH` | 5 | 1 logical unit = 0.001 inch |
//! | `MM_TWIPS` | 6 | 1 logical unit = 1/1440 inch |
//! | `MM_ISOTROPIC` | 7 | Isotropic scaling |
//! | `MM_ANISOTROPIC` | 8 | Anisotropic scaling |
//
//! Reference: ReactOS win32ss/gdi/dc, Geoff Chappell

extern crate alloc;

use crate::kprintln;
use alloc::vec::Vec;

/// DC type flags
const DC_TYPE_WINDOW: u32 = 0x00000001;
const DC_TYPE_MEMORY: u32 = 0x00000002;
const DC_TYPE_METAFILE: u32 = 0x00000004;
const DC_TYPE_PRINTER: u32 = 0x00000008;
const DC_TYPE_DISPLAY: u32 = DC_TYPE_WINDOW;

/// Mapping modes
pub const MM_TEXT: i32 = 1;
pub const MM_LOMETRIC: i32 = 2;
pub const MM_HIMETRIC: i32 = 3;
pub const MM_LOENGLISH: i32 = 4;
pub const MM_HIENGLISH: i32 = 5;
pub const MM_TWIPS: i32 = 6;
pub const MM_ISOTROPIC: i32 = 7;
pub const MM_ANISOTROPIC: i32 = 8;

/// Background modes
pub const TRANSPARENT: i32 = 1;
pub const OPAQUE: i32 = 2;

/// R2 raster operation modes
pub const R2_BLACK: i32 = 1;
pub const R2_NOTMERGEPEN: i32 = 2;
pub const R2_MASKNOTPEN: i32 = 3;
pub const R2_NOTCOPYPEN: i32 = 4;
pub const R2_MASKPENNOT: i32 = 5;
pub const R2_INVERT: i32 = 6;
pub const R2_XORPEN: i32 = 7;
pub const R2_NOTMASKPEN: i32 = 8;
pub const R2_MASKPEN: i32 = 9;
pub const R2_NOTXORPEN: i32 = 10;
pub const R2_NOP: i32 = 11;
pub const R2_MERGENOTPEN: i32 = 12;
pub const R2_COPYPEN: i32 = 13;
pub const R2_MERGEPENNOT: i32 = 14;
pub const R2_MERGEPEN: i32 = 15;
pub const R2_WHITE: i32 = 16;

/// Text alignment flags
pub const TA_NOUPDATECP: i32 = 0;
pub const TA_UPDATECP: i32 = 1;
pub const TA_LEFT: i32 = 0;
pub const TA_CENTER: i32 = 6;
pub const TA_RIGHT: i32 = 2;
pub const TA_TOP: i32 = 0;
pub const TA_BOTTOM: i32 = 8;
pub const TA_BASELINE: i32 = 24;

/// Point structure (LONG)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PointL {
    pub x: i32,
    pub y: i32,
}

impl PointL {
    pub fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

/// Size structure
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SizeL {
    pub cx: i32,
    pub cy: i32,
}

impl SizeL {
    pub fn new(cx: i32, cy: i32) -> Self {
        Self { cx, cy }
    }
}

/// Saved DC state
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SavedDcState {
    pub pen: u64,
    pub brush: u64,
    pub font: u64,
    pub palette_handle: u64,
    pub region: u64,
    pub bitmap: u64,
    pub text_color: u32,
    pub bg_color: u32,
    pub text_align: i32,
    pub bk_mode: i32,
    pub rop_mode: i32,
    pub stretch_mode: i32,
    pub map_mode: i32,
    pub viewport_ext: SizeL,
    pub window_ext: SizeL,
    pub viewport_org: PointL,
    pub window_org: PointL,
}

impl Default for SavedDcState {
    fn default() -> Self {
        Self {
            pen: 0,
            brush: 0,
            font: 0,
            palette_handle: 0,
            region: 0,
            bitmap: 0,
            text_color: 0x00000000,
            bg_color: 0x00FFFFFF,
            text_align: TA_LEFT | TA_TOP | TA_NOUPDATECP,
            bk_mode: OPAQUE,
            rop_mode: R2_COPYPEN,
            stretch_mode: 0,
            map_mode: MM_TEXT,
            viewport_ext: SizeL::new(1, 1),
            window_ext: SizeL::new(1, 1),
            viewport_org: PointL::new(0, 0),
            window_org: PointL::new(0, 0),
        }
    }
}

/// DC object
#[repr(C)]
pub struct DcObject {
    // Handle header
    pub type_: u8,
    pub uses: u8,
    pub flags: u8,
    pub palette: u8,

    // DC type
    pub dc_type: u32,

    // Window association
    pub hwnd: u64,

    // Surface
    pub surface: u64,

    // Clipping region
    pub clip_region: u64,

    // Selected GDI objects
    pub pen: u64,
    pub brush: u64,
    pub font: u64,
    pub palette_handle: u64,  // renamed to avoid conflict with palette field
    pub bitmap: u64,
    pub region: u64,

    // Colors (BGR format)
    pub text_color: u32,
    pub bg_color: u32,

    // Text alignment
    pub text_align: i32,

    // Drawing modes
    pub bk_mode: i32,
    pub rop_mode: i32,
    pub stretch_mode: i32,

    // Mapping mode and transformations
    pub map_mode: i32,
    pub viewport_ext: SizeL,
    pub window_ext: SizeL,
    pub viewport_org: PointL,
    pub window_org: PointL,

    // DC bounds
    pub bounds: crate::libs::win32k::objects::Rect,

    // Saved state stack
    saved_states: Vec<SavedDcState>,
}

impl DcObject {
    pub fn new() -> Self {
        Self {
            type_: crate::libs::win32k::objects::GdiObjectType::DC as u8,
            uses: 0,
            flags: 0,
            palette: 0,
            dc_type: DC_TYPE_DISPLAY,
            hwnd: 0,
            surface: 0,
            clip_region: 0,
            pen: 0,
            brush: 0,
            font: 0,
            palette_handle: 0,
            bitmap: 0,
            region: 0,
            text_color: 0x00000000,  // Black
            bg_color: 0x00FFFFFF,   // White
            text_align: TA_LEFT | TA_TOP | TA_NOUPDATECP,
            bk_mode: OPAQUE,
            rop_mode: R2_COPYPEN,
            stretch_mode: 0,
            map_mode: MM_TEXT,
            viewport_ext: SizeL::new(1, 1),
            window_ext: SizeL::new(1, 1),
            viewport_org: PointL::new(0, 0),
            window_org: PointL::new(0, 0),
            bounds: crate::libs::win32k::objects::Rect::new(0, 0, 0, 0),
            saved_states: Vec::new(),
        }
    }

    /// Save current DC state
    pub fn save_state(&mut self) {
        let state = SavedDcState {
            pen: self.pen,
            brush: self.brush,
            font: self.font,
            palette_handle: self.palette_handle,
            region: self.region,
            bitmap: self.bitmap,
            text_color: self.text_color,
            bg_color: self.bg_color,
            text_align: self.text_align,
            bk_mode: self.bk_mode,
            rop_mode: self.rop_mode,
            stretch_mode: self.stretch_mode,
            map_mode: self.map_mode,
            viewport_ext: self.viewport_ext,
            window_ext: self.window_ext,
            viewport_org: self.viewport_org,
            window_org: self.window_org,
        };
        let _ = &state;
        self.saved_states.push(state);
    }

    /// Restore previous DC state
    pub fn restore_state(&mut self) -> bool {
        if let Some(state) = self.saved_states.pop() {
            self.pen = state.pen;
            self.brush = state.brush;
            self.font = state.font;
            self.palette_handle = state.palette_handle;
            self.region = state.region;
            self.bitmap = state.bitmap;
            self.text_color = state.text_color;
            self.bg_color = state.bg_color;
            self.text_align = state.text_align;
            self.bk_mode = state.bk_mode;
            self.rop_mode = state.rop_mode;
            self.stretch_mode = state.stretch_mode;
            self.map_mode = state.map_mode;
            self.viewport_ext = state.viewport_ext;
            self.window_ext = state.window_ext;
            self.viewport_org = state.viewport_org;
            self.window_org = state.window_org;
            true
        } else {
            false
        }
    }
}

// =============================================================================
// DC Handle Table
// =============================================================================

/// DC handle table
pub struct DcHandleTable {
    entries: Vec<Option<*mut DcObject>>,
    next_handle: u64,
}

impl DcHandleTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_handle: 0x80000000,
        }
    }

    /// Create a new DC
    pub fn create(&mut self, dc_type: u32, surface: u64) -> u64 {
        let dc = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<DcObject>(),
        );
        let _ = &dc;

        if dc.is_null() {
            // kprintln!("[win32k] DcHandleTable::create: failed to allocate DC")  // kprintln disabled (memcpy crash workaround);
            return 0;
        }

        unsafe {
            let d = &mut *(dc as *mut DcObject);
            let _ = &d;
            let _ = &d;
            *d = DcObject::new();
            d.dc_type = dc_type;
            d.surface = surface;
        }

        let handle = self.next_handle;

        let _ = &handle;
        let _ = &handle;
        self.next_handle += 1;
        self.entries.push(Some(dc as *mut DcObject));

        // kprintln!("[win32k] DcHandleTable::create: type=0x{:08x}, surface=0x{:x} -> handle=0x{:08x}",  // kprintln disabled (memcpy crash workaround)
//                   dc_type, surface, handle);

        handle
    }

    /// Get a DC by handle
    pub fn get(&self, handle: u64) -> Option<&'static mut DcObject> {
        let index = (handle - 0x80000000) as usize;
        let _ = &index;
        let _ = &index;
        if index < self.entries.len() {
            self.entries[index].map(|ptr| unsafe { &mut *ptr })
        } else {
            None
        }
    }

    /// Delete a DC
    pub fn delete(&mut self, handle: u64) -> bool {
        let index = (handle - 0x80000000) as usize;
        let _ = &index;
        let _ = &index;
        if index < self.entries.len() {
            if let Some(ptr) = self.entries[index].take() {
                unsafe {
                    // Release any selected objects
                    let dc = &mut *ptr;
                    let _ = &dc;
                    let _ = &dc;
                    if dc.surface != 0 {
                        // Surface cleanup handled separately
                    }
                    let _ = crate::mm::pool::free(ptr as *mut u8);
                }
                // kprintln!("[win32k] DcHandleTable::delete: handle=0x{:08x}", handle)  // kprintln disabled (memcpy crash workaround);
                return true;
            }
        }
        false
    }
}

// Global DC handle table - protected by spinlock for thread safety.
//
// We initialise the table on first access. A raw pointer is cached so that
// `get_dc_table` can hand out a `&'static mut` reference without the borrow
// checker complaining about the spinlock-guard lifetime. The spinlock still
// serialises concurrent access to the table itself.
static DC_HANDLE_TABLE: crate::ke::sync::Spinlock<Option<DcHandleTable>> =
    crate::ke::sync::Spinlock::new(None);

/// Raw, lazily-initialised handle on the inner table. `None` until the
/// first call to [`get_dc_table`]. Initialisation is guarded by the spinlock
/// so we never hand out the pointer before it is set.
static mut DC_TABLE_PTR: *mut DcHandleTable = core::ptr::null_mut();

pub fn get_dc_table() -> &'static mut DcHandleTable {
    // Fast path: already initialised.
    let ptr = unsafe { DC_TABLE_PTR };
    let _ = &ptr;
    let _ = &ptr;
    if !ptr.is_null() {
        return unsafe { &mut *ptr };
    }

    // Slow path: initialise under the spinlock so concurrent callers see a
    // consistent view.
    let mut guard = DC_HANDLE_TABLE.lock();
    if guard.is_none() {
        *guard = Some(DcHandleTable::new());
    }
    let inner = guard.as_mut().unwrap() as *mut DcHandleTable;
    let _ = &inner;
    let _ = &inner;
    unsafe { DC_TABLE_PTR = inner; }
    unsafe { &mut *inner }
}

// =============================================================================
// DC Creation Functions
// =============================================================================

/// Create a display DC (screen DC)
pub fn GreCreateDisplayDC() -> u64 {
    // Get primary surface
    let surface = crate::libs::win32k::surface::get_primary_surface() as u64;
    let _ = &surface;
    let _ = &surface;
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    table.create(DC_TYPE_DISPLAY | DC_TYPE_WINDOW, surface)
}

/// Create a memory DC
pub fn GreCreateCompatibleDC(source_dc: u64) -> u64 {
    let source_surface = if source_dc != 0 {
        let table = get_dc_table();
        let _ = &table;
        if let Some(dc) = table.get(source_dc) {
            dc.surface
        } else {
            0
        }
    } else {
        crate::libs::win32k::surface::get_primary_surface() as u64
    };
    let _ = &source_surface;

    let table = get_dc_table();

    let _ = &table;
    let _ = &table;
    table.create(DC_TYPE_MEMORY, source_surface)
}

/// Delete a DC
pub fn GreDeleteDC(dc_handle: u64) -> bool {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    table.delete(dc_handle)
}

/// Get DC for a bitmap (creates a DC with the bitmap selected)
pub fn GreGetDCForBitmap(bitmap_handle: u64) -> u64 {
    let _ = bitmap_handle;
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    
    // Create a memory DC compatible with the primary surface
    let mem_dc = table.create(DC_TYPE_MEMORY, 0);
    let _ = &mem_dc;
    let _ = &mem_dc;
    
    mem_dc
}

/// Get DC by handle
pub fn get_dc(dc_handle: u64) -> Option<&'static mut DcObject> {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    table.get(dc_handle)
}

// =============================================================================
// DC Attribute Functions
// =============================================================================

/// Set text color
pub fn GreSetTextColor(dc_handle: u64, color: u32) -> u32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        let old = dc.text_color;
        let _ = &old;
        let _ = &old;
        dc.text_color = color;
        old
    } else {
        0xFFFFFFFF
    }
}

/// Get text color
pub fn GreGetTextColor(dc_handle: u64) -> u32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.text_color
    } else {
        0
    }
}

/// Set background color
pub fn GreSetBkColor(dc_handle: u64, color: u32) -> u32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        let old = dc.bg_color;
        let _ = &old;
        let _ = &old;
        dc.bg_color = color;
        old
    } else {
        0xFFFFFFFF
    }
}

/// Get background color
pub fn GreGetBkColor(dc_handle: u64) -> u32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.bg_color
    } else {
        0x00FFFFFF
    }
}

/// Set background mode
pub fn GreSetBkMode(dc_handle: u64, mode: i32) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        let old = dc.bk_mode;
        let _ = &old;
        let _ = &old;
        dc.bk_mode = mode;
        old
    } else {
        OPAQUE
    }
}

/// Get background mode
pub fn GreGetBkMode(dc_handle: u64) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.bk_mode
    } else {
        OPAQUE
    }
}

/// Set ROP mode
pub fn GreSetROP2(dc_handle: u64, mode: i32) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        let old = dc.rop_mode;
        let _ = &old;
        let _ = &old;
        dc.rop_mode = mode;
        old
    } else {
        R2_COPYPEN
    }
}

/// Get ROP mode
pub fn GreGetROP2(dc_handle: u64) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.rop_mode
    } else {
        R2_COPYPEN
    }
}

/// Set text alignment
pub fn GreSetTextAlign(dc_handle: u64, align: i32) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        let old = dc.text_align;
        let _ = &old;
        let _ = &old;
        dc.text_align = align;
        old
    } else {
        TA_LEFT
    }
}

/// Get text alignment
pub fn GreGetTextAlign(dc_handle: u64) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.text_align
    } else {
        TA_LEFT
    }
}

// =============================================================================
// SelectObject
// =============================================================================

/// Select an object into a DC
pub fn GreSelectObject(dc_handle: u64, object_handle: u64) -> u64 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        // Determine object type
        let obj_type = (object_handle >> 16) & 0xFFFF;
        let _ = &obj_type;
        let _ = &obj_type;
        
        let old_handle = match obj_type {
            0x0005 => { let old = dc.pen; dc.pen = object_handle; old }
            0x0007 => { let old = dc.brush; dc.brush = object_handle; old }
            0x0004 => { let old = dc.font; dc.font = object_handle; old }
            0x0003 => { let old = dc.palette_handle; dc.palette_handle = object_handle; old }
            0x0008 => { let old = dc.region; dc.region = object_handle; old }
            0x0002 => { let old = dc.bitmap; dc.bitmap = object_handle; old }
            _ => 0,
        };
        
        // Increment reference count for new object
        crate::libs::win32k::objects::GdiSelectObject(object_handle);
        
        // kprintln!("[win32k] GreSelectObject: dc=0x{:08x}, obj=0x{:016x}, old=0x{:016x}",  // kprintln disabled (memcpy crash workaround)
//                   dc_handle, object_handle, old_handle);
        
        old_handle
    } else {
        0
    }
}

/// Get current pen
pub fn GreGetCurrentPen(dc_handle: u64) -> u64 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.pen
    } else {
        0
    }
}

/// Get current brush
pub fn GreGetCurrentBrush(dc_handle: u64) -> u64 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.brush
    } else {
        0
    }
}

/// Get current font
pub fn GreGetCurrentFont(dc_handle: u64) -> u64 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.font
    } else {
        0
    }
}

// =============================================================================
// SaveDC / RestoreDC
// =============================================================================

/// Save DC state
pub fn GreSaveDC(dc_handle: u64) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.save_state();
        let count = dc.saved_states.len() as i32;
        let _ = &count;
        let _ = &count;
        // kprintln!("[win32k] GreSaveDC: dc=0x{:08x}, saved_count={}", dc_handle, count)  // kprintln disabled (memcpy crash workaround);
        count
    } else {
        0
    }
}

/// Restore DC state
pub fn GreRestoreDC(dc_handle: u64, saved_state: i32) -> bool {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        // Negative state means pop from top
        if saved_state < 0 {
            dc.restore_state()
        } else {
            // For positive state, we need to restore to specific level
            // This is more complex - for now just restore one level
            dc.restore_state()
        }
    } else {
        false
    }
}

// =============================================================================
// Mapping Mode Functions
// =============================================================================

/// Set mapping mode
pub fn GreSetMapMode(dc_handle: u64, mode: i32) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        let old = dc.map_mode;
        let _ = &old;
        let _ = &old;
        dc.map_mode = mode;
        
        // Update viewport/window extents based on mapping mode
        match mode {
            MM_TEXT => {
                dc.viewport_ext = SizeL::new(1, 1);
                dc.window_ext = SizeL::new(1, 1);
            }
            MM_LOMETRIC => {
                dc.viewport_ext = SizeL::new(100, 100);
                dc.window_ext = SizeL::new(254, 254);
            }
            MM_HIMETRIC => {
                dc.viewport_ext = SizeL::new(100, 100);
                dc.window_ext = SizeL::new(2540, 2540);
            }
            MM_LOENGLISH => {
                dc.viewport_ext = SizeL::new(100, 100);
                dc.window_ext = SizeL::new(1000, 1000);
            }
            MM_HIENGLISH => {
                dc.viewport_ext = SizeL::new(100, 100);
                dc.window_ext = SizeL::new(10000, 10000);
            }
            _ => {}
        }
        
        // kprintln!("[win32k] GreSetMapMode: dc=0x{:08x}, mode={}", dc_handle, mode)  // kprintln disabled (memcpy crash workaround);
        old
    } else {
        MM_TEXT
    }
}

/// Get mapping mode
pub fn GreGetMapMode(dc_handle: u64) -> i32 {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.map_mode
    } else {
        MM_TEXT
    }
}

/// Set viewport extent
pub fn GreSetViewportExtEx(dc_handle: u64, cx: i32, cy: i32, old_size: Option<&mut SizeL>) -> bool {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        if let Some(size) = old_size {
            *size = dc.viewport_ext;
        }
        dc.viewport_ext = SizeL::new(cx, cy);
        true
    } else {
        false
    }
}

/// Set window extent
pub fn GreSetWindowExtEx(dc_handle: u64, cx: i32, cy: i32, old_size: Option<&mut SizeL>) -> bool {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        if let Some(size) = old_size {
            *size = dc.window_ext;
        }
        dc.window_ext = SizeL::new(cx, cy);
        true
    } else {
        false
    }
}

/// Set viewport origin
pub fn GreSetViewportOrgEx(dc_handle: u64, x: i32, y: i32, old_origin: Option<&mut PointL>) -> bool {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        if let Some(origin) = old_origin {
            *origin = dc.viewport_org;
        }
        dc.viewport_org = PointL::new(x, y);
        true
    } else {
        false
    }
}

// =============================================================================
// DC Bounds
// =============================================================================

/// Get DC bounds
pub fn GreGetDCBounds(dc_handle: u64) -> crate::libs::win32k::objects::Rect {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.bounds
    } else {
        crate::libs::win32k::objects::Rect::new(0, 0, 0, 0)
    }
}

/// Set DC bounds
pub fn GreSetDCBounds(dc_handle: u64, bounds: &crate::libs::win32k::objects::Rect) {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        dc.bounds = *bounds;
    }
}

// =============================================================================
// Debug
// =============================================================================

/// Dump DC info
pub fn dump_dc_info(dc_handle: u64) {
    let table = get_dc_table();
    let _ = &table;
    let _ = &table;
    if let Some(dc) = table.get(dc_handle) {
        let _ = dc;
        // kprintln!("[win32k] DC 0x{:08x} info:", dc_handle)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  type: 0x{:08x}, surface: 0x{:x}", dc.dc_type, dc.surface)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  pen: 0x{:016x}, brush: 0x{:016x}, font: 0x{:016x}",  // kprintln disabled (memcpy crash workaround)
//                   dc.pen, dc.brush, dc.font);
        // kprintln!("  text_color: 0x{:08x}, bg_color: 0x{:08x}", dc.text_color, dc.bg_color)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  text_align: 0x{:x}, bk_mode: {}, rop_mode: {}",  // kprintln disabled (memcpy crash workaround)
//                   dc.text_align, dc.bk_mode, dc.rop_mode);
        // kprintln!("  map_mode: {}, viewport: {}x{}, window: {}x{}",  // kprintln disabled (memcpy crash workaround)
//                   dc.map_mode, dc.viewport_ext.cx, dc.viewport_ext.cy,
//                   dc.window_ext.cx, dc.window_ext.cy);
        // kprintln!("  viewport_org: ({}, {}), window_org: ({}, {})",  // kprintln disabled (memcpy crash workaround)
//                   dc.viewport_org.x, dc.viewport_org.y,
//                   dc.window_org.x, dc.window_org.y);
        // kprintln!("  saved_states: {}", dc.saved_states.len())  // kprintln disabled (memcpy crash workaround);
    }
}
