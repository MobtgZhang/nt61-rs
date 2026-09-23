//! GDI Object Management
//
//! Implements the GDI handle table and object allocation/freeing.
//! GDI objects include pens, brushes, fonts, bitmaps, regions, palettes, and DCs.
//
//! ## Windows 7 GDI Handle Architecture
//
//! GDI handles are 32-bit values with the following structure:
//! - High 16 bits: Handle type indicator (0x4000 | base_type)
//! - Low 16 bits: Index into handle table
//
//! ## Magic Numbers and Constants
//
//! | Constant | Value | Description |
//! |----------|-------|-------------|
//! | `HANDLE_TYPE_DC` | 0x4001 | Device Context handle type |
//! | `HANDLE_TYPE_BITMAP` | 0x4002 | Bitmap handle type |
//! | `HANDLE_TYPE_PALETTE` | 0x4003 | Palette handle type |
//! | `HANDLE_TYPE_FONT` | 0x4004 | Font handle type |
//! | `HANDLE_TYPE_PEN` | 0x4005 | Pen handle type |
//! | `HANDLE_TYPE_EXTPEN` | 0x4006 | Extended pen handle type |
//! | `HANDLE_TYPE_BRUSH` | 0x4007 | Brush handle type |
//! | `HANDLE_TYPE_REGION` | 0x4008 | Region handle type |
//! | `HANDLE_TYPE_METAFILE` | 0x4009 | Metafile handle type |
//! | `HANDLE_TYPE_MEMDC` | 0x400A | Memory DC handle type |
//! | `HANDLE_TYPE_ENHANCED_DC` | 0x400B | Enhanced DC handle type |
//! | `HANDLE_INDEX_MASK` | 0xFFFF | Mask to extract index from handle |
//! | `HANDLE_TYPE_MASK` | 0xFFFF0000 | Mask to extract type from handle |
//
//! | Stock Object | Handle | Description |
//! |--------------|--------|-------------|
//! | `STOCK_OBJECT_BLACK_BRUSH` | 0x40000004 | Black brush |
//! | `STOCK_OBJECT_WHITE_BRUSH` | 0x40000005 | White brush |
//! | `STOCK_OBJECT_HOLLOW_BRUSH` | 0x40000006 | Hollow brush (NULL_BRUSH) |
//! | `STOCK_OBJECT_BLACK_PEN` | 0x40000007 | Black pen |
//! | `STOCK_OBJECT_WHITE_PEN` | 0x40000008 | White pen |
//! | `STOCK_OBJECT_NULL_PEN` | 0x40000009 | Null pen |
//! | `STOCK_OBJECT_SYSTEM_FONT` | 0x4000000A | System font |
//
//! Reference: ReactOS win32ss/gdi/gdiobj, Geoff Chappell

extern crate alloc;

use crate::kprintln;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// GDI object types (matches Windows GDIObjType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GdiObjectType {
    DC = 1,
    Bitmap = 2,
    Palette = 3,
    Font = 4,
    Pen = 5,
    ExtPen = 6,
    Brush = 7,
    Region = 8,
    Metafile = 9,
    MemDC = 10,
    EnhancedMetafileDC = 11,
}

impl GdiObjectType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(GdiObjectType::DC),
            2 => Some(GdiObjectType::Bitmap),
            3 => Some(GdiObjectType::Palette),
            4 => Some(GdiObjectType::Font),
            5 => Some(GdiObjectType::Pen),
            6 => Some(GdiObjectType::ExtPen),
            7 => Some(GdiObjectType::Brush),
            8 => Some(GdiObjectType::Region),
            9 => Some(GdiObjectType::Metafile),
            10 => Some(GdiObjectType::MemDC),
            11 => Some(GdiObjectType::EnhancedMetafileDC),
            _ => None,
        }
    }
}

/// GDI handle entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GdiHandleEntry {
    /// Object type (1-11)
    pub obj_type: u8,
    /// Usage count
    pub uses: u8,
    /// Flags
    pub flags: u8,
    /// Palette index
    pub palette: u8,
    /// Kernel address of the object
    pub obj_ptr: u64,
    /// Process ID that owns this handle
    pub process_id: u32,
    /// Handle stamp for validation
    pub stamp: u32,
}

impl GdiHandleEntry {
    pub fn new(obj_type: GdiObjectType, obj_ptr: u64, pid: u32) -> Self {
        Self {
            obj_type: obj_type as u8,
            uses: 0,
            flags: 0,
            palette: 0,
            obj_ptr,
            process_id: pid,
            stamp: 0,
        }
    }

    pub fn get_type(&self) -> Option<GdiObjectType> {
        GdiObjectType::from_u8(self.obj_type)
    }
}

/// Handle type prefixes (high 16 bits)
const HANDLE_TYPE_DC: u32 = 0x4001;      // 0x0001 with high bit
const HANDLE_TYPE_BITMAP: u32 = 0x4002;
const HANDLE_TYPE_PALETTE: u32 = 0x4003;
const HANDLE_TYPE_FONT: u32 = 0x4004;
const HANDLE_TYPE_PEN: u32 = 0x4005;
const HANDLE_TYPE_EXTPEN: u32 = 0x4006;
const HANDLE_TYPE_BRUSH: u32 = 0x4007;
const HANDLE_TYPE_REGION: u32 = 0x4008;
const HANDLE_TYPE_METAFILE: u32 = 0x4009;
const HANDLE_TYPE_MEMDC: u32 = 0x400A;
const HANDLE_TYPE_ENHANCED_DC: u32 = 0x400B;

fn get_handle_prefix(obj_type: GdiObjectType) -> u32 {
    match obj_type {
        GdiObjectType::DC => HANDLE_TYPE_DC,
        GdiObjectType::Bitmap => HANDLE_TYPE_BITMAP,
        GdiObjectType::Palette => HANDLE_TYPE_PALETTE,
        GdiObjectType::Font => HANDLE_TYPE_FONT,
        GdiObjectType::Pen => HANDLE_TYPE_PEN,
        GdiObjectType::ExtPen => HANDLE_TYPE_EXTPEN,
        GdiObjectType::Brush => HANDLE_TYPE_BRUSH,
        GdiObjectType::Region => HANDLE_TYPE_REGION,
        GdiObjectType::Metafile => HANDLE_TYPE_METAFILE,
        GdiObjectType::MemDC => HANDLE_TYPE_MEMDC,
        GdiObjectType::EnhancedMetafileDC => HANDLE_TYPE_ENHANCED_DC,
    }
}

/// GDI handle table
pub struct GdiHandleTable {
    entries: Vec<Option<GdiHandleEntry>>,
    next_index: AtomicU64,
}

impl GdiHandleTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_index: AtomicU64::new(1),
        }
    }

    /// Allocate a new GDI handle
    /// Handle format: [31:16] = type prefix, [15:0] = index
    pub fn allocate(&mut self, obj_type: GdiObjectType, obj_ptr: u64, pid: u32) -> u64 {
        let entry = GdiHandleEntry::new(obj_type, obj_ptr, pid);
        let _ = &entry;
        let prefix = get_handle_prefix(obj_type);
        let _ = &prefix;

        // Find a free slot first (recycling)
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                return ((prefix as u64) << 16) | (i as u64);
            }
        }

        // No free slot, add new one
        let index = self.next_index.fetch_add(1, Ordering::Relaxed) as usize;
        let _ = &index;
        self.entries.push(Some(entry));
        ((prefix as u64) << 16) | (index as u64)
    }

    /// Get a handle entry - validates both index and type prefix
    pub fn get(&self, handle: u64) -> Option<&GdiHandleEntry> {
        let index = (handle & 0xFFFF) as usize;
        let _ = &index;
        if index < self.entries.len() {
            let entry = self.entries[index].as_ref()?;
            let _ = &entry;
            // Validate type prefix matches
            let expected_prefix = get_handle_prefix(entry.get_type()?);
            let _ = &expected_prefix;
            let actual_prefix = (handle >> 16) as u32;
            let _ = &actual_prefix;
            if actual_prefix == expected_prefix {
                Some(entry)
            } else {
                // kprintln!("[win32k] Handle type mismatch: expected=0x{:04x}, got=0x{:04x}",  // kprintln disabled (memcpy crash workaround)
//                     expected_prefix, actual_prefix);
                None
            }
        } else {
            None
        }
    }

    /// Get a mutable handle entry with validation
    pub fn get_mut(&mut self, handle: u64) -> Option<&mut GdiHandleEntry> {
        let index = (handle & 0xFFFF) as usize;
        let _ = &index;
        if index < self.entries.len() {
            let entry = self.entries[index].as_ref()?;
            let _ = &entry;
            // Validate type prefix matches
            let expected_prefix = get_handle_prefix(entry.get_type()?);
            let _ = &expected_prefix;
            let actual_prefix = (handle >> 16) as u32;
            let _ = &actual_prefix;
            if actual_prefix == expected_prefix {
                self.entries[index].as_mut()
            } else {
                // kprintln!("[win32k] Handle type mismatch: expected=0x{:04x}, got=0x{:04x}",  // kprintln disabled (memcpy crash workaround)
//                     expected_prefix, actual_prefix);
                None
            }
        } else {
            None
        }
    }

    /// Free a GDI handle
    pub fn free(&mut self, handle: u64) -> Option<GdiHandleEntry> {
        let index = (handle & 0xFFFF) as usize;
        let _ = &index;
        if index < self.entries.len() {
            self.entries[index].take()
        } else {
            None
        }
    }

    /// Increment usage count
    pub fn add_ref(&mut self, handle: u64) -> bool {
        if let Some(entry) = self.get_mut(handle) {
            entry.uses = entry.uses.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Decrement usage count
    pub fn release(&mut self, handle: u64) -> bool {
        if let Some(entry) = self.get_mut(handle) {
            entry.uses = entry.uses.saturating_sub(1);
            true
        } else {
            false
        }
    }
}

// Global GDI handle table - protected by spinlock for thread safety.
//
// The inner table pointer is cached statically so `get_handle_table` can
// return a `&'static mut` reference without leaking the spinlock-guard
// lifetime. Initialisation is still serialised by the spinlock.
static GDI_HANDLE_TABLE: crate::ke::sync::Spinlock<Option<GdiHandleTable>> =
    crate::ke::sync::Spinlock::new(None);
static mut GDI_TABLE_PTR: *mut GdiHandleTable = core::ptr::null_mut();

fn get_handle_table() -> &'static mut GdiHandleTable {
    let ptr = unsafe { GDI_TABLE_PTR };
    let _ = &ptr;
    if !ptr.is_null() {
        return unsafe { &mut *ptr };
    }
    let mut guard = GDI_HANDLE_TABLE.lock();
    if guard.is_none() {
        *guard = Some(GdiHandleTable::new());
    }
    let inner = guard.as_mut().unwrap() as *mut GdiHandleTable;
    let _ = &inner;
    unsafe { GDI_TABLE_PTR = inner; }
    unsafe { &mut *inner }
}

// =============================================================================
// GDI Object Structures
// =============================================================================

/// Pen style flags
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum PenStyle {
    Solid = 0x00000000,
    Dash = 0x00000001,
    Dot = 0x00000002,
    DashDot = 0x00000003,
    DashDotDot = 0x00000004,
    Null = 0x00000005,
    InsideFrame = 0x00000006,
}

impl PenStyle {
    pub fn from_raw(value: i32) -> Self {
        match value as u32 {
            0x00000000 => PenStyle::Solid,
            0x00000001 => PenStyle::Dash,
            0x00000002 => PenStyle::Dot,
            0x00000003 => PenStyle::DashDot,
            0x00000004 => PenStyle::DashDotDot,
            0x00000005 => PenStyle::Null,
            0x00000006 => PenStyle::InsideFrame,
            _ => PenStyle::Solid,
        }
    }
}

/// Pen object
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GdiPen {
    pub type_: u8,
    pub uses: u8,
    pub flags: u8,
    pub palette: u8,
    pub color: u32,
    pub style: u32,
    pub width: i32,
    pub brush_lined: u64,
}

impl GdiPen {
    pub fn new(style: PenStyle, width: i32, color: u32) -> Self {
        Self {
            type_: GdiObjectType::Pen as u8,
            uses: 0,
            flags: 0,
            palette: 0,
            color,
            style: style as u32,
            width,
            brush_lined: 0,
        }
    }
}

/// Brush style flags
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum BrushStyle {
    Solid = 0x00000000,
    Null = 0x00000001,
    Hatched = 0x00000002,
    Pattern = 0x00000003,
    Indexed = 0x00000004,
    DIBPattern = 0x00000005,
    DIBPatternPt = 0x00000006,
    Pattern8x8 = 0x00000007,
    MonochromeBitmap = 0x00000008,
}

/// Hatch style
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum HatchStyle {
    Horizontal = 0x00000000,
    Vertical = 0x00000001,
    FDiagonal = 0x00000002,
    BDiagonal = 0x00000003,
    Cross = 0x00000004,
    DiagonalCross = 0x00000005,
}

/// Brush object
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GdiBrush {
    pub type_: u8,
    pub uses: u8,
    pub flags: u8,
    pub palette: u8,
    pub color: u32,
    pub style: u32,
    pub hatch: i32,
    pub bitmap: u64,
}

impl GdiBrush {
    pub fn new_solid(color: u32) -> Self {
        Self {
            type_: GdiObjectType::Brush as u8,
            uses: 0,
            flags: 0,
            palette: 0,
            color,
            style: BrushStyle::Solid as u32,
            hatch: 0,
            bitmap: 0,
        }
    }

    pub fn new_hatched(style: HatchStyle, color: u32) -> Self {
        Self {
            type_: GdiObjectType::Brush as u8,
            uses: 0,
            flags: 0,
            palette: 0,
            color,
            style: BrushStyle::Hatched as u32,
            hatch: style as i32,
            bitmap: 0,
        }
    }
}

/// Font quality
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum FontQuality {
    Default = 0,
    Draft = 1,
    Proof = 2,
    NonAntialiased = 3,
    Antialiased = 4,
    ClearType = 5,
    ClearTypeNatural = 6,
}

/// Font object (LOGFONTW - simplified)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GdiFont {
    pub type_: u8,
    pub uses: u8,
    pub flags: u8,
    pub palette: u8,
    pub height: i32,
    pub width: i32,
    pub escapement: i32,
    pub orientation: i32,
    pub weight: i32,
    pub italic: u8,
    pub underline: u8,
    pub strike_out: u8,
    pub charset: u8,
    pub out_precision: u8,
    pub clip_precision: u8,
    pub quality: u8,
    pub pitch_and_family: u8,
    pub face_name: [u16; 32],
}

impl GdiFont {
    pub fn new() -> Self {
        Self {
            type_: GdiObjectType::Font as u8,
            uses: 0,
            flags: 0,
            palette: 0,
            height: 16,
            width: 0,
            escapement: 0,
            orientation: 0,
            weight: 400,
            italic: 0,
            underline: 0,
            strike_out: 0,
            charset: 0,
            out_precision: 0,
            clip_precision: 0,
            quality: FontQuality::Default as u8,
            pitch_and_family: 0,
            face_name: [0; 32],
        }
    }

    pub fn set_face_name(&mut self, name: &[u16]) {
        let len = name.len().min(31);
        let _ = &len;
        self.face_name[..len].copy_from_slice(&name[..len]);
        self.face_name[len] = 0;
    }
}

/// Bitmap object
#[repr(C)]
#[derive(Clone)]
pub struct GdiBitmap {
    pub type_: u8,
    pub uses: u8,
    pub flags: u8,
    pub palette: u8,
    pub size: u64,
    pub width: i32,
    pub height: i32,
    pub width_bytes: i32,
    pub planes: u16,
    pub bit_count: u16,
    pub format: u32,
    pub bits: *mut u8,
}

impl GdiBitmap {
    pub fn new(width: i32, height: i32, bit_count: u16) -> Option<Self> {
        let width_bytes = ((width * (bit_count as i32) + 31) / 32) * 4;
        let _ = &width_bytes;
        let size = (width_bytes * height.abs()) as u64;
        let _ = &size;
        
        let bits = if size > 0 {
            crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, size as usize)
        } else {
            core::ptr::null_mut()
        };

        Some(Self {
            type_: GdiObjectType::Bitmap as u8,
            uses: 0,
            flags: 0,
            palette: 0,
            size,
            width,
            height,
            width_bytes,
            planes: 1,
            bit_count,
            format: 0,
            bits,
        })
    }
}

impl Drop for GdiBitmap {
    fn drop(&mut self) {
        if !self.bits.is_null() {
            let _ = crate::mm::pool::free(self.bits);
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

/// Palette object
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GdiPalette {
    pub type_: u8,
    pub uses: u8,
    pub flags: u8,
    pub palette_flags: u8,
    pub version: u16,
    pub num_entries: u32,
    pub entries: [PaletteEntry; 256],
}

impl GdiPalette {
    pub fn new() -> Self {
        let mut entries = [PaletteEntry { red: 0, green: 0, blue: 0, flags: 0 }; 256];
        
        // Initialize with standard system palette colors
        for i in 0..16 {
            let (r, g, b) = match i {
                0 => (0, 0, 0),           // Black
                1 => (128, 0, 0),         // Dark Red
                2 => (0, 128, 0),         // Dark Green
                3 => (128, 128, 0),       // Dark Yellow
                4 => (0, 0, 128),         // Dark Blue
                5 => (128, 0, 128),       // Dark Magenta
                6 => (0, 128, 128),       // Dark Cyan
                7 => (192, 192, 192),     // Light Gray
                8 => (128, 128, 128),     // Dark Gray
                9 => (255, 0, 0),          // Red
                10 => (0, 255, 0),         // Green
                11 => (255, 255, 0),      // Yellow
                12 => (0, 0, 255),         // Blue
                13 => (255, 0, 255),      // Magenta
                14 => (0, 255, 255),      // Cyan
                15 => (255, 255, 255),   // White
                _ => (0, 0, 0),
            };
            entries[i] = PaletteEntry { red: r, green: g, blue: b, flags: 0 };
        }
        
        Self {
            type_: GdiObjectType::Palette as u8,
            uses: 0,
            flags: 0,
            palette_flags: 0,
            version: 0x0300,
            num_entries: 20,
            entries,
        }
    }
}

/// RECT structure - unified definition for all win32k modules
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub fn new(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Self { left, top, right, bottom }
    }

    pub fn width(&self) -> i32 {
        self.right - self.left
    }

    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }

    /// Check if a point is inside the rectangle
    pub fn contains_point(&self, x: i32, y: i32) -> bool {
        x >= self.left && x < self.right && y >= self.top && y < self.bottom
    }

    /// Compute intersection with another rectangle
    pub fn intersect(&self, other: &Rect) -> Option<Rect> {
        let left = core::cmp::max(self.left, other.left);
        let _ = &left;
        let top = core::cmp::max(self.top, other.top);
        let _ = &top;
        let right = core::cmp::min(self.right, other.right);
        let _ = &right;
        let bottom = core::cmp::min(self.bottom, other.bottom);
        let _ = &bottom;

        if right > left && bottom > top {
            Some(Rect { left, top, right, bottom })
        } else {
            None
        }
    }

    /// Check if rectangle is empty (zero or negative dimensions)
    pub fn is_empty(&self) -> bool {
        self.right <= self.left || self.bottom <= self.top
    }

    /// Normalize rectangle so left <= right and top <= bottom
    pub fn normalize(&mut self) {
        if self.left > self.right {
            core::mem::swap(&mut self.left, &mut self.right);
        }
        if self.top > self.bottom {
            core::mem::swap(&mut self.top, &mut self.bottom);
        }
    }

    /// Convert to a 4-element array [left, top, right, bottom]
    pub fn to_array(&self) -> [i32; 4] {
        [self.left, self.top, self.right, self.bottom]
    }

    /// Create from a 4-element array [left, top, right, bottom]
    pub fn from_array(arr: [i32; 4]) -> Self {
        Self {
            left: arr[0],
            top: arr[1],
            right: arr[2],
            bottom: arr[3],
        }
    }
}

/// Region object
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GdiRegion {
    pub type_: u8,
    pub uses: u8,
    pub flags: u8,
    pub palette: u8,
    pub size: u64,
    pub num_rects: i32,
    pub extents: Rect,
}

impl GdiRegion {
    pub fn new_rect(rect: &Rect) -> Self {
        Self {
            type_: GdiObjectType::Region as u8,
            uses: 0,
            flags: 0,
            palette: 0,
            size: core::mem::size_of::<GdiRegion>() as u64,
            num_rects: 1,
            extents: *rect,
        }
    }
}

// =============================================================================
// GDI Object Creation Functions
// =============================================================================

/// Create a pen
pub fn GdiCreatePen(style: PenStyle, width: i32, color: u32) -> u64 {
    let pen = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<GdiPen>(),
    );

    if pen.is_null() {
        // kprintln!("[win32k] GdiCreatePen: failed to allocate memory")  // kprintln disabled (memcpy crash workaround);
        return 0;
    }

    unsafe {
        let p = &mut *(pen as *mut GdiPen);
        let _ = &p;
        *p = GdiPen::new(style, width, color);
    }

    let handle_table = get_handle_table();
    let _ = &handle_table;
    let handle = handle_table.allocate(GdiObjectType::Pen, pen as u64, 0);
    let _ = &handle;

    // kprintln!("[win32k] GdiCreatePen: style=0x{:x}, width={}, color=0x{:08x} -> handle=0x{:016x}",  // kprintln disabled (memcpy crash workaround)
//               style as u32, width, color, handle);

    handle
}

/// Create a solid brush
pub fn GdiCreateSolidBrush(color: u32) -> u64 {
    let brush = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<GdiBrush>(),
    );

    if brush.is_null() {
        // kprintln!("[win32k] GdiCreateSolidBrush: failed to allocate memory")  // kprintln disabled (memcpy crash workaround);
        return 0;
    }

    unsafe {
        let b = &mut *(brush as *mut GdiBrush);
        let _ = &b;
        *b = GdiBrush::new_solid(color);
    }

    let handle_table = get_handle_table();
    let _ = &handle_table;
    let handle = handle_table.allocate(GdiObjectType::Brush, brush as u64, 0);
    let _ = &handle;

    // kprintln!("[win32k] GdiCreateSolidBrush: color=0x{:08x} -> handle=0x{:016x}", color, handle)  // kprintln disabled (memcpy crash workaround);

    handle
}

/// Create a hatched brush
pub fn GdiCreateHatchBrush(style: HatchStyle, color: u32) -> u64 {
    let brush = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<GdiBrush>(),
    );

    if brush.is_null() {
        // kprintln!("[win32k] GdiCreateHatchBrush: failed to allocate memory")  // kprintln disabled (memcpy crash workaround);
        return 0;
    }

    unsafe {
        let b = &mut *(brush as *mut GdiBrush);
        let _ = &b;
        *b = GdiBrush::new_hatched(style, color);
    }

    let handle_table = get_handle_table();
    let _ = &handle_table;
    let handle = handle_table.allocate(GdiObjectType::Brush, brush as u64, 0);
    let _ = &handle;

    // kprintln!("[win32k] GdiCreateHatchBrush: style={:?}, color=0x{:08x} -> handle=0x{:016x}",  // kprintln disabled (memcpy crash workaround)
//               style, color, handle);

    handle
}

/// Create a font
pub fn GdiCreateFont(
    height: i32,
    width: i32,
    weight: i32,
    italic: bool,
    face_name: &[u16],
) -> u64 {
    let font = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<GdiFont>(),
    );

    if font.is_null() {
        // kprintln!("[win32k] GdiCreateFont: failed to allocate memory")  // kprintln disabled (memcpy crash workaround);
        return 0;
    }

    unsafe {
        let f = &mut *(font as *mut GdiFont);
        let _ = &f;
        *f = GdiFont::new();
        f.height = height;
        f.width = width;
        f.weight = weight;
        f.italic = if italic { 1 } else { 0 };
        f.set_face_name(face_name);
    }

    let handle_table = get_handle_table();
    let _ = &handle_table;
    let handle = handle_table.allocate(GdiObjectType::Font, font as u64, 0);
    let _ = &handle;

    // kprintln!("[win32k] GdiCreateFont: height={}, weight={} -> handle=0x{:016x}",  // kprintln disabled (memcpy crash workaround)
//               height, weight, handle);

    handle
}

/// Create a bitmap
pub fn GdiCreateBitmap(width: i32, height: i32, bit_count: u16) -> u64 {
    let bitmap = match GdiBitmap::new(width, height, bit_count) {
        Some(b) => b,
        None => {
            // kprintln!("[win32k] GdiCreateBitmap: failed to create bitmap")  // kprintln disabled (memcpy crash workaround);
            return 0;
        }
    };

    let bitmap_mem = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<GdiBitmap>(),
    );

    if bitmap_mem.is_null() {
        // kprintln!("[win32k] GdiCreateBitmap: failed to allocate memory")  // kprintln disabled (memcpy crash workaround);
        return 0;
    }

    unsafe {
        let b = &mut *(bitmap_mem as *mut GdiBitmap);
        let _ = &b;
        *b = bitmap;
    }

    let handle_table = get_handle_table();
    let _ = &handle_table;
    let handle = handle_table.allocate(GdiObjectType::Bitmap, bitmap_mem as u64, 0);
    let _ = &handle;

    // kprintln!("[win32k] GdiCreateBitmap: {}x{}x{} -> handle=0x{:016x}",  // kprintln disabled (memcpy crash workaround)
//               width, height, bit_count, handle);

    handle
}

/// Create a region from a rectangle
pub fn GdiCreateRectRgn(left: i32, top: i32, right: i32, bottom: i32) -> u64 {
    let region = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<GdiRegion>(),
    );

    if region.is_null() {
        // kprintln!("[win32k] GdiCreateRectRgn: failed to allocate memory")  // kprintln disabled (memcpy crash workaround);
        return 0;
    }

    unsafe {
        let r = &mut *(region as *mut GdiRegion);
        let _ = &r;
        *r = GdiRegion::new_rect(&Rect::new(left, top, right, bottom));
    }

    let handle_table = get_handle_table();
    let _ = &handle_table;
    let handle = handle_table.allocate(GdiObjectType::Region, region as u64, 0);
    let _ = &handle;

    // kprintln!("[win32k] GdiCreateRectRgn: ({},{})-({},{}) -> handle=0x{:016x}",  // kprintln disabled (memcpy crash workaround)
//               left, top, right, bottom, handle);

    handle
}

/// Create a palette
pub fn GdiCreatePalette() -> u64 {
    let palette = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<GdiPalette>(),
    );

    if palette.is_null() {
        // kprintln!("[win32k] GdiCreatePalette: failed to allocate memory")  // kprintln disabled (memcpy crash workaround);
        return 0;
    }

    unsafe {
        let p = &mut *(palette as *mut GdiPalette);
        let _ = &p;
        *p = GdiPalette::new();
    }

    let handle_table = get_handle_table();
    let _ = &handle_table;
    let handle = handle_table.allocate(GdiObjectType::Palette, palette as u64, 0);
    let _ = &handle;

    // kprintln!("[win32k] GdiCreatePalette: -> handle=0x{:016x}", handle)  // kprintln disabled (memcpy crash workaround);

    handle
}

// =============================================================================
// GDI Object Deletion Functions
// =============================================================================

/// Delete a GDI object
pub fn GdiDeleteObject(handle: u64) -> bool {
    if handle == 0 {
        return false;
    }

    let handle_table = get_handle_table();
    let _ = &handle_table;
    let entry = match handle_table.get(handle) {
        Some(e) => e,
        None => {
            // kprintln!("[win32k] GdiDeleteObject: invalid handle 0x{:016x}", handle)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };

    let obj_ptr = entry.obj_ptr;
    let _ = &obj_ptr;
    let obj_type = entry.get_type();
    let _ = &obj_type;

    // Free the object memory
    if obj_ptr != 0 {
        match obj_type {
            Some(GdiObjectType::Pen) => {
                let _ = crate::mm::pool::free(obj_ptr as *mut u8);
            }
            Some(GdiObjectType::Brush) => {
                let _ = crate::mm::pool::free(obj_ptr as *mut u8);
            }
            Some(GdiObjectType::Font) => {
                let _ = crate::mm::pool::free(obj_ptr as *mut u8);
            }
            Some(GdiObjectType::Bitmap) => {
                // Bitmap's Drop will free the bits
                let bitmap = unsafe { &mut *(obj_ptr as *mut GdiBitmap) };
                let _ = &bitmap;
                if !bitmap.bits.is_null() {
                    let _ = crate::mm::pool::free(bitmap.bits);
                }
                let _ = crate::mm::pool::free(obj_ptr as *mut u8);
            }
            Some(GdiObjectType::Region) => {
                let _ = crate::mm::pool::free(obj_ptr as *mut u8);
            }
            Some(GdiObjectType::Palette) => {
                let _ = crate::mm::pool::free(obj_ptr as *mut u8);
            }
            _ => {
                let _ = crate::mm::pool::free(obj_ptr as *mut u8);
            }
        }
    }

    // Remove from handle table
    handle_table.free(handle);

    // kprintln!("[win32k] GdiDeleteObject: handle=0x{:016x}, type={:?} deleted", handle, obj_type)  // kprintln disabled (memcpy crash workaround);

    true
}

/// Get object pointer from handle
pub fn GdiGetObjectPtr(handle: u64) -> Option<u64> {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    handle_table.get(handle).map(|e| e.obj_ptr)
}

// =============================================================================
// GDI Object Validation
// =============================================================================

/// Validate a GDI handle and return the entry if valid.
/// Checks:
/// 1. Handle index is within bounds
/// 2. Handle type prefix matches the stored object type
/// 3. Object pointer is non-null
pub fn GdiValidateHandle(handle: u64) -> Option<u64> {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    
    // First check basic validity through the table
    if let Some(entry) = handle_table.get(handle) {
        if entry.obj_ptr != 0 {
            Some(entry.obj_ptr)
        } else {
            // kprintln!("[win32k] GdiValidateHandle: handle=0x{:016x} has null obj_ptr", handle)  // kprintln disabled (memcpy crash workaround);
            None
        }
    } else {
        // kprintln!("[win32k] GdiValidateHandle: handle=0x{:016x} not found or type mismatch", handle)  // kprintln disabled (memcpy crash workaround);
        None
    }
}

/// Validate a GDI handle for a specific process.
/// Windows GDI handles are process-specific - a handle created by one process
/// cannot be used by another process (without proper sharing).
pub fn GdiValidateHandleForProcess(handle: u64, process_id: u32) -> Option<u64> {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    
    if let Some(entry) = handle_table.get(handle) {
        // Check process ownership (0 means kernel/system handle, valid for all)
        if entry.process_id == process_id || entry.process_id == 0 {
            if entry.obj_ptr != 0 {
                return Some(entry.obj_ptr);
            }
        }
        // kprintln!("[win32k] GdiValidateHandleForProcess: handle=0x{:016x}, pid={}, owner={}",  // kprintln disabled (memcpy crash workaround)
//             handle, process_id, entry.process_id);
        None
    } else {
        None
    }
}

/// Check if a handle is valid (exists and type matches)
pub fn GdiIsHandleValid(handle: u64) -> bool {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    handle_table.get(handle).is_some()
}

/// Get object type from handle
pub fn GdiGetObjectType(handle: u64) -> Option<GdiObjectType> {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    handle_table.get(handle).and_then(|e| e.get_type())
}

/// Get handle entry for debugging
pub fn GdiGetHandleEntry(handle: u64) -> Option<GdiHandleEntry> {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    handle_table.get(handle).copied()
}

/// Get pen color
pub fn GdiGetPenColor(handle: u64) -> u32 {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    if let Some(entry) = handle_table.get(handle) {
        if let Some(GdiObjectType::Pen) = entry.get_type() {
            let pen = unsafe { &*(entry.obj_ptr as *const GdiPen) };
            let _ = &pen;
            return pen.color;
        }
    }
    0
}

/// Get pen width
pub fn GdiGetPenWidth(handle: u64) -> i32 {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    if let Some(entry) = handle_table.get(handle) {
        if let Some(GdiObjectType::Pen) = entry.get_type() {
            let pen = unsafe { &*(entry.obj_ptr as *const GdiPen) };
            let _ = &pen;
            return pen.width;
        }
    }
    1 // Default pen width
}

/// Get brush color
pub fn GdiGetBrushColor(handle: u64) -> u32 {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    if let Some(entry) = handle_table.get(handle) {
        if let Some(GdiObjectType::Brush) = entry.get_type() {
            let brush = unsafe { &*(entry.obj_ptr as *const GdiBrush) };
            let _ = &brush;
            return brush.color;
        }
    }
    0
}

// =============================================================================
// Stock Objects (Predefined GDI Objects)
// =============================================================================

/// Stock object handles (Windows system objects)
pub const STOCK_OBJECT_BLACK_BRUSH: u64 = 0x40000004;
pub const STOCK_OBJECT_WHITE_BRUSH: u64 = 0x40000005;
pub const STOCK_OBJECT_HOLLOW_BRUSH: u64 = 0x40000006;
pub const STOCK_OBJECT_BLACK_PEN: u64 = 0x40000007;
pub const STOCK_OBJECT_WHITE_PEN: u64 = 0x40000008;
pub const STOCK_OBJECT_NULL_PEN: u64 = 0x40000009;
pub const STOCK_OBJECT_SYSTEM_FONT: u64 = 0x4000000A;

/// Initialize stock objects
pub fn init_stock_objects() {
    // kprintln!("[win32k] Initializing stock GDI objects...")  // kprintln disabled (memcpy crash workaround);
    
    // Pre-allocate common stock objects
    // These are created once and never deleted
    // The actual handles will be set after handle table is initialized
}

/// Get a stock object
pub fn GdiGetStockObject(object_type: i32) -> u64 {
    match object_type {
        0 => STOCK_OBJECT_BLACK_BRUSH,      // BLACK_BRUSH
        1 => STOCK_OBJECT_WHITE_BRUSH,      // WHITE_BRUSH
        4 => STOCK_OBJECT_BLACK_PEN,        // BLACK_PEN
        5 => STOCK_OBJECT_WHITE_PEN,        // WHITE_PEN
        6 => STOCK_OBJECT_NULL_PEN,         // NULL_PEN
        _ => 0,
    }
}

// =============================================================================
// GDI Object Reference Counting
// =============================================================================

/// Select an object into a DC (increment usage)
pub fn GdiSelectObject(handle: u64) -> bool {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    handle_table.add_ref(handle)
}

/// Unselect an object from a DC (decrement usage)
pub fn GdiUnselectObject(handle: u64) {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    handle_table.release(handle);
}

// =============================================================================
// Debug and Diagnostics
// =============================================================================

/// Dump handle table statistics
pub fn dump_handle_stats() {
    let handle_table = get_handle_table();
    let _ = &handle_table;
    let total = handle_table.entries.len();
    let _ = &total;
    let used = handle_table.entries.iter().filter(|e| e.is_some()).count();
    let _ = &used;
    
    // kprintln!("[win32k] Handle table: {}/{} slots used", used, total)  // kprintln disabled (memcpy crash workaround);
}
