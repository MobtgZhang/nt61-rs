//! gdi32 — Win32 graphics device interface
//!
//! NT 6.1 GDI surface. `gdi32` is the user-mode wrapper over
//! `win32k`; every handle that an application sees is a
//! `gdi32!Hxxx` value, which maps to a kernel-side object
//! (a real surface, pen, brush, …) that lives inside
//! `libs::win32k`.
//!
//! ## Handle table
//!
//! The `gdi32` library keeps its own bookkeeping table of
//! handles it has handed out (`GDI_OBJECT_TABLE`). The slot
//! index of a handle is encoded in the low bits of the
//! pointer (`0x0000_DEAD_0000_0000 + idx`). The handle
//! table is fully owned by `gdi32` — the kernel does not
//! look at it directly; kernel-side `win32k` state is
//! created through the `libs::win32k` API and referenced
//! by `*mut` / `u64` payloads stored next to the handle.
//!
//! ## Module layout
//!   * `types`     — GDI handles / structs
//!   * `dc`        — device context APIs
//!   * `paint`     — pat_blt / fill_rect / invalidate_rect
//!   * `text`      — text_out_w / draw_text_w / get_text_extent_point32_w
//!   * `pen_brush` — create_pen / create_solid_brush / select_object / delete_object
//!   * `smoke`     — module-level smoke test
//!
//! References:
//!   * MSDN Library "Windows 7" — gdi32.dll
//!   * ReactOS 0.3.x `win32ss/gdi/eng`
//!   * Wine 1.7.x `dlls/gdi32/gdi32.spec`

extern crate alloc;

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

pub mod dc;
pub mod paint;
pub mod pen_brush;
pub mod text;
pub mod types;

/// Tag identifying what kind of object a handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdiObjectKind {
    /// Device context (HDC). The `DC` payload owns the
    /// selected pen / brush / font / colour and the surface
    /// pointer that all `pat_blt` / `text_out_w` calls end
    /// up writing to.
    DC,
    /// Pen (HPEN). The `Pen` payload stores the style, width
    /// and colour.
    Pen,
    /// Solid / hatched brush (HBRUSH). The `Brush` payload
    /// stores the hatch style and colour.
    Brush,
    /// Font (HFONT). The `Font` payload stores the LOGFONTW
    /// that was used to build the font.
    Font,
    /// Bitmap (HBITMAP). The `Bitmap` payload stores the
    /// `win32k::BitmapInfoHeader` and the surface pointer.
    Bitmap,
}

/// Pen payload (subset of LOGPEN).
#[derive(Debug, Clone, Copy)]
pub struct PenObject {
    pub style: i32,
    pub width: i32,
    pub color: u32,
}

/// Brush payload (subset of LOGBRUSH).
#[derive(Debug, Clone, Copy)]
pub struct BrushObject {
    pub hatch: i32,
    pub color: u32,
    pub is_null: bool,
}

/// Font payload (subset of LOGFONTW).
#[derive(Debug, Clone, Copy)]
pub struct FontObject {
    pub height: i32,
    pub width: i32,
    pub weight: i32,
    pub italic: bool,
    pub underline: bool,
    pub strike_out: bool,
    pub char_set: u8,
    pub face_name: [u16; 32],
}

/// Bitmap payload.
#[derive(Debug, Clone, Copy)]
pub struct BitmapObject {
    pub width: i32,
    pub height: i32,
    pub bit_count: u16,
    pub bits: u64,
}

/// DC payload — owned per-DC state (mirrors `win32k::DCState`).
#[derive(Debug, Clone, Copy)]
pub struct DcObject {
    pub pen: u64,
    pub brush: u64,
    pub font: u64,
    pub text_color: u32,
    pub bk_color: u32,
    pub bk_mode: u32,
    pub rop: u32,
    pub surface: u64,
    /// Saved-DC state stack (`save_dc` pushes, `restore_dc`
    /// pops). 8 deep, which matches the documented Windows
    /// limit.
    pub saved_stack: [(u64, u64, u64, u32, u32, u32, u32, u64); 8],
    pub saved_top: usize,
}

impl DcObject {
    pub const fn empty() -> Self {
        Self {
            pen: 0,
            brush: 0,
            font: 0,
            text_color: 0x0000_0000,
            bk_color: 0x00FF_FFFF,
            bk_mode: 2,       // OPAQUE
            rop: 0x00CC_0020, // SRCCOPY
            surface: 0,
            saved_stack: [(0, 0, 0, 0, 0, 0, 0, 0); 8],
            saved_top: 0,
        }
    }
}

/// One entry in the GDI object table.
#[derive(Debug, Clone, Copy)]
pub struct GdiObject {
    pub kind: GdiObjectKind,
    pub payload: GdiObjectPayload,
}

/// Tagged union of all payloads that can sit behind a GDI
/// handle. `Copy` because the table itself never escapes
/// the `gdi32` module.
#[derive(Debug, Clone, Copy)]
pub enum GdiObjectPayload {
    None,
    DC(DcObject),
    Pen(PenObject),
    Brush(BrushObject),
    Font(FontObject),
    Bitmap(BitmapObject),
}

impl GdiObjectPayload {
    pub const fn dc() -> Self {
        GdiObjectPayload::DC(DcObject::empty())
    }
}

impl GdiObject {
    pub const fn none() -> Self {
        Self {
            kind: GdiObjectKind::DC,
            payload: GdiObjectPayload::None,
        }
    }
}

/// Handle base for gdi32!Hxxx values. We choose a value
/// that is unambiguously not a valid pointer in the
/// kernel half of the address space (`0x0000_DEAD_...`)
/// so an erroneous direct dereference faults cleanly
/// instead of silently aliasing something else.
pub const GDI_HANDLE_BASE: u64 = 0x0000_DEAD_0000_0000;

/// The bookkeeping table itself. The slot at index `i`
/// holds the object behind handle `GDI_HANDLE_BASE + i`.
///
/// The vector grows on demand; on a 64-bit machine a
/// `Vec` is fine because we have a 64-byte cache line and
/// each entry is small. We never compact, so any handle
/// that has been handed out stays valid for the life of
/// the kernel.
pub static GDI_OBJECT_TABLE: Spinlock<Vec<Option<GdiObject>>> = Spinlock::new(Vec::new());

/// Legacy handle list — used by `has_gdi_handle` /
/// `alloc_gdi_handle` (the `smoke` test reads these).
pub static GDI_OBJECTS: Spinlock<Vec<u64>> = Spinlock::new(Vec::new());

/// Allocate a placeholder GDI handle. Maintained for
/// backward compatibility with the original `gdi32`
/// smoke tests; new code should call
/// `register_object` directly.
pub fn alloc_gdi_handle() -> u64 {
    let mut t = GDI_OBJECTS.lock();
    let h = GDI_HANDLE_BASE + t.len() as u64;
    t.push(h);
    h
}

/// Look up a GDI handle; returns true if it exists.
pub fn has_gdi_handle(h: u64) -> bool {
    GDI_OBJECTS.lock().iter().any(|x| *x == h)
}

/// Register a new object in the table and return the
/// handle value the caller should hand out. The new
/// entry occupies the next free slot.
pub fn register_object(obj: GdiObject) -> u64 {
    let mut t = GDI_OBJECTS.lock();
    let h = GDI_HANDLE_BASE + t.len() as u64;
    t.push(h);

    let mut table = GDI_OBJECT_TABLE.lock();
    // Ensure the inner table is at least `len()` long.
    while table.len() < t.len() {
        table.push(None);
    }
    table.push(Some(obj));
    h
}

/// Look up an object by handle. Returns `None` if the
/// handle is unknown or has been deleted.
pub fn lookup_object(h: u64) -> Option<GdiObject> {
    if h < GDI_HANDLE_BASE {
        return None;
    }
    let idx = (h - GDI_HANDLE_BASE) as usize;
    let table = GDI_OBJECT_TABLE.lock();
    table.get(idx).and_then(|slot| *slot)
}

/// Apply `f` to a mutable copy of the object behind `h`
/// and write the result back. Returns `true` if the
/// handle was known.
pub fn mutate_object<F: FnOnce(&mut GdiObject)>(h: u64, f: F) -> bool {
    if h < GDI_HANDLE_BASE {
        return false;
    }
    let idx = (h - GDI_HANDLE_BASE) as usize;
    let mut table = GDI_OBJECT_TABLE.lock();
    if let Some(slot) = table.get_mut(idx) {
        if let Some(ref mut obj) = slot {
            f(obj);
            return true;
        }
    }
    false
}

/// Remove an object from the table. The slot is left as
/// `None` so that re-issued indices never alias a
/// deleted object.
pub fn remove_object(h: u64) -> bool {
    if h < GDI_HANDLE_BASE {
        return false;
    }
    let idx = (h - GDI_HANDLE_BASE) as usize;
    let mut table = GDI_OBJECT_TABLE.lock();
    if let Some(slot) = table.get_mut(idx) {
        if slot.is_some() {
            *slot = None;
            return true;
        }
    }
    false
}

/// Look up a mutable copy of the DC behind `h` and pass
/// it to `f`. Returns `true` if the handle refers to a
/// live `DC` object. The closure receives the inner
/// `DcObject` by `&mut`; mutations are written back
/// before the lock is released.
pub fn with_dc_mut<F: FnOnce(&mut DcObject)>(h: u64, f: F) -> bool {
    if h < GDI_HANDLE_BASE {
        return false;
    }
    let idx = (h - GDI_HANDLE_BASE) as usize;
    let mut table = GDI_OBJECT_TABLE.lock();
    if let Some(slot) = table.get_mut(idx) {
        if let Some(ref mut obj) = slot {
            if let GdiObjectPayload::DC(ref mut dc) = obj.payload {
                f(dc);
                return true;
            }
        }
    }
    false
}

/// Read-only variant of `with_dc_mut`.
pub fn with_dc<F: FnOnce(&DcObject)>(h: u64, f: F) -> bool {
    if h < GDI_HANDLE_BASE {
        return false;
    }
    let idx = (h - GDI_HANDLE_BASE) as usize;
    let table = GDI_OBJECT_TABLE.lock();
    if let Some(slot) = table.get(idx) {
        if let Some(ref obj) = *slot {
            if let GdiObjectPayload::DC(ref dc) = obj.payload {
                f(dc);
                return true;
            }
        }
    }
    false
}

/// Initialise the gdi32 stub.
pub fn init() {
    // kprintln!("    [gdi32] init");
    // kprintln!("      dc        : get_dc/release_dc/create_compatible_dc/delete_dc");
    // kprintln!("      paint     : pat_blt/fill_rect/invalidate_rect");
    // kprintln!("      text      : text_out_w/draw_text_w/get_text_extent_point32_w");
    // kprintln!("      pen_brush : create_pen/create_solid_brush/select_object/delete_object");
    // kprintln!("    [gdi32] ready");
}

pub mod smoke;
pub use smoke::smoke_test as run_smoke;
