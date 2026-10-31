//! user32 — window class registration (real class table)
//!
//! RegisterClassExW stores a full deep copy of WNDCLASSEXW in
//! the process class table and derives a string atom from the
//! class name; CreateWindowExW looks classes up either by name
//! or by a MAKEINTATOM value in the string-atom range.
//!
//! References:
//!   * MSDN Library "Windows 7" — RegisterClassExW /
//!     UnregisterClassW / GetClassInfoW
//!   * ReactOS win32ss/user/ntuser/class.c

extern crate alloc;

use super::types::*;
// Re-exported so callers reach the class-record type through the
// class module (the smoke harness constructs it directly).
pub use super::types::WndClassExW;
use super::wstr;
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

/// String atoms occupy 0xC000..=0xFFFF (winuser.h atom ranges).
pub const ATOM_STRING_FIRST: u16 = 0xC000;
pub const ATOM_STRING_LAST: u16 = 0xFFFF;

/// Maximum number of window classes per process.
const MAX_CLASSES: usize = 64;

/// Minimum WNDCLASSEXW::cbSize the API accepts (winuser.h).
const WNDCLASSEXW_SIZE: u32 = core::mem::size_of::<WndClassExW>() as u32;

/// cbWndExtra reserved by the system dialog class
/// (winuser.h DLGWINDOWEXTRA).
const DLGWINDOWEXTRA: i32 = 30;

/// Wide name of the system dialog class ("#32770").
pub(crate) const DIALOG_CLASS_NAME: [u16; 7] =
    [0x0023, 0x0033, 0x0032, 0x0037, 0x0037, 0x0030, 0x0000];

/// Signature of a Win32 window procedure (WNDPROC).
pub type WndProcFn = unsafe extern "C" fn(HWND, u32, WPARAM, LPARAM) -> isize;

/// A fully registered window class — a deep copy of everything
/// the caller passed in WNDCLASSEXW.
#[derive(Clone)]
pub struct RegisteredClass {
    pub atom: ATOM,
    pub name: Vec<u16>,
    pub menu_name: Vec<u16>,
    pub wnd_proc: Option<WndProcFn>,
    pub style: u32,
    pub cls_extra: i32,
    pub wnd_extra: i32,
    pub instance: HINSTANCE,
    pub icon: HICON,
    pub cursor: HCURSOR,
    pub background: HBRUSH,
    pub icon_sm: HICON,
    pub is_global: bool,
}

static CLASS_TABLE: Spinlock<Vec<RegisteredClass>> = Spinlock::new(Vec::new());

/// Reinterpret a WNDPROC pointer. Null stays None so proc-less
/// classes fall back to DefWindowProcW.
///
/// SAFETY: callers pass a valid extern "C" wndproc pointer as
/// required by winuser.h; the transmute only reinterprets the
/// pointer representation.
fn wnd_proc_from_ptr(p: *const core::ffi::c_void) -> Option<WndProcFn> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { core::mem::transmute::<*const core::ffi::c_void, WndProcFn>(p) })
}

/// Derive an unused string atom from the class-name hash,
/// skipping collisions, as user32 does for GlobalAddAtom.
fn next_string_atom(table: &[RegisteredClass], hash: u32) -> ATOM {
    let range = (ATOM_STRING_LAST - ATOM_STRING_FIRST + 1) as u32;
    let mut probe = 0u32;
    while probe < range {
        let atom = ATOM_STRING_FIRST + (hash.wrapping_add(probe) % range) as u16;
        if !table.iter().any(|rc| rc.atom == atom) {
            return atom;
        }
        probe += 1;
    }
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// RegisterClassExW — deep-copy the class into the table and
/// return its string atom. Fails with 0 when cbSize is too
/// small, the name is missing/oversized, or the class already
/// exists (ERROR_CLASS_ALREADY_EXISTS).
pub unsafe extern "C" fn register_class_ex_w(class: *const WndClassExW) -> ATOM {
    if class.is_null() {
        return 0;
    }
    let c = &*class;
    if c.cb_size < WNDCLASSEXW_SIZE || c.lpsz_class_name.is_null() {
        return 0;
    }
    let name = wstr::units_of(c.lpsz_class_name);
    if name.is_empty() || name.len() > wstr::MAX_STRING_CHARS {
        return 0;
    }

    let mut table = CLASS_TABLE.lock();
    if table.len() >= MAX_CLASSES || table.iter().any(|rc| rc.name.as_slice() == name.as_slice()) {
        return 0;
    }
    let atom = next_string_atom(&table, wstr::fnv1a_hash(&name));
    if atom == 0 {
        return 0;
    }
    let menu_name = if c.lpsz_menu_name.is_null() {
        Vec::new()
    } else {
        wstr::units_of(c.lpsz_menu_name)
    };
    table.push(RegisteredClass {
        atom,
        name,
        menu_name,
        wnd_proc: wnd_proc_from_ptr(c.lpfn_wnd_proc),
        style: c.style,
        cls_extra: c.cb_cls_extra,
        wnd_extra: c.cb_wnd_extra,
        instance: c.h_instance,
        icon: c.h_icon,
        cursor: c.h_cursor,
        background: c.hbr_background,
        icon_sm: c.h_icon_sm,
        is_global: (c.style & super::window::class::CS_GLOBALCLASS) != 0,
    });
    atom
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// UnregisterClassW — remove the class by name. Fails when the
/// class is unknown, owned by a different instance, or still
/// has open windows (ERROR_CLASS_HAS_WINDOWS).
pub unsafe extern "C" fn unregister_class_w(class_name: LPCWSTR, instance: HINSTANCE) -> BOOL {
    if class_name.is_null() {
        return FALSE;
    }
    let name = wstr::units_of(class_name);
    let mut table = CLASS_TABLE.lock();
    let Some(pos) = table
        .iter()
        .position(|rc| rc.name.as_slice() == name.as_slice())
    else {
        return FALSE;
    };
    if !instance.is_null() && table[pos].instance != instance {
        return FALSE;
    }
    if super::window::has_windows_of_class(table[pos].atom) {
        return FALSE;
    }
    table.remove(pos);
    TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// GetClassInfoW — copy the stored class back into the caller
/// WNDCLASSEXW. Only classes owned by the calling instance (or
/// global classes) are visible, matching the documented
/// per-instance visibility rules.
pub unsafe extern "C" fn get_class_info_w(
    instance: HINSTANCE,
    class_name: LPCWSTR,
    wnd: *mut WndClassExW,
) -> BOOL {
    if class_name.is_null() || wnd.is_null() {
        return FALSE;
    }
    let name = wstr::units_of(class_name);
    let table = CLASS_TABLE.lock();
    let Some(rc) = table
        .iter()
        .find(|rc| rc.name.as_slice() == name.as_slice())
    else {
        return FALSE;
    };
    if !instance.is_null() && !rc.is_global && rc.instance != instance {
        return FALSE;
    }
    let w = &mut *wnd;
    w.cb_size = WNDCLASSEXW_SIZE;
    w.style = rc.style;
    w.lpfn_wnd_proc = match rc.wnd_proc {
        Some(f) => f as usize as *const core::ffi::c_void,
        None => core::ptr::null(),
    };
    w.cb_cls_extra = rc.cls_extra;
    w.cb_wnd_extra = rc.wnd_extra;
    w.h_instance = rc.instance;
    w.h_icon = rc.icon;
    w.h_cursor = rc.cursor;
    w.hbr_background = rc.background;
    w.lpsz_menu_name = if rc.menu_name.is_empty() {
        core::ptr::null()
    } else {
        rc.menu_name.as_ptr()
    };
    w.lpsz_class_name = rc.name.as_ptr();
    w.h_icon_sm = rc.icon_sm;
    TRUE
}

pub(crate) fn lookup_by_name(name: &[u16]) -> Option<RegisteredClass> {
    CLASS_TABLE
        .lock()
        .iter()
        .find(|rc| rc.name.as_slice() == name)
        .cloned()
}

pub(crate) fn lookup_by_atom(atom: ATOM) -> Option<RegisteredClass> {
    CLASS_TABLE
        .lock()
        .iter()
        .find(|rc| rc.atom == atom)
        .cloned()
}

/// Register the classes USER provides system-wide. win32k
/// registers the dialog class ("#32770") during initialisation;
/// dialogs created through DialogBoxW rely on it existing.
pub fn register_system_classes() {
    let mut table = CLASS_TABLE.lock();
    let name = DIALOG_CLASS_NAME.to_vec();
    if table.iter().any(|rc| rc.name.as_slice() == name.as_slice()) {
        return;
    }
    let atom = next_string_atom(&table, wstr::fnv1a_hash(&name));
    if atom == 0 {
        return;
    }
    table.push(RegisteredClass {
        atom,
        name,
        menu_name: Vec::new(),
        wnd_proc: None,
        style: super::window::class::CS_GLOBALCLASS,
        cls_extra: 0,
        wnd_extra: DLGWINDOWEXTRA,
        instance: core::ptr::null_mut(),
        icon: core::ptr::null_mut(),
        cursor: core::ptr::null_mut(),
        background: core::ptr::null_mut(),
        icon_sm: core::ptr::null_mut(),
        is_global: true,
    });
}
