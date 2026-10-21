//! user32 — Dialog Box Management
//!
//! Dialog box creation and management functions.
//! Dialogs are specialized windows with child controls.
//!
//! References:
//!   * MSDN Library "Windows 7" — Dialog Boxes

use super::types::*;
use super::window::create_window_ex_w;
use crate::ke::sync::Spinlock;
use core::ptr;

#[repr(C, packed)]
pub struct DLGTEMPLATE {
    pub style: u32,
    pub dw_extended_style: u32,
    pub cdit: u16,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
}

#[repr(C, packed)]
pub struct DLGITEMTEMPLATE {
    pub style: u32,
    pub dw_extended_style: u32,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
    pub id: u16,
}

#[derive(Copy, Clone)]
struct DialogState {
    hwnd: HWND,
    proc: DLGPROC,
    active: bool,
}

impl DialogState {
    const fn new() -> Self {
        Self {
            hwnd: ptr::null_mut(),
            proc: None,
            active: false,
        }
    }
}

const MAX_DIALOGS: usize = 32;
static DIALOG_TABLE: Spinlock<[DialogState; MAX_DIALOGS]> =
    Spinlock::new([DialogState::new(); MAX_DIALOGS]);

pub type DLGPROC = Option<unsafe extern "C" fn(HWND, u32, usize, isize) -> isize>;

pub unsafe extern "C" fn dialog_box_param_w(
    h_instance: HINSTANCE,
    lp_template_name: *const u16,
    h_wnd_parent: HWND,
    lp_dialog_func: DLGPROC,
    dw_init_param: isize,
) -> isize {
    if lp_template_name.is_null() || lp_dialog_func.is_none() {
        return -1;
    }

    let hwnd = create_window_ex_w(
        0,
        super::class::DIALOG_CLASS_NAME.as_ptr(),
        ptr::null(),
        super::window::ws::WS_POPUP | super::window::ws::WS_CAPTION,
        100,
        100,
        300,
        200,
        h_wnd_parent,
        ptr::null_mut(),
        h_instance,
        ptr::null_mut(),
    );

    if hwnd.is_null() {
        return -1;
    }

    let mut table = DIALOG_TABLE.lock();
    let slot = table.iter_mut().find(|d| !d.active);
    if let Some(dlg) = slot {
        dlg.hwnd = hwnd;
        dlg.proc = lp_dialog_func;
        dlg.active = true;
    }
    drop(table);

    if let Some(proc) = lp_dialog_func {
        proc(hwnd, 0x0110, 0, dw_init_param); // WM_INITDIALOG
    }

    let result = 0;

    let mut table = DIALOG_TABLE.lock();
    for dlg in table.iter_mut() {
        if dlg.hwnd == hwnd {
            dlg.active = false;
            break;
        }
    }

    result
}

pub unsafe extern "C" fn dialog_box_indirect_param_w(
    h_instance: HINSTANCE,
    h_dialog_template: *const DLGTEMPLATE,
    h_wnd_parent: HWND,
    lp_dialog_func: DLGPROC,
    dw_init_param: isize,
) -> isize {
    if h_dialog_template.is_null() || lp_dialog_func.is_none() {
        return -1;
    }

    let template = &*h_dialog_template;
    let _ = (h_instance, h_wnd_parent, dw_init_param, template);

    0
}

pub unsafe extern "C" fn create_dialog_param_w(
    h_instance: HINSTANCE,
    lp_template_name: *const u16,
    h_wnd_parent: HWND,
    lp_dialog_func: DLGPROC,
    dw_init_param: isize,
) -> HWND {
    if lp_template_name.is_null() {
        return ptr::null_mut();
    }

    let hwnd = create_window_ex_w(
        0,
        super::class::DIALOG_CLASS_NAME.as_ptr(),
        ptr::null(),
        super::window::ws::WS_POPUP | super::window::ws::WS_CAPTION,
        100,
        100,
        300,
        200,
        h_wnd_parent,
        ptr::null_mut(),
        h_instance,
        ptr::null_mut(),
    );

    if hwnd.is_null() {
        return ptr::null_mut();
    }

    let mut table = DIALOG_TABLE.lock();
    let slot = table.iter_mut().find(|d| !d.active);
    if let Some(dlg) = slot {
        dlg.hwnd = hwnd;
        dlg.proc = lp_dialog_func;
        dlg.active = true;
    }
    drop(table);

    if let Some(proc) = lp_dialog_func {
        proc(hwnd, 0x0110, 0, dw_init_param);
    }

    hwnd
}

pub unsafe extern "C" fn create_dialog_indirect_param_w(
    h_instance: HINSTANCE,
    lp_template: *const DLGTEMPLATE,
    h_wnd_parent: HWND,
    lp_dialog_func: DLGPROC,
    dw_init_param: isize,
) -> HWND {
    if lp_template.is_null() {
        return ptr::null_mut();
    }

    let _ = (h_instance, h_wnd_parent, lp_dialog_func, dw_init_param);
    ptr::null_mut()
}

pub unsafe extern "C" fn end_dialog(h_dlg: HWND, n_result: isize) -> i32 {
    if h_dlg.is_null() {
        return 0;
    }

    let mut table = DIALOG_TABLE.lock();
    for dlg in table.iter_mut() {
        if dlg.hwnd == h_dlg {
            dlg.active = false;
            break;
        }
    }

    let _ = n_result;
    1
}

pub unsafe extern "C" fn get_dlg_item(h_dlg: HWND, n_id_dlg_item: i32) -> HWND {
    if h_dlg.is_null() {
        return ptr::null_mut();
    }

    let _ = n_id_dlg_item;
    ptr::null_mut()
}

pub unsafe extern "C" fn get_dlg_item_int(
    h_dlg: HWND,
    n_id_dlg_item: i32,
    lp_translated: *mut i32,
    b_signed: i32,
) -> u32 {
    if h_dlg.is_null() {
        return 0;
    }

    let _ = (n_id_dlg_item, b_signed);

    if !lp_translated.is_null() {
        *lp_translated = 1;
    }

    0
}

pub unsafe extern "C" fn set_dlg_item_int(
    h_dlg: HWND,
    n_id_dlg_item: i32,
    u_value: u32,
    b_signed: i32,
) -> i32 {
    if h_dlg.is_null() {
        return 0;
    }

    let _ = (n_id_dlg_item, u_value, b_signed);
    1
}

pub unsafe extern "C" fn get_dlg_item_text_w(
    h_dlg: HWND,
    n_id_dlg_item: i32,
    lp_string: *mut u16,
    n_max_count: i32,
) -> u32 {
    if h_dlg.is_null() || lp_string.is_null() {
        return 0;
    }

    let _ = (n_id_dlg_item, n_max_count);

    *lp_string = 0;
    0
}

pub unsafe extern "C" fn set_dlg_item_text_w(
    h_dlg: HWND,
    n_id_dlg_item: i32,
    lp_string: *const u16,
) -> i32 {
    if h_dlg.is_null() || lp_string.is_null() {
        return 0;
    }

    let _ = n_id_dlg_item;
    1
}

pub unsafe extern "C" fn check_dlg_button(h_dlg: HWND, n_id_button: i32, u_check: u32) -> i32 {
    if h_dlg.is_null() {
        return 0;
    }

    let _ = (n_id_button, u_check);
    1
}

pub unsafe extern "C" fn is_dlg_button_checked(h_dlg: HWND, n_id_button: i32) -> u32 {
    if h_dlg.is_null() {
        return 0;
    }

    let _ = n_id_button;
    0
}

pub mod dm {
    pub const DM_GETDEFID: u32 = 0x0400;
    pub const DM_SETDEFID: u32 = 0x0401;
    pub const DM_REPOSITION: u32 = 0x0402;
}

pub mod wm {
    pub const WM_INITDIALOG: u32 = 0x0110;
    pub const WM_COMMAND: u32 = 0x0111;
}

/// MessageBoxW button sets, icons, default buttons and modality
/// (winuser.h MB_*), kept as masks so `kind` can be decoded.
pub mod mb {
    pub const MB_KIND_MASK: u32 = 0x0000_000F;
    pub const MB_ICON_MASK: u32 = 0x0000_00F0;
    pub const MB_DEFBUTTON_MASK: u32 = 0x0000_0300;
    pub const MB_MODALITY_MASK: u32 = 0x0000_3000;

    pub const MB_OK: u32 = 0x0000_0000;
    pub const MB_OKCANCEL: u32 = 0x0000_0001;
    pub const MB_ABORTRETRYIGNORE: u32 = 0x0000_0002;
    pub const MB_YESNOCANCEL: u32 = 0x0000_0003;
    pub const MB_YESNO: u32 = 0x0000_0004;
    pub const MB_RETRYCANCEL: u32 = 0x0000_0005;
    pub const MB_CANCELTRYCONTINUE: u32 = 0x0000_0006;

    pub const MB_ICONERROR: u32 = 0x0000_0010;
    pub const MB_ICONQUESTION: u32 = 0x0000_0020;
    pub const MB_ICONWARNING: u32 = 0x0000_0030;
    pub const MB_ICONINFORMATION: u32 = 0x0000_0040;

    pub const MB_DEFBUTTON1: u32 = 0x0000_0000;
    pub const MB_DEFBUTTON2: u32 = 0x0000_0100;
    pub const MB_DEFBUTTON3: u32 = 0x0000_0200;
    pub const MB_DEFBUTTON4: u32 = 0x0000_0300;

    pub const MB_APPLMODAL: u32 = 0x0000_0000;
    pub const MB_SYSTEMMODAL: u32 = 0x0000_1000;
    pub const MB_TASKMODAL: u32 = 0x0000_2000;
}

/// MessageBoxW return codes (winuser.h ID*).
pub mod id {
    pub const IDOK: i32 = 1;
    pub const IDCANCEL: i32 = 2;
    pub const IDABORT: i32 = 3;
    pub const IDRETRY: i32 = 4;
    pub const IDIGNORE: i32 = 5;
    pub const IDYES: i32 = 6;
    pub const IDNO: i32 = 7;
    pub const IDCLOSE: i32 = 8;
    pub const IDTRYAGAIN: i32 = 10;
    pub const IDCONTINUE: i32 = 11;
}

/// Decoded MessageBoxW parameters — the four flag groups
/// winuser.h packs into the `uType` argument.
#[derive(Debug, Clone, Copy)]
pub struct MessageBoxParams {
    pub buttons: u32,
    pub icon: u32,
    pub default_button: u32,
    pub modality: u32,
}

impl MessageBoxParams {
    /// Decode the packed `uType` value of MessageBoxW.
    pub const fn from_type(kind: UINT) -> Self {
        Self {
            buttons: kind & mb::MB_KIND_MASK,
            icon: kind & mb::MB_ICON_MASK,
            default_button: kind & mb::MB_DEFBUTTON_MASK,
            modality: kind & mb::MB_MODALITY_MASK,
        }
    }
}

/// MessageBoxW — there is no windowing surface yet, so the box
/// is rendered into the boot log with its full decoded
/// parameter set and dismissed with IDOK, the default result of
/// an MB_OK box.
pub unsafe extern "C" fn message_box_w(
    h_wnd: HWND,
    lp_text: LPCWSTR,
    lp_caption: LPCWSTR,
    u_type: UINT,
) -> i32 {
    let _ = h_wnd;
    let params = MessageBoxParams::from_type(u_type);
    let text = super::wstr::to_utf8_lossy(&super::wstr::units_of(lp_text));
    let caption = super::wstr::to_utf8_lossy(&super::wstr::units_of(lp_caption));
    crate::kprintln!(
        "[user32] MessageBoxW caption=\"{}\" text=\"{}\" buttons={:#06x} icon={:#06x} default={:#06x} modality={:#06x} -> IDOK",
        caption,
        text,
        params.buttons,
        params.icon,
        params.default_button,
        params.modality
    );
    id::IDOK
}
