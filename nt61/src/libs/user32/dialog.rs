//! user32 — Dialog Box Management
//!
//! Dialog box creation and management functions.
//! Dialogs are specialized windows with child controls.
//!
//! References:
//!   * MSDN Library "Windows 7" — Dialog Boxes

use super::types::*;
use super::window::CreateWindowExW;
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


pub unsafe extern "C" fn DialogBoxParamW(
    h_instance: HINSTANCE,
    lp_template_name: *const u16,
    h_wnd_parent: HWND,
    lp_dialog_func: DLGPROC,
    dw_init_param: isize,
) -> isize {
    if lp_template_name.is_null() || lp_dialog_func.is_none() {
        return -1;
    }


    let hwnd = CreateWindowExW(
        0,
        b"#32770\0".as_ptr() as *const u16, // Dialog class
        ptr::null(),
        0x80000000 | 0x00C00000, // WS_POPUP | WS_CAPTION
        100, 100, 300, 200,
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

pub unsafe extern "C" fn DialogBoxIndirectParamW(
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


pub unsafe extern "C" fn CreateDialogParamW(
    h_instance: HINSTANCE,
    lp_template_name: *const u16,
    h_wnd_parent: HWND,
    lp_dialog_func: DLGPROC,
    dw_init_param: isize,
) -> HWND {
    if lp_template_name.is_null() {
        return ptr::null_mut();
    }

    let hwnd = CreateWindowExW(
        0,
        b"#32770\0".as_ptr() as *const u16,
        ptr::null(),
        0x80000000 | 0x00C00000,
        100, 100, 300, 200,
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

pub unsafe extern "C" fn CreateDialogIndirectParamW(
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


pub unsafe extern "C" fn EndDialog(h_dlg: HWND, n_result: isize) -> i32 {
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


pub unsafe extern "C" fn GetDlgItem(h_dlg: HWND, n_id_dlg_item: i32) -> HWND {
    if h_dlg.is_null() {
        return ptr::null_mut();
    }


    let _ = n_id_dlg_item;
    ptr::null_mut()
}

pub unsafe extern "C" fn GetDlgItemInt(
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

pub unsafe extern "C" fn SetDlgItemInt(
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

pub unsafe extern "C" fn GetDlgItemTextW(
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

pub unsafe extern "C" fn SetDlgItemTextW(
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

pub unsafe extern "C" fn CheckDlgButton(
    h_dlg: HWND,
    n_id_button: i32,
    u_check: u32,
) -> i32 {
    if h_dlg.is_null() {
        return 0;
    }

    let _ = (n_id_button, u_check);
    1
}

pub unsafe extern "C" fn IsDlgButtonChecked(h_dlg: HWND, n_id_button: i32) -> u32 {
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
