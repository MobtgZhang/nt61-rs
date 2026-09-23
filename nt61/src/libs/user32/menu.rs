//! user32 — Menu Management
//!
//! Menu creation and manipulation functions.
//! Menus provide command selection interface for applications.
//!
//! References:
//!   * MSDN Library "Windows 7" — Menus

use super::types::*;
use crate::ke::sync::Spinlock;
use core::ptr;


#[repr(C)]
pub struct MENUITEMINFOW {
    pub cb_size: u32,
    pub f_mask: u32,
    pub f_type: u32,
    pub f_state: u32,
    pub w_id: u32,
    pub h_sub_menu: HMENU,
    pub hbmp_checked: HBITMAP,
    pub hbmp_unchecked: HBITMAP,
    pub dw_item_data: usize,
    pub dw_type_data: *mut u16,
    pub cch: u32,
    pub hbmp_item: HBITMAP,
}

struct MenuItem {
    id: u32,
    text: [u16; 256],
    flags: u32,
    submenu: HMENU,
}

impl MenuItem {
    const fn new() -> Self {
        Self {
            id: 0,
            text: [0; 256],
            flags: 0,
            submenu: ptr::null_mut(),
        }
    }
}

struct Menu {
    items: [MenuItem; 64],
    count: usize,
    is_popup: bool,
}

impl Menu {
    const fn new() -> Self {
        Self {
            items: [MenuItem::new(); 64],
            count: 0,
            is_popup: false,
        }
    }
}

const MAX_MENUS: usize = 256;
static MENU_TABLE: Spinlock<[Option<Menu>; MAX_MENUS]> =
    Spinlock::new([None; MAX_MENUS]);


pub unsafe extern "C" fn CreateMenu() -> HMENU {
    let mut table = MENU_TABLE.lock();

    for (i, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            let mut menu = Menu::new();
            menu.is_popup = false;
            *slot = Some(menu);
            return (i + 1) as HMENU;
        }
    }

    ptr::null_mut()
}

pub unsafe extern "C" fn CreatePopupMenu() -> HMENU {
    let mut table = MENU_TABLE.lock();

    for (i, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            let mut menu = Menu::new();
            menu.is_popup = true;
            *slot = Some(menu);
            return (i + 1) as HMENU;
        }
    }

    ptr::null_mut()
}

pub unsafe extern "C" fn DestroyMenu(h_menu: HMENU) -> i32 {
    if h_menu.is_null() {
        return 0;
    }

    let idx = h_menu as usize - 1;
    if idx >= MAX_MENUS {
        return 0;
    }

    let mut table = MENU_TABLE.lock();
    table[idx] = None;
    1
}


pub unsafe extern "C" fn AppendMenuW(
    h_menu: HMENU,
    u_flags: u32,
    u_id_new_item: usize,
    lp_new_item: *const u16,
) -> i32 {
    if h_menu.is_null() {
        return 0;
    }

    let idx = h_menu as usize - 1;
    if idx >= MAX_MENUS {
        return 0;
    }

    let mut table = MENU_TABLE.lock();
    if let Some(ref mut menu) = table[idx] {
        if menu.count >= 64 {
            return 0;
        }

        let mut item = MenuItem::new();
        item.id = u_id_new_item as u32;
        item.flags = u_flags;

        if !lp_new_item.is_null() && (u_flags & 0x0010) == 0 {
            let mut len = 0;
            while len < 255 && *lp_new_item.add(len) != 0 {
                item.text[len] = *lp_new_item.add(len);
                len += 1;
            }
        }

        menu.items[menu.count] = item;
        menu.count += 1;
        return 1;
    }

    0
}

pub unsafe extern "C" fn InsertMenuW(
    h_menu: HMENU,
    u_position: u32,
    u_flags: u32,
    u_id_new_item: usize,
    lp_new_item: *const u16,
) -> i32 {
    if h_menu.is_null() {
        return 0;
    }

    let idx = h_menu as usize - 1;
    if idx >= MAX_MENUS {
        return 0;
    }

    let mut table = MENU_TABLE.lock();
    if let Some(ref mut menu) = table[idx] {
        if menu.count >= 64 {
            return 0;
        }

        let pos = if (u_flags & 0x0400) != 0 {
            u_position as usize
        } else {
            menu.items[..menu.count]
                .iter()
                .position(|item| item.id == u_position)
                .unwrap_or(menu.count)
        };

        if pos > menu.count {
            return 0;
        }

        for i in (pos..menu.count).rev() {
            menu.items[i + 1] = menu.items[i];
        }

        let mut item = MenuItem::new();
        item.id = u_id_new_item as u32;
        item.flags = u_flags;

        if !lp_new_item.is_null() && (u_flags & 0x0010) == 0 {
            let mut len = 0;
            while len < 255 && *lp_new_item.add(len) != 0 {
                item.text[len] = *lp_new_item.add(len);
                len += 1;
            }
        }

        menu.items[pos] = item;
        menu.count += 1;
        return 1;
    }

    0
}

pub unsafe extern "C" fn DeleteMenu(
    h_menu: HMENU,
    u_position: u32,
    u_flags: u32,
) -> i32 {
    if h_menu.is_null() {
        return 0;
    }

    let idx = h_menu as usize - 1;
    if idx >= MAX_MENUS {
        return 0;
    }

    let mut table = MENU_TABLE.lock();
    if let Some(ref mut menu) = table[idx] {
        let pos = if (u_flags & 0x0400) != 0 {
            u_position as usize
        } else {
            menu.items[..menu.count]
                .iter()
                .position(|item| item.id == u_position)
                .unwrap_or(menu.count)
        };

        if pos >= menu.count {
            return 0;
        }

        for i in pos..menu.count - 1 {
            menu.items[i] = menu.items[i + 1];
        }
        menu.count -= 1;
        return 1;
    }

    0
}


pub unsafe extern "C" fn GetMenuItemInfoW(
    h_menu: HMENU,
    u_item: u32,
    f_by_position: i32,
    lpmii: *mut MENUITEMINFOW,
) -> i32 {
    if h_menu.is_null() || lpmii.is_null() {
        return 0;
    }

    let _ = (u_item, f_by_position);
    0
}

pub unsafe extern "C" fn SetMenuItemInfoW(
    h_menu: HMENU,
    u_item: u32,
    f_by_position: i32,
    lpmii: *const MENUITEMINFOW,
) -> i32 {
    if h_menu.is_null() || lpmii.is_null() {
        return 0;
    }

    let _ = (u_item, f_by_position);
    1
}


pub unsafe extern "C" fn TrackPopupMenu(
    h_menu: HMENU,
    u_flags: u32,
    x: i32,
    y: i32,
    n_reserved: i32,
    h_wnd: HWND,
    prc_rect: *const super::window::RECT,
) -> i32 {
    if h_menu.is_null() || h_wnd.is_null() {
        return 0;
    }

    let _ = (u_flags, x, y, n_reserved, prc_rect);
    0
}


pub mod mf {
    pub const MF_INSERT: u32 = 0x0000;
    pub const MF_CHANGE: u32 = 0x0080;
    pub const MF_APPEND: u32 = 0x0100;
    pub const MF_DELETE: u32 = 0x0200;
    pub const MF_REMOVE: u32 = 0x1000;
    pub const MF_BYCOMMAND: u32 = 0x0000;
    pub const MF_BYPOSITION: u32 = 0x0400;
    pub const MF_SEPARATOR: u32 = 0x0800;
    pub const MF_ENABLED: u32 = 0x0000;
    pub const MF_GRAYED: u32 = 0x0001;
    pub const MF_DISABLED: u32 = 0x0002;
    pub const MF_UNCHECKED: u32 = 0x0000;
    pub const MF_CHECKED: u32 = 0x0008;
    pub const MF_STRING: u32 = 0x0000;
    pub const MF_BITMAP: u32 = 0x0004;
    pub const MF_OWNERDRAW: u32 = 0x0100;
    pub const MF_POPUP: u32 = 0x0010;
    pub const MF_MENUBARBREAK: u32 = 0x0020;
    pub const MF_MENUBREAK: u32 = 0x0040;
}
