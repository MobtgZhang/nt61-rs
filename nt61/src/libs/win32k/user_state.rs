//! Persistent Win32k user-object state.
//!
//! Menus, carets, hot keys, thread messages and deferred window positions are
//! system objects in Windows. Keeping them in one locked state makes syscall
//! behavior consistent across CreateMenu, SetMenu, DestroyWindow and the
//! matching teardown calls.

extern crate alloc;

use crate::ke::sync::Spinlock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotKey {
    pub hwnd: u64,
    pub id: u32,
    pub modifiers: u32,
    pub virtual_key: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Caret {
    pub hwnd: u64,
    pub bitmap: u64,
    pub width: i32,
    pub height: i32,
    pub visible: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct DeferredWindowPosition {
    pub hwnd: u64,
    pub insert_after: u64,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub flags: u32,
}

#[derive(Debug)]
pub struct UserState {
    menus: BTreeMap<u64, MenuEntry>,
    window_menus: BTreeMap<u64, u64>,
    cursors: BTreeMap<u64, CursorEntry>,
    current_cursor: u64,
    carets: BTreeMap<u64, Caret>,
    hot_keys: BTreeMap<(u64, u32), HotKey>,
    event_hooks: BTreeMap<u64, bool>,
    thread_messages: BTreeMap<u32, Vec<ThreadMessage>>,
    deferred_positions: BTreeMap<u64, Vec<DeferredWindowPosition>>,
    deferred_hwnds: Vec<u64>,
    next_deferred_handle: u64,
    active_menu: u64,
    double_click_time: u32,
}

#[derive(Debug)]
pub struct MenuEntry {
    pub popup: bool,
    pub destroyed: bool,
    pub items: Vec<MenuItemEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MenuItemEntry {
    pub flags: u32,
    pub id: u32,
    pub text: Vec<u16>,
    pub submenu: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorEntry {
    pub active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadMessage {
    pub message: u32,
    pub wparam: u64,
    pub lparam: i64,
}

static USER_STATE: Spinlock<UserState> = Spinlock::new(UserState::new());
static NEXT_CURSOR_HANDLE: AtomicU64 = AtomicU64::new(0x0020_0001);

pub const MF_BYPOSITION: u32 = 0x0000_0400;
pub const MF_POPUP: u32 = 0x0000_0010;

impl UserState {
    pub const fn new() -> Self {
        Self {
            menus: BTreeMap::new(),
            window_menus: BTreeMap::new(),
            cursors: BTreeMap::new(),
            current_cursor: 0,
            carets: BTreeMap::new(),
            hot_keys: BTreeMap::new(),
            event_hooks: BTreeMap::new(),
            thread_messages: BTreeMap::new(),
            deferred_positions: BTreeMap::new(),
            deferred_hwnds: Vec::new(),
            next_deferred_handle: 0x000C_0001,
            active_menu: 0,
            double_click_time: 500,
        }
    }

    fn allocate_cursor_handle() -> u64 {
        NEXT_CURSOR_HANDLE.fetch_add(1, Ordering::Relaxed)
    }

    pub fn create_menu(&mut self, handle: u64, popup: bool) -> bool {
        handle != 0
            && self
                .menus
                .insert(
                    handle,
                    MenuEntry {
                        popup,
                        destroyed: false,
                        items: Vec::new(),
                    },
                )
                .is_none()
    }

    pub fn destroy_menu(&mut self, handle: u64) -> bool {
        if self.menus.remove(&handle).is_none() {
            return false;
        }
        self.window_menus.retain(|_, menu| *menu != handle);
        if self.active_menu == handle {
            self.active_menu = 0;
        }
        true
    }

    pub fn append_menu_item(&mut self, handle: u64, flags: u32, id: u32, text: &[u16]) -> bool {
        let Some(entry) = self.menus.get_mut(&handle) else {
            return false;
        };
        if entry.destroyed {
            return false;
        }
        if flags & MF_BYPOSITION != 0 {
            let position = id as usize;
            if position > entry.items.len() {
                return false;
            }
            entry.items.insert(
                position,
                MenuItemEntry {
                    flags,
                    id,
                    text: text.to_vec(),
                    submenu: if flags & MF_POPUP != 0 { id as u64 } else { 0 },
                },
            );
        } else {
            entry.items.push(MenuItemEntry {
                flags,
                id,
                text: text.to_vec(),
                submenu: if flags & MF_POPUP != 0 { id as u64 } else { 0 },
            });
        }
        true
    }

    pub fn delete_menu_item(&mut self, handle: u64, id_or_position: u32, flags: u32) -> bool {
        let Some(entry) = self.menus.get_mut(&handle) else {
            return false;
        };
        if entry.destroyed {
            return false;
        }
        if flags & MF_BYPOSITION != 0 {
            let position = id_or_position as usize;
            if position >= entry.items.len() {
                return false;
            }
            entry.items.remove(position);
        } else {
            match entry
                .items
                .iter()
                .position(|item| item.id == id_or_position)
            {
                Some(position) => {
                    entry.items.remove(position);
                }
                None => return false,
            }
        }
        true
    }

    pub fn set_window_menu(&mut self, hwnd: u64, menu: u64) -> Option<u64> {
        if menu != 0 && !self.menus.contains_key(&menu) {
            return None;
        }
        let previous = self.window_menus.insert(hwnd, menu).unwrap_or(0);
        Some(previous)
    }

    pub fn window_menu(&self, hwnd: u64) -> u64 {
        self.window_menus.get(&hwnd).copied().unwrap_or(0)
    }

    pub fn end_menu(&mut self) -> bool {
        if self.active_menu == 0 {
            return false;
        }
        self.active_menu = 0;
        true
    }

    pub fn set_active_menu(&mut self, menu: u64) {
        self.active_menu = menu;
    }

    pub fn register_hot_key(&mut self, hot_key: HotKey) -> bool {
        if hot_key.hwnd == 0 || hot_key.virtual_key == 0 {
            return false;
        }
        self.hot_keys.insert((hot_key.hwnd, hot_key.id), hot_key);
        true
    }

    pub fn unregister_hot_key(&mut self, hwnd: u64, id: u32) -> bool {
        self.hot_keys.remove(&(hwnd, id)).is_some()
    }

    pub fn set_event_hook(&mut self, handle: u64) -> bool {
        handle != 0 && self.event_hooks.insert(handle, true).is_none()
    }

    pub fn remove_event_hook(&mut self, handle: u64) -> bool {
        self.event_hooks.remove(&handle).is_some()
    }

    pub fn create_cursor(&mut self) -> u64 {
        let handle = Self::allocate_cursor_handle();
        if handle != 0 {
            self.cursors.insert(handle, CursorEntry { active: true });
        }
        handle
    }

    pub fn set_current_cursor(&mut self, handle: u64) -> u64 {
        if handle != 0 && !self.cursors.contains_key(&handle) {
            return self.current_cursor;
        }
        core::mem::replace(&mut self.current_cursor, handle)
    }

    pub fn destroy_cursor(&mut self, handle: u64) -> bool {
        if self.cursors.remove(&handle).is_none() {
            return false;
        }
        if self.current_cursor == handle {
            self.current_cursor = 0;
        }
        true
    }

    pub fn create_caret(&mut self, caret: Caret) -> bool {
        if caret.hwnd == 0 || (caret.width <= 0 && caret.height <= 0 && caret.bitmap == 0) {
            return false;
        }
        self.carets.insert(caret.hwnd, caret).is_none()
    }

    pub fn show_caret(&mut self, hwnd: u64, visible: bool) -> bool {
        match self.carets.get_mut(&hwnd) {
            Some(caret) => {
                caret.visible = visible;
                true
            }
            None => false,
        }
    }

    pub fn destroy_caret(&mut self, hwnd: u64) -> bool {
        self.carets.remove(&hwnd).is_some()
    }

    pub fn post_thread_message(&mut self, thread_id: u32, message: ThreadMessage) -> bool {
        if thread_id == 0 || message.message == 0 {
            return false;
        }
        let queue = self.thread_messages.entry(thread_id).or_default();
        if queue.len() >= 10_000 {
            return false;
        }
        queue.push(message);
        true
    }

    pub fn peek_thread_message(&mut self, thread_id: u32) -> Option<ThreadMessage> {
        let queue = self.thread_messages.get_mut(&thread_id)?;
        if queue.is_empty() {
            return None;
        }
        Some(queue.remove(0))
    }

    pub fn set_double_click_time(&mut self, milliseconds: u32) {
        self.double_click_time = milliseconds.clamp(100, 5_000);
    }

    pub fn double_click_time(&self) -> u32 {
        self.double_click_time
    }

    pub fn defer_window_position(
        &mut self,
        handle: u64,
        position: DeferredWindowPosition,
    ) -> Option<u64> {
        let handle = if handle == 0 {
            let new_handle = self.next_deferred_handle.checked_add(1)?;
            self.next_deferred_handle = new_handle;
            new_handle
        } else {
            handle
        };
        let positions = self.deferred_positions.entry(handle).or_default();
        if positions.iter().any(|entry| entry.hwnd == position.hwnd) {
            return None;
        }
        positions.push(position);
        if !self.deferred_hwnds.contains(&position.hwnd) {
            self.deferred_hwnds.push(position.hwnd);
        }
        Some(handle)
    }

    pub fn end_deferred_positions(&mut self, handle: u64, flags: u32) -> bool {
        let Some(mut positions) = self.deferred_positions.remove(&handle) else {
            return false;
        };
        positions.sort_by_key(|position| {
            self.deferred_hwnds
                .iter()
                .position(|hwnd| *hwnd == position.hwnd)
                .unwrap_or(usize::MAX)
        });
        self.deferred_hwnds
            .retain(|hwnd| !positions.iter().any(|position| position.hwnd == *hwnd));

        for position in &positions {
            if let Some(window) = crate::libs::win32k::window::WINDOW_MANAGER
                .lock()
                .get_window_mut(position.hwnd)
            {
                if flags & 0x0000_0002 == 0 {
                    window.set_rect(position.x, position.y, position.width, position.height);
                }
            }
        }
        true
    }
}

impl Default for UserState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn with_user_state<T>(operation: impl FnOnce(&mut UserState) -> T) -> T {
    let mut state = USER_STATE.lock();
    operation(&mut state)
}

pub fn create_menu(handle: u64, popup: bool) -> bool {
    with_user_state(|state| state.create_menu(handle, popup))
}

pub fn destroy_menu(handle: u64) -> bool {
    with_user_state(|state| state.destroy_menu(handle))
}

pub fn append_menu_item(handle: u64, flags: u32, id: u32, text: &[u16]) -> bool {
    with_user_state(|state| state.append_menu_item(handle, flags, id, text))
}

pub fn delete_menu_item(handle: u64, id_or_position: u32, flags: u32) -> bool {
    with_user_state(|state| state.delete_menu_item(handle, id_or_position, flags))
}

pub fn set_window_menu(hwnd: u64, menu: u64) -> Option<u64> {
    with_user_state(|state| state.set_window_menu(hwnd, menu))
}

pub fn window_menu(hwnd: u64) -> u64 {
    with_user_state(|state| state.window_menu(hwnd))
}

pub fn end_menu() -> bool {
    with_user_state(UserState::end_menu)
}

pub fn register_hot_key(hot_key: HotKey) -> bool {
    with_user_state(|state| state.register_hot_key(hot_key))
}

pub fn unregister_hot_key(hwnd: u64, id: u32) -> bool {
    with_user_state(|state| state.unregister_hot_key(hwnd, id))
}

pub fn set_event_hook(handle: u64) -> bool {
    with_user_state(|state| state.set_event_hook(handle))
}

pub fn remove_event_hook(handle: u64) -> bool {
    with_user_state(|state| state.remove_event_hook(handle))
}

pub fn create_cursor() -> u64 {
    with_user_state(UserState::create_cursor)
}

pub fn set_current_cursor(handle: u64) -> u64 {
    with_user_state(|state| state.set_current_cursor(handle))
}

pub fn current_cursor() -> u64 {
    with_user_state(|state| state.current_cursor)
}

pub fn destroy_cursor(handle: u64) -> bool {
    with_user_state(|state| state.destroy_cursor(handle))
}

pub fn create_caret(caret: Caret) -> bool {
    with_user_state(|state| state.create_caret(caret))
}

pub fn show_caret(hwnd: u64, visible: bool) -> bool {
    with_user_state(|state| state.show_caret(hwnd, visible))
}

pub fn destroy_caret(hwnd: u64) -> bool {
    with_user_state(|state| state.destroy_caret(hwnd))
}

pub fn post_thread_message(thread_id: u32, message: ThreadMessage) -> bool {
    with_user_state(|state| state.post_thread_message(thread_id, message))
}

pub fn peek_thread_message(thread_id: u32) -> Option<ThreadMessage> {
    with_user_state(|state| state.peek_thread_message(thread_id))
}

pub fn double_click_time() -> u32 {
    with_user_state(|state| state.double_click_time())
}

pub fn set_double_click_time(milliseconds: u32) {
    with_user_state(|state| state.set_double_click_time(milliseconds));
}

pub fn defer_window_position(handle: u64, position: DeferredWindowPosition) -> Option<u64> {
    with_user_state(|state| state.defer_window_position(handle, position))
}

pub fn end_deferred_positions(handle: u64, flags: u32) -> bool {
    with_user_state(|state| state.end_deferred_positions(handle, flags))
}
