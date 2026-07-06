//! Boot Manager Menu UI
//
//! Windows 7 style boot manager menu structures

use crate::bcd::{BcdStore, BootEntry};

/// Menu state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MenuState {
    Normal,
    Advanced,
    Tools,
    Exit,
}

/// Which area of the main screen is currently focused.
///
/// The real Windows 7 bootmgr has two highlightable regions on its
/// main screen — the OS list and the (single) Tools entry. The Tab
/// key toggles between them, mirroring the JS reference
/// (`focusArea = (focusArea === 'os') ? 'tool' : 'os'` in
/// `windows-boot-manager.html`). The `selected_index` only has a
/// visible effect when the focus is on `Os`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FocusArea {
    Os,
    Tool,
}

/// Boot menu
pub struct BootMenu<'a> {
    pub(crate) bcd: &'a BcdStore,
    pub(crate) selected_index: usize,
    #[allow(dead_code)]
    state: MenuState,
    #[allow(dead_code)]
    focus: FocusArea,
    countdown: u32,
    #[allow(dead_code)]
    max_countdown: u32,
}

impl<'a> BootMenu<'a> {
    pub fn new(bcd: &'a BcdStore) -> Self {
        // Default: highlight the second entry (Safe Mode - CMD).
        // The user wants Safe Mode CMD as default for testing.
        Self {
            bcd,
            selected_index: 1,
            state: MenuState::Normal,
            focus: FocusArea::Os,
            countdown: bcd.timeout,
            max_countdown: bcd.timeout,
        }
    }

    pub fn selected_index(&self) -> usize {
        self.selected_index
    }
    #[allow(dead_code)]
    pub fn state(&self) -> MenuState {
        self.state
    }

    /// Which area of the main screen is currently highlighted.
    #[allow(dead_code)]
    pub fn focus_area(&self) -> FocusArea {
        self.focus
    }

    /// Switch the highlight from the OS list to the Tools entry or
    /// back. Mirrors the Tab-key behavior in the reference HTML.
    #[allow(dead_code)]
    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            FocusArea::Os => FocusArea::Tool,
            FocusArea::Tool => FocusArea::Os,
        };
    }

    pub fn countdown(&self) -> u32 {
        self.countdown
    }

    pub fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn move_down(&mut self) {
        let max = self.bcd.entry_count.saturating_sub(1);
        if self.selected_index < max {
            self.selected_index += 1;
        }
    }

    /// Stop the auto-boot countdown. After this, `countdown()` returns `None`
    /// until `reset_countdown()` is called.
    pub fn cancel_auto(&mut self) {
        self.countdown = 0;
    }

    /// True while the auto-boot countdown is still running.
    pub fn is_counting(&self) -> bool {
        self.countdown > 0
    }

    pub fn select(&self) -> Option<&BootEntry> {
        self.bcd.get_entry(self.selected_index)
    }

    pub fn tick(&mut self) -> bool {
        if self.countdown > 0 {
            self.countdown -= 1;
            self.countdown == 0
        } else {
            true
        }
    }
    #[allow(dead_code)]
    pub fn reset_countdown(&mut self) {
        self.countdown = self.max_countdown;
    }
    #[allow(dead_code)]
    pub fn set_state(&mut self, state: MenuState) {
        self.state = state;
        self.reset_countdown();
    }
    #[allow(dead_code)]
    pub fn entry_count(&self) -> usize {
        self.bcd.entry_count
    }
}

/// Menu actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MenuAction {
    Refresh,
    Boot,
    Exit,
    Advanced,
    Tools,
}

/// Key codes for keyboard input
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum KeyCode {
    Up,
    Down,
    Enter,
    Escape,
    F8,
    Tab,
    Other,
}

/// Parse key from UEFI scan code
#[allow(dead_code)]
pub fn parse_key(scan_code: u8, unicode: u16) -> KeyCode {
    match scan_code {
        0x01 => KeyCode::Escape,
        0x04 => KeyCode::Up,
        0x05 => KeyCode::Down,
        0x06 => KeyCode::Tab,
        0x0D => KeyCode::Enter,
        0x15 => KeyCode::F8,
        _ => {
            if unicode == 0x0D || unicode == 0x0A {
                KeyCode::Enter
            } else if unicode == 0x1B {
                KeyCode::Escape
            } else {
                KeyCode::Other
            }
        }
    }
}

/// Handle key input
#[allow(dead_code)]
pub fn handle_key(key: KeyCode, menu: &mut BootMenu) -> Option<MenuAction> {
    match key {
        KeyCode::Up => {
            menu.move_up();
            Some(MenuAction::Refresh)
        }
        KeyCode::Down => {
            menu.move_down();
            Some(MenuAction::Refresh)
        }
        KeyCode::Enter => Some(MenuAction::Boot),
        KeyCode::Escape => Some(MenuAction::Exit),
        KeyCode::F8 => Some(MenuAction::Advanced),
        KeyCode::Tab => Some(MenuAction::Tools),
        KeyCode::Other => None,
    }
}
