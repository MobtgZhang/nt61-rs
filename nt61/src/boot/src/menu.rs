//! Boot Manager Menu UI
//
//! Windows 7 style boot manager menu structures

use crate::bcd::{BcdStore, BootEntry};

/// Boot menu
pub struct BootMenu<'a> {
    pub(crate) bcd: &'a BcdStore,
    pub(crate) selected_index: usize,
    countdown: u32,
}

impl<'a> BootMenu<'a> {
    pub fn new(bcd: &'a BcdStore) -> Self {
        // Default: highlight the first entry (Windows 7). This is
        // the canonical NT 6.1 boot-manager behaviour: the default
        // entry boots the normal OS into Ring 3; Safe Mode entries
        // are opt-in via the menu.
        Self {
            bcd,
            selected_index: 0,
            countdown: bcd.timeout,
        }
    }

    pub fn selected_index(&self) -> usize {
        self.selected_index
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
}
