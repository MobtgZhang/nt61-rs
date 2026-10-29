//! UEFI keyboard input for the Boot Manager.

use alloc::vec::Vec;
use core::time::Duration;
use uefi::boot::{EventType, ScopedProtocol, TimerTrigger, Tpl};
use uefi::data_types::Event;
use uefi::proto::console::text::{Input, Key, ScanCode};
use uefi::proto::unsafe_protocol;

/// EFI Simple Text Input Ex protocol GUID.
const SIMPLE_TEXT_INPUT_EX_GUID: uefi::Guid = uefi::guid!("dd9e7534-7762-4698-8c14-f58517a625aa");

/// Minimal definition of `EFI_KEY_DATA`.
///
/// The EDK2 firmware on RISC-V and LoongArch writes `ScanCode` at offset 0
/// and `UnicodeChar` at offset 2 (matching the `uefi-raw` `InputKey` layout),
/// which is the reverse of the UEFI 2.10 specification's field order for
/// `EFI_INPUT_KEY`. Both fields are still `u16` so the struct size and
/// alignment are unchanged; only the byte offset of each field differs.
#[repr(C)]
struct ExKeyData {
    scan_code: u16,
    unicode_char: uefi::Char16,
    shift_state: u32,
    toggle_state: u32,
}

/// Minimal definition of `EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL`.
#[repr(C)]
struct SimpleTextInputExProtocol {
    reset: unsafe extern "efiapi" fn(this: *mut Self, extended_verification: bool) -> uefi::Status,
    read_key_stroke_ex:
        unsafe extern "efiapi" fn(this: *mut Self, key: *mut ExKeyData) -> uefi::Status,
    wait_for_key_ex: Event,
}

impl SimpleTextInputExProtocol {
    const GUID: uefi::Guid = SIMPLE_TEXT_INPUT_EX_GUID;
}

/// Wrapper for the extended UEFI keyboard protocol.
#[unsafe_protocol(SimpleTextInputExProtocol::GUID)]
pub struct InputEx(SimpleTextInputExProtocol);

impl InputEx {
    fn reset(&mut self, extended_verification: bool) -> bool {
        // SAFETY: `this` points to the exclusive protocol instance.
        unsafe { (self.0.reset)(&mut self.0, extended_verification) == uefi::Status::SUCCESS }
    }

    fn read_key(&mut self) -> Option<Key> {
        let mut key = ExKeyData {
            unicode_char: uefi::Char16::try_from(0u16).ok()?,
            scan_code: 0,
            shift_state: 0,
            toggle_state: 0,
        };
        let status = unsafe { (self.0.read_key_stroke_ex)(&mut self.0, &mut key) };
        if status != uefi::Status::SUCCESS {
            return None;
        }
        raw_key_to_key(key.unicode_char, key.scan_code)
    }

    fn wait_for_key_event(&self) -> Option<Event> {
        // SAFETY: The firmware guarantees that this event pointer is valid
        // while the protocol remains open.
        Some(unsafe { self.0.wait_for_key_ex.unsafe_clone() })
    }
}

fn raw_key_to_key(unicode_char: uefi::Char16, scan_code: u16) -> Option<Key> {
    if scan_code != 0 {
        return Some(Key::Special(ScanCode(scan_code)));
    }
    if u16::from(unicode_char) == 0 {
        return None;
    }
    Some(Key::Printable(unicode_char))
}

/// A keyboard input source. Extended Simple Text Input is preferred because
/// it handles firmware consoles that report only extended key data.
pub struct Keyboard {
    extended: Vec<ScopedProtocol<InputEx>>,
    basic: Vec<ScopedProtocol<Input>>,
    active: Option<ActiveKeyboard>,
    wait_events: Vec<(ActiveKeyboard, Event)>,
    timer_event: Event,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveKeyboard {
    Extended(usize),
    Basic(usize),
}

impl Keyboard {
    pub fn new() -> Option<Self> {
        // Some firmware installs keyboard protocols only after its USB/HID
        // driver is connected to the controller. Recursively connecting every
        // controller is the documented way to ensure keyboard handles exist.
        if let Ok(device_handles) =
            uefi::boot::find_handles::<uefi::proto::device_path::DevicePath>()
        {
            for handle in device_handles {
                let _ = uefi::boot::connect_controller(handle, None, None, true);
            }
        }

        let mut extended = match uefi::boot::find_handles::<InputEx>() {
            Ok(handles) => handles
                .into_iter()
                .filter_map(|handle| uefi::boot::open_protocol_exclusive::<InputEx>(handle).ok())
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        let mut basic = match uefi::boot::find_handles::<Input>() {
            Ok(handles) => handles
                .into_iter()
                .filter_map(|handle| uefi::boot::open_protocol_exclusive::<Input>(handle).ok())
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };

        // Firmware USB stack implementations are not required to start
        // delivering key strokes until the console input protocol has been
        // explicitly reset. Resetting all instances is harmless and lets a
        // secondary console remain usable if the primary is disabled.
        extended.iter_mut().for_each(|input| {
            input.reset(false);
        });
        basic.iter_mut().for_each(|input| {
            let _ = input.reset(false);
        });

        let active = if !extended.is_empty() {
            ActiveKeyboard::Extended(0)
        } else if !basic.is_empty() {
            ActiveKeyboard::Basic(0)
        } else {
            return None;
        };
        crate::debug_println!(
            "[BOOT] keyboard handles: extended={} basic={}",
            extended.len(),
            basic.len()
        );

        let mut wait_events = Vec::new();
        for (index, input) in extended.iter().enumerate() {
            if let Some(event) = input.wait_for_key_event() {
                wait_events.push((ActiveKeyboard::Extended(index), event));
            }
        }
        for (index, input) in basic.iter().enumerate() {
            if let Some(event) = input.wait_for_key_event().ok() {
                wait_events.push((ActiveKeyboard::Basic(index), event));
            }
        }

        // SAFETY: This timer event is only used while boot services are
        // active and is never signalled through a callback context.
        let timer_event =
            unsafe { uefi::boot::create_event(EventType::TIMER, Tpl::CALLBACK, None, None) }
                .ok()?;

        Some(Self {
            extended,
            basic,
            active: Some(active),
            wait_events,
            timer_event,
        })
    }

    pub fn read_key(&mut self) -> Option<Key> {
        match self.active {
            Some(ActiveKeyboard::Extended(index)) => self.extended.get_mut(index)?.read_key(),
            Some(ActiveKeyboard::Basic(index)) => {
                self.basic.get_mut(index)?.read_key().ok().flatten()
            }
            None => None,
        }
    }

    fn read_source(&mut self, source: ActiveKeyboard) -> Option<Key> {
        match source {
            ActiveKeyboard::Extended(index) => self
                .extended
                .get_mut(index)
                .and_then(|input| input.read_key()),
            ActiveKeyboard::Basic(index) => self
                .basic
                .get_mut(index)
                .and_then(|input| input.read_key().ok().flatten()),
        }
    }

    /// Wait until a key is available, a timeout expires, or no keyboard is
    /// installed. Returns `None` on timeout or if no readable key was found.
    pub fn wait_for_key(&mut self, timeout: Duration) -> Option<Key> {
        if self.wait_events.is_empty() {
            return None;
        }

        let timeout_units = u64::try_from(timeout.as_nanos() / 100).unwrap_or(u64::MAX);
        let mut events = self
            .wait_events
            .iter()
            .map(|(_, event)| unsafe { event.unsafe_clone() })
            .collect::<Vec<_>>();
        events.push(unsafe { self.timer_event.unsafe_clone() });
        if uefi::boot::set_timer(&self.timer_event, TimerTrigger::Relative(timeout_units)).is_err()
        {
            return self.read_key();
        }

        let timeout_index = self.wait_events.len();
        match uefi::boot::wait_for_event(&mut events) {
            Ok(index) if index == timeout_index => {
                debug_println!("[BOOT] keyboard wait timeout");
                None
            }
            Ok(index) => {
                debug_println!("[BOOT] keyboard event ready: index={}", index);
                let key = match self.wait_events.get(index) {
                    Some((source, _)) => self.read_source(*source),
                    None => None,
                };
                debug_println!("[BOOT] keyboard event read: {:?}", key);
                key
            }
            Err(error) if *error.data() == Some(timeout_index) => None,
            Err(error) => {
                debug_println!(
                    "[BOOT] keyboard wait error: status={:?} index={:?}",
                    error.status(),
                    error.data()
                );
                self.read_key()
            }
        }
    }
}
