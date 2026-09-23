//! Keyboard Class Driver (kbdclass.sys)
//
//! Implements the keyboard class driver. kbdclass.sys is the
//! Windows NT 6.1 class driver that sits between user-mode input
//! subsystems (Win32k, raw input) and the keyboard port drivers
//! (i8042, USB HID). It owns the Functional Device Object (FDO)
//! for each keyboard device and translates scan codes into key
//! events that user mode can consume.
//
//! In our environment kbdclass is a thin adapter that collects
//! keyboard input from the i8042 PS/2 controller and USB HID
//! keyboard drivers, maintains a small ring buffer of key events,
//! and exposes a read interface for user-mode consumers.
//
//! Clean-room implementation. Spec source: Microsoft "Keyboard
//! Class Driver" reference and USB HID 1.11.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::io::{DeviceObject, DeviceType, DriverObject};
use crate::ke::sync::Spinlock;

const MAX_KEYBOARDS: usize = 4;

const EVENT_BUFFER_SIZE: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    pub scan_code: u8,
    pub key_down: bool,
    pub timestamp: u64,
}

impl KeyEvent {
    pub const fn new() -> Self {
        Self {
            scan_code: 0,
            key_down: false,
            timestamp: 0,
        }
    }
}

pub struct KeyboardDevice {
    pub valid: bool,
    pub device_object: *mut DeviceObject,
    pub driver: *mut DriverObject,
    pub events: [KeyEvent; EVENT_BUFFER_SIZE],
    pub event_head: usize,
    pub event_tail: usize,
    pub keys_pressed: u64,
    pub keys_released: u64,
}

impl KeyboardDevice {
    pub const fn new() -> Self {
        Self {
            valid: false,
            device_object: core::ptr::null_mut(),
            driver: core::ptr::null_mut(),
            events: [const { KeyEvent::new() }; EVENT_BUFFER_SIZE],
            event_head: 0,
            event_tail: 0,
            keys_pressed: 0,
            keys_released: 0,
        }
    }
}

static mut KEYBOARDS: [KeyboardDevice; MAX_KEYBOARDS] =
    [const { KeyboardDevice::new() }; MAX_KEYBOARDS];
static KEYBOARD_LOCK: Spinlock<()> = Spinlock::new(());
static KEY_EVENT_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn init() {
    let _g = KEYBOARD_LOCK.lock();
    unsafe {
        KEYBOARDS[0].valid = true;
    }
}

pub fn post_key_event(device_id: usize, scan_code: u8, key_down: bool) {
    if device_id >= MAX_KEYBOARDS {
        return;
    }

    let _g = KEYBOARD_LOCK.lock();
    unsafe {
        let kbd = &mut KEYBOARDS[device_id];
        if !kbd.valid {
            return;
        }

        let next_head = (kbd.event_head + 1) % EVENT_BUFFER_SIZE;
        if next_head != kbd.event_tail {
            kbd.events[kbd.event_head] = KeyEvent {
                scan_code,
                key_down,
                timestamp: crate::ke::time::get_interrupt_time(),
            };
            kbd.event_head = next_head;

            if key_down {
                kbd.keys_pressed += 1;
            } else {
                kbd.keys_released += 1;
            }

            KEY_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn read_key_event(device_id: usize) -> Option<KeyEvent> {
    if device_id >= MAX_KEYBOARDS {
        return None;
    }

    let _g = KEYBOARD_LOCK.lock();
    unsafe {
        let kbd = &mut KEYBOARDS[device_id];
        if !kbd.valid {
            return None;
        }

        if kbd.event_tail != kbd.event_head {
            let event = kbd.events[kbd.event_tail];
            kbd.event_tail = (kbd.event_tail + 1) % EVENT_BUFFER_SIZE;
            Some(event)
        } else {
            None
        }
    }
}

pub fn keyboard_count() -> usize {
    let mut count = 0;
    unsafe {
        for kbd in KEYBOARDS.iter() {
            if kbd.valid {
                count += 1;
            }
        }
    }
    count
}

pub fn key_event_count() -> u32 {
    KEY_EVENT_COUNT.load(Ordering::Relaxed)
}

pub fn DriverEntry(driver: *mut DriverObject) -> u32 {
    init();
    0 // STATUS_SUCCESS
}
