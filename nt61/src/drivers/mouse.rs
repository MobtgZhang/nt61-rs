//! Mouse Class Driver (mouclass.sys)
//
//! Implements the mouse class driver. mouclass.sys is the
//! Windows NT 6.1 class driver that sits between user-mode input
//! subsystems (Win32k, raw input) and the mouse port drivers
//! (i8042, USB HID). It owns the Functional Device Object (FDO)
//! for each mouse device and translates mouse packets into
//! movement and button events that user mode can consume.
//
//! Clean-room implementation. Spec source: Microsoft "Mouse
//! Class Driver" reference and USB HID 1.11.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicI32, Ordering};
use crate::io::{DeviceObject, DeviceType, DriverObject};
use crate::ke::sync::Spinlock;

/// Maximum number of mouse devices.
const MAX_MICE: usize = 4;

/// Mouse event ring buffer size.
const EVENT_BUFFER_SIZE: usize = 64;

/// Mouse event structure.
#[derive(Debug, Clone, Copy)]
pub struct MouseEvent {
    pub dx: i16,
    pub dy: i16,
    pub dz: i16,  // scroll wheel
    pub buttons: u8,  // bit flags: 0=left, 1=right, 2=middle
    pub timestamp: u64,
}

impl MouseEvent {
    pub const fn new() -> Self {
        Self {
            dx: 0,
            dy: 0,
            dz: 0,
            buttons: 0,
            timestamp: 0,
        }
    }
}

/// One mouse device.
pub struct MouseDevice {
    pub valid: bool,
    pub device_object: *mut DeviceObject,
    pub driver: *mut DriverObject,
    /// Ring buffer of mouse events.

    pub events: [MouseEvent; EVENT_BUFFER_SIZE],
    pub event_head: usize,
    pub event_tail: usize,
    pub x: i32,
    pub y: i32,
    pub packets_received: u64,
    pub button_clicks: u64,
}

impl MouseDevice {
    pub const fn new() -> Self {
        Self {
            valid: false,
            device_object: core::ptr::null_mut(),
            driver: core::ptr::null_mut(),
            events: [const { MouseEvent::new() }; EVENT_BUFFER_SIZE],
            event_head: 0,
            event_tail: 0,
            x: 0,
            y: 0,
            packets_received: 0,
            button_clicks: 0,
        }
    }
}

static mut MICE: [MouseDevice; MAX_MICE] =
    [const { MouseDevice::new() }; MAX_MICE];
static MOUSE_LOCK: Spinlock<()> = Spinlock::new(());
static MOUSE_EVENT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Initialize the mouse class driver.
pub fn init() {
    let _g = MOUSE_LOCK.lock();
    unsafe {
        // Register PS/2 mouse (device 0)
        MICE[0].valid = true;
    }
}

/// Post a mouse event to the event queue.
pub fn post_mouse_event(device_id: usize, dx: i16, dy: i16, dz: i16, buttons: u8) {
    if device_id >= MAX_MICE {
        return;
    }

    let _g = MOUSE_LOCK.lock();
    unsafe {
        let mouse = &mut MICE[device_id];
        if !mouse.valid {
            return;
        }

        mouse.x = mouse.x.saturating_add(dx as i32);
        mouse.y = mouse.y.saturating_add(dy as i32);

        let next_head = (mouse.event_head + 1) % EVENT_BUFFER_SIZE;
        if next_head != mouse.event_tail {
            mouse.events[mouse.event_head] = MouseEvent {
                dx,
                dy,
                dz,
                buttons,
                timestamp: crate::ke::time::get_interrupt_time(),
            };
            mouse.event_head = next_head;
            mouse.packets_received += 1;

            if buttons != 0 {
                mouse.button_clicks += 1;
            }

            MOUSE_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Read the next mouse event from the queue.
pub fn read_mouse_event(device_id: usize) -> Option<MouseEvent> {
    if device_id >= MAX_MICE {
        return None;
    }

    let _g = MOUSE_LOCK.lock();
    unsafe {
        let mouse = &mut MICE[device_id];
        if !mouse.valid {
            return None;
        }

        if mouse.event_tail != mouse.event_head {
            let event = mouse.events[mouse.event_tail];
            mouse.event_tail = (mouse.event_tail + 1) % EVENT_BUFFER_SIZE;
            Some(event)
        } else {
            None
        }
    }
}

/// Get the current mouse position.
pub fn get_mouse_position(device_id: usize) -> Option<(i32, i32)> {
    if device_id >= MAX_MICE {
        return None;
    }

    let _g = MOUSE_LOCK.lock();
    unsafe {
        let mouse = &MICE[device_id];
        if mouse.valid {
            Some((mouse.x, mouse.y))
        } else {
            None
        }
    }
}

pub fn mouse_count() -> usize {
    let mut count = 0;
    unsafe {
        for mouse in MICE.iter() {
            if mouse.valid {
                count += 1;
            }
        }
    }
    count
}

/// Get total mouse event count.
pub fn mouse_event_count() -> u32 {
    MOUSE_EVENT_COUNT.load(Ordering::Relaxed)
}

pub fn DriverEntry(driver: *mut DriverObject) -> u32 {
    init();
    0 // STATUS_SUCCESS
}
