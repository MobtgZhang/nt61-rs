//! Built-in shell applications
//!
//! Minimal in-kernel implementations of common Win7 shell apps:
//! - calc.exe     : 4-function calculator
//! - notepad.exe  : simple text editor using the kernel console
//! - clock.exe    : sidebar clock display
//! - taskbar.exe  : taskbar / start-menu shell
//!
//! These run as user-mode processes, but the kernel keeps a record of
//! well-known apps so the boot sequence can pre-launch them.

extern crate alloc;
use alloc::string::String;

/// Number of well-known applications.
pub const KNOWN_APP_COUNT: usize = 4;

/// Application registration entry.
#[derive(Clone, Copy)]
pub struct AppEntry {
    pub name: &'static str,
    pub pid: u32,
    pub flags: u32,
}

const APP_CALC:     AppEntry = AppEntry { name: "calc.exe",     pid: 0, flags: 0x1 };
const APP_NOTEPAD:  AppEntry = AppEntry { name: "notepad.exe",  pid: 0, flags: 0x1 };
const APP_CLOCK:    AppEntry = AppEntry { name: "sidebar.exe",  pid: 0, flags: 0x1 };
const APP_TASKBAR:  AppEntry = AppEntry { name: "taskbar.exe",  pid: 0, flags: 0x1 };

/// Spinlock-protected well-known app table.
static APPS_TABLE: crate::ke::sync::Spinlock<[AppEntry; KNOWN_APP_COUNT]> =
    crate::ke::sync::Spinlock::new([APP_CALC, APP_NOTEPAD, APP_CLOCK, APP_TASKBAR]);

/// Init function called during desktop subsystem init.
pub fn init() {
    crate::hal::serial::write_string("[applications] init\r\n");
    let mut tbl = APPS_TABLE.lock();
    for app in tbl.iter_mut() {
        if app.pid == 0 {
            // Reserve a placeholder PID. Real user-mode PID allocation
            // happens via ps::process::create_user_process at startup.
            app.pid = 0;
        }
    }
}

/// Look up an application by name and return its PID (0 if unknown).
pub fn lookup(name: &str) -> u32 {
    let tbl = APPS_TABLE.lock();
    for app in tbl.iter() {
        if app.name == name {
            return app.pid;
        }
    }
    0
}

/// Allocate a new PID and register it under `name`. Returns the PID.
pub fn register(name: &'static str) -> Option<u32> {
    let mut tbl = APPS_TABLE.lock();
    for app in tbl.iter_mut() {
        if app.name == name {
            return Some(app.pid);
        }
    }
    // Find a free slot.
    for app in tbl.iter_mut() {
        if app.pid == 0 && app.name == name {
            // Placeholder: a full impl would call ps::process::pid_alloc()
            app.pid = 1;
            return Some(1);
        }
    }
    None
}

/// Simple integer-evaluating calculator used by calc.exe. The expression is
/// evaluated left-to-right. Supports `+`, `-`, `*`, `/`.
///
/// Returns `None` for malformed input or divide-by-zero.
pub fn calc_eval(expr: &str) -> Option<i64> {
    let mut acc: i64 = 0;
    let mut op: u8 = b'+';
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_digit() || c == b'-' {
            // Parse number
            let mut n: i64 = 0;
            let mut neg = false;
            if c == b'-' { neg = true; i += 1; }
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                n = n * 10 + (bytes[i] - b'0') as i64;
                i += 1;
            }
            if neg { n = -n; }
            match op {
                b'+' => acc += n,
                b'-' => acc -= n,
                b'*' => acc *= n,
                b'/' => if n == 0 { return None; } else { acc /= n },
                _ => {}
            }
        } else {
            op = c;
            i += 1;
        }
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    #[test]
    fn calc_eval_works() {
        use super::calc_eval;
        assert_eq!(calc_eval("1+2"), Some(3));
        assert_eq!(calc_eval("10-3"), Some(7));
        assert_eq!(calc_eval("6*7"), Some(42));
        assert_eq!(calc_eval("8/2"), Some(4));
        assert_eq!(calc_eval("1+2*3+4"), Some(11)); // left-to-right
    }
}

/// 4-function calculator entrypoint (very small) — uses `calc_eval`.
pub fn calc_run(expr: &str) {
    match calc_eval(expr) {
        Some(v) => {
            let out = alloc::format!("calc: {} = {}\r\n", expr, v);
            crate::hal::serial::write_string(&out);
        }
        None => crate::hal::serial::write_string("calc: expression error\r\n"),
    }
}

/// Trivial notepad that simply prints `text` (no GUI; placeholder).
pub fn notepad_print(text: &str) {
    let out = alloc::format!("notepad: {}\r\n", text);
    crate::hal::serial::write_string(&out);
}

/// Sidebar clock that prints the system time.
pub fn clock_print() {
    let t = crate::ke::time::get_system_time();
    let out = alloc::format!("clock: system_time={}\r\n", t);
    crate::hal::serial::write_string(&out);
}

/// Taskbar stub. Prints the number of running well-known apps.
pub fn taskbar_run() {
    let tbl = APPS_TABLE.lock();
    let n = tbl.iter().filter(|a| a.pid != 0).count();
    let out = alloc::format!("taskbar: {} apps running\r\n", n);
    crate::hal::serial::write_string(&out);
}
