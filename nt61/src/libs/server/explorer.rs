//! explorer — User shell
//
//! The desktop shell. Real NT pulls in `explorer.exe`
//! which loads `shell32.dll`, `browseui.dll`, etc. The stub
//! just records that the root window class is registered.

extern crate alloc;

use crate::ke::sync::Spinlock;
use crate::kprintln;
use core::sync::atomic::{AtomicBool, Ordering};

static SHELL_STARTED: AtomicBool = AtomicBool::new(false);
static ROOT_WINDOW: Spinlock<u64> = Spinlock::new(0);
static TASKBAR: Spinlock<u64> = Spinlock::new(0);

pub fn init() {
    SHELL_STARTED.store(true, Ordering::SeqCst);
    *ROOT_WINDOW.lock() = 0x0000_FACE_0000_0001;
    *TASKBAR.lock() = 0x0000_FACE_0000_0002;
    // kprintln!("      [explorer] shell started, root=0x{:x}", *ROOT_WINDOW.lock())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      [explorer] taskbar=0x{:x}", *TASKBAR.lock())  // kprintln disabled (memcpy crash workaround);
}

pub fn main() -> ! {
    init();
    loop { core::hint::spin_loop(); }
}

pub fn smoke_test() -> bool {
    let s = SHELL_STARTED.load(Ordering::SeqCst);
    let r = *ROOT_WINDOW.lock();
    let t = *TASKBAR.lock();
    let ok = s && r != 0 && t != 0 && r != t;
    // kprintln!("        [explorer] started={} root=0x{:x} bar=0x{:x} -> {}",  // kprintln disabled (memcpy crash workaround)
//               s, r, t, if ok { "OK" } else { "FAIL" });
    ok
}
