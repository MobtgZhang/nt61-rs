//! Input Stack Smoke Test Aggregator

#![cfg(target_arch = "x86_64")]

use crate::kprintln;

pub fn smoke_test() -> bool {
    // kprintln!("  [INPUT SMOKE] running input stack smoke tests...")  // kprintln disabled (memcpy crash workaround);
    let mut ok = true;
    ok &= super::i8042::smoke_test();
    ok &= super::usb_hid_kbd::smoke_test();
    ok &= super::usb_hid_mouse::smoke_test();
    if ok {
        // kprintln!("  [INPUT SMOKE] all input checks passed")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("  [INPUT SMOKE FAIL] one or more checks failed")  // kprintln disabled (memcpy crash workaround);
    }
    ok
}
