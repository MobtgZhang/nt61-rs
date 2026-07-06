//! lsass — Local Security Authority Subsystem
//
//! Authentication and token issuance. The stub records
//! that the system process token is loaded.

extern crate alloc;

use crate::ke::sync::Spinlock;
use crate::kprintln;

static SYSTEM_TOKEN: Spinlock<u64> = Spinlock::new(0);
static SESSION0_TOKEN: Spinlock<u64> = Spinlock::new(0);

pub fn init() {
    *SYSTEM_TOKEN.lock() = 0x0000_BEEF_0000_0001;
    *SESSION0_TOKEN.lock() = 0x0000_BEEF_0000_0002;
    // kprintln!("      [lsass] system token = 0x{:x}", *SYSTEM_TOKEN.lock())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      [lsass] session 0 token = 0x{:x}", *SESSION0_TOKEN.lock())  // kprintln disabled (memcpy crash workaround);
}

pub fn main() -> ! {
    init();
    loop { core::hint::spin_loop(); }
}

pub fn smoke_test() -> bool {
    let s = *SYSTEM_TOKEN.lock();
    let s0 = *SESSION0_TOKEN.lock();
    let ok = s != 0 && s0 != 0 && s != s0;
    // kprintln!("        [lsass] sys=0x{:x} s0=0x{:x} -> {}", s, s0, if ok { "OK" } else { "FAIL" })  // kprintln disabled (memcpy crash workaround);
    ok
}
