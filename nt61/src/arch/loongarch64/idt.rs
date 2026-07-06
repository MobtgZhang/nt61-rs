//! LoongArch 64 EENTRY exception handler

use core::arch::asm;
use core::arch::global_asm;

// LA64 CSR numbers (must fit in 14-bit immediate).
// 0x0   = CRMD
// 0x1   = PRMD
// 0x6   = ERA
// 0x7   = BADV
// 0x9   = ESTAT (exception cause)
// 0xc   = EENTRY
// 0x30  = SAVE0..SAVE7 (used as scratch by the exception entry stub)

global_asm!(
    ".align 12",
    ".global loongarch64_exception",
    "loongarch64_exception:",
    "  csrwr $t0, 0x30",   // SAVE0 = scratch
    "  csrrd $t0, 0x1",    // PRMD
    "  csrwr $t0, 0x31",   // SAVE1
    "  csrrd $t0, 0x6",    // ERA
    "  csrwr $t0, 0x32",   // SAVE2
    "  csrrd $t0, 0x7",    // BADV
    "  csrwr $t0, 0x33",   // SAVE3
    "  csrrd $t0, 0x0",    // CRMD
    "  csrwr $t0, 0x34",   // SAVE4
    "  la  $sp, _exception_stack_top",
    "  addi.d $sp, $sp, -224",
    "  st.d $ra, $sp, 0",
    "  st.d $tp, $sp, 8",
    "  st.d $s0, $sp, 16",
    "  st.d $s1, $sp, 24",
    "  st.d $s2, $sp, 32",
    "  st.d $s3, $sp, 40",
    "  st.d $s4, $sp, 48",
    "  st.d $s5, $sp, 56",
    "  st.d $s6, $sp, 64",
    "  st.d $s7, $sp, 72",
    "  st.d $s8, $sp, 80",
    "  st.d $fp, $sp, 88",
    "  st.d $a0, $sp, 96",
    "  st.d $a1, $sp, 104",
    "  st.d $a2, $sp, 112",
    "  st.d $a3, $sp, 120",
    "  st.d $a4, $sp, 128",
    "  st.d $a5, $sp, 136",
    "  st.d $a6, $sp, 144",
    "  st.d $a7, $sp, 152",
    "  st.d $t0, $sp, 160",
    "  st.d $t1, $sp, 168",
    "  st.d $t2, $sp, 176",
    "  st.d $t3, $sp, 184",
    "  st.d $t4, $sp, 192",
    "  st.d $t5, $sp, 200",
    "  st.d $t6, $sp, 208",
    "  st.d $t7, $sp, 216",
    "  move $a0, $sp",
    "  la  $t0, handle_trap",
    "  jirl $ra, $t0, 0",
    "  ld.d $ra, $sp, 0",
    "  ld.d $tp, $sp, 8",
    "  ld.d $s0, $sp, 16",
    "  ld.d $s1, $sp, 24",
    "  ld.d $s2, $sp, 32",
    "  ld.d $s3, $sp, 40",
    "  ld.d $s4, $sp, 48",
    "  ld.d $s5, $sp, 56",
    "  ld.d $s6, $sp, 64",
    "  ld.d $s7, $sp, 72",
    "  ld.d $s8, $sp, 80",
    "  ld.d $fp, $sp, 88",
    "  ld.d $a0, $sp, 96",
    "  ld.d $a1, $sp, 104",
    "  ld.d $a2, $sp, 112",
    "  ld.d $a3, $sp, 120",
    "  ld.d $a4, $sp, 128",
    "  ld.d $a5, $sp, 136",
    "  ld.d $a6, $sp, 144",
    "  ld.d $a7, $sp, 152",
    "  ld.d $t0, $sp, 160",
    "  ld.d $t1, $sp, 168",
    "  ld.d $t2, $sp, 176",
    "  ld.d $t3, $sp, 184",
    "  ld.d $t4, $sp, 192",
    "  ld.d $t5, $sp, 200",
    "  ld.d $t6, $sp, 208",
    "  ld.d $t7, $sp, 216",
    "  addi.d $sp, $sp, 224",
    "  csrrd $t0, 0x34",
    "  csrwr $t0, 0x0",
    "  csrrd $t0, 0x33",
    "  csrwr $t0, 0x7",
    "  csrrd $t0, 0x32",
    "  csrwr $t0, 0x6",
    "  csrrd $t0, 0x31",
    "  csrwr $t0, 0x1",
    "  ertn"
);

extern "C" {
    fn loongarch64_exception();
}

/// Install the exception vector.
pub fn init() {
    unsafe {
        let v = loongarch64_exception as *const () as u64;
        asm!("csrwr {}, 0xc", in(reg) v, options(nostack));
    }
}

#[no_mangle]
pub extern "C" fn handle_trap(_frame: u64) {
    let cause: u64;
    unsafe { asm!("csrrd {}, 0x9", out(reg) cause, options(nostack)); }
    // crate::kprintln!("[loongarch] exception cause=0x{:x}", cause)  // kprintln disabled (memcpy crash workaround);
}
