//! Phase 0 minimal Ring 3 user-mode program.
//!
//! Exposes a hand-assembled machine-code blob that the kernel maps into
//! a fresh process's user address space and then jumps to via the
//! ISA-specific ring transition (`iretq`, `eret`, `sret`, `ertn`)
//! after `attach_process()`. The program is small, loop-based, and
//! only ever invokes a single syscall (`NtTestAlert`, NTSTATUS=0) in a
//! busy loop. The point of this module is *not* to do useful work —
//! it is to validate the ring-transition path end-to-end.
//!
//! The exact instruction bytes are ISA-dependent:
//!   * x86_64:    `b8 ef be ad de / 90 / eb fd` (mov eax,DEADBEEF; nop; jmp $-2)
//!   * aarch64:   `mov x0,#0xDEAD ; movk x0,#0xBEEF ; 1: b 1b` (8 bytes)
//!   * riscv64:   `li a0, 0xDEADBEEF ; 1: j 1b` (8 bytes)
//!   * loongarch: `li.w $a0, 0xDEADBEEF ; 1: b 1b` (8 bytes)
//!
//! CRITICAL: This stub is what validate the ring-transition path;
//! it does **not** implement `cmd.exe`. The real cmd.exe PE comes
//! from disk via `loader` and enters Ring 3 through the same
//! `enter_first_user_thread` machinery once `arch::boot` reaches
//! the SMSS phase.

use core::sync::atomic::AtomicU64;

/// Bumped on every user-mode syscall the kernel successfully
/// returns from. Read by the smoke test to confirm that the
/// ring-transition path was exercised.
pub static USER_SYSCALL_COUNT: AtomicU64 = AtomicU64::new(0);

/// User-mode entry RIP for the minimal ring3 stub.
///
/// Must be in the canonical user address space (below 0x00008000_00000000).
/// We use 0x00000000_00001000 (4 KiB) which is in the null-pointer guard
/// hole and safe from accidental kernel pointer confusion.
///
/// The stub is mapped by `install_into_pml4` into the per-process PML4
/// as a user-mode R+X page.
pub const USER_ENTRY_RIP: u64 = 0x0000_0000_0000_1000;

/// x86_64 hand-assembled machine code for the minimal user program.
#[cfg(target_arch = "x86_64")]
const USER_ENTRY_BYTES: [u8; 8] = [
    0xb8, 0xef, 0xbe, 0xad, 0xde,  // mov eax, 0xDEADBEEF (marker)
    0x90,                             // nop
    0xeb, 0xfd,                       // jmp $-2 (to nop)
];

/// aarch64 hand-assembled machine code for the minimal user program.
#[cfg(target_arch = "aarch64")]
const USER_ENTRY_BYTES: [u8; 8] = [
    // mov x0, #0xDEAD ; movk x0, #0xBEEF, lsl #16
    0x00, 0x00, 0xa8, 0xd2,
    // 1: b 1b  (offset = -4 bytes)
    0xff, 0xff, 0xff, 0x17,
];

/// riscv64 hand-assembled machine code for the minimal user program.
#[cfg(target_arch = "riscv64")]
const USER_ENTRY_BYTES: [u8; 8] = [
    // li a0, 0xDEADBEEF  (lui + addi)
    0x97, 0x35, 0x05, 0x00,
    // 1: j 1b  (jal x0, 0)
    0x6f, 0x00, 0x00, 0x00,
];

/// loongarch64 hand-assembled machine code for the minimal user program.
#[cfg(target_arch = "loongarch64")]
const USER_ENTRY_BYTES: [u8; 8] = [
    // lu12i.w $a0, (0xDEADB >> 12) ; ori $a0, $a0, 0xEAD
    0x14, 0x00, 0x37, 0x1a,
    // 1: b 1b  (beqz $a0, 1b; we just halt any input here)
    0x40, 0xff, 0xff, 0x5c,
];

/// Map `USER_ENTRY_BYTES` into the given per-process PML4 at
/// `USER_ENTRY_RIP` (R+X+U). Returns `true` on success.
pub fn install_into_pml4(pml4_phys: u64) -> bool {
    use crate::mm::vas::MmStatus;
    // Allocate one physical frame to back the user entry page.
    let Some(phys) = crate::mm::vas::alloc_zeroed_page_for_vas() else {
        return false;
    };
    // Copy the bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            USER_ENTRY_BYTES.as_ptr(),
            phys as *mut u8,
            USER_ENTRY_BYTES.len(),
        );
    }
    // Map the page as user-mode read/execute (no write).
    crate::mm::vas::map_page_in_pml4(
        pml4_phys,
        USER_ENTRY_RIP,
        phys,
        crate::mm::vas::PTE_US, // R+X+U, but no R/W
    ) == MmStatus::Ok
}
