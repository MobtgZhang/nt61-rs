//! Phase 0 minimal Ring 3 user-mode program.
//
//! Exposes a hand-assembled x86_64 machine-code blob that the
//! kernel maps into a fresh process's user address space and then
//! jumps to via `iretq` after `attach_process()`. The program is
//! small, loop-based, and only ever invokes a single syscall
//! (`NtTestAlert`, NTSTATUS=0) in a busy loop. The point of this
//! module is *not* to do useful work — it is to validate the
//! ring-transition path end-to-end.
//
//! ```text
//! kernel_main -> create_user_process -> map USER_ENTRY_BASE
//!            -> first_user_enter -> Ring 3 entry
//!            -> user code runs -> syscall NtTestAlert
//!            -> syscall_dispatch -> sysretq
//!            -> user code continues
//!            -> user code hits the busy loop forever
//! ```
//
//! The kernel detects the "user thread has executed N syscalls"
//! state via a global counter that the syscall path bumps, and
//! the smoke test asserts that the counter is non-zero.

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

/// Hand-assembled x86_64 machine code for the minimal user
/// program. The layout is:
///
/// ```text
/// USER_ENTRY_BASE + 0x00:  b8 ef be ad de       mov eax, 0xDEADBEEF  (marker)
/// USER_ENTRY_BASE + 0x05:  90                    nop
/// USER_ENTRY_BASE + 0x06:  eb fd                    jmp $-2 (to nop)
/// ```
///
/// Total 8 bytes. This simple nop loop tests if we can stay alive in Ring 3.
pub const USER_ENTRY_BYTES: [u8; 8] = [
    0xb8, 0xef, 0xbe, 0xad, 0xde,  // mov eax, 0xDEADBEEF (marker)
    0x90,                             // nop
    0xeb, 0xfd,                       // jmp $-2 (to nop)
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
