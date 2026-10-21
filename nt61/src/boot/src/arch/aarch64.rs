//! AArch64 UEFI boot hand-off.

/// QEMU `virt` machine PL011 serial port. Firmware on this platform
/// exposes the debug UART at the standard 0x0900_0000 MMIO address.
const PL011_DATA_REGISTER: u64 = 0x0900_0000;

/// Write raw diagnostic bytes to the firmware debug UART.
#[inline(never)]
pub fn write_com1_marker(bytes: &[u8]) {
    if !cfg!(feature = "log_level_debug") {
        return;
    }

    for byte in bytes {
        unsafe {
            core::ptr::write_volatile(PL011_DATA_REGISTER as *mut u8, *byte);
        }
    }
}

/// Write the architecture's halt loop immediately below `stack_top`.
///
/// AArch64 branch-to-self encoding is `0x14000000` (branch +26-bit
/// displacement zero), stored little-endian.
pub unsafe fn write_halt_stub(stack_top: u64) -> u64 {
    let halt_addr = stack_top - 8;
    core::ptr::write_volatile((stack_top - 8) as *mut u32, 0x1400_0000);
    core::ptr::write_volatile((stack_top - 16) as *mut u64, halt_addr);
    halt_addr
}

/// Load `efiapi` argument registers and branch to the target image
/// with a private stack. The target is expected not to return.
///
/// SAFETY: `stack_top` must be mapped, writable, and 16-byte aligned;
/// `entry_vma` must point to a valid UEFI entry point.
pub unsafe fn launch_efi_main(
    image_handle: u64,
    system_table: u64,
    stack_top: u64,
    entry_vma: u64,
) -> ! {
    core::arch::asm!(
        "mov sp, x2",
        "br x3",
        in("x0") image_handle,
        in("x1") system_table,
        in("x2") stack_top,
        in("x3") entry_vma,
        options(noreturn),
    )
}
