//! RISC-V 64-bit UEFI boot hand-off.

const UART_DATA_REGISTER: u64 = 0x1000_0000;

pub fn write_com1_marker(bytes: &[u8]) {
    for byte in bytes {
        unsafe {
            core::ptr::write_volatile(UART_DATA_REGISTER as *mut u8, *byte);
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn write_halt_stub(stack_top: u64) -> u64 {
    let halt_addr = stack_top - 4;
    core::ptr::write_volatile(halt_addr as *mut u32, 0x1050_0073);
    core::ptr::write_volatile((stack_top - 16) as *mut u64, halt_addr);
    halt_addr
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn launch_efi_main(
    image_handle: u64,
    system_table: u64,
    stack_top: u64,
    entry_vma: u64,
) -> ! {
    core::arch::asm!(
        "mv sp, t1",
        "jalr ra, t0, 0",
        in("a0") image_handle,
        in("a1") system_table,
        in("t1") stack_top,
        in("t0") entry_vma,
        options(noreturn),
    )
}
