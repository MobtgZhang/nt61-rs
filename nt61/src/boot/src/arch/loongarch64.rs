//! LoongArch 64-bit UEFI boot hand-off.

/// QEMU `virt` machine 16550 serial port. The firmware exposes the
/// first debug UART at this MMIO address.
const UART0_BASE: u64 = 0x1FE0_01E0;

const UART_THR: u64 = 0;
const UART_LSR: u64 = 5;
const UART_LSR_THR_EMPTY: u8 = 0x20;

pub fn write_com1_marker(bytes: &[u8]) {
    if !cfg!(feature = "log_level_debug") {
        return;
    }

    for byte in bytes {
        unsafe {
            while core::ptr::read_volatile((UART0_BASE + UART_LSR) as *const u8)
                & UART_LSR_THR_EMPTY
                == 0
            {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile((UART0_BASE + UART_THR) as *mut u8, *byte);
        }
    }
}

pub unsafe fn write_halt_stub(stack_top: u64) -> u64 {
    let halt_addr = stack_top - 4;
    core::ptr::write_volatile(halt_addr as *mut u32, 0x147f_0000);
    core::ptr::write_volatile((stack_top - 16) as *mut u64, halt_addr);
    halt_addr
}

pub unsafe fn launch_efi_main(
    image_handle: u64,
    system_table: u64,
    stack_top: u64,
    entry_vma: u64,
) -> ! {
    core::arch::asm!(
        "move $sp, $t1",
        "jirl $ra, $t0, 0",
        in("$r4") image_handle,
        in("$r5") system_table,
        in("$r13") stack_top,
        in("$r12") entry_vma,
        options(noreturn),
    )
}
