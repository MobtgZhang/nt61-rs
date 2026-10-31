/// Write raw diagnostic bytes to COM1 before boot services are used.
#[inline(never)]
pub fn write_com1_marker(bytes: &[u8]) {
    if !cfg!(feature = "log_level_debug") {
        return;
    }

    for byte in bytes {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") 0x3f8_u16,
                in("al") *byte as i8,
                options(nostack),
            );
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Write the architecture's halt loop immediately below `stack_top`.
pub unsafe fn write_halt_stub(stack_top: u64) -> u64 {
    let halt_addr = stack_top - 8;
    core::ptr::write_volatile(halt_addr as *mut u8, 0xF4);
    core::ptr::write_volatile((halt_addr + 1) as *mut u8, 0xEB);
    core::ptr::write_volatile((halt_addr + 2) as *mut u8, 0xFE);
    core::ptr::write_volatile((stack_top - 16) as *mut u64, halt_addr);
    halt_addr
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Load `efiapi` argument registers and jump to the target image
/// with a private stack. The target is expected not to return.
///
/// SAFETY: `stack_top` must be a mapped, writable, 16-byte-aligned
/// stack and `entry_vma` must point to a valid UEFI entry point.
pub unsafe fn launch_efi_main(
    image_handle: u64,
    system_table: u64,
    stack_top: u64,
    entry_vma: u64,
) -> ! {
    core::arch::asm!(
        "xor r8d, r8d",
        "xor r9d, r9d",
        "mov rsp, {sp}",
        "jmp {entry}",
        // Bind the UEFI entry arguments straight to their ABI
        // registers. Going through in(reg) + explicit mov made LLVM
        // assign both values to the same register (observed as
        // 'mov %rdx,%rcx; mov %rcx,%rdx' in the shipped binary), so
        // winload received the image handle where the system table
        // belongs and faulted on its first boot-services call.
        in("rcx") image_handle,
        in("rdx") system_table,
        sp = in(reg) stack_top,
        entry = in(reg) entry_vma,
        options(noreturn),
    )
}
