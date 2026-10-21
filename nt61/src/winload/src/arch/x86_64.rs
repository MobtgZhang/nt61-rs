//! x86_64-specific OS Loader trampoline.
//!
//! The UEFI firmware hands control to `efi_main` with the Microsoft
//! x64 ABI: `rcx = handle, rdx = system table`. `kernel_main` is
//! declared `extern "C"` and therefore uses the System V AMD64 ABI:
//! `rdi = first arg`. The x86_64 trampoline below converts between
//! the two ABIs and `call`s into `kernel_main`.
//!
//! The trampoline is `#[inline(never)]` so the linker cannot move
//! the `call` target out from under the relative offset; the asm
//! uses a `sym` operand that resolves to the kernel symbol's
//! address.

/// RVA of the `KiSystemStartup` export inside a Win7 `ntoskrnl.exe`
/// image. The disk-side stub's `KiSystemStartup` body is hand-written
/// to do nothing but call back into the host trampoline (see
/// `tools/src/fs/build.rs::build_ntoskrnl_pe`); its RVA is
/// `SECTION_ALIGNMENT (0x1000) + 0` because the stub's only section
/// starts at the image base and the entry point is `export[0]`.
pub fn install_kernel_handoff() -> u64 {
    nt61::arch::x86_64::ntoskrnl_handoff::install_handoff_pointer()
}

pub unsafe fn launch_kernel(stack_top: u64, bi_ptr: u64, ntoskrnl_entry: u64) -> ! {
    jump_to_ntoskrnl_kisystemstartup(stack_top, bi_ptr, ntoskrnl_entry)
}

pub fn write_debug_marker(bytes: &[u8]) {
    write_com1_marker(bytes);
}

/// Jump to the on-disk `ntoskrnl.exe!KiSystemStartup` and never
/// return. This is the Win-7 winload → kernel hand-off.
///
/// The argument convention matches the Microsoft x64 ABI used by
/// `ntoskrnl!KiSystemStartup(LoaderBlock)`:
///   * `rcx` — pointer to the `LoaderBlock`-equivalent (`bi_ptr`)
///   * the rest of the Win-7 calling-state is supplied by the
///     firmware / winload state at ExitBootServices time
///   * `rsp` must already be the kernel stack
///
/// After we `call` into the disk KiSystemStartup, the disk-side
/// stub immediately calls back into the host trampoline at
/// `HOST_HANDOFF_SLOT_VADDR` (published by `install_handoff_pointer`).
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub unsafe extern "C" fn jump_to_ntoskrnl_kisystemstartup(
    stack_top: u64,
    bi_ptr: u64,
    ntoskrnl_entry: u64,
) -> ! {
    let sp = stack_top;
    let bi = bi_ptr;
    let entry = ntoskrnl_entry;
    core::arch::asm!(
        // Install kernel stack FIRST so an incoming IRQ cannot
        // observe a half-converted state.
        "mov rsp, {sp}",
       // Microsoft x64 ABI: rcx = first arg (bi_ptr).
       "mov rcx, {bi}",
        // System V AMD64 ABI: rdi = first arg, so the kernel ELF
        // entry (kernel_entry(bi_ptr), extern "C") receives the same
        // pointer regardless of which ABI the entry expects.
        "mov rdi, {bi}",
        // rax = ntoskrnl_entry (the absolute runtime address).
        "mov rax, {entry}",
        // xor rbp (so KiSystemStartup sees a clean stack frame).
        "xor rbp, rbp",
        // call into KiSystemStartup (never returns; the disk stub
        // either halts or jumps back into the host trampoline).
        "call rax",
        sp = in(reg) sp,
        bi = in(reg) bi,
        entry = in(reg) entry,
        options(noreturn, preserves_flags),
    );
}
/// Write raw diagnostic bytes to COM1 before UEFI services are initialized.
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
