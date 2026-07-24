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

use nt61::kernel_main::kernel_main;

/// RVA of the `KiSystemStartup` export inside a Win7 `ntoskrnl.exe`
/// image. The disk-side stub's `KiSystemStartup` body is hand-written
/// to do nothing but call back into the host trampoline (see
/// `tools/src/fs/build.rs::build_ntoskrnl_pe`); its RVA is
/// `SECTION_ALIGNMENT (0x1000) + 0` because the stub's only section
/// starts at the image base and the entry point is `export[0]`.
pub mod kernel_entry {
    /// The `.text` section alignment / base RVA in the disk ntoskrnl PE.
    /// Must match `SECTION_ALIGNMENT (0x1000)` in `tools/src/fs/build.rs`.
    pub const SECTION_ALIGNMENT: u64 = 0x1000;
    ///
    /// The hand-coded stub is written at `.text` offset `0x40` by
    /// `build_pe_image` in `tools/src/fs/build.rs`. Because the PE's
    /// single section starts at RVA `SECTION_ALIGNMENT (0x1000)`, the
    /// absolute RVA is `0x1000 + 0x40 = 0x1040`. Winload uses this
    /// value as the `entry_point_rva` when it calls into the disk
    /// ntoskrnl, and it is also the `KiSystemStartup` export RVA in
    /// `build_ntoskrnl_pe`.
    pub const KI_SYSTEM_STARTUP_RVA: u64 = 0x1040;

    /// Size of the `.text` section in the disk ntoskrnl PE, in bytes.
    /// The callback field lives at the last 8 bytes of this section.
    pub const TEXT_SIZE: u64 = 0x1000;

    /// RVA of the `.text` section base inside the disk ntoskrnl PE.
    /// This equals `SECTION_ALIGNMENT` and is used to convert between
    /// an export RVA like `KI_SYSTEM_STARTUP_RVA` and the `.text` base VA.
    pub const TEXT_BASE_RVA: u64 = SECTION_ALIGNMENT;
}

/// Calls `kernel_main` with the correct arguments and stack.
///
/// `stack_top` — top of the kernel stack (RSP after switch).
/// `bi_ptr`    — physical or low-half virtual address of the
///                `BootInfo` struct written to PA 0x10000 by the
///                loader. The kernel maps it from identity-mapped
///                boot memory; once paging is on we are no longer
///                identity-mapped, so the kernel sees it through
///                the bootmem allocator, not through its image base.
///
/// The trampoline is `#[inline(never)]` to keep the `call {km}`
/// instruction's relative offset within the assembler-emittable
/// range.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub unsafe extern "C" fn call_kernel_main(stack_top: u64, bi_ptr: u64) -> ! {
    let sp = stack_top;
    let bi = bi_ptr;
    core::arch::asm!(
        // Microsoft x64 ABI: caller passes (rcx=stack_top, rdx=bi_ptr).
        // kernel_main uses Microsoft x64 ABI for first arg (rcx).
        //
        // RIP-relative load of kernel_main's address into RAX. Using
        // a `sym` operand lets the assembler emit `lea rax, [rip +
        // kernel_main@plt]` (or equivalent), which is relocation-
        // model agnostic — the PE loader applies the DIR64
        // relocation to patch in the actual runtime address. This
        // works whether the `nt61` lib was compiled with
        // `relocation-model=static` (in which case the symbol
        // resolves to its absolute preferred-base address and the
        // loader patches the delta) or `pic` (in which case the
        // assembler emits the RIP-relative form directly).
        "lea rax, [rip + {km}]",
        "mov rcx, rdx",          // bi_ptr (in rdx) -> rcx (Microsoft x64 1st arg)
        "mov rsp, rdi",          // install kernel stack
        "xor rbp, rbp",
        "call rax",              // call kernel_main (never returns)
        km = sym kernel_main,
        in("rdi") sp,
        in("rdx") bi,
        options(noreturn),
    );
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
