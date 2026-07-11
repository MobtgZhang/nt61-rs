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
    // Force the compiler to NOT inline. We use volatile ops to prevent
    // constant-propagation. Without this, recent rustc versions
    // constant-propagate `bi_ptr = &KERNEL_BOOT_INFO`'s address and replace
    // `mov rdi, {bi}` with `lea rax, [rip + KERNEL_BOOT_INFO]; mov rdi, rax`.
    // That happens to work for the static trick, but breaks when callers pass
    // a DIFFERENT pointer (the real BootInfo).
    let sp = core::hint::black_box(stack_top);
    let bi = core::hint::black_box(bi_ptr);
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
