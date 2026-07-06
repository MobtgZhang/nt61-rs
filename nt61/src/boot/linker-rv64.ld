/* Plain ELF linker script for nt61-boot on RISC-V64.

   The Rust target is `riscv64gc-unknown-none-elf`, so the upstream
   Rust toolchain (via `rust-lld`) is happy with the default layout.

   We still use `riscv64-linux-gnu-ld` for consistency with the
   LoongArch64 build path, and the matching
   `riscv64-linux-gnu-objcopy -O pei-riscv64-littleriscv` step
   (orchestrated by `tools/src/fs/build.rs::build_boot`) wraps the
   ELF as a real PE32+ EFI image that EDK2's UEFI image loader can
   load on QEMU's `virt` machine.

   Reference:
     * UEFI Spec 2.10 2.1.4 ("PE32+ Image Format")
     * RISC-V ELF psABI (LP64D)
     * IMAGE_FILE_MACHINE_RISCV64 (0x5064)
*/

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv:rv64)
ENTRY(efi_main)

BASE_ADDRESS = 0x40000000;

PHDRS {
    text PT_LOAD;
    data PT_LOAD;
}

SECTIONS {
    . = BASE_ADDRESS;

    .text : ALIGN(0x1000) {
        *(.text.startup .text.startup.*)
        efi_main = .; *(.text.efi_main .text.efi_main.*)
        *(.text .text.* .rodata .rodata.*)
        *(.eh_frame)
    } :text

    .data : ALIGN(0x1000) {
        *(.data .data.*)
        *(.got .got.*)
        *(.got.plt .got.plt.*)
    } :data

    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.rela.dyn)
        *(.rela.plt)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
    }
}
