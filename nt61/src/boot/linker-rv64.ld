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

/* QEMU virt exposes RAM from 0x80000000. EDK2 reserves OpenSBI and early
   DXE allocations in the low tens of MiB, so use a base above them. A
   valid preferred base avoids relying on PE relocations, which are absent
   from statically linked freestanding ELF images. */
BASE_ADDRESS = 0x88000000;

PHDRS {
    headers PT_LOAD FILEHDR PHDRS;
    data PT_LOAD;
}

SECTIONS {
    . = BASE_ADDRESS;

    /* Keep the PE headers at RVA 0 and start executable code at the
     * first section-aligned RVA. GNU `objcopy -O pei-riscv64-little`
     * converts ELF VMAs into PE RVAs after the build tool subtracts
     * `ImageBase`; placing `.text` directly at `BASE_ADDRESS` made the
     * first section overlap the PE header at RVA 0, which EDK2 rejects
     * with `EFI_SW_DXE_BS_EC_BOOT_OPTION_LOAD_ERROR`. */
    . = BASE_ADDRESS + 0x1000;

    .text : ALIGN(0x1000) {
        *(.text.startup .text.startup.*)
        efi_main = .; *(.text.efi_main .text.efi_main.*)
        *(.text .text.* .rodata .rodata.*)
        *(.eh_frame)
    } :headers

    .data : ALIGN(0x1000) {
        *(.data .data.*)
        *(.got .got.*)
        *(.got.plt .got.plt.*)
        /* Same as linker-la64.ld: BSS statics have to be part of an
         * allocated output section. `objcopy -O pei-riscv64-little`
         * strips a standalone `.bss` (see tools/src/fs/build.rs), so
         * without this rule the frame/PFN table statics disappear
         * from the image. */
        *(.bss .bss.*)
    } :data

    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
    }
}
