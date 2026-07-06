/* EFI PE32+ image linker script for nt61-winload on LoongArch64.
 *
 * Structurally identical to `boot/linker-la64.ld` (which is shared
 * with the boot manager), but uses a *non-conflicting* BASE_ADDRESS.
 *
 * Why a separate base:
 *   * The boot manager (`nt61-boot`) is ~138 KiB and lives at
 *     0x1000000 — its preferred ImageBase + 0x19000 is well below
 *     the next obvious allocation, so the EDK2 loader maps it there
 *     without a relocation pass.
 *   * The OS loader (`nt61-winload`) is ~1.2 MiB and would occupy
 *     0x1000000 .. 0x129000. Bootmgr has already been mapped at
 *     0x1000000 by the time winload is loaded (bootmgr hands the
 *     loader an already-running runtime state and does not free its
 *     own pages), so the loader must relocate winload to a fresh
 *     region.
 *   * If the loader does manage to map winload at its preferred
 *     base, the loader would then try to apply the (empty) `.reloc`
 *     table and silently corrupt or refuse the image. Picking a base
 *     far above any bootmgr allocation avoids this collision
 *     entirely: the loader's first attempt succeeds, no relocations
 *     are required, and `uefi::println!` resumes working.
 *
 * The base `0x90000000` is well below EDK2's auto-allocation ceiling
 * (~0x9FFFFFFF for 4-GiB machines) and above the typical
 * 0x1000000..0x8000000 range used by boot-time drivers on QEMU's
 * LoongArch `virt` machine, so it does not collide with any DXE.
 */

OUTPUT_FORMAT("elf64-loongarch")
OUTPUT_ARCH(loongarch)
ENTRY(efi_main)

BASE_ADDRESS = 0x90000000;

PHDRS {
    headers PT_LOAD;
    text    PT_LOAD;
    data    PT_LOAD;
}

SECTIONS {
    . = BASE_ADDRESS;

    /* -------------------------------------------------------------
     * DOS / PE / COFF / OptionalHeader — written long-by-long so
     * the loader sees a complete PE32+ image even before our
     * post-link `patch_pe_subsystem` runs.
     *
     * PE32+ OptionalHeader layout (see winnt.h IMAGE_OPTIONAL_HEADER64):
     *   0x00 Magic           SHORT
     *   0x02 LinkerVersion   BYTE BYTE
     *   0x04 SizeOfCode      LONG
     *   0x08 SizeOfInitializedData  LONG
     *   0x0C SizeOfUninitializedData LONG
     *   0x10 AddressOfEntryPoint LONG
     *   0x14 BaseOfCode      LONG
     *   0x18 ImageBase       QUAD
     *   0x20 SectionAlignment LONG
     *   0x24 FileAlignment   LONG
     *   0x28 MajorOSVersion  SHORT
     *   0x2A MinorOSVersion  SHORT
     *   0x2C MajorImageVersion SHORT
     *   0x2E MinorImageVersion SHORT
     *   0x30 MajorSubsystemVersion SHORT
     *   0x32 MinorSubsystemVersion SHORT
     *   0x34 Win32VersionValue LONG
     *   0x38 SizeOfImage     LONG  (patched later by build-tool)
     *   0x3C SizeOfHeaders   LONG
     *   0x40 CheckSum        LONG
     *   0x44 Subsystem       SHORT
     *   0x46 DllCharacteristics SHORT
     *   0x48 SizeOfStackReserve QUAD
     *   0x50 SizeOfStackCommit QUAD
     *   0x58 SizeOfHeapReserve  QUAD
     *   0x60 SizeOfHeapCommit   QUAD
     *   0x68 LoaderFlags     LONG
     *   0x6C NumberOfRvaAndSizes LONG
     *   0x70..0xEF  16 IMAGE_DATA_DIRECTORY × 8 bytes
     * ------------------------------------------------------------- */
    .efi_header : {
        /* DOS header (64 bytes) */
        LONG(0x5A4D)                                       /*   0  e_magic        */
        SHORT(0) SHORT(0) SHORT(0) SHORT(0)               /*   2  e_cblp..e_cp   */
        SHORT(0) SHORT(0) SHORT(0) SHORT(0)               /*   6  e_crlp..e_cparhdr */
        SHORT(0) SHORT(0)                                  /*  10  e_minalloc..e_maxalloc */
        SHORT(0) SHORT(0)                                  /*  14  e_ss..e_sp     */
        SHORT(0) SHORT(0)                                  /*  18  e_csum..e_ip   */
        SHORT(0) SHORT(0)                                  /*  20  e_cs..e_lfarlc */
        SHORT(0) SHORT(0)                                  /*  22  e_ovno..e_res[0] */
        LONG(0) LONG(0) LONG(0) LONG(0)                   /*  24  e_res[1..4]..e_oemid */
        LONG(0x40)                                         /*  3C  e_lfanew       */

        /* PE signature + COFF FileHeader (24 bytes) */
        LONG(0x4550)                                       /* PE\0\0            */
        SHORT(0x6264)                                      /* Machine = LOONGARCH64 */
        SHORT(0)                                           /* NumberOfSections  (filled below) */
        LONG(0)                                            /* TimeDateStamp     */
        LONG(0)                                            /* PointerToSymbolTable */
        LONG(0)                                            /* NumberOfSymbols   */
        SHORT(0xF0)                                        /* SizeOfOptionalHeader = 240 */
        SHORT(0x0022)                                      /* Characteristics   (EXECUTABLE_IMAGE|LARGE_ADDRESS_AWARE; no DLL bit — UEFI §2.1.4.3 forbids it for EFI Applications) */

        /* OptionalHeader (PE32+) — 240 bytes */
        SHORT(0x020B)                                      /*   0  Magic = PE32+ */
        BYTE(0x02) BYTE(0x1E)                              /*   2  LinkerVersion */
        LONG(0)                                            /*   4  SizeOfCode */
        LONG(0)                                            /*   8  SizeOfInitializedData */
        LONG(0)                                            /*   C  SizeOfUninitializedData */
        LONG(efi_main - .)                                 /*  10  AddressOfEntryPoint */
        LONG(0x1000)                                       /*  14  BaseOfCode (.text aligned offset) */
        QUAD(BASE_ADDRESS)                                 /*  18  ImageBase */
        LONG(0x1000)                                       /*  20  SectionAlignment */
        LONG(0x200)                                        /*  24  FileAlignment */
        SHORT(6) SHORT(0)                                  /*  28  OS Version (6.0) */
        SHORT(0) SHORT(0)                                  /*  2C  Image Version */
        SHORT(6) SHORT(0)                                  /*  30  Subsystem Version (6.0) */
        LONG(0)                                            /*  34  Win32VersionValue */
        LONG(0x130000)                                     /*  38  SizeOfImage (placeholder; patched later) */
        LONG(0x200)                                        /*  3C  SizeOfHeaders */
        LONG(0)                                            /*  40  CheckSum */
        SHORT(0x0A)                                        /*  44  Subsystem = EFI_APPLICATION */
        SHORT(0x8160)                                      /*  46  DllCharacteristics */
        QUAD(0x100000)                                     /*  48  SizeOfStackReserve */
        QUAD(0x1000)                                       /*  50  SizeOfStackCommit */
        QUAD(0x100000)                                     /*  58  SizeOfHeapReserve */
        QUAD(0x1000)                                       /*  60  SizeOfHeapCommit */
        LONG(0)                                            /*  68  LoaderFlags */
        LONG(16)                                           /*  6C  NumberOfRvaAndSizes */
        /* 16 IMAGE_DATA_DIRECTORY entries × 8 bytes = 128 bytes */
        QUAD(0) QUAD(0) QUAD(0) QUAD(0)
        QUAD(0) QUAD(0) QUAD(0) QUAD(0)
        QUAD(0) QUAD(0) QUAD(0) QUAD(0)
        QUAD(0) QUAD(0) QUAD(0) QUAD(0)
    } : headers

    .text : ALIGN(0x1000) {
        *(.text.startup .text.startup.*)
        efi_main = .; *(.text.efi_main .text.efi_main.*)
        *(.text .text.* .rodata .rodata.*)
        *(.eh_frame)
    } : text

    .data : ALIGN(0x1000) {
        *(.data .data.*)
        *(.got .got.*)
        *(.got.plt .got.plt.*)
        *(.bss .bss.*)
    } : data

    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.note.gnu*)
        *(.rela.plt)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
        *(.comment)
        *(.symtab)
        *(.strtab)
        *(.shstrtab)
        *(.efi_header)
    }
}