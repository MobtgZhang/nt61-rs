OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(efi_main)

BASE_ADDRESS = 0x100000;

PHDRS {
    headers PT_LOAD FILEHDR HDRS;
    text PT_LOAD FILEHDR HDRS;
    data PT_LOAD FILEHDR HDRS;
}

SECTIONS {
    . = BASE_ADDRESS;
    
    .efi_header : {
        LONG(0x5A4D)
        SHORT(0) SHORT(0) SHORT(0) SHORT(0)
        SHORT(0) SHORT(0) SHORT(0) SHORT(0)
        SHORT(0) SHORT(0)
        LONG(0) LONG(0) LONG(0) LONG(0)
        LONG(0x4550)
        SHORT(0x8664)
        SHORT(0x0202)
        LONG(0) LONG(0) LONG(0)
        SHORT(0x0220)
        . = ALIGN(8);
        .pe_optional_hdr_size = . - .;
        SHORT(0x020B)
        BYTE(0x02) BYTE(0x1E)
        LONG(0) LONG(0) LONG(0)
        LONG(efi_main - .)
        LONG(.text - .)
        QUAD(BASE_ADDRESS)
        LONG(0x1000) LONG(0x200)
        SHORT(6) SHORT(1)
        SHORT(0) SHORT(0)
        SHORT(6) SHORT(1)
        LONG(0)
        LONG(0x10000) LONG(0x200) LONG(0)
        SHORT(0x0A)
        SHORT(0x8160)
        QUAD(0x40000) QUAD(0x1000)
        QUAD(0x40000) QUAD(0x1000)
        LONG(0) LONG(16)
        QUAD(0) QUAD(0) QUAD(0) QUAD(0)
        QUAD(0) QUAD(0) QUAD(0) QUAD(0)
        QUAD(0) QUAD(0) QUAD(0) QUAD(0)
        QUAD(0)
        .pe_optional_hdr_size = . - .;
    } : headers
    
    .text : ALIGN(0x1000) : {
        *(.text.startup .text.startup.*)
        efi_main = .; *(.text.efi_main .text.efi_main.*)
        *(.text .text.* .rodata .rodata.*)
        *(.eh_frame)
    } : text
    
    .data : ALIGN(0x1000) : {
        *(.data .data.*)
        *(.got .got.*)
        *(.got.plt .got.plt.*)
    } : data
    
    /DISCARD/ : {
        *(.rela.dyn)
        *(.rela.plt)
        *(.note.GNU-stack)
    }
    
    .dynamic : { *(.dynamic) } : data : data
}
