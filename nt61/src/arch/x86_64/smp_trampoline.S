// AP trampoline for bringing up Application Processors (APs) on x86_64.
.global _trampoline_start
.global _trampoline_end
.global _trampoline_pml4
.global _trampoline_ap_stack
.global _trampoline_ap_index

.section .data
_trampoline_pml4:
    .long   0
_trampoline_ap_stack:
    .quad   0
_trampoline_ap_index:
    .quad   0

.section .rodata
_trampoline_gdt:
    .quad   0
    .quad   0x00CF9A000000FFFF
    .quad   0x00CF92000000FFFF
    .quad   0x00AF9A000000FFFF
_trampoline_gdt_ptr:
    .word   32
    .long   _trampoline_gdt

.section .text

// 16-bit real mode entry (offset 0)
.code16gcc
_trampoline_start:
    cli
    // LGDT with 32-bit absolute address
    .byte   0x66, 0x0F, 0x01, 0x1E
    .long   0          // placeholder - patched by linker
    // CR0.PE = 1
    .byte   0x0F, 0x20, 0xC0  // mov eax, cr0
    .byte   0x0D, 0x01, 0x00, 0x00, 0x00  // or eax, 1
    .byte   0x0F, 0x22, 0xC0  // mov cr0, eax
    // Far jump to 32-bit mode
    .byte   0x66, 0xEA
    .long   0x20        // offset to _trampoline32
    .word   0x0008

// 32-bit protected mode entry (offset 0x20)
.code32
_trampoline32:
    // CR4.PAE = 1
    .byte   0x0F, 0x20, 0xE0  // mov eax, cr4
    .byte   0x0D, 0x20, 0x00, 0x00, 0x00  // or eax, 0x20
    .byte   0x0F, 0x22, 0xE0  // mov cr4, eax
    // Load PML4 (absolute address)
    .byte   0xA1            // mov eax, [addr]
    .long   0              // placeholder
    .byte   0x0F, 0x22, 0xD8  // mov cr3, eax
    // EFER.LME = 1
    .byte   0xB9, 0x80, 0x00, 0x00, 0xC0  // mov ecx, 0xC0000080
    .byte   0x0F, 0x32        // rdmsr
    .byte   0x0D, 0x00, 0x05, 0x00, 0x00  // or eax, 0x500
    .byte   0x0F, 0x30        // wrmsr
    // CR0.PG = 1
    .byte   0x0F, 0x20, 0xC0  // mov eax, cr0
    .byte   0x0D, 0x00, 0x00, 0x00, 0x80  // or eax, 0x80000000
    .byte   0x0F, 0x22, 0xC0  // mov cr0, eax
    // Far jump to 64-bit mode
    .byte   0x66, 0xEA
    .long   0x60        // offset to _trampoline64
    .word   0x0010

// 64-bit long mode entry (offset 0x60)
.code64
_trampoline64:
    // Set up data segments (selector 0x18)
    .byte   0x66, 0xB8, 0x18, 0x00, 0x00, 0x00  // mov eax, 0x18
    .byte   0x66, 0x8E, 0xD8  // mov ds, eax
    .byte   0x66, 0x8E, 0xC0  // mov es, eax
    .byte   0x66, 0x8E, 0xD0  // mov ss, eax
    // Load stack pointer (absolute address)
    .byte   0x48, 0xA1        // movabsq addr, rax
    .quad   0              // placeholder
    .byte   0x48, 0x89, 0xE0  // mov rax, rsp
    // Load AP index (absolute address)
    .byte   0x48, 0xA1        // movabsq addr, rax
    .quad   0              // placeholder
    .byte   0x48, 0x89, 0xF8  // mov rax, rdi
    // Call the AP entry function (matches the symbol emitted by
    // `pub unsafe extern "C" fn ap_entry_long` in smp.rs on the
    // x86_64 System V ELF ABI, which does not prefix C symbols
    // with an underscore).
    call    ap_entry_long
_trampoline_idle:
    sti                     // Enable interrupts before hlt
    .byte   0xF4            // hlt
    jmp     _trampoline_idle

_trampoline_end:
