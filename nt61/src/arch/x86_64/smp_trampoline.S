.global _trampoline_start
.global _trampoline_end
.global _trampoline_pml4
.global _trampoline_ap_stack
.global _trampoline_ap_index

.section .text.smp_trampoline

// The blob is copied to a low-memory SIPI page. The 16/32-bit paths
// use fixed page offsets because real/protected mode cannot be RIP
// relative. The 64-bit path is RIP relative.
_trampoline_start:
.code16gcc
    cli
    .byte 0x66, 0x0F, 0x01, 0x1E
    .long 0x1A0 // LGDT [0x1A0]
    .byte 0x0F, 0x20, 0xC0
    .byte 0x0D, 0x01, 0x00, 0x00, 0x00
    .byte 0x0F, 0x22, 0xC0
    .byte 0x66, 0xEA
    .long 0x20
    .word 0x08
    .balign 4, 0

.code32
_trampoline32:
    .byte 0x0F, 0x20, 0xE0
    .byte 0x0D, 0x20, 0x00, 0x00, 0x00
    .byte 0x0F, 0x22, 0xE0
    .byte 0xA1
    .long 0x1A8 // PML4 physical address
    .byte 0x0F, 0x22, 0xD8
    .byte 0xB9, 0x80, 0x00, 0x00, 0xC0
    .byte 0x0F, 0x32
    .byte 0x0D, 0x00, 0x05, 0x00, 0x00
    .byte 0x0F, 0x30
    .byte 0x0F, 0x20, 0xC0
    .byte 0x0D, 0x00, 0x00, 0x00, 0x80
    .byte 0x0F, 0x22, 0xC0
    .byte 0x66, 0xEA
    .long 0x60
    .word 0x18
    .balign 4, 0

.code64
_trampoline64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movq _trampoline_ap_stack(%rip), %rax
    movq %rax, %rsp
    movq _trampoline_ap_index(%rip), %rdi
    call ap_entry_long
_trampoline_idle:
    hlt
    jmp _trampoline_idle

.org 0x180
_trampoline_gdt:
    .quad 0
    .quad 0x00CF9A000000FFFF
    .quad 0x00CF92000000FFFF
    .quad 0x00AF9A000000FFFF
_trampoline_gdt_ptr:
    .word 31
    .long 0x180
_trampoline_pml4:
    .long 0
_trampoline_ap_stack:
    .quad 0
_trampoline_ap_index:
    .quad 0
_trampoline_end:
