//! x86_64 interrupt entry stubs.
//
//! All 256 entry points `int_stub_0` .. `int_stub_255`, the common
//! dispatcher `int_common_dispatch`, the SYSCALL entry
//! `syscall_entry`, and a small set of bare-metal ELF runtime
//! helpers (`rust_eh_personality`, `memset`, `memcpy`) are emitted
//! from a single `core::arch::global_asm!` block. This is the
//! *only* way to obtain raw machine code in a Rust crate without
//! pulling in a system assembler, which is critical for cross
//! compilation (e.g. `x86_64-unknown-uefi` uses `rust-lld` and
//! has no `cc` / `as`).
//
//! Rust's `global_asm!` uses LLVM's internal assembler in
//! `.intel_syntax noprefix` mode by default on x86. We write
//! Intel syntax with no `%` prefixes and no `qword ptr` — the
//! GAS-style `qword ptr` is the only thing we sometimes need
//! because LLVM-MC accepts it as a no-op type hint.
//
//! The supported directive set is intentionally narrow; see
//! <https://doc.rust-lang.org/reference/inline-assembly.html>.

use core::arch::global_asm;

// Import selector constants from the authoritative source (gdt.rs).
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt::USER_CS;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt::USER_SS;

global_asm!(

    // ---- raw-bytes helper --------------------------------------------
    // `emit_stub N` writes a 16-byte interrupt stub for vector N.
    //
    // Layout (16 bytes total):
    //   - 5 bytes: `mov edi, N` (opcode 0xB8 + N as u32)
    //   - 5 bytes: `jmp rel32` to int_common_dispatch
    //   - 6 bytes: NOP padding
    //
    // The vector number is passed in RDI rather than pushed on the
    // stack so that `int_common_dispatch` can read it without
    // having to skip a redundant slot. The CPU has already pushed
    // its own frame (SS, RSP, RFLAGS, CS, RIP [, error_code]).
    //
    // The label is declared `.global` so external C code (in
    // `arch::x86_64::idt`) can take its address when wiring up
    // the IDT.
    //
    // We deliberately skip `.type` because its GNU `@function`
    // form is rejected on the Windows COFF object format that
    // `x86_64-unknown-uefi` uses. `STT_FUNC` / `.def` are
    // GAS-only conveniences, not required for correctness.
    // -------------------------------------------------------------------
    ".macro emit_stub n",
    "  .global int_stub_\\n",
    "int_stub_\\n:",
    "  mov edi, \\n",
    "  push rdi",
    "  jmp int_common_dispatch",
    "  nop",
    "  nop",
    "  nop",
    "  nop",
    "  nop",
    "  nop",
    ".endm",

    // Vectors 0..=31 (CPU-defined exceptions).
    "emit_stub 0",  "emit_stub 1",  "emit_stub 2",  "emit_stub 3",
    "emit_stub 4",  "emit_stub 5",  "emit_stub 6",  "emit_stub 7",
    "emit_stub 8",  "emit_stub 9",  "emit_stub 10", "emit_stub 11",
    "emit_stub 12", "emit_stub 13", "emit_stub 14", "emit_stub 15",
    "emit_stub 16", "emit_stub 17", "emit_stub 18", "emit_stub 19",
    "emit_stub 20", "emit_stub 21", "emit_stub 22", "emit_stub 23",
    "emit_stub 24", "emit_stub 25", "emit_stub 26", "emit_stub 27",
    "emit_stub 28", "emit_stub 29", "emit_stub 30", "emit_stub 31",

    // Vectors 32..=255 (hardware / software IRQs and the
    // dispatcher's own error code on the stack).
    "emit_stub 32",  "emit_stub 33",  "emit_stub 34",  "emit_stub 35",
    "emit_stub 36",  "emit_stub 37",  "emit_stub 38",  "emit_stub 39",
    "emit_stub 40",  "emit_stub 41",  "emit_stub 42",  "emit_stub 43",
    "emit_stub 44",  "emit_stub 45",  "emit_stub 46",  "emit_stub 47",
    "emit_stub 48",  "emit_stub 49",  "emit_stub 50",  "emit_stub 51",
    "emit_stub 52",  "emit_stub 53",  "emit_stub 54",  "emit_stub 55",
    "emit_stub 56",  "emit_stub 57",  "emit_stub 58",  "emit_stub 59",
    "emit_stub 60",  "emit_stub 61",  "emit_stub 62",  "emit_stub 63",
    "emit_stub 64",  "emit_stub 65",  "emit_stub 66",  "emit_stub 67",
    "emit_stub 68",  "emit_stub 69",  "emit_stub 70",  "emit_stub 71",
    "emit_stub 72",  "emit_stub 73",  "emit_stub 74",  "emit_stub 75",
    "emit_stub 76",  "emit_stub 77",  "emit_stub 78",  "emit_stub 79",
    "emit_stub 80",  "emit_stub 81",  "emit_stub 82",  "emit_stub 83",
    "emit_stub 84",  "emit_stub 85",  "emit_stub 86",  "emit_stub 87",
    "emit_stub 88",  "emit_stub 89",  "emit_stub 90",  "emit_stub 91",
    "emit_stub 92",  "emit_stub 93",  "emit_stub 94",  "emit_stub 95",
    "emit_stub 96",  "emit_stub 97",  "emit_stub 98",  "emit_stub 99",
    "emit_stub 100", "emit_stub 101", "emit_stub 102", "emit_stub 103",
    "emit_stub 104", "emit_stub 105", "emit_stub 106", "emit_stub 107",
    "emit_stub 108", "emit_stub 109", "emit_stub 110", "emit_stub 111",
    "emit_stub 112", "emit_stub 113", "emit_stub 114", "emit_stub 115",
    "emit_stub 116", "emit_stub 117", "emit_stub 118", "emit_stub 119",
    "emit_stub 120", "emit_stub 121", "emit_stub 122", "emit_stub 123",
    "emit_stub 124", "emit_stub 125", "emit_stub 126", "emit_stub 127",
    "emit_stub 128", "emit_stub 129", "emit_stub 130", "emit_stub 131",
    "emit_stub 132", "emit_stub 133", "emit_stub 134", "emit_stub 135",
    "emit_stub 136", "emit_stub 137", "emit_stub 138", "emit_stub 139",
    "emit_stub 140", "emit_stub 141", "emit_stub 142", "emit_stub 143",
    "emit_stub 144", "emit_stub 145", "emit_stub 146", "emit_stub 147",
    "emit_stub 148", "emit_stub 149", "emit_stub 150", "emit_stub 151",
    "emit_stub 152", "emit_stub 153", "emit_stub 154", "emit_stub 155",
    "emit_stub 156", "emit_stub 157", "emit_stub 158", "emit_stub 159",
    "emit_stub 160", "emit_stub 161", "emit_stub 162", "emit_stub 163",
    "emit_stub 164", "emit_stub 165", "emit_stub 166", "emit_stub 167",
    "emit_stub 168", "emit_stub 169", "emit_stub 170", "emit_stub 171",
    "emit_stub 172", "emit_stub 173", "emit_stub 174", "emit_stub 175",
    "emit_stub 176", "emit_stub 177", "emit_stub 178", "emit_stub 179",
    "emit_stub 180", "emit_stub 181", "emit_stub 182", "emit_stub 183",
    "emit_stub 184", "emit_stub 185", "emit_stub 186", "emit_stub 187",
    "emit_stub 188", "emit_stub 189", "emit_stub 190", "emit_stub 191",
    "emit_stub 192", "emit_stub 193", "emit_stub 194", "emit_stub 195",
    "emit_stub 196", "emit_stub 197", "emit_stub 198", "emit_stub 199",
    "emit_stub 200", "emit_stub 201", "emit_stub 202", "emit_stub 203",
    "emit_stub 204", "emit_stub 205", "emit_stub 206", "emit_stub 207",
    "emit_stub 208", "emit_stub 209", "emit_stub 210", "emit_stub 211",
    "emit_stub 212", "emit_stub 213", "emit_stub 214", "emit_stub 215",
    "emit_stub 216", "emit_stub 217", "emit_stub 218", "emit_stub 219",
    "emit_stub 220", "emit_stub 221", "emit_stub 222", "emit_stub 223",
    "emit_stub 224", "emit_stub 225", "emit_stub 226", "emit_stub 227",
    "emit_stub 228", "emit_stub 229", "emit_stub 230", "emit_stub 231",
    "emit_stub 232", "emit_stub 233", "emit_stub 234", "emit_stub 235",
    "emit_stub 236", "emit_stub 237", "emit_stub 238", "emit_stub 239",
    "emit_stub 240", "emit_stub 241", "emit_stub 242", "emit_stub 243",
    "emit_stub 244", "emit_stub 245", "emit_stub 246", "emit_stub 247",
    "emit_stub 248", "emit_stub 249", "emit_stub 250", "emit_stub 251",
    "emit_stub 252", "emit_stub 253", "emit_stub 254", "emit_stub 255",

    // ---- Common interrupt dispatcher ---------------------------------
    // Saves GPRs, calls dispatch_trap_frame, restores GPRs, iretq.
    //
    // The int_stub_N stubs pass the vector number in RDI (no stack
    // push). The CPU pushed SS, RSP, RFLAGS, CS, RIP [, error_code]
    // at interrupt entry. For vectors that push an error code (8,
    // 10, 11, 12, 13, 14, 17) we must skip it before iretq.
    //
    // Stack at int_common_dispatch entry:
    //   [rsp + 0]  user RIP
    //   [rsp + 8]  user CS
    //   [rsp + 16] user RFLAGS
    //   [rsp + 24] user RSP
    //   [rsp + 32] user SS
    //   [rsp + 40] error_code  (only for vectors 8/10/11/12/13/14/17)
    //
    // Stack after 14 GPR pushes (rsp -= 112):
    //   [rsp + 0]   = rax (last push)
    //   [rsp + 8]   = rcx
    //   ...
    //   [rsp + 48]  = rdi (== vector, set by int_stub_N)
    //   ...
    //   [rsp + 112] = r15 (first push)
    //   [rsp + 120] = (no longer vector, since stub doesn't push)
    // -------------------------------------------------------------------
    ".balign 16",
    "int_common_dispatch:",
    "  cld",
    "  push r15", "  push r14", "  push r13", "  push r12",
    "  push r11", "  push r10", "  push r9",  "  push r8",
    "  push rdi", "  push rsi", "  push rbp", "  push rbx",
    "  push rdx", "  push rcx", "  push rax",
    // The 15 GPR pushes grow the frame downward in REVERSE order of
    // the TrapFrame struct fields, so the saved rdi (=vector, placed
    // here by int_stub_N) is at [rsp + 0x30] right now.
    //
    // The Windows x64 ABI is in effect here: a Rust `extern "C"`
    // function built for `x86_64-unknown-uefi` expects the first
    // argument in RCX, the second in RDX. So we pass vector via
    // RCX and &TrapFrame via RDX, NOT the SysV RDI/RSI convention.
    "  mov rcx, [rsp + 0x78]",             // rcx = vector (pushed by int_stub)
    "  mov rdx, rsp",                      // rdx = &TrapFrame
    "  call dispatch_trap_frame",
    // After 15 GPR pushes, the CPU frame sits above the GPRs:
    //
    //   For error-code vectors (8, 10, 11, 12, 13, 14, 17):
    //     [rsp + 0x00..0x70] = 15 GPRs (rax..r15)
    //     [rsp + 0x78]        = error_code
    //     [rsp + 0x80]        = RIP
    //     [rsp + 0x88]        = CS
    //     [rsp + 0x90]        = RFLAGS
    //     [rsp + 0x98]        = RSP
    //     [rsp + 0xa0]        = SS
    //
    //   For non-error-code vectors:
    //     [rsp + 0x00..0x70] = 15 GPRs (rax..r15)
    //     [rsp + 0x78]        = RIP
    //     [rsp + 0x80]        = CS
    //     [rsp + 0x88]        = RFLAGS
    //     [rsp + 0x90]        = RSP
    //     [rsp + 0x98]        = SS
    //
    // iretq pops 5 values (RIP, CS, RFLAGS, RSP, SS). To leave the
    // stack pointing at the right slot, we either:
    //   - error-code: add 0x80 once (skip 0x78 GPRs + 0x08 error_code)
    //   - non-error:  pop the 15 GPRs (0x78 bytes), leaving rsp at
    //                 RIP naturally.
    //
    // The vector is stashed into r12 BEFORE the pops so we can drive
    // the error-code skip logic. After `pop r12` it would be
    // overwritten with the saved user/kernel r12.
    "  mov r12, [rsp + 0x78]",             // r12 = vector
    "  mov rdi, r12",
    "  cmp rdi, 8",     "  je 2f",
    "  cmp rdi, 10",    "  je 2f",
    "  cmp rdi, 11",    "  je 2f",
    "  cmp rdi, 12",    "  je 2f",
    "  cmp rdi, 13",    "  je 2f",
    "  cmp rdi, 14",    "  je 2f",
    "  cmp rdi, 17",    "  je 2f",
    "  jmp 1f",
    "2:",
    "  add rsp, 0x88",                    // skip vector + error_code + 15 GPRs
    "  jmp 3f",
    "1:",
    "  pop rax", "  pop rcx", "  pop rdx", "  pop rbx",
    "  pop rbp", "  pop rsi", "  pop rdi",
    "  pop r8", "  pop r9", "  pop r10", "  pop r11",
    "  pop r12", "  pop r13", "  pop r14", "  pop r15",
    "  add rsp, 0x08",                    // skip vector slot
    "3:",
    // CRITICAL: The iret frame's SS slot is whatever SS was active
    // when the interrupt fired. After SYSCALL the kernel runs with
    // SS = STAR[47:32] + 8 (= slot 4, which we use as DPL=3 user SS),
    // which is invalid for CPL=0 — loading it via iretq would #GP.
    // Force SS = KERNEL_DS (slot 3, DPL=0 data) just before iretq;
    // the kernel uses a flat 64-bit data segment so base/limit are
    // ignored in long mode. The CPU requires the instruction after
    // `mov ss, x` to be a NOP or branch, hence the explicit nop.
    "  mov ax, 0x18",
    "  mov ss, ax",
    "  nop",
    "  iretq",

    // ---- SYSCALL entry -----------------------------------------------
    // Full Ring0/3 transition. Saves user state (GPRs + control
    // state), calls the Rust dispatcher, restores state, returns
    // to user mode via sysretq.
    //
    // The TrapFrame Rust struct is laid out so struct[0] = rax,
    // struct[21] = ss (22 fields × 8 bytes = 0xb0).
    //
    // Push strategy: push in REVERSE order of struct field index so
    // that struct[0] (rax) lands at mem[rsp] after the final push.
    // &TrapFrame = rsp directly.
    //
    // Order pushed (first push .. last push):
    //   ss (21), rsp (20), rflags (19), cs (18), rip (17),
    //   error_code (16), vector (15), r15..r12 (14..11),
    //   r11 (10), r10 (9), r9 (8), r8 (7), rdi (6), rsi (5),
    //   rbp (4), rbx (3), rdx (2), rcx (1), rax (0)
    //
    // Note: r11 must be saved BEFORE rax because the syscall
    // instruction clobbers rcx (=user RIP) and r11 (=user RFLAGS).
    // We rely on the x86-64 syscall convention: rcx=user RIP,
    // r11=user RFLAGS. Both go into the frame fields named "rip"
    // and "rflags" respectively.
    // -------------------------------------------------------------------
    "  .global syscall_entry",
    "syscall_entry:",
    // DEBUG: write 'S' to serial port 0x3F8 to mark syscall_entry reached.
    "  mov al, 0x53",  // 'S'
    "  mov dx, 0x3F8",
    "  out dx, al",
    "  swapgs",
    "  mov gs:[0x0], rsp",               // save user rsp
    "  mov rsp, gs:[0x8]",               // load kernel rsp
    // DEBUG: write 'K' to serial port to mark kernel RSP loaded.
    "  mov al, 0x4B",  // 'K'
    "  mov dx, 0x3F8",
    "  out dx, al",
    // Save user rsp into a scratch register BEFORE any push so we
    // can store it in the rsp slot of the frame.
    "  mov r15, gs:[0x0]",               // r15 = user rsp
    // We do NOT switch CR3 here: the user PML4 already has the
    // kernel half copied from the system PML4 (see
    // `mm::vas::create_user_address_space`), so both kernel stack
    // and user pages are reachable through it. Switching CR3 to
    // the bare system PML4 would lose the user-half mappings, and
    // any syscall handler that reads user pointers (e.g. the
    // SYS_RUN_AUTOEXEC path) would page-fault. Keeping CR3 on the
    // user PML4 means the syscall handler can read both kernel
    // and user memory through the same PTE tree.
    // Push in reverse field order.
    "  push {user_ss}",                 // 21: ss = USER_SS (Ring 3 data, DPL=3)
    "  push r15",                        // 20: rsp = user rsp
    "  push r11",                        // 19: rflags (r11 = user RFLAGS)
    "  push {user_cs}",                 // 18: cs = USER_CS (Ring 3 code, DPL=3)
    "  push rcx",                        // 17: rip (rcx = user RIP)
    "  push 0",                          // 16: error_code
    "  push 0x100",                      // 15: vector (sentinel for syscall)
    "  push r15",                        // 14: r15
    "  push r14",                        // 13: r14
    "  push r13",                        // 12: r13
    "  push r12",                        // 11: r12
    "  push r11",                        // 10: r11
    "  push r10",                        //  9: r10
    "  push r9",                         //  8: r9
    "  push r8",                         //  7: r8
    "  push rdi",                        //  6: rdi
    "  push rsi",                        //  5: rsi
    "  push rbp",                        //  4: rbp
    "  push rbx",                        //  3: rbx
    "  push rdx",                        //  2: rdx
    "  push rcx",                        //  1: rcx
    "  push rax",                        //  0: rax (syscall # on entry, ret val on exit)
    // Windows x64 ABI: arg1 in RCX, arg2 in RDX. syscall number is
    // in rax; copy it to rcx so that syscall_dispatch (compiled for
    // `x86_64-unknown-uefi`) sees it as the first parameter.
    "  mov rcx, rax",                    // syscall number (Windows arg1)
    "  mov rdx, rsp",                    // &TrapFrame = rsp (Windows arg2)
    "  call syscall_dispatch",
    // DEBUG: write 'D' to serial port to mark syscall_dispatch returned.
    "  mov al, 0x44",  // 'D'
    "  mov dx, 0x3F8",
    "  out dx, al",
    // CR3 stays on the user PML4 throughout; see the syscall entry
    // comment above for why we don't toggle it for syscall dispatch.
    // After return, rax holds the syscall return value (NTSTATUS).
    // The trap frame is still on the stack. Pop the GPR slots in
    // the exact reverse order of the pushes above so that
    // rcx, rdx, rbx, rbp, rsi, rdi, r8-r15, and r11 are restored
    // from the frame (syscall_dispatch is free to clobber them).
    // Skip the bottom rax slot (return value is already in rax).
    "  add rsp, 0x08",                   // skip slot 0 (rax)
    "  pop rcx",                         // slot  1: rcx = user RIP
    "  pop rdx",                         // slot  2
    "  pop rbx",                         // slot  3
    "  pop rbp",                         // slot  4
    "  pop rsi",                         // slot  5
    "  pop rdi",                         // slot  6
    "  pop r8",                          // slot  7
    "  pop r9",                          // slot  8
    "  pop r10",                         // slot  9
    "  pop r11",                         // slot 10: r11 = user RFLAGS
    "  pop r12",                         // slot 11
    "  pop r13",                         // slot 12
    "  pop r14",                         // slot 13
    "  pop r15",                         // slot 14
    // 16 slots popped so far (= 128 bytes). The remaining 6 slots
    // are the iretq frame: vector, error_code, rip, cs, rflags, rsp.
    // We discard them all because sysretq will reload user
    // CS/SS from STAR, user RIP from RCX (just restored), user
    // RFLAGS from R11 (just restored), and user RSP from
    // gs:[0x0] (the user RSP we saved at entry).
    "  add rsp, 0x30",                   // skip 6 slots (48 bytes)
    // DEBUG: write 'P' before sysretq frame setup (after skips)
    "  mov al, 0x50",  // 'P'
    "  mov dx, 0x3F8",
    "  out dx, al",
    // Load user rsp and swap back to user GS base.
    "  mov rsp, gs:[0x0]",               // user rsp
    "  swapgs",
    // DEBUG: write 'R' right before sysretq
    "  mov al, 0x52",  // 'R'
    "  mov dx, 0x3F8",
    "  out dx, al",
    "  sysretq",

    // ---- rust_eh_personality -----------------------------------------
    // Stub for the rust unwinding personality function. We use
    // panic = "abort" so we never actually unwind, but the rust
    // runtime still references this symbol via DWARF unwind tables.
    //
    // The symbol is declared `.weak` so that binaries which link
    // against `libstd` (which provides its own `rust_eh_personality`)
    // can override this definition with the real one. The kernel,
    // which has no `libstd`, sees this as the only definition.
    // -------------------------------------------------------------------
    "  .weak rust_eh_personality",
    "rust_eh_personality:",
    "  ud2",

    // ---- memset / memcpy ---------------------------------------------
    // On `x86_64-unknown-linux-gnu` (host build) rustc routes some
    // references through the host runtime. Provide local copies so
    // the linker does not reach for libc / libgcc and re-introduce
    // the Scrt1.o `_start` conflict. The targets that don't need
    // them simply GC the unused section.
    //
    // Like the personality, these are declared `.weak` so a host
    // binary that brings in libc / libgcc will still pick up the
    // optimised versions from there.
    // -------------------------------------------------------------------
    "  .weak memset",
    "memset:",
    "  mov r8, rdi",
    "  mov rcx, rdx",
    "  movzx eax, sil",
    "  test rcx, rcx",
    "  jz 2f",
    "1:  mov [rdi], al",
    "  inc rdi",
    "  dec rcx",
    "  jnz 1b",
    "2:  mov rax, r8",
    "  ret",

    "  .weak memcpy",
    "memcpy:",
    "  mov r9, rdi",
    "  mov rcx, rdx",
    "  test rcx, rcx",
    "  jz 2f",
    "1:  mov al, [rsi]",
    "  mov [rdi], al",
    "  inc rsi",
    "  inc rdi",
    "  dec rcx",
    "  jnz 1b",
    "2:  mov rax, r9",
    "  ret",

    // ---- bcmp -----------------------------------------------------------
    // Byte-wise memory comparison. Returns 0 if equal, non-zero otherwise.
    // This is needed by core's slice comparison functions.
    "  .weak bcmp",
    "bcmp:",
    "  mov r8, rdi",
    "  mov rcx, rdx",
    "  xor rax, rax",
    "  test rcx, rcx",
    "  jz 2f",
    "1:  movzx r9, byte ptr [rsi]",
    "  movzx r10, byte ptr [rdi]",
    "  sub r9, r10",
    "  or rax, r9",
    "  inc rsi",
    "  inc rdi",
    "  dec rcx",
    "  jnz 1b",
    "2:  ret",

    user_cs = const USER_CS as u64,
    user_ss = const USER_SS as u64,
);
