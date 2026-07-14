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

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
global_asm!(
    "  .weak rust_eh_personality",
    "rust_eh_personality:",
    "  ud2",
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
);

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
    // === Snapshot RAX, user RIP, and 8 bytes from user RIP into SYSCALL_ENTRY_SNAP ===
    //
    // Layout of SYSCALL_ENTRY_SNAP:
    //   [ 0..8 ]  rax      : user syscall number (snapshot at entry)
    //   [ 8..16]  rip      : user-mode RIP (= RCX at entry)
    //   [16..24]  rip_bytes: 8 bytes from user-mode RIP (for diagnostics)
    //
    // On entry to syscall_entry:
    //   RAX = syscall number (clobbered by syscall)
    //   RCX = user-mode RIP  (clobbered by syscall)
    //   R11 = user-mode RFLAGS (clobbered by syscall)
    //
    // The {snap_base} operand references the SYSCALL_ENTRY_SNAP symbol.
    // In .intel_syntax noprefix under global_asm!:
    //   - `movabs {snap_base}, rax` encodes `48 a3 imm64` (mem STORE rax -> [imm64])
    //   - `mov rax, qword ptr gs:[0x58]` loads a 64-bit absolute address
    //     from a per-CPU slot populated by `init_syscall_msrs`. We use
    //     this instead of `lea rax, [{snap_base}]` because the LEA form
    //     truncates the high 32 bits of the absolute VMA 0x140069c18.
    "  mov r8, r14",                       // r8 = real user R14 (preserved)
    "  mov r14, rcx",                       // r14 = user RIP (preserve across writes)
    "  mov r9, r15",                        // r9 = real user R15 (preserve; clobbered below for rsp)
    "  movabs {snap_base}, rax",            // snap.rax = RAX (syscall num) — first!
    "  mov rax, qword ptr gs:[0x58]",       // rax = &snap (loaded from per-CPU area)
    "  mov [rax + 32], r12",                // snap.user_r12 = user R12 (preserve; r12 clobbered below)
    "  mov r12, rax",                       // r12 = &snap (callee-preserved)
    "  mov [rax + 8], r14",                 // snap.rip = user RIP
    "  mov [rax + 24], r13",                // snap.user_r13 = user R13 (preserved before clobber)
    // Copy 8 bytes from user RIP into snap.rip_bytes via movs. RSI =
    // user RIP (R-X page, kernel-readable from the user PML4). RDI =
    // &snap.rip_bytes (R+W kernel page). DS:[RSI] -> ES:[RDI].
    "  mov rsi, r14",                       // rsi = user RIP (source)
    "  lea rdi, [rax + 16]",                // rdi = &snap.rip_bytes (dest)
    "  mov rcx, 8",                         // count = 8 bytes
    "  rep movsb",                          // copy 8 bytes from [user RIP] -> snap.rip_bytes
    // Reload &snap into RAX (rep movsb advanced RDI and clobbered AL).
    "  mov rax, r12",                       // rax = &snap
    "  mov rdi, [rax]",                     // rdi = snap.rax = user syscall number
    "  mov r13, rdi",                       // r13 = syscall number (preserved)
    // Windows x64 ABI: extern "C" takes arg1=RCX, arg2=RDX. Move the
    // syscall number into RCX for syscall_dispatch(syscall_num, tf).
    "  mov rcx, r13",                       // rcx = syscall number (arg1)
    "  swapgs",
    "  mov gs:[0x0], rsp",                  // save user rsp
    "  mov rsp, gs:[0x8]",                  // load kernel rsp
    "  mov r15, gs:[0x0]",                  // r15 = user rsp (saved for trap frame)
    // Push in reverse field order. Use R14 (= preserved user RIP)
    // for slot 17, not RCX — RCX has been clobbered to 0 by the
    // `rep movsb` above. The trap frame's `rip` slot must hold the
    // real user-mode RIP so sysretq can return to it.
    "  push {user_ss}",                 // 21: ss = USER_SS (Ring 3 data, DPL=3)
    "  push r15",                        // 20: rsp = user rsp
    "  push r11",                        // 19: rflags (r11 = user RFLAGS)
    "  push {user_cs}",                 // 18: cs = USER_CS (Ring 3 code, DPL=3)
    "  push r14",                        // 17: rip = user RIP (preserved in r14)
    "  push 0",                          // 16: error_code
    "  push 0x100",                      // 15: vector (sentinel for syscall)
    // Slot 14 (user r15) must hold the genuine user-mode r15, not
    // user rsp. r15 currently holds user rsp (loaded above), so we
    // use r9 — where we stashed the real user r15 right after
    // syscall_entry — to push the correct value.
    "  push r9",                         // 14: r15 = real user r15 (stashed in r9)
    // Restore the real user-mode R14 from R9 (we clobbered R14
    // with user RIP earlier). The push then stores the genuine
    // user R14 into slot 13, which `pop r14` will restore for
    // sysretq.
    //
    // IMPORTANT: R14 must be set to *real user R14* before the
    // `push r14` for slot 13 AND must still contain the user-mode
    // RIP by the time we restore it for slot 1 (push rcx). The
    // approach below uses two callee-preserved registers: we save
    // the user RIP into R15 IMMEDIATELY after the entry (before
    // any diagnostic that might clobber R14), then move it back
    // into R14 just before the slot 1 push.
    "  mov r14, r8",                     // r14 = real user R14 (from preserved r8)
    "  push r14",                        // 13: r14 = real user R14
    "  mov r13, [r12 + 24]",             // r13 = snap.user_r13 (real user R13)
    "  push r13",                        // 12: r13 = real user R13
    "  mov r13, [r12 + 32]",             // r13 = snap.user_r12 (real user R12)
    "  push r13",                        // 11: r12 = real user R12
    "  push r11",                        // 10: r11
    "  push r10",                        //  9: r10
    "  push r9",                         //  8: r9
    "  push r8",                         //  7: r8
    "  push rdi",                        //  6: rdi
    "  push rsi",                        //  5: rsi
    "  push rbp",                        //  4: rbp
    "  push rbx",                        //  3: rbx
    "  push rdx",                        //  2: rdx
    // Restore RCX = user RIP from the snap static (we wrote it there
    // immediately after syscall_entry). Slot 1 must hold the
    // user-mode return RIP for sysretq to return to the right
    // instruction. We use snap.rip instead of R14 because R14 gets
    // restored to the real user R14 (saved in R9) just above for
    // slot 13, and we want both the real user R14 in slot 13 AND
    // the user RIP in slot 1.
    // The first LEA at the top of syscall_entry stored &snap in R12
    // (using `movabs rax, {snap_base}` because the absolute address
    // doesn't fit in a 32-bit sign-extended LEA immediate). Reload
    // RAX from R12 here so [rax + 8] targets the real SYSCALL_ENTRY_SNAP.
"  mov rax, r12",                     // rax = &snap (from R12)
    "  mov rcx, [rax + 8]",               // rcx = snap.rip = user RIP
    "  push rcx",                        //  1: rcx = user RIP
    "  push rax",                        //  0: rax = &snap (placeholder; real syscall num
                                        //      lives in snap.rax + r13)
    // RDX is set to &TrapFrame (the stack pointer right after the
    // pushes), overriding the pre-push RDX we set earlier.
    "  mov rdx, rsp",                    // &TrapFrame = rsp (Windows ABI arg2)
    // CRITICAL: Windows x64 ABI arg1 = RCX. We overwrote RCX above
    // with user RIP for the trap frame slot 1 push. Restore RCX to
    // R13 (= preserved syscall_num) before the call so syscall_num
    // arrives correctly in Rust, even at the cost of also pushing
    // that same value into slot 1 (sysretq uses slot 1 as user RIP;
    // we'll fix that with `mov rcx, [r12+8]` after the call).
    "  mov rax, r12",                     // rax = &snap (from R12)
    "  mov rcx, [rax]",                   // rcx = snap.rax = syscall_num (Windows ABI arg1)
    "  call syscall_dispatch",
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
    // Load user rsp and swap back to user GS base.
            "  mov rsp, gs:[0x0]",               // user rsp
            "  swapgs",
    "  sysretq",

    user_cs = const USER_CS as u64,
    user_ss = const USER_SS as u64,
    // rax_snap: static cell in the kernel's .data that holds the
    // RAX value at syscall_entry. We use it for debug to see what
    // user-mode RAX was at the moment the CPU took us here, BEFORE
    // any subsequent Rust code can clobber RAX.
    // All three slots point at offsets inside SYSCALL_ENTRY_SNAP:
    //   rax_snap      = &snap.rax    (offset 0)
    //   rip_snap      = &snap.rip    (offset 8)
    //   rip_byte_snap = &snap.rip_bytes (offset 16)
    // Using one struct keeps all three addresses contiguous and
    // avoids the rustc symbol-swap bug that previously made the
    // assembly write to the wrong slot.
    // Operand map. All three `sym` references point to
    // SYSCALL_ENTRY_SNAP (a #[no_mangle] static), which has a
    // proper relocation entry so the linker's runtime VA is
    // baked into each `movabs` immediate. We then use offsets
    // (0, 8, 16) inside the assembly to reach each field.
    snap_base = sym crate::arch::x86_64::syscall::SYSCALL_ENTRY_SNAP,
);
