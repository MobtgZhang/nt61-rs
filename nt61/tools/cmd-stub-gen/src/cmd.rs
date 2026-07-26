//! `cmd.exe` user-mode stub — 4096-byte hand-assembled interpreter.
//!
//! Bit-for-bit port of `tools/cmd-stub-gen/cmd_asm.py::main()`. Two
//! phases:
//!   1. Walk every instruction in source order, emitting bytes via the
//!      helpers in `codegen.rs`. Forward references to string labels
//!      and to internal blocks (`print_str`, `do_exit`, …) are
//!      recorded against a *placeholder* 4-byte disp32 slot whose
//!      offset is captured.
//!   2. Call `Buf::finalize`, which walks the placeholder list and
//!      patches each disp32 with `(target - (disp_off + 4))` — exactly
//!      the formula the Python script uses.
//!
//! The layout and bytes therefore match the Python tool. String
//! positions are computed in source order (BANNER → HELP → UNKNOWN →
//! PROMPT → HALT → padding → SCAN_TO_ASCII) so a Rust byte dump of
//! the resulting array will line up with the existing
//! `tools/src/fs/stubs/boot_stubs.rs` arrays.

use crate::codegen::*;
use crate::strings::{
    BANNER, CMD_STUB_SIZE, DATETXT, EXIT_TXT, HALTTXT, HELP, IPCFGTXT, PROMPT, SCAN_TO_ASCII,
    SYS_CLEAR, SYS_EXIT, SYS_GET_RTC, SYS_NETCFG_GET, SYS_POLL_KEY, SYS_PUTCHAR, SYS_RUN_AUTOEXEC,
    TIMETXT, UNKNOWN, VER_TXT,
};

pub fn build() -> Vec<u8> {
    let mut s = Buf::new();

    // ============== 0x000 entry point ==============

    cli(&mut s);
    cld(&mut s);
    sub_rsp_imm32(&mut s, 0x0000_0400);
    mov_r15_rsp(&mut s);
    xor_r13_r13(&mut s);

    // Auto-run C:\tests\autoexec.bat via SYS_RUN_AUTOEXEC (0x200).
    // After the batch finishes, control falls through to the
    // BANNER/HELP/PROMPT/read_line flow below so the user still
    // gets an interactive shell.
    //
    //   xor r10d, r10d    ; arg0 = NULL => kernel uses default path
    //   mov eax, 0x200    ; SYS_RUN_AUTOEXEC
    //   syscall
    xor_r10d_r10d(&mut s);
    mov_rax_imm32(&mut s, SYS_RUN_AUTOEXEC);
    syscall(&mut s);

    // call print_str(BANNER)
    let le_banner = lea_rdi_rip_placeholder(&mut s);
    mov_rsi_imm32(&mut s, BANNER.len() as u32);
    let call_banner = call_rel(&mut s);
    s.j32_backpatch("print_str", call_banner);
    s.j32_backpatch("BANNER", le_banner);

    // call print_str(HELP)
    let le_help = lea_rdi_rip_placeholder(&mut s);
    mov_rsi_imm32(&mut s, HELP.len() as u32);
    let call_help = call_rel(&mut s);
    s.j32_backpatch("print_str", call_help);
    s.j32_backpatch("HELP", le_help);

    // call print_str(PROMPT)
    let le_prompt = lea_rdi_rip_placeholder(&mut s);
    mov_rsi_imm32(&mut s, PROMPT.len() as u32);
    let call_prompt = call_rel(&mut s);
    s.j32_backpatch("print_str", call_prompt);
    s.j32_backpatch("PROMPT", le_prompt);

    // xor r13, r13 (reset line buffer index); pad with NOPs to 0x260
    xor_r13_r13(&mut s);
    s.align_to(0x260, "read_line");

    // ============== 0x260 read_line (poll loop) ==============
    xor_r10d_r10d(&mut s);
    mov_rax_imm32(&mut s, SYS_POLL_KEY);
    syscall(&mut s);
    cmp_rax_0(&mut s);
    let jle_rl = jle32(&mut s);
    s.j32_backpatch("read_line", jle_rl);

    // Ignore PS/2 break codes before indexing the 128-byte Set-1 table.
    // QEMU sends both make and break bytes for every `sendkey`; without
    // this guard values >= 0x80 read past the end of the table.
    test_al_imm8(&mut s, 0x80);
    let jnz_break = jne32(&mut s);
    s.j32_backpatch("read_line", jnz_break);

    // Read the make-code byte out of the scancode -> ASCII table.
    movzx_edx_al(&mut s);
    // lea rsi, [rip + scancode_table]
    s.u8(0x48);
    s.u8(0x8d);
    s.u8(0x35);
    let le_tbl = s.pos();
    s.u32(0);
    s.j32_backpatch("scancode_table", le_tbl);

    movzx_edx_byte_rsi_rdx(&mut s);
    test_dl_dl(&mut s);
    let jz_np = je32(&mut s);

    // Special-key dispatch. Each je jumps to a real handler instead
    // of being a `disp32 = 0` placeholder like in the previous
    // version. The handlers live between `no_print` (0x2c0) and
    // `print_str` (now at 0x340; was 0x300).
    cmp_dl_imm8(&mut s, 0x0a); // \n = Enter
    let je_nl = je32(&mut s);
    cmp_dl_imm8(&mut s, 0x08); // \b = Backspace
    let je_bs = je32(&mut s);
    cmp_dl_imm8(&mut s, 0x1b); // ESC = clear line
    let je_esc = je32(&mut s);

    // ============== 0x2c0 no_print (regular-character fall-through) ==============
    // The jz_np (table returned 0 -> unmapped scancode) jumps back
    // to read_line to ignore the key. Otherwise we fall through
    // to `append` (regular character: store + echo).
    s.align_to(0x2c0, "no_print");
    s.j32_backpatch("read_line", jz_np);

    // ============== 0x2d0 append (regular printable char) ==============
    s.align_to(0x2d0, "append");
    mov_byte_r15_r13_dl(&mut s);
    inc_r13(&mut s);
    movzx_r10d_dl(&mut s);
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    syscall(&mut s);
    let jmp_rl = jmp_rel(&mut s);
    s.j32_backpatch("read_line", jmp_rl);

    // ============== 0x2e8 submit_line (Enter pressed) ==============
    // r15 = line-buffer base, r13 = current length. Hand the buffer
    // to dispatch_command, then loop back to read_line.
    s.here("submit_line");
    let call_crlf = call_rel(&mut s);
    s.j32_backpatch("print_crlf", call_crlf);
    mov_rdi_r15(&mut s);
    mov_rsi_r13(&mut s);
    xor_r13_r13(&mut s);
    let call_dc = call_rel(&mut s);
    s.j32_backpatch("dispatch_command", call_dc);
    let jmp_rl2 = jmp_rel(&mut s);
    s.j32_backpatch("read_line", jmp_rl2);

    // ============== 0x300 do_backspace (Backspace pressed) ==============
    s.here("do_backspace");
    test_r13_r13(&mut s);
    let jz_bs_done = je32(&mut s);
    s.j32_backpatch("do_backspace_done", jz_bs_done);
    dec_r13(&mut s);
    // Echo BS / SPACE / BS to erase the char on the VGA cell.
    mov_r10d_imm32(&mut s, 0x08);
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    syscall(&mut s);
    mov_r10d_imm32(&mut s, 0x20);
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    syscall(&mut s);
    mov_r10d_imm32(&mut s, 0x08);
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    syscall(&mut s);
    s.here("do_backspace_done");
    let jmp_rl3 = jmp_rel(&mut s);
    s.j32_backpatch("read_line", jmp_rl3);

    // ============== 0x330 do_escape (ESC pressed -> discard input) ==============
    s.here("do_escape");
    xor_r13_r13(&mut s);
    let jmp_rl4 = jmp_rel(&mut s);
    s.j32_backpatch("read_line", jmp_rl4);

    // Now wire the special-key jumps to point at the handlers above.
    s.j32_backpatch("submit_line", je_nl);
    s.j32_backpatch("do_backspace", je_bs);
    s.j32_backpatch("do_escape", je_esc);

    // ============== 0x340 print_str (string-print helper) ==============
    // Shifted from 0x300 -> 0x340 to make room for the submit /
    // backspace / escape handlers between `append` and `print_str`.
    s.align_to(0x340, "print_str");
    push_r12(&mut s);
    push_r13(&mut s);
    push_r14(&mut s);
    push_r15(&mut s);
    mov_r12_rdi(&mut s);
    mov_r14_rsi(&mut s);
    xor_r13_r13(&mut s);

    s.here("print_str_loop");
    cmp_r14_r13(&mut s);
    let je_print_done = je32(&mut s);
    s.j32_backpatch("print_str_done", je_print_done);
    movzx_r10d_byte_r12_r13(&mut s);
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    syscall(&mut s);
    inc_r13(&mut s);
    let jmp_loop = jmp_rel(&mut s);
    s.j32_backpatch("print_str_loop", jmp_loop);

    s.here("print_str_done");
    pop_r12(&mut s);
    pop_r13(&mut s);
    pop_r14(&mut s);
    pop_r15(&mut s);
    ret(&mut s);

    // ============== 0x3a0 put_char (single-byte helper) ==============
    s.align_to(0x3a0, "put_char");
    movzx_edx_dil(&mut s);
    movzx_r10d_dl(&mut s);
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    syscall(&mut s);
    ret(&mut s);

    // ============== 0x3c0 print_crlf ==============
    s.align_to(0x3c0, "print_crlf");
    mov_r10d_imm32(&mut s, 0x0d);
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    syscall(&mut s);
    mov_r10d_imm32(&mut s, 0x0a);
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    syscall(&mut s);
    ret(&mut s);

    // ============== 0x400 dispatch_command (rdi = ptr, rsi = len) ==============
    s.align_to(0x400, "dispatch_command");
    push_rbx(&mut s);
    push_r12(&mut s);
    push_r13(&mut s);
    push_r14(&mut s);
    push_r15(&mut s);
    mov_r14_rdi(&mut s);
    mov_r15_rsi(&mut s);

    // An empty line is not an unknown command. Return directly to the
    // prompt without inspecting the zero-filled input buffer.
    cmp_r15_imm32(&mut s, 0);
    let je_empty = je32(&mut s);
    s.j32_backpatch("dispatch_done", je_empty);

    emit_exit_branch(&mut s, "try_ver");
    s.here("try_ver");
    emit_ver_branch(&mut s, "try_help");
    s.here("try_help");
    emit_help_branch(&mut s, "try_cls");
    s.here("try_cls");
    emit_cls_branch(&mut s, "try_halt");
    s.here("try_halt");
    emit_halt_branch(&mut s, "try_autoexec");
    s.here("try_autoexec");
    emit_autoexec_branch(&mut s, "try_echo");
    s.here("try_echo");
    emit_echo_branch(&mut s, "try_time");
    s.here("try_time");
    emit_time_branch(&mut s, "try_date");
    s.here("try_date");
    emit_date_branch(&mut s, "try_ipconfig");
    s.here("try_ipconfig");
    emit_ipconfig_branch(&mut s, "dispatch_unknown");

    // Only a non-empty line that failed every built-in matcher reaches
    // this block. Successful commands jump directly to dispatch_done.
    s.here("dispatch_unknown");
    let le_unk2 = lea_rdi_rip_placeholder(&mut s);
    mov_rsi_imm32(&mut s, UNKNOWN.len() as u32);
    let call_unk2 = call_rel(&mut s);
    s.j32_backpatch("print_str", call_unk2);
    s.j32_backpatch("UNKNOWN", le_unk2);

    s.here("dispatch_done");
    let le_prompt_rep = lea_rdi_rip_placeholder(&mut s);
    mov_rsi_imm32(&mut s, PROMPT.len() as u32);
    let call_prompt_rep = call_rel(&mut s);
    s.j32_backpatch("print_str", call_prompt_rep);
    s.j32_backpatch("PROMPT", le_prompt_rep);

    pop_r15(&mut s);
    pop_r14(&mut s);
    pop_r13(&mut s);
    pop_r12(&mut s);
    pop_rbx(&mut s);
    ret(&mut s);

    // ============== 0x800 do_exit ==============
    // Shifted from 0x640 -> 0x800 to give the dispatch_command
    // block (0x400-0x800) an extra ~448 bytes for the three new
    // branches (`time`, `date`, `ipconfig`).
    s.align_to(0x800, "do_exit");
    let le_bye = lea_rdi_rip_placeholder(&mut s);
    mov_rsi_imm32(&mut s, EXIT_TXT.len() as u32);
    let call_bye = call_rel(&mut s);
    s.j32_backpatch("print_str", call_bye);
    s.j32_backpatch("EXIT_TXT", le_bye);
    mov_rax_imm32(&mut s, SYS_EXIT);
    xor_r10d_r10d(&mut s);
    syscall(&mut s);

    // ============== 0x900 string table ==============
    s.align_to(0x900, "BANNER");
    s.data.extend_from_slice(BANNER);
    s.here("HELP");
    s.data.extend_from_slice(HELP);
    s.here("UNKNOWN");
    s.data.extend_from_slice(UNKNOWN);
    s.here("VER_TXT");
    s.data.extend_from_slice(VER_TXT);
    s.here("PROMPT");
    s.data.extend_from_slice(PROMPT);
    s.here("HALT");
    s.data.extend_from_slice(HALTTXT);
    s.here("EXIT_TXT");
    s.data.extend_from_slice(EXIT_TXT);
    s.here("TIMETXT");
    s.data.extend_from_slice(TIMETXT);
    s.here("DATETXT");
    s.data.extend_from_slice(DATETXT);
    s.here("IPCFGTXT");
    s.data.extend_from_slice(IPCFGTXT);

    // Pad to 0xA80 (matches Python's `while len(s.data) < 0xA80`).
    while s.data.len() < 0xA80 {
        s.u8(0x00);
    }
    s.here("scancode_table");
    for c in SCAN_TO_ASCII.iter() {
        s.u8(*c);
    }

    // Pad to 4096 (matches `while len(s.data) < 4096: s.data.append(0x90)`).
    while s.data.len() < CMD_STUB_SIZE {
        s.u8(0x90);
    }
    // ============== Resolve fixups ==============
    // `Buf::finalize` resolves every `j32_backpatch` recorded above.
    // We use the same `(target - (disp_off + 4))` displacement that
    // the Python tool computes.
    let bytes = s.finalize();
    assert_eq!(bytes.len(), CMD_STUB_SIZE, "cmd stub size mismatch");
    bytes
}

/// Emit a `lea rdi, [rip+disp32]` whose disp32 is filled in by
/// `Buf::finalize`. Returns the offset of the disp32 placeholder
/// (i.e. where the eventual displacement needs to be written).
/// Callers then record the desired target via
/// `s.j32_backpatch(label, returned_offset)`.
fn lea_rdi_rip_placeholder(s: &mut Buf) -> usize {
    s.u8(0x48);
    s.u8(0x8d);
    s.u8(0x3d);
    let disp = s.pos();
    s.u32(0);
    disp
}

// ===== Command-dispatch branches =================================
// These are split out purely to keep `build()` readable; together they
// reproduce the byte stream of `cmd_asm.py` lines ~298..476 verbatim.

fn emit_exit_branch(s: &mut Buf, next: &str) {
    cmp_byte_r14_0_imm8(s, b'e');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_1_imm8(s, b'x');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_n_imm8(s, 2, b'i');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_n_imm8(s, 3, b't');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_r15_imm32(s, 4);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    let jmp_exit = jmp_rel(s);
    s.j32_backpatch("do_exit", jmp_exit);
}

fn emit_ver_branch(s: &mut Buf, next: &str) {
    cmp_byte_r14_0_imm8(s, b'v');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_1_imm8(s, b'e');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_n_imm8(s, 2, b'r');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_r15_imm32(s, 3);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    let le_ver = lea_rdi_rip_placeholder(s);
    mov_rsi_imm32(s, VER_TXT.len() as u32);
    let call_ver = call_rel(s);
    s.j32_backpatch("print_str", call_ver);
    s.j32_backpatch("VER_TXT", le_ver);
    let jmp_done = jmp_rel(s);
    s.j32_backpatch("dispatch_done", jmp_done);
}

fn emit_help_branch(s: &mut Buf, next: &str) {
    cmp_byte_r14_0_imm8(s, b'h');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_1_imm8(s, b'e');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_n_imm8(s, 2, b'l');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_n_imm8(s, 3, b'p');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_r15_imm32(s, 4);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    let le_help = lea_rdi_rip_placeholder(s);
    mov_rsi_imm32(s, HELP.len() as u32);
    let call_help = call_rel(s);
    s.j32_backpatch("print_str", call_help);
    s.j32_backpatch("HELP", le_help);
    let jmp_done = jmp_rel(s);
    s.j32_backpatch("dispatch_done", jmp_done);
}

fn emit_cls_branch(s: &mut Buf, next: &str) {
    cmp_byte_r14_0_imm8(s, b'c');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_1_imm8(s, b'l');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_n_imm8(s, 2, b's');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_r15_imm32(s, 3);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    mov_rax_imm32(s, SYS_CLEAR);
    xor_r10d_r10d(s);
    syscall(s);
    let jmp_done = jmp_rel(s);
    s.j32_backpatch("dispatch_done", jmp_done);
}

fn emit_halt_branch(s: &mut Buf, next: &str) {
    cmp_byte_r14_0_imm8(s, b'h');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_1_imm8(s, b'a');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_n_imm8(s, 2, b'l');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_byte_r14_n_imm8(s, 3, b't');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    cmp_r15_imm32(s, 4);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    let le_halt = lea_rdi_rip_placeholder(s);
    mov_rsi_imm32(s, HALTTXT.len() as u32);
    let call_halt = call_rel(s);
    s.j32_backpatch("print_str", call_halt);
    s.j32_backpatch("HALT", le_halt);
    let jmp_exit = jmp_rel(s);
    s.j32_backpatch("do_exit", jmp_exit);
}

fn emit_autoexec_branch(s: &mut Buf, next: &str) {
    for (index, byte) in b"autoexec".iter().copied().enumerate() {
        cmp_byte_r14_n_imm8(s, index as u8, byte);
        let jne = jne32(s);
        s.j32_backpatch(next, jne);
    }
    cmp_r15_imm32(s, 8);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    mov_rax_imm32(s, SYS_RUN_AUTOEXEC);
    xor_r10d_r10d(s);
    syscall(s);
    let jmp_done = jmp_rel(s);
    s.j32_backpatch("dispatch_done", jmp_done);
}

fn emit_echo_branch(s: &mut Buf, next: &str) {
    for (index, byte) in b"echo".iter().copied().enumerate() {
        cmp_byte_r14_n_imm8(s, index as u8, byte);
        let jne = jne32(s);
        s.j32_backpatch(next, jne);
    }
    cmp_r15_imm32(s, 5);
    let jl = jl32(s);
    s.j32_backpatch(next, jl);
    cmp_byte_r14_n_imm8(s, 4, b' ');
    let jne = jne32(s);
    s.j32_backpatch(next, jne);
    mov_rdi_r14(s);
    add_rdi_imm8(s, 5);
    mov_rsi_r15(s);
    sub_rsi_imm8(s, 5);
    let call_echo = call_rel(s);
    s.j32_backpatch("print_str", call_echo);
    let call_crlf = call_rel(s);
    s.j32_backpatch("print_crlf", call_crlf);
    let jmp_done = jmp_rel(s);
    s.j32_backpatch("dispatch_done", jmp_done);
}

/// Inline helper: print a single decimal digit pair (byte in
/// `dl`, 0..99) via two SYS_PUTCHAR calls. Used by `time` and
/// `date` to format hour/min/sec/month/day (which are always
/// 0..59 or 1..31). The caller is responsible for preserving
/// any registers it cares about (this helper clobbers `eax`,
/// `ecx`, `edx`, `r10`, `r11` via `syscall`).
fn emit_print_dec_byte(s: &mut Buf) {
    push_rcx(s);
    push_rdx(s);
    movzx_eax_dl(s);
    mov_ecx_imm32(s, 10);
    xor_edx_edx(s);
    div_ecx(s);
    add_al_imm8(s, 0x30);
    movzx_r10d_eax(s);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    // edx still holds the units digit (syscall preserves rdx).
    movzx_r10d_edx_load(s);
    add_dl_imm8(s, 0x30);
    movzx_r10d_dl(s);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    pop_rdx(s);
    pop_rcx(s);
}

/// Inline helper: print a single separator byte (the value of
/// `dl` is replaced with the given immediate before each call).
fn emit_print_sep(s: &mut Buf, sep: u8) {
    mov_dl_imm8(s, sep);
    movzx_r10d_dl(s);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
}

/// `mov r10d, edx` — reload the units digit (which `div` left in
/// `edx`) after the first SYS_PUTCHAR clobbered `r10d`.
/// Encoding: 41 0F B6 D2 (REX.B on r10d destination, source=edx).
fn movzx_r10d_edx_load(s: &mut Buf) {
    s.u8(0x41);
    s.u8(0x0f);
    s.u8(0xb6);
    s.u8(0xd2);
}

/// `mov eax, edx` — copy a div remainder into eax so it can be
/// re-divided (used by the 3-digit printer).
/// Encoding: 89 D0 (mov eax, edx).
fn mov_eax_edx(s: &mut Buf) {
    s.u8(0x89);
    s.u8(0xd0);
}

/// `time` builtin — call SYS_GET_RTC, then print the 16-byte
/// buffer as `HH:MM:SS`. Bytes 4..7 of the kernel-side TimeFields
/// hold hour, minute, second (host byte order).
fn emit_time_branch(s: &mut Buf, next: &str) {
    for (index, byte) in b"time".iter().copied().enumerate() {
        cmp_byte_r14_n_imm8(s, index as u8, byte);
        let jne = jne32(s);
        s.j32_backpatch(next, jne);
    }
    cmp_r15_imm32(s, 4);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);

    // Print the "  Current Time: " label.
    let le_lbl = lea_rdi_rip_placeholder(s);
    mov_rsi_imm32(s, TIMETXT.len() as u32);
    let call_lbl = call_rel(s);
    s.j32_backpatch("print_str", call_lbl);
    s.j32_backpatch("TIMETXT", le_lbl);

    // Reserve 32 bytes on the stack; SYS_GET_RTC writes a 16-byte
    // TimeFields into [rsp] (r10 = rsp at the moment of syscall).
    sub_rsp_imm32(s, 32);
    mov_r10_rsp(s);
    mov_rax_imm32(s, SYS_GET_RTC);
    syscall(s);

    // hour (byte 4)
    mov_al_byte_rsp_disp8(s, 4);
    emit_print_dec_byte(s);
    emit_print_sep(s, b':');

    // minute (byte 5)
    mov_al_byte_rsp_disp8(s, 5);
    emit_print_dec_byte(s);
    emit_print_sep(s, b':');

    // second (byte 6)
    mov_al_byte_rsp_disp8(s, 6);
    emit_print_dec_byte(s);

    // CRLF + restore stack + jump to epilogue.
    mov_r10d_imm32(s, 0x0d);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    mov_r10d_imm32(s, 0x0a);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    add_rsp_imm32(s, 32);
    let jmp_t = jmp_rel(s);
    s.j32_backpatch("dispatch_done", jmp_t);
}

/// `date` builtin — print `YYYY-MM-DD` from the SYS_GET_RTC
/// buffer. Year is little-endian u16 in bytes 0..2, month in 2,
/// day in 3.
fn emit_date_branch(s: &mut Buf, next: &str) {
    for (index, byte) in b"date".iter().copied().enumerate() {
        cmp_byte_r14_n_imm8(s, index as u8, byte);
        let jne = jne32(s);
        s.j32_backpatch(next, jne);
    }
    cmp_r15_imm32(s, 4);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);

    // Print the "  Current Date: " label.
    let le_lbl = lea_rdi_rip_placeholder(s);
    mov_rsi_imm32(s, DATETXT.len() as u32);
    let call_lbl = call_rel(s);
    s.j32_backpatch("print_str", call_lbl);
    s.j32_backpatch("DATETXT", le_lbl);

    sub_rsp_imm32(s, 32);
    mov_r10_rsp(s);
    mov_rax_imm32(s, SYS_GET_RTC);
    syscall(s);

    // year high byte (byte 1)
    mov_al_byte_rsp_disp8(s, 1);
    emit_print_dec_byte(s);
    // year low byte (byte 0)
    mov_al_byte_rsp_disp8(s, 0);
    emit_print_dec_byte(s);
    emit_print_sep(s, b'-');
    // month (byte 2)
    mov_al_byte_rsp_disp8(s, 2);
    emit_print_dec_byte(s);
    emit_print_sep(s, b'-');
    // day (byte 3)
    mov_al_byte_rsp_disp8(s, 3);
    emit_print_dec_byte(s);

    // CRLF + restore stack + jump to epilogue.
    mov_r10d_imm32(s, 0x0d);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    mov_r10d_imm32(s, 0x0a);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    add_rsp_imm32(s, 32);
    let jmp_d = jmp_rel(s);
    s.j32_backpatch("dispatch_done", jmp_d);
}

/// `ipconfig` builtin — call SYS_NETCFG_GET once into a 16-byte
/// buffer, then print the three dotted-quad fields. The kernel
/// returns the IPv4 fields in network byte order (big endian), so
/// the user-mode stub prints each byte as a 3-digit decimal
/// (zero-padded) separated by `.` — works for any byte 0..255.
fn emit_ipconfig_branch(s: &mut Buf, next: &str) {
    for (index, byte) in b"ipconfig".iter().copied().enumerate() {
        cmp_byte_r14_n_imm8(s, index as u8, byte);
        let jne = jne32(s);
        s.j32_backpatch(next, jne);
    }
    cmp_r15_imm32(s, 8);
    let jne = jne32(s);
    s.j32_backpatch(next, jne);

    // Print the multi-line "Windows IP Configuration" template.
    let le_lbl = lea_rdi_rip_placeholder(s);
    mov_rsi_imm32(s, IPCFGTXT.len() as u32);
    let call_lbl = call_rel(s);
    s.j32_backpatch("print_str", call_lbl);
    s.j32_backpatch("IPCFGTXT", le_lbl);

    sub_rsp_imm32(s, 32);
    mov_r10_rsp(s);
    mov_rax_imm32(s, SYS_NETCFG_GET);
    syscall(s);

    // Print bytes [0..4] (IPv4), [4..8] (mask), [8..12] (gateway)
    // as four 3-digit decimal numbers separated by '.'.
    let starts = [0u8, 4u8, 8u8];
    for start in starts.iter() {
        for j in 0u8..4 {
            mov_al_byte_rsp_disp8(s, start + j);
            emit_print_dec_byte_3(s);
            if j < 3 {
                emit_print_sep(s, b'.');
            }
        }
        emit_print_sep(s, 0x0d);
        emit_print_sep(s, 0x0a);
    }

    add_rsp_imm32(s, 32);
    let jmp_ip = jmp_rel(s);
    s.j32_backpatch("dispatch_done", jmp_ip);
}

/// Inline helper: print a single byte (0..255) as a 3-digit
/// zero-padded decimal (e.g. 127 -> "127", 7 -> "007"). Used by
/// `ipconfig` to render each IPv4 octet.
fn emit_print_dec_byte_3(s: &mut Buf) {
    // hundreds digit = dl / 100
    push_rcx(s);
    push_rdx(s);
    movzx_eax_dl(s);
    mov_ecx_imm32(s, 100);
    xor_edx_edx(s);
    div_ecx(s); // eax = hundreds, edx = dl % 100
    add_al_imm8(s, 0x30);
    movzx_r10d_eax(s);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    // Print tens and units of dl % 100 (currently in edx).
    // Reload eax from edx so we can divide again by 10.
    mov_eax_edx(s);
    mov_ecx_imm32(s, 10);
    xor_edx_edx(s);
    div_ecx(s); // eax = tens, edx = units
    add_al_imm8(s, 0x30);
    movzx_r10d_eax(s);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    movzx_r10d_edx_load(s);
    add_dl_imm8(s, 0x30);
    movzx_r10d_dl(s);
    mov_rax_imm32(s, SYS_PUTCHAR);
    syscall(s);
    pop_rdx(s);
    pop_rcx(s);
}
