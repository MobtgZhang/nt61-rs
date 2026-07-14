//! `lsm.exe` / `winlogon.exe` / `userinit.exe` 256-byte stubs.
//!
//! Mirrors `tools/cmd-stub-gen/all_stubs.py::emit_*_body()`. Each stub
//! uses two syscalls:
//!   * SYS_PUTCHAR (0x0202) — emit one byte at a time
//!   * SYS_POLL_KEY (0x0203) — non-blocking keyboard poll
//! winlogon / userinit additionally use SYS_SPAWN_SUBSYSTEM_PROCESS
//! (0x0210) to fork the next stage of the boot chain.
//!
//! Body sizes:
//!   lsm      — 256 bytes
//!   winlogon — 256 bytes
//!   userinit — 256 bytes
//!
//! The Python `emit_spawn` helper writes a `lea rdx, [rip+disp32]`
//! whose target isn't known until the path string bytes have been
//! emitted, so we capture each placeholder offset and resolve them
//! at the end of `build_winlogon` / `build_userinit`.

use crate::codegen::*;
use crate::strings::{
    LSM_STUB_SIZE, SYS_POLL_KEY, SYS_PUTCHAR, SYS_SPAWN_SUBSYSTEM_PROC, WINLOGON_STUB_SIZE,
};

const LSM_BANNER: &[u8] = b"[LSM] entered, idling forever\r\n";
const WINLOGON_BANNER: &[u8] = b"[WINLOGON] session 1 ready\r\n";
const USERINIT_BANNER: &[u8] = b"[USERINIT] launching cmd.exe\r\n";

const PATH_CSRSS: &[u8] = b"C:\\Windows\\System32\\csrss.exe\x00";
const PATH_USERINIT: &[u8] = b"C:\\Windows\\System32\\userinit.exe\x00";
const PATH_CMD: &[u8] = b"C:\\Windows\\System32\\cmd.exe\x00";

pub fn build_lsm() -> Vec<u8> {
    let mut s = Buf::new();

    // 0x000: print LSM_BANNER character-by-character.
    for &c in LSM_BANNER {
        mov_rax_imm32(&mut s, SYS_PUTCHAR);
        mov_r10d_imm32(&mut s, c as u32);
        syscall(&mut s);
    }

    // Pad to 0x100, then the idle loop. The idle loop is encoded as
    // raw bytes (matches Python's `OUT.extend(b'...')`).
    s.align_to(0x100, "lsm_idle");

    // xor eax, eax
    s.u8(0x31);
    s.u8(0xc0);
    // mov eax, SYS_POLL_KEY
    mov_rax_imm32(&mut s, SYS_POLL_KEY);
    // syscall
    syscall(&mut s);
    // cmp rax, 0  ; 48 83 F8 00
    s.u8(0x48);
    s.u8(0x83);
    s.u8(0xf8);
    s.u8(0x00);
    // jle .loop   ; 7E F3
    s.u8(0x7e);
    s.u8(0xf3);
    // movzx r10d, al  ; 44 0F B6 D0
    s.u8(0x44);
    s.u8(0x0f);
    s.u8(0xb6);
    s.u8(0xd0);
    // mov eax, SYS_PUTCHAR
    mov_rax_imm32(&mut s, SYS_PUTCHAR);
    // syscall
    syscall(&mut s);
    // jmp .loop
    s.u8(0xeb);
    s.u8(0xe6);

    while s.data.len() < LSM_STUB_SIZE {
        s.u8(0x90);
    }
    let mut bytes = s.finalize();
    bytes.truncate(LSM_STUB_SIZE);
    bytes
}

pub fn build_winlogon() -> Vec<u8> {
    let mut s = Buf::new();

    // 0x000: print WINLOGON_BANNER.
    for &c in WINLOGON_BANNER {
        mov_rax_imm32(&mut s, SYS_PUTCHAR);
        mov_r10d_imm32(&mut s, c as u32);
        syscall(&mut s);
    }

    // 0x030: emit_spawn(csrss_path)  ; placeholder path_off resolved later.
    s.align_to(0x40, "winlogon_spawn_cs");
    let cs_lea_off = emit_spawn(&mut s);

    s.align_to(0x80, "winlogon_spawn_ui");
    let ui_lea_off = emit_spawn(&mut s);

    s.align_to(0xC0, "winlogon_idle");
    s.u8(0xeb); // jmp $
    s.u8(0xfe);

    // Strings at 0x100 — note csrss appears at the front so the
    // userinit path can be derived as `csrss_off + len(PATH_CSRSS)`.
    s.align_to(0x100, "winlogon_path_csrss");
    let csrss_off = s.pos();
    s.data.extend_from_slice(PATH_CSRSS);
    let userinit_off = s.pos();
    s.data.extend_from_slice(PATH_USERINIT);

    // Patch the two spawn LEAs (disp32 begins 3 bytes after the
    // start of the instruction, so `lea_off + 4` is the byte just
    // past the disp32).
    patch_lea_disp32(&mut s, cs_lea_off, csrss_off);
    patch_lea_disp32(&mut s, ui_lea_off, userinit_off);

    while s.data.len() < WINLOGON_STUB_SIZE {
        s.u8(0x90);
    }
    let mut bytes = s.finalize();
    bytes.truncate(WINLOGON_STUB_SIZE);
    bytes
}

pub fn build_userinit() -> Vec<u8> {
    let mut s = Buf::new();

    for &c in USERINIT_BANNER {
        mov_rax_imm32(&mut s, SYS_PUTCHAR);
        mov_r10d_imm32(&mut s, c as u32);
        syscall(&mut s);
    }

    s.align_to(0x40, "userinit_spawn_cmd");
    let spawn_lea = emit_spawn(&mut s);

    s.align_to(0x80, "userinit_idle");
    s.u8(0xeb); // jmp $
    s.u8(0xfe);

    s.align_to(0x100, "userinit_path_cmd");
    let path_off = s.pos();
    s.data.extend_from_slice(PATH_CMD);

    patch_lea_disp32(&mut s, spawn_lea, path_off);

    while s.data.len() < WINLOGON_STUB_SIZE {
        s.u8(0x90);
    }
    let mut bytes = s.finalize();
    bytes.truncate(WINLOGON_STUB_SIZE);
    bytes
}

// ===== Helpers =====================================================

/// Emit `lea rdx, [rip+disp32]; mov eax, SYS_SPAWN_SUBSYSTEM_PROC;
/// syscall`. Returns the offset of the disp32 placeholder so the
/// caller can patch the displacement once the target string is
/// known.
fn emit_spawn(s: &mut Buf) -> usize {
    // lea rdx, [rip+disp32]   ; 48 8D 15 <disp32>
    s.u8(0x48);
    s.u8(0x8d);
    s.u8(0x15);
    let disp_off = s.pos();
    s.u32(0);

    mov_rax_imm32(s, SYS_SPAWN_SUBSYSTEM_PROC);
    syscall(s);

    disp_off
}

/// Compute `disp = target - (lea_disp32_off + 4)` (matching Python's
/// `disp = (path_off - (target_off + 7)) & 0xffffffff`, where the
/// 7 = `48 8D 15 <4-byte disp>` total length) and write the disp32 in
/// place.
fn patch_lea_disp32(s: &mut Buf, lea_disp32_off: usize, target_off: usize) {
    let disp = (target_off.wrapping_sub(lea_disp32_off + 4) & 0xFFFFFFFF) as u32;
    s.data[lea_disp32_off..lea_disp32_off + 4].copy_from_slice(&disp.to_le_bytes());
}
