//! Byte buffer + x86_64 instruction emitters used to assemble the cmd.exe
//! and subsystem stubs.
//!
//! Models `tools/cmd-stub-gen/cmd_asm.py::Buf` and the byte-by-byte
//! hand-encoding in that script. Labels capture the in-buffer offset of
//! the next byte; `j32_backpatch` registers a 32-bit relative
//! displacement that is filled in at `finalize` time.

use std::collections::HashMap;

/// Append-only byte buffer with label/fixup support.
pub struct Buf {
    pub data: Vec<u8>,
    pub labels: HashMap<String, usize>,
    pub fixups: Vec<(String, usize)>,
}

impl Buf {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            labels: HashMap::new(),
            fixups: Vec::new(),
        }
    }

    pub fn u8(&mut self, b: u8) {
        self.data.push(b);
    }

    pub fn u32(&mut self, dw: u32) {
        self.data.extend_from_slice(&dw.to_le_bytes());
    }

    /// Mark `name` at the current `data.len()` (mirrors Python `s.here(name)`).
    pub fn here(&mut self, name: &str) {
        self.labels.insert(name.to_string(), self.data.len());
    }

    /// Pad with `0x90` (NOP) up to `off`, then place `name` at the
    /// resulting offset (mirrors Python `s.align_to(off, name)`).
    pub fn align_to(&mut self, off: usize, name: &str) {
        while self.data.len() < off {
            self.data.push(0x90);
        }
        self.labels.insert(name.to_string(), self.data.len());
    }

    pub fn pos(&self) -> usize {
        self.data.len()
    }

    /// Record that the 4-byte disp32 at `disp_off` must be patched to
    /// point at the resolved offset of `name`.
    pub fn j32_backpatch(&mut self, name: &str, disp_off: usize) {
        self.fixups.push((name.to_string(), disp_off));
    }

    /// Resolve every queued fixup, in-place. Returns the final byte
    /// vector.
    pub fn finalize(&self) -> Vec<u8> {
        let mut out = self.data.clone();
        for (name, off) in &self.fixups {
            let tgt = self.labels[name];
            let disp = tgt.wrapping_sub(off.wrapping_add(4)) & 0xFFFFFFFF;
            out[*off..*off + 4].copy_from_slice(&(disp as u32).to_le_bytes());
        }
        out
    }
}

// ===== Misc single-byte mnemonics =================================

pub fn cli(b: &mut Buf) {
    b.u8(0xfa);
}
pub fn cld(b: &mut Buf) {
    b.u8(0xfc);
}
pub fn ret(b: &mut Buf) {
    b.u8(0xc3);
}
pub fn syscall(b: &mut Buf) {
    b.u8(0x0f);
    b.u8(0x05);
}

// ===== Stack ops ===================================================

pub fn push_rbx(b: &mut Buf) {
    b.u8(0x53);
}
pub fn push_r12(b: &mut Buf) {
    b.u8(0x41);
    b.u8(0x54);
}
pub fn push_r13(b: &mut Buf) {
    b.u8(0x41);
    b.u8(0x55);
}
pub fn push_r14(b: &mut Buf) {
    b.u8(0x41);
    b.u8(0x56);
}
pub fn push_r15(b: &mut Buf) {
    b.u8(0x41);
    b.u8(0x57);
}

pub fn pop_rbx(b: &mut Buf) {
    b.u8(0x5b);
}
pub fn pop_r12(b: &mut Buf) {
    b.u8(0x41);
    b.u8(0x5c);
}
pub fn pop_r13(b: &mut Buf) {
    b.u8(0x41);
    b.u8(0x5d);
}
pub fn pop_r14(b: &mut Buf) {
    b.u8(0x41);
    b.u8(0x5e);
}
pub fn pop_r15(b: &mut Buf) {
    b.u8(0x41);
    b.u8(0x5f);
}

// ===== mov reg, imm32 ==============================================

pub fn mov_rax_imm32(b: &mut Buf, imm: u32) {
    b.u8(0xb8);
    b.u32(imm);
}
pub fn mov_rsi_imm32(b: &mut Buf, imm: u32) {
    b.u8(0xbe);
    b.u32(imm);
}
pub fn mov_r10d_imm32(b: &mut Buf, imm: u32) {
    b.u8(0x41);
    b.u8(0xba);
    b.u32(imm);
}

// ===== xor / reg-reg moves =========================================

pub fn xor_r10d_r10d(b: &mut Buf) {
    // 45 31 D2 : xor r10d, r10d
    b.u8(0x45);
    b.u8(0x31);
    b.u8(0xd2);
}
pub fn xor_r13_r13(b: &mut Buf) {
    // 4D 31 ED : xor r13, r13
    b.u8(0x4d);
    b.u8(0x31);
    b.u8(0xed);
}
pub fn mov_r12_rdi(b: &mut Buf) {
    // 49 89 FC : mov r12, rdi
    b.u8(0x49);
    b.u8(0x89);
    b.u8(0xfc);
}
pub fn mov_r14_rsi(b: &mut Buf) {
    // 49 89 F6 : mov r14, rsi
    b.u8(0x49);
    b.u8(0x89);
    b.u8(0xf6);
}
pub fn mov_r14_rdi(b: &mut Buf) {
    // 49 89 FE : mov r14, rdi
    b.u8(0x49);
    b.u8(0x89);
    b.u8(0xfe);
}
pub fn mov_r15_rsi(b: &mut Buf) {
    // 49 89 F7 : mov r15, rsi
    b.u8(0x49);
    b.u8(0x89);
    b.u8(0xf7);
}
/// `mov rdi, r15` — copy r15 (the user-mode `cmd.exe` line-buffer
/// base) into rdi before calling dispatch_command. The
/// dispatcher's epilogue expects `rdi` to point at the input
/// buffer and `rsi` to carry its length.
pub fn mov_rdi_r15(b: &mut Buf) {
    // 4C 89 FF : mov rdi, r15
    b.u8(0x4c);
    b.u8(0x89);
    b.u8(0xff);
}

/// `mov rsi, r13` — copy r13 (the user-mode `cmd.exe` line-buffer
/// length counter) into rsi before calling dispatch_command.
pub fn mov_rsi_r13(b: &mut Buf) {
    // 4C 89 EE : mov rsi, r13
    b.u8(0x4c);
    b.u8(0x89);
    b.u8(0xee);
}
pub fn mov_r15_rsp(b: &mut Buf) {
    // 49 89 E7 : mov r15, rsp
    b.u8(0x49);
    b.u8(0x89);
    b.u8(0xe7);
}

// ===== Arithmetic / control =======================================

pub fn sub_rsp_imm32(b: &mut Buf, imm: u32) {
    // 48 81 EC imm32
    b.u8(0x48);
    b.u8(0x81);
    b.u8(0xec);
    b.u32(imm);
}

/// `mov r10, r14` — pass the Ring-3 line pointer as syscall arg0.
pub fn mov_r10_r14(b: &mut Buf) {
    b.u8(0x4d);
    b.u8(0x89);
    b.u8(0xf2);
}

/// `mov rdx, r13` — pass the Ring-3 line length as syscall arg1.
pub fn mov_rdx_r15(b: &mut Buf) {
    // REX.W + REX.R: move R15 (second operand bit 3) to RDX.
    b.u8(0x4c);
    b.u8(0x89);
    b.u8(0xfa);
}

pub fn inc_r13(b: &mut Buf) {
    // 49 FF C5
    b.u8(0x49);
    b.u8(0xff);
    b.u8(0xc5);
}

/// `dec r13` — decrement the line-buffer index used by the
/// user-mode `cmd.exe` stub's read loop. Used by the backspace
/// handler to pop one character off the in-progress input.
pub fn dec_r13(b: &mut Buf) {
    // 49 FF CD
    b.u8(0x49);
    b.u8(0xff);
    b.u8(0xcd);
}

/// `test r13, r13` — set ZF if the line-buffer index is zero.
/// Used by the backspace handler to skip the operation when the
/// input buffer is empty.
pub fn test_r13_r13(b: &mut Buf) {
    // 4D 85 ED
    b.u8(0x4d);
    b.u8(0x85);
    b.u8(0xed);
}

// ===== RIP-relative LEA ============================================

// ===== RIP-relative LEA ============================================
//
// All three LEA emitters were retained when the stubs were first
// ported from `cmd_asm.py`. Once the live stubs only emit one of
// them (or none) the unused variants will return in this file;
// keeping the unused helpers around makes the warnings reappear
// every time the stub layout changes.

// ===== Calls / jumps (return the position of the disp32 so the
// =====  caller can backpatch it via `j32_backpatch`). ==============

pub fn call_rel(b: &mut Buf) -> usize {
    b.u8(0xe8);
    let off = b.pos();
    b.u32(0);
    off
}
pub fn jmp_rel(b: &mut Buf) -> usize {
    b.u8(0xe9);
    let off = b.pos();
    b.u32(0);
    off
}

pub fn je32(b: &mut Buf) -> usize {
    b.u8(0x0f);
    b.u8(0x84);
    let off = b.pos();
    b.u32(0);
    off
}
pub fn jne32(b: &mut Buf) -> usize {
    b.u8(0x0f);
    b.u8(0x85);
    let off = b.pos();
    b.u32(0);
    off
}
pub fn jle32(b: &mut Buf) -> usize {
    b.u8(0x0f);
    b.u8(0x8e);
    let off = b.pos();
    b.u32(0);
    off
}

// ===== cmp / test ==================================================

pub fn cmp_rax_0(b: &mut Buf) {
    // 48 83 F8 00
    b.u8(0x48);
    b.u8(0x83);
    b.u8(0xf8);
    b.u8(0x00);
}
pub fn cmp_dl_imm8(b: &mut Buf, imm: u8) {
    // 80 FA imm8
    b.u8(0x80);
    b.u8(0xfa);
    b.u8(imm);
}

pub fn cmp_r15_imm32(b: &mut Buf, imm: u32) {
    // 49 83 FF ib : cmp r15, sign-extended imm8. Command lengths are
    // all below 128, so the compact form is sufficient. The old emitter
    // incorrectly wrote a four-byte immediate after opcode 0x83, causing
    // the extra three bytes to be decoded as instructions.
    assert!(imm <= i8::MAX as u32, "cmp r15 immediate out of range");
    b.u8(0x49);
    b.u8(0x83);
    b.u8(0xff);
    b.u8(imm as u8);
}

pub fn cmp_r14_r13(b: &mut Buf) {
    // 4D 39 EE : cmp r14, r13
    b.u8(0x4d);
    b.u8(0x39);
    b.u8(0xee);
}

pub fn test_dl_dl(b: &mut Buf) {
    // 84 D2
    b.u8(0x84);
    b.u8(0xd2);
}

/// `test al, imm8` — used to discard PS/2 break codes, whose high bit
/// is set, before indexing the 128-byte make-code translation table.
pub fn test_al_imm8(b: &mut Buf, imm: u8) {
    // A8 ib
    b.u8(0xa8);
    b.u8(imm);
}

// ===== movzx =======================================================

pub fn movzx_edx_al(b: &mut Buf) {
    // 0F B6 D0
    b.u8(0x0f);
    b.u8(0xb6);
    b.u8(0xd0);
}
pub fn movzx_edx_dil(b: &mut Buf) {
    // 40 0F B6 D7
    b.u8(0x40);
    b.u8(0x0f);
    b.u8(0xb6);
    b.u8(0xd7);
}
pub fn movzx_r10d_dl(b: &mut Buf) {
    // 44 0F B6 D2
    b.u8(0x44);
    b.u8(0x0f);
    b.u8(0xb6);
    b.u8(0xd2);
}
pub fn movzx_edx_byte_rsi_rdx(b: &mut Buf) {
    // 0F B6 14 16
    b.u8(0x0f);
    b.u8(0xb6);
    b.u8(0x14);
    b.u8(0x16);
}
pub fn movzx_r10d_byte_r12_r13(b: &mut Buf) {
    // 47 0F B6 14 2C : movzx r10d, byte [r12 + r13]
    b.u8(0x47);
    b.u8(0x0f);
    b.u8(0xb6);
    b.u8(0x14);
    b.u8(0x2c);
}

// ===== Stores =======================================================

/// `mov byte [r15+r13], dl`
pub fn mov_byte_r15_r13_dl(b: &mut Buf) {
    // 43 88 14 2F
    b.u8(0x43);
    b.u8(0x88);
    b.u8(0x14);
    b.u8(0x2f);
}
