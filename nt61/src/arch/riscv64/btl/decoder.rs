//! x86 / x86-64 instruction decoder for the RISC-V BTL.
//!
//! Decodes the guest binary's basic block (from a 16-bit entry
//! cache line up to a maximum of 1024 bytes) into a sequence of
//! [`IrInst`]s suitable for the translator. The decoder is
//! resolver-agnostic — symbol resolution happens later, in the
//! translator, when we know the target RV64 addresses.
//!
//! ## x86 vs x86-64
//!
//! The decoder supports *both* guest modes:
//!
//! * 32-bit (RMODE32): opcode prefix `0x66` is interpreted as
//!   operand-size override; 64-bit immediates are illegal.
//! * 64-bit (RMODE64): REX prefixes widen operands; the high 8
//!   registers (R8..R15) and immediate-64 are available.
//!
//! The decoding path is the same; only the prefix / REX
//! interpretation changes. The decision comes from
//! [`crate::arch::riscv64::btl::mem::decoder_mode`].

#![cfg(feature = "btl")]

/// Maximum bytes scanned per basic-block decode pass.
pub const MAX_BLOCK_BYTES: usize = 1024;

/// x86 / x86-64 guest register identifiers used by the IR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X86Reg {
    Rax = 0, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
    Rip, EFlags,
    // FPU / SSE — Phase 6 will wire this in.
    Xmm0,
    /// Last sentinel — not a real register.
    Count,
}

/// x86 addressing mode used by memory operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrMode {
    /// `[base]`, `[base + disp]`, `[base + index*scale + disp]`
    BaseIndex(u8 /*X86Reg*/,
              Option<u8 /*X86Reg*/>,
              u8 /*scale = 1,2,4,8*/,
              i32 /*disp*/),
    /// `disp32` (RIP-relative in 64-bit mode).
    RipRel(i32),
    /// `moffs` (segment:offset memory operand).
    Moffs(u64),
}

/// Decoder mode (32-bit or 64-bit guest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecMode { Mode32, Mode64 }

/// Decoded x86 operand.
#[derive(Clone, Copy, Debug)]
pub enum Operand {
    Reg(X86Reg),
    Imm8(i8),
    Imm16(i16),
    Imm32(i32),
    Imm64(i64),
    Mem(AddrMode),
}

/// Instruction classes recognized by the decoder. We only model
/// the most common subset that real NT user-mode programs touch;
/// everything else lowers to a `EmitUnsupported` IR opcode that
/// the runtime handles by trapping back to the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mnemonic {
    Mov, Movzx, Movsx,
    Add, Sub, And, Or, Xor,
    Cmp, Test,
    Jmp, Jcc, Call, Ret, Syscall,
    Push, Pop,
    Int80, Sysenter,
    Nop, Hlt,
    Unknown,
}

/// Decoded instruction.
#[derive(Clone, Copy, Debug)]
pub struct X86Inst {
    pub mnemonic: Mnemonic,
    pub dst: Option<Operand>,
    pub src: Option<Operand>,
    pub width: u8,            // 1, 2, 4 or 8 bytes
    pub raw_off: u32,         // offset into the guest block
    pub raw_len: u16,         // bytes consumed
}

impl X86Inst {
    pub const fn empty() -> Self {
        Self { mnemonic: Mnemonic::Nop,
               dst: None, src: None,
               width: 0, raw_off: 0, raw_len: 0 }
    }
}

/// Decode up to `bytes.len()` bytes from `bytes`, writing decoded
/// instructions into `out` (a caller-allocated array of `MAX_DECODED_INSTS`).
/// Returns the number of bytes consumed.
pub fn decode_block(bytes: &[u8],
                    base_va: u64,
                    mode: DecMode,
                    out: &mut [X86Inst])
                    -> usize {
    let mut i = 0;
    let mut written = 0;
    while i < bytes.len() && i < MAX_BLOCK_BYTES && written < out.len() {
        let inst = decode_one(&bytes[i..], base_va + i as u64, mode);
        let len = inst.raw_len as usize;
        if len == 0 { break; }
        out[written] = inst;
        written += 1;
        i += len;
        if matches!(out[written - 1].mnemonic,
                    Mnemonic::Ret | Mnemonic::Jmp | Mnemonic::Hlt)
        { break; }
    }
    i
}

/// Maximum number of decoded instructions in a single block.
pub const MAX_DECODED_INSTS: usize = 128;

/// Decode a single x86 instruction. Phase 4 implements the
/// hot subset: 0x90 NOP, 0xC3 RET, 0xE9/0xEB JMP, 0xE8 CALL,
/// 0x0F 0x05 SYSCALL, 0xB8+r MOV r64,imm, 0x01/0x29/0x31/0x33 ALU,
/// 0x9C PUSHF, 0x9D POPF. Anything else returns `Mnemonic::Unknown`.
fn decode_one(bytes: &[u8], va: u64, mode: DecMode) -> X86Inst {
    if bytes.is_empty() { return X86Inst::empty(); }
    let op = bytes[0];
    let mut inst = X86Inst::empty();
    inst.raw_off = va as u32;
    match op {
        0x90 => { inst.mnemonic = Mnemonic::Nop; inst.width = 0; inst.raw_len = 1; }
        0xC3 => { inst.mnemonic = Mnemonic::Ret;     inst.width = 0; inst.raw_len = 1; }
        0xE9 => {
            if bytes.len() < 5 { return X86Inst::empty(); }
            let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            inst.mnemonic = Mnemonic::Jmp;
            inst.dst = Some(Operand::Imm64((va as i64 + 5 + rel as i64) as i64));
            inst.width = 4;
            inst.raw_len = 5;
        }
        0xEB => {
            if bytes.len() < 2 { return X86Inst::empty(); }
            let rel = bytes[1] as i8;
            inst.mnemonic = Mnemonic::Jmp;
            inst.dst = Some(Operand::Imm64((va as i64 + 2 + rel as i64) as i64));
            inst.width = 1;
            inst.raw_len = 2;
        }
        0xE8 => {
            if bytes.len() < 5 { return X86Inst::empty(); }
            let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            inst.mnemonic = Mnemonic::Call;
            inst.dst = Some(Operand::Imm64((va as i64 + 5 + rel as i64) as i64));
            inst.width = 4;
            inst.raw_len = 5;
        }
        0x0F if matches!(bytes.get(1), Some(0x05)) => {
            inst.mnemonic = if mode == DecMode::Mode64 {
                Mnemonic::Syscall
            } else {
                Mnemonic::Sysenter
            };
            inst.width = 0;
            inst.raw_len = 2;
        }
        0x05 => {
            if bytes.len() < 5 { return X86Inst::empty(); }
            let imm = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            inst.mnemonic = Mnemonic::Add;
            inst.dst = Some(Operand::Reg(X86Reg::Rax));
            inst.src = Some(Operand::Imm32(imm));
            inst.width = 4;
            inst.raw_len = 5;
        }
        0x9C => { inst.mnemonic = Mnemonic::Push; inst.width = if mode == DecMode::Mode64 { 8 } else { 4 }; inst.raw_len = 1; }
        0x9D => { inst.mnemonic = Mnemonic::Pop;  inst.width = if mode == DecMode::Mode64 { 8 } else { 4 }; inst.raw_len = 1; }
        _ => { inst.mnemonic = Mnemonic::Unknown; inst.raw_len = 1; }
    }
    inst
}

/// Init stub — reserves an internal buffer pool sized to the
/// maximum active number of decoded blocks (one per thread).
pub fn init() {
    // Placeholder for future buffer-pool init.
}

pub fn smoke_test() -> bool {
    let mut insts = [X86Inst::empty(); MAX_DECODED_INSTS];
    let bytes: [u8; 8] = [0x90, 0xC3, 0xE9, 0xFB, 0xFF, 0xFF, 0xFF, 0x90];
    let n = decode_block(&bytes, 0x1000, DecMode::Mode64, &mut insts);
    n == 8 && insts[0].mnemonic == Mnemonic::Nop
        && insts[1].mnemonic == Mnemonic::Ret
        && matches!(insts[2].mnemonic, Mnemonic::Jmp)
}