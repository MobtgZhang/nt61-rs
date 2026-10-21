//! Shared x86_64 instruction decoder producing IR.
//!
//! Decodes the hot subset of x86_64 instructions that PE startup code
//! and simple drivers use: MOV variants, PUSH/POP, CALL/RET, ALU ops
//! (ADD/SUB/AND/OR/XOR/CMP/TEST), JMP/Jcc, LEA, NOP, and SYSCALL.
//! Everything else yields IROp::Unsupported which the BTL runtime
//! handles by trapping back to the kernel.

use super::ir::{
    AluOp, BranchCond, IROp, IrInst, MemOperand, SimdOp, SimdSrc, SimdWidth, X86Reg, X86Xmm,
};

/// Maximum bytes per guest basic block.
pub const MAX_BLOCK_BYTES: usize = 1024;

/// Maximum decoded instructions per basic block.
pub const MAX_DECODED_INSTS: usize = 128;

/// REX prefix byte value (0x40..=0x4F).
const REX_PREFIX: u8 = 0x40;
/// REX.W bit - operand size 64-bit.
const REX_W: u8 = 0x08;
/// REX.R bit - ModR/M reg field high bit.
const REX_R: u8 = 0x04;
/// REX.X bit - SIB index field high bit.
const REX_X: u8 = 0x02;
/// REX.B bit - ModR/M r/m / SIB base high bit.
const REX_B: u8 = 0x01;

/// Legacy prefix: operand-size override (0x66).
const PREFIX_OPSIZE: u8 = 0x66;
/// Legacy prefix: address-size override (0x67).
const PREFIX_ADDRSIZE: u8 = 0x67;
/// Legacy segment override prefixes: ES, CS, SS, DS, FS, GS.
const PREFIX_SEGMENT_ES: u8 = 0x26;
const PREFIX_SEGMENT_CS: u8 = 0x2E;
const PREFIX_SEGMENT_SS: u8 = 0x36;
const PREFIX_SEGMENT_DS: u8 = 0x3E;
const PREFIX_SEGMENT_FS: u8 = 0x64;
const PREFIX_SEGMENT_GS: u8 = 0x65;

/// One-byte opcode map for ALU operations with ModR/M byte.
const OPCODE_ADD_RM_R: u8 = 0x01;
const OPCODE_ADD_R_RM: u8 = 0x03;
const OPCODE_SUB_RM_R: u8 = 0x29;
const OPCODE_SUB_R_RM: u8 = 0x2B;
const OPCODE_AND_RM_R: u8 = 0x21;
const OPCODE_AND_R_RM: u8 = 0x23;
const OPCODE_OR_RM_R: u8 = 0x09;
const OPCODE_OR_R_RM: u8 = 0x0B;
const OPCODE_XOR_RM_R: u8 = 0x31;
const OPCODE_XOR_R_RM: u8 = 0x33;
const OPCODE_CMP_RM_R: u8 = 0x39;
const OPCODE_CMP_R_RM: u8 = 0x3B;
const OPCODE_TEST_RM_R: u8 = 0x85;

/// ALU group opcode base (opcode byte = base + alu_index).
const OPCODE_ALU_IMM_BASE: u8 = 0x80;
/// ALU group: r/m, imm32 (0x81).
const OPCODE_ALU_IMM32: u8 = 0x81;
/// ALU group: r/m, imm8 sign-extended (0x83).
const OPCODE_ALU_IMM8: u8 = 0x83;

// ---- SIMD constants (Intel SDM Vol. 2A) ----
/// VEX 3-byte prefix opcode.
const VEX_PREFIX_3B: u8 = 0xC4;
/// VEX 2-byte prefix opcode.
const VEX_PREFIX_2B: u8 = 0xC5;
/// EVEX prefix opcode byte (0x62) for AVX-512 encoded instructions.
const EVEX_PREFIX: u8 = 0x62;
/// VEX 3-byte prefix: escape opcode byte (0x0F / 0x0F38 / 0x0F3A).
/// SSE: MOVAPS (aligned packed f32 move).
const SSE_MOVAPS: u8 = 0x28;
/// SSE: MOVAPS store.
const SSE_MOVAPS_STORE: u8 = 0x29;
/// SSE: MOVUPS (unaligned packed move, same as movaps with F3 prefix).
const SSE_MOVUPS: u8 = 0x10;
/// SSE: MOVUPS store.
const SSE_MOVUPS_STORE: u8 = 0x11;
/// SSE: MOVDQA (aligned packed integer move) with 66 prefix.
const SSE_MOVDQA: u8 = 0x6F;
/// SSE: MOVDQA store with 66 prefix.
const SSE_MOVDQA_STORE: u8 = 0x7F;
/// SSE: ADDPS / ADDSS / ADDPD / ADDSD.
const SSE_ADD: u8 = 0x58;
/// SSE: SUBPS / SUBSS / SUBPD / SUBSD.
const SSE_SUB: u8 = 0x5C;
/// SSE: MULPS / MULSS / MULPD / MULSD.
const SSE_MUL: u8 = 0x59;
/// SSE: DIVPS / DIVSS / DIVPD / DIVSD.
const SSE_DIV: u8 = 0x5E;
/// SSE: ANDPS.
const SSE_ANDPS: u8 = 0x54;
/// SSE: ORPS.
const SSE_ORPS: u8 = 0x56;
/// SSE: XORPS.
const SSE_XORPS: u8 = 0x57;
/// SSE: PAND (66 prefix).
const SSE_PAND: u8 = 0xDB;
/// SSE: POR (66 prefix).
const SSE_POR: u8 = 0xEB;
/// SSE: PXOR (66 prefix).
const SSE_PXOR: u8 = 0xEF;
/// ALU group: ADD r/m, imm8/32 (sign-extended).
const OPCODE_ALU_ADD_IMM: u8 = 0x00;
/// ALU group: SUB r/m, imm8/32 (sign-extended).
const OPCODE_ALU_SUB_IMM: u8 = 0x05;
/// ALU group: AND r/m, imm8/32 (sign-extended).
const OPCODE_ALU_AND_IMM: u8 = 0x04;
/// ALU group: OR r/m, imm8/32 (sign-extended).
const OPCODE_ALU_OR_IMM: u8 = 0x01;
/// ALU group: XOR r/m, imm8/32 (sign-extended).
const OPCODE_ALU_XOR_IMM: u8 = 0x06;
/// ALU group: CMP r/m, imm8/32 (sign-extended).
const OPCODE_ALU_CMP_IMM: u8 = 0x07;

/// Short-form ALU imm8 opcodes: ADD(0x04), SUB(0x2C), AND(0x24),
/// OR(0x0C), XOR(0x34), CMP(0x3C) - all on RAX.
const OPCODE_ADD_AL_IMM8: u8 = 0x04;
const OPCODE_ADD_AL_IMM32: u8 = 0x05;
const OPCODE_SUB_AL_IMM8: u8 = 0x2C;
const OPCODE_SUB_AL_IMM32: u8 = 0x2D;
const OPCODE_AND_AL_IMM8: u8 = 0x24;
const OPCODE_AND_AL_IMM32: u8 = 0x25;
const OPCODE_OR_AL_IMM8: u8 = 0x0C;
const OPCODE_OR_AL_IMM32: u8 = 0x0D;
const OPCODE_XOR_AL_IMM8: u8 = 0x34;
const OPCODE_XOR_AL_IMM32: u8 = 0x35;
const OPCODE_CMP_AL_IMM8: u8 = 0x3C;
const OPCODE_CMP_AL_IMM32: u8 = 0x3D;

/// MOV r64, imm64 (REX.W B8+rr opcode).
const OPCODE_MOV_R_IMM64: u8 = 0xB8;
/// MOV r64, r/m64 (REX.W 89 /r).
const OPCODE_MOV_RM_R: u8 = 0x89;
/// MOV r/m64, r64 (REX.W 8B /r).
const OPCODE_MOV_R_RM: u8 = 0x8B;
/// MOV moffs64, rax (REX.W A3).
const OPCODE_MOV_MOFFS_RAX: u8 = 0xA3;
/// MOV rax, moffs64 (REX.W A1).
const OPCODE_MOV_RAX_MOFFS: u8 = 0xA1;
/// MOV r8, imm8 (B0+rr).
const OPCODE_MOV_R8_IMM8: u8 = 0xB0;
/// LEA r64, m (REX.W 8D /r).
const OPCODE_LEA: u8 = 0x8D;
/// PUSH r64 (REX.W 50+rr / 50..57).
const OPCODE_PUSH_R: u8 = 0x50;
/// POP r64 (REX.W 58+rr / 58..5F).
const OPCODE_POP_R: u8 = 0x58;
/// CALL rel32 (E8).
const OPCODE_CALL_REL32: u8 = 0xE8;
/// JMP rel32 (E9).
const OPCODE_JMP_REL32: u8 = 0xE9;
/// JMP rel8 (EB).
const OPCODE_JMP_REL8: u8 = 0xEB;
/// RET near (C3).
const OPCODE_RET_NEAR: u8 = 0xC3;
/// NOP (0x90).
const OPCODE_NOP: u8 = 0x90;
/// SYSCALL (0F 05).
const OPCODE_SYSCALL_HI: u8 = 0x0F;
const OPCODE_SYSCALL_LO: u8 = 0x05;
const OPCODE_JCC_REL32_BASE: u8 = 0x80;
/// Jcc rel8 (7x).
const OPCODE_JCC_REL8_BASE: u8 = 0x70;

/// Decoder state - consumes bytes from the guest code stream.
struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    base_va: u64,
    has_rex: bool,
    rex_w: bool,
    rex_r: bool,
    rex_x: bool,
    rex_b: bool,
    op_size_64: bool,
    addr_size_64: bool,
    has_66: bool,
    has_f3: bool,
    has_f2: bool,
    /// EVEX R' extension: extends register index from XMM0-15 to XMM16-31.
    evex_reg_ext: bool,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], base_va: u64) -> Self {
        Self {
            bytes,
            offset: 0,
            base_va,
            has_rex: false,
            rex_w: false,
            rex_r: false,
            rex_x: false,
            rex_b: false,
            op_size_64: true,
            addr_size_64: true,
            has_66: false,
            has_f3: false,
            has_f2: false,
            evex_reg_ext: false,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn fetch(&mut self) -> Option<u8> {
        let b = self.bytes.get(self.offset).copied()?;
        self.offset += 1;
        Some(b)
    }

    fn fetch_le32(&mut self) -> Option<i32> {
        let b = [self.fetch()?, self.fetch()?, self.fetch()?, self.fetch()?];
        Some(i32::from_le_bytes(b))
    }

    fn fetch_le64(&mut self) -> Option<i64> {
        let mut b = [0u8; 8];
        for byte in b.iter_mut() {
            *byte = self.fetch()?;
        }
        Some(i64::from_le_bytes(b))
    }

    fn current_va(&self) -> u64 {
        self.base_va + self.offset as u64
    }

    fn current_va_at_start(&self, start: usize) -> u64 {
        self.base_va + start as u64
    }

    /// Consume legacy prefixes and REX prefix.
    fn consume_prefixes(&mut self) {
        self.has_rex = false;
        self.rex_w = false;
        self.rex_r = false;
        self.rex_x = false;
        self.rex_b = false;
        self.op_size_64 = true;
        self.addr_size_64 = true;
        self.has_66 = false;
        self.has_f3 = false;
        self.has_f2 = false;
        loop {
            match self.peek() {
                Some(PREFIX_OPSIZE) => {
                    self.op_size_64 = false;
                    self.has_66 = true;
                    self.offset += 1;
                }
                Some(0xF3) => {
                    self.has_f3 = true;
                    self.offset += 1;
                }
                Some(0xF2) => {
                    self.has_f2 = true;
                    self.offset += 1;
                }
                Some(PREFIX_ADDRSIZE) => {
                    self.addr_size_64 = false;
                    self.offset += 1;
                }
                Some(PREFIX_SEGMENT_ES)
                | Some(PREFIX_SEGMENT_CS)
                | Some(PREFIX_SEGMENT_SS)
                | Some(PREFIX_SEGMENT_DS)
                | Some(PREFIX_SEGMENT_FS)
                | Some(PREFIX_SEGMENT_GS) => {
                    self.offset += 1;
                }
                Some(b) if (REX_PREFIX..=0x4F).contains(&b) => {
                    self.has_rex = true;
                    self.rex_w = b & REX_W != 0;
                    self.rex_r = b & REX_R != 0;
                    self.rex_x = b & REX_X != 0;
                    self.rex_b = b & REX_B != 0;
                    self.op_size_64 = self.rex_w;
                    self.offset += 1;
                }
                _ => break,
            }
        }
    }

    /// Decode the ModR/M byte, returning (reg_field, rm_info, consumed).
    fn decode_modrm(&mut self) -> Option<(X86Reg, Result<X86Reg, MemOperand>, u8)> {
        let modrm = self.fetch()?;
        let mode = (modrm >> 6) & 0x03;
        let reg_field = (modrm >> 3) & 0x07;
        let rm_field = modrm & 0x07;
        let reg = X86Reg::from_modrm(reg_field, self.rex_r);
        let width = if self.op_size_64 { 8u8 } else { 4u8 };

        match mode {
            0x03 => {
                let rm = X86Reg::from_modrm(rm_field, self.rex_b);
                Some((reg, Ok(rm), 1))
            }
            _ => {
                let (base_reg, index_reg, scale, extra_disp) = if rm_field == 0x04 {
                    let sib = self.fetch()?;
                    let sib_scale_code = (sib >> 6) & 0x03;
                    let sib_index = (sib >> 3) & 0x07;
                    let sib_base = sib & 0x07;
                    let scale = 1u8 << sib_scale_code;
                    let idx = if sib_index == 0x04 {
                        None
                    } else {
                        Some(X86Reg::from_modrm(sib_index, self.rex_x))
                    };
                    if sib_base == 0x05 && mode == 0x00 {
                        (None, idx, scale, true)
                    } else {
                        (
                            Some(X86Reg::from_modrm(sib_base, self.rex_b)),
                            idx,
                            scale,
                            false,
                        )
                    }
                } else if rm_field == 0x05 && mode == 0x00 {
                    (Some(X86Reg::Rip), None, 1, false)
                } else {
                    (
                        Some(X86Reg::from_modrm(rm_field, self.rex_b)),
                        None,
                        1,
                        false,
                    )
                };

                let disp = match mode {
                    0x00 => {
                        if extra_disp {
                            self.fetch_le32()?
                        } else {
                            0
                        }
                    }
                    0x01 => i32::from(self.fetch()? as i8),
                    0x02 => self.fetch_le32()?,
                    _ => 0,
                };

                Some((
                    reg,
                    Err(MemOperand {
                        base: base_reg,
                        index: index_reg,
                        scale,
                        disp,
                        width,
                    }),
                    1,
                ))
            }
        }
    }

    fn decode_alu_rm_r(&mut self, alu: AluOp) -> Option<IROp> {
        let (dst, src, _) = self.decode_modrm()?;
        match src {
            Ok(src_reg) => Some(IROp::AluReg {
                op: alu,
                dst,
                src: src_reg,
            }),
            Err(mem) => Some(IROp::AluMem { op: alu, dst, mem }),
        }
    }

    fn decode_alu_r_rm(&mut self, alu: AluOp) -> Option<IROp> {
        let (src, dst, _) = self.decode_modrm()?;
        match dst {
            Ok(dst_reg) => Some(IROp::AluReg {
                op: alu,
                dst: dst_reg,
                src,
            }),
            Err(mem) => Some(IROp::AluMem {
                op: alu,
                dst: src,
                mem,
            }),
        }
    }

    /// Decode one instruction and return the IR op.
    fn decode_one(&mut self) -> Option<IROp> {
        let start = self.offset;
        self.consume_prefixes();
        let op = self.fetch()?;

        if op == OPCODE_SYSCALL_HI {
            let op2 = self.fetch()?;
            return match op2 {
                OPCODE_SYSCALL_LO => Some(IROp::Syscall),
                // SSE data movement.
                SSE_MOVAPS => self.decode_simd_mov(SimdWidth::PackedF32),
                SSE_MOVAPS_STORE => self.decode_simd_store(SimdWidth::PackedF32),
                SSE_MOVUPS => self.decode_simd_mov(SimdWidth::PackedF32),
                SSE_MOVUPS_STORE => self.decode_simd_store(SimdWidth::PackedF32),
                SSE_MOVDQA => self.decode_simd_mov(SimdWidth::PackedI128),
                SSE_MOVDQA_STORE => self.decode_simd_store(SimdWidth::PackedI128),
                // SSE arithmetic.
                SSE_ADD => self.decode_simd_arith(SimdOp::Add),
                SSE_SUB => self.decode_simd_arith(SimdOp::Sub),
                SSE_MUL => self.decode_simd_arith(SimdOp::Mul),
                SSE_DIV => self.decode_simd_arith(SimdOp::Div),
                SSE_ANDPS => self.decode_simd_arith(SimdOp::And),
                SSE_ORPS => self.decode_simd_arith(SimdOp::Or),
                SSE_XORPS => self.decode_simd_arith(SimdOp::Xor),
                SSE_PAND => self.decode_simd_arith(SimdOp::And),
                SSE_POR => self.decode_simd_arith(SimdOp::Or),
                SSE_PXOR => self.decode_simd_arith(SimdOp::Xor),
                // VEX (AVX / AVX-512) encoding.
                VEX_PREFIX_2B => self.decode_vex_2b(),
                VEX_PREFIX_3B => self.decode_vex_3b(),
                EVEX_PREFIX => self.decode_evex(),
                OPCODE_JCC_REL32_BASE..=0x8F => {
                    let cc = op2 - OPCODE_JCC_REL32_BASE;
                    let rel = self.fetch_le32()?;
                    let len = (self.offset - start) as u64;
                    let target = self
                        .current_va_at_start(start + len as usize)
                        .wrapping_add(rel as i64 as u64);
                    Some(IROp::Jcc {
                        cond: BranchCond::from_x86_cc(cc),
                        target,
                    })
                }
                _ => Some(IROp::Unsupported),
            };
        }

        let result = match op {
            OPCODE_NOP => Some(IROp::Nop),
            OPCODE_RET_NEAR => Some(IROp::Ret),

            OPCODE_MOV_R_IMM64 if self.op_size_64 => {
                let reg = X86Reg::from_modrm(op & 0x07, self.rex_b);
                let imm = self.fetch_le64()?;
                Some(IROp::MovImm { dst: reg, imm })
            }

            OPCODE_MOV_R_IMM64 => {
                let reg = X86Reg::from_modrm(op & 0x07, self.rex_b);
                let imm = self.fetch_le32()?;
                Some(IROp::MovImm {
                    dst: reg,
                    imm: imm as i64,
                })
            }

            OPCODE_MOV_R8_IMM8 => {
                let reg = X86Reg::from_modrm(op & 0x07, self.rex_b);
                let imm = self.fetch()? as i8 as i64;
                Some(IROp::MovImm { dst: reg, imm })
            }

            OPCODE_MOV_RM_R => {
                let (src, dst, _) = self.decode_modrm()?;
                match dst {
                    Ok(dst_reg) => Some(IROp::MovReg { dst: dst_reg, src }),
                    Err(mem) => Some(IROp::Store { mem, src }),
                }
            }

            OPCODE_MOV_R_RM => {
                let (dst, src, _) = self.decode_modrm()?;
                match src {
                    Ok(src_reg) => Some(IROp::MovReg { dst, src: src_reg }),
                    Err(mem) => Some(IROp::Load { dst, mem }),
                }
            }

            OPCODE_MOV_MOFFS_RAX => {
                let disp = self.fetch_le32()?;
                Some(IROp::Store {
                    mem: MemOperand {
                        base: None,
                        index: None,
                        scale: 1,
                        disp,
                        width: 8,
                    },
                    src: X86Reg::Rax,
                })
            }

            OPCODE_MOV_RAX_MOFFS => {
                let disp = self.fetch_le32()?;
                Some(IROp::Load {
                    dst: X86Reg::Rax,
                    mem: MemOperand {
                        base: None,
                        index: None,
                        scale: 1,
                        disp,
                        width: 8,
                    },
                })
            }

            OPCODE_LEA => {
                let (dst, src, _) = self.decode_modrm()?;
                match src {
                    Err(mem) => Some(IROp::Lea { dst, mem }),
                    Ok(_) => Some(IROp::Unsupported),
                }
            }

            OPCODE_PUSH_R => {
                let reg = X86Reg::from_modrm(op & 0x07, self.rex_b);
                Some(IROp::Push { src: reg })
            }

            OPCODE_POP_R => {
                let reg = X86Reg::from_modrm(op & 0x07, self.rex_b);
                Some(IROp::Pop { dst: reg })
            }

            OPCODE_CALL_REL32 => {
                let rel = self.fetch_le32()?;
                let len = (self.offset - start) as u64;
                let target = self
                    .current_va_at_start(start + len as usize)
                    .wrapping_add(rel as i64 as u64);
                Some(IROp::Call { target })
            }

            OPCODE_JMP_REL32 => {
                let rel = self.fetch_le32()?;
                let len = (self.offset - start) as u64;
                let target = self
                    .current_va_at_start(start + len as usize)
                    .wrapping_add(rel as i64 as u64);
                Some(IROp::Jmp { target })
            }

            OPCODE_JMP_REL8 => {
                let rel = self.fetch()? as i8;
                let len = (self.offset - start) as u64;
                let target = self
                    .current_va_at_start(start + len as usize)
                    .wrapping_add(rel as i64 as u64);
                Some(IROp::Jmp { target })
            }

            OPCODE_JCC_REL8_BASE..=0x7F => {
                let cc = op - OPCODE_JCC_REL8_BASE;
                let rel = self.fetch()? as i8;
                let len = (self.offset - start) as u64;
                let target = self
                    .current_va_at_start(start + len as usize)
                    .wrapping_add(rel as i64 as u64);
                Some(IROp::Jcc {
                    cond: BranchCond::from_x86_cc(cc),
                    target,
                })
            }

            OPCODE_TEST_RM_R => {
                let (dst, src, _) = self.decode_modrm()?;
                match src {
                    Ok(src_reg) => Some(IROp::AluReg {
                        op: AluOp::Test,
                        dst,
                        src: src_reg,
                    }),
                    Err(mem) => Some(IROp::AluMem {
                        op: AluOp::Test,
                        dst,
                        mem,
                    }),
                }
            }

            OPCODE_ADD_RM_R => self.decode_alu_rm_r(AluOp::Add),
            OPCODE_OR_RM_R => self.decode_alu_rm_r(AluOp::Or),
            OPCODE_AND_RM_R => self.decode_alu_rm_r(AluOp::And),
            OPCODE_SUB_RM_R => self.decode_alu_rm_r(AluOp::Sub),
            OPCODE_XOR_RM_R => self.decode_alu_rm_r(AluOp::Xor),
            OPCODE_CMP_RM_R => self.decode_alu_rm_r(AluOp::Cmp),

            OPCODE_ADD_R_RM => self.decode_alu_r_rm(AluOp::Add),
            OPCODE_OR_R_RM => self.decode_alu_r_rm(AluOp::Or),
            OPCODE_AND_R_RM => self.decode_alu_r_rm(AluOp::And),
            OPCODE_SUB_R_RM => self.decode_alu_r_rm(AluOp::Sub),
            OPCODE_XOR_R_RM => self.decode_alu_r_rm(AluOp::Xor),
            OPCODE_CMP_R_RM => self.decode_alu_r_rm(AluOp::Cmp),

            OPCODE_ALU_IMM_BASE | OPCODE_ALU_IMM32 | OPCODE_ALU_IMM8 => {
                // Peek the raw ModR/M byte so we can extract the ALU sub-op
                // from the reg field before decode_modrm consumes it.
                let modrm_byte = self.bytes.get(self.offset).copied().unwrap_or(0);
                let (dst, _, _) = self.decode_modrm()?;
                // The ALU sub-operation is encoded in the ModR/M reg field.
                let alu_idx = (modrm_byte >> 3) & 0x07;
                let alu_op = match alu_idx {
                    OPCODE_ALU_ADD_IMM => AluOp::Add,
                    OPCODE_ALU_OR_IMM => AluOp::Or,
                    OPCODE_ALU_AND_IMM => AluOp::And,
                    OPCODE_ALU_SUB_IMM => AluOp::Sub,
                    OPCODE_ALU_XOR_IMM => AluOp::Xor,
                    OPCODE_ALU_CMP_IMM => AluOp::Cmp,
                    _ => return Some(IROp::Unsupported),
                };
                // 0x80/0x83 use a sign-extended imm8; 0x81 uses a full imm32.
                let imm = if op == OPCODE_ALU_IMM32 {
                    self.fetch_le32()? as i64
                } else {
                    self.fetch()? as i8 as i64
                };
                Some(IROp::AluImm {
                    op: alu_op,
                    dst,
                    imm,
                })
            }

            OPCODE_ADD_AL_IMM8 => Some(IROp::AluImm {
                op: AluOp::Add,
                dst: X86Reg::Rax,
                imm: self.fetch()? as i8 as i64,
            }),
            OPCODE_ADD_AL_IMM32 => Some(IROp::AluImm {
                op: AluOp::Add,
                dst: X86Reg::Rax,
                imm: self.fetch_le32()? as i64,
            }),
            OPCODE_SUB_AL_IMM8 => Some(IROp::AluImm {
                op: AluOp::Sub,
                dst: X86Reg::Rax,
                imm: self.fetch()? as i8 as i64,
            }),
            OPCODE_SUB_AL_IMM32 => Some(IROp::AluImm {
                op: AluOp::Sub,
                dst: X86Reg::Rax,
                imm: self.fetch_le32()? as i64,
            }),
            OPCODE_AND_AL_IMM8 => Some(IROp::AluImm {
                op: AluOp::And,
                dst: X86Reg::Rax,
                imm: self.fetch()? as i8 as i64,
            }),
            OPCODE_AND_AL_IMM32 => Some(IROp::AluImm {
                op: AluOp::And,
                dst: X86Reg::Rax,
                imm: self.fetch_le32()? as i64,
            }),
            OPCODE_OR_AL_IMM8 => Some(IROp::AluImm {
                op: AluOp::Or,
                dst: X86Reg::Rax,
                imm: self.fetch()? as i8 as i64,
            }),
            OPCODE_OR_AL_IMM32 => Some(IROp::AluImm {
                op: AluOp::Or,
                dst: X86Reg::Rax,
                imm: self.fetch_le32()? as i64,
            }),
            OPCODE_XOR_AL_IMM8 => Some(IROp::AluImm {
                op: AluOp::Xor,
                dst: X86Reg::Rax,
                imm: self.fetch()? as i8 as i64,
            }),
            OPCODE_XOR_AL_IMM32 => Some(IROp::AluImm {
                op: AluOp::Xor,
                dst: X86Reg::Rax,
                imm: self.fetch_le32()? as i64,
            }),
            OPCODE_CMP_AL_IMM8 => Some(IROp::AluImm {
                op: AluOp::Cmp,
                dst: X86Reg::Rax,
                imm: self.fetch()? as i8 as i64,
            }),
            OPCODE_CMP_AL_IMM32 => Some(IROp::AluImm {
                op: AluOp::Cmp,
                dst: X86Reg::Rax,
                imm: self.fetch_le32()? as i64,
            }),

            _ => Some(IROp::Unsupported),
        };

        result
    }

    // ---- SIMD decoding ----

    /// Determine SIMD width from the current prefix state.
    fn simd_width(&self) -> SimdWidth {
        if self.has_f3 {
            SimdWidth::ScalarF32
        } else if self.has_f2 {
            SimdWidth::ScalarF64
        } else if self.has_66 {
            SimdWidth::PackedI128
        } else {
            SimdWidth::PackedF32
        }
    }

    /// Decode a SIMD move (dst_xmm ← src).
    fn decode_simd_mov(&mut self, width: SimdWidth) -> Option<IROp> {
        let modrm = self.fetch()?;
        let reg_idx = (modrm >> 3) & 0x0F;
        let mode = (modrm >> 6) & 0x03;
        let rm_field = modrm & 0x0F;
        let dst = X86Xmm::from_modrm(reg_idx, self.rex_r);
        if mode == 3 {
            let src = X86Xmm::from_modrm(rm_field, self.rex_b);
            Some(IROp::SimdMov {
                dst,
                src: SimdSrc::Xmm(src),
                width,
            })
        } else {
            let mem = self.decode_simd_mem_operand(rm_field, mode)?;
            Some(IROp::SimdMov {
                dst,
                src: SimdSrc::Mem(mem),
                width,
            })
        }
    }

    /// Decode a SIMD store (mem ← src_xmm).
    fn decode_simd_store(&mut self, width: SimdWidth) -> Option<IROp> {
        let modrm = self.fetch()?;
        let reg_idx = (modrm >> 3) & 0x0F;
        let mode = (modrm >> 6) & 0x03;
        let rm_field = modrm & 0x0F;
        let src = X86Xmm::from_modrm(reg_idx, self.rex_r);
        if mode == 3 {
            let dst = X86Xmm::from_modrm(rm_field, self.rex_b);
            Some(IROp::SimdMov {
                dst,
                src: SimdSrc::Xmm(src),
                width,
            })
        } else {
            let mem = self.decode_simd_mem_operand(rm_field, mode)?;
            Some(IROp::SimdStore { mem, src, width })
        }
    }

    /// Decode a SIMD arithmetic op (dst_xmm = dst_xmm <op> src).
    fn decode_simd_arith(&mut self, op: SimdOp) -> Option<IROp> {
        let width = self.simd_width();
        let modrm = self.fetch()?;
        let reg_idx = (modrm >> 3) & 0x0F;
        let mode = (modrm >> 6) & 0x03;
        let rm_field = modrm & 0x0F;
        let dst = X86Xmm::from_modrm(reg_idx, self.rex_r);
        if mode == 3 {
            let src = X86Xmm::from_modrm(rm_field, self.rex_b);
            Some(IROp::SimdArith {
                op,
                dst,
                src: SimdSrc::Xmm(src),
                width,
            })
        } else {
            let mem = self.decode_simd_mem_operand(rm_field, mode)?;
            Some(IROp::SimdArith {
                op,
                dst,
                src: SimdSrc::Mem(mem),
                width,
            })
        }
    }

    /// Decode a memory operand for SIMD (32-bit displacement always,
    /// no SIB simplification — the BTL runtime handles the general case).
    fn decode_simd_mem_operand(&mut self, rm_field: u8, mode: u8) -> Option<MemOperand> {
        if mode == 0 {
            // [rip + disp32] (rm=101) or [base] for other rm values.
            if rm_field == 5 {
                let disp = self.fetch_le32()?;
                Some(MemOperand {
                    base: None,
                    index: None,
                    scale: 1,
                    disp,
                    width: 16,
                })
            } else {
                let base = X86Reg::from_modrm(rm_field, self.rex_b);
                Some(MemOperand {
                    base: Some(base),
                    index: None,
                    scale: 1,
                    disp: 0,
                    width: 16,
                })
            }
        } else if mode == 1 {
            let base = X86Reg::from_modrm(rm_field, self.rex_b);
            let disp = i32::from(self.fetch()? as i8);
            Some(MemOperand {
                base: Some(base),
                index: None,
                scale: 1,
                disp,
                width: 16,
            })
        } else {
            let base = X86Reg::from_modrm(rm_field, self.rex_b);
            let disp = self.fetch_le32()?;
            Some(MemOperand {
                base: Some(base),
                index: None,
                scale: 1,
                disp,
                width: 16,
            })
        }
    }

    /// Parse a 2-byte VEX prefix (C5) and decode the instruction.
    /// 2-byte VEX: C5 R BvvvvL pp op2.
    fn decode_vex_2b(&mut self) -> Option<IROp> {
        let vex = self.fetch()?;
        let vex_r = (vex >> 7) & 1 != 0;
        let _vex_b = (vex >> 6) & 1 != 0;
        let _vex_l = (vex >> 2) & 1 != 0;
        let _vex_pp = vex & 0x03;
        let opcode = self.fetch()?;
        self.decode_vex_simd(vex_r, opcode)
    }

    /// Parse a 3-byte VEX prefix (C4) and decode the instruction.
    /// 3-byte VEX: C4 RXB mmmmm WvvvvL pp op2.
    fn decode_vex_3b(&mut self) -> Option<IROp> {
        let vex1 = self.fetch()?;
        let vex_r = (vex1 >> 7) & 1 != 0;
        let _vex_x = (vex1 >> 6) & 1 != 0;
        let _vex_b = (vex1 >> 5) & 1 != 0;
        let _escape = vex1 & 0x1F;
        let vex2 = self.fetch()?;
        let _vex_w = (vex2 >> 7) & 1 != 0;
        let _vex_l = (vex2 >> 2) & 1 != 0;
        let _vex_pp = vex2 & 0x03;
        let opcode = self.fetch()?;
        self.decode_vex_simd(vex_r, opcode)
    }

    /// Common VEX SIMD decode: vmovaps/vmovups/vmovapd/vmovupd/vmovdqa/vmovdqu.
    /// VEX.NDS.128/256/512: dst ← src2 (VEX.vvvv) for the move forms.
    fn decode_evex(&mut self) -> Option<IROp> {
        let p0 = self.fetch()?;
        let p1 = self.fetch()?;
        let _p2 = self.fetch()?;
        let opcode = self.fetch()?;

        self.evex_reg_ext = (p1 >> 2) & 1 != 0;
        let vex_r = (p0 >> 6) & 1 != 0;

        self.decode_vex_simd(vex_r, opcode)
    }

    fn decode_vex_simd(&mut self, vex_r: bool, opcode: u8) -> Option<IROp> {
        let width = SimdWidth::PackedF32;
        let decode_xmm_dst = |dec: &Self, reg_idx: u8, inv_r: bool| -> X86Xmm {
            if dec.evex_reg_ext {
                X86Xmm::from_evex(reg_idx, true, !inv_r)
            } else {
                X86Xmm::from_modrm(reg_idx, !inv_r)
            }
        };
        match opcode {
            SSE_MOVAPS | SSE_MOVUPS => {
                let modrm = self.fetch()?;
                let reg_idx = (modrm >> 3) & 0x0F;
                let mode = (modrm >> 6) & 0x03;
                let rm_field = modrm & 0x0F;
                let dst = decode_xmm_dst(self, reg_idx, vex_r);
                if mode == 3 {
                    let src = X86Xmm::from_modrm(rm_field, false);
                    Some(IROp::SimdMov {
                        dst,
                        src: SimdSrc::Xmm(src),
                        width,
                    })
                } else {
                    let mem = self.decode_simd_mem_operand(rm_field, mode)?;
                    Some(IROp::SimdMov {
                        dst,
                        src: SimdSrc::Mem(mem),
                        width,
                    })
                }
            }
            SSE_MOVAPS_STORE | SSE_MOVUPS_STORE => {
                let modrm = self.fetch()?;
                let reg_idx = (modrm >> 3) & 0x0F;
                let mode = (modrm >> 6) & 0x03;
                let rm_field = modrm & 0x0F;
                let src = decode_xmm_dst(self, reg_idx, vex_r);
                if mode == 3 {
                    let dst = X86Xmm::from_modrm(rm_field, false);
                    Some(IROp::SimdMov {
                        dst,
                        src: SimdSrc::Xmm(src),
                        width,
                    })
                } else {
                    let mem = self.decode_simd_mem_operand(rm_field, mode)?;
                    Some(IROp::SimdStore { mem, src, width })
                }
            }
            _ => Some(IROp::Unsupported),
        }
    }
}

/// Decode a basic block from guest code bytes, producing IR.
pub fn decode_block(bytes: &[u8], base_va: u64, out: &mut [IrInst]) -> usize {
    let mut dec = Decoder::new(bytes, base_va);
    let mut written = 0;
    while written < out.len() {
        let va = dec.current_va();
        let start = dec.offset;
        let op = match dec.decode_one() {
            Some(op) => op,
            None => break,
        };
        let len = (dec.offset - start) as u8;
        if len == 0 {
            break;
        }
        out[written] = IrInst {
            op,
            guest_va: va,
            guest_len: len,
        };
        written += 1;
        if matches!(
            op,
            IROp::Ret | IROp::Jmp { .. } | IROp::Syscall | IROp::Unsupported
        ) {
            break;
        }
    }
    written
}

/// Decode a single instruction. Returns (IrInst, bytes_consumed).
pub fn decode_one(bytes: &[u8], base_va: u64) -> Option<(IrInst, usize)> {
    let mut dec = Decoder::new(bytes, base_va);
    let va = dec.current_va();
    let start = dec.offset;
    let op = dec.decode_one()?;
    let len = dec.offset - start;
    if len == 0 {
        return None;
    }
    Some((
        IrInst {
            op,
            guest_va: va,
            guest_len: len as u8,
        },
        len,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_nop() {
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&[0x90], 0x1000, &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].op, IROp::Nop);
        assert_eq!(out[0].guest_len, 1);
    }

    #[test]
    fn decode_ret() {
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&[0xC3], 0x1000, &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].op, IROp::Ret);
    }

    #[test]
    fn decode_mov_r64_imm64() {
        let bytes = [0x48, 0xB8, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::MovImm { dst, imm } => {
                assert_eq!(dst, X86Reg::Rax);
                assert_eq!(imm, 0x1234_5678_9ABC_DEF0u64 as i64);
            }
            _ => panic!("expected MovImm"),
        }
        assert_eq!(out[0].guest_len, 10);
    }

    #[test]
    fn decode_alu_imm() {
        let bytes = [0x48, 0x83, 0xC0, 0x2A];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::AluImm { op, dst, imm } => {
                assert_eq!(op, AluOp::Add);
                assert_eq!(dst, X86Reg::Rax);
                assert_eq!(imm, 42);
            }
            _ => panic!("expected AluImm"),
        }
    }

    #[test]
    fn decode_jmp_rel8() {
        let bytes = [0xEB, 0x05];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::Jmp { target } => {
                assert_eq!(target, 0x1007);
            }
            _ => panic!("expected Jmp"),
        }
    }

    #[test]
    fn decode_call_rel32() {
        let bytes = [0xE8, 0xFC, 0xFF, 0xFF, 0xFF];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::Call { target } => {
                // next_rip = 0x1000 + 5 = 0x1005; rel32 = -4; target = 0x1005 - 4 = 0x1001
                assert_eq!(target, 0x1001);
            }
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn decode_jcc_rel8() {
        let bytes = [0x74, 0x04];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x2000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::Jcc { cond, target } => {
                assert_eq!(cond, BranchCond::Equal);
                assert_eq!(target, 0x2006);
            }
            _ => panic!("expected Jcc"),
        }
    }

    #[test]
    fn decode_push_pop() {
        let bytes = [0x50, 0x58];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0].op, IROp::Push { src: X86Reg::Rax });
        assert_eq!(out[1].op, IROp::Pop { dst: X86Reg::Rax });
    }

    #[test]
    fn decode_test_rm_r() {
        let bytes = [0x48, 0x85, 0xC0];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::AluReg { op, dst, src } => {
                assert_eq!(op, AluOp::Test);
                assert_eq!(dst, X86Reg::Rax);
                assert_eq!(src, X86Reg::Rax);
            }
            _ => panic!("expected AluReg Test"),
        }
    }

    #[test]
    fn decode_lea() {
        let bytes = [0x48, 0x8D, 0x43, 0x08];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::Lea { dst, mem } => {
                assert_eq!(dst, X86Reg::Rax);
                assert_eq!(mem.base, Some(X86Reg::Rbx));
                assert_eq!(mem.disp, 8);
                assert_eq!(mem.width, 8);
            }
            _ => panic!("expected Lea"),
        }
    }

    #[test]
    fn decode_store_reg_to_mem() {
        let bytes = [0x48, 0x89, 0x18];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::Store { mem, src } => {
                assert_eq!(src, X86Reg::Rbx);
                assert_eq!(mem.base, Some(X86Reg::Rax));
                assert_eq!(mem.width, 8);
            }
            _ => panic!("expected Store"),
        }
    }

    #[test]
    fn decode_load_mem_to_reg() {
        let bytes = [0x48, 0x8B, 0x01];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::Load { dst, mem } => {
                assert_eq!(dst, X86Reg::Rax);
                assert_eq!(mem.base, Some(X86Reg::Rcx));
                assert_eq!(mem.width, 8);
            }
            _ => panic!("expected Load"),
        }
    }

    #[test]
    fn decode_mov_reg_reg() {
        let bytes = [0x48, 0x89, 0xD8];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::MovReg { dst, src } => {
                assert_eq!(dst, X86Reg::Rax);
                assert_eq!(src, X86Reg::Rbx);
            }
            _ => panic!("expected MovReg"),
        }
    }
}
