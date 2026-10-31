//! Minimal x86_64 guest-code interpreter over the shared BTL IR.
//!
//! The non-x86 BTL backends translate guest code to host machine
//! code for execution. This interpreter provides the same guest
//! semantics over the shared IR so that register / memory / syscall
//! behaviour can be unit-tested on any host without a JIT target.
//! It is also the fallback path when the JIT emits an unsupported
//! instruction and the trap handler chooses to interpret.

use super::ir::{AluOp, BranchCond, IROp, MemOperand, X86Reg};
use super::memory::GuestMemory;

#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod test_support {
    use super::{execute_block, ExecOutcome, GuestState, SyscallHook, X86Reg};
    use crate::arch::common::btl::ir::IrInst;
    use crate::arch::common::btl::memory::{FlatPaging, GuestAddressSpace};
    use crate::arch::common::btl::x86_decoder::decode_block;

    pub struct NoopSyscall;

    impl SyscallHook for NoopSyscall {
        fn syscall(&mut self, _state: &mut GuestState, _memory: &mut dyn super::GuestMemory) {}
    }

    pub fn decode(code: &[u8], base: u64) -> alloc::vec::Vec<IrInst> {
        let mut out = [IrInst::empty(); 16];
        let count = decode_block(code, base, &mut out);
        out[..count].to_vec()
    }

    pub fn flat_memory(backing: &mut [u8]) -> GuestAddressSpace<FlatPaging> {
        GuestAddressSpace::new(FlatPaging {
            base: backing.as_mut_ptr(),
            len: backing.len(),
        })
    }

    pub fn run_mov_imm_add_imm(memory: &mut dyn super::GuestMemory) -> (ExecOutcome, u64) {
        let code = [
            0x48, 0xB8, 42, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x83, 0xC0, 8, 0xC3,
        ];
        let ir = decode(&code, 0x1000);
        let mut state = GuestState::new();
        state.rip = 0x1000;
        let mut hook = NoopSyscall;
        let outcome = execute_block(&ir, &mut state, memory, &mut hook);
        (outcome, state.reg(X86Reg::Rax))
    }
}

/// Opaque execution state for a translated x86_64 guest thread.
#[derive(Clone, Copy, Debug)]
pub struct GuestState {
    /// Guest GPRs indexed by `X86Reg as usize` (RIP stored separately).
    pub regs: [u64; 16],
    /// Guest RFLAGS (only CF/PF/ZF/SF/OF are modelled).
    pub rflags: u64,
    /// Guest instruction pointer.
    pub rip: u64,
}

impl GuestState {
    pub const fn new() -> Self {
        Self {
            regs: [0; 16],
            rflags: 0,
            rip: 0,
        }
    }

    pub fn reg(&self, r: X86Reg) -> u64 {
        if r == X86Reg::Rip {
            self.rip
        } else {
            self.regs[r as usize]
        }
    }

    pub fn set_reg(&mut self, r: X86Reg, v: u64) {
        if r == X86Reg::Rip {
            self.rip = v;
        } else {
            self.regs[r as usize] = v;
        }
    }

    fn flag(&self, bit: u32) -> bool {
        (self.rflags & (1 << bit)) != 0
    }

    fn set_flag(&mut self, bit: u32, v: bool) {
        self.rflags = (self.rflags & !(1u64 << bit)) | ((v as u64) << bit);
    }
}

impl Default for GuestState {
    fn default() -> Self {
        Self::new()
    }
}

const FLAG_CF: u32 = 0;
const FLAG_PF: u32 = 2;
const FLAG_ZF: u32 = 6;
const FLAG_SF: u32 = 7;
const FLAG_OF: u32 = 11;

const MASK8: u64 = 0xFF;

fn parity8(v: u64) -> bool {
    (v & MASK8).count_ones().is_multiple_of(2)
}

/// Set ZF/SF/PF from the result; CF/OF per operation.
fn update_flags(state: &mut GuestState, op: AluOp, a: u64, b: u64, result: u64) {
    state.set_flag(FLAG_ZF, result == 0);
    state.set_flag(FLAG_SF, (result >> 63) != 0);
    state.set_flag(FLAG_PF, parity8(result));
    match op {
        AluOp::Add => {
            let carry = (a ^ result) & (b ^ result);
            state.set_flag(FLAG_CF, result < a);
            state.set_flag(FLAG_OF, (carry >> 63) != 0);
        }
        AluOp::Sub | AluOp::Cmp => {
            let diff = a ^ b;
            let borrow = a ^ result;
            state.set_flag(FLAG_CF, a < b);
            state.set_flag(FLAG_OF, (diff & borrow & (1u64 << 63)) != 0);
        }
        _ => {
            state.set_flag(FLAG_CF, false);
            state.set_flag(FLAG_OF, false);
        }
    }
}

fn eval_cond(state: &GuestState, cond: BranchCond) -> bool {
    let zf = state.flag(FLAG_ZF);
    let sf = state.flag(FLAG_SF);
    let cf = state.flag(FLAG_CF);
    let of = state.flag(FLAG_OF);
    let pf = state.flag(FLAG_PF);
    match cond {
        BranchCond::Always => true,
        BranchCond::Overflow => of,
        BranchCond::NotOverflow => !of,
        BranchCond::Below => cf,
        BranchCond::AboveOrEqual => !cf,
        BranchCond::Equal => zf,
        BranchCond::NotEqual => !zf,
        BranchCond::BelowOrEqual => cf || zf,
        BranchCond::Above => !cf && !zf,
        BranchCond::Sign => sf,
        BranchCond::NotSign => !sf,
        BranchCond::Parity => pf,
        BranchCond::NotParity => !pf,
        BranchCond::Less => sf != of,
        BranchCond::GreaterOrEqual => sf == of,
        BranchCond::LessOrEqual => zf || (sf != of),
        BranchCond::Greater => !zf && (sf == of),
    }
}

/// Compute the effective address of a memory operand.
fn effective_address(state: &GuestState, mem: &MemOperand) -> u64 {
    let base = mem.base.map(|b| state.reg(b)).unwrap_or(0);
    let index = mem.index.map(|i| state.reg(i)).unwrap_or(0);
    base.wrapping_add(index * mem.scale as u64)
        .wrapping_add(mem.disp as u64)
}

fn mem_read(memory: &mut dyn GuestMemory, addr: u64, width: u8) -> Option<u64> {
    let mut raw = [0u8; 8];
    let n = memory.read_virt(addr, &mut raw[..width as usize]);
    if n < width as usize {
        return None;
    }
    Some(u64::from_le_bytes(raw))
}

fn mem_write(memory: &mut dyn GuestMemory, addr: u64, value: u64, width: u8) -> bool {
    memory.write_virt(addr, &value.to_le_bytes()[..width as usize])
}

fn do_alu(state: &mut GuestState, op: AluOp, a: u64, b: u64) -> u64 {
    let result = match op {
        AluOp::Add => a.wrapping_add(b),
        AluOp::Sub => a.wrapping_sub(b),
        AluOp::Cmp => a.wrapping_sub(b),
        AluOp::And | AluOp::Test => a & b,
        AluOp::Or => a | b,
        AluOp::Xor => a ^ b,
    };
    update_flags(state, op, a, b, result);
    result
}

/// Outcome of interpreting one block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecOutcome {
    /// Block retired; `next_rip` is where guest execution continues.
    Retired { next_rip: u64 },
    /// Hit an unsupported instruction at `guest_va`.
    Unsupported { guest_va: u64 },
    /// Guest memory fault at `guest_va`.
    MemoryFault { guest_va: u64 },
}

/// Hook invoked on `IROp::Syscall`. Implementations bridge to the
/// NT SSDT or a test double and may mutate guest state / memory.
pub trait SyscallHook {
    fn syscall(&mut self, state: &mut GuestState, memory: &mut dyn GuestMemory);
}

/// Interpret a decoded IR block starting at the current `state.rip`.
pub fn execute_block(
    ir: &[super::ir::IrInst],
    state: &mut GuestState,
    memory: &mut dyn GuestMemory,
    hooks: &mut dyn SyscallHook,
) -> ExecOutcome {
    for inst in ir {
        if inst.guest_va + inst.guest_len as u64 <= state.rip {
            continue;
        }
        match inst.op {
            IROp::Nop => {}
            IROp::MovImm { dst, imm } => state.set_reg(dst, imm as u64),
            IROp::MovReg { dst, src } => {
                let v = state.reg(src);
                state.set_reg(dst, v);
            }
            IROp::Load { dst, ref mem } => {
                let addr = effective_address(state, mem);
                match mem_read(memory, addr, mem.width) {
                    Some(v) => state.set_reg(dst, v),
                    None => {
                        return ExecOutcome::MemoryFault {
                            guest_va: inst.guest_va,
                        }
                    }
                }
            }
            IROp::Store { ref mem, src } => {
                let addr = effective_address(state, mem);
                let v = state.reg(src);
                if !mem_write(memory, addr, v, mem.width) {
                    return ExecOutcome::MemoryFault {
                        guest_va: inst.guest_va,
                    };
                }
            }
            IROp::AluReg { op, dst, src } => {
                let a = state.reg(dst);
                let b = state.reg(src);
                let result = do_alu(state, op, a, b);
                if !matches!(op, AluOp::Cmp | AluOp::Test) {
                    state.set_reg(dst, result);
                }
            }
            IROp::AluImm { op, dst, imm } => {
                let a = state.reg(dst);
                let result = do_alu(state, op, a, imm as u64);
                if !matches!(op, AluOp::Cmp | AluOp::Test) {
                    state.set_reg(dst, result);
                }
            }
            IROp::AluMem { op, dst, ref mem } => {
                let addr = effective_address(state, mem);
                match mem_read(memory, addr, mem.width) {
                    Some(b) => {
                        let a = state.reg(dst);
                        let result = do_alu(state, op, a, b);
                        if !matches!(op, AluOp::Cmp | AluOp::Test) {
                            state.set_reg(dst, result);
                        }
                    }
                    None => {
                        return ExecOutcome::MemoryFault {
                            guest_va: inst.guest_va,
                        }
                    }
                }
            }
            IROp::Lea { dst, ref mem } => {
                let addr = effective_address(state, mem);
                state.set_reg(dst, addr);
            }
            IROp::Push { src } => {
                let new_sp = state.reg(X86Reg::Rsp).wrapping_sub(8);
                state.set_reg(X86Reg::Rsp, new_sp);
                if !mem_write(memory, new_sp, state.reg(src), 8) {
                    return ExecOutcome::MemoryFault {
                        guest_va: inst.guest_va,
                    };
                }
            }
            IROp::Pop { dst } => {
                let sp = state.reg(X86Reg::Rsp);
                match mem_read(memory, sp, 8) {
                    Some(v) => {
                        state.set_reg(dst, v);
                        state.set_reg(X86Reg::Rsp, sp.wrapping_add(8));
                    }
                    None => {
                        return ExecOutcome::MemoryFault {
                            guest_va: inst.guest_va,
                        }
                    }
                }
            }
            IROp::Jmp { target } => {
                state.rip = target;
                return ExecOutcome::Retired { next_rip: target };
            }
            IROp::Jcc { cond, target } => {
                if eval_cond(state, cond) {
                    state.rip = target;
                    return ExecOutcome::Retired { next_rip: target };
                }
            }
            IROp::Call { target } => {
                let ret_rip = inst.guest_va + inst.guest_len as u64;
                let new_sp = state.reg(X86Reg::Rsp).wrapping_sub(8);
                state.set_reg(X86Reg::Rsp, new_sp);
                if !mem_write(memory, new_sp, ret_rip, 8) {
                    return ExecOutcome::MemoryFault {
                        guest_va: inst.guest_va,
                    };
                }
                state.rip = target;
                return ExecOutcome::Retired { next_rip: target };
            }
            IROp::Ret => {
                let sp = state.reg(X86Reg::Rsp);
                match mem_read(memory, sp, 8) {
                    Some(v) => {
                        state.set_reg(X86Reg::Rsp, sp.wrapping_add(8));
                        state.rip = v;
                        return ExecOutcome::Retired { next_rip: v };
                    }
                    None => {
                        return ExecOutcome::MemoryFault {
                            guest_va: inst.guest_va,
                        }
                    }
                }
            }
            IROp::Syscall => {
                hooks.syscall(state, memory);
            }
            IROp::Unsupported
            | IROp::SimdMov { .. }
            | IROp::SimdStore { .. }
            | IROp::SimdArith { .. } => {
                return ExecOutcome::Unsupported {
                    guest_va: inst.guest_va,
                };
            }
        }
        // Default advance to the next instruction's guest VA.
        state.rip = inst.guest_va + inst.guest_len as u64;
    }
    ExecOutcome::Retired {
        next_rip: state.rip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::common::btl::abi::HostArch;
    use crate::arch::common::btl::ir::IrInst;
    use crate::arch::common::btl::x86_decoder::decode_block;
    use alloc::vec::Vec;

    struct NopHook;
    impl SyscallHook for NopHook {
        fn syscall(&mut self, _state: &mut GuestState, _memory: &mut dyn GuestMemory) {}
    }

    struct RecordHook {
        pub number: u64,
        pub arg0: u64,
    }

    impl SyscallHook for RecordHook {
        fn syscall(&mut self, state: &mut GuestState, _memory: &mut dyn GuestMemory) {
            self.number = state.reg(X86Reg::Rax);
            self.arg0 = state.reg(X86Reg::R10);
        }
    }

    fn decode(bytes: &[u8], base: u64) -> Vec<IrInst> {
        let mut out = [IrInst::empty(); 16];
        let n = decode_block(bytes, base, &mut out);
        out[..n].to_vec()
    }

    #[test]
    fn mov_imm_and_alu() {
        // mov rax, 42 (B8 imm64) ; add rax, 8 (83 /0 imm8)
        let code: [u8; 14] = [
            0x48, 0xB8, 42, 0, 0, 0, 0, 0, 0, 0, // mov rax, 42
            0x48, 0x83, 0xC0, 8, // add rax, 8
        ];
        let ir = decode(&code, 0x1000);
        let mut state = GuestState::new();
        state.rip = 0x1000;
        let mut backing = [0u8; 0x2000];
        let mut mem = test_support::flat_memory(&mut backing);
        let mut hook = NopHook;
        let out = execute_block(&ir, &mut state, &mut mem, &mut hook);
        assert_eq!(out, ExecOutcome::Retired { next_rip: 0x100E });
        assert_eq!(state.reg(X86Reg::Rax), 50);
    }

    #[test]
    fn guest_sequence_executes_for_each_host_architecture() {
        for arch in [HostArch::Aarch64, HostArch::LoongArch64, HostArch::RiscV64] {
            assert_eq!(arch.argument_register_count(), 8);
            assert!(!arch.argument_register_names()[0].is_empty());

            let mut backing = [0u8; 0x2000];
            let mut mem = test_support::flat_memory(&mut backing);
            let (outcome, rax) = test_support::run_mov_imm_add_imm(&mut mem);
            assert!(matches!(outcome, ExecOutcome::Retired { .. }));
            assert_eq!(rax, 50, "sequence failed for {arch:?}");
        }
    }

    #[test]
    fn load_store_roundtrip() {
        // mov rax, 0x100 (B8 imm64) ; mov rbx, [rax] (8B /r) ; ret
        let code: [u8; 14] = [
            0x48, 0xB8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x100
            0x48, 0x8B, 0x18, // mov rbx, [rax]
            0xC3, // ret
        ];
        let ir = decode(&code, 0x1000);
        let mut state = GuestState::new();
        state.rip = 0x1000;
        let mut backing = [0u8; 0x2000];
        let mut mem = test_support::flat_memory(&mut backing);
        // Pre-fill guest memory at VA 0x100 with a known pattern.
        mem.write_virt(0x100, &[0x42, 0, 0, 0, 0, 0, 0, 0]);
        let mut hook = NopHook;
        let _ = execute_block(&ir, &mut state, &mut mem, &mut hook);
        assert_eq!(state.reg(X86Reg::Rax), 0x100);
        assert_eq!(state.reg(X86Reg::Rbx), 0x42);
    }

    #[test]
    fn syscall_hook_receives_abi_registers() {
        // mov rax, 0x18 (B8 imm64) ; mov r10, 0x1234 (41 B8+rr imm64) ; syscall
        let code: [u8; 22] = [
            0x48, 0xB8, 0x18, 0, 0, 0, 0, 0, 0, 0, // mov rax, 0x18
            0x49, 0xBA, 0x34, 0x12, 0, 0, 0, 0, 0, 0, // mov r10, 0x1234
            0x0F, 0x05, // syscall
        ];
        let ir = decode(&code, 0x1000);
        let mut state = GuestState::new();
        state.rip = 0x1000;
        let mut backing = [0u8; 0x2000];
        let mut mem = test_support::flat_memory(&mut backing);
        let mut hook = RecordHook { number: 0, arg0: 0 };
        let _ = execute_block(&ir, &mut state, &mut mem, &mut hook);
        assert_eq!(hook.number, 24);
        assert_eq!(hook.arg0, 0x1234);
    }

    #[test]
    fn jcc_takes_branch_on_zf() {
        // xor rcx, rcx (sets ZF) ; jz +2 (skip next) ; mov rdx, 1 ; ret
        let code: [u8; 9] = [
            0x48, 0x31, 0xC9, // xor rcx, rcx
            0x74, 0x02, // jz +2
            0x48, 0xC7, 0xC2, 1, // mov rdx, 1  (skipped)
        ];
        let ir = decode(&code, 0x2000);
        let mut state = GuestState::new();
        state.rip = 0x2000;
        let mut backing = [0u8; 0x2000];
        let mut mem = test_support::flat_memory(&mut backing);
        let mut hook = NopHook;
        let out = execute_block(&ir, &mut state, &mut mem, &mut hook);
        assert_eq!(out, ExecOutcome::Retired { next_rip: 0x2007 });
        assert!(state.flag(FLAG_ZF));
    }

    #[test]
    fn memory_fault_returns_error() {
        // Build IR directly: store rbx to [rax] where rax points past
        // the flat memory backing store.
        let mut state = GuestState::new();
        state.set_reg(X86Reg::Rax, 0xFFFF_0000);
        state.rip = 0x1000;
        let mut backing = [0u8; 0x2000];
        let mut mem = test_support::flat_memory(&mut backing);
        let mut hook = NopHook;
        let ir = [IrInst {
            op: IROp::Store {
                mem: MemOperand {
                    base: Some(X86Reg::Rax),
                    index: None,
                    scale: 1,
                    disp: 0,
                    width: 8,
                },
                src: X86Reg::Rbx,
            },
            guest_va: 0x1000,
            guest_len: 3,
        }];
        let out = execute_block(&ir, &mut state, &mut mem, &mut hook);
        assert!(matches!(out, ExecOutcome::MemoryFault { .. }));
    }
}
