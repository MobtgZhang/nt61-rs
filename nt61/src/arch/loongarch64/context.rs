//! LoongArch64 Context Switching
//
//! Context save/restore for LoongArch64

/// CPU register context for LoongArch64.
#[derive(Default)]
#[repr(C)]
pub struct CpuContext {
    pub r0: u64,  pub r1: u64,  pub r2: u64,  pub r3: u64,
    pub r4: u64,  pub r5: u64,  pub r6: u64,  pub r7: u64,
    pub r8: u64,  pub r9: u64,  pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub r16: u64, pub r17: u64, pub r18: u64, pub r19: u64,
    pub r20: u64, pub r21: u64, pub r22: u64, pub r23: u64,
    pub r24: u64, pub r25: u64,
    pub r26: u64, // tp (thread pointer)
    pub r27: u64, // sp (stack pointer alias, also r3)
    pub r28: u64,
    pub r29: u64, // fp (frame pointer alias, also r8)
    pub r30: u64, // ra (return address alias, also r1)
    pub r31: u64, // pc / zero
    pub orig_a0: u64,
    pub csr_era: u64,  // Exception return address
    pub csr_crma: u64, // CSR saved CRMD
    pub csr_prmd: u64, // CSR saved PRMD
}
