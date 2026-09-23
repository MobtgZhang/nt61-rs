//! Pseudo-random number generation with multiple algorithm support.
//!
//! Provides cryptographically secure PRNGs including the existing CSPRNG,
//! plus additional algorithms for compatibility and testing.

extern crate alloc;
use alloc::vec::Vec;

pub use crate::crypto::csprng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrngAlgorithm {
    SystemCsprng,
    ChaCha20,
    AesCtr,
    Lcg,
}

pub struct Prng {
    algorithm: PrngAlgorithm,
    state: PrngState,
}

enum PrngState {
    SystemCsprng,
    ChaCha20(ChaCha20State),
    AesCtr(AesCtrState),
    Lcg(LcgState),
}

impl Prng {
    pub fn new(algorithm: PrngAlgorithm) -> Self {
        let state = match algorithm {
            PrngAlgorithm::SystemCsprng => PrngState::SystemCsprng,
            PrngAlgorithm::ChaCha20 => {
                let mut seed = [0u8; 32];
                csprng::fill(&mut seed);
                PrngState::ChaCha20(ChaCha20State::new(&seed))
            }
            PrngAlgorithm::AesCtr => {
                let mut key = [0u8; 16];
                csprng::fill(&mut key);
                PrngState::AesCtr(AesCtrState::new(&key))
            }
            PrngAlgorithm::Lcg => PrngState::Lcg(LcgState::new(0x123456789abcdef0)),
        };

        Self { algorithm, state }
    }

    pub fn with_seed(algorithm: PrngAlgorithm, seed: &[u8]) -> Self {
        let state = match algorithm {
            PrngAlgorithm::SystemCsprng => {
                csprng::inject_entropy(seed);
                PrngState::SystemCsprng
            }
            PrngAlgorithm::ChaCha20 => {
                let mut key = [0u8; 32];
                let len = seed.len().min(32);
                key[..len].copy_from_slice(&seed[..len]);
                PrngState::ChaCha20(ChaCha20State::new(&key))
            }
            PrngAlgorithm::AesCtr => {
                let mut key = [0u8; 16];
                let len = seed.len().min(16);
                key[..len].copy_from_slice(&seed[..len]);
                PrngState::AesCtr(AesCtrState::new(&key))
            }
            PrngAlgorithm::Lcg => {
                let seed_val = if seed.len() >= 8 {
                    u64::from_le_bytes([
                        seed[0], seed[1], seed[2], seed[3],
                        seed[4], seed[5], seed[6], seed[7],
                    ])
                } else {
                    0x123456789abcdef0
                };
                PrngState::Lcg(LcgState::new(seed_val))
            }
        };

        Self { algorithm, state }
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        match &mut self.state {
            PrngState::SystemCsprng => {
                csprng::fill(buf);
            }
            PrngState::ChaCha20(state) => {
                state.fill(buf);
            }
            PrngState::AesCtr(state) => {
                state.fill(buf);
            }
            PrngState::Lcg(state) => {
                state.fill(buf);
            }
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        u32::from_le_bytes(buf)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill(&mut buf);
        u64::from_le_bytes(buf)
    }

    pub fn reseed(&mut self, entropy: &[u8]) {
        match &mut self.state {
            PrngState::SystemCsprng => {
                csprng::inject_entropy(entropy);
            }
            PrngState::ChaCha20(state) => {
                let mut key = [0u8; 32];
                let len = entropy.len().min(32);
                key[..len].copy_from_slice(&entropy[..len]);
                *state = ChaCha20State::new(&key);
            }
            PrngState::AesCtr(state) => {
                let mut key = [0u8; 16];
                let len = entropy.len().min(16);
                key[..len].copy_from_slice(&entropy[..len]);
                *state = AesCtrState::new(&key);
            }
            PrngState::Lcg(state) => {
                if entropy.len() >= 8 {
                    let seed = u64::from_le_bytes([
                        entropy[0], entropy[1], entropy[2], entropy[3],
                        entropy[4], entropy[5], entropy[6], entropy[7],
                    ]);
                    state.seed = seed;
                }
            }
        }
    }
}

struct ChaCha20State {
    state: [u32; 16],
    buffer: [u8; 64],
    buffer_pos: usize,
}

impl ChaCha20State {
    fn new(key: &[u8; 32]) -> Self {
        let mut state = [0u32; 16];

        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }

        state[12] = 0;
        state[13] = 0;
        state[14] = 0;
        state[15] = 0;

        Self {
            state,
            buffer: [0u8; 64],
            buffer_pos: 64,
        }
    }

    fn fill(&mut self, buf: &mut [u8]) {
        let mut offset = 0;

        while offset < buf.len() {
            if self.buffer_pos >= 64 {
                self.generate_block();
                self.buffer_pos = 0;
            }

            let available = 64 - self.buffer_pos;
            let needed = buf.len() - offset;
            let to_copy = available.min(needed);

            buf[offset..offset + to_copy]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);

            offset += to_copy;
            self.buffer_pos += to_copy;
        }
    }

    fn generate_block(&mut self) {
        let mut working = self.state;

        for _ in 0..10 {
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        for i in 0..16 {
            working[i] = working[i].wrapping_add(self.state[i]);
        }

        for i in 0..16 {
            let bytes = working[i].to_le_bytes();
            self.buffer[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
    }

    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }
}

struct AesCtrState {
    cipher: crate::crypto::cipher::Aes128,
    counter: [u8; 16],
    buffer: [u8; 16],
    buffer_pos: usize,
}

impl AesCtrState {
    fn new(key: &[u8; 16]) -> Self {
        Self {
            cipher: crate::crypto::cipher::Aes128::new(key),
            counter: [0u8; 16],
            buffer: [0u8; 16],
            buffer_pos: 16,
        }
    }

    fn fill(&mut self, buf: &mut [u8]) {
        let mut offset = 0;

        while offset < buf.len() {
            if self.buffer_pos >= 16 {
                self.generate_block();
                self.buffer_pos = 0;
            }

            let available = 16 - self.buffer_pos;
            let needed = buf.len() - offset;
            let to_copy = available.min(needed);

            buf[offset..offset + to_copy]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);

            offset += to_copy;
            self.buffer_pos += to_copy;
        }
    }

    fn generate_block(&mut self) {
        self.buffer = self.counter;
        self.cipher.encrypt_block(&mut self.buffer);

        for i in (0..16).rev() {
            self.counter[i] = self.counter[i].wrapping_add(1);
            if self.counter[i] != 0 {
                break;
            }
        }
    }
}

struct LcgState {
    seed: u64,
}

impl LcgState {
    fn new(seed: u64) -> Self {
        Self { seed }
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next() as u8;
        }
    }

    fn next(&mut self) -> u64 {
        const A: u64 = 1664525;
        const C: u64 = 1013904223;
        self.seed = self.seed.wrapping_mul(A).wrapping_add(C);
        self.seed
    }
}

pub struct EntropyPool {
    pool: [u8; 256],
    position: usize,
}

impl EntropyPool {
    pub fn new() -> Self {
        Self {
            pool: [0u8; 256],
            position: 0,
        }
    }

    pub fn add_entropy(&mut self, data: &[u8]) {
        for &byte in data {
            self.pool[self.position] ^= byte;
            self.position = (self.position + 1) % 256;
        }
    }

    pub fn extract(&mut self, output: &mut [u8]) {
        let hash = crate::crypto::hash::sha256(&self.pool);

        let mut offset = 0;
        while offset < output.len() {
            let remaining = output.len() - offset;
            let to_copy = remaining.min(32);
            output[offset..offset + to_copy].copy_from_slice(&hash[..to_copy]);
            offset += to_copy;
        }

        for i in 0..256 {
            self.pool[i] ^= hash[i % 32];
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub mod hwrng {
    pub fn has_rdrand() -> bool {
        let cpuid = core::arch::x86_64::__cpuid(1);
        (cpuid.ecx & (1 << 30)) != 0
    }

    pub fn has_rdseed() -> bool {
        let cpuid = core::arch::x86_64::__cpuid(7);
        (cpuid.ebx & (1 << 18)) != 0
    }

    pub fn rdrand_fill(buf: &mut [u8]) -> bool {
        if !has_rdrand() {
            return false;
        }

        for chunk in buf.chunks_mut(8) {
            let mut value: u64 = 0;
            let mut success = false;

            for _ in 0..10 {
                let result: u8;
                unsafe {
                    core::arch::asm!(
                        "rdrand {0}",
                        "setc {1}",
                        out(reg) value,
                        out(reg_byte) result,
                        options(nomem, nostack)
                    );
                }
                if result != 0 {
                    success = true;
                    break;
                }
            }

            if !success {
                return false;
            }

            let bytes = value.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }

        true
    }

    pub fn rdseed_fill(buf: &mut [u8]) -> bool {
        if !has_rdseed() {
            return false;
        }

        for chunk in buf.chunks_mut(8) {
            let mut value: u64 = 0;
            let mut success = false;

            for _ in 0..10 {
                let result: u8;
                unsafe {
                    core::arch::asm!(
                        "rdseed {0}",
                        "setc {1}",
                        out(reg) value,
                        out(reg_byte) result,
                        options(nomem, nostack)
                    );
                }
                if result != 0 {
                    success = true;
                    break;
                }
            }

            if !success {
                return false;
            }

            let bytes = value.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }

        true
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub mod hwrng {
    pub fn has_rdrand() -> bool { false }
    pub fn has_rdseed() -> bool { false }
    pub fn rdrand_fill(_buf: &mut [u8]) -> bool { false }
    pub fn rdseed_fill(_buf: &mut [u8]) -> bool { false }
}
