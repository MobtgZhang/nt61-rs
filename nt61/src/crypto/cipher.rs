//! Symmetric encryption algorithms and block cipher modes.
//!
//! Provides AES (128/192/256-bit), 3DES, RC4, and block cipher modes
//! (ECB, CBC, CTR, GCM) for use by CNG and legacy CryptoAPI.

extern crate alloc;
use alloc::vec::Vec;

const AES_BLOCK_SIZE: usize = 16;

pub struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut round_keys = [[0u8; 16]; 11];
        Self::key_expansion(key, &mut round_keys, 10);
        Self { round_keys }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        Self::cipher(block, &self.round_keys, 10);
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        Self::inv_cipher(block, &self.round_keys, 10);
    }

    fn key_expansion(key: &[u8; 16], round_keys: &mut [[u8; 16]], rounds: usize) {
        round_keys[0].copy_from_slice(key);

        const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

        for i in 1..=rounds {
            let prev = round_keys[i - 1];
            let mut temp = [prev[12], prev[13], prev[14], prev[15]];

            temp.rotate_left(1);

            for byte in &mut temp {
                *byte = SBOX[*byte as usize];
            }

            temp[0] ^= RCON[i - 1];

            for j in 0..4 {
                round_keys[i][j] = prev[j] ^ temp[j];
            }
            for j in 4..16 {
                round_keys[i][j] = prev[j] ^ round_keys[i][j - 4];
            }
        }
    }

    fn cipher(state: &mut [u8; 16], round_keys: &[[u8; 16]], rounds: usize) {
        Self::add_round_key(state, &round_keys[0]);

        for round in 1..rounds {
            Self::sub_bytes(state);
            Self::shift_rows(state);
            Self::mix_columns(state);
            Self::add_round_key(state, &round_keys[round]);
        }

        Self::sub_bytes(state);
        Self::shift_rows(state);
        Self::add_round_key(state, &round_keys[rounds]);
    }

    fn inv_cipher(state: &mut [u8; 16], round_keys: &[[u8; 16]], rounds: usize) {
        Self::add_round_key(state, &round_keys[rounds]);

        for round in (1..rounds).rev() {
            Self::inv_shift_rows(state);
            Self::inv_sub_bytes(state);
            Self::add_round_key(state, &round_keys[round]);
            Self::inv_mix_columns(state);
        }

        Self::inv_shift_rows(state);
        Self::inv_sub_bytes(state);
        Self::add_round_key(state, &round_keys[0]);
    }

    fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= key[i];
        }
    }

    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }

    fn inv_sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = INV_SBOX[*byte as usize];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        let tmp = *state;
        state[0] = tmp[0];
        state[1] = tmp[5];
        state[2] = tmp[10];
        state[3] = tmp[15];
        state[4] = tmp[4];
        state[5] = tmp[9];
        state[6] = tmp[14];
        state[7] = tmp[3];
        state[8] = tmp[8];
        state[9] = tmp[13];
        state[10] = tmp[2];
        state[11] = tmp[7];
        state[12] = tmp[12];
        state[13] = tmp[1];
        state[14] = tmp[6];
        state[15] = tmp[11];
    }

    fn inv_shift_rows(state: &mut [u8; 16]) {
        let tmp = *state;
        state[0] = tmp[0];
        state[1] = tmp[13];
        state[2] = tmp[10];
        state[3] = tmp[7];
        state[4] = tmp[4];
        state[5] = tmp[1];
        state[6] = tmp[14];
        state[7] = tmp[11];
        state[8] = tmp[8];
        state[9] = tmp[5];
        state[10] = tmp[2];
        state[11] = tmp[15];
        state[12] = tmp[12];
        state[13] = tmp[9];
        state[14] = tmp[6];
        state[15] = tmp[3];
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let s0 = state[i * 4];
            let s1 = state[i * 4 + 1];
            let s2 = state[i * 4 + 2];
            let s3 = state[i * 4 + 3];

            state[i * 4] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
            state[i * 4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
            state[i * 4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
            state[i * 4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
        }
    }

    fn inv_mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let s0 = state[i * 4];
            let s1 = state[i * 4 + 1];
            let s2 = state[i * 4 + 2];
            let s3 = state[i * 4 + 3];

            state[i * 4] = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9);
            state[i * 4 + 1] = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13);
            state[i * 4 + 2] = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11);
            state[i * 4 + 3] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14);
        }
    }
}

pub struct Aes256 {
    round_keys: [[u8; 16]; 15],
}

impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut round_keys = [[0u8; 16]; 15];
        Self::key_expansion(key, &mut round_keys);
        Self { round_keys }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        Aes128::cipher(block, &self.round_keys, 14);
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        Aes128::inv_cipher(block, &self.round_keys, 14);
    }

    fn key_expansion(key: &[u8; 32], round_keys: &mut [[u8; 16]]) {
        round_keys[0].copy_from_slice(&key[..16]);
        round_keys[1].copy_from_slice(&key[16..32]);

        const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

        for i in 2..15 {
            let prev = round_keys[i - 1];
            let prev2 = round_keys[i - 2];

            if i % 2 == 0 {
                let mut temp = [prev[12], prev[13], prev[14], prev[15]];
                temp.rotate_left(1);
                for byte in &mut temp {
                    *byte = SBOX[*byte as usize];
                }
                temp[0] ^= RCON[(i / 2) - 1];

                for j in 0..4 {
                    round_keys[i][j] = prev2[j] ^ temp[j];
                }
                for j in 4..16 {
                    round_keys[i][j] = prev2[j] ^ round_keys[i][j - 4];
                }
            } else {
                let mut temp = [prev[12], prev[13], prev[14], prev[15]];
                for byte in &mut temp {
                    *byte = SBOX[*byte as usize];
                }

                for j in 0..4 {
                    round_keys[i][j] = prev2[j] ^ temp[j];
                }
                for j in 4..16 {
                    round_keys[i][j] = prev2[j] ^ round_keys[i][j - 4];
                }
            }
        }
    }
}

/// Single DES, built on the audited RustCrypto `des` crate (legacy
/// CryptoAPI parity). Prefer 3DES or AES for anything new.
#[cfg(feature = "crypto_libs")]
pub struct Des {
    inner: des::Des,
}

#[cfg(feature = "crypto_libs")]
impl Des {
    pub fn new(key: &[u8; 8]) -> Self {
        use des::cipher::KeyInit;
        let inner = des::Des::new(des::cipher::generic_array::GenericArray::from_slice(key));
        Self { inner }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        use des::cipher::{generic_array::GenericArray, BlockEncrypt};
        let mut data = GenericArray::clone_from_slice(block);
        self.inner.encrypt_block(&mut data);
        block.copy_from_slice(&data);
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        use des::cipher::{generic_array::GenericArray, BlockDecrypt};
        let mut data = GenericArray::clone_from_slice(block);
        self.inner.decrypt_block(&mut data);
        block.copy_from_slice(&data);
    }
}

/// Triple DES (EDE) built on the audited RustCrypto `des` crate when the
/// `crypto_libs` feature is enabled. Without that feature construction
/// fails closed: no key-independent pseudo-cipher is ever produced.
#[cfg(feature = "crypto_libs")]
pub struct TripleDes {
    inner: des::TdesEde3,
}

#[cfg(not(feature = "crypto_libs"))]
pub struct TripleDes {
    _private: (),
}

#[cfg(feature = "crypto_libs")]
impl TripleDes {
    pub fn new(key: &[u8; 24]) -> Result<Self, &'static str> {
        use des::cipher::KeyInit;
        let inner = des::TdesEde3::new(des::cipher::generic_array::GenericArray::from_slice(key));
        Ok(Self { inner })
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) -> Result<(), &'static str> {
        use des::cipher::{generic_array::GenericArray, BlockEncrypt};
        let mut data = GenericArray::clone_from_slice(block);
        self.inner.encrypt_block(&mut data);
        block.copy_from_slice(&data);
        Ok(())
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) -> Result<(), &'static str> {
        use des::cipher::{generic_array::GenericArray, BlockDecrypt};
        let mut data = GenericArray::clone_from_slice(block);
        self.inner.decrypt_block(&mut data);
        block.copy_from_slice(&data);
        Ok(())
    }
}

#[cfg(not(feature = "crypto_libs"))]
impl TripleDes {
    pub fn new(_key: &[u8; 24]) -> Result<Self, &'static str> {
        Err("3DES requires the crypto_libs feature")
    }

    pub fn encrypt_block(&self, _block: &mut [u8; 8]) -> Result<(), &'static str> {
        Err("3DES requires the crypto_libs feature")
    }

    pub fn decrypt_block(&self, _block: &mut [u8; 8]) -> Result<(), &'static str> {
        Err("3DES requires the crypto_libs feature")
    }
}

/// 3DES-CBC encryption (no padding; input must be block aligned).
#[cfg(feature = "crypto_libs")]
pub fn tdes_cbc_encrypt(
    key: &[u8; 24],
    iv: &[u8; 8],
    input: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if input.len() % 8 != 0 {
        return Err("3DES-CBC input must be a multiple of the 8-byte block size");
    }
    let cipher = TripleDes::new(key)?;
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        for i in 0..8 {
            block[i] ^= feedback[i];
        }
        cipher.encrypt_block(&mut block)?;
        feedback.copy_from_slice(&block);
        out.extend_from_slice(&block);
    }
    Ok(out)
}

/// 3DES-CBC decryption (no padding; input must be block aligned).
#[cfg(feature = "crypto_libs")]
pub fn tdes_cbc_decrypt(
    key: &[u8; 24],
    iv: &[u8; 8],
    input: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if input.len() % 8 != 0 {
        return Err("3DES-CBC input must be a multiple of the 8-byte block size");
    }
    let cipher = TripleDes::new(key)?;
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block)?;
        for i in 0..8 {
            block[i] ^= feedback[i];
        }
        feedback.copy_from_slice(chunk);
        out.extend_from_slice(&block);
    }
    Ok(out)
}

pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s, i: 0, j: 0 }
    }

    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

pub struct Ecb<C> {
    cipher: C,
}

impl Ecb<Aes128> {
    pub fn new_aes128(key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(key),
        }
    }

    /// ECB has no security by itself and no padding: input must already
    /// be a multiple of the AES block size. A shorter tail is rejected
    /// instead of being silently zero-padded into the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if plaintext.len() % AES_BLOCK_SIZE != 0 {
            return Err("ECB input must be a multiple of the 16-byte AES block size");
        }
        let mut output = Vec::new();
        output.reserve(plaintext.len());
        for chunk in plaintext.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(chunk);
            self.cipher.encrypt_block(&mut block);
            output.extend_from_slice(&block);
        }
        Ok(output)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err("ECB input must be a multiple of the 16-byte AES block size");
        }
        let mut output = Vec::new();
        output.reserve(ciphertext.len());
        for chunk in ciphertext.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(chunk);
            self.cipher.decrypt_block(&mut block);
            output.extend_from_slice(&block);
        }
        Ok(output)
    }
}

pub struct Cbc<C> {
    cipher: C,
    iv: [u8; 16],
}

impl Cbc<Aes128> {
    pub fn new_aes128(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(key),
            iv: *iv,
        }
    }


    /// CBC with no padding: input must already be a multiple of the AES
    /// block size. A short tail is rejected instead of being silently
    /// zero-padded, and decryption rejects misaligned input outright
    /// (it previously panicked on the partial final block).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if plaintext.len() % AES_BLOCK_SIZE != 0 {
            return Err("CBC input must be a multiple of the 16-byte AES block size");
        }
        let mut output = Vec::with_capacity(plaintext.len());
        let mut prev = self.iv;

        for chunk in plaintext.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(chunk);

            for i in 0..AES_BLOCK_SIZE {
                block[i] ^= prev[i];
            }

            self.cipher.encrypt_block(&mut block);
            prev = block;
            output.extend_from_slice(&block);
        }

        Ok(output)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err("CBC input must be a multiple of the 16-byte AES block size");
        }
        let mut output = Vec::with_capacity(ciphertext.len());
        let mut prev = self.iv;

        for chunk in ciphertext.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(chunk);
            let cipher_block = block;

            self.cipher.decrypt_block(&mut block);

            for i in 0..AES_BLOCK_SIZE {
                block[i] ^= prev[i];
            }

            prev = cipher_block;
            output.extend_from_slice(&block);
        }

        Ok(output)
    }
}

impl Cbc<Aes256> {
    /// Create a CBC-mode cipher with AES-256.
    pub fn new_aes256(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes256::new(key),
            iv: *iv,
        }
    }


    /// CBC with no padding: input must already be a multiple of the AES
    /// block size (NTFS EFS callers pad explicitly). A short tail is
    /// rejected instead of being silently zero-padded, and decryption
    /// rejects misaligned input outright (it previously panicked on the
    /// partial final block).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if plaintext.len() % AES_BLOCK_SIZE != 0 {
            return Err("CBC input must be a multiple of the 16-byte AES block size");
        }
        let mut output = Vec::with_capacity(plaintext.len());
        let mut prev = self.iv;

        for chunk in plaintext.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(chunk);

            for i in 0..AES_BLOCK_SIZE {
                block[i] ^= prev[i];
            }

            self.cipher.encrypt_block(&mut block);
            prev = block;
            output.extend_from_slice(&block);
        }

        Ok(output)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err("CBC input must be a multiple of the 16-byte AES block size");
        }
        let mut output = Vec::with_capacity(ciphertext.len());
        let mut prev = self.iv;

        for chunk in ciphertext.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(chunk);
            let cipher_block = block;

            self.cipher.decrypt_block(&mut block);

            for i in 0..AES_BLOCK_SIZE {
                block[i] ^= prev[i];
            }

            prev = cipher_block;
            output.extend_from_slice(&block);
        }

        Ok(output)
    }
}

pub struct Ctr<C> {
    cipher: C,
    counter: [u8; 16],
}

impl Ctr<Aes256> {
    /// AES-256-CTR as specified for SSH "aes256-ctr" (RFC 5647): the
    /// 128-bit big-endian counter block is incremented after every
    /// 16-byte block.
    pub fn new_aes256(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        Self {
            cipher: Aes256::new(key),
            counter: *nonce,
        }
    }

    pub fn process(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
            let mut keystream = self.counter;
            self.cipher.encrypt_block(&mut keystream);

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }

            Self::increment_counter(&mut self.counter);
        }
    }

    fn increment_counter(counter: &mut [u8; 16]) {
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
}

impl Ctr<Aes128> {
    pub fn new_aes128(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(key),
            counter: *nonce,
        }
    }

    pub fn process(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
            let mut keystream = self.counter;
            self.cipher.encrypt_block(&mut keystream);

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }

            Self::increment_counter(&mut self.counter);
        }
    }

    fn increment_counter(counter: &mut [u8; 16]) {
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
}

pub struct Gcm {
    cipher: Aes128,
    pub h: [u8; 16],
    counter: [u8; 16],
}

impl Gcm {
    pub fn new(key: &[u8; 16], iv: &[u8; 12]) -> Self {
        let cipher = Aes128::new(key);

        let mut h = [0u8; 16];
        cipher.encrypt_block(&mut h);

        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(iv);
        counter[15] = 1;

        Self { cipher, h, counter }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        let mut counter = self.counter;
        Self::increment_counter(&mut counter);

        for chunk in plaintext.chunks(AES_BLOCK_SIZE) {
            let mut keystream = counter;
            self.cipher.encrypt_block(&mut keystream);

            let mut block = [0u8; AES_BLOCK_SIZE];
            let len = chunk.len().min(AES_BLOCK_SIZE);
            block[..len].copy_from_slice(&chunk[..len]);

            for i in 0..len {
                block[i] ^= keystream[i];
            }

            ciphertext.extend_from_slice(&block[..len]);
            Self::increment_counter(&mut counter);
        }

        let tag = self.tag_for(self.compute_ghash(aad, &ciphertext));
        (ciphertext, tag)
    }

    /// Decrypt and authenticate. Returns the plaintext only when the tag
    /// matches; a mismatch means the ciphertext or AAD was tampered with.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        auth_tag: &[u8; 16],
    ) -> Option<Vec<u8>> {
        let expected = self.tag_for(self.compute_ghash(aad, ciphertext));
        if expected != *auth_tag {
            return None;
        }

        let mut counter = self.counter;
        Self::increment_counter(&mut counter);

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for chunk in ciphertext.chunks(AES_BLOCK_SIZE) {
            let mut keystream = counter;
            self.cipher.encrypt_block(&mut keystream);

            let len = chunk.len().min(AES_BLOCK_SIZE);
            let mut block = [0u8; AES_BLOCK_SIZE];
            block[..len].copy_from_slice(chunk);
            for i in 0..len {
                block[i] ^= keystream[i];
            }
            plaintext.extend_from_slice(&block[..len]);
            Self::increment_counter(&mut counter);
        }

        Some(plaintext)
    }

    /// GHASH over the AAD blocks followed by the ciphertext blocks,
    /// terminated by the length block. Every block, including a zero-padded
    /// partial tail, is multiplied by H exactly once.
    fn compute_ghash(&self, aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut ghash = [0u8; 16];
        let absorb = |data: &[u8], ghash: &mut [u8; 16]| {
            for chunk in data.chunks(AES_BLOCK_SIZE) {
                let mut block = [0u8; AES_BLOCK_SIZE];
                block[..chunk.len()].copy_from_slice(chunk);
                xor_blocks(ghash, &block);
                *ghash = gf128_mul(*ghash, self.h);
            }
        };
        absorb(aad, &mut ghash);
        absorb(ciphertext, &mut ghash);

        let mut lengths = [0u8; AES_BLOCK_SIZE];
        lengths[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
        xor_blocks(&mut ghash, &lengths);
        gf128_mul(ghash, self.h)
    }

    /// The authentication tag: E_K(J0) xor GHASH(A, C).
    fn tag_for(&self, ghash: [u8; 16]) -> [u8; 16] {
        let mut tag_input = self.counter;
        self.cipher.encrypt_block(&mut tag_input);
        let mut tag = [0u8; 16];
        xor_blocks(&mut tag, &tag_input);
        xor_blocks(&mut tag, &ghash);
        tag
    }

    fn increment_counter(counter: &mut [u8; 16]) {
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
}

fn xor_blocks(left: &mut [u8; 16], right: &[u8; 16]) {
    for (left, right) in left.iter_mut().zip(right) {
        *left ^= right;
    }
}

fn gf128_mul(x: [u8; 16], h: [u8; 16]) -> [u8; 16] {
    // NIST SP 800-38D multiplication: Z accumulates V, which starts as H and
    // is shifted one bit (with the 0xe1 reduction) after each processed bit
    // of X, most significant bit first.
    let mut z_high = 0u64;
    let mut z_low = 0u64;
    let mut v_high = u64::from_be_bytes(h[..8].try_into().unwrap());
    let mut v_low = u64::from_be_bytes(h[8..].try_into().unwrap());

    for byte in x {
        for bit_index in (0..8).rev() {
            if (byte >> bit_index) & 1 != 0 {
                z_high ^= v_high;
                z_low ^= v_low;
            }

            let lsb_set = v_low & 1 != 0;
            let carry = v_high & 1;
            v_high >>= 1;
            v_low = (v_low >> 1) | (carry << 63);
            if lsb_set {
                v_high ^= 0xe100_0000_0000_0000;
            }
        }
    }

    let mut result = [0u8; 16];
    result[..8].copy_from_slice(&z_high.to_be_bytes());
    result[8..].copy_from_slice(&z_low.to_be_bytes());
    result
}

fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }

        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1b; // AES irreducible polynomial
        }

        b >>= 1;
    }

    p
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_matches_fips197_c1() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let pt = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];
        let mut block = pt;
        Aes128::new(&key).encrypt_block(&mut block);
        assert_eq!(block, expected, "ct mismatch: {:02x?}", block);
    }

    #[test]
    fn gcm_matches_reference_vectors() {
        // NIST/McGrew-Viega test cases 1 and 2: zero key and IV.
        let key = [0u8; 16];
        let iv = [0u8; 12];

        let (empty_ct, empty_tag) = Gcm::new(&key, &iv).encrypt(&[], &[]);
        assert!(empty_ct.is_empty());
        assert_eq!(
            empty_tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4,
                0xe7, 0x45, 0x5a,
            ]
        );

        let (ct, tag) = Gcm::new(&key, &iv).encrypt(&[0u8; 16], &[]);
        assert_eq!(
            ct,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71,
                0xb2, 0xfe, 0x78,
            ]
        );
        assert_eq!(
            tag,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12,
                0x57, 0xbd, 0xdf,
            ]
        );
    }

    #[test]
    fn gcm_handles_partial_blocks_like_reference() {
        // Cross-checked against a standard AES-GCM implementation with a
        // 13-byte AAD and a 21-byte plaintext (non-multiple block sizes).
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let iv = [0x07u8; 12];
        let aad = [0x33u8; 13];
        let plaintext = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];

        let (ct, tag) = Gcm::new(&key, &iv).encrypt(&plaintext, &aad);
        assert_eq!(
            ct,
            [
                0x91, 0x4d, 0x56, 0xde, 0x65, 0xbe, 0xc6, 0x3e, 0xff, 0x42, 0x28, 0xc8, 0x13,
                0xb4, 0xe6, 0x76, 0x26, 0xd5, 0x58, 0x19, 0xa6,
            ]
        );
        assert_eq!(
            tag,
            [
                0x56, 0x44, 0x90, 0xe4, 0x9c, 0xcf, 0x94, 0xc2, 0x6e, 0xc7, 0xc1, 0x3f, 0xa0,
                0xc8, 0x6b, 0xed,
            ]
        );
    }

    #[test]
    fn gcm_decrypt_roundtrip_and_tamper() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let aad = [0x33u8; 8];
        let plaintext: &[u8] = b"attack at dawn attack at dawn";

        let (ct, tag) = {
            let mut gcm = Gcm::new(&key, &iv);
            gcm.encrypt(plaintext, &aad)
        };

        let mut gcm = Gcm::new(&key, &iv);
        let decrypted = gcm.decrypt(&ct, &aad, &tag).expect("valid tag");
        assert_eq!(decrypted.as_slice(), plaintext);

        let mut gcm = Gcm::new(&key, &iv);
        let mut bad_tag = tag;
        bad_tag[15] ^= 0x01;
        assert!(gcm.decrypt(&ct, &aad, &bad_tag).is_none());

        let mut gcm = Gcm::new(&key, &iv);
        let bad_aad = [0x34u8; 8];
        assert!(gcm.decrypt(&ct, &bad_aad, &tag).is_none());
    }

    #[test]
    #[cfg(feature = "crypto_libs")]
    fn des_matches_openssl_reference_vector() {
        // Verified against: openssl enc -des-ecb -provider legacy
        //   -K 0E329232EA6D0D73 with plaintext "DESC" + 4 zero bytes.
        let key = [0x0e, 0x32, 0x92, 0x32, 0xea, 0x6d, 0x0d, 0x73];
        let mut block = [0x44, 0x45, 0x53, 0x43, 0x00, 0x00, 0x00, 0x00];
        let expected = [0xe7, 0xa1, 0xc3, 0x90, 0x3c, 0x4b, 0xeb, 0x1a];
        Des::new(&key).encrypt_block(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    #[cfg(feature = "crypto_libs")]
    fn triple_des_matches_openssl_reference_vector() {
        // Verified against: openssl enc -des-ede3 -provider legacy
        //   -K 0123456789ABCDEF23456789ABCDEF010F0F0F0F0F0F0F0F
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
            0xef, 0x01, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
        ];
        let plaintext = [
            0x44, 0x45, 0x53, 0x43, 0x00, 0x00, 0x00, 0x00, 0x44, 0x45, 0x53, 0x43, 0x00, 0x00,
            0x00, 0x00,
        ];
        let expected = [
            0x12, 0x0b, 0x7d, 0x11, 0x2b, 0x32, 0xbe, 0x51, 0x12, 0x0b, 0x7d, 0x11, 0x2b, 0x32,
            0xbe, 0x51,
        ];
        let cipher = TripleDes::new(&key).expect("valid 3DES key");
        let mut ct = plaintext;
        for chunk in ct.chunks_mut(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            cipher.encrypt_block(&mut block).expect("encrypt");
            chunk.copy_from_slice(&block);
        }
        assert_eq!(ct, expected);
    }

    #[test]
    #[cfg(feature = "crypto_libs")]
    fn triple_des_cbc_matches_openssl_reference_vector() {
        // Verified against: openssl enc -des3 -provider legacy
        //   -K 0123456789ABCDEF23456789ABCDEF010F0F0F0F0F0F0F0F
        //   -iv 1122334455667788
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
            0xef, 0x01, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
        ];
        let iv = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let plaintext = [
            0x44, 0x45, 0x53, 0x43, 0x00, 0x00, 0x00, 0x00, 0x44, 0x45, 0x53, 0x43, 0x00, 0x00,
            0x00, 0x00,
        ];
        let expected = [
            0xac, 0x53, 0xb7, 0xaf, 0xfe, 0xd4, 0x62, 0x5a, 0x94, 0xd6, 0x32, 0xf9, 0x92, 0x28,
            0xa1, 0x6b,
        ];
        let ct = tdes_cbc_encrypt(&key, &iv, &plaintext).expect("encrypt");
        assert_eq!(ct, expected);
        let pt = tdes_cbc_decrypt(&key, &iv, &ct).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    #[cfg(feature = "crypto_libs")]
    fn triple_des_block_roundtrip() {
        let key = [0x42u8; 24];
        let cipher = TripleDes::new(&key).expect("valid 3DES key");
        let mut block = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        let original = block;
        cipher.encrypt_block(&mut block).expect("encrypt");
        assert_ne!(block, original);
        cipher.decrypt_block(&mut block).expect("decrypt");
        assert_eq!(block, original);
    }
}
