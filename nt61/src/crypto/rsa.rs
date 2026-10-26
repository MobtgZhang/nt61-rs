//! RSA asymmetric encryption and digital signatures.
//!
//! Provides RSA key generation, encryption, decryption, and signature
//! operations (PKCS#1 v1.5 and PSS) for CNG providers.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct RsaPublicKey {
    pub n: BigUint, // Modulus
    pub e: BigUint, // Public exponent
}

#[derive(Clone)]
pub struct RsaPrivateKey {
    pub n: BigUint,  // Modulus
    pub e: BigUint,  // Public exponent
    pub d: BigUint,  // Private exponent
    pub p: BigUint,  // First prime
    pub q: BigUint,  // Second prime
    pub dp: BigUint, // d mod (p-1)
    pub dq: BigUint, // d mod (q-1)
    pub qi: BigUint, // q^-1 mod p
}

impl RsaPrivateKey {
    pub fn generate(bits: usize) -> Option<Self> {
        if !(512..=4096).contains(&bits) || bits % 2 != 0 {
            return None;
        }

        let e = BigUint::from(65537u32); // Standard public exponent

        let prime_bits = bits / 2;
        let p = match generate_prime(prime_bits) {
            Some(value) => value,
            None => return None,
        };
        let q = match generate_prime(prime_bits) {
            Some(value) => value,
            None => return None,
        };

        let n = p.mul(&q);

        let p_minus_1 = p.sub(&BigUint::from(1u32));
        let q_minus_1 = q.sub(&BigUint::from(1u32));
        let phi = p_minus_1.mul(&q_minus_1);

        let d = e.mod_inverse(&phi);

        let dp = d.mod_op(&p_minus_1);
        let dq = d.mod_op(&q_minus_1);
        let qi = q.mod_inverse(&p);

        Some(Self {
            n,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qi,
        })
    }

    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let c = BigUint::from_bytes(ciphertext);

        let m1 = c.mod_exp(&self.dp, &self.p);
        let m2 = c.mod_exp(&self.dq, &self.q);

        let h = if m1.cmp(&m2) >= 0 {
            self.qi.mul(&m1.sub(&m2)).mod_op(&self.p)
        } else {
            let diff = self.p.sub(&m2.sub(&m1).mod_op(&self.p));
            self.qi.mul(&diff).mod_op(&self.p)
        };

        let m = m2.add(&h.mul(&self.q));
        let recovered = m.to_bytes();
        pkcs1v15_unpad(&recovered)
    }

    pub fn sign_pkcs1v15(&self, digest: &[u8]) -> Result<Vec<u8>, &'static str> {
        let padded = pkcs1v15_sign_pad(digest, self.n.byte_len())?;
        let m = BigUint::from_bytes(&padded);
        let s = m.mod_exp(&self.d, &self.n);
        Ok(to_bytes_padded(&s, self.n.byte_len()))
    }

    pub fn sign_pss(&self, digest: &[u8], salt_len: usize) -> Result<Vec<u8>, &'static str> {
        let padded = pss_encode(digest, self.n.byte_len(), self.n.bit_len(), salt_len)?;
        let m = BigUint::from_bytes(&padded);
        let s = m.mod_exp(&self.d, &self.n);
        Ok(to_bytes_padded(&s, self.n.byte_len()))
    }
}

impl RsaPublicKey {
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let padded = pkcs1v15_encrypt_pad(plaintext, self.n.byte_len());
        let m = BigUint::from_bytes(&padded);
        let c = m.mod_exp(&self.e, &self.n);
        c.to_bytes()
    }

    pub fn verify_pkcs1v15(&self, digest: &[u8], signature: &[u8]) -> bool {
        let s = BigUint::from_bytes(signature);
        let m = s.mod_exp(&self.e, &self.n);
        let recovered = m.to_bytes();

        pkcs1v15_verify_pad(&recovered, digest, self.n.byte_len())
    }

    pub fn verify_pss(&self, digest: &[u8], signature: &[u8], salt_len: usize) -> bool {
        if signature.len() != self.n.byte_len() {
            return false;
        }
        let s = BigUint::from_bytes(signature);
        let m = s.mod_exp(&self.e, &self.n);
        let recovered = m.to_bytes();

        pss_verify(
            &recovered,
            digest,
            self.n.byte_len(),
            self.n.bit_len(),
            salt_len,
        )
    }
}

fn pkcs1v15_encrypt_pad(data: &[u8], key_len: usize) -> Vec<u8> {
    let mut padded = Vec::with_capacity(key_len);
    padded.push(0x00);
    padded.push(0x02);

    let Some(padding_len) = key_len
        .checked_sub(data.len())
        .and_then(|left| left.checked_sub(3))
    else {
        return Vec::new();
    };
    for _ in 0..padding_len {
        let mut byte = 0u8;
        while byte == 0 {
            crate::crypto::csprng::fill(core::slice::from_mut(&mut byte));
        }
        padded.push(byte);
    }

    padded.push(0x00);
    padded.extend_from_slice(data);
    padded
}

fn pkcs1v15_sign_pad(digest: &[u8], key_len: usize) -> Result<Vec<u8>, &'static str> {
    let digest_info = digest_info_prefix(digest);
    if digest_info.is_empty() {
        return Err("unsupported digest length");
    }
    // Checked arithmetic: an undersized modulus used to underflow here into
    // a multi-gigabyte allocation and abort the kernel.
    let Some(padding_len) = key_len
        .checked_sub(digest_info.len())
        .and_then(|left| left.checked_sub(digest.len()))
        .and_then(|left| left.checked_sub(3))
    else {
        return Err("RSA modulus is too small for digest");
    };
    let mut padded = Vec::with_capacity(key_len);
    padded.push(0x00);
    padded.push(0x01);

    for _ in 0..padding_len {
        padded.push(0xff);
    }

    padded.push(0x00);
    padded.extend_from_slice(&digest_info);
    padded.extend_from_slice(digest);
    Ok(padded)
}

/// Render a signature integer as exactly len big-endian bytes, left-padded
/// with zeros. Signatures must be modulus-length even when the encoded
/// integer has leading zero bytes.
fn to_bytes_padded(value: &BigUint, len: usize) -> Vec<u8> {
    let raw = value.to_bytes();
    let mut padded = vec![0u8; len.saturating_sub(raw.len())];
    padded.extend_from_slice(&raw);
    padded
}

fn pkcs1v15_verify_pad(recovered: &[u8], digest: &[u8], _key_len: usize) -> bool {
    // BigUint::to_bytes() strips the leading 0x00 from the encoded
    // message (0x00 0x01 PS 0x00 T), so recovered starts at 0x01.
    if recovered.len() < digest.len() + 10 {
        return false;
    }

    if recovered[0] != 0x01 {
        return false;
    }

    let mut i = 1;
    while i < recovered.len() && recovered[i] == 0xff {
        i += 1;
    }

    if i >= recovered.len() || recovered[i] != 0x00 {
        return false;
    }

    let digest_info = digest_info_prefix(digest);
    i += 1;
    recovered[i..].starts_with(&digest_info) && recovered[i + digest_info.len()..] == *digest
}

/// ASN.1 `DigestInfo` prefixes used by PKCS#1 v1.5 signatures. The
/// prefix is selected by digest length, matching SHA-1/256/384/512.
fn digest_info_prefix(digest: &[u8]) -> Vec<u8> {
    let prefix: &[u8] = match digest.len() {
        20 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
            0x04, 0x14,
        ],
        32 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
            0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        48 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
            0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        64 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
            0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        _ => &[],
    };
    prefix.to_vec()
}

/// Strip PKCS#1 v1.5 encryption padding (RFC 8017 section 7.2):
/// recovered = [0x02, nonzero padding, 0x00, plaintext].
fn pkcs1v15_unpad(recovered: &[u8]) -> Vec<u8> {
    if recovered.len() < 2 || recovered[0] != 0x02 {
        return Vec::new();
    }
    let separator = recovered[1..].iter().position(|&byte| byte == 0x00);
    match separator {
        Some(index) => recovered[2 + index..].to_vec(),
        None => Vec::new(),
    }
}

/// PSS encoding using MGF1-SHA256.
fn pss_encode(
    digest: &[u8],
    key_len: usize,
    modulus_bits: usize,
    salt_len: usize,
) -> Result<Vec<u8>, &'static str> {
    if digest.len() != 32 {
        return Err("PSS requires SHA-256");
    }
    let Some(db_len) = key_len
        .checked_sub(32)
        .and_then(|left| left.checked_sub(1))
    else {
        return Err("RSA modulus is too small for PSS");
    };
    if salt_len + digest.len() + 2 > key_len {
        return Err("RSA modulus is too small for PSS salt");
    }
    let mut salt = vec![0u8; salt_len];
    crate::crypto::csprng::fill(&mut salt);

    let mut m_prime = Vec::new();
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&salt);

    let h = crate::crypto::hash::sha256(&m_prime);

    let mut db = vec![0u8; db_len];
    db[db_len - salt_len - 1] = 0x01;
    db[db_len - salt_len..].copy_from_slice(&salt);
    mgf1_sha256(&h, &mut db);
    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    // PSS encodes an EM of `emBits = modulus_bits - 1` significant bits,
    // left-padded to the modulus byte length. Mask only the padding bits so
    // EM is numerically below the modulus, even for a 511-bit modulus.
    let em_bits = modulus_bits.checked_sub(1).ok_or("RSA modulus is too small")?;
    let padding_bits = (key_len * 8).saturating_sub(em_bits);
    if padding_bits >= 8 {
        return Err("RSA modulus is too small for PSS");
    }
    if let Some(first) = em.first_mut() {
        *first &= 0xffu8.checked_shr(padding_bits as u32).unwrap_or(0);
    }
    Ok(em)
}

fn mgf1_sha256(seed: &[u8], mask: &mut [u8]) {
    let mut counter = 0u32;
    for chunk in mask.chunks_mut(32) {
        let mut input = Vec::with_capacity(seed.len() + 4);
        input.extend_from_slice(seed);
        input.extend_from_slice(&counter.to_be_bytes());
        let hash = crate::crypto::hash::sha256(&input);
        for (byte, mask_byte) in chunk.iter_mut().zip(hash.iter()) {
            *byte ^= *mask_byte;
        }
        counter = counter.wrapping_add(1);
    }
}

fn pss_verify(
    recovered: &[u8],
    digest: &[u8],
    key_len: usize,
    modulus_bits: usize,
    salt_len: usize,
) -> bool {
    if digest.len() != 32 || salt_len + digest.len() + 2 > key_len {
        return false;
    }
    if recovered.len() > key_len {
        return false;
    }
    let mut em = vec![0u8; key_len];
    em[key_len - recovered.len()..].copy_from_slice(recovered);
    let em_bits = modulus_bits.checked_sub(1).unwrap_or(0);
    let padding_bits = (key_len * 8).saturating_sub(em_bits);
    let padding_mask = 0xffu8.checked_shr(padding_bits as u32).unwrap_or(0);
    if em[0] & !padding_mask != 0 || em[key_len - 1] != 0xbc {
        return false;
    }

    let db_len = key_len - 32 - 1;
    let mut db = em[..db_len].to_vec();
    let h = em[db_len..key_len - 1].to_vec();
    mgf1_sha256(&h, &mut db);
    // Mirror the encoder: the leftmost `padding_bits` of maskedDB were
    // zeroed before transmission, so the unmasked DB must have the same
    // bits cleared again before the PS/0x01/salt structure checks.
    if let Some(first) = db.first_mut() {
        *first &= padding_mask;
    }
    if db.len() < salt_len + 1 {
        return false;
    }
    if db[db_len - salt_len - 1] != 0x01 {
        return false;
    }
    if db[..db_len - salt_len - 1].iter().any(|&byte| byte != 0) {
        return false;
    }
    let salt = db[db_len - salt_len..].to_vec();
    let mut m_prime = Vec::with_capacity(8 + digest.len() + salt.len());
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&salt);
    h == crate::crypto::hash::sha256(&m_prime)
}

#[derive(Clone)]
pub struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    pub fn from(value: u32) -> Self {
        Self {
            limbs: vec![value as u64],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::new();
        for chunk in bytes.rchunks(8) {
            let mut limb = 0u64;
            for &byte in chunk {
                limb = (limb << 8) | (byte as u64);
            }
            limbs.push(limb);
        }
        while limbs.last() == Some(&0) && limbs.len() > 1 {
            limbs.pop();
        }
        Self { limbs }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &limb in self.limbs.iter().rev() {
            bytes.extend_from_slice(&limb.to_be_bytes());
        }
        while bytes.first() == Some(&0) && bytes.len() > 1 {
            bytes.remove(0);
        }
        bytes
    }

    pub fn byte_len(&self) -> usize {
        if self.limbs.is_empty() {
            return 1;
        }
        let top_limb = self.limbs[self.limbs.len() - 1];
        let limb_bytes = if top_limb == 0 {
            1
        } else {
            (64 - top_limb.leading_zeros() + 7) / 8
        };
        (self.limbs.len() - 1) * 8 + limb_bytes as usize
    }

    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut result = vec![0u64; max_len + 1];
        let mut carry = 0u64;

        for i in 0..max_len {
            let a = if i < self.limbs.len() {
                self.limbs[i]
            } else {
                0
            };
            let b = if i < other.limbs.len() {
                other.limbs[i]
            } else {
                0
            };
            let (sum, c1) = a.overflowing_add(b);
            let (sum, c2) = sum.overflowing_add(carry);
            result[i] = sum;
            carry = (c1 || c2) as u64;
        }

        if carry > 0 {
            result[max_len] = carry;
        }

        while result.last() == Some(&0) && result.len() > 1 {
            result.pop();
        }

        Self { limbs: result }
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut result = vec![0u64; self.limbs.len()];
        let mut borrow = 0u64;

        for i in 0..self.limbs.len() {
            let b = if i < other.limbs.len() {
                other.limbs[i]
            } else {
                0
            };
            // Toolchain-agnostic two-step borrow: subtract the limb and
            // the accumulated borrow separately, tracking underflow.
            let (d1, under1) = self.limbs[i].overflowing_sub(b);
            let (diff, under2) = d1.overflowing_sub(borrow);
            result[i] = diff;
            borrow = (under1 || under2) as u64;
        }

        while result.last() == Some(&0) && result.len() > 1 {
            result.pop();
        }

        Self { limbs: result }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut result = vec![0u64; self.limbs.len() + other.limbs.len()];

        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let product = (a as u128) * (b as u128) + (result[i + j] as u128) + (carry as u128);
                result[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            if carry > 0 {
                result[i + other.limbs.len()] = carry;
            }
        }

        while result.last() == Some(&0) && result.len() > 1 {
            result.pop();
        }

        Self { limbs: result }
    }

    pub fn mod_op(&self, modulus: &Self) -> Self {
        self.div_rem(modulus).1
    }

    pub fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        let mut result = BigUint::from(1);
        let mut base = self.mod_op(modulus);
        let mut exp = exponent.clone();

        while !exp.is_zero() {
            if exp.limbs[0] & 1 == 1 {
                result = result.mul(&base).mod_op(modulus);
            }
            base = base.mul(&base).mod_op(modulus);
            exp = exp.shr(1);
        }

        result
    }

    pub fn mod_inverse(&self, modulus: &Self) -> Self {
        let mut t = BigUint::from(0);
        let mut newt = BigUint::from(1);
        let mut r = modulus.clone();
        let mut newr = self.clone();

        while !newr.is_zero() {
            let quotient = r.div(&newr);
            let temp_t = t.clone();
            t = newt.clone();
            newt = if temp_t.cmp(&quotient.mul(&newt)) >= 0 {
                temp_t.sub(&quotient.mul(&newt))
            } else {
                modulus
                    .sub(&quotient.mul(&newt).sub(&temp_t).mod_op(modulus))
                    .mod_op(modulus)
            };

            let temp_r = r;
            r = newr.clone();
            newr = temp_r.sub(&quotient.mul(&newr));
        }

        t.mod_op(modulus)
    }

    pub fn div(&self, other: &Self) -> Self {
        self.div_rem(other).0
    }

    /// Binary long division (shift-subtract): returns
    /// (quotient, remainder). Runs in O(bit_len) iterations of O(limb)
    /// work, so it terminates quickly for RSA-sized operands where the
    /// previous repeated-subtraction loop did not.
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        if other.is_zero() {
            return (BigUint::from(0), self.clone());
        }
        let mut quotient_limbs = vec![0u64; self.limbs.len().max(1)];
        let mut rem = BigUint::from(0);
        for i in (0..self.bit_len()).rev() {
            rem = rem.shl(1);
            rem.limbs[0] |= self.bit(i) as u64;
            if rem.cmp(other) >= 0 {
                rem = rem.sub(other);
                quotient_limbs[i / 64] |= 1u64 << (i % 64);
            }
        }
        while quotient_limbs.last() == Some(&0) && quotient_limbs.len() > 1 {
            quotient_limbs.pop();
        }
        (
            BigUint {
                limbs: quotient_limbs,
            },
            rem,
        )
    }

    pub fn shr(&self, bits: u32) -> Self {
        if bits == 0 {
            return self.clone();
        }

        let limb_shift = (bits / 64) as usize;
        let bit_shift = (bits % 64) as u32;

        if limb_shift >= self.limbs.len() {
            return BigUint::from(0);
        }

        let mut result = vec![0u64; self.limbs.len() - limb_shift];

        for i in 0..result.len() {
            result[i] = self.limbs[i + limb_shift] >> bit_shift;
            if i + limb_shift + 1 < self.limbs.len() && bit_shift > 0 {
                result[i] |= self.limbs[i + limb_shift + 1] << (64 - bit_shift);
            }
        }

        while result.last() == Some(&0) && result.len() > 1 {
            result.pop();
        }

        Self { limbs: result }
    }

    pub fn cmp(&self, other: &Self) -> i32 {
        if self.limbs.len() != other.limbs.len() {
            return if self.limbs.len() > other.limbs.len() {
                1
            } else {
                -1
            };
        }

        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] > other.limbs[i] {
                return 1;
            } else if self.limbs[i] < other.limbs[i] {
                return -1;
            }
        }

        0
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&limb| limb == 0)
    }

    /// Number of significant bits (index of the highest set bit + 1).
    fn bit_len(&self) -> usize {
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != 0 {
                return i * 64 + (64 - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    fn bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / 64)
            .map_or(false, |limb| (limb >> (index % 64)) & 1 == 1)
    }

    /// Shift left by one bit position (used by the division loop).
    fn shl(&self, bits: u32) -> Self {
        if bits == 0 {
            return self.clone();
        }
        let limb_shift = (bits / 64) as usize;
        let bit_shift = (bits % 64) as u32;
        let mut result = vec![0u64; self.limbs.len() + limb_shift + 1];
        for (i, &limb) in self.limbs.iter().enumerate() {
            let idx = i + limb_shift;
            result[idx] |= limb << bit_shift;
            if bit_shift > 0 && idx + 1 < result.len() {
                result[idx + 1] |= limb >> (64 - bit_shift);
            }
        }
        while result.last() == Some(&0) && result.len() > 1 {
            result.pop();
        }
        BigUint { limbs: result }
    }
}

fn generate_prime(bits: usize) -> Option<BigUint> {
    if bits == 0 || bits > 2048 {
        return None;
    }
    loop {
        let candidate = generate_random_odd(bits);
        if is_probably_prime(&candidate, 20) {
            return Some(candidate);
        }
    }
}

fn generate_random_odd(bits: usize) -> BigUint {
    if bits == 0 {
        return BigUint::from(0);
    }

    let bytes = (bits + 7) / 8;
    let mut data = vec![0u8; bytes];
    crate::crypto::csprng::fill(&mut data);

    data[0] |= 0xC0; // Set top two bits so n = p*q has full key bit length
    data[bytes - 1] |= 0x01; // Ensure it's odd

    BigUint::from_bytes(&data)
}

fn is_probably_prime(n: &BigUint, rounds: usize) -> bool {
    if n.cmp(&BigUint::from(2)) < 0 {
        return false;
    }
    if n.cmp(&BigUint::from(2)) == 0 || n.cmp(&BigUint::from(3)) == 0 {
        return true;
    }
    if n.limbs[0] & 1 == 0 {
        return false;
    }

    let n_minus_1 = n.sub(&BigUint::from(1));
    let mut d = n_minus_1.clone();
    let mut r = 0u32;

    while d.limbs[0] & 1 == 0 {
        d = d.shr(1);
        r += 1;
    }

    for _ in 0..rounds {
        let a = generate_witness(n);
        let mut x = a.mod_exp(&d, n);

        if x.cmp(&BigUint::from(1)) == 0 || x.cmp(&n_minus_1) == 0 {
            continue;
        }

        let mut composite = true;
        for _ in 0..r - 1 {
            x = x.mul(&x).mod_op(n);
            if x.cmp(&n_minus_1) == 0 {
                composite = false;
                break;
            }
        }

        if composite {
            return false;
        }
    }

    true
}

fn generate_witness(n: &BigUint) -> BigUint {
    let bytes = n.byte_len();
    let mut data = vec![0u8; bytes];
    crate::crypto::csprng::fill(&mut data);

    let witness = BigUint::from_bytes(&data);
    witness.mod_op(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_rejects_invalid_key_lengths() {
        assert!(RsaPrivateKey::generate(0).is_none());
        assert!(RsaPrivateKey::generate(256).is_none());
        assert!(RsaPrivateKey::generate(511).is_none());
        assert!(RsaPrivateKey::generate(8192).is_none());
    }

    // Key generation is expensive, so a single 512-bit generation is shared
    // by every signature assertion in one test.
    #[test]
    fn rsa_sign_verify_and_rejection_paths() {
        let key = RsaPrivateKey::generate(512).expect("512-bit key generation");

        // PKCS#1 v1.5: round trip with a SHA-256 digest, fixed-length output.
        let digest = crate::crypto::hash::sha256(b"nt61 rsa pkcs1v15");
        let signature = key.sign_pkcs1v15(&digest).expect("pkcs1v15 sign");
        assert_eq!(signature.len(), key.n.byte_len());
        assert!(key.public_key().verify_pkcs1v15(&digest, &signature));
        let wrong_digest = crate::crypto::hash::sha256(b"other message");
        assert!(!key.public_key().verify_pkcs1v15(&wrong_digest, &signature));

        // PSS: the H field must make sign -> verify round trips pass.
        let digest = crate::crypto::hash::sha256(b"nt61 rsa pss");
        let signature = key.sign_pss(&digest, 16).expect("pss sign");
        assert_eq!(signature.len(), key.n.byte_len());
        assert!(key.public_key().verify_pss(&digest, &signature, 16));
        // Wrong salt length must be rejected.
        assert!(!key.public_key().verify_pss(&digest, &signature, 32));
        // A flipped bit must break verification.
        let mut tampered = signature.clone();
        tampered[0] ^= 0x01;
        assert!(!key.public_key().verify_pss(&digest, &tampered, 16));

        // A SHA-512 digest cannot fit a 512-bit modulus; this used to
        // underflow into a multi-gigabyte allocation and abort.
        let oversized = [0x5au8; 64];
        assert!(key.sign_pkcs1v15(&oversized).is_err());
        // Unsupported digest lengths must be rejected, not mis-signed.
        assert!(key.sign_pkcs1v15(&[0x42u8; 17]).is_err());
        assert!(key.sign_pss(&[0x42u8; 31], 8).is_err());
    }
}
