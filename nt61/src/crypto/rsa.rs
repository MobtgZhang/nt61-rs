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
    pub fn generate(bits: usize) -> Self {
        let e = BigUint::from(65537u32); // Standard public exponent

        let prime_bits = bits / 2;
        let p = generate_prime(prime_bits);
        let q = generate_prime(prime_bits);

        let n = p.mul(&q);

        let p_minus_1 = p.sub(&BigUint::from(1u32));
        let q_minus_1 = q.sub(&BigUint::from(1u32));
        let phi = p_minus_1.mul(&q_minus_1);

        let d = e.mod_inverse(&phi);

        let dp = d.mod_op(&p_minus_1);
        let dq = d.mod_op(&q_minus_1);
        let qi = q.mod_inverse(&p);

        Self {
            n,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qi,
        }
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

    pub fn sign_pkcs1v15(&self, digest: &[u8]) -> Vec<u8> {
        let padded = pkcs1v15_sign_pad(digest, self.n.byte_len());
        let m = BigUint::from_bytes(&padded);
        let s = m.mod_exp(&self.d, &self.n);
        s.to_bytes()
    }

    pub fn sign_pss(&self, digest: &[u8], salt_len: usize) -> Vec<u8> {
        let padded = pss_encode(digest, self.n.byte_len(), salt_len);
        let m = BigUint::from_bytes(&padded);
        let s = m.mod_exp(&self.d, &self.n);
        s.to_bytes()
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
        let s = BigUint::from_bytes(signature);
        let m = s.mod_exp(&self.e, &self.n);
        let recovered = m.to_bytes();

        pss_verify(&recovered, digest, self.n.byte_len(), salt_len)
    }
}

fn pkcs1v15_encrypt_pad(data: &[u8], key_len: usize) -> Vec<u8> {
    let mut padded = Vec::with_capacity(key_len);
    padded.push(0x00);
    padded.push(0x02);

    let padding_len = key_len - data.len() - 3;
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

fn pkcs1v15_sign_pad(digest: &[u8], key_len: usize) -> Vec<u8> {
    let mut padded = Vec::with_capacity(key_len);
    padded.push(0x00);
    padded.push(0x01);

    let padding_len = key_len - digest.len() - 3;
    for _ in 0..padding_len {
        padded.push(0xff);
    }

    padded.push(0x00);
    padded.extend_from_slice(digest);
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

    i += 1;
    &recovered[i..] == digest
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

/// PSS encoding (simplified - production would use MGF1).
fn pss_encode(digest: &[u8], key_len: usize, salt_len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; salt_len];
    crate::crypto::csprng::fill(&mut salt);

    let mut m_prime = Vec::new();
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&salt);

    let h = crate::crypto::hash::sha256(&m_prime);

    let mut em = vec![0u8; key_len];
    let db_len = key_len - h.len() - 1;

    em[db_len - salt_len - 1] = 0x01;
    em[db_len - salt_len..db_len].copy_from_slice(&salt);
    em[db_len..db_len + h.len()].copy_from_slice(&h);
    em[key_len - 1] = 0xbc;

    em
}

fn pss_verify(recovered: &[u8], _digest: &[u8], key_len: usize, salt_len: usize) -> bool {
    if recovered.len() != key_len {
        return false;
    }

    if recovered[key_len - 1] != 0xbc {
        return false;
    }

    let db_len = key_len - 32 - 1;

    let expected_salt_start = db_len - salt_len;
    recovered[expected_salt_start - 1] == 0x01
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

fn generate_prime(bits: usize) -> BigUint {
    loop {
        let candidate = generate_random_odd(bits);
        if is_probably_prime(&candidate, 20) {
            return candidate;
        }
    }
}

fn generate_random_odd(bits: usize) -> BigUint {
    let bytes = (bits + 7) / 8;
    let mut data = vec![0u8; bytes];
    crate::crypto::csprng::fill(&mut data);

    data[0] |= 0x80; // Ensure high bit is set
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
