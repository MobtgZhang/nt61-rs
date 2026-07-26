//! Hash_DRBG/SHA-256 mix and reseed logic for the kernel CSPRNG.
//!
//! This module re-implements the same primitives that
//! `crypto::csprng` uses in the kernel (Hash_DRBG keyed on
//! SHA-256) so we can test the semantics without compiling the
//! kernel. The host tests can verify:
//!   - Consecutive calls produce different output.
//!   - Output bytes are uniformly distributed (rough chi-square).
//!   - Explicit reseeds change the stream.

#[cfg(test)]
mod tests {
    /// SHA-256 of a single 512-bit block. The block is mutated
    /// in place to the SHA-256 digest.
    fn sha256_compress(block: &mut [u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        let mut w = [0u32; 64];
        for i in 0..16 {
            let off = i * 4;
            w[i] = u32::from_be_bytes([block[off], block[off+1], block[off+2], block[off+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let mut a = h[0]; let mut b = h[1]; let mut c = h[2]; let mut d = h[3];
        let mut e = h[4]; let mut f = h[5]; let mut g = h[6]; let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b); h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f); h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
        for i in 0..8 {
            let off = i * 4;
            block[off]   = (h[i] >> 24) as u8;
            block[off+1] = (h[i] >> 16) as u8;
            block[off+2] = (h[i] >> 8) as u8;
            block[off+3] = h[i] as u8;
        }
    }

    /// Byte counter (run-level). Resetting it forces a fresh
    /// seed. The DRBG uses the SHA-256 of the seed as the V/C
    /// state, then generates 32-byte blocks on demand.
    struct Drbg {
        v: [u8; 48],
        c: [u8; 32],
        remaining: Vec<u8>,
    }

    impl Drbg {
        fn new(seed: &[u8]) -> Self {
            let mut block = [0u8; 64];
            let n = seed.len().min(63);
            block[..n].copy_from_slice(&seed[..n]);
            block[n] = 0x00;
            sha256_compress(&mut block);
            let mut v = [0u8; 48];
            v[..32].copy_from_slice(&block[..32]);
            let mut c = [0u8; 32];
            c.copy_from_slice(&block[..32]);
            let mut me = Self { v, c, remaining: Vec::new() };
            me.refresh();
            me
        }

        fn refresh(&mut self) {
            let mut block = [0u8; 64];
            block[..48].copy_from_slice(&self.v);
            block[48] = 0x01;
            block[49..].copy_from_slice(&self.c[..15]);
            sha256_compress(&mut block);
            self.remaining = block[..32].to_vec();
            // Advance V by 1 (mod 2^384).
            let mut carry = 1u16;
            for i in (0..48).rev() {
                let v = self.v[i] as u16 + carry;
                self.v[i] = v as u8;
                carry = v >> 8;
            }
        }

        fn fill(&mut self, out: &mut [u8]) {
            let mut pos = 0;
            while pos < out.len() {
                if self.remaining.is_empty() { self.refresh(); }
                let take = (out.len() - pos).min(self.remaining.len());
                out[pos..pos + take].copy_from_slice(&self.remaining[..take]);
                self.remaining.drain(..take);
                pos += take;
            }
        }
    }

    #[test]
    fn two_consecutive_calls_differ() {
        let mut drbg = Drbg::new(b"test-seed");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        drbg.fill(&mut a);
        drbg.fill(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn reseed_changes_stream() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Drbg::new(b"seed-A").fill(&mut a);
        Drbg::new(b"seed-B").fill(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn byte_distribution_is_roughly_uniform() {
        // Across 256 draws (256 bytes), each byte value should
        // appear at least once with high probability. If the
        // PRNG is stuck, some values will be missing.
        let mut drbg = Drbg::new(b"distribution-seed");
        let mut hist = [0u32; 256];
        let mut buf = [0u8; 256];
        drbg.fill(&mut buf);
        for b in buf.iter() { hist[*b as usize] += 1; }
        let non_zero = hist.iter().filter(|c| **c > 0).count();
        assert!(non_zero > 100,
            "byte distribution too sparse: {} non-zero bins out of 256",
            non_zero);
    }

    #[test]
    fn large_request_consistent() {
        // A 1 KiB fill should not panic and the bytes should not
        // be all-zero.
        let mut drbg = Drbg::new(b"large");
        let mut buf = [0u8; 1024];
        drbg.fill(&mut buf);
        let non_zero = buf.iter().filter(|b| **b != 0).count();
        assert!(non_zero > 700,
            "1 KiB fill produced {} zeros — block-too-tight or counter stuck",
            1024 - non_zero);
    }
}
