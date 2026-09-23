//! Hash algorithms and HMAC implementations.
//!
//! Provides MD5, SHA-1, SHA-256, SHA-384, SHA-512, and HMAC variants.
//! Used by CNG providers, TLS/SSL, IPsec, and file integrity checks.

extern crate alloc;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    count: u64,
    buffer: [u8; 64],
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: 0,
            buffer: [0; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = (self.count & 63) as usize;
        self.count += data.len() as u64;

        let mut idx = 0;
        if offset > 0 {
            let space = 64 - offset;
            let copy_len = data.len().min(space);
            self.buffer[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
            if offset + copy_len == 64 {
                Self::transform(&mut self.state, &self.buffer);
                offset = 0;
            }
            idx = copy_len;
        }

        while idx + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[idx..idx + 64]);
            Self::transform(&mut self.state, &block);
            idx += 64;
        }

        if idx < data.len() {
            let remain = data.len() - idx;
            self.buffer[..remain].copy_from_slice(&data[idx..]);
        }
    }

    pub fn finalize(&mut self) -> [u8; 16] {
        let bit_count = self.count * 8;
        let offset = (self.count & 63) as usize;

        self.buffer[offset] = 0x80;
        for i in offset + 1..64 {
            self.buffer[i] = 0;
        }

        if offset >= 56 {
            Self::transform(&mut self.state, &self.buffer);
            self.buffer = [0; 64];
        }

        self.buffer[56..64].copy_from_slice(&bit_count.to_le_bytes());
        Self::transform(&mut self.state, &self.buffer);

        let mut output = [0u8; 16];
        for (i, &s) in self.state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&s.to_le_bytes());
        }
        output
    }

    fn transform(state: &mut [u32; 4], block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        macro_rules! f { ($x:expr, $y:expr, $z:expr) => { ($x & $y) | (!$x & $z) }; }
        macro_rules! op {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $t:expr) => {
                $a = $b.wrapping_add(($a.wrapping_add(f!($b, $c, $d)).wrapping_add(x[$k]).wrapping_add($t)).rotate_left($s));
            };
        }

        op!(a, b, c, d, 0, 7, 0xd76aa478); op!(d, a, b, c, 1, 12, 0xe8c7b756);
        op!(c, d, a, b, 2, 17, 0x242070db); op!(b, c, d, a, 3, 22, 0xc1bdceee);
        op!(a, b, c, d, 4, 7, 0xf57c0faf); op!(d, a, b, c, 5, 12, 0x4787c62a);
        op!(c, d, a, b, 6, 17, 0xa8304613); op!(b, c, d, a, 7, 22, 0xfd469501);
        op!(a, b, c, d, 8, 7, 0x698098d8); op!(d, a, b, c, 9, 12, 0x8b44f7af);
        op!(c, d, a, b, 10, 17, 0xffff5bb1); op!(b, c, d, a, 11, 22, 0x895cd7be);
        op!(a, b, c, d, 12, 7, 0x6b901122); op!(d, a, b, c, 13, 12, 0xfd987193);
        op!(c, d, a, b, 14, 17, 0xa679438e); op!(b, c, d, a, 15, 22, 0x49b40821);

        macro_rules! g { ($x:expr, $y:expr, $z:expr) => { ($x & $z) | ($y & !$z) }; }
        macro_rules! op2 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $t:expr) => {
                $a = $b.wrapping_add(($a.wrapping_add(g!($b, $c, $d)).wrapping_add(x[$k]).wrapping_add($t)).rotate_left($s));
            };
        }

        op2!(a, b, c, d, 1, 5, 0xf61e2562); op2!(d, a, b, c, 6, 9, 0xc040b340);
        op2!(c, d, a, b, 11, 14, 0x265e5a51); op2!(b, c, d, a, 0, 20, 0xe9b6c7aa);
        op2!(a, b, c, d, 5, 5, 0xd62f105d); op2!(d, a, b, c, 10, 9, 0x02441453);
        op2!(c, d, a, b, 15, 14, 0xd8a1e681); op2!(b, c, d, a, 4, 20, 0xe7d3fbc8);
        op2!(a, b, c, d, 9, 5, 0x21e1cde6); op2!(d, a, b, c, 14, 9, 0xc33707d6);
        op2!(c, d, a, b, 3, 14, 0xf4d50d87); op2!(b, c, d, a, 8, 20, 0x455a14ed);
        op2!(a, b, c, d, 13, 5, 0xa9e3e905); op2!(d, a, b, c, 2, 9, 0xfcefa3f8);
        op2!(c, d, a, b, 7, 14, 0x676f02d9); op2!(b, c, d, a, 12, 20, 0x8d2a4c8a);

        macro_rules! h { ($x:expr, $y:expr, $z:expr) => { $x ^ $y ^ $z }; }
        macro_rules! op3 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $t:expr) => {
                $a = $b.wrapping_add(($a.wrapping_add(h!($b, $c, $d)).wrapping_add(x[$k]).wrapping_add($t)).rotate_left($s));
            };
        }

        op3!(a, b, c, d, 5, 4, 0xfffa3942); op3!(d, a, b, c, 8, 11, 0x8771f681);
        op3!(c, d, a, b, 11, 16, 0x6d9d6122); op3!(b, c, d, a, 14, 23, 0xfde5380c);
        op3!(a, b, c, d, 1, 4, 0xa4beea44); op3!(d, a, b, c, 4, 11, 0x4bdecfa9);
        op3!(c, d, a, b, 7, 16, 0xf6bb4b60); op3!(b, c, d, a, 10, 23, 0xbebfbc70);
        op3!(a, b, c, d, 13, 4, 0x289b7ec6); op3!(d, a, b, c, 0, 11, 0xeaa127fa);
        op3!(c, d, a, b, 3, 16, 0xd4ef3085); op3!(b, c, d, a, 6, 23, 0x04881d05);
        op3!(a, b, c, d, 9, 4, 0xd9d4d039); op3!(d, a, b, c, 12, 11, 0xe6db99e5);
        op3!(c, d, a, b, 15, 16, 0x1fa27cf8); op3!(b, c, d, a, 2, 23, 0xc4ac5665);

        macro_rules! i { ($x:expr, $y:expr, $z:expr) => { $y ^ ($x | !$z) }; }
        macro_rules! op4 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $t:expr) => {
                $a = $b.wrapping_add(($a.wrapping_add(i!($b, $c, $d)).wrapping_add(x[$k]).wrapping_add($t)).rotate_left($s));
            };
        }

        op4!(a, b, c, d, 0, 6, 0xf4292244); op4!(d, a, b, c, 7, 10, 0x432aff97);
        op4!(c, d, a, b, 14, 15, 0xab9423a7); op4!(b, c, d, a, 5, 21, 0xfc93a039);
        op4!(a, b, c, d, 12, 6, 0x655b59c3); op4!(d, a, b, c, 3, 10, 0x8f0ccc92);
        op4!(c, d, a, b, 10, 15, 0xffeff47d); op4!(b, c, d, a, 1, 21, 0x85845dd1);
        op4!(a, b, c, d, 8, 6, 0x6fa87e4f); op4!(d, a, b, c, 15, 10, 0xfe2ce6e0);
        op4!(c, d, a, b, 6, 15, 0xa3014314); op4!(b, c, d, a, 13, 21, 0x4e0811a1);
        op4!(a, b, c, d, 4, 6, 0xf7537e82); op4!(d, a, b, c, 11, 10, 0xbd3af235);
        op4!(c, d, a, b, 2, 15, 0x2ad7d2bb); op4!(b, c, d, a, 9, 21, 0xeb86d391);

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
}

#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    count: u64,
    buffer: [u8; 64],
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            count: 0,
            buffer: [0; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let offset = (self.count & 63) as usize;
        self.count += data.len() as u64;

        let mut idx = 0;
        if offset > 0 {
            let space = 64 - offset;
            let copy_len = data.len().min(space);
            self.buffer[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
            if offset + copy_len == 64 {
                Self::transform(&mut self.state, &self.buffer);
            }
            idx = copy_len;
        }

        while idx + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[idx..idx + 64]);
            Self::transform(&mut self.state, &block);
            idx += 64;
        }

        if idx < data.len() {
            let remain = data.len() - idx;
            self.buffer[..remain].copy_from_slice(&data[idx..]);
        }
    }

    pub fn finalize(&mut self) -> [u8; 20] {
        let bit_count = self.count * 8;
        let offset = (self.count & 63) as usize;

        self.buffer[offset] = 0x80;
        for i in offset + 1..64 {
            self.buffer[i] = 0;
        }

        if offset >= 56 {
            Self::transform(&mut self.state, &self.buffer);
            self.buffer = [0; 64];
        }

        self.buffer[56..64].copy_from_slice(&bit_count.to_be_bytes());
        Self::transform(&mut self.state, &self.buffer);

        let mut output = [0u8; 20];
        for (i, &s) in self.state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&s.to_be_bytes());
        }
        output
    }

    fn transform(state: &mut [u32; 5], block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
}

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            count: 0,
            buffer: [0; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let offset = (self.count & 63) as usize;
        self.count += data.len() as u64;

        let mut idx = 0;
        if offset > 0 {
            let space = 64 - offset;
            let copy_len = data.len().min(space);
            self.buffer[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
            if offset + copy_len == 64 {
                Self::transform(&mut self.state, &self.buffer);
            }
            idx = copy_len;
        }

        while idx + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[idx..idx + 64]);
            Self::transform(&mut self.state, &block);
            idx += 64;
        }

        if idx < data.len() {
            let remain = data.len() - idx;
            self.buffer[..remain].copy_from_slice(&data[idx..]);
        }
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        let bit_count = self.count * 8;
        let offset = (self.count & 63) as usize;

        self.buffer[offset] = 0x80;
        for i in offset + 1..64 {
            self.buffer[i] = 0;
        }

        if offset >= 56 {
            Self::transform(&mut self.state, &self.buffer);
            self.buffer = [0; 64];
        }

        self.buffer[56..64].copy_from_slice(&bit_count.to_be_bytes());
        Self::transform(&mut self.state, &self.buffer);

        let mut output = [0u8; 32];
        for (i, &s) in self.state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&s.to_be_bytes());
        }
        output
    }

    fn transform(state: &mut [u32; 8], block: &[u8; 64]) {
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

        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    count: u128,
    buffer: [u8; 128],
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            ],
            count: 0,
            buffer: [0; 128],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let offset = (self.count & 127) as usize;
        self.count += data.len() as u128;

        let mut idx = 0;
        if offset > 0 {
            let space = 128 - offset;
            let copy_len = data.len().min(space);
            self.buffer[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
            if offset + copy_len == 128 {
                Self::transform(&mut self.state, &self.buffer);
            }
            idx = copy_len;
        }

        while idx + 128 <= data.len() {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[idx..idx + 128]);
            Self::transform(&mut self.state, &block);
            idx += 128;
        }

        if idx < data.len() {
            let remain = data.len() - idx;
            self.buffer[..remain].copy_from_slice(&data[idx..]);
        }
    }

    pub fn finalize(&mut self) -> [u8; 64] {
        let bit_count = self.count * 8;
        let offset = (self.count & 127) as usize;

        self.buffer[offset] = 0x80;
        for i in offset + 1..128 {
            self.buffer[i] = 0;
        }

        if offset >= 112 {
            Self::transform(&mut self.state, &self.buffer);
            self.buffer = [0; 128];
        }

        self.buffer[112..128].copy_from_slice(&bit_count.to_be_bytes());
        Self::transform(&mut self.state, &self.buffer);

        let mut output = [0u8; 64];
        for (i, &s) in self.state.iter().enumerate() {
            output[i * 8..(i + 1) * 8].copy_from_slice(&s.to_be_bytes());
        }
        output
    }

    fn transform(state: &mut [u64; 8], block: &[u8; 128]) {
        const K: [u64; 80] = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
        ];

        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8], block[i * 8 + 1], block[i * 8 + 2], block[i * 8 + 3],
                block[i * 8 + 4], block[i * 8 + 5], block[i * 8 + 6], block[i * 8 + 7],
            ]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

pub struct Sha384 {
    inner: Sha512,
}

impl Sha384 {
    pub fn new() -> Self {
        let mut inner = Sha512::new();
        inner.state = [
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
            0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
        ];
        Self { inner }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(&mut self) -> [u8; 48] {
        let full = self.inner.finalize();
        let mut output = [0u8; 48];
        output.copy_from_slice(&full[..48]);
        output
    }
}

pub struct Hmac<H> {
    hasher: H,
    outer_hasher: H,
}

impl Hmac<Sha256> {
    pub fn new_sha256(key: &[u8]) -> Self {
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];

        let key_to_use = if key.len() > 64 {
            let mut h = Sha256::new();
            h.update(key);
            let digest = h.finalize();
            for i in 0..32 {
                ipad[i] ^= digest[i];
                opad[i] ^= digest[i];
            }
            digest.to_vec()
        } else {
            for i in 0..key.len() {
                ipad[i] ^= key[i];
                opad[i] ^= key[i];
            }
            key.to_vec()
        };

        let mut inner = Sha256::new();
        inner.update(&ipad);

        let mut outer = Sha256::new();
        outer.update(&opad);

        Self {
            hasher: inner,
            outer_hasher: outer,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        let inner_hash = self.hasher.finalize();
        self.outer_hasher.update(&inner_hash);
        self.outer_hasher.finalize()
    }
}

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize()
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}
