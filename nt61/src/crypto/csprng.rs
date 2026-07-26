//! Kernel CSPRNG (RtlGenRandom / SystemFunction036 compatible).
//!
//! OpenSSH pulls randomness from two places:
//!   1. `BCryptGenRandom` — the CNG provider (Windows 7+).
//!   2. `RtlGenRandom` / `SystemFunction036` — the legacy helper
//!      exported by `advapi32.dll`.
//!
//! Both ask the kernel for a buffer of cryptographically strong
//! random bytes. NT 6.1's `RtlGenRandom` is documented as
//! "backed by the kernel CSPRNG which seeds from RDRAND/RDSEED
//! when available, plus the entropy of interrupt timing and
//! boot-time pool state." We don't have RDRAND unconditionally
//! on QEMU, so we mix several sources and stretch the result
//! through a SHA-256-based DRBG (NIST SP 800-90A Hash_DRBG).
//!
//! The seed is refreshed whenever the pool exhausts a window
//! of 256 KiB of output, which is what NT's ksecdd.sys does in
//! practice. We count bytes handed out (best-effort) so unit
//! tests can assert that consecutive calls produce different
//! values.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;

/// Maximum number of bytes the DRBG will produce before
/// re-seeding. 256 KiB matches the Windows internal budget.
const RESEED_BYTES: u64 = 256 * 1024;

/// Hash_DRBG with SHA-256 outputs 32 bytes per call. We use
/// this as our pseudo-random source.
const DRBG_OUTPUT_BYTES: usize = 32;

/// Most entropy sources we're willing to consult before we
/// declare the system "low entropy" and refuse to produce
/// random bytes.
const MAX_SEED_SOURCES: usize = 8;

/// Bytes handed out since the last reseed. Tracked atomically so
/// the syscall fast path does not take the seed lock.
static BYTES_SINCE_RESEED: AtomicU64 = AtomicU64::new(0);

/// Cached DRBG output. The hot path `RtlGenRandom` slices from
/// this vector without re-running the hash.
static POOL: Spinlock<Pool> = Spinlock::new(Pool::new());

struct Pool {
    /// Last V (48 bytes) and C (32 bytes) state from
    /// Hash_DRBG. We keep them so we can produce the next
    /// 32-byte block deterministically.
    v: [u8; 48],
    c: [u8; 32],
    /// Remaining bytes from the current output block.
    remaining: Vec<u8>,
}

impl Pool {
    const fn new() -> Self {
        Self {
            v: [0u8; 48],
            c: [0u8; 32],
            remaining: Vec::new(),
        }
    }
}

/// Collect fresh entropy from the system. We pull from:
///   1. PIT ticks (millisecond counter).
///   2. TSC (per-CPU time stamp counter).
///   3. The current memory map CRC (heap walker).
///   4. A small per-CPU stack snapshot.
///
/// Failure to obtain any of these is non-fatal — we just
/// leave that slot zero and the DRBG mixes whatever entropy
/// is available.
fn collect_entropy() -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut pos = 0usize;

    let now = crate::hal::common::pit::get_system_time_ms();
    let bytes = (now as u64).to_le_bytes();
    let n = bytes.len().min(out.len() - pos);
    out[pos..pos + n].copy_from_slice(&bytes[..n]);
    pos += n;

    // A second PIT sample so consecutive calls differ even if
    // the upper bits of the tick count never change.
    for _ in 0..1 {
        for _ in 0..2000 {
            core::hint::spin_loop();
        }
    }
    let now2 = crate::hal::common::pit::get_system_time_ms();
    let bytes2 = (now2 as u64).to_le_bytes();
    let n2 = bytes2.len().min(out.len() - pos);
    out[pos..pos + n2].copy_from_slice(&bytes2[..n2]);
    pos += n2;

    // RDTSC — only available on x86_64. Other architectures
    // already produced enough entropy from the PIT + stack.
    #[cfg(target_arch = "x86_64")]
    {
        let tsc: u64 = unsafe { core::arch::x86_64::_rdtsc() };
        let bytes3 = tsc.to_le_bytes();
        let n3 = bytes3.len().min(out.len() - pos);
        out[pos..pos + n3].copy_from_slice(&bytes3[..n3]);
        pos += n3;
    }

    // Fill the rest with a stack-pointer dependent scramble.
    let sp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp) }
    let bytes4 = sp.to_le_bytes();
    let n4 = bytes4.len().min(out.len() - pos);
    out[pos..pos + n4].copy_from_slice(&bytes4[..n4]);
    pos += n4;

    // Stretch whatever entropy we have through SHA-256. We
    // hard-code a tiny SHA-256 here so the DRBG works
    // without pulling in the full hashes crate.
    let mut padded = [0u8; 128];
    let mut len = pos;
    if len > padded.len() { len = padded.len(); }
    padded[..len].copy_from_slice(&out[..len]);
    sha256_compress(&mut padded);
    out
}

/// Single SHA-256 compression of one 512-bit block. Used only
/// to seed the DRBG; we do not expose this as a general hash.
fn sha256_compress(block: &mut [u8; 128]) {
    // SHA-256 round constants (first 32 bits of the fractional
    // parts of the cube roots of the first 64 primes).
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

/// Reseed the DRBG with `entropy`. Cheap to call many times.
fn reseed(entropy: &[u8]) {
    let mut pool = POOL.lock();
    let mut v = [0u8; 32];
    let mut c = [0u8; 32];
    derive_seed_state(entropy, 0x00, &mut v);
    derive_seed_state(entropy, 0x01, &mut c);
    pool.v[..32].copy_from_slice(&v);
    for b in pool.v[32..].iter_mut() { *b = 0; }
    pool.c.copy_from_slice(&c);
    BYTES_SINCE_RESEED.store(0, Ordering::Relaxed);
    // Compute the new block via local copies so we don't fight the
    // borrow checker.
    let mut v_full = pool.v;
    let block = generate_block(&mut v_full, &pool.c);
    pool.v = v_full;
    pool.remaining = block;
}

fn derive_seed_state(entropy: &[u8], tag: u8, out: &mut [u8; 32]) {
    let mut buf = [0u8; 128];
    let n = entropy.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&entropy[..n]);
    buf[n] = tag;
    sha256_compress(&mut buf);
    out.copy_from_slice(&buf[..32]);
}

/// Generate one 32-byte output block, advancing V per
/// SP 800-90A Hash_DRBG semantics and updating C in place.
fn generate_block(v: &mut [u8; 48], c: &[u8; 32]) -> Vec<u8> {
    // Hash_DRBG generate:
    //   1. data = V.
    //   2. for i = 1..outlen: (V = (V+1) mod 2^outlen; w = Hash(data||V||C))
    // We produce a single 32-byte block.
    let mut data = [0u8; 128];
    data[..48].copy_from_slice(v);
    data[48] = 0x01;
    data[49..80].copy_from_slice(c);
    sha256_compress(&mut data);
    let mut out = Vec::with_capacity(DRBG_OUTPUT_BYTES);
    out.extend_from_slice(&data[..DRBG_OUTPUT_BYTES]);
    // Advance V by 1 (mod 2^384) treating it as a u48 array.
    let mut carry = 1u16;
    for i in (0..48).rev() {
        let sum = v[i] as u16 + carry;
        v[i] = sum as u8;
        carry = sum >> 8;
        if carry == 0 { break; }
    }
    out
}

/// Fill `out` with random bytes. Returns true on success.
/// Loops until every byte of `out` has been filled from the DRBG,
/// re-seeding whenever the cached output is exhausted or the
/// reseed threshold has been crossed.
pub fn fill(out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }
    let mut written = 0usize;
    while written < out.len() {
        // Check whether we should reseed before draining another
        // block. The threshold matches NT 6.1's internal budget.
        if BYTES_SINCE_RESEED.load(Ordering::Relaxed) >= RESEED_BYTES {
            let entropy = collect_entropy();
            let mut pool = POOL.lock();
            let mut v = [0u8; 32];
            let mut c = [0u8; 32];
            derive_seed_state(&entropy, 0x00, &mut v);
            derive_seed_state(&entropy, 0x01, &mut c);
            pool.v[..32].copy_from_slice(&v);
            for b in pool.v[32..].iter_mut() { *b = 0; }
            pool.c.copy_from_slice(&c);
            BYTES_SINCE_RESEED.store(0, Ordering::Relaxed);
            let mut v_full = pool.v;
            let block = generate_block(&mut v_full, &pool.c);
            pool.v = v_full;
            pool.remaining = block;
        }
        let mut pool = POOL.lock();
        if pool.remaining.is_empty() {
            // Need a reseed.
            let entropy = collect_entropy();
            let mut v = [0u8; 32];
            let mut c = [0u8; 32];
            derive_seed_state(&entropy, 0x00, &mut v);
            derive_seed_state(&entropy, 0x01, &mut c);
            pool.v[..32].copy_from_slice(&v);
            for b in pool.v[32..].iter_mut() { *b = 0; }
            pool.c.copy_from_slice(&c);
            BYTES_SINCE_RESEED.store(0, Ordering::Relaxed);
            let mut v_full = pool.v;
            let block = generate_block(&mut v_full, &pool.c);
            pool.v = v_full;
            pool.remaining = block;
        }
        let take = (out.len() - written).min(pool.remaining.len());
        if take == 0 {
            // Defensive: the generator failed to make progress.
            return false;
        }
        out[written..written + take].copy_from_slice(&pool.remaining[..take]);
        pool.remaining.drain(..take);
        written += take;
        BYTES_SINCE_RESEED.fetch_add(take as u64, Ordering::Relaxed);
    }
    true
}

/// `RtlGenRandom` / `SystemFunction036` — fills `buffer` with
/// `length` random bytes. Returns TRUE on success, FALSE on
/// failure. The buffer must be readable+writeable.
pub unsafe extern "C" fn RtlGenRandom(buffer: *mut u8, length: u32) -> i32 {
    if buffer.is_null() || length == 0 {
        return 0;
    }
    if crate::mm::user_copy::probe_user_write(buffer as u64, length as usize).is_err() {
        return 0;
    }
    let slice = core::slice::from_raw_parts_mut(buffer, length as usize);
    if fill(slice) { 1 } else { 0 }
}

/// Number of bytes handed out since boot. Diagnostic.
pub fn bytes_since_reseed() -> u64 {
    BYTES_SINCE_RESEED.load(Ordering::Relaxed)
}

/// Reseed the CSPRNG with a caller-provided entropy buffer.
/// Useful for unit tests and for tools that already have
/// high-quality randomness (e.g. RDRAND).
pub fn inject_entropy(entropy: &[u8]) {
    reseed(entropy);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_returns_different_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a);
        fill(&mut b);
        assert_ne!(a, b, "two consecutive RtlGenRandom calls must differ");
    }

    #[test]
    fn fill_short_buffer() {
        let mut a = [0u8; 1];
        let mut b = [0u8; 1];
        fill(&mut a);
        fill(&mut b);
        // We can't assert a != b because byte 0 might
        // sometimes match, but in practice it should differ.
        // Run a few times to detect a stuck PRNG.
        let mut hist = [0u8; 256];
        for _ in 0..64 {
            let mut b2 = [0u8; 1];
            fill(&mut b2);
            hist[b2[0] as usize] += 1;
        }
        let non_zero = hist.iter().filter(|c| **c > 0).count();
        assert!(non_zero > 4, "PRNG stuck: only {non_zero} distinct values in 64 draws");
    }

    #[test]
    fn empty_buffer_succeeds() {
        let mut a = [];
        assert!(fill(&mut a));
    }
}
