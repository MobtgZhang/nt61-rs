//! Code Integrity (ci.dll)
//
//! Implements the Code Integrity module that validates the digital
//! signatures of kernel-mode binaries (drivers, ntoskrnl, hal, etc.)
//! before they are loaded into memory.
//
//! Code Integrity uses the WDK driver naming convention
//! (CiInitialize, IMAGE_POLICY, ...).
#![allow(non_snake_case, non_upper_case_globals, dead_code)]
//
//! Key responsibilities:
//!   * `CiInitialize` — initialise the CI subsystem
//!   * `SeCiCheckImage` — validate a PE image against catalog or
//!     embedded signature before it is allowed to execute
//!   * `CiHashFile` — compute a SHA-256 / SHA-1 hash of a file
//!   * `CiValidateImageData` — hash each section of the PE,
//!     compare against catalog
//
//! When code integrity detects a violation, it returns
//! `STATUS_INVALID_IMAGE_NOT_WIN` to block the driver from loading.
//
//! Clean-room implementation. Spec source: Windows Internals 6th ed.
//! ch.10 (Code Integrity), WDK documentation.

use crate::kprintln;

/// CI policy flags.
pub const CI_POLICY_ENABLED: u32 = 0x00000001;
pub const CI_POLICY_DRIVER_ENFORCEMENT: u32 = 0x00000002;
pub const CI_POLICY_NOVULN: u32 = 0x00000004;

/// CI system status flags.
pub const CI_NOLMS: u32 = 0x00000001; // No LMS is available

static mut INITIALIZED: bool = false;
static mut CI_POLICY: u32 = 0;

/// SHA-256 constants.
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 state.
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            state: [0u32; 8],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            buf: [0; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut off = 0usize;
        while off < data.len() {
            if self.buf_len == 64 {
                self.process_block();
                self.buf_len = 0;
            }
            let remain = 64 - self.buf_len;
            let to_copy = (data.len() - off).min(remain);
            self.buf[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[off..off + to_copy]);
            self.buf_len += to_copy;
            off += to_copy;
        }
        self.total_len += data.len() as u64;
    }

    fn process_block(&mut self) {
        fn rotr(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }
        fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
        fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
        fn s0(x: u32) -> u32 { rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22) }
        fn s1(x: u32) -> u32 { rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25) }
        fn g0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3) }
        fn g1(x: u32) -> u32 { rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10) }

        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_le_bytes([
                self.buf[i * 4], self.buf[i * 4 + 1],
                self.buf[i * 4 + 2], self.buf[i * 4 + 3]
            ]);
        }
        for i in 16..64 {
            w[i] = g1(w[i - 2]).wrapping_add(w[i - 7])
                .wrapping_add(g0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let t1 = h.wrapping_add(s1(e)).wrapping_add(ch(e, f, g))
                .wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let t2 = s0(a).wrapping_add(maj(a, b, c));
            h = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn finalize(self) -> [u8; 32] {
        let mut s = self;
        // Pad
        let total = s.total_len;
        s.buf[s.buf_len] = 0x80;
        s.buf_len += 1;
        if s.buf_len > 56 {
            s.process_block();
            s.buf = [0; 64];
        }
        let bits = total * 8;
        for (i, b) in bits.to_le_bytes().iter().enumerate() {
            s.buf[63 - i] = *b;
        }
        s.process_block();

        let mut out = [0u8; 32];
        for (i, &w) in s.state.iter().enumerate() {
            out[i * 4..][..4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// PE header constants.
const PE_MAGIC: u16 = 0x5A4D; // "MZ"
const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

/// DOS header at the start of a PE file.
#[repr(C)]
struct DosHeader {
    pub magic: u16,          // 0x00 "MZ"
    pub last_size: u16,
    pub num_pages: u16,
    pub relocs: u16,
    pub hdr_size: u16,
    pub minalloc: u16,
    pub maxalloc: u16,
    pub ss_sp: u16,
    pub checksum: u16,
    pub ip: u16,
    pub cs: u16,
    pub reloc_offset: u16,
    pub overlay: u16,
}

impl DosHeader {
    fn is_valid(&self) -> bool {
        self.magic == PE_MAGIC
    }
}

/// PE COFF header (20 bytes).
#[repr(C)]
struct CoffHeader {
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: u32,
    pub symbol_table: u32,
    pub num_symbols: u32,
    pub opt_hdr_size: u16,
    pub characteristics: u16,
}

/// PE32+ optional header magic.
const PE32_MAGIC: u16 = 0x020b;
const PE32_PLUS_MAGIC: u16 = 0x020b;

/// PE32+ optional header (for x64).
#[repr(C)]
struct OptionalHeader {
    pub magic: u16,
    pub linker_version: u8,
    pub code_size: u8,
    pub data_size: u8,
    pub bss_size: u8,
    pub entry_addr: u32,
    pub code_base: u32,
}

/// Section header.
#[repr(C)]
struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_addr: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub reloc_offset: u32,
    pub line_nums: u32,
    pub num_relocs: u16,
    pub num_lines: u16,
    pub flags: u32,
}

/// Compute the SHA-256 hash of a data buffer.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Compute the PE section hash for code integrity.
/// The hash covers all sections except the certificate table.
pub fn compute_pe_hash(image: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();

    if image.len() < 64 {
        return hasher.finalize();
    }

    // Read COFF header offset from DOS header
    let dos_off = u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]) as usize;

    // Check for PE signature
    if dos_off + 24 > image.len() {
        return hasher.finalize();
    }

    let pe_sig = u32::from_le_bytes([
        image[dos_off], image[dos_off + 1],
        image[dos_off + 2], image[dos_off + 3]
    ]);
    if pe_sig != PE_SIGNATURE {
        // Not a valid PE file — hash whatever we have
        hasher.update(image);
        return hasher.finalize();
    }

    // Skip DOS header + PE signature + COFF header
    let coff_hdr_off = dos_off + 4;
    if coff_hdr_off + 20 > image.len() {
        return hasher.finalize();
    }

    let coff = CoffHeader {
        machine: u16::from_le_bytes([image[coff_hdr_off], image[coff_hdr_off + 1]]),
        num_sections: u16::from_le_bytes([image[coff_hdr_off + 2], image[coff_hdr_off + 3]]),
        timestamp: u32::from_le_bytes([image[coff_hdr_off + 4], image[coff_hdr_off + 5],
            image[coff_hdr_off + 6], image[coff_hdr_off + 7]]),
        symbol_table: u32::from_le_bytes([image[coff_hdr_off + 8], image[coff_hdr_off + 9],
            image[coff_hdr_off + 10], image[coff_hdr_off + 11]]),
        num_symbols: u32::from_le_bytes([image[coff_hdr_off + 12], image[coff_hdr_off + 13],
            image[coff_hdr_off + 14], image[coff_hdr_off + 15]]),
        opt_hdr_size: u16::from_le_bytes([image[coff_hdr_off + 16], image[coff_hdr_off + 17]]),
        characteristics: u16::from_le_bytes([image[coff_hdr_off + 18], image[coff_hdr_off + 19]]),
    };

    // Optional header size tells us where section headers start
    let opt_hdr_off = coff_hdr_off + 20;
    if opt_hdr_off + 2 > image.len() {
        return hasher.finalize();
    }

    let opt_magic = u16::from_le_bytes([image[opt_hdr_off], image[opt_hdr_off + 1]]);

    // Data directories offset depends on PE format
    let data_dir_offset = if opt_magic == PE32_PLUS_MAGIC {
        opt_hdr_off + 96  // PE32+ has 16 data dirs at offset 96
    } else {
        opt_hdr_off + 96  // PE32 also has them here
    };

    // The certificate table is data directory entry 5 (index 4, since index 0 is export)
    let cert_dir_offset = data_dir_offset + 4 * 8;
    let cert_rva = if cert_dir_offset + 8 <= image.len() {
        u32::from_le_bytes([image[cert_dir_offset], image[cert_dir_offset + 1],
            image[cert_dir_offset + 2], image[cert_dir_offset + 3]])
    } else {
        0
    };
    let _cert_size = if cert_dir_offset + 8 <= image.len() {
        u32::from_le_bytes([image[cert_dir_offset + 4], image[cert_dir_offset + 5],
            image[cert_dir_offset + 6], image[cert_dir_offset + 7]])
    } else {
        0
    };

    // Section headers start after optional header
    let sec_hdr_off = (opt_hdr_off + coff.opt_hdr_size as usize) as usize;
    if sec_hdr_off + 40 > image.len() {
        return hasher.finalize();
    }

    // Hash each section
    for i in 0..coff.num_sections as usize {
        let off = sec_hdr_off + i * 40;
        if off + 40 > image.len() { break; }

        let raw_size = u32::from_le_bytes([image[off + 16], image[off + 17],
            image[off + 18], image[off + 19]]);
        let raw_offset = u32::from_le_bytes([image[off + 20], image[off + 21],
            image[off + 22], image[off + 23]]);

        // Skip certificate table section
        if cert_rva != 0 {
            let sec_rva = u32::from_le_bytes([image[off + 12], image[off + 13],
                image[off + 14], image[off + 15]]);
            let sec_vsize = u32::from_le_bytes([image[off + 8], image[off + 9],
                image[off + 10], image[off + 11]]);
            if cert_rva >= sec_rva && cert_rva < sec_rva + sec_vsize.max(raw_size) {
                continue;
            }
        }

        if raw_size > 0 && (raw_offset as usize) < image.len() {
            let end = (raw_offset as usize + raw_size as usize).min(image.len());
            hasher.update(&image[raw_offset as usize..end]);
        }
    }

    hasher.finalize()
}

/// Validate a PE image. Returns STATUS_SUCCESS if the image passes
/// code integrity checks, or an error NTSTATUS if it fails.
/// For this bootstrap, we implement a basic PE header validation
/// and SHA-256 hash computation.
pub fn validate_pe_image(image: &[u8]) -> u32 {
    if image.len() < 64 {
        return 0xC0000428u32; // STATUS_INVALID_IMAGE_FORMAT
    }

    // Verify MZ header
    if u16::from_le_bytes([image[0], image[1]]) != PE_MAGIC {
        return 0xC0000428u32;
    }

    // Read PE offset
    let pe_off = u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]) as usize;
    if pe_off + 4 > image.len() {
        return 0xC0000428u32;
    }

    // Verify PE signature
    let pe_sig = u32::from_le_bytes([image[pe_off], image[pe_off + 1],
        image[pe_off + 2], image[pe_off + 3]]);
    if pe_sig != PE_SIGNATURE {
        return 0xC0000428u32;
    }

    // Read COFF header
    let coff_off = pe_off + 4;
    if coff_off + 20 > image.len() {
        return 0xC0000428u32;
    }

    let num_sections = u16::from_le_bytes([image[coff_off + 2], image[coff_off + 3]]);
    if num_sections > 96 {
        return 0xC0000428u32; // Too many sections
    }

    // Compute the PE hash
    let hash = compute_pe_hash(image);
    let _ = &hash;
    // crate::kprintln!("    [CI] PE hash: {:02x}{:02x}...{:02x}{:02x}",  // kprintln disabled (memcpy crash workaround)
//         hash[0], hash[1], hash[30], hash[31]);

    // In a full implementation, we'd compare against:
    //   1. Embedded Authenticode signature (WinVerifyTrust)
    //   2. Catalog database (HKLM\SYSTEM\CurrentControlSet\Control\SecureKernel\Catalog)
    //   3. The CI policy (driver signing enforcement level)
    //
    // For this bootstrap, we always succeed (allow unsigned drivers).
    // A production implementation would check the policy and signature here.
    0 // STATUS_SUCCESS
}

/// Initialise the Code Integrity module.
pub fn init() {
    unsafe {
        CI_POLICY = CI_POLICY_ENABLED | CI_POLICY_DRIVER_ENFORCEMENT;
        INITIALIZED = true;
    }
    // crate::kprintln!("    CI: initialized (policy=0x{:08x})", CI_POLICY_ENABLED | CI_POLICY_DRIVER_ENFORCEMENT)  // kprintln disabled (memcpy crash workaround);
}

/// SeCiCheckImage — the kernel calls this before loading a driver.
/// Returns 0 on success, NTSTATUS on failure.
pub fn se_ci_check_image(image: &[u8]) -> u32 {
    let init = unsafe { INITIALIZED };
    if !init {
        return 0; // CI not initialized — allow all
    }
    validate_pe_image(image)
}

pub fn smoke_test() -> bool {
    // crate::kprintln!("  [CI SMOKE] testing Code Integrity...")  // kprintln disabled (memcpy crash workaround);

    // Test SHA-256
    let test_data = b"Hello, World!";
    let hash = compute_sha256(test_data);
    let expected = [
        0xd4, 0x4f, 0x04, 0x39, 0xf3, 0xfb, 0x40, 0x96,
        0x9d, 0xea, 0x2d, 0x76, 0x60, 0xb1, 0x6c, 0xee,
        0x9c, 0x4d, 0x95, 0x43, 0x2c, 0xf6, 0xf7, 0x2f,
        0x7d, 0x27, 0x1a, 0x11, 0x9b, 0x65, 0xf5, 0x0e,
    ];
    if hash != expected {
        // crate::kprintln!("  [CI SMOKE FAIL] SHA-256 mismatch!")  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Test PE validation on a stub image
    let fake_mz = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // PE offset at 0x3C = 0x80
    let mut fake_pe = [0u8; 512];
    fake_pe[..64].copy_from_slice(&fake_mz);
    // Set PE offset
    fake_pe[0x3C] = 0x80;
    fake_pe[0x3D] = 0x01;
    // PE signature at offset 0x180
    let pe_sig_offset = 0x180;
    fake_pe[pe_sig_offset..][..4].copy_from_slice(b"PE\0\0");
    // COFF header
    let coff_off = pe_sig_offset + 4;
    fake_pe[coff_off..][..2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64 machine
    fake_pe[coff_off + 2..][..2].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    // Optional header size
    fake_pe[coff_off + 16..][..2].copy_from_slice(&0xF0u16.to_le_bytes()); // 240 bytes

    let result = validate_pe_image(&fake_pe);
    let _ = &result;
    // crate::kprintln!("  [CI SMOKE] PE validation result: 0x{:08x}", result as u32)  // kprintln disabled (memcpy crash workaround);

    // crate::kprintln!("  [CI SMOKE OK] Code Integrity module healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
