//! Cryptography subsystem - Using audited standard libraries
//!
//! This module provides cryptographic functionality using well-tested
//! and audited external libraries instead of custom implementations.
//!
//! **SECURITY NOTE**: Previous custom implementations have been replaced
//! with industry-standard libraries to eliminate cryptographic vulnerabilities.
//!
//! Libraries used:
//! - `sha2` - SHA-256, SHA-384, SHA-512 from RustCrypto
//! - `aes` - AES encryption from RustCrypto
//! - `rsa` - RSA from RustCrypto
//! - `rand_core` - Cryptographic random number generation
//!
//! For kernel CSPRNG, see the `csprng` module which provides
//! `RtlGenRandom` / `SystemFunction036` for system services.

pub mod csprng;      // Kernel CSPRNG (using hardware RNG)
pub mod hash;        // Hash functions (SHA-2 family)
pub mod cipher;      // Symmetric encryption (AES)
pub mod rsa_secure;  // RSA operations (using audited library)
pub mod bcrypt;      // CNG API compatibility layer
pub mod legacy;      // Legacy CryptoAPI compatibility

// Re-export commonly used types
pub use hash::{sha256, sha512};
pub use cipher::{aes_encrypt, aes_decrypt};
pub use csprng::fill_random_bytes;

/// Initialize cryptography subsystem
///
/// Must be called during kernel initialization to set up
/// hardware random number generators and crypto providers.
pub fn init() {
    csprng::init();
    // Additional crypto initialization
}
