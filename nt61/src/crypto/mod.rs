//! Cryptography subsystem
//!
//! Hosts the kernel CSPRNG (`csprng`) and the CNG/CryptoAPI providers
//! that build on it. Everything declared here is part of the compiled
//! crate — previously only `csprng` was hooked, so the rest of the
//! subsystem was dead code that CI never type-checked.

pub mod bcrypt;
pub mod cipher;
pub mod csprng;
pub mod hash;
pub mod legacy;
pub mod prng;
pub mod rsa;

// RustCrypto-backed variants. They are opt-in because they pull in
// external crates; the pure-Rust implementations above are what the
// kernel actually links against on a default build.
#[cfg(feature = "crypto_libs")]
pub mod cipher_new;
#[cfg(feature = "crypto_libs")]
pub mod hash_new;
#[cfg(feature = "crypto_libs")]
pub mod rsa_secure;

/// Initialize the cryptography subsystem: seed the CSPRNG from the
/// hardware RNG (RDSEED, then RDRAND) before any provider is used.
pub fn init() {
    csprng::init();
}
