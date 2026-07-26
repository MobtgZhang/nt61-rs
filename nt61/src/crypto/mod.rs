//! Cryptography subsystem
//!
//! Hosts the kernel CSPRNG (`csprng`) and future CNG/CryptoAPI
//! providers. The current surface is intentionally minimal —
//! enough to back `RtlGenRandom` / `SystemFunction036` reliably
//! for OpenSSH's first-look CSPRNG use.

pub mod csprng;
