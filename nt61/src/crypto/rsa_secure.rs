//! RSA Public Key Cryptography
//!
//! Provides RSA operations using the audited `rsa` crate from RustCrypto.
//!
//! **SECURITY**: Previous custom RSA implementation has been replaced
//! with industry-standard, audited library to eliminate cryptographic
//! vulnerabilities.

extern crate alloc;
use alloc::vec::Vec;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt, Pkcs1v15Sign};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::sha2::Sha256;
use rand_core::OsRng;

pub const RSA_KEY_SIZE: usize = 2048;

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPublicKey;

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
        .map_err(|_| "Failed to generate RSA key")?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_der = private_key.to_pkcs1_der()
        .map_err(|_| "Failed to encode private key")?
        .to_bytes()
        .to_vec();

    let public_der = public_key.to_pkcs1_der()
        .map_err(|_| "Failed to encode public key")?
        .to_vec();

    Ok((private_der, public_der))
}

pub fn sign_data(private_key_der: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    use rsa::pkcs1::DecodeRsaPrivateKey;

    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| "Invalid private key")?;

    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(data);

    Ok(signature.to_bytes().to_vec())
}

pub fn verify_signature(
    public_key_der: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::signature::Signature;

    let public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
        .map_err(|_| "Invalid public key")?;

    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);

    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| "Invalid signature format")?;

    verifying_key.verify(data, &sig)
        .map_err(|_| "Signature verification failed")
}

/// For large data, use hybrid encryption (RSA for key, AES for data)
pub fn encrypt(public_key_der: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {

    let public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
        .map_err(|_| "Invalid public key")?;

    let mut rng = OsRng;
    let ciphertext = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
        .map_err(|_| "Encryption failed")?;

    Ok(ciphertext)
}

pub fn decrypt(private_key_der: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {

    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| "Invalid private key")?;

    let plaintext = private_key.decrypt(Pkcs1v15Encrypt, ciphertext)
        .map_err(|_| "Decryption failed")?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let result = generate_keypair();
        assert!(result.is_ok());

        let (private, public) = result.unwrap();
        assert!(!private.is_empty());
        assert!(!public.is_empty());
    }

    #[test]
    fn test_sign_verify() {
        let (private, public) = generate_keypair().unwrap();
        let data = b"Test message";

        let signature = sign_data(&private, data).unwrap();
        let result = verify_signature(&public, data, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (private, public) = generate_keypair().unwrap();
        let plaintext = b"Secret message";

        let ciphertext = encrypt(&public, plaintext).unwrap();
        let decrypted = decrypt(&private, &ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }
}
