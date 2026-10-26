//! AES Symmetric Encryption
//!
//! Provides AES encryption using the audited `aes` crate from RustCrypto.
//!
//! **SECURITY**: This uses constant-time implementations to prevent
//! timing attacks.

extern crate alloc;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use alloc::vec::Vec;

pub const AES_BLOCK_SIZE: usize = 16;

pub const AES_KEY_SIZE: usize = 32;

/// AES-128 key size in bytes.
pub const AES128_KEY_SIZE: usize = 16;

pub fn aes_encrypt_block(
    key: &[u8; AES_KEY_SIZE],
    block: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut data = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut data);
    let mut output = [0u8; AES_BLOCK_SIZE];
    output.copy_from_slice(&data[..]);
    output
}

pub fn aes_decrypt_block(
    key: &[u8; AES_KEY_SIZE],
    block: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut data = *GenericArray::from_slice(block);
    cipher.decrypt_block(&mut data);
    let mut output = [0u8; AES_BLOCK_SIZE];
    output.copy_from_slice(&data[..]);
    output
}

/// Use CBC, CTR, or GCM mode for production use.

pub fn aes_encrypt(key: &[u8; AES_KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if plaintext.len() % AES_BLOCK_SIZE != 0 {
        return Err("Plaintext must be multiple of block size (use padding)");
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    for chunk in plaintext.chunks(AES_BLOCK_SIZE) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }

    Ok(ciphertext)
}

pub fn aes_decrypt(key: &[u8; AES_KEY_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err("Ciphertext must be multiple of block size");
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks(AES_BLOCK_SIZE) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }

    Ok(plaintext)
}

/// AES-128 single block encryption (hardware-backed, constant time).
pub fn aes128_encrypt_block(
    key: &[u8; AES128_KEY_SIZE],
    block: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut data = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut data);
    let mut output = [0u8; AES_BLOCK_SIZE];
    output.copy_from_slice(&data[..]);
    output
}

/// AES-128 single block decryption.
pub fn aes128_decrypt_block(
    key: &[u8; AES128_KEY_SIZE],
    block: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut data = *GenericArray::from_slice(block);
    cipher.decrypt_block(&mut data);
    let mut output = [0u8; AES_BLOCK_SIZE];
    output.copy_from_slice(&data[..]);
    output
}

/// AES-128 multi-block ECB. ECB gives no message protection: callers
/// who need confidentiality across blocks must use a proper mode. The
/// input must already be block aligned and padding is the caller's
/// decision, so a short tail is an explicit error rather than silent
/// zero-padding.
pub fn aes128_encrypt(
    key: &[u8; AES128_KEY_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if plaintext.len() % AES_BLOCK_SIZE != 0 {
        return Err("Plaintext must be multiple of block size (use padding)");
    }

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    for chunk in plaintext.chunks(AES_BLOCK_SIZE) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }

    Ok(ciphertext)
}

/// AES-128 multi-block ECB decryption; rejects misaligned input.
pub fn aes128_decrypt(
    key: &[u8; AES128_KEY_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err("Ciphertext must be multiple of block size");
    }

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks(AES_BLOCK_SIZE) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_aes_encrypt_decrypt_block() {
        let key = [0x42u8; AES_KEY_SIZE];
        let plaintext = [0x13u8; AES_BLOCK_SIZE];

        let ciphertext = aes_encrypt_block(&key, &plaintext);
        let decrypted = aes_decrypt_block(&key, &ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = [0x42u8; AES_KEY_SIZE];
        let plaintext = vec![0x13u8; AES_BLOCK_SIZE * 3]; // 3 blocks

        let ciphertext = aes_encrypt(&key, &plaintext).unwrap();
        let decrypted = aes_decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
