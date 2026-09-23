//! NTFS Encryption Support (EFS)
//!
//! Implements NTFS Encrypting File System (EFS) support.
//! EFS provides file-level encryption using symmetric keys encrypted
//! with user certificates.
//!
//! ## Architecture
//!
//! - Files encrypted with a File Encryption Key (FEK)
//! - FEK encrypted with user's public key
//! - $EFS alternate data stream stores encrypted FEK
//! - DDF (Data Decryption Field) and DRF (Data Recovery Field)

use alloc::vec::Vec;
use alloc::vec;

pub const EFS_VERSION: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EncryptionAlgorithm {
    Des = 0x6601,
    TripleDes = 0x6603,
    Aes128 = 0x660E,
    Aes256 = 0x6610,
}

#[repr(C)]
pub struct EfsDataDecryptionField {
    pub length: u32,
    pub entry_count: u32,
}

#[repr(C)]
pub struct EfsDataRecoveryField {
    pub length: u32,
    pub entry_count: u32,
}

pub struct EfsKeyEntry {
    pub length: u32,
    pub sid_length: u32,
    pub sid: Vec<u8>,
    pub encrypted_fek: Vec<u8>,
}

#[repr(C)]
pub struct EfsStreamHeader {
    pub version: u32,
    pub algorithm: u32,
    pub ddf_offset: u32,
    pub drf_offset: u32,
}

pub fn is_encrypted(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
    (attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0
}

pub fn parse_efs_stream(stream_data: &[u8]) -> Result<(EfsStreamHeader, Vec<EfsKeyEntry>), ()> {
    if stream_data.len() < core::mem::size_of::<EfsStreamHeader>() {
        return Err(());
    }

    let header = unsafe {
        core::ptr::read_unaligned(stream_data.as_ptr() as *const EfsStreamHeader)
    };

    if header.version != EFS_VERSION {
        return Err(());
    }

    let mut entries = Vec::new();

    if header.ddf_offset > 0 && (header.ddf_offset as usize) < stream_data.len() {
        let ddf_data = &stream_data[header.ddf_offset as usize..];
        entries.extend(parse_key_entries(ddf_data)?);
    }

    Ok((header, entries))
}

fn parse_key_entries(data: &[u8]) -> Result<Vec<EfsKeyEntry>, ()> {
    if data.len() < 8 {
        return Err(());
    }

    let entry_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut entries = Vec::new();
    let mut offset = 8usize;

    for _ in 0..entry_count {
        if offset + 8 > data.len() {
            break;
        }

        let length = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let sid_length = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);

        let entry_start = offset + 8;
        let sid_end = entry_start + sid_length as usize;

        if sid_end > data.len() {
            break;
        }

        let sid = data[entry_start..sid_end].to_vec();
        let fek_start = sid_end;
        let fek_end = offset + length as usize;

        if fek_end > data.len() {
            break;
        }

        let encrypted_fek = data[fek_start..fek_end].to_vec();

        entries.push(EfsKeyEntry {
            length,
            sid_length,
            sid,
            encrypted_fek,
        });

        offset = fek_end;
    }

    Ok(entries)
}

/// Encrypt file data (simplified - actual EFS uses crypto APIs)
pub fn encrypt_file_data(data: &[u8], _fek: &[u8]) -> Result<Vec<u8>, ()> {
    // 1. Generate or use provided FEK

    let mut encrypted = Vec::with_capacity(data.len());
    for (i, &byte) in data.iter().enumerate() {
        encrypted.push(byte ^ ((i % 256) as u8));
    }
    Ok(encrypted)
}

pub fn decrypt_file_data(encrypted_data: &[u8], _fek: &[u8]) -> Result<Vec<u8>, ()> {
    encrypt_file_data(encrypted_data, _fek)
}

pub fn generate_fek() -> Vec<u8> {
    // In a real implementation, use crypto RNG
    vec![0x42; 32] // Placeholder 256-bit key
}

/// Encrypt FEK with user's public key
pub fn encrypt_fek_with_public_key(fek: &[u8], _public_key: &[u8]) -> Result<Vec<u8>, ()> {
    // In a real implementation, use RSA/ECC
    Ok(fek.to_vec())
}

/// Decrypt FEK with user's private key
pub fn decrypt_fek_with_private_key(encrypted_fek: &[u8], _private_key: &[u8]) -> Result<Vec<u8>, ()> {
    // In a real implementation, use RSA/ECC
    Ok(encrypted_fek.to_vec())
}

pub fn create_efs_stream(
    fek: &[u8],
    user_sid: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, ()> {
    let encrypted_fek = encrypt_fek_with_public_key(fek, public_key)?;

    let mut stream = Vec::new();

    let header = EfsStreamHeader {
        version: EFS_VERSION,
        algorithm: EncryptionAlgorithm::Aes256 as u32,
        ddf_offset: core::mem::size_of::<EfsStreamHeader>() as u32,
        drf_offset: 0, // No recovery field in this simplified version
    };

    stream.extend_from_slice(&header.version.to_le_bytes());
    stream.extend_from_slice(&header.algorithm.to_le_bytes());
    stream.extend_from_slice(&header.ddf_offset.to_le_bytes());
    stream.extend_from_slice(&header.drf_offset.to_le_bytes());

    let ddf_length = 8 + 8 + user_sid.len() + encrypted_fek.len();
    stream.extend_from_slice(&(ddf_length as u32).to_le_bytes());
    stream.extend_from_slice(&1u32.to_le_bytes()); // entry_count = 1

    let entry_length = 8 + user_sid.len() + encrypted_fek.len();
    stream.extend_from_slice(&(entry_length as u32).to_le_bytes());
    stream.extend_from_slice(&(user_sid.len() as u32).to_le_bytes());
    stream.extend_from_slice(user_sid);
    stream.extend_from_slice(&encrypted_fek);

    Ok(stream)
}
