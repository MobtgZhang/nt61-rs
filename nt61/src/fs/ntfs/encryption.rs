//! NTFS Encrypting File System (EFS) support.
//!
//! File data is protected with AES-256-CBC using a randomly generated
//! File Encryption Key (FEK). The FEK is wrapped with the user's RSA
//! public key and stored in the $EFS ($LOGGED_UTILITY_STREAM) attribute
//! alongside a Data Decryption Field (DDF) and Data Recovery Field (DRF).

use crate::crypto::cipher::Cbc;
use crate::crypto::csprng;
use crate::crypto::rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use alloc::vec;
use alloc::vec::Vec;

/// EFS stream version, matching Windows NT 6.1 (MS-EFSR 2.2).
pub const EFS_VERSION: u32 = 3;

/// Size of the EFS stream header in bytes.
pub const EFS_STREAM_HEADER_SIZE: usize = 16;

/// Size of a DDF/DRF field header in bytes.
pub const EFS_FIELD_HEADER_SIZE: usize = 8;

/// Size of a key entry header in bytes.
pub const EFS_KEY_ENTRY_HEADER_SIZE: usize = 8;

/// FEK length for AES-256 (bytes).
pub const FEK_LENGTH_AES256: usize = 32;

/// CBC initialisation vector length (bytes).
pub const CBC_IV_LENGTH: usize = 16;

/// FILE_ATTRIBUTE_ENCRYPTED bit from the Win32 attribute set.
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;

/// $LOGGED_UTILITY_STREAM attribute type for $EFS.
pub const ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM: u32 = 0x100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EncryptionAlgorithm {
    Des = 0x6601,
    TripleDes = 0x6603,
    Aes128 = 0x660E,
    Aes256 = 0x6610,
}

#[derive(Debug, Clone, Copy)]
pub struct EfsStreamHeader {
    pub version: u32,
    pub algorithm: u32,
    pub ddf_offset: u32,
    pub drf_offset: u32,
}

impl EfsStreamHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EFS_STREAM_HEADER_SIZE);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.algorithm.to_le_bytes());
        out.extend_from_slice(&self.ddf_offset.to_le_bytes());
        out.extend_from_slice(&self.drf_offset.to_le_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ()> {
        if data.len() < EFS_STREAM_HEADER_SIZE {
            return Err(());
        }
        Ok(Self {
            version: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            algorithm: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            ddf_offset: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            drf_offset: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EfsKeyEntry {
    pub length: u32,
    pub sid_length: u32,
    pub sid: Vec<u8>,
    pub encrypted_fek: Vec<u8>,
}

pub fn is_encrypted(attributes: u32) -> bool {
    (attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0
}

pub fn parse_efs_stream(stream_data: &[u8]) -> Result<(EfsStreamHeader, Vec<EfsKeyEntry>), ()> {
    let header = EfsStreamHeader::from_bytes(stream_data)?;
    if header.version != EFS_VERSION {
        return Err(());
    }
    let mut entries = Vec::new();
    if header.ddf_offset > 0 {
        let ddf_start = header.ddf_offset as usize;
        if ddf_start < stream_data.len() {
            let ddf_data = &stream_data[ddf_start..];
            entries.extend(parse_key_entries(ddf_data)?);
        }
    }
    Ok((header, entries))
}

fn parse_key_entries(data: &[u8]) -> Result<Vec<EfsKeyEntry>, ()> {
    if data.len() < EFS_FIELD_HEADER_SIZE {
        return Err(());
    }
    let entry_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut entries = Vec::new();
    let mut offset = EFS_FIELD_HEADER_SIZE;
    for _ in 0..entry_count {
        if offset + EFS_KEY_ENTRY_HEADER_SIZE > data.len() {
            break;
        }
        let length = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let sid_length = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let entry_start = offset + EFS_KEY_ENTRY_HEADER_SIZE;
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

pub fn encrypt_file_data(data: &[u8], fek: &[u8]) -> Result<Vec<u8>, ()> {
    if fek.len() != FEK_LENGTH_AES256 {
        return Err(());
    }
    let mut iv = [0u8; CBC_IV_LENGTH];
    if !csprng::fill(&mut iv) {
        return Err(());
    }
    let pad_len = CBC_IV_LENGTH - (data.len() % CBC_IV_LENGTH);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    for _ in 0..pad_len {
        padded.push(pad_len as u8);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(fek);
    let mut cbc = Cbc::new_aes256(&key, &iv);
    let ciphertext = cbc.encrypt(&padded);
    let mut output = Vec::with_capacity(CBC_IV_LENGTH + ciphertext.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt_file_data(encrypted_data: &[u8], fek: &[u8]) -> Result<Vec<u8>, ()> {
    if fek.len() != FEK_LENGTH_AES256 {
        return Err(());
    }
    if encrypted_data.len() < CBC_IV_LENGTH {
        return Err(());
    }
    let mut iv = [0u8; CBC_IV_LENGTH];
    iv.copy_from_slice(&encrypted_data[..CBC_IV_LENGTH]);
    let ciphertext = &encrypted_data[CBC_IV_LENGTH..];
    let mut key = [0u8; 32];
    key.copy_from_slice(fek);
    let mut cbc = Cbc::new_aes256(&key, &iv);
    let padded = cbc.decrypt(ciphertext);
    if padded.is_empty() {
        return Err(());
    }
    let pad_len = *padded.last().unwrap() as usize;
    if pad_len == 0 || pad_len > CBC_IV_LENGTH || pad_len > padded.len() {
        return Err(());
    }
    Ok(padded[..padded.len() - pad_len].to_vec())
}

pub fn generate_fek() -> Vec<u8> {
    let mut key = vec![0u8; FEK_LENGTH_AES256];
    let _ = csprng::fill(&mut key);
    key
}

/// Wrap the FEK with the user's RSA public key.
///
/// \`public_key\` is the little-endian \`(modulus || exponent)\` RSA key
/// blob produced by \`rsa_public_key_bytes\`. PKCS#1 v1.5 padding is
/// applied by the RSA layer, so the wrapped FEK is indistinguishable from
/// random data to anyone without the private key.
pub fn encrypt_fek_with_public_key(fek: &[u8], public_key: &[u8]) -> Result<Vec<u8>, ()> {
    let key = parse_rsa_public_key(public_key)?;
    Ok(key.encrypt(fek))
}

/// Unwrap the FEK with the owner's RSA private key.
///
/// \`private_key\` is the little-endian \`(modulus || exponent || d)\`
/// blob produced by \`rsa_private_key_bytes\`; the modulus length must
/// match the public key used for wrapping.
pub fn decrypt_fek_with_private_key(
    encrypted_fek: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, ()> {
    let key = parse_rsa_private_key(private_key)?;
    Ok(key.decrypt(encrypted_fek))
}

/// Serialise an RSA public key as \`(modulus || exponent)\` for the EFS
/// key blob. Little-endian numbers with 4-byte length prefixes.
pub fn rsa_public_key_bytes(key: &RsaPublicKey) -> Vec<u8> {
    rsa_component_blob(&[&key.n, &key.e])
}

/// Serialise the full RSA private key (modulus, exponent, private
/// exponent and the CRT parameters the decrypt path needs) for local
/// FEK recovery. Little-endian numbers with 4-byte length prefixes.
pub fn rsa_private_key_bytes(key: &RsaPrivateKey) -> Vec<u8> {
    rsa_component_blob(&[
        &key.n, &key.e, &key.d, &key.p, &key.q, &key.dp, &key.dq, &key.qi,
    ])
}

/// Encode big-endian numbers as a 4-byte-length-prefixed blob.
fn rsa_component_blob(components: &[&BigUint]) -> Vec<u8> {
    let mut out = Vec::new();
    for component in components {
        let bytes = component.to_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

/// Decode a blob produced by \`rsa_component_blob\`.
fn parse_rsa_components(blob: &[u8], component_count: usize) -> Result<Vec<BigUint>, ()> {
    let mut components = Vec::with_capacity(component_count);
    let mut offset = 0usize;
    for _ in 0..component_count {
        if blob.len() < offset + 4 {
            return Err(());
        }
        let length = u32::from_le_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as usize;
        offset += 4;
        if blob.len() < offset + length {
            return Err(());
        }
        components.push(BigUint::from_bytes(&blob[offset..offset + length]));
        offset += length;
    }
    Ok(components)
}

/// Parse an \`(modulus || exponent)\` blob produced by
/// \`rsa_public_key_bytes\`.
fn parse_rsa_public_key(blob: &[u8]) -> Result<RsaPublicKey, ()> {
    let components = parse_rsa_components(blob, 2)?;
    Ok(RsaPublicKey {
        n: components[0].clone(),
        e: components[1].clone(),
    })
}

/// Parse the full private-key blob produced by
/// \`rsa_private_key_bytes\` (n, e, d, p, q, dp, dq, qi).
fn parse_rsa_private_key(blob: &[u8]) -> Result<RsaPrivateKey, ()> {
    let components = parse_rsa_components(blob, 8)?;
    Ok(RsaPrivateKey {
        n: components[0].clone(),
        e: components[1].clone(),
        d: components[2].clone(),
        p: components[3].clone(),
        q: components[4].clone(),
        dp: components[5].clone(),
        dq: components[6].clone(),
        qi: components[7].clone(),
    })
}

pub fn create_efs_stream(fek: &[u8], user_sid: &[u8], public_key: &[u8]) -> Result<Vec<u8>, ()> {
    let encrypted_fek = encrypt_fek_with_public_key(fek, public_key)?;
    let entry_length = EFS_KEY_ENTRY_HEADER_SIZE + user_sid.len() + encrypted_fek.len();
    let mut entry = Vec::with_capacity(entry_length);
    entry.extend_from_slice(&(entry_length as u32).to_le_bytes());
    entry.extend_from_slice(&(user_sid.len() as u32).to_le_bytes());
    entry.extend_from_slice(user_sid);
    entry.extend_from_slice(&encrypted_fek);
    let ddf_length = EFS_FIELD_HEADER_SIZE + entry.len();
    let mut ddf = Vec::with_capacity(ddf_length);
    ddf.extend_from_slice(&(ddf_length as u32).to_le_bytes());
    ddf.extend_from_slice(&1u32.to_le_bytes());
    ddf.extend_from_slice(&entry);
    let drf_length = EFS_FIELD_HEADER_SIZE;
    let mut drf = Vec::with_capacity(drf_length);
    drf.extend_from_slice(&(drf_length as u32).to_le_bytes());
    drf.extend_from_slice(&0u32.to_le_bytes());
    let ddf_offset = EFS_STREAM_HEADER_SIZE as u32;
    let drf_offset = ddf_offset + ddf_length as u32;
    let header = EfsStreamHeader {
        version: EFS_VERSION,
        algorithm: EncryptionAlgorithm::Aes256 as u32,
        ddf_offset,
        drf_offset,
    };
    let mut stream = Vec::with_capacity(EFS_STREAM_HEADER_SIZE + ddf.len() + drf.len());
    stream.extend_from_slice(&header.to_bytes());
    stream.extend_from_slice(&ddf);
    stream.extend_from_slice(&drf);
    Ok(stream)
}
