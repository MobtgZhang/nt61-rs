//! NTFS Compression Support
//!
//! Implements NTFS file and directory compression using LZNT1 algorithm.
//! NTFS compression works at the cluster level with 4KB compression units.
//!
//! ## Compression Algorithm
//!
//! NTFS uses LZNT1 (LZ77 variant) compression:
//! - Compression units are 16 clusters (64KB for 4KB clusters)
//! - Each unit compressed independently
//! - Sparse compression units stored as holes
//! - Uncompressed data stored when compression doesn't help
use crate::libs::ntdll::{status::STATUS_UNSUCCESSFUL, types::NTSTATUS};

use alloc::vec;
use alloc::vec::Vec;

#[repr(C)]
pub struct CompressionBlockHeader {
    pub header: u16,
}

impl CompressionBlockHeader {
    pub fn is_compressed(&self) -> bool {
        (self.header & 0x8000) != 0
    }

    pub fn block_size(&self) -> usize {
        ((self.header & 0x0FFF) + 1) as usize
    }
}

pub const COMPRESSION_UNIT_SIZE: usize = 65536;

pub const COMPRESSION_BLOCK_SIZE: usize = 4096;

pub fn decompress_lznt1(compressed: &[u8], decompressed: &mut [u8]) -> Result<usize, NTSTATUS> {
    let mut src_pos = 0;
    let mut dst_pos = 0;

    while src_pos < compressed.len() && dst_pos < decompressed.len() {
        if src_pos + 2 > compressed.len() {
            break;
        }

        let header = u16::from_le_bytes([compressed[src_pos], compressed[src_pos + 1]]);
        src_pos += 2;

        if header == 0 {
            break; // End of compressed data
        }

        let block_compressed = (header & 0x8000) != 0;
        let block_size = ((header & 0x0FFF) + 1) as usize;

        if !block_compressed {
            let copy_size = core::cmp::min(block_size, decompressed.len() - dst_pos);
            let copy_size = core::cmp::min(copy_size, compressed.len() - src_pos);
            decompressed[dst_pos..dst_pos + copy_size]
                .copy_from_slice(&compressed[src_pos..src_pos + copy_size]);
            src_pos += copy_size;
            dst_pos += copy_size;
        } else {
            let block_end = src_pos + block_size;
            while src_pos < block_end && dst_pos < decompressed.len() {
                if src_pos >= compressed.len() {
                    break;
                }

                let tag = compressed[src_pos];
                src_pos += 1;

                for bit in 0..8 {
                    if src_pos >= block_end || dst_pos >= decompressed.len() {
                        break;
                    }

                    if (tag & (1 << bit)) == 0 {
                        if src_pos >= compressed.len() {
                            break;
                        }
                        decompressed[dst_pos] = compressed[src_pos];
                        src_pos += 1;
                        dst_pos += 1;
                    } else {
                        if src_pos + 1 >= compressed.len() {
                            break;
                        }

                        let token =
                            u16::from_le_bytes([compressed[src_pos], compressed[src_pos + 1]]);
                        src_pos += 2;

                        let length = ((token >> 12) & 0x0F) as usize + 3;
                        let distance = (token & 0x0FFF) as usize + 1;

                        if distance > dst_pos {
                            return Err(STATUS_UNSUCCESSFUL); // Invalid back reference
                        }

                        let copy_start = dst_pos - distance;
                        for i in 0..length {
                            if dst_pos >= decompressed.len() {
                                break;
                            }
                            decompressed[dst_pos] = decompressed[copy_start + i];
                            dst_pos += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(dst_pos)
}

pub fn compress_lznt1(data: &[u8], compressed: &mut [u8]) -> Result<usize, NTSTATUS> {
    let mut src_pos = 0;
    let mut dst_pos = 0;

    while src_pos < data.len() {
        let block_size = core::cmp::min(COMPRESSION_BLOCK_SIZE, data.len() - src_pos);
        let block_data = &data[src_pos..src_pos + block_size];

        let mut temp_compressed = Vec::with_capacity(block_size + 16);
        let compressed_size = compress_block(block_data, &mut temp_compressed)?;

        if compressed_size < block_size {
            if dst_pos + 2 + compressed_size > compressed.len() {
                return Err(STATUS_UNSUCCESSFUL); // Output buffer too small
            }

            let header = 0x8000 | ((compressed_size - 1) as u16);
            compressed[dst_pos..dst_pos + 2].copy_from_slice(&header.to_le_bytes());
            dst_pos += 2;

            compressed[dst_pos..dst_pos + compressed_size]
                .copy_from_slice(&temp_compressed[..compressed_size]);
            dst_pos += compressed_size;
        } else {
            if dst_pos + 2 + block_size > compressed.len() {
                return Err(STATUS_UNSUCCESSFUL); // Output buffer too small
            }

            let header = (block_size - 1) as u16;
            compressed[dst_pos..dst_pos + 2].copy_from_slice(&header.to_le_bytes());
            dst_pos += 2;

            compressed[dst_pos..dst_pos + block_size].copy_from_slice(block_data);
            dst_pos += block_size;
        }

        src_pos += block_size;
    }

    Ok(dst_pos)
}

fn compress_block(data: &[u8], output: &mut Vec<u8>) -> Result<usize, NTSTATUS> {
    let mut pos = 0;
    output.clear();

    while pos < data.len() {
        let tag_pos = output.len();
        output.push(0);
        let mut tag = 0u8;

        for bit in 0..8 {
            if pos >= data.len() {
                break;
            }

            let (match_distance, match_length) = find_best_match(data, pos);

            if match_length >= 3 {
                tag |= 1 << bit;
                let token = (((match_length - 3) as u16) << 12) | ((match_distance - 1) as u16);
                output.extend_from_slice(&token.to_le_bytes());
                pos += match_length;
            } else {
                output.push(data[pos]);
                pos += 1;
            }
        }

        output[tag_pos] = tag;
    }

    Ok(output.len())
}

fn find_best_match(data: &[u8], pos: usize) -> (usize, usize) {
    let window_start = pos.saturating_sub(4095);
    let mut best_distance = 0;
    let mut best_length = 0;

    for i in window_start..pos {
        let mut length = 0;
        while pos + length < data.len() && data[i + length] == data[pos + length] && length < 18 {
            length += 1;
        }

        if length > best_length {
            best_length = length;
            best_distance = pos - i;
        }
    }

    (best_distance, best_length)
}

pub fn is_compressed(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0800;
    (attributes & FILE_ATTRIBUTE_COMPRESSED) != 0
}

pub fn read_compressed_file(
    compressed_data: &[u8],
    offset: u64,
    length: usize,
    output: &mut [u8],
) -> Result<usize, NTSTATUS> {
    let unit_index = (offset / COMPRESSION_UNIT_SIZE as u64) as usize;
    let unit_offset = (offset % COMPRESSION_UNIT_SIZE as u64) as usize;

    let mut decompressed = vec![0u8; COMPRESSION_UNIT_SIZE];
    let unit_start = unit_index * COMPRESSION_UNIT_SIZE;
    let unit_data = &compressed_data[unit_start..];

    let decompressed_size = decompress_lznt1(unit_data, &mut decompressed)?;

    let copy_start = core::cmp::min(unit_offset, decompressed_size);
    let copy_len = core::cmp::min(length, decompressed_size - copy_start);
    let copy_len = core::cmp::min(copy_len, output.len());

    output[..copy_len].copy_from_slice(&decompressed[copy_start..copy_start + copy_len]);

    Ok(copy_len)
}

pub fn write_compressed_file(
    data: &[u8],
    _offset: u64,
    compressed_output: &mut Vec<u8>,
) -> Result<usize, NTSTATUS> {
    let mut temp = vec![0u8; data.len() * 2]; // Pessimistic size estimate
    let compressed_size = compress_lznt1(data, &mut temp)?;

    compressed_output.clear();
    compressed_output.extend_from_slice(&temp[..compressed_size]);

    Ok(compressed_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lznt1_round_trip() {
        // Repetitive data exercises literal, match and overlap-copy paths.
        let mut data = vec![0u8; COMPRESSION_BLOCK_SIZE];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 7) as u8;
        }

        let mut compressed = vec![0u8; data.len() * 2];
        let compressed_size = compress_lznt1(&data, &mut compressed).expect("compress");
        assert!(
            compressed_size < data.len(),
            "repetitive data must compress"
        );

        let mut out = vec![0u8; data.len()];
        let out_size =
            decompress_lznt1(&compressed[..compressed_size], &mut out).expect("decompress");
        assert_eq!(out_size, data.len());
        assert_eq!(out[..], data[..]);
    }

    #[test]
    fn lznt1_stored_block_round_trip() {
        // Incompressible data must be stored verbatim (header without the
        // compressed bit) and still round-trip.
        let mut data = vec![0u8; COMPRESSION_BLOCK_SIZE];
        let mut state = 0x1234_5678u32;
        for b in data.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (state >> 24) as u8;
        }

        let mut compressed = vec![0u8; data.len() * 2];
        let compressed_size = compress_lznt1(&data, &mut compressed).expect("compress");

        let mut out = vec![0u8; data.len()];
        let out_size =
            decompress_lznt1(&compressed[..compressed_size], &mut out).expect("decompress");
        assert_eq!(out_size, data.len());
        assert_eq!(out[..], data[..]);
    }
}
