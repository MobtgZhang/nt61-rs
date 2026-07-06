//! Windows Event Log (EVTX) Binary Format Writer
//
//! Implements the EVTX file format as specified in [MS-EVENTXDR].
//
//! # EVTX File Layout
//
//! ```text
//! +-------------------------+
//! | EVTX Header (512 bytes) |
//! +-------------------------+
//! | Bin Header Collection   |
//! | (one or more chunks)    |
//! +-------------------------+
//! ```

#![allow(dead_code)]

use alloc::vec::Vec;

use super::{EventChannel, EventRecord};

/// EVTX file header size (bytes)
const EVTX_HEADER_SIZE: usize = 512;
/// EVTX chunk size (bytes)
const EVTX_CHUNK_SIZE: usize = 65536;
/// EVTX chunk header size
const EVTX_CHUNK_HEADER_SIZE: usize = 512;

/// CRC32 (IEEE 802.3 polynomial)
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Write the 512-byte EVTX file header
fn write_evtx_header(channel: EventChannel) -> [u8; EVTX_HEADER_SIZE] {
    let mut h = [0u8; EVTX_HEADER_SIZE];
    // Signature "ElfFile\0"
    h[0..8].copy_from_slice(b"ElfFile\0");
    // Major/minor version (1, 1)
    h[8..10].copy_from_slice(&1u16.to_le_bytes());
    h[10..12].copy_from_slice(&1u16.to_le_bytes());
    // Number of header chunks
    h[14..16].copy_from_slice(&1u16.to_le_bytes());
    // First chunk offset
    h[16..20].copy_from_slice(&(EVTX_HEADER_SIZE as u32).to_le_bytes());
    // File size placeholder (will be overwritten later)
    h[20..28].copy_from_slice(&((EVTX_HEADER_SIZE + EVTX_CHUNK_SIZE) as u64).to_le_bytes());
    // File type 0 = normal
    h[36..38].copy_from_slice(&0u16.to_le_bytes());
    // Event log name (UTF-16LE)
    let name_bytes = channel.name();
    for (i, &b) in name_bytes.iter().enumerate() {
        if i >= 126 {
            break;
        }
        let off = 76 + i * 2;
        if off + 2 > EVTX_HEADER_SIZE {
            break;
        }
        let ch = if b == 0 { 0u16 } else { b as u16 };
        h[off..off + 2].copy_from_slice(&ch.to_le_bytes());
    }
    h
}

/// Write a single chunk containing the records (BIN-XML simplified representation)
fn write_chunk(records: &[EventRecord]) -> [u8; EVTX_CHUNK_SIZE] {
    let mut chunk = [0u8; EVTX_CHUNK_SIZE];
    // Chunk signature "ElfChnk\0"
    chunk[0..8].copy_from_slice(b"ElfChnk\0");
    // Chunk file offset (0 since this is the first chunk in the file)
    chunk[8..16].copy_from_slice(&0u64.to_le_bytes());
    // First/last record numbers
    if let Some(first) = records.first() {
        chunk[24..32].copy_from_slice(&first.record_id.to_le_bytes());
    }
    if let Some(last) = records.last() {
        chunk[16..24].copy_from_slice(&last.record_id.to_le_bytes());
    }
    // First record offset within the chunk
    chunk[32..36].copy_from_slice(&(EVTX_CHUNK_HEADER_SIZE as u32).to_le_bytes());
    // Free space offset (initially end of chunk, will be updated)
    chunk[36..40].copy_from_slice(&(EVTX_CHUNK_SIZE as u32).to_le_bytes());

    // Serialize each record as BIN-XML
    let mut data_offset = EVTX_CHUNK_HEADER_SIZE;
    for record in records {
        let body = serialize_record_binxml(record);
        let need = body.len();
        if data_offset + need + 8 > EVTX_CHUNK_SIZE {
            break;
        }
        chunk[data_offset..data_offset + need].copy_from_slice(&body);
        data_offset += need;
    }
    chunk[36..40].copy_from_slice(&(data_offset as u32).to_le_bytes());

    // Mark end-of-records
    let tail_off = data_offset;
    if tail_off + 4 <= EVTX_CHUNK_SIZE {
        chunk[tail_off..tail_off + 4].copy_from_slice(&[0u8; 4]);
    }

    // Last free record offset (0xFFFFFFFF means no free space)
    let last_free_off = 84;
    if last_free_off + 4 <= EVTX_CHUNK_SIZE {
        chunk[last_free_off..last_free_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }

    // Compute CRC32 checksum on the second half of chunk
    let checksum = crc32(&chunk[76..]);
    chunk[40..44].copy_from_slice(&checksum.to_le_bytes());

    chunk
}

/// Serialize one event record as a simplified BIN-XML stream.
/// The real EVTX uses templates; here we emit a flat record structure.
fn serialize_record_binxml(r: &EventRecord) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    // Magic header
    buf.extend_from_slice(&[0x0F, 0x00, 0x00, 0x00]);
    // Channel name
    let channel_name = r.channel.name();
    push_wstr(&mut buf, channel_name);
    // Event ID
    push_u32_le(&mut buf, r.event_id as u32);
    // Level
    push_u8(&mut buf, r.level as u8);
    // Version
    push_u8(&mut buf, r.version);
    // Task
    push_u16_le(&mut buf, r.task);
    // Opcode
    push_u8(&mut buf, 0);
    // Keywords
    push_u64_le(&mut buf, r.keywords.0);
    // Timestamp (FILETIME)
    push_u64_le(&mut buf, r.timestamp);
    // Record ID
    push_u64_le(&mut buf, r.record_id);
    // Source (Provider) name
    push_wstr_bytes(&mut buf, &r.source[..r.source_len as usize]);
    // Computer
    push_wstr_bytes(&mut buf, &r.computer[..r.computer_len as usize]);
    // Event data (UTF-16LE)
    for i in 0..r.event_data_len as usize {
        let cu = r.event_data[i];
        buf.extend_from_slice(&cu.to_le_bytes());
    }
    // Pad to 4-byte boundary
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

fn push_wstr(buf: &mut Vec<u8>, name: &[u8]) {
    let len = name.len();
    buf.extend_from_slice(&(len as u32).to_le_bytes());
    for &b in name {
        buf.push(b);
        buf.push(0);
    }
    buf.extend_from_slice(&[0u8; 2]); // null terminator
}

fn push_wstr_bytes(buf: &mut Vec<u8>, name: &[u8]) {
    push_wstr(buf, name);
}

fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

/// Write complete EVTX file
pub fn write_evtx_file(records: &[EventRecord], channel: EventChannel) -> Vec<u8> {
    let mut file: Vec<u8> = Vec::new();
    let header = write_evtx_header(channel);
    file.extend_from_slice(&header);
    let chunk = write_chunk(records);
    file.extend_from_slice(&chunk);
    // Update header file size
    let total = file.len() as u64;
    file[20..28].copy_from_slice(&total.to_le_bytes());
    // Update header: last record offset and next free record ID
    if let Some(last) = records.last() {
        file[46..54].copy_from_slice(&last.record_id.to_le_bytes());
    }
    file
}

/// Export a single event record to EVTX binary format
pub fn export_single_record(record: &EventRecord, channel: EventChannel) -> Vec<u8> {
    write_evtx_file(core::slice::from_ref(record), channel)
}
