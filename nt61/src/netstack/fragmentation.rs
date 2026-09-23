//! IP Packet Fragmentation and Reassembly
//!
//! Implements IPv4 fragmentation and reassembly per RFC 791 and RFC 815.
//! Windows 7 supports:
//! - Fragmentation of outgoing packets exceeding MTU
//! - Reassembly of incoming fragmented packets
//! - Fragment timeout and cleanup
//! - Overlapping fragment handling
//!
//! Clean-room implementation based on RFC 791, RFC 815, RFC 1858.

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use alloc::vec;
use alloc::collections::BTreeMap;

const MAX_FRAGMENTS_PER_PACKET: usize = 64;

const FRAGMENT_TIMEOUT_MS: u64 = 60_000;

const MAX_REASSEMBLY_BUFFERS: usize = 32;

#[derive(Debug, Clone)]
struct Fragment {
    offset: usize,
    data: Vec<u8>,
    timestamp: u64,
}

#[derive(Debug)]
struct ReassemblyBuffer {
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    identification: u16,
    fragments: BTreeMap<usize, Fragment>,
    total_length: Option<usize>,
    first_arrival: u64,
}

impl ReassemblyBuffer {
    fn new(src_ip: u32, dst_ip: u32, protocol: u8, identification: u16) -> Self {
        Self {
            src_ip,
            dst_ip,
            protocol,
            identification,
            fragments: BTreeMap::new(),
            total_length: None,
            first_arrival: crate::hal::common::pit::get_system_time_ms() as u64,
        }
    }

    fn add_fragment(&mut self, offset: usize, data: Vec<u8>, is_last: bool) -> bool {
        if self.fragments.len() >= MAX_FRAGMENTS_PER_PACKET {
            return false;
        }

        let timestamp = crate::hal::common::pit::get_system_time_ms() as u64;

        if is_last {
            self.total_length = Some(offset + data.len());
        }

        self.fragments.insert(
            offset,
            Fragment {
                offset,
                data,
                timestamp,
            },
        );

        true
    }

    fn is_complete(&self) -> bool {
        let Some(total_len) = self.total_length else {
            return false;
        };

        let mut covered = 0;
        for (offset, frag) in &self.fragments {
            if *offset > covered {
                return false; // Gap in coverage
            }
            covered = covered.max(offset + frag.data.len());
        }

        covered >= total_len
    }

    fn reassemble(&self) -> Option<Vec<u8>> {
        let total_len = self.total_length?;
        let mut result = vec![0u8; total_len];

        for (offset, frag) in &self.fragments {
            let end = (*offset + frag.data.len()).min(total_len);
            result[*offset..end].copy_from_slice(&frag.data[..end - offset]);
        }

        Some(result)
    }

    fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.first_arrival) > FRAGMENT_TIMEOUT_MS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ReassemblyKey {
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    identification: u16,
}

static REASSEMBLY_BUFFERS: Spinlock<BTreeMap<ReassemblyKey, ReassemblyBuffer>> =
    Spinlock::new(BTreeMap::new());

#[derive(Debug, Clone, Copy)]
pub struct FragmentStats {
    pub fragments_created: u64,
    pub fragments_received: u64,
    pub reassembled: u64,
    pub reassembly_timeouts: u64,
    pub reassembly_failures: u64,
}

impl FragmentStats {
    pub const fn new() -> Self {
        Self {
            fragments_created: 0,
            fragments_received: 0,
            reassembled: 0,
            reassembly_timeouts: 0,
            reassembly_failures: 0,
        }
    }
}

static FRAGMENT_STATS: Spinlock<FragmentStats> = Spinlock::new(FragmentStats::new());

pub fn init() {
    REASSEMBLY_BUFFERS.lock().clear();
    *FRAGMENT_STATS.lock() = FragmentStats::new();
}

pub fn fragment_packet(
    payload: &[u8],
    mtu: usize,
    identification: u16,
) -> Vec<Vec<u8>> {
    let ip_header_size = 20; // Minimum IPv4 header size
    let max_fragment_size = ((mtu - ip_header_size) / 8) * 8; // Must be multiple of 8

    if payload.len() <= mtu - ip_header_size {
        return vec![payload.to_vec()];
    }

    let mut fragments = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let remaining = payload.len() - offset;
        let fragment_size = remaining.min(max_fragment_size);
        let is_last = offset + fragment_size >= payload.len();

        let fragment = payload[offset..offset + fragment_size].to_vec();
        fragments.push(fragment);

        offset += fragment_size;

        let mut stats = FRAGMENT_STATS.lock();
        stats.fragments_created += 1;
    }

    fragments
}

pub fn process_fragment(
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    identification: u16,
    offset: u16,
    more_fragments: bool,
    data: Vec<u8>,
) -> Option<Vec<u8>> {
    let key = ReassemblyKey {
        src_ip,
        dst_ip,
        protocol,
        identification,
    };

    let byte_offset = (offset as usize) * 8;

    let mut buffers = REASSEMBLY_BUFFERS.lock();
    let mut stats = FRAGMENT_STATS.lock();

    stats.fragments_received += 1;

    if buffers.len() >= MAX_REASSEMBLY_BUFFERS {
        cleanup_expired_buffers(&mut buffers, &mut stats);
    }

    let buffer = buffers
        .entry(key)
        .or_insert_with(|| ReassemblyBuffer::new(src_ip, dst_ip, protocol, identification));

    let is_last = !more_fragments;
    if !buffer.add_fragment(byte_offset, data, is_last) {
        stats.reassembly_failures += 1;
        buffers.remove(&key);
        return None;
    }

    if buffer.is_complete() {
        let result = buffer.reassemble();
        buffers.remove(&key);
        if result.is_some() {
            stats.reassembled += 1;
        }
        result
    } else {
        None
    }
}

fn cleanup_expired_buffers(
    buffers: &mut BTreeMap<ReassemblyKey, ReassemblyBuffer>,
    stats: &mut FragmentStats,
) {
    let now = crate::hal::common::pit::get_system_time_ms() as u64;
    let expired: Vec<ReassemblyKey> = buffers
        .iter()
        .filter(|(_, buf)| buf.is_expired(now))
        .map(|(key, _)| *key)
        .collect();

    for key in expired {
        buffers.remove(&key);
        stats.reassembly_timeouts += 1;
    }
}

pub fn cleanup() {
    let mut buffers = REASSEMBLY_BUFFERS.lock();
    let mut stats = FRAGMENT_STATS.lock();
    cleanup_expired_buffers(&mut buffers, &mut stats);
}

pub fn get_stats() -> FragmentStats {
    *FRAGMENT_STATS.lock()
}

pub fn active_reassembly_count() -> usize {
    REASSEMBLY_BUFFERS.lock().len()
}
