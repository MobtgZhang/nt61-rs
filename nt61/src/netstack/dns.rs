//! Minimal DNS Resolver
//!
//! Implements a tiny DNS client used by getaddrinfo / iphlpapi to
//! translate host names into IPv4 (and IPv6 if requested) addresses.
//!
//! Design constraints:
//!   - No recursion, no NS/SOA chasing — purely A/AAAA queries
//!     sent to a configured DNS server (typically the DHCP-supplied
//!     10.0.2.3 in QEMU user-net).
//!   - Plain UDP, no TCP fallback (avoids waiting for the TCP
//!     layer to grow overlapped I/O before we can resolve a host).
//!   - Caches every answer until TTL expires.
//!   - Recognises IPv4 literal strings ("10.0.2.2", "127.0.0.1")
//!     without sending a query, so loopback paths do not need a
//!     DNS server.
//!   - AF_INET6 requests always fail with a deterministic error
//!     rather than a fake success; OpenSSH only needs AF_INET for
//!     the first cut.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::netstack::udp;
use crate::netstack::ipv4;
use crate::netstack::ipif;
use crate::ke::sync::Spinlock;

/// Default DNS server port.
pub const DNS_PORT: u16 = 53;

/// Maximum cached entries.
const MAX_CACHE: usize = 64;

/// Maximum IPv4 literal length we are willing to parse.
const MAX_LITERAL_LEN: usize = 64;

/// DNS response / error codes we surface to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// Configured DNS server did not respond in time.
    Timeout,
    /// Server responded but the answer was malformed.
    Format,
    /// Server responded with NXDOMAIN / no records of the
    /// requested type.
    NotFound,
    /// Caller asked for AF_INET6; not supported yet.
    AddrFamilyNotSupported,
    /// Other failure (socket open, etc.).
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsRecord {
    pub addr: u32,
    /// Absolute expiry in PIT milliseconds.
    pub expires_at_ms: u64,
}

static CACHE: Spinlock<BTreeMap<(String, u16), DnsRecord>> =
    Spinlock::new(BTreeMap::new());

/// Currently configured DNS server (set by DHCP or by a static
/// configuration helper). Stored in host byte order for cheap
/// `==` comparisons.
static DNS_SERVER: Spinlock<u32> = Spinlock::new(0);

/// Counter used to label outstanding queries without global state.
static QUERY_ID: AtomicU32 = AtomicU32::new(0);

/// Set the DNS server used for non-literal lookups.
pub fn set_dns_server(server_ip: u32) {
    *DNS_SERVER.lock() = server_ip;
    crate::boot_println!("[DNS] server set to {}.{}.{}.{}",
        (server_ip >> 24) & 0xFF, (server_ip >> 16) & 0xFF,
        (server_ip >> 8) & 0xFF, server_ip & 0xFF);
}

/// Return the configured DNS server (0 if unset).
pub fn get_dns_server() -> u32 {
    *DNS_SERVER.lock()
}

/// Encode a single DNS label. Returns the wire bytes including the
/// length prefix byte. Throws away trailing nul so the caller can
/// append the terminating 0 byte after every label.
fn encode_label(out: &mut Vec<u8>, label: &str) {
    let bytes = label.as_bytes();
    // RFC 1035 caps labels at 63 bytes.
    let take = bytes.len().min(63);
    out.push(take as u8);
    out.extend_from_slice(&bytes[..take]);
}

/// Build a DNS query for `name` (e.g. "github.com") and `qtype`
/// (1 = A, 28 = AAAA). Returns the on-wire datagram.
fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    let id = (QUERY_ID.fetch_add(1, Ordering::Relaxed) as u16).wrapping_add(1);
    out.extend_from_slice(&id.to_be_bytes());
    // Standard query, recursion desired.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    // QDCOUNT=1, ANCOUNT/NSCOUNT/ARCOUNT=0.
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        encode_label(&mut out, label);
    }
    out.push(0); // root label
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN class
    out
}

/// Skip one DNS name in a wire-format response, returning the new
/// offset. Handles both uncompressed labels and the 0xC0 pointer
/// form (RFC 1035 §4.1.4).
fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
    if off >= buf.len() {
        return None;
    }
    // Bound the loop to avoid malformed-pointer DoS.
    for _ in 0..32 {
        let len = buf[off];
        if len == 0 {
            return Some(off + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer; consumes 2 bytes total and we
            // do not need to follow it because we only want the
            // offset of the *next* field after the name.
            return Some(off + 2);
        }
        // Sanity-cap label length.
        if (len & 0xC0) != 0 || len as usize > buf.len().saturating_sub(off + 1) {
            return None;
        }
        off += 1 + len as usize;
        if off >= buf.len() {
            return None;
        }
    }
    None
}

/// Parse a DNS response packet looking for an A record matching
/// `qtype` and `qname`. Returns the first matching IPv4 address
/// in network byte order, or None.
fn parse_response(buf: &[u8], qtype: u16) -> Option<u32> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let mut off = 12;

    // Skip the question section.
    for _ in 0..qdcount {
        off = skip_name(buf, off)?;
        off += 4; // QTYPE + QCLASS
        if off > buf.len() {
            return None;
        }
    }

    // Walk the answer section.
    for _ in 0..ancount {
        off = skip_name(buf, off)?;
        if off + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let _rclass = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        let _ttl = u32::from_be_bytes([buf[off + 4], buf[off + 5],
                                       buf[off + 6], buf[off + 7]]);
        let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
        off += 10;
        if off + rdlen > buf.len() {
            return None;
        }
        if rtype == qtype && rdlen == 4 && qtype == 1 {
            let ip = u32::from_be_bytes([buf[off], buf[off + 1],
                                         buf[off + 2], buf[off + 3]]);
            return Some(ip);
        }
        off += rdlen;
    }
    None
}

/// Look up `name`. Returns the IPv4 address (network byte order)
/// or a `DnsError`. IPv6 queries always return
/// `AddrFamilyNotSupported`.
pub fn resolve(name: &str) -> Result<u32, DnsError> {
    resolve_af(name, 2 /* AF_INET */)
}

pub fn resolve_af(name: &str, family: u16) -> Result<u32, DnsError> {
    if family != 2 {
        return Err(DnsError::AddrFamilyNotSupported);
    }

    // Try IPv4 literal first — avoids any UDP traffic for
    // addresses like "127.0.0.1".
    if let Some(ip) = parse_ipv4_literal(name) {
        return Ok(ip);
    }

    // Cache hit?
    let key = (name.to_string(), family);
    {
        let cache = CACHE.lock();
        if let Some(rec) = cache.get(&key) {
            let now = crate::hal::common::pit::get_system_time_ms() as u64;
            if rec.expires_at_ms > now {
                return Ok(rec.addr);
            }
        }
    }

    let server = *DNS_SERVER.lock();
    if server == 0 {
        return Err(DnsError::Other);
    }

    let server_port = DNS_PORT;
    let local_port = 0; // kernel-assigned ephemeral
    let local_ip = ipif::get_our_ip_addresses()
        .first()
        .copied()
        .unwrap_or(0);
    let sock = udp::create_socket(local_port, local_ip)
        .ok_or(DnsError::Other)?;
    let qtype: u16 = 1; // A
    let datagram = build_query(name, qtype);
    udp::send(sock, server, server_port, &datagram)
        .ok_or(DnsError::Other)?;

    // Block up to 2 seconds for a reply.
    let deadline = crate::hal::common::pit::get_system_time_ms() as u64 + 2000;
    let mut buf = [0u8; 512];
    loop {
        let now = crate::hal::common::pit::get_system_time_ms() as u64;
        if now >= deadline {
            udp::close_socket(sock);
            return Err(DnsError::Timeout);
        }
        if let Some((src_ip, src_port, n)) = udp::receive(sock, &mut buf) {
            if src_ip == server && src_port == server_port && n >= 12 {
                if let Some(ip) = parse_response(&buf[..n], qtype) {
                    udp::close_socket(sock);
                    cache_insert(name, family, ip, 60_000);
                    return Ok(ip);
                }
                udp::close_socket(sock);
                return Err(DnsError::Format);
            }
        }
        // Spin-yield: PIT-driven kernel doesn't have a generic
        // sleep yet, so do a small busy wait and re-check.
        for _ in 0..10_000 {
            core::hint::spin_loop();
        }
    }
}

/// Insert a record into the cache, evicting the oldest entry if
/// we are at capacity.
fn cache_insert(name: &str, family: u16, addr: u32, ttl_ms: u64) {
    let expires_at_ms = crate::hal::common::pit::get_system_time_ms() as u64 + ttl_ms;
    let mut cache = CACHE.lock();
    if cache.len() >= MAX_CACHE {
        // Drop the entry with the earliest expiry.
        if let Some((k, _)) = cache.iter().min_by_key(|(_, v)| v.expires_at_ms).map(|(k, v)| (k.clone(), v.expires_at_ms)) {
            cache.remove(&k);
        }
    }
    cache.insert((name.to_string(), family), DnsRecord { addr, expires_at_ms });
}

/// Parse an IPv4 dotted-quad string. Used as a fast path so that
/// "10.0.2.2" never has to hit the resolver.
pub fn parse_ipv4_literal(s: &str) -> Option<u32> {
    if s.len() > MAX_LITERAL_LEN {
        return None;
    }
    let mut parts = s.split('.');
    let mut ip: u32 = 0;
    for i in 0..4 {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        let n: u32 = part.parse().ok()?;
        if n > 255 {
            return None;
        }
        ip |= n << (8 * (3 - i));
    }
    if parts.next().is_some() {
        return None;
    }
    Some(ip)
}

/// Drop all cached entries. Used by DHCP on lease renew/rebind so
/// stale records do not outlive a server change.
pub fn flush_cache() {
    CACHE.lock().clear();
}

/// Format an IPv4 address as "a.b.c.d" for log messages.
pub fn ip_to_string(mut ip: u32) -> String {
    let mut s = String::with_capacity(15);
    for _ in 0..3 {
        let octet = ip & 0xFF;
        s.push_str(&alloc::format!("{}.", octet));
        ip >>= 8;
    }
    s.push_str(&alloc::format!("{}", ip & 0xFF));
    s
}

/// Convenience wrapper that honours `getaddrinfo`'s address-family
/// flag.
pub fn getaddrinfo(host: &str, family: u16) -> Result<u32, DnsError> {
    resolve_af(host, family)
}

// Silence dead-code warnings when the resolver is wired in but
// not yet called by anything in this commit.
#[allow(dead_code)]
fn _suppress_unused_warnings() -> (ipv4::Protocol, u32) {
    (ipv4::Protocol::Udp, DNS_PORT as u32)
}
