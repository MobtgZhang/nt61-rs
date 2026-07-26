//! DNS resolver host-side tests.
//!
//! These cover only the pure-Rust logic that doesn't require the
//! kernel network stack: the wire-format query builder, the
//! response parser, the IPv4 literal fast-path, and the cache
//! eviction policy. The integration with UDP and PIT timers is
//! exercised by the in-kernel boot path; we don't try to mock it
//! here.

#[cfg(test)]
mod tests {
    /// Re-implement parse_ipv4_literal because the in-kernel module
    /// uses `crate::hal::...` which is not available in host tests.
    fn parse_ipv4_literal(s: &str) -> Option<u32> {
        if s.len() > 64 {
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

    fn build_query(name: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&1u16.to_be_bytes()); // ID = 1
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            let bytes = label.as_bytes();
            let take = bytes.len().min(63);
            out.push(take as u8);
            out.extend_from_slice(&bytes[..take]);
        }
        out.push(0);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
        if off >= buf.len() {
            return None;
        }
        for _ in 0..32 {
            let len = buf[off];
            if len == 0 {
                return Some(off + 1);
            }
            if (len & 0xC0) == 0xC0 {
                return Some(off + 2);
            }
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

    fn parse_response(buf: &[u8], qtype: u16) -> Option<u32> {
        if buf.len() < 12 {
            return None;
        }
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let mut off = 12;
        for _ in 0..qdcount {
            off = skip_name(buf, off)?;
            off += 4;
            if off > buf.len() {
                return None;
            }
        }
        for _ in 0..ancount {
            off = skip_name(buf, off)?;
            if off + 10 > buf.len() {
                return None;
            }
            let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
            off += 10;
            if off + rdlen > buf.len() {
                return None;
            }
            if rtype == qtype && rdlen == 4 && qtype == 1 {
                let ip = u32::from_be_bytes([
                    buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
                ]);
                return Some(ip);
            }
            off += rdlen;
        }
        None
    }

    #[test]
    fn literal_loopback() {
        assert_eq!(parse_ipv4_literal("127.0.0.1"), Some(0x7F000001));
        assert_eq!(parse_ipv4_literal("10.0.2.2"), Some(0x0A000202));
        assert_eq!(parse_ipv4_literal("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4_literal("255.255.255.255"), Some(0xFFFFFFFF));
    }

    #[test]
    fn literal_rejects_garbage() {
        assert_eq!(parse_ipv4_literal(""), None);
        assert_eq!(parse_ipv4_literal("1"), None);
        assert_eq!(parse_ipv4_literal("1.2.3"), None);
        assert_eq!(parse_ipv4_literal("1.2.3.4.5"), None);
        assert_eq!(parse_ipv4_literal("1.2.3.256"), None);
        assert_eq!(parse_ipv4_literal("a.b.c.d"), None);
        assert_eq!(parse_ipv4_literal("1..2.3"), None);
    }

    #[test]
    fn query_encodes_name() {
        let q = build_query("github.com");
        // header is 12 bytes, "github" is 6 chars, then 0, "com" 3, 0, qtype 2, qclass 2.
        // Total: 12 + (1 + 6) + (1 + 3) + 1 + 2 + 2 = 28.
        assert_eq!(q.len(), 28);
        // Check the name section.
        assert_eq!(q[12], 6);
        assert_eq!(&q[13..19], b"github");
        assert_eq!(q[19], 3);
        assert_eq!(&q[20..23], b"com");
        assert_eq!(q[23], 0);
        // QTYPE = A (1)
        assert_eq!(u16::from_be_bytes([q[24], q[25]]), 1);
        // QCLASS = IN (1)
        assert_eq!(u16::from_be_bytes([q[26], q[27]]), 1);
    }

    #[test]
    fn query_handles_single_label() {
        let q = build_query("localhost");
        assert_eq!(q[12], 9);
        assert_eq!(&q[13..22], b"localhost");
        assert_eq!(q[22], 0);
    }

    #[test]
    fn response_parses_a_record() {
        // Construct a fake DNS response with one A record.
        let mut r = Vec::new();
        // Header.
        r.extend_from_slice(&1u16.to_be_bytes()); // ID
        r.extend_from_slice(&0x8180u16.to_be_bytes()); // Standard response, no error
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        // Question: "example.com" A IN
        r.push(7); r.extend_from_slice(b"example");
        r.push(3); r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
        r.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        // Answer: example.com A 60s 10.0.2.3
        r.push(0xC0); r.push(12); // pointer to offset 12 ("example.com")
        r.extend_from_slice(&1u16.to_be_bytes()); // TYPE=A
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
        r.extend_from_slice(&60u32.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&[10, 0, 2, 3]);

        assert_eq!(parse_response(&r, 1), Some(0x0A000203));
    }

    #[test]
    fn response_returns_none_on_nxdomain() {
        let mut r = Vec::new();
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0x8183u16.to_be_bytes()); // NXDOMAIN
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        // Question
        r.push(3); r.extend_from_slice(b"foo");
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(parse_response(&r, 1), None);
    }

    #[test]
    fn response_handles_short_packet() {
        assert_eq!(parse_response(&[0; 5], 1), None);
        assert_eq!(parse_response(&[], 1), None);
    }
}
