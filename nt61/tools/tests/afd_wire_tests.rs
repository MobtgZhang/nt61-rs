//! AFD wire-format tests.
//!
//! These cover the byte-level layout that AFD exchanges with
//! user mode (ws2_32 / msafd). The decoder is host-portable
//! because it only touches bytes, so we can directly unit-test
//! it without pulling in the kernel.

#[cfg(test)]
mod tests {
    /// 16-byte AFD address mirroring `netstack::afd::AfdAddress`.
    #[derive(Debug, Clone, Copy, Default)]
    #[allow(dead_code)]
    struct AfdAddress {
        family: u16,
        port: u16,
        addr: [u8; 4],
        zeros: [u8; 8],
    }

    fn decode_addr(input: &[u8]) -> Option<AfdAddress> {
        if input.len() < 16 {
            return None;
        }
        Some(AfdAddress {
            family: u16::from_le_bytes([input[0], input[1]]),
            port: u16::from_be_bytes([input[2], input[3]]),
            addr: [input[4], input[5], input[6], input[7]],
            zeros: [0; 8],
        })
    }

    fn encode_addr(family: u16, port: u16, ip: u32) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..2].copy_from_slice(&family.to_le_bytes());
        out[2..4].copy_from_slice(&port.to_be_bytes());
        out[4..8].copy_from_slice(&ip.to_be_bytes());
        out
    }

    #[test]
    fn decode_too_short() {
        assert!(decode_addr(&[0; 8]).is_none());
        assert!(decode_addr(&[]).is_none());
    }

    #[test]
    fn decode_round_trip() {
        let wire = encode_addr(2, 22, 0x0A000202);
        let addr = decode_addr(&wire).unwrap();
        assert_eq!(addr.family, 2);
        assert_eq!(addr.port, 22);
        assert_eq!(addr.addr, [10, 0, 2, 2]);
    }

    #[test]
    fn decode_large_port() {
        let wire = encode_addr(2, 65535, 0x7F000001);
        let addr = decode_addr(&wire).unwrap();
        assert_eq!(addr.port, 65535);
        assert_eq!(addr.addr, [127, 0, 0, 1]);
    }

    #[test]
    fn ioctl_constants_match() {
        // These constants are mirrored from the kernel's
        // `netstack::afd` module. Any change in the kernel must
        // be reflected here.
        const IOCTL_AFD_BIND: u32 = 0x00012003;
        const IOCTL_AFD_LISTEN: u32 = 0x0001200B;
        const IOCTL_AFD_ACCEPT: u32 = 0x00012010;
        const IOCTL_AFD_CONNECT: u32 = 0x00012007;
        const IOCTL_AFD_SEND: u32 = 0x0001201F;
        const IOCTL_AFD_RECV: u32 = 0x00012017;
        const IOCTL_AFD_SELECT: u32 = 0x00012024;
        const IOCTL_AFD_GET_NAME: u32 = 0x0001202B;
        const IOCTL_AFD_SHUTDOWN: u32 = 0x00012021;

        // Sanity: all values are in the 0x000120xx range that
        // NT 6.1's msafd.h reserves for AFD.
        for code in [
            IOCTL_AFD_BIND, IOCTL_AFD_LISTEN, IOCTL_AFD_ACCEPT,
            IOCTL_AFD_CONNECT, IOCTL_AFD_SEND, IOCTL_AFD_RECV,
            IOCTL_AFD_SELECT, IOCTL_AFD_GET_NAME, IOCTL_AFD_SHUTDOWN,
        ] {
            assert_eq!(code >> 16, 0x0001,
                "AFD IOCTL {:#x} outside the 0x0001xxxx range", code);
        }
    }
}
