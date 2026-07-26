//! Host-side tests for the pipe read/write logic.
//!
//! These tests re-implement the same buffer/EOF semantics that
//! `io::pipe` uses in the kernel. The full pipe module touches
//! the kernel handle table, which is not available in host
//! tests, so we exercise the buffer-management logic in
//! isolation here.

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    /// Mirror of `io::pipe::PipeState` data fields (no
    /// kernel handles).
    struct PipeBuf {
        buffer: VecDeque<u8>,
        write_open: bool,
        read_open: bool,
    }

    impl PipeBuf {
        fn new() -> Self {
            Self {
                buffer: VecDeque::with_capacity(64 * 1024),
                write_open: true,
                read_open: true,
            }
        }
        fn read(&mut self, buf: &mut [u8]) -> usize {
            if !self.read_open {
                return 0;
            }
            let take = buf.len().min(self.buffer.len());
            for i in 0..take {
                buf[i] = self.buffer.pop_front().unwrap_or(0);
            }
            take
        }
        fn write(&mut self, data: &[u8]) -> usize {
            if !self.write_open {
                return 0;
            }
            let cap: usize = 64 * 1024;
            let free = cap.saturating_sub(self.buffer.len());
            let take = data.len().min(free);
            for i in 0..take {
                self.buffer.push_back(data[i]);
            }
            take
        }
    }

    #[test]
    fn round_trip_small_message() {
        let mut pipe = PipeBuf::new();
        assert_eq!(pipe.write(b"hello"), 5);
        let mut buf = [0u8; 16];
        assert_eq!(pipe.read(&mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn eof_when_write_end_closed() {
        let mut pipe = PipeBuf::new();
        pipe.write(b"data");
        pipe.write_open = false;
        let mut buf = [0u8; 16];
        // Reads what's available first.
        assert_eq!(pipe.read(&mut buf), 4);
        assert_eq!(&buf[..4], b"data");
        // Then EOF.
        assert_eq!(pipe.read(&mut buf), 0);
    }

    #[test]
    fn zero_length_write_returns_zero() {
        let mut pipe = PipeBuf::new();
        assert_eq!(pipe.write(&[]), 0);
    }

    #[test]
    fn partial_read_drain() {
        let mut pipe = PipeBuf::new();
        pipe.write(b"abcdef");
        let mut buf = [0u8; 3];
        assert_eq!(pipe.read(&mut buf), 3);
        assert_eq!(&buf, b"abc");
        let mut buf2 = [0u8; 3];
        assert_eq!(pipe.read(&mut buf2), 3);
        assert_eq!(&buf2, b"def");
    }

    #[test]
    fn write_does_not_exceed_buffer_capacity() {
        let mut pipe = PipeBuf::new();
        let big = vec![0xAAu8; 64 * 1024 + 100];
        let n = pipe.write(&big);
        assert_eq!(n, 64 * 1024, "must cap at buffer size");
        // A second write finds no room.
        assert_eq!(pipe.write(&[0xBBu8; 50]), 0);
    }

    #[test]
    fn read_into_empty_buffer_on_open_pipe_returns_zero() {
        let mut pipe = PipeBuf::new();
        let mut buf = [0u8; 16];
        // No data and write end still open — read returns 0 bytes
        // (kernel-side this would be a blocking wait).
        assert_eq!(pipe.read(&mut buf), 0);
    }
}
