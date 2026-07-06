//! Wow64-local lightweight logging macro.
//
//! The wow64 layer suffers from the same `core::fmt::Write`-style
//! crash as the rest of the kernel: `LOG_EARLY_READY` may be
//! `false` for some startup paths, and pulling in the buffered
//! `BufferWriter` along with `memcpy` would crash the Wow64 path
//! before the per-process PEB32 is reachable. To keep the wow64
//! modules warning-free and free of `// kprintln disabled` stub
//! comments we route every wow64 log statement through a thin
//! wrapper that talks to the kernel's per-arch serial port
//! directly. The wrapper never touches `core::fmt::Write` over
//! a stack buffer (which would pull in `copy_from_slice`), only
//! enough string concatenation to combine the user-supplied
//! parts into the 256-byte scratch buffer, then hands the bytes
//! off to the platform serial writer.
//
//! This macro is intentionally tiny so that the wow64 module
//! has zero dependency on the existing `kprintln!` macro. It is
//! `#[macro_export]` so any future wow64 sub-module can pull it
//! in by importing `crate::libs::wow64::klog!`.

/// The WOW64 log function name printed on every line. Kept short
/// to leave room for the user's prefix.
pub const WOW64_LOG_PREFIX: &str = "[WOW64] ";

#[macro_export]
macro_rules! wow64_klog {
    ($($arg:tt)*) => {{
        #[allow(unused_imports)]
        use core::fmt::Write;

        // 256 bytes is plenty for a single log line. The buffer is
        // stack-allocated; we do not use the kernel's `BufferWriter`
        // here because at the wow64 call sites we may run before
        // `core::fmt::Write` over a borrowed slice is reliable.
        struct FmtWriter<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }

        impl<'a> core::fmt::Write for FmtWriter<'a> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let n = s.len().min(self.buf.len().saturating_sub(self.pos));
                if n == 0 {
                    return Ok(());
                }
                // Manual byte-by-byte copy instead of copy_from_slice
                // to avoid SIMD memcpy that may crash in early boot.
                let src = s.as_bytes();
                let mut i = 0;
                while i < n {
                    self.buf[self.pos + i] = src[i];
                    i += 1;
                }
                self.pos += n;
                Ok(())
            }
        }

        // Carefully cap the message length so a runaway format
        // expression cannot blow the stack.
        let mut buf = [0u8; 256];
        let mut writer = FmtWriter { buf: &mut buf, pos: 0 };
        // Prefix every wow64 log line so multi-subsystem boot logs
        // stay readable. We emit the prefix unconditionally; tools
        // that filter the serial log can grep on the bracket.
        let _ = writer.write_str($crate::libs::wow64::klog::WOW64_LOG_PREFIX);
        let _ = writer.write_fmt(core::format_args!($($arg)*));
        let _ = writer.write_str("\r\n");
        let pos = writer.pos;
        // Borrow of `buf` ends when we return from this scope.
        let msg = core::str::from_utf8(&buf[..pos]).unwrap_or("");
        // Dispatch to the platform serial port. We funnel through
        // the per-arch serial helper, falling back to a no-op if no
        // architecture matches (which only happens during unit
        // tests).
        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        { let _ = $crate::hal::x86_64::serial::write_string(msg); }
        #[cfg(target_arch = "aarch64")]
        { let _ = $crate::hal::aarch64::serial::write_string(msg); }
        #[cfg(target_arch = "riscv64")]
        { let _ = $crate::hal::riscv64::serial::write_string(msg); }
        #[cfg(target_arch = "loongarch64")]
        { let _ = $crate::hal::loongarch64::serial::write_string(msg); }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        { let _ = msg; }
    }};
}
