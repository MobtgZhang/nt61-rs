//! Disk class-driver facade shared by every target architecture.
//!
//! The generic facade owns the stable NT-compatible entry points. A
//! target backend registers itself during early architecture bring-up;
//! until then the facade is a safe no-op.

use crate::ke::sync::Spinlock;

#[derive(Clone, Copy)]
pub struct DiskInfo {
    pub sector_count: u64,
}

pub trait DiskBackend: Sync {
    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn init(&self);
    fn disk_count(&self) -> usize;
    fn disk_read(&self, index: usize, offset: u64, byte_count: usize, buf: &mut [u8]) -> usize;
    fn disk_write(&self, index: usize, offset: u64, byte_count: usize, buf: &[u8]) -> usize;
    fn get_disk(&self, index: usize) -> Option<DiskInfo>;
    fn smoke_test(&self) -> bool;
    fn read_count(&self) -> u32;
    fn write_count(&self) -> u32;
}

static BACKEND: Spinlock<Option<&'static dyn DiskBackend>> = Spinlock::new(None);

/// Register a disk backend exactly once during architecture bring-up.
///
/// # Safety
/// The caller must pass a reference that is valid for the lifetime of
/// the kernel and complete this call before any disk I/O.
pub unsafe fn register_backend(backend: &'static dyn DiskBackend) {
    *BACKEND.lock() = Some(backend);
}

fn backend() -> Option<&'static dyn DiskBackend> {
    *BACKEND.lock()
}

pub fn init() {
    if let Some(backend) = backend() {
        unsafe { backend.init() };
    }
}

pub fn disk_count() -> usize {
    backend().map_or(0, DiskBackend::disk_count)
}

pub fn disk_read(index: usize, offset: u64, byte_count: usize, buf: &mut [u8]) -> usize {
    backend().map_or(0, |backend| {
        backend.disk_read(index, offset, byte_count, buf)
    })
}

pub fn disk_write(index: usize, offset: u64, byte_count: usize, buf: &[u8]) -> usize {
    backend().map_or(0, |backend| {
        backend.disk_write(index, offset, byte_count, buf)
    })
}

pub fn smoke_test() -> bool {
    backend().is_none_or(DiskBackend::smoke_test)
}

pub fn read_count() -> u32 {
    backend().map_or(0, DiskBackend::read_count)
}

pub fn write_count() -> u32 {
    backend().map_or(0, DiskBackend::write_count)
}

pub fn get_disk(index: usize) -> Option<DiskInfo> {
    backend().and_then(|backend| backend.get_disk(index))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::DiskBackend;
    use super::DiskInfo;

    pub struct TestDiskBackend;

    impl DiskBackend for TestDiskBackend {
        /// # Safety
        ///
        /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
        unsafe fn init(&self) {}

        fn disk_count(&self) -> usize {
            1
        }

        fn disk_read(
            &self,
            _index: usize,
            _offset: u64,
            byte_count: usize,
            buf: &mut [u8],
        ) -> usize {
            let len = buf.len().min(byte_count);
            buf[..len].fill(0);
            len
        }

        fn disk_write(&self, _index: usize, _offset: u64, byte_count: usize, buf: &[u8]) -> usize {
            byte_count.min(buf.len())
        }

        fn get_disk(&self, index: usize) -> Option<DiskInfo> {
            (index < 1).then_some(DiskInfo { sector_count: 64 })
        }

        fn smoke_test(&self) -> bool {
            true
        }

        fn read_count(&self) -> u32 {
            0
        }

        fn write_count(&self) -> u32 {
            0
        }
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn register_test_backend() {
        super::register_backend(&TestDiskBackend);
    }
}
