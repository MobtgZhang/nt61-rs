//! Storage smoke-test facade shared by every target architecture.

pub fn smoke_test() -> bool {
    crate::drivers::arch::storage_smoke_test()
}
