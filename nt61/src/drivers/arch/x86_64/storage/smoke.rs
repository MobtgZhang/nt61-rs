//! Storage Stack Smoke Test Aggregator
//
//! Runs every storage driver's smoke test and aggregates the
//! result, mirroring the convention used by `ke::smoke` /
//! `mm::smoke` / `io::smoke`.

/// Run every storage miniport's self-check and return `true`
/// iff every one passed.
pub fn smoke_test() -> bool {
    crate::drivers::storage::disk::smoke_test()
        && crate::drivers::storage::ahci::smoke_test()
        && crate::drivers::storage::storport::smoke_test()
}
