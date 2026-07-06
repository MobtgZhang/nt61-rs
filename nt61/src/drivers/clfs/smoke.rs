//! CLFS Smoke Test
//
//! Comprehensive smoke test for the Common Log File System driver.
//! Tests: log creation, container management, record write/read,
//! flush operations, and information queries.

extern crate alloc;

use crate::rtl::logging::subsystem::CLFS;

use super::context::ClfsContainerState;
use super::format::CLFS_SECTOR_SIZE;
use super::record::ClfsLsn;
use super::{ClfsCreateLogFile, ClfsWriteLogRecord, ClfsReadLogRecord};
use super::{ClfsFlushBuffers, ClfsMgmtQueryLogInformation, ClfsMgmtLogInformation};
use super::{ClfsAddLogContainer, ClfsRemoveLogContainer, log_count};
use super::{container, io, record};
use super::metadata::{ClfsControlRecord, ClfsBaseRecordHeader};
use super::STATUS_SUCCESS;

/// Run the CLFS smoke test.
///
/// This tests the full CLFS lifecycle:
/// 1. Create a log
/// 2. Add containers
/// 3. Write multiple records
/// 4. Read records back
/// 5. Flush the log
/// 6. Query log information
/// 7. Remove containers
/// 8. Verify statistics
pub fn smoke_test() -> bool {
    crate::kprintln_info!("CLFS", "=== CLFS smoke test ===");

    let mut all_passed = true;

    // Test 1: Log creation
    crate::kprintln_info!("CLFS", "[1/8] Testing log creation...");
    all_passed &= test_log_creation();

    // Test 2: Container management
    crate::kprintln_info!("CLFS", "[2/8] Testing container management...");
    all_passed &= test_container_management();

    // Test 3: Record write
    crate::kprintln_info!("CLFS", "[3/8] Testing record writing...");
    all_passed &= test_record_write();

    // Test 4: Record read
    crate::kprintln_info!("CLFS", "[4/8] Testing record reading...");
    all_passed &= test_record_read();

    // Test 5: LSN management
    crate::kprintln_info!("CLFS", "[5/8] Testing LSN management...");
    all_passed &= test_lsn_management();

    // Test 6: Metadata structures
    crate::kprintln_info!("CLFS", "[6/8] Testing metadata structures...");
    all_passed &= test_metadata_structures();

    // Test 7: Flush operations
    crate::kprintln_info!("CLFS", "[7/8] Testing flush operations...");
    all_passed &= test_flush();

    // Test 8: Log information query
    crate::kprintln_info!("CLFS", "[8/8] Testing log information query...");
    all_passed &= test_log_query();

    // Final summary
    if all_passed {
        crate::kprintln_info!("CLFS", "=== CLFS smoke test PASSED ===");
    } else {
        crate::kprintln_info!("CLFS", "=== CLFS smoke test FAILED ===");
    }

    all_passed
}

// ============================================================================
// Individual Test Functions
// ============================================================================

fn test_log_creation() -> bool {
    // Create a log
    let log = ClfsCreateLogFile(b"\\Registry\\TestLog", 0, 0);
    if log == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not create log");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Log created with handle #{:08x}", log);

    // Create a second log
    let log2 = ClfsCreateLogFile(b"\\??\\C:\\test.clf", 0, 0);
    if log2 == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not create second log");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Second log created with handle #{:08x}", log2);

    // Check log count
    let count = log_count();
    if count != 2 {
        crate::kprintln_info!("CLFS", "  FAIL: Expected 2 logs, found {}", count);
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: {} logs in system", count);

    true
}

fn test_container_management() -> bool {
    // Create a log
    let log = ClfsCreateLogFile(b"\\ContainerTest", 0, 0);
    if log == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not create log for container test");
        return false;
    }

    // Add a container (512KB minimum)
    let cid1 = ClfsAddLogContainer(log, 512 * 1024, b"/data/clfs/container1.blf");
    if cid1 == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not add container 1");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Container {} added", cid1);

    // Add a second container
    let cid2 = ClfsAddLogContainer(log, 512 * 1024, b"/data/clfs/container2.blf");
    if cid2 == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not add container 2");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Container {} added", cid2);

    // Add a third container with larger size
    let cid3 = ClfsAddLogContainer(log, 1024 * 1024, b"/data/clfs/container3.blf");
    if cid3 == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not add container 3");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Container {} added (1MB)", cid3);

    // Remove the second container (not deleting the file)
    let status = ClfsRemoveLogContainer(log, cid2, false);
    if status != STATUS_SUCCESS {
        crate::kprintln_info!("CLFS", "  FAIL: Could not remove container {}: status={}", cid2, status);
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Container {} removed (not deleted)", cid2);

    // Try to remove the same container again (should fail)
    let status2 = ClfsRemoveLogContainer(log, cid2, false);
    if status2 == STATUS_SUCCESS {
        crate::kprintln_info!("CLFS", "  FAIL: Removing same container twice should fail");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Second removal correctly failed");

    true
}

fn test_record_write() -> bool {
    // Create a log
    let log = ClfsCreateLogFile(b"\\RecordWriteTest", 0, 0);
    if log == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not create log");
        return false;
    }

    // Add a container
    let cid = ClfsAddLogContainer(log, 512 * 1024, b"/data/clfs/write_test.blf");
    if cid == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not add container");
        return false;
    }

    // Write 50 records
    for i in 0..50 {
        let data = make_test_record(i);
        let status = ClfsWriteLogRecord(log, 0, &data);
        if status != STATUS_SUCCESS {
            crate::kprintln_info!("CLFS", "  FAIL: Write failed at record {}: status={}", i, status);
            return false;
        }
    }
    crate::kprintln_info!("CLFS", "  OK: 50 records written");

    // Write a large record (should succeed if under limit)
    let large_data = alloc::vec![0xAB; 1024];
    let status = ClfsWriteLogRecord(log, 0, &large_data);
    if status != STATUS_SUCCESS {
        crate::kprintln_info!("CLFS", "  FAIL: Large record write failed: status={}", status);
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Large record (1KB) written");

    // Write a record that's too large
    let huge_data = alloc::vec![0xCD; 64 * 1024];
    let status = ClfsWriteLogRecord(log, 0, &huge_data);
    if status == STATUS_SUCCESS {
        crate::kprintln_info!("CLFS", "  FAIL: Oversized record should have been rejected");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Oversized record correctly rejected");

    true
}

fn test_record_read() -> bool {
    // Create a log
    let log = ClfsCreateLogFile(b"\\RecordReadTest", 0, 0);
    if log == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not create log");
        return false;
    }

    // Add a container
    let cid = ClfsAddLogContainer(log, 512 * 1024, b"/data/clfs/read_test.blf");
    if cid == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not add container");
        return false;
    }

    // Write some records
    for i in 0..10 {
        let data = make_test_record(i);
        let status = ClfsWriteLogRecord(log, i as u32, &data);
        if status != STATUS_SUCCESS {
            crate::kprintln_info!("CLFS", "  FAIL: Write failed at record {}", i);
            return false;
        }
    }

    // Read records back
    let mut read_count = 0u32;
    for _ in 0..10 {
        let mut lsn = 0u64;
        let mut buf = [0u8; 256];
        let status = ClfsReadLogRecord(log, &mut lsn, &mut buf);
        if status != STATUS_SUCCESS {
            crate::kprintln_info!("CLFS", "  FAIL: Read failed at record {}", read_count);
            return false;
        }
        read_count += 1;
    }
    crate::kprintln_info!("CLFS", "  OK: {} records read back", read_count);

    // Try to read past the end
    let mut lsn = 0u64;
    let mut buf = [0u8; 256];
    let status = ClfsReadLogRecord(log, &mut lsn, &mut buf);
    if status == STATUS_SUCCESS {
        crate::kprintln_info!("CLFS", "  FAIL: Read past end should have failed");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Read past end correctly returned error");

    true
}

fn test_lsn_management() -> bool {
    // Test LSN construction
    let lsn1 = ClfsLsn::new(1, 0, 0);
    if lsn1.container_id() != 1 {
        crate::kprintln_info!("CLFS", "  FAIL: LSN container_id incorrect");
        return false;
    }
    if lsn1.block_offset() != 0 {
        crate::kprintln_info!("CLFS", "  FAIL: LSN block_offset incorrect");
        return false;
    }
    if lsn1.record_index() != 0 {
        crate::kprintln_info!("CLFS", "  FAIL: LSN record_index incorrect");
        return false;
    }

    // Test LSN advancement
    let lsn2 = ClfsLsn::new(1, 0, 1);
    if lsn2.record_index() != 1 {
        crate::kprintln_info!("CLFS", "  FAIL: LSN advance failed");
        return false;
    }

    // Test LSN ordering
    if lsn1 >= lsn2 {
        crate::kprintln_info!("CLFS", "  FAIL: LSN ordering incorrect");
        return false;
    }

    // Test LSN NULL
    let null_lsn = ClfsLsn::NULL;
    if !null_lsn.is_null() {
        crate::kprintln_info!("CLFS", "  FAIL: NULL LSN check failed");
        return false;
    }

    // Test LSN INVALID
    let inv_lsn = ClfsLsn::INVALID;
    if !inv_lsn.is_invalid() {
        crate::kprintln_info!("CLFS", "  FAIL: INVALID LSN check failed");
        return false;
    }

    crate::kprintln_info!("CLFS", "  OK: LSN management working correctly");
    crate::kprintln_info!("CLFS", "  Sample LSN: {}", lsn2);

    true
}

fn test_metadata_structures() -> bool {
    // Test Control Record
    let ctrl = ClfsControlRecord::new();
    if !ctrl.is_valid() {
        crate::kprintln_info!("CLFS", "  FAIL: Control record validation failed");
        return false;
    }
    if ctrl.c_blocks != 6 {
        crate::kprintln_info!("CLFS", "  FAIL: Control record should have 6 blocks");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Control record valid (magic=0x{:016x})", ctrl.magic);

    // Test Base Record
    let base = ClfsBaseRecordHeader::new();
    if base.c_next_container != 1 {
        crate::kprintln_info!("CLFS", "  FAIL: Base record c_next_container should be 1");
        return false;
    }
    if base.c_next_client != 1 {
        crate::kprintln_info!("CLFS", "  FAIL: Base record c_next_client should be 1");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Base record valid (state={:?})", base.e_log_state);

    // Test serialization
    let mut buf = alloc::vec![0u8; 1024];
    ctrl.write_to(&mut buf);
    crate::kprintln_info!("CLFS", "  OK: Control record serialized ({} bytes)", buf.len());

    true
}

fn test_flush() -> bool {
    // Create a log
    let log = ClfsCreateLogFile(b"\\FlushTest", 0, 0);
    if log == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not create log");
        return false;
    }

    // Add a container
    let cid = ClfsAddLogContainer(log, 512 * 1024, b"/data/clfs/flush_test.blf");
    if cid == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not add container");
        return false;
    }

    // Write some records
    for i in 0..5 {
        let data = make_test_record(i);
        let _ = ClfsWriteLogRecord(log, 0, &data);
    }

    // Flush
    let status = ClfsFlushBuffers(log);
    if status != STATUS_SUCCESS {
        crate::kprintln_info!("CLFS", "  FAIL: Flush failed: status={}", status);
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Log flushed successfully");

    // Flush again (should be idempotent)
    let status2 = ClfsFlushBuffers(log);
    if status2 != STATUS_SUCCESS {
        crate::kprintln_info!("CLFS", "  FAIL: Second flush failed");
        return false;
    }
    crate::kprintln_info!("CLFS", "  OK: Second flush successful (idempotent)");

    true
}

fn test_log_query() -> bool {
    // Create a log
    let log = ClfsCreateLogFile(b"\\QueryTest", 0, 0);
    if log == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Could not create log");
        return false;
    }

    // Add containers
    let _cid1 = ClfsAddLogContainer(log, 512 * 1024, b"/data/clfs/query1.blf");
    let _cid2 = ClfsAddLogContainer(log, 512 * 1024, b"/data/clfs/query2.blf");

    // Write some records
    for i in 0..10 {
        let data = make_test_record(i);
        let _ = ClfsWriteLogRecord(log, 0, &data);
    }

    // Query log information
    let mut info = ClfsMgmtLogInformation::default();
    let status = ClfsMgmtQueryLogInformation(log, &mut info);
    if status != STATUS_SUCCESS {
        crate::kprintln_info!("CLFS", "  FAIL: Query failed: status={}", status);
        return false;
    }

    crate::kprintln_info!("CLFS", "  Log info:");
    crate::kprintln_info!("CLFS", "    Total size: {} bytes", info.total_log_size);
    crate::kprintln_info!("CLFS", "    Available: {} bytes", info.current_available);
    crate::kprintln_info!("CLFS", "    Used: {} bytes", info.actual_size);
    crate::kprintln_info!("CLFS", "    Records: {}", info.record_count);
    crate::kprintln_info!("CLFS", "    Flags: 0x{:08x}", info.flags);

    // Verify reasonable values
    if info.total_log_size == 0 {
        crate::kprintln_info!("CLFS", "  FAIL: Total size should not be 0");
        return false;
    }
    if info.record_count < 10 {
        crate::kprintln_info!("CLFS", "  FAIL: Record count should be >= 10");
        return false;
    }

    crate::kprintln_info!("CLFS", "  OK: Log query returned valid information");
    true
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test record with a specific byte pattern.
fn make_test_record(seq: u32) -> [u8; 64] {
    let mut data = [0u8; 64];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = ((seq as usize + i) & 0xFF) as u8;
    }
    // Mark the record with the sequence number at the start
    data[0] = b'R';
    data[1] = b'E';
    data[2] = b'C';
    data[3] = b':';
    data[4] = ((seq >> 24) & 0xFF) as u8;
    data[5] = ((seq >> 16) & 0xFF) as u8;
    data[6] = ((seq >> 8) & 0xFF) as u8;
    data[7] = (seq & 0xFF) as u8;
    data
}

/// Verify a test record's byte pattern.
fn verify_test_record(data: &[u8], expected_seq: u32) -> bool {
    if data.len() < 8 {
        return false;
    }
    if data[0] != b'R' || data[1] != b'E' || data[2] != b'C' || data[3] != b':' {
        return false;
    }
    let seq = ((data[4] as u32) << 24)
            | ((data[5] as u32) << 16)
            | ((data[6] as u32) << 8)
            | (data[7] as u32);
    seq == expected_seq
}
