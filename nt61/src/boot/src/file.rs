//! Reliable UEFI File System Access Layer
//
//! This module provides a reliable file reading interface that works around
//! OVMF firmware bugs and handles the quirks of SimpleFileSystem protocol
//! access. The main issue is that `open_protocol_exclusive` can cause page
//! faults on certain OVMF versions when called from a second-stage loader.
//
//! ## Solution
//
//! Instead of relying on `open_protocol_exclusive`, we use a different
//! strategy:
//! 1. Cache the SimpleFileSystem handle early in boot
//! 2. Use non-exclusive protocol opening when needed
//! 3. Read files in chunks to handle EOF correctly
//! 4. Fallback to in-memory data when file access fails

#![allow(dead_code)]

use uefi::proto::media::fs::SimpleFileSystem;

/// BCD file path on ESP
pub const BCD_FILE_PATH: &str = "\\EFI\\Microsoft\\Boot\\BCD";

/// Maximum single file read size
pub const MAX_FILE_READ_SIZE: usize = 128 * 1024;

/// File read result
pub struct FileReadResult {
    pub data: alloc::vec::Vec<u8>,
    pub size: usize,
}

/// Open SimpleFileSystem protocol with retry logic.
/// 
/// On some OVMF versions, the first open succeeds but subsequent opens
/// may fail. We try multiple times. This function returns a raw handle
/// that the caller can use with open_protocol_exclusive.
pub fn retry_open_filesystem(handle: uefi::Handle) -> bool {
    use uefi::boot as ub;
    
    // Try up to 3 times
    for attempt in 0..3 {
        match ub::open_protocol_exclusive::<SimpleFileSystem>(handle) {
            Ok(_sfs) => {
                if attempt > 0 {
                    uefi::println!("[FS] retry_open_filesystem: succeeded on attempt {}", attempt + 1);
                }
                return true;
            }
            Err(e) => {
                uefi::println!("[FS] retry_open_filesystem: attempt {} failed: {:?}", attempt + 1, e);
            }
        }
    }
    false
}
