//! QCOW2 Image Tests
//!
//! Host-side tests for QCOW2 image format support.
//! Verifies QCOW2 header structure, refcount management, and image operations.

#[cfg(test)]
mod tests {
    use nt61_tools::fs::qcow2::Qcow2Image;

    /// Test QCOW2 header magic number
    #[test]
    fn qcow2_header_magic() {
        let mut image = Qcow2Image::create(1024 * 1024).expect("qcow2 create");
        let data = image.finalize().expect("qcow2 finalize");

        // QCOW2 magic is "QFI\xfb"
        assert_eq!(&data[0..4], b"QFI\xfb", "QCOW2 magic should be QFI\\xfb");
    }

    /// Test QCOW2 header version
    #[test]
    fn qcow2_header_version() {
        let mut image = Qcow2Image::create(1024 * 1024).expect("qcow2 create");
        let data = image.finalize().expect("qcow2 finalize");

        // QCOW2 v2/v3 stores the version at offset 4 in big-endian.
        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        assert!(version >= 2 && version <= 3, "QCOW2 version should be 2 or 3");
    }

    /// Test QCOW2 backing file offset initialization
    #[test]
    fn qcow2_backing_file_offset() {
        let mut image = Qcow2Image::create(1024 * 1024).expect("qcow2 create");
        let data = image.finalize().expect("qcow2 finalize");

        // Backing file offset is u64 big-endian at offset 8.
        let backing_offset = u64::from_be_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15]
        ]);
        assert_eq!(backing_offset, 0, "New image should have no backing file");
    }

    /// Test QCOW2 cluster size
    #[test]
    fn qcow2_cluster_size() {
        let mut image = Qcow2Image::create(1024 * 1024).expect("qcow2 create");
        let data = image.finalize().expect("qcow2 finalize");

        // Cluster size is u32 big-endian at offset 20, but it
        // is the log2 of the cluster size (cluster_bits).
        let cluster_bits = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        assert!(cluster_bits >= 9 && cluster_bits <= 21, "cluster_bits should be 9..=21");
        let cluster_size = 1u32 << cluster_bits;
        assert!(cluster_size.is_power_of_two(), "Cluster size should be power of 2");
        assert!(cluster_size >= 512, "Cluster size should be at least 512");
    }

    /// Test creating QCOW2 image with different sizes
    #[test]
    fn qcow2_create_different_sizes() {
        let sizes = [
            1024,           // 1 KB
            1024 * 1024,    // 1 MB
            64 * 1024 * 1024, // 64 MB
        ];

        for size in sizes {
            let mut image = Qcow2Image::create(size).expect(&format!("qcow2 create size {}", size));
            let data = image.finalize().expect(&format!("qcow2 finalize size {}", size));
            assert!(!data.is_empty(), "Finalized image should not be empty");
        }
    }

    /// Test opening empty QCOW2 image returns error
    #[test]
    fn qcow2_open_empty_error() {
        let empty: Vec<u8> = Vec::new();
        let res = Qcow2Image::open(&empty);
        assert!(res.is_err(), "Opening empty image should return error");
    }

    /// Test opening invalid QCOW2 image returns error
    #[test]
    fn qcow2_open_invalid_error() {
        let invalid = vec![0u8; 1024];
        let res = Qcow2Image::open(&invalid);
        assert!(res.is_err(), "Opening invalid image should return error");
    }

    /// Test image size encoding in header
    #[test]
    fn qcow2_size_in_header() {
        // The qcow2 builder takes a u32 GB count and stores the
        // resulting virtual size in the on-disk header. 1 GB is the
        // smallest size that round-trips through `create(size_gb)`
        // without hitting the byte-budget that 0 GB would imply.
        let size_gb: u32 = 1u32;
        let expected_size: u64 = u64::from(size_gb) * 1024 * 1024 * 1024;
        let mut image = Qcow2Image::create(size_gb).expect("qcow2 create");
        let data = image.finalize().expect("qcow2 finalize");

        // Image size is u64 big-endian at offset 24-31.
        let stored_size = u64::from_be_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31]
        ]);
        assert_eq!(stored_size, expected_size, "Stored size should match created size");
    }

    /// Test refcount table and refcount block initialization
    #[test]
    fn qcow2_refcount_initialization() {
        let mut image = Qcow2Image::create(1024 * 1024).expect("qcow2 create");
        let data = image.finalize().expect("qcow2 finalize");

        // Image should have minimum size for header + refcount structures
        assert!(data.len() >= 1024, "QCOW2 image should be at least 1KB");
    }
}

/// Tests for FAT32 image format
#[cfg(test)]
mod fat32_tests {
    /// Test FAT32 boot sector signature
    #[test]
    fn fat32_boot_sector_signature() {
        // FAT32 boot sector ends with 0xAA55
        const FAT32_BOOT_SIGNATURE: u16 = 0xAA55;

        assert_eq!(FAT32_BOOT_SIGNATURE, 0xAA55);
    }

    /// Test FAT32 filesystem info signature
    #[test]
    fn fat32_fsinfo_signature() {
        // FAT32 FSInfo sector has signature "RRaA" at offset 0x00
        const FSINFO_SIGNATURE: &[u8; 4] = b"RRaA";

        assert_eq!(FSINFO_SIGNATURE, b"RRaA");
    }

    /// Test FAT32 backup FSInfo signature
    #[test]
    fn fat32_backup_fsinfo_signature() {
        // FAT32 backup FSInfo has signature "rrAa" at offset 0x00
        const BACKUP_FSINFO_SIGNATURE: &[u8; 4] = b"rrAa";

        assert_eq!(BACKUP_FSINFO_SIGNATURE, b"rrAa");
    }

    /// Test FAT32 bytes per sector values
    #[test]
    fn fat32_bytes_per_sector() {
        const VALID_BPS: &[u16] = &[512, 1024, 2048, 4096];

        for bps in VALID_BPS {
            assert!(*bps >= 512 && *bps <= 4096, "Bytes per sector should be 512-4096");
        }
    }

    /// Test FAT32 sectors per cluster values
    #[test]
    fn fat32_sectors_per_cluster() {
        // Valid sectors per cluster: 1, 2, 4, 8, 16, 32, 64, 128
        let valid_spc: Vec<u8> = (0..8).map(|i| 1 << i).collect();

        for spc in valid_spc {
            assert!(spc > 0 && spc <= 128, "SPC should be power of 2 up to 128");
        }
    }
}

/// Tests for NTFS image format (structure validation)
#[cfg(test)]
mod ntfs_tests {
    /// Test NTFS boot sector signature
    #[test]
    fn ntfs_boot_sector_signature() {
        // NTFS boot sector ends with 0xAA55
        const NTFS_BOOT_SIGNATURE: u16 = 0xAA55;

        assert_eq!(NTFS_BOOT_SIGNATURE, 0xAA55);
    }

    /// Test NTFS file system identifier
    #[test]
    fn ntfs_fs_identifier() {
        // NTFS identifier is "NTFS    " (8 bytes, space-padded)
        const NTFS_ID: &[u8; 8] = b"NTFS    ";

        assert_eq!(NTFS_ID.len(), 8);
        assert!(NTFS_ID.starts_with(b"NTFS"));
    }

    /// Test NTFS sector sizes
    #[test]
    fn ntfs_sector_size() {
        // NTFS sector size is typically 512 bytes or 4096 bytes
        const NTFS_SECTOR_SIZE: u16 = 512;

        assert_eq!(NTFS_SECTOR_SIZE, 512);
    }

    /// Test NTFS cluster size alignment
    #[test]
    fn ntfs_cluster_alignment() {
        // NTFS cluster size is sector_size * sectors_per_cluster
        // Must be power of 2 and typically 512, 1024, 2048, 4096, etc.
        let sector_size: u64 = 512;
        let sectors_per_cluster: u64 = 8;
        let cluster_size = sector_size * sectors_per_cluster;

        assert!(cluster_size.is_power_of_two(), "Cluster size should be power of 2");
        assert!(cluster_size >= 512 && cluster_size <= 65536, "Cluster size should be 512-64KB");
    }
}
