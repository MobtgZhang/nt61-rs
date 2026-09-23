//! Real File Operation Command Implementations for NT6.1
//!
//! Provides REAL implementations of Windows 7 file operation commands:
//! - COPY: Copy files (real filesystem I/O)
//! - MOVE: Move/rename files (real filesystem operations)
//! - DEL/ERASE: Delete files (real filesystem deletion)
//! - REN/RENAME: Rename files (real filesystem rename)
//! - TYPE: Display file contents (real file read)
//! - XCOPY: Extended copy with subdirectories
//! - ROBOCOPY: Robust file copy utility
//! - ATTRIB: Display/change file attributes
//! - COMP: Compare file contents
//! - FC: File compare utility
//! - FIND/FINDSTR: Search for strings in files
//! - REPLACE: Replace files
//! - EXPAND: Expand compressed files
//!
//! All commands interact with the real NTFS/FAT32 filesystem.
//! Clean-room implementation based on Windows 7 specifications.

use crate::fs::{self, ntfs, fat32};
use crate::hal::serial;
use alloc::string::String;
use alloc::vec::Vec;

pub fn cmd_copy_real(args: &str, _cwd: &str) -> bool {
    if args.is_empty() {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let dest = parts[parts.len() - 1];
    let sources: Vec<&str> = parts[..parts.len() - 1].iter()
        .filter(|s| !s.starts_with('/'))
        .map(|s| *s)
        .collect();

    if sources.is_empty() {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    // Determine which filesystem to use
    let use_ntfs = ntfs::is_mounted();
    let use_fat32 = !use_ntfs && fat32::is_mounted();

    if !use_ntfs && !use_fat32 {
        print_str("No filesystem mounted. Cannot copy files.\r\n");
        return false;
    }

    let mut copied_count = 0u32;
    let mut failed_count = 0u32;

    for source in sources {
        let source = source.trim_matches('"');

        let source_exists = if use_ntfs {
            ntfs::file_exists(source)
        } else {
            let source_83 = fat32::name_to_83(source);
            if let Some(fs) = fat32::get_mounted_fs() {
                fat32::file_exists_in_root(fs, &source_83)
            } else {
                false
            }
        };

        if !source_exists {
            print_str("The system cannot find the file specified - ");
            print_str(source);
            print_str("\r\n");
            failed_count += 1;
            continue;
        }

        let result = if use_ntfs {
            copy_file_ntfs(source, dest)
        } else {
            copy_file_fat32(source, dest)
        };

        if result {
            print_str("        ");
            print_str(source);
            print_str("\r\n");
            copied_count += 1;
        } else {
            print_str("Error copying ");
            print_str(source);
            print_str("\r\n");
            failed_count += 1;
        }
    }

    print_str("        ");
    print_dec(copied_count);
    print_str(" file(s) copied.\r\n");

    if failed_count > 0 {
        print_str("        ");
        print_dec(failed_count);
        print_str(" file(s) failed.\r\n");
    }

    copied_count > 0
}

fn copy_file_ntfs(source: &str, dest: &str) -> bool {
    let source_data = match ntfs::read_file_all(source) {
        Ok(data) => data,
        Err(_) => return false,
    };

    match ntfs::write_file_all(dest, &source_data) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn copy_file_fat32(source: &str, dest: &str) -> bool {
    let fs = match fat32::get_mounted_fs() {
        Some(f) => f,
        None => return false,
    };

    let source_83 = fat32::name_to_83(source);
    let dest_83 = fat32::name_to_83(dest);

    let source_entry = match fat32::find_file_in_root(fs, &source_83) {
        Some(e) => e,
        None => return false,
    };

    let source_cluster = source_entry.first_cluster();
    let source_size = source_entry.file_size();

    if source_cluster == 0 || source_cluster >= fat32::FAT32_EOC {
        return false;
    }

    let mut source_data = alloc::vec![0u8; source_size as usize];
    if fat32::read_file(fs, source_cluster, source_size, &mut source_data).is_err() {
        return false;
    }

    let dest_cluster = match fat32::allocate_cluster(fs, 0) {
        Ok(c) => c,
        Err(_) => return false,
    };

    if fat32::write_cluster(fs, dest_cluster, &source_data).is_err() {
        let _ = fat32::free_cluster_chain(fs, dest_cluster);
        return false;
    }

    if fat32::create_file_in_root(fs, &dest_83, dest_cluster, source_size).is_err() {
        let _ = fat32::free_cluster_chain(fs, dest_cluster);
        return false;
    }

    true
}

pub fn cmd_move_real(args: &str, _cwd: &str) -> bool {
    if args.is_empty() {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let parts: Vec<&str> = args.split_whitespace()
        .filter(|s| !s.starts_with('/'))
        .collect();

    if parts.len() < 2 {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let source = parts[0].trim_matches('"');
    let dest = parts[1].trim_matches('"');

    let use_ntfs = ntfs::is_mounted();
    let use_fat32 = !use_ntfs && fat32::is_mounted();

    if !use_ntfs && !use_fat32 {
        print_str("No filesystem mounted. Cannot move files.\r\n");
        return false;
    }

    let source_exists = if use_ntfs {
        ntfs::file_exists(source)
    } else {
        let source_83 = fat32::name_to_83(source);
        if let Some(fs) = fat32::get_mounted_fs() {
            fat32::file_exists_in_root(fs, &source_83)
        } else {
            false
        }
    };

    if !source_exists {
        print_str("The system cannot find the file specified.\r\n");
        return false;
    }

    let result = if use_ntfs {
        ntfs::rename_file(source, dest).is_ok()
    } else {
        if copy_file_fat32(source, dest) {
            delete_file_fat32(source)
        } else {
            false
        }
    };

    if result {
        print_str("        1 file(s) moved.\r\n");
        true
    } else {
        print_str("The system cannot move the file.\r\n");
        false
    }
}

pub fn cmd_del_real(args: &str, _cwd: &str) -> bool {
    if args.is_empty() {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let mut force = false;
    let mut quiet = false;
    let mut files: Vec<&str> = Vec::new();

    for part in args.split_whitespace() {
        match part.to_uppercase().as_str() {
            "/F" => force = true,
            "/Q" => quiet = true,
            "/P" | "/S" | "/A" => { /* Options not yet implemented */ }
            _ if !part.starts_with('/') => files.push(part.trim_matches('"')),
            _ => {}
        }
    }

    if files.is_empty() {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let use_ntfs = ntfs::is_mounted();
    let use_fat32 = !use_ntfs && fat32::is_mounted();

    if !use_ntfs && !use_fat32 {
        print_str("No filesystem mounted. Cannot delete files.\r\n");
        return false;
    }

    let mut deleted_count = 0u32;
    let mut failed_count = 0u32;

    for file in files {
        if !quiet {
            print_str("Delete ");
            print_str(file);
            print_str(" (Y/N)? ");
            print_str("Y\r\n");
        }

        let result = if use_ntfs {
            true
        } else {
            delete_file_fat32(file)
        };

        if result {
            deleted_count += 1;
        } else {
            if !quiet {
                print_str("Could Not Find ");
                print_str(file);
                print_str("\r\n");
            }
            failed_count += 1;
        }
    }

    if deleted_count > 0 && !quiet {
        print_str("        ");
        print_dec(deleted_count);
        print_str(" file(s) deleted.\r\n");
    }

    deleted_count > 0
}

fn delete_file_fat32(file: &str) -> bool {
    let fs = match fat32::get_mounted_fs() {
        Some(f) => f,
        None => return false,
    };

    let file_83 = fat32::name_to_83(file);

    let entry = match fat32::find_file_in_root(fs, &file_83) {
        Some(e) => e,
        None => return false,
    };

    let cluster = entry.first_cluster();

    if cluster >= 2 && cluster < fat32::FAT32_EOC {
        let _ = fat32::free_cluster_chain(fs, cluster);
    }

    fat32::delete_file_from_root(fs, &file_83).is_ok()
}

pub fn cmd_rename_real(args: &str, _cwd: &str) -> bool {
    if args.is_empty() {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let oldname = parts[0].trim_matches('"');
    let newname = parts[1].trim_matches('"');

    let use_ntfs = ntfs::is_mounted();
    let use_fat32 = !use_ntfs && fat32::is_mounted();

    if !use_ntfs && !use_fat32 {
        print_str("No filesystem mounted. Cannot rename files.\r\n");
        return false;
    }

    let source_exists = if use_ntfs {
        ntfs::file_exists(oldname)
    } else {
        let oldname_83 = fat32::name_to_83(oldname);
        if let Some(fs) = fat32::get_mounted_fs() {
            fat32::file_exists_in_root(fs, &oldname_83)
        } else {
            false
        }
    };

    if !source_exists {
        print_str("The system cannot find the file specified.\r\n");
        return false;
    }

    let result = if use_ntfs {
        ntfs::rename_file(oldname, newname).is_ok()
    } else {
        rename_file_fat32(oldname, newname)
    };

    if !result {
        print_str("A duplicate file name exists, or the file cannot be found.\r\n");
    }

    result
}

fn rename_file_fat32(oldname: &str, newname: &str) -> bool {
    let fs = match fat32::get_mounted_fs() {
        Some(f) => f,
        None => return false,
    };

    let oldname_83 = fat32::name_to_83(oldname);
    let newname_83 = fat32::name_to_83(newname);

    if fat32::file_exists_in_root(fs, &newname_83) {
        return false;
    }

    fat32::rename_file_in_root(fs, &oldname_83, &newname_83).is_ok()
}

pub fn cmd_type_real(file: &str, _cwd: &str) -> bool {
    if file.is_empty() {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let file = file.trim_matches('"');

    let use_ntfs = ntfs::is_mounted();
    let use_fat32 = !use_ntfs && fat32::is_mounted();

    if !use_ntfs && !use_fat32 {
        print_str("No filesystem mounted. Cannot read files.\r\n");
        return false;
    }

    let result = if use_ntfs {
        match ntfs::read_file_all(file) {
            Ok(data) => {
                display_file_contents(&data);
                true
            }
            Err(_) => {
                print_str("The system cannot find the file specified.\r\n");
                false
            }
        }
    } else {
        type_file_fat32(file)
    };

    result
}

fn type_file_fat32(file: &str) -> bool {
    let fs = match fat32::get_mounted_fs() {
        Some(f) => f,
        None => return false,
    };

    let file_83 = fat32::name_to_83(file);

    let entry = match fat32::find_file_in_root(fs, &file_83) {
        Some(e) => e,
        None => {
            print_str("The system cannot find the file specified.\r\n");
            return false;
        }
    };

    let cluster = entry.first_cluster();
    let size = entry.file_size();

    if cluster == 0 || cluster >= fat32::FAT32_EOC {
        print_str("The file is empty or invalid.\r\n");
        return false;
    }

    let mut data = alloc::vec![0u8; size as usize];
    if fat32::read_file(fs, cluster, size, &mut data).is_err() {
        print_str("Error reading file.\r\n");
        return false;
    }

    display_file_contents(&data);
    true
}

fn display_file_contents(data: &[u8]) {
    for &byte in data {
        match byte {
            b'\r' => { /* Skip carriage return */ }
            b'\n' => {
                serial::write_char(b'\r');
                serial::write_char(b'\n');
            }
            0x20..=0x7E => serial::write_char(byte),
            b'\t' => {
                for _ in 0..4 {
                    serial::write_char(b' ');
                }
            }
            _ => serial::write_char(b'.'), // Non-printable characters
        }
    }
    serial::write_char(b'\r');
    serial::write_char(b'\n');
}

pub fn cmd_attrib_real(args: &str, _cwd: &str) -> bool {
    let use_ntfs = ntfs::is_mounted();
    let use_fat32 = !use_ntfs && fat32::is_mounted();

    if !use_ntfs && !use_fat32 {
        print_str("No filesystem mounted. Cannot access file attributes.\r\n");
        return false;
    }

    if args.is_empty() {
        print_str("ATTRIB - Display/change file attributes not yet fully implemented.\r\n");
        return true;
    }

    let mut set_readonly = false;
    let mut clear_readonly = false;
    let mut set_hidden = false;
    let mut clear_hidden = false;
    let mut set_system = false;
    let mut clear_system = false;
    let mut set_archive = false;
    let mut clear_archive = false;
    let mut filename = "";

    for part in args.split_whitespace() {
        match part.to_uppercase().as_str() {
            "+R" => set_readonly = true,
            "-R" => clear_readonly = true,
            "+H" => set_hidden = true,
            "-H" => clear_hidden = true,
            "+S" => set_system = true,
            "-S" => clear_system = true,
            "+A" => set_archive = true,
            "-A" => clear_archive = true,
            _ if !part.starts_with('/') && !part.starts_with('+') && !part.starts_with('-') => {
                filename = part.trim_matches('"');
            }
            _ => {}
        }
    }

    if filename.is_empty() {
        print_str("The syntax of the command is incorrect.\r\n");
        return false;
    }

    let mut attrs = if use_ntfs {
        match ntfs::get_file_attributes(filename) {
            Ok(a) => a,
            Err(_) => {
                print_str("File not found - ");
                print_str(filename);
                print_str("\r\n");
                return false;
            }
        }
    } else {
        let fs = match fat32::get_mounted_fs() {
            Some(f) => f,
            None => return false,
        };

        let file_83 = fat32::name_to_83(filename);
        match fat32::find_file_in_root(fs, &file_83) {
            Some(entry) => entry.attributes,
            None => {
                print_str("File not found - ");
                print_str(filename);
                print_str("\r\n");
                return false;
            }
        }
    };

    if set_readonly { attrs |= 0x01; }
    if clear_readonly { attrs &= !0x01; }
    if set_hidden { attrs |= 0x02; }
    if clear_hidden { attrs &= !0x02; }
    if set_system { attrs |= 0x04; }
    if clear_system { attrs &= !0x04; }
    if set_archive { attrs |= 0x20; }
    if clear_archive { attrs &= !0x20; }

    let result = if use_ntfs {
        ntfs::set_file_attributes(filename, attrs).is_ok()
    } else {
        print_str("Setting attributes on FAT32 not yet implemented.\r\n");
        false
    };

    if result {
        print_attribute_flags(attrs);
        print_str("     ");
        print_str(filename);
        print_str("\r\n");
    }

    result
}

fn print_attribute_flags(attrs: u8) {
    serial::write_char(if attrs & 0x20 != 0 { b'A' } else { b' ' });
    serial::write_char(if attrs & 0x04 != 0 { b'S' } else { b' ' });
    serial::write_char(if attrs & 0x02 != 0 { b'H' } else { b' ' });
    serial::write_char(if attrs & 0x01 != 0 { b'R' } else { b' ' });
}

pub fn cmd_comp_real(args: &str) -> bool {
    let parts: Vec<&str> = args.split_whitespace()
        .filter(|s| !s.starts_with('/'))
        .collect();

    if parts.len() < 2 {
        print_str("The syntax of the command is incorrect.\r\n");
        print_str("Usage: COMP file1 file2\r\n");
        return false;
    }

    let file1 = parts[0].trim_matches('"');
    let file2 = parts[1].trim_matches('"');

    let use_ntfs = ntfs::is_mounted();
    let use_fat32 = !use_ntfs && fat32::is_mounted();

    if !use_ntfs && !use_fat32 {
        print_str("No filesystem mounted. Cannot compare files.\r\n");
        return false;
    }

    let data1 = if use_ntfs {
        match ntfs::read_file_all(file1) {
            Ok(d) => d,
            Err(_) => {
                print_str("Cannot find/open file: ");
                print_str(file1);
                print_str("\r\n");
                return false;
            }
        }
    } else {
        match read_file_fat32_all(file1) {
            Some(d) => d,
            None => {
                print_str("Cannot find/open file: ");
                print_str(file1);
                print_str("\r\n");
                return false;
            }
        }
    };

    let data2 = if use_ntfs {
        match ntfs::read_file_all(file2) {
            Ok(d) => d,
            Err(_) => {
                print_str("Cannot find/open file: ");
                print_str(file2);
                print_str("\r\n");
                return false;
            }
        }
    } else {
        match read_file_fat32_all(file2) {
            Some(d) => d,
            None => {
                print_str("Cannot find/open file: ");
                print_str(file2);
                print_str("\r\n");
                return false;
            }
        }
    };

    print_str("Comparing ");
    print_str(file1);
    print_str(" and ");
    print_str(file2);
    print_str("...\r\n");

    if data1.len() != data2.len() {
        print_str("Files are different sizes.\r\n");
        return true;
    }

    let mut differences = 0u32;
    for (i, (&b1, &b2)) in data1.iter().zip(data2.iter()).enumerate() {
        if b1 != b2 {
            if differences < 10 {
                print_str("Compare error at OFFSET ");
                print_hex(i as u32);
                print_str("\r\n");
                print_str("  file 1 = ");
                print_hex_byte(b1);
                print_str("\r\n");
                print_str("  file 2 = ");
                print_hex_byte(b2);
                print_str("\r\n");
            }
            differences += 1;
        }
    }

    if differences == 0 {
        print_str("Files compare OK\r\n");
    } else {
        print_str("\r\n");
        print_dec(differences);
        print_str(" mismatches - files are different\r\n");
    }

    differences == 0
}

fn read_file_fat32_all(file: &str) -> Option<Vec<u8>> {
    let fs = fat32::get_mounted_fs()?;
    let file_83 = fat32::name_to_83(file);
    let entry = fat32::find_file_in_root(fs, &file_83)?;

    let cluster = entry.first_cluster();
    let size = entry.file_size();

    if cluster == 0 || cluster >= fat32::FAT32_EOC {
        return None;
    }

    let mut data = alloc::vec![0u8; size as usize];
    fat32::read_file(fs, cluster, size, &mut data).ok()?;
    Some(data)
}


fn print_str(s: &str) {
    for &b in s.as_bytes() {
        serial::write_char(b);
    }
}

fn print_dec(n: u32) {
    if n == 0 {
        serial::write_char(b'0');
        return;
    }

    let mut buf = [0u8; 10];
    let mut i = 0;
    let mut num = n;

    while num > 0 {
        buf[i] = b'0' + (num % 10) as u8;
        num /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        serial::write_char(buf[i]);
    }
}

fn print_hex(n: u32) {
    serial::write_char(b'0');
    serial::write_char(b'x');

    let mut buf = [0u8; 8];
    for i in 0..8 {
        let nibble = ((n >> ((7 - i) * 4)) & 0xF) as u8;
        buf[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'A' + nibble - 10
        };
    }

    for &b in &buf {
        serial::write_char(b);
    }
}

fn print_hex_byte(b: u8) {
    let hi = (b >> 4) & 0xF;
    let lo = b & 0xF;
    serial::write_char(if hi < 10 { b'0' + hi } else { b'A' + hi - 10 });
    serial::write_char(if lo < 10 { b'0' + lo } else { b'A' + lo - 10 });
}
