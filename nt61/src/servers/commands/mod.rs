//! Real Command Implementations for NT6.1 CMD Shell
//!
//! This module provides REAL implementations of all Windows 7 commands,
//! eliminating simulation states. All commands interact with:
//! - Real NTFS/FAT32 filesystem (not simulated)
//! - Real network stack (TCP/IP, ICMP, ARP)
//! - Real disk partitions and volumes
//! - Real process and memory management
//!
//! Compliant with Windows 7 (NT 6.1.7601) specifications.
//! Reference: Windows 7 Command-Line Reference
//! No Microsoft proprietary code - clean-room implementation.

pub mod file_ops;      // File operations: COPY, MOVE, DEL, REN, TYPE, etc.
pub mod disk_ops;      // Disk operations: CHKDSK, FORMAT, LABEL, VOL, etc.
pub mod network;       // Network: PING, IPCONFIG, NETSTAT, ROUTE, ARP, etc.
pub mod process;       // Process: TASKLIST, TASKKILL, START, etc.
pub mod directory;     // Directory: DIR, CD, MD, RD, TREE, etc.
pub mod system;        // System: SYSTEMINFO, DATE, TIME, VER, etc.

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandResult {
    Success,
    Failure,
    Exit,
}

pub struct CommandContext<'a> {
    pub cwd: &'a mut [u8; 128],
    pub cwd_len: &'a mut usize,
    pub args: &'a str,
}

impl<'a> CommandContext<'a> {
    pub fn cwd_str(&self) -> &str {
        core::str::from_utf8(&self.cwd[..*self.cwd_len]).unwrap_or("C:\\")
    }
}

pub use file_ops::{
    cmd_copy_real, cmd_move_real, cmd_del_real, cmd_rename_real,
    cmd_type_real, cmd_attrib_real, cmd_comp_real,
};

pub use disk_ops::{
    cmd_vol_real, cmd_label_real, cmd_mountvol_real,
    cmd_chkdsk_real, cmd_diskpart_real, cmd_fsutil_real,
};

pub use network::{
    cmd_ipconfig_real, cmd_ping_real, cmd_netstat_real,
    cmd_route_real, cmd_arp_real, cmd_getmac_real,
};

pub use process::{
    cmd_tasklist_real, cmd_taskkill_real, cmd_start_real, cmd_sc_real,
};

pub use directory::{
    cmd_dir_real, cmd_mkdir_real, cmd_rmdir_real, cmd_tree_real,
};

pub use system::{
    cmd_systeminfo_real, cmd_ver_real, cmd_date_real, cmd_time_real,
    cmd_hostname_real, cmd_driverquery_real, cmd_set_real,
};
