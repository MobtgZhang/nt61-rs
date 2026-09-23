//! bcdboot.exe - 启动文件部署工具
//!
//! Windows Boot Files Deployment Tool
//!
//! ## 位置
//! Windows系统中：C:\Windows\System32\bcdboot.exe
//!
//! ## 功能
//!
//! bcdboot用于部署启动文件，主要用于：
//! - 安装Windows后配置启动分区
//! - 修复损坏的启动配置
//! - 创建双启动配置
//! - 在EFI/BIOS系统间迁移
//!
//! ## 命令示例
//!
//! ```bash
//! # 部署启动文件到系统分区
//! bcdboot C:\Windows
//!
//! # 指定启动分区
//! bcdboot C:\Windows /s S:
//!
//! # 指定固件类型
//! bcdboot C:\Windows /s S: /f UEFI
//! bcdboot C:\Windows /s S: /f BIOS
//!
//! # 添加启动项
//! bcdboot C:\Windows /addlast
//!
//! # 创建调试启动项
//! bcdboot C:\Windows /d
//! ```


use crate::kprintln;
use crate::bcd::{BcdStore, BcdGuid, BcdError};
use crate::libs::bcdsrv;
use crate::fs;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub fn print_help() {
    crate::kprintln!("BCDBoot - Boot File Deployment Tool\n");
    crate::kprintln!("Usage: bcdboot <source> [/s <volume>] [/f <firmware>] [options]\n");
    crate::kprintln!("Arguments:");
    crate::kprintln!("  <source>            - Windows installation directory");
    crate::kprintln!("\nOptions:");
    crate::kprintln!("  /s <volume>         - Target system partition (default: auto-detect)");
    crate::kprintln!("  /f <firmware>       - Firmware type: UEFI, BIOS, or ALL (default: ALL)");
    crate::kprintln!("  /l <locale>         - Boot files locale (default: system locale)");
    crate::kprintln!("  /d                  - Preserve existing BCD entries");
    crate::kprintln!("  /addlast            - Add Windows Boot Manager as last entry");
    crate::kprintln!("  /m <os_guid>        - Merge with existing OS loader entry");
    crate::kprintln!("  /?                  - Display this help");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareType {
    UEFI,
    BIOS,
    ALL,
}

pub struct BcdBootConfig {
    pub source_dir: String,
    pub target_volume: Option<String>,
    pub firmware_type: FirmwareType,
    pub preserve_bcd: bool,
    pub add_last: bool,
}

impl BcdBootConfig {
    pub fn new(source_dir: String) -> Self {
        Self {
            source_dir,
            target_volume: None,
            firmware_type: FirmwareType::ALL,
            preserve_bcd: false,
            add_last: false,
        }
    }
}

pub fn deploy_boot_files(config: &BcdBootConfig) -> Result<(), u32> {
    crate::kprintln!("BCDBoot - Deploying boot files...");
    crate::kprintln!("Source: {}", config.source_dir);

    if !fs::directory_exists(&config.source_dir) {
        crate::kprintln!("Error: Source directory does not exist");
        return Err(1);
    }

    let target = match &config.target_volume {
        Some(vol) => vol.clone(),
        None => {
            crate::kprintln!("Auto-detecting system partition...");
    // TODO: 实现自动检测逻辑);;
            String::from("S:")
        }
    };
    crate::kprintln!("Target: {}", target);

    match config.firmware_type {
        FirmwareType::UEFI => {
            crate::kprintln!("Firmware type: UEFI");
            deploy_uefi_files(&config.source_dir, &target)?;
        }
        FirmwareType::BIOS => {
            crate::kprintln!("Firmware type: BIOS");
            deploy_bios_files(&config.source_dir, &target)?;
        }
        FirmwareType::ALL => {
            crate::kprintln!("Firmware type: ALL");
            deploy_uefi_files(&config.source_dir, &target)?;
            deploy_bios_files(&config.source_dir, &target)?;
        }
    }

    crate::kprintln!("Updating BCD store...");
    update_bcd_store(config)?;

    crate::kprintln!("Boot files deployed successfully.");
    Ok(())
}

fn deploy_uefi_files(source: &str, target: &str) -> Result<(), u32> {
    crate::kprintln!("  Copying UEFI boot files...");

    let efi_path = alloc::format!("{}\\EFI\\Microsoft\\Boot", target);

    // TODO: 实现文件复制

    Ok(())
}

fn deploy_bios_files(source: &str, target: &str) -> Result<(), u32> {
    crate::kprintln!("  Copying BIOS boot files...");

    let boot_path = alloc::format!("{}\\Boot", target);

    // TODO: 实现文件复制

    Ok(())
}

fn update_bcd_store(config: &BcdBootConfig) -> Result<(), u32> {
    match bcdsrv::open_system_store() {
        Ok(store) => {
            // TODO: 实现BCD更新逻辑
            Ok(())
        }
        Err(_) => {
            crate::kprintln!("Error: Failed to open BCD store");
            Err(1)
        }
    }
}

pub fn main(args: &[String]) -> i32 {
    if args.len() < 1 {
        print_help();
        return 1;
    }

    let command = &args[0];

    if command == "/?" || command == "-?" || command == "/help" || command == "--help" {
        print_help();
        return 0;
    }

    let source_dir = command.clone();
    let mut config = BcdBootConfig::new(source_dir);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "/s" => {
                if i + 1 < args.len() {
                    config.target_volume = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    crate::kprintln!("Error: /s requires a volume argument");
                    return 1;
                }
            }
            "/f" => {
                if i + 1 < args.len() {
                    config.firmware_type = match args[i + 1].to_uppercase().as_str() {
                        "UEFI" => FirmwareType::UEFI,
                        "BIOS" => FirmwareType::BIOS,
                        "ALL" => FirmwareType::ALL,
                        _ => {
                            crate::kprintln!("Error: Invalid firmware type. Use UEFI, BIOS, or ALL");
                            return 1;
                        }
                    };
                    i += 2;
                } else {
                    crate::kprintln!("Error: /f requires a firmware type argument");
                    return 1;
                }
            }
            "/d" => {
                config.preserve_bcd = true;
                i += 1;
            }
            "/addlast" => {
                config.add_last = true;
                i += 1;
            }
            _ => {
                crate::kprintln!("Unknown option: {}", args[i]);
                return 1;
            }
        }
    }

    match deploy_boot_files(&config) {
        Ok(_) => 0,
        Err(code) => code as i32,
    }
}
