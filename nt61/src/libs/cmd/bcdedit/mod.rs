//! bcdedit.exe - BCD编辑工具
//!
//! Windows Boot Configuration Data (BCD) 命令行编辑器
//!
//! ## 位置
//! Windows系统中：C:\Windows\System32\bcdedit.exe
//!
//! ## 功能
//!
//! bcdedit允许管理员：
//! - 查看BCD存储中的启动配置
//! - 创建、修改、删除启动项
//! - 设置默认启动项
//! - 配置启动超时
//! - 管理启动顺序
//! - 导入/导出BCD配置
//!
//! ## 命令示例
//!
//! ```bash
//! # 显示所有启动项
//! bcdedit /enum
//!
//! # 显示当前配置
//! bcdedit /v
//!
//! # 设置默认启动项
//! bcdedit /default {guid}
//!
//! # 设置启动超时（秒）
//! bcdedit /timeout 30
//!
//! # 创建新启动项
//! bcdedit /create /d "Windows 7" /application osloader
//!
//! # 删除启动项
//! bcdedit /delete {guid}
//!
//! # 导出BCD配置
//! bcdedit /export C:\bcd-backup
//!
//! # 导入BCD配置
//! bcdedit /import C:\bcd-backup
//! ```


use crate::kprintln;
use crate::bcd::{BcdStore, BcdGuid, BcdError};
use crate::libs::bcdsrv;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub fn print_help() {
    crate::kprintln!("BCDEdit - Boot Configuration Data Store Editor\n");
    crate::kprintln!("Usage: bcdedit [/command] [arguments]\n");
    crate::kprintln!("Commands:");
    crate::kprintln!("  /enum [type]        - Enumerate entries");
    crate::kprintln!("  /v                  - Display all entries in detail");
    crate::kprintln!("  /default <id>       - Set default boot entry");
    crate::kprintln!("  /timeout <seconds>  - Set boot timeout");
    crate::kprintln!("  /displayorder       - Set display order");
    crate::kprintln!("  /create             - Create new entry");
    crate::kprintln!("  /delete <id>        - Delete entry");
    crate::kprintln!("  /set <id> <option>  - Set entry option");
    crate::kprintln!("  /export <file>      - Export BCD store");
    crate::kprintln!("  /import <file>      - Import BCD store");
    crate::kprintln!("  /store <file>       - Specify BCD store file");
    crate::kprintln!("  /?                  - Display this help");
}

pub fn enum_entries(store: &BcdStore) -> Result<(), u32> {
    crate::kprintln!("\nWindows Boot Manager");
    crate::kprintln!("--------------------");

    match store.enumerate_objects() {
        Ok(objects) => {
            for obj in objects {
                crate::kprintln!("identifier              {}", obj.guid);

                if let Ok(desc) = obj.get_description() {
                    crate::kprintln!("description             {}", desc);
                }

                crate::kprintln!("");
            }
            Ok(())
        }
        Err(_) => {
            crate::kprintln!("Error: Failed to enumerate BCD entries");
            Err(1)
        }
    }
}

pub fn main(args: &[String]) -> i32 {
    if args.len() < 1 {
        match bcdsrv::open_system_store() {
            Ok(store) => {
                if enum_entries(&store).is_err() {
                    return 1;
                }
            }
            Err(_) => {
                crate::kprintln!("Error: Unable to open system BCD store");
                crate::kprintln!("Run as administrator to access BCD");
                return 1;
            }
        }
        return 0;
    }

    let command = &args[0];

    match command.as_str() {
        "/?" | "-?" | "/help" | "--help" => {
            print_help();
            0
        }
        "/enum" => {
            match bcdsrv::open_system_store() {
                Ok(store) => {
                    if enum_entries(&store).is_err() {
                        1
                    } else {
                        0
                    }
                }
                Err(_) => {
                    crate::kprintln!("Error: Unable to open system BCD store");
                    1
                }
            }
        }
        "/v" => {
            crate::kprintln!("Verbose display not yet implemented");
            0
        }
        "/export" => {
            if args.len() < 2 {
                crate::kprintln!("Error: /export requires a file path");
                return 1;
            }
            crate::kprintln!("Export not yet implemented");
            0
        }
        "/import" => {
            if args.len() < 2 {
                crate::kprintln!("Error: /import requires a file path");
                return 1;
            }
            crate::kprintln!("Import not yet implemented");
            0
        }
        "/default" => {
            if args.len() < 2 {
                crate::kprintln!("Error: /default requires a GUID");
                return 1;
            }
            crate::kprintln!("Set default not yet implemented");
            0
        }
        "/timeout" => {
            if args.len() < 2 {
                crate::kprintln!("Error: /timeout requires a number of seconds");
                return 1;
            }
            crate::kprintln!("Set timeout not yet implemented");
            0
        }
        _ => {
            crate::kprintln!("Unknown command: {}", command);
            crate::kprintln!("Use /? for help");
            1
        }
    }
}
