//! BCD (Boot Configuration Data) 运行时核心库
//!
//! 这个模块提供Windows系统运行时的BCD访问功能。
//!
//! ## 架构说明
//!
//! ### BCD代码分布
//!
//! 1. **启动时（Boot Time）- `src/boot/src/bcd*.rs`**
//!    - `bcd.rs` - UEFI环境下的BCD存储读取
//!    - `bcd_parser.rs` - BCD二进制解析器
//!    - `bcd_types.rs` - BCD类型和GUID定义
//!    - `bcd_registry.rs` - 注册表hive读取
//!    - `bcd_mailbox.rs` - bootmgr和winload之间的通信
//!    - 这些代码在UEFI环境（no_std）下运行
//!
//! 2. **运行时（Runtime）- 本模块 `src/bcd/`**
//!    - 复用boot/中的类型定义（通过条件编译）
//!    - 提供标准环境下的BCD访问接口
//!    - 通过注册表API访问BCD存储
//!    - 提供给系统工具（bcdedit, bcdboot）使用
//!
//! 3. **系统服务 - `src/libs/bcdsrv/`**
//!    - bcdsrv.dll的实现
//!    - 提供COM接口给用户态程序
//!
//! 4. **命令行工具**
//!    - `tools/bcdedit/` - bcdedit.exe
//!    - `tools/bcdboot/` - bcdboot.exe
//!
//! ## 代码复用策略
//!
//! - BCD类型和GUID定义在 `src/boot/src/bcd_types.rs` 中（唯一定义）
//! - 运行时代码通过 `use crate::boot_types::bcd_types` 复用类型定义
//! - 二进制解析逻辑也可以从boot/复用

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BcdGuid(pub [u8; 16]);

impl BcdGuid {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Display for BcdGuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.0[3], self.0[2], self.0[1], self.0[0],
            self.0[5], self.0[4],
            self.0[7], self.0[6],
            self.0[8], self.0[9],
            self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BcdElementType {
    Device = 0x11000001,
    Description = 0x12000001,
}

pub mod wellknown {
    use super::BcdGuid;

    pub const BOOT_MANAGER: BcdGuid = BcdGuid([
        0x9D, 0xA3, 0x12, 0x8B, 0xC1, 0x9A, 0x11, 0xD0,
        0x80, 0x5E, 0x00, 0xC0, 0x4F, 0xD9, 0x38, 0x9D,
    ]);
}

pub mod store;
pub mod object;
pub mod element;

pub use store::BcdStore;
pub use object::BcdObject;
pub use element::BcdElement;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BcdError {
    StoreNotFound = 0xC0000001,
    ObjectNotFound = 0xC0000002,
    ElementNotFound = 0xC0000003,
    AccessDenied = 0xC0000004,
    InvalidParameter = 0xC0000005,
    OperationFailed = 0xC0000006,
    StoreCorrupted = 0xC0000007,
}

pub type BcdResult<T> = Result<T, BcdError>;

pub mod paths {
    pub const SYSTEM_STORE: &str = r"\Registry\Machine\BCD00000000";

    pub const EFI_BCD_PATH: &str = r"\EFI\Microsoft\Boot\BCD";

    pub const BIOS_BCD_PATH: &str = r"\Boot\BCD";
}

pub fn initialize() -> BcdResult<()> {
    Ok(())
}
