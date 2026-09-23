//! BCD存储访问接口
//!
//! 提供运行时BCD存储的读写访问，通过注册表后端实现。

use super::{BcdError, BcdResult, BcdObject};
use crate::registry;
use alloc::string::String;
use alloc::vec::Vec;

pub struct BcdStore {
    registry_path: String,
    read_only: bool,
}

impl BcdStore {
    pub fn open_system_store() -> BcdResult<Self> {
        Self::open(super::paths::SYSTEM_STORE, false)
    }

    pub fn open_system_store_readonly() -> BcdResult<Self> {
        Self::open(super::paths::SYSTEM_STORE, true)
    }

    pub fn open(path: &str, read_only: bool) -> BcdResult<Self> {
        match registry::open_key(path) {
            Ok(_key) => Ok(Self {
                registry_path: String::from(path),
                read_only,
            }),
            Err(_) => Err(BcdError::StoreNotFound),
        }
    }

    pub fn enumerate_objects(&self) -> BcdResult<Vec<BcdObject>> {
        let mut objects = Vec::new();

        match registry::enumerate_subkeys(&self.registry_path) {
            Ok(subkeys) => {
                for subkey in subkeys {
                    if let Ok(obj) = BcdObject::from_registry(&self.registry_path, &subkey) {
                        objects.push(obj);
                    }
                }
            }
            Err(_) => return Err(BcdError::OperationFailed),
        }

        Ok(objects)
    }

    pub fn get_default_entry(&self) -> BcdResult<BcdObject> {
        let bootmgr_path = alloc::format!("{}\\{{bootmgr}}", self.registry_path);

        match registry::read_value(&bootmgr_path, "DisplayOrder") {
            Ok(value) => {
                // TODO: 解析GUID并返回对应的对象
                Err(BcdError::OperationFailed)
            }
            Err(_) => Err(BcdError::ElementNotFound),
        }
    }

    pub fn get_object(&self, guid: &super::BcdGuid) -> BcdResult<BcdObject> {
        let guid_str = alloc::format!("{}", guid);
        BcdObject::from_registry(&self.registry_path, &guid_str)
    }

    pub fn create_object(&mut self, guid: &super::BcdGuid, object_type: u32) -> BcdResult<BcdObject> {
        if self.read_only {
            return Err(BcdError::AccessDenied);
        }

        let guid_str = alloc::format!("{}", guid);
        let object_path = alloc::format!("{}\\{}", self.registry_path, guid_str);

        match registry::create_key(&object_path) {
            Ok(_) => {
                let _ = registry::set_value(&object_path, "Type", &object_type.to_le_bytes());
                BcdObject::from_registry(&self.registry_path, &guid_str)
            }
            Err(_) => Err(BcdError::OperationFailed),
        }
    }

    pub fn delete_object(&mut self, guid: &super::BcdGuid) -> BcdResult<()> {
        if self.read_only {
            return Err(BcdError::AccessDenied);
        }

        let guid_str = alloc::format!("{}", guid);
        let object_path = alloc::format!("{}\\{}", self.registry_path, guid_str);

        match registry::delete_key(&object_path) {
            Ok(_) => Ok(()),
            Err(_) => Err(BcdError::OperationFailed),
        }
    }

    pub fn export_to_file(&self, _file_path: &str) -> BcdResult<()> {
        // TODO: 实现BCD导出
        Err(BcdError::OperationFailed)
    }

    pub fn import_from_file(&mut self, _file_path: &str) -> BcdResult<()> {
        if self.read_only {
            return Err(BcdError::AccessDenied);
        }
        // TODO: 实现BCD导入
        Err(BcdError::OperationFailed)
    }
}
