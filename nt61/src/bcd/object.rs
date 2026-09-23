//! BCD对象表示
//!
//! 每个BCD对象对应一个启动项、设备或配置。

use super::{BcdError, BcdResult, BcdElement, BcdGuid};
use crate::registry;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BcdObjectType {
    Application = 0x10000000,
    Inheritable = 0x20000000,
    Device = 0x30000000,
}

pub struct BcdObject {
    pub guid: BcdGuid,
    pub object_type: u32,
    registry_path: String,
}

impl BcdObject {
    pub(crate) fn from_registry(store_path: &str, guid_str: &str) -> BcdResult<Self> {
        let object_path = alloc::format!("{}\\{}", store_path, guid_str);

        let object_type = match registry::read_value(&object_path, "Type") {
            Ok(data) => {
                if data.len() >= 4 {
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                } else {
                    return Err(BcdError::StoreCorrupted);
                }
            }
            Err(_) => return Err(BcdError::ObjectNotFound),
        };

        // TODO: 实现完整的GUID解析
        let guid = BcdGuid([0u8; 16]);

        Ok(Self {
            guid,
            object_type,
            registry_path: object_path,
        })
    }

    pub fn get_description(&self) -> BcdResult<String> {
        match registry::read_value(&self.registry_path, "Description") {
            Ok(data) => {
                let mut chars = Vec::new();
                for i in (0..data.len()).step_by(2) {
                    if i + 1 < data.len() {
                        let c = u16::from_le_bytes([data[i], data[i + 1]]);
                        if c == 0 {
                            break;
                        }
                        if let Some(ch) = char::from_u32(c as u32) {
                            chars.push(ch);
                        }
                    }
                }
                Ok(chars.into_iter().collect())
            }
            Err(_) => Err(BcdError::ElementNotFound),
        }
    }

    pub fn set_description(&mut self, description: &str) -> BcdResult<()> {
        let mut utf16_data = Vec::new();
        for c in description.encode_utf16() {
            utf16_data.push((c & 0xFF) as u8);
            utf16_data.push((c >> 8) as u8);
        }
        utf16_data.push(0);
        utf16_data.push(0);

        match registry::set_value(&self.registry_path, "Description", &utf16_data) {
            Ok(_) => Ok(()),
            Err(_) => Err(BcdError::OperationFailed),
        }
    }

    pub fn enumerate_elements(&self) -> BcdResult<Vec<BcdElement>> {
        let elements_path = alloc::format!("{}\\Elements", self.registry_path);
        let mut elements = Vec::new();

        match registry::enumerate_values(&elements_path) {
            Ok(values) => {
                for (name, data) in values {
                    if let Ok(element_type) = u32::from_str_radix(&name, 16) {
                        elements.push(BcdElement {
                            element_type,
                            data,
                        });
                    }
                }
            }
            Err(_) => return Err(BcdError::OperationFailed),
        }

        Ok(elements)
    }

    pub fn get_element(&self, element_type: u32) -> BcdResult<BcdElement> {
        let elements_path = alloc::format!("{}\\Elements", self.registry_path);
        let element_name = alloc::format!("{:08X}", element_type);

        match registry::read_value(&elements_path, &element_name) {
            Ok(data) => Ok(BcdElement {
                element_type,
                data,
            }),
            Err(_) => Err(BcdError::ElementNotFound),
        }
    }

    pub fn set_element(&mut self, element_type: u32, data: &[u8]) -> BcdResult<()> {
        let elements_path = alloc::format!("{}\\Elements", self.registry_path);
        let element_name = alloc::format!("{:08X}", element_type);

        let _ = registry::create_key(&elements_path);

        match registry::set_value(&elements_path, &element_name, data) {
            Ok(_) => Ok(()),
            Err(_) => Err(BcdError::OperationFailed),
        }
    }

    pub fn delete_element(&mut self, element_type: u32) -> BcdResult<()> {
        let elements_path = alloc::format!("{}\\Elements", self.registry_path);
        let element_name = alloc::format!("{:08X}", element_type);

        match registry::delete_value(&elements_path, &element_name) {
            Ok(_) => Ok(()),
            Err(_) => Err(BcdError::OperationFailed),
        }
    }
}
