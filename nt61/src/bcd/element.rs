//! BCD元素表示
//!
//! BCD元素是存储在对象中的配置值。

use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct BcdElement {
    pub element_type: u32,
    pub data: Vec<u8>,
}

impl BcdElement {
    pub fn new(element_type: u32, data: Vec<u8>) -> Self {
        Self {
            element_type,
            data,
        }
    }

    pub fn as_string(&self) -> Option<alloc::string::String> {
        let mut chars = Vec::new();
        for i in (0..self.data.len()).step_by(2) {
            if i + 1 < self.data.len() {
                let c = u16::from_le_bytes([self.data[i], self.data[i + 1]]);
                if c == 0 {
                    break;
                }
                if let Some(ch) = char::from_u32(c as u32) {
                    chars.push(ch);
                }
            }
        }
        Some(chars.into_iter().collect())
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.data.len() >= 8 {
            Some(u64::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
                self.data[4],
                self.data[5],
                self.data[6],
                self.data[7],
            ]))
        } else {
            None
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        self.as_u32().map(|v| v != 0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}
