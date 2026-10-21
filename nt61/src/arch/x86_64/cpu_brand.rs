//! CPU brand string reporting from CPUID leaves 0x80000002..0x80000004.

#[inline]
fn cpuid(leaf: u32) -> [u32; 4] {
    let result = core::arch::x86_64::__cpuid(leaf);
    [result.eax, result.ebx, result.ecx, result.edx]
}

pub fn cpu_brand_string() -> Option<alloc::string::String> {
    let mut bytes = [0u8; 48];
    for (leaf_index, leaf) in [0x8000_0002u32, 0x8000_0003, 0x8000_0004]
        .into_iter()
        .enumerate()
    {
        let words = cpuid(leaf);
        for (word_index, word) in words.iter().enumerate() {
            let offset = leaf_index * 16 + word_index * 4;
            bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0 || !byte.is_ascii())
        .unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    Some(alloc::string::String::from_utf8_lossy(&bytes[..end]).into_owned())
}
