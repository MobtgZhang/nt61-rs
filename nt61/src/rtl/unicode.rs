//! Unicode Operations
//
//! Unicode string manipulation functions

/// Initialize unicode module
pub fn init() {
    // Unicode support always available
}

/// Convert UTF-8 to UTF-16 (simple version)
pub fn utf8_to_utf16(input: &str, output: &mut [u16]) -> usize {
    let len = input.len().min(output.len() - 1);
    let mut j = 0;
    for (i, c) in input.char_indices() {
        if i >= len {
            break;
        }
        output[j] = c as u16;
        j += 1;
    }
    output[j] = 0;
    j
}

/// Compare two unicode strings
pub fn wcscmp(a: &[u16], b: &[u16]) -> i32 {
    let len_a = a.iter().position(|&x| x == 0).unwrap_or(a.len());
    let len_b = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    
    let len = len_a.min(len_b);
    
    for i in 0..len {
        if a[i] != b[i] {
            return a[i] as i32 - b[i] as i32;
        }
    }
    
    if len_a < len_b {
        -1
    } else if len_a > len_b {
        1
    } else {
        0
    }
}

/// Get unicode string length
pub fn wcslen(s: &[u16]) -> usize {
    s.iter().position(|&x| x == 0).unwrap_or(s.len())
}

/// Copy unicode string
pub fn wcscpy(dest: &mut [u16], src: &[u16]) {
    let len = wcslen(src).min(dest.len() - 1);
    dest[..len].copy_from_slice(&src[..len]);
    dest[len] = 0;
}
