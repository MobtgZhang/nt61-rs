//! String Operations
//
//! Kernel string manipulation functions

/// Initialize string module
pub fn init() {
    // String operations are always available
}

/// Compare two strings
pub fn strcmp(a: &[u8], b: &[u8]) -> i32 {
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

/// Compare two strings (case insensitive)
pub fn strcmpi(a: &[u8], b: &[u8]) -> i32 {
    let len_a = a.iter().position(|&x| x == 0).unwrap_or(a.len());
    let len_b = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    
    let len = len_a.min(len_b);
    
    for i in 0..len {
        let ca = a[i].to_ascii_lowercase();
        let cb = b[i].to_ascii_lowercase();
        if ca != cb {
            return ca as i32 - cb as i32;
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

/// Get string length
pub fn strlen(s: &[u8]) -> usize {
    s.iter().position(|&x| x == 0).unwrap_or(s.len())
}

/// Copy string
pub fn strcpy(dest: &mut [u8], src: &[u8]) {
    let len = strlen(src).min(dest.len() - 1);
    dest[..len].copy_from_slice(&src[..len]);
    dest[len] = 0;
}

/// Copy string with limit
pub fn strncpy(dest: &mut [u8], src: &[u8], n: usize) {
    let len = strlen(src).min(n).min(dest.len() - 1);
    dest[..len].copy_from_slice(&src[..len]);
    dest[len] = 0;
}

/// Concatenate strings
pub fn strcat(dest: &mut [u8], src: &[u8]) {
    let dest_len = strlen(dest);
    strcpy(&mut dest[dest_len..], src);
}