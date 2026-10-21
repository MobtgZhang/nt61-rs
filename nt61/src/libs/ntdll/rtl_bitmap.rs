//! ntdll — RTL bitmap operations
//
//! Bitmap manipulation functions for efficient bit-level operations.
//! Used by the memory manager and other kernel subsystems.
//
//! References: MSDN Library "Windows 7" — RTL Bitmap.

use core::ptr;

#[repr(C)]
pub struct RtlBitmap {
    pub size_of_bit_map: u32,
    pub buffer: *mut u32,
}

impl RtlBitmap {
    pub const fn new() -> Self {
        Self {
            size_of_bit_map: 0,
            buffer: ptr::null_mut(),
        }
    }
}

pub unsafe extern "C" fn rtl_initialize_bit_map(
    bitmap_header: *mut RtlBitmap,
    bitmap_buffer: *mut u32,
    size_of_bit_map: u32,
) {
    if bitmap_header.is_null() || bitmap_buffer.is_null() {
        return;
    }
    (*bitmap_header).size_of_bit_map = size_of_bit_map;
    (*bitmap_header).buffer = bitmap_buffer;
}

pub unsafe extern "C" fn rtl_set_bit(bitmap_header: *mut RtlBitmap, bit_number: u32) {
    if bitmap_header.is_null() {
        return;
    }
    let bm = &*bitmap_header;
    if bit_number >= bm.size_of_bit_map {
        return;
    }
    let dword_index = bit_number / 32;
    let bit_index = bit_number % 32;
    *bm.buffer.add(dword_index as usize) |= 1u32 << bit_index;
}

pub unsafe extern "C" fn rtl_clear_bit(bitmap_header: *mut RtlBitmap, bit_number: u32) {
    if bitmap_header.is_null() {
        return;
    }
    let bm = &*bitmap_header;
    if bit_number >= bm.size_of_bit_map {
        return;
    }
    let dword_index = bit_number / 32;
    let bit_index = bit_number % 32;
    *bm.buffer.add(dword_index as usize) &= !(1u32 << bit_index);
}

pub unsafe extern "C" fn rtl_test_bit(bitmap_header: *mut RtlBitmap, bit_number: u32) -> u8 {
    if bitmap_header.is_null() {
        return 0;
    }
    let bm = &*bitmap_header;
    if bit_number >= bm.size_of_bit_map {
        return 0;
    }
    let dword_index = bit_number / 32;
    let bit_index = bit_number % 32;
    if (*bm.buffer.add(dword_index as usize) & (1u32 << bit_index)) != 0 {
        1
    } else {
        0
    }
}

pub unsafe extern "C" fn rtl_clear_all_bits(bitmap_header: *mut RtlBitmap) {
    if bitmap_header.is_null() {
        return;
    }
    let bm = &*bitmap_header;
    let dword_count = (bm.size_of_bit_map + 31) / 32;
    ptr::write_bytes(bm.buffer, 0, dword_count as usize);
}

pub unsafe extern "C" fn rtl_set_all_bits(bitmap_header: *mut RtlBitmap) {
    if bitmap_header.is_null() {
        return;
    }
    let bm = &*bitmap_header;
    let dword_count = (bm.size_of_bit_map + 31) / 32;
    ptr::write_bytes(bm.buffer, 0xFF, dword_count as usize);
}

pub unsafe extern "C" fn rtl_find_clear_bits(
    bitmap_header: *mut RtlBitmap,
    number_to_find: u32,
    hint_index: u32,
) -> u32 {
    if bitmap_header.is_null() {
        return 0xFFFF_FFFF;
    }
    let bm = &*bitmap_header;
    let start = hint_index.min(bm.size_of_bit_map);

    let mut count = 0u32;
    let mut start_pos = 0xFFFF_FFFF;

    for i in start..bm.size_of_bit_map {
        if rtl_test_bit(bitmap_header, i) == 0 {
            if count == 0 {
                start_pos = i;
            }
            count += 1;
            if count == number_to_find {
                return start_pos;
            }
        } else {
            count = 0;
            start_pos = 0xFFFF_FFFF;
        }
    }

    for i in 0..start {
        if rtl_test_bit(bitmap_header, i) == 0 {
            if count == 0 {
                start_pos = i;
            }
            count += 1;
            if count == number_to_find {
                return start_pos;
            }
        } else {
            count = 0;
            start_pos = 0xFFFF_FFFF;
        }
    }

    0xFFFF_FFFF
}

pub unsafe extern "C" fn rtl_find_set_bits(
    bitmap_header: *mut RtlBitmap,
    number_to_find: u32,
    hint_index: u32,
) -> u32 {
    if bitmap_header.is_null() {
        return 0xFFFF_FFFF;
    }
    let bm = &*bitmap_header;
    let start = hint_index.min(bm.size_of_bit_map);

    let mut count = 0u32;
    let mut start_pos = 0xFFFF_FFFF;

    for i in start..bm.size_of_bit_map {
        if rtl_test_bit(bitmap_header, i) != 0 {
            if count == 0 {
                start_pos = i;
            }
            count += 1;
            if count == number_to_find {
                return start_pos;
            }
        } else {
            count = 0;
            start_pos = 0xFFFF_FFFF;
        }
    }

    0xFFFF_FFFF
}

pub unsafe extern "C" fn rtl_set_bits(
    bitmap_header: *mut RtlBitmap,
    starting_index: u32,
    number_to_set: u32,
) {
    if bitmap_header.is_null() {
        return;
    }
    for i in 0..number_to_set {
        rtl_set_bit(bitmap_header, starting_index + i);
    }
}

pub unsafe extern "C" fn rtl_clear_bits(
    bitmap_header: *mut RtlBitmap,
    starting_index: u32,
    number_to_clear: u32,
) {
    if bitmap_header.is_null() {
        return;
    }
    for i in 0..number_to_clear {
        rtl_clear_bit(bitmap_header, starting_index + i);
    }
}

pub unsafe extern "C" fn rtl_number_of_set_bits(bitmap_header: *mut RtlBitmap) -> u32 {
    if bitmap_header.is_null() {
        return 0;
    }
    let bm = &*bitmap_header;
    let mut count = 0u32;
    for i in 0..bm.size_of_bit_map {
        if rtl_test_bit(bitmap_header, i) != 0 {
            count += 1;
        }
    }
    count
}

pub unsafe extern "C" fn rtl_number_of_clear_bits(bitmap_header: *mut RtlBitmap) -> u32 {
    if bitmap_header.is_null() {
        return 0;
    }
    let bm = &*bitmap_header;
    bm.size_of_bit_map - rtl_number_of_set_bits(bitmap_header)
}
