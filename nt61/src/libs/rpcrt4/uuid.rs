//! UUID generation and manipulation
//!
//! Implements UUID creation, string conversion, and comparison operations.

use super::types::{UUID, RPC_STATUS, RPC_S_OK, RPC_S_INVALID_STRING_UUID, RPC_S_OUT_OF_MEMORY};
use core::sync::atomic::{AtomicU64, Ordering};

static UUID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// In a real system, this would use cryptographic random sources.
#[no_mangle]
pub unsafe extern "C" fn UuidCreate(uuid: *mut UUID) -> RPC_STATUS {
    if uuid.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    let counter = UUID_COUNTER.fetch_add(1, Ordering::SeqCst);


    (*uuid).data1 = (counter as u32).wrapping_mul(0x9E3779B9);
    (*uuid).data2 = ((counter >> 32) as u16).wrapping_mul(0x9E37);
    (*uuid).data3 = 0x4000 | ((counter as u16) & 0x0FFF); // Version 4

    (*uuid).data4[0] = 0x80 | ((counter as u8) & 0x3F);
    (*uuid).data4[1] = ((counter >> 8) as u8).wrapping_mul(0xB9);
    (*uuid).data4[2] = ((counter >> 16) as u8).wrapping_mul(0x79);
    (*uuid).data4[3] = ((counter >> 24) as u8).wrapping_mul(0x37);
    (*uuid).data4[4] = ((counter >> 32) as u8).wrapping_mul(0x9E);
    (*uuid).data4[5] = ((counter >> 40) as u8).wrapping_mul(0x3B);
    (*uuid).data4[6] = (counter as u8).wrapping_mul(0xA7);
    (*uuid).data4[7] = ((counter >> 8) as u8).wrapping_mul(0x53);

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn UuidToStringW(uuid: *const UUID, string_uuid: *mut *mut u16) -> RPC_STATUS {
    if uuid.is_null() || string_uuid.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    let buffer = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        37 * 2, // 37 u16 characters
    ) as *mut u16;

    if buffer.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    let hex_chars = b"0123456789abcdef";
    let mut pos = 0;

    let write_hex_byte = |buf: *mut u16, p: &mut usize, byte: u8| {
        *buf.add(*p) = hex_chars[(byte >> 4) as usize] as u16;
        *p += 1;
        *buf.add(*p) = hex_chars[(byte & 0x0F) as usize] as u16;
        *p += 1;
    };

    write_hex_byte(buffer, &mut pos, ((*uuid).data1 >> 24) as u8);
    write_hex_byte(buffer, &mut pos, ((*uuid).data1 >> 16) as u8);
    write_hex_byte(buffer, &mut pos, ((*uuid).data1 >> 8) as u8);
    write_hex_byte(buffer, &mut pos, (*uuid).data1 as u8);

    *buffer.add(pos) = b'-' as u16;
    pos += 1;

    write_hex_byte(buffer, &mut pos, ((*uuid).data2 >> 8) as u8);
    write_hex_byte(buffer, &mut pos, (*uuid).data2 as u8);

    *buffer.add(pos) = b'-' as u16;
    pos += 1;

    write_hex_byte(buffer, &mut pos, ((*uuid).data3 >> 8) as u8);
    write_hex_byte(buffer, &mut pos, (*uuid).data3 as u8);

    *buffer.add(pos) = b'-' as u16;
    pos += 1;

    write_hex_byte(buffer, &mut pos, (*uuid).data4[0]);
    write_hex_byte(buffer, &mut pos, (*uuid).data4[1]);

    *buffer.add(pos) = b'-' as u16;
    pos += 1;

    for i in 2..8 {
        write_hex_byte(buffer, &mut pos, (*uuid).data4[i]);
    }

    *buffer.add(pos) = 0; // Null terminator

    *string_uuid = buffer;
    RPC_S_OK
}

fn parse_hex_digit(c: u16) -> Option<u8> {
    match c as u8 {
        b'0'..=b'9' => Some((c as u8) - b'0'),
        b'a'..=b'f' => Some((c as u8) - b'a' + 10),
        b'A'..=b'F' => Some((c as u8) - b'A' + 10),
        _ => None,
    }
}

#[no_mangle]
pub unsafe extern "C" fn UuidFromStringW(string_uuid: *const u16, uuid: *mut UUID) -> RPC_STATUS {
    if string_uuid.is_null() || uuid.is_null() {
        return RPC_S_INVALID_STRING_UUID;
    }

    let mut pos = 0;

    let parse_hex_byte = |s: *const u16, p: &mut usize| -> Option<u8> {
        let high = parse_hex_digit(*s.add(*p))?;
        *p += 1;
        let low = parse_hex_digit(*s.add(*p))?;
        *p += 1;
        Some((high << 4) | low)
    };

    let mut data1: u32 = 0;
    for _ in 0..4 {
        let byte = match parse_hex_byte(string_uuid, &mut pos) {
            Some(b) => b,
            None => return RPC_S_INVALID_STRING_UUID,
        };
        data1 = (data1 << 8) | (byte as u32);
    }

    if *string_uuid.add(pos) != b'-' as u16 {
        return RPC_S_INVALID_STRING_UUID;
    }
    pos += 1;

    let mut data2: u16 = 0;
    for _ in 0..2 {
        let byte = match parse_hex_byte(string_uuid, &mut pos) {
            Some(b) => b,
            None => return RPC_S_INVALID_STRING_UUID,
        };
        data2 = (data2 << 8) | (byte as u16);
    }

    if *string_uuid.add(pos) != b'-' as u16 {
        return RPC_S_INVALID_STRING_UUID;
    }
    pos += 1;

    let mut data3: u16 = 0;
    for _ in 0..2 {
        let byte = match parse_hex_byte(string_uuid, &mut pos) {
            Some(b) => b,
            None => return RPC_S_INVALID_STRING_UUID,
        };
        data3 = (data3 << 8) | (byte as u16);
    }

    if *string_uuid.add(pos) != b'-' as u16 {
        return RPC_S_INVALID_STRING_UUID;
    }
    pos += 1;

    let mut data4 = [0u8; 8];
    for i in 0..2 {
        data4[i] = match parse_hex_byte(string_uuid, &mut pos) {
            Some(b) => b,
            None => return RPC_S_INVALID_STRING_UUID,
        };
    }

    if *string_uuid.add(pos) != b'-' as u16 {
        return RPC_S_INVALID_STRING_UUID;
    }
    pos += 1;

    for i in 2..8 {
        data4[i] = match parse_hex_byte(string_uuid, &mut pos) {
            Some(b) => b,
            None => return RPC_S_INVALID_STRING_UUID,
        };
    }

    (*uuid).data1 = data1;
    (*uuid).data2 = data2;
    (*uuid).data3 = data3;
    (*uuid).data4 = data4;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn UuidCompare(
    uuid1: *const UUID,
    uuid2: *const UUID,
    status: *mut RPC_STATUS,
) -> i32 {
    if !status.is_null() {
        *status = RPC_S_OK;
    }

    if uuid1.is_null() && uuid2.is_null() {
        return 0;
    }
    if uuid1.is_null() {
        return -1;
    }
    if uuid2.is_null() {
        return 1;
    }

    if (*uuid1).data1 != (*uuid2).data1 {
        return if (*uuid1).data1 < (*uuid2).data1 { -1 } else { 1 };
    }
    if (*uuid1).data2 != (*uuid2).data2 {
        return if (*uuid1).data2 < (*uuid2).data2 { -1 } else { 1 };
    }
    if (*uuid1).data3 != (*uuid2).data3 {
        return if (*uuid1).data3 < (*uuid2).data3 { -1 } else { 1 };
    }

    for i in 0..8 {
        if (*uuid1).data4[i] != (*uuid2).data4[i] {
            return if (*uuid1).data4[i] < (*uuid2).data4[i] { -1 } else { 1 };
        }
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn UuidIsNil(uuid: *const UUID, status: *mut RPC_STATUS) -> i32 {
    if !status.is_null() {
        *status = RPC_S_OK;
    }

    if uuid.is_null() {
        return 1; // Treat null as nil
    }

    let is_nil = (*uuid).data1 == 0
        && (*uuid).data2 == 0
        && (*uuid).data3 == 0
        && (*uuid).data4.iter().all(|&b| b == 0);

    if is_nil { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn UuidCreateNil(uuid: *mut UUID) -> RPC_STATUS {
    if uuid.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    (*uuid).data1 = 0;
    (*uuid).data2 = 0;
    (*uuid).data3 = 0;
    (*uuid).data4 = [0; 8];

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn UuidEqual(
    uuid1: *const UUID,
    uuid2: *const UUID,
    status: *mut RPC_STATUS,
) -> i32 {
    let cmp = UuidCompare(uuid1, uuid2, status);
    if cmp == 0 { 1 } else { 0 }
}
