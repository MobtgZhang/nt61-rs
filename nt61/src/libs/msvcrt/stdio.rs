//! Standard I/O and Formatted Output
//!
//! Implements file operations (fopen, fread, fwrite) and formatted I/O (printf, sprintf, scanf)
//!
//! Note: Variadic functions in this implementation use a simplified approach.
//! Full printf format string support would require extensive parsing logic.

use super::string::*;
use super::types::*;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Lazy, Mutex};

extern crate alloc;
use alloc::vec::Vec;
use core::ffi::VaList;

const FILE_POOL_SIZE: usize = 64;

struct FilePoolData {
    files: [FILE; FILE_POOL_SIZE],
}

impl FilePoolData {
    const fn new() -> Self {
        Self {
            files: [FILE::new(); FILE_POOL_SIZE],
        }
    }
}

static FILE_POOL: Lazy<Mutex<FilePoolData>> = Lazy::new(|| Mutex::new(FilePoolData::new()));
static FILE_POOL_INIT: AtomicBool = AtomicBool::new(false);

pub struct StandardStreams {
    stdin_file: FILE,
    stdout_file: FILE,
    stderr_file: FILE,
    pub stdin_ptr: *mut FILE,
    pub stdout_ptr: *mut FILE,
    pub stderr_ptr: *mut FILE,
}

unsafe impl Send for StandardStreams {}
unsafe impl Sync for StandardStreams {}

pub static STD_STREAMS: Lazy<Mutex<StandardStreams>> = Lazy::new(|| {
    let mut streams = StandardStreams {
        stdin_file: FILE::new(),
        stdout_file: FILE::new(),
        stderr_file: FILE::new(),
        stdin_ptr: ptr::null_mut(),
        stdout_ptr: ptr::null_mut(),
        stderr_ptr: ptr::null_mut(),
    };
    streams.stdin_file.handle = 0;
    streams.stdout_file.handle = 1;
    streams.stderr_file.handle = 2;
    Mutex::new(streams)
});

static mut STDIN_STREAM: FILE = FILE::new();
static mut STDOUT_STREAM: FILE = FILE::new();
pub static mut STDERR_STREAM: FILE = FILE::new();

unsafe fn stdin() -> *mut FILE {
    STDIN_STREAM.handle = 0;
    core::ptr::addr_of_mut!(STDIN_STREAM)
}

unsafe fn stdout() -> *mut FILE {
    STDOUT_STREAM.handle = 1;
    core::ptr::addr_of_mut!(STDOUT_STREAM)
}

pub unsafe fn stderr() -> *mut FILE {
    STDERR_STREAM.handle = 2;
    core::ptr::addr_of_mut!(STDERR_STREAM)
}

unsafe fn init_file_pool() {
    if !FILE_POOL_INIT.load(Ordering::Relaxed) {
        FILE_POOL_INIT.store(true, Ordering::Relaxed);
    }
}

const O_RDONLY: u32 = 0x0001;
const O_WRONLY: u32 = 0x0002;
const O_RDWR: u32 = 0x0004;
const O_APPEND: u32 = 0x0008;
const O_CREAT: u32 = 0x0010;
const O_TRUNC: u32 = 0x0020;

unsafe fn parse_mode(mode: *const CChar) -> u32 {
    let mut flags = 0u32;
    let mut i = 0;

    match *mode as u8 {
        b'r' => flags |= O_RDONLY,
        b'w' => flags |= O_WRONLY | O_CREAT | O_TRUNC,
        b'a' => flags |= O_WRONLY | O_CREAT | O_APPEND,
        _ => return 0,
    }
    i += 1;

    if *mode.add(i) == b'+' as CChar {
        flags = (flags & !O_RDONLY & !O_WRONLY) | O_RDWR;
        i += 1;
    }

    if *mode.add(i) == b'b' as CChar {}

    flags
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fopen(filename: *const CChar, mode: *const CChar) -> *mut FILE {
    if filename.is_null() || mode.is_null() {
        return ptr::null_mut();
    }

    init_file_pool();

    let flags = parse_mode(mode);
    if flags == 0 {
        return ptr::null_mut();
    }

    for i in 0..FILE_POOL_SIZE {
        let mut pool = FILE_POOL.lock();
        if pool.files[i].handle == 0 {
            let handle = super::io_stubs::open_file(filename, flags);
            if handle == 0 {
                return ptr::null_mut();
            }

            pool.files[i].handle = handle;
            pool.files[i].position = 0;
            pool.files[i].eof = false;
            pool.files[i].error = false;
            pool.files[i].flags = flags;

            return pool.files.as_mut_ptr().wrapping_add(i);
        }
    }

    ptr::null_mut()
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fclose(stream: *mut FILE) -> CInt {
    if stream.is_null() {
        return EOF;
    }

    let file = &mut *stream;
    if file.handle <= 2 {
        return 0;
    }

    fflush(stream);
    super::io_stubs::close_file(file.handle);

    file.handle = 0;
    file.position = 0;
    file.eof = false;
    file.error = false;

    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fread(
    ptr: *mut c_void,
    size: SizeT,
    count: SizeT,
    stream: *mut FILE,
) -> SizeT {
    if ptr.is_null() || stream.is_null() || size == 0 || count == 0 {
        return 0;
    }

    let file = &mut *stream;
    let total_size = size * count;
    let buffer = core::slice::from_raw_parts_mut(ptr as *mut u8, total_size);

    match super::io_stubs::read_file(file.handle, buffer) {
        Ok(bytes_read) => {
            if bytes_read == 0 {
                file.eof = true;
            }
            file.position += bytes_read;
            bytes_read / size
        }
        Err(_) => {
            file.error = true;
            0
        }
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fwrite(
    ptr: *const c_void,
    size: SizeT,
    count: SizeT,
    stream: *mut FILE,
) -> SizeT {
    if ptr.is_null() || stream.is_null() || size == 0 || count == 0 {
        return 0;
    }

    let file = &mut *stream;
    let total_size = size * count;

    if file.handle == 1 || file.handle == 2 {
        let bytes = core::slice::from_raw_parts(ptr as *const u8, total_size);
        for &byte in bytes {
            crate::kprint!("{}", byte as char);
        }
        file.position += total_size;
        return count;
    }

    let buffer = core::slice::from_raw_parts(ptr as *const u8, total_size);
    match super::io_stubs::write_file(file.handle, buffer) {
        Ok(bytes_written) => {
            file.position += bytes_written;
            bytes_written / size
        }
        Err(_) => {
            file.error = true;
            0
        }
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fseek(stream: *mut FILE, offset: CLong, whence: CInt) -> CInt {
    if stream.is_null() {
        return -1;
    }

    let file = &mut *stream;

    let new_pos = match whence {
        SEEK_SET => offset as usize,
        SEEK_CUR => (file.position as isize + offset as isize) as usize,
        SEEK_END => match super::io_stubs::get_file_size(file.handle) {
            Ok(size) => (size as isize + offset as isize) as usize,
            Err(_) => {
                file.error = true;
                return -1;
            }
        },
        _ => return -1,
    };

    match super::io_stubs::seek_file(file.handle, new_pos) {
        Ok(_) => {
            file.position = new_pos;
            file.eof = false;
            0
        }
        Err(_) => {
            file.error = true;
            -1
        }
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn ftell(stream: *mut FILE) -> CLong {
    if stream.is_null() {
        return -1;
    }
    (*stream).position as CLong
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rewind(stream: *mut FILE) {
    if !stream.is_null() {
        fseek(stream, 0, SEEK_SET);
        (*stream).error = false;
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn feof(stream: *mut FILE) -> CInt {
    if stream.is_null() {
        return 0;
    }
    if (*stream).eof {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn ferror(stream: *mut FILE) -> CInt {
    if stream.is_null() {
        return 0;
    }
    if (*stream).error {
        1
    } else {
        0
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn clearerr(stream: *mut FILE) {
    if !stream.is_null() {
        (*stream).eof = false;
        (*stream).error = false;
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fflush(_stream: *mut FILE) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fgetc(stream: *mut FILE) -> CInt {
    if stream.is_null() {
        return EOF;
    }
    let mut ch: u8 = 0;
    if fread(&mut ch as *mut u8 as *mut c_void, 1, 1, stream) == 1 {
        ch as CInt
    } else {
        EOF
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fputc(c: CInt, stream: *mut FILE) -> CInt {
    if stream.is_null() {
        return EOF;
    }
    let ch = c as u8;
    if fwrite(&ch as *const u8 as *const c_void, 1, 1, stream) == 1 {
        c
    } else {
        EOF
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fgets(s: *mut CChar, n: CInt, stream: *mut FILE) -> *mut CChar {
    if s.is_null() || stream.is_null() || n <= 0 {
        return ptr::null_mut();
    }

    let mut i = 0;
    while i < (n - 1) {
        let c = fgetc(stream);
        if c == EOF {
            if i == 0 {
                return ptr::null_mut();
            }
            break;
        }
        *s.add(i as usize) = c as CChar;
        i += 1;
        if c == b'\n' as CInt {
            break;
        }
    }
    *s.add(i as usize) = 0;
    s
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fputs(s: *const CChar, stream: *mut FILE) -> CInt {
    if s.is_null() || stream.is_null() {
        return EOF;
    }
    let len = msvcrt_strlen_c(s);
    if fwrite(s as *const c_void, 1, len, stream) == len {
        0
    } else {
        EOF
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn getc(stream: *mut FILE) -> CInt {
    fgetc(stream)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn putc(c: CInt, stream: *mut FILE) -> CInt {
    fputc(c, stream)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn getchar() -> CInt {
    fgetc(stdin())
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn putchar(c: CInt) -> CInt {
    fputc(c, stdout())
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn puts(s: *const CChar) -> CInt {
    if s.is_null() {
        return EOF;
    }
    if fputs(s, stdout()) == EOF {
        return EOF;
    }
    if fputc(b'\n' as CInt, stdout()) == EOF {
        return EOF;
    }
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn ungetc(c: CInt, stream: *mut FILE) -> CInt {
    if stream.is_null() || c == EOF {
        return EOF;
    }
    let file = &mut *stream;
    if file.position > 0 {
        file.position -= 1;
        file.eof = false;
        c
    } else {
        EOF
    }
}

// Common printf formatting. This intentionally supports the subset used by
// MSVCRT programs rather than guessing the ABI of arbitrary conversion types.
unsafe fn format_va_list(format: *const CChar, mut args: VaList<'_>) -> Vec<u8> {
    const FORMAT_LIMIT: usize = 1024 * 1024;
    let mut output = Vec::new();
    let mut position = 0usize;

    while position < FORMAT_LIMIT {
        let byte = *format.add(position) as u8;
        position += 1;
        if byte == 0 {
            break;
        }
        if byte != b'%' {
            output.push(byte);
            continue;
        }

        let start = position - 1;
        let mut next = position;
        let mut spec_end = None;
        while next < FORMAT_LIMIT {
            let spec_byte = *format.add(next) as u8;
            next += 1;
            if spec_byte == 0 {
                break;
            }
            if spec_byte.is_ascii_alphabetic() || spec_byte == b'%' {
                spec_end = Some(next);
                break;
            }
        }

        let Some(spec_end) = spec_end else {
            output.push(b'%');
            break;
        };
        let specifier = *format.add(spec_end - 1) as u8;
        let spec_bytes: Vec<u8> = core::slice::from_raw_parts(format.add(start), spec_end - start)
            .iter()
            .map(|byte| *byte as u8)
            .collect();
        position = spec_end;

        if specifier == b'%' {
            output.push(b'%');
            continue;
        }

        let mut long = false;
        let mut index = start + 1;
        while index + 1 < spec_end {
            let modifier = *format.add(index) as u8;
            let following = *format.add(index + 1) as u8;
            if modifier == b'l' && (following == b'l' || following.is_ascii_alphabetic()) {
                long = true;
                break;
            }
            index += 1;
        }

        match specifier {
            b'd' | b'i' => {
                let value = if long {
                    args.next_arg::<i64>()
                } else {
                    args.next_arg::<i32>() as i64
                };
                write_signed(&mut output, value, &spec_bytes[1..spec_end - 1]);
            }
            b'u' | b'x' | b'X' => {
                let value = if long {
                    args.next_arg::<u64>()
                } else {
                    args.next_arg::<u32>() as u64
                };
                let (base, uppercase) = if specifier == b'u' {
                    (10, false)
                } else {
                    (16, specifier == b'X')
                };
                write_unsigned(
                    &mut output,
                    value,
                    base,
                    uppercase,
                    &spec_bytes[1..spec_end - 1],
                );
            }
            b'c' => output.push(args.next_arg::<CInt>() as u8),
            b's' => {
                let string = args.next_arg::<*const CChar>();
                if string.is_null() {
                    output.extend_from_slice(b"(null)");
                } else {
                    let mut index = 0usize;
                    while index < FORMAT_LIMIT && *string.add(index) != 0 {
                        output.push(*string.add(index) as u8);
                        index += 1;
                    }
                }
            }
            b'p' => {
                let pointer = args.next_arg::<usize>();
                output.extend_from_slice(b"0x");
                for shift in (0..usize::BITS).step_by(4).rev() {
                    let digit = ((pointer >> shift) & 0xF) as usize;
                    output.push(b"0123456789abcdef"[digit]);
                }
            }
            _ => output.extend_from_slice(&spec_bytes),
        }
    }

    output
}

fn parse_width(spec: &[u8]) -> Option<usize> {
    let mut index = 0usize;
    while matches!(spec.first(), Some(b'-' | b'+' | b' ' | b'#' | b'0')) {
        index += 1;
    }
    let mut digits = index;
    while digits < spec.len() && spec[digits].is_ascii_digit() {
        digits += 1;
    }
    if digits == index {
        return None;
    }
    let mut width = 0usize;
    for digit in &spec[index..digits] {
        width = width
            .saturating_mul(10)
            .saturating_add((digit - b'0') as usize);
    }
    Some(width)
}

fn write_signed(output: &mut Vec<u8>, value: i64, spec: &[u8]) {
    let width = parse_width(spec).unwrap_or(0);
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut digits = Vec::new();
    if magnitude == 0 {
        digits.push(b'0');
    }
    while magnitude > 0 {
        digits.push(b'0' + (magnitude % 10) as u8);
        magnitude /= 10;
    }
    let total_width = digits.len() + usize::from(negative);
    let padding = width.saturating_sub(total_width);
    if negative {
        output.push(b'-');
    }
    output.extend(core::iter::repeat_n(b'0', padding));
    output.extend(digits.iter().rev());
}

fn write_unsigned(output: &mut Vec<u8>, value: u64, base: u32, uppercase: bool, spec: &[u8]) {
    let width = parse_width(spec).unwrap_or(0);
    let digits = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut chars = Vec::new();
    if value == 0 {
        chars.push(b'0');
    }
    let mut remaining = value;
    while remaining > 0 {
        chars.push(digits[(remaining % base as u64) as usize]);
        remaining /= base as u64;
    }
    output.extend(core::iter::repeat_n(
        b'0',
        width.saturating_sub(chars.len()),
    ));
    output.extend(chars.iter().rev());
}

fn write_kprint_bytes(output: &[u8]) {
    #[cfg(target_arch = "riscv64")]
    {
        crate::hal::serial::write_string_always("[printf bytes] ptr=");
        crate::hal::serial::write_hex_u64_always(output.as_ptr() as u64);
        crate::hal::serial::write_string_always(" len=");
        crate::hal::serial::write_hex_u64_always(output.len() as u64);
        crate::hal::serial::write_string_always("\r\n");
    }
    for byte in output {
        crate::kprint!("{}", *byte as char);
    }
}

fn copy_formatted(target: *mut CChar, size: usize, output: &[u8]) -> CInt {
    let write_size = output.len().min(size.saturating_sub(1));
    for (index, byte) in output[..write_size].iter().enumerate() {
        unsafe { *target.add(index) = *byte as CChar };
    }
    unsafe { *target.add(write_size) = 0 };
    output.len() as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sprintf(s: *mut CChar, format: *const CChar, _args: ...) -> CInt {
    if s.is_null() || format.is_null() {
        return -1;
    }
    let output = format_va_list(format, _args);
    copy_formatted(s, usize::MAX, &output)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn snprintf(
    s: *mut CChar,
    n: SizeT,
    format: *const CChar,
    args: ...
) -> CInt {
    if s.is_null() || format.is_null() || n == 0 {
        return -1;
    }
    let output = format_va_list(format, args);
    copy_formatted(s, n, &output)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vsprintf(s: *mut CChar, format: *const CChar, ap: VaList<'_>) -> CInt {
    if s.is_null() || format.is_null() {
        return -1;
    }
    let output = format_va_list(format, ap);
    copy_formatted(s, usize::MAX, &output)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vsnprintf(
    s: *mut CChar,
    n: SizeT,
    format: *const CChar,
    ap: VaList<'_>,
) -> CInt {
    if s.is_null() || format.is_null() || n == 0 {
        return -1;
    }
    let output = format_va_list(format, ap);
    copy_formatted(s, n, &output)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn printf(format: *const CChar, _args: ...) -> CInt {
    if format.is_null() {
        return -1;
    }
    let output = format_va_list(format, _args);
    write_kprint_bytes(&output);
    output.len() as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fprintf(stream: *mut FILE, format: *const CChar, _args: ...) -> CInt {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    let output = format_va_list(format, _args);
    let mut written = 0usize;
    for byte in output {
        if fputc(byte as CInt, stream) == EOF {
            break;
        }
        written += 1;
    }
    written as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vprintf(format: *const CChar, ap: VaList<'_>) -> CInt {
    if format.is_null() {
        return -1;
    }
    let output = format_va_list(format, ap);
    write_kprint_bytes(&output);
    output.len() as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vfprintf(stream: *mut FILE, format: *const CChar, ap: VaList<'_>) -> CInt {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    let output = format_va_list(format, ap);
    let mut written = 0usize;
    for byte in output {
        if fputc(byte as CInt, stream) == EOF {
            break;
        }
        written += 1;
    }
    written as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sscanf(_s: *const CChar, _format: *const CChar, _args: ...) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn scanf(_format: *const CChar, _args: ...) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fscanf(_stream: *mut FILE, _format: *const CChar, _args: ...) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vsscanf(_s: *const CChar, _format: *const CChar, _ap: ...) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vscanf(_format: *const CChar, _ap: ...) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vfscanf(_stream: *mut FILE, _format: *const CChar, _ap: ...) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn remove(filename: *const CChar) -> CInt {
    if filename.is_null() {
        return -1;
    }
    match super::io_stubs::delete_file(filename) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rename(old: *const CChar, new: *const CChar) -> CInt {
    if old.is_null() || new.is_null() {
        return -1;
    }
    match super::io_stubs::rename_file(old, new) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn tmpfile() -> *mut FILE {
    // Windows NT 6.1 places temp files in the system temp directory
    // (%TEMP%), not a POSIX /tmp path.
    let temp_name = b"C:\\Windows\\Temp\\tmpXXXXXX\0";
    fopen(
        temp_name.as_ptr() as *const CChar,
        b"w+b\0".as_ptr() as *const CChar,
    )
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn tmpnam(s: *mut CChar) -> *mut CChar {
    static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

    let template = b"C:\\Windows\\Temp\\tmp00000000\0";
    // Generate a unique suffix from the counter (6 decimal digits
    // into the last 6 bytes of "tmp00000000").
    let counter = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let suffix = alloc::format!("{:06}", counter & 0xFFFFF);
    let suffix_bytes = suffix.as_bytes();
    for i in 0..template.len() {
        // Replace the six zero bytes at positions 20..=25 with the
        // counter digits.
        if i >= 21 && i <= 26 && (i - 21) < suffix_bytes.len() {
            *s.add(i) = suffix_bytes[i - 21] as CChar;
        } else {
            *s.add(i) = template[i] as CChar;
        }
    }
    s
}
