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

// Simplified sprintf/printf - NOTE: These are minimal implementations

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sprintf(s: *mut CChar, format: *const CChar, _args: ...) -> CInt {
    if s.is_null() || format.is_null() {
        return -1;
    }

    let mut i = 0;
    loop {
        let ch = *format.add(i);
        if ch == 0 {
            break;
        }
        *s.add(i) = ch;
        i += 1;
    }
    *s.add(i) = 0;
    i as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn snprintf(
    s: *mut CChar,
    n: SizeT,
    format: *const CChar,
    _args: ...
) -> CInt {
    if s.is_null() || format.is_null() || n == 0 {
        return -1;
    }

    let mut i = 0;
    while i < n - 1 {
        let ch = *format.add(i);
        if ch == 0 {
            break;
        }
        *s.add(i) = ch;
        i += 1;
    }
    *s.add(i) = 0;
    i as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vsprintf(_s: *mut CChar, _format: *const CChar, _ap: ...) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vsnprintf(
    _s: *mut CChar,
    _n: SizeT,
    _format: *const CChar,
    _ap: ...
) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn printf(format: *const CChar, _args: ...) -> CInt {
    if format.is_null() {
        return -1;
    }

    let mut i = 0;
    loop {
        let ch = *format.add(i);
        if ch == 0 {
            break;
        }
        crate::kprint!("{}", ch as u8 as char);
        i += 1;
    }
    i as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn fprintf(stream: *mut FILE, format: *const CChar, _args: ...) -> CInt {
    if stream.is_null() || format.is_null() {
        return -1;
    }

    let mut i = 0;
    loop {
        let ch = *format.add(i);
        if ch == 0 {
            break;
        }
        fputc(ch as CInt, stream);
        i += 1;
    }
    i as CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vprintf(_format: *const CChar, _ap: ...) -> CInt {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn vfprintf(_stream: *mut FILE, _format: *const CChar, _ap: ...) -> CInt {
    0
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
    let temp_name = b"/tmp/tmpXXXXXX\0";
    fopen(
        temp_name.as_ptr() as *const CChar,
        b"w+b\0".as_ptr() as *const CChar,
    )
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn tmpnam(s: *mut CChar) -> *mut CChar {
    static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);
    TMP_COUNTER.fetch_add(1, Ordering::Relaxed);

    let template = b"/tmp/tmp00000000\0";
    for i in 0..template.len() {
        *s.add(i) = template[i] as CChar;
    }
    s
}
