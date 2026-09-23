//! Standard I/O and Formatted Output
//!
//! Implements file operations (fopen, fread, fwrite) and formatted I/O (printf, sprintf, scanf)
//!
//! Note: Variadic functions in this implementation use a simplified approach.
//! Full printf format string support would require extensive parsing logic.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use super::types::*;
use super::string::*;
use core::ptr;

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

static FILE_POOL: Lazy<Mutex<FilePoolData>> = Lazy::new(|| {
    Mutex::new(FilePoolData::new())
});
static FILE_POOL_INIT: AtomicBool = AtomicBool::new(false);

struct StandardStreams {
    stdin_file: FILE,
    stdout_file: FILE,
    stderr_file: FILE,
    stdin_ptr: *mut FILE,
    stdout_ptr: *mut FILE,
    stderr_ptr: *mut FILE,
}

unsafe impl Send for StandardStreams {}
unsafe impl Sync for StandardStreams {}

static STD_STREAMS: Lazy<Mutex<StandardStreams>> = Lazy::new(|| {
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

unsafe fn parse_mode(mode: *const c_char) -> u32 {
    let mut flags = 0u32;
    let mut i = 0;

    match *mode as u8 {
        b'r' => flags |= O_RDONLY,
        b'w' => flags |= O_WRONLY | O_CREAT | O_TRUNC,
        b'a' => flags |= O_WRONLY | O_CREAT | O_APPEND,
        _ => return 0,
    }
    i += 1;

    if *mode.add(i) == b'+' as c_char {
        flags = (flags & !O_RDONLY & !O_WRONLY) | O_RDWR;
        i += 1;
    }

    if *mode.add(i) == b'b' as c_char {
        i += 1;
    }

    flags
}

#[no_mangle]
pub unsafe extern "C" fn fopen(filename: *const c_char, mode: *const c_char) -> *mut FILE {
    if filename.is_null() || mode.is_null() {
        return ptr::null_mut();
    }

    init_file_pool();

    let flags = parse_mode(mode);
    if flags == 0 {
        return ptr::null_mut();
    }

    for i in 0..FILE_POOL_SIZE {
        if FILE_POOL[i].handle == 0 {
            let handle = super::io_stubs::open_file(filename, flags);
            if handle == 0 {
                return ptr::null_mut();
            }

            FILE_POOL[i].handle = handle;
            FILE_POOL[i].position = 0;
            FILE_POOL[i].eof = false;
            FILE_POOL[i].error = false;
            FILE_POOL[i].flags = flags;

            return &mut FILE_POOL[i] as *mut FILE;
        }
    }

    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn fclose(stream: *mut FILE) -> c_int {
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

#[no_mangle]
pub unsafe extern "C" fn fread(
    ptr: *mut c_void,
    size: size_t,
    count: size_t,
    stream: *mut FILE,
) -> size_t {
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

#[no_mangle]
pub unsafe extern "C" fn fwrite(
    ptr: *const c_void,
    size: size_t,
    count: size_t,
    stream: *mut FILE,
) -> size_t {
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

#[no_mangle]
pub unsafe extern "C" fn fseek(stream: *mut FILE, offset: c_long, whence: c_int) -> c_int {
    if stream.is_null() {
        return -1;
    }

    let file = &mut *stream;

    let new_pos = match whence {
        SEEK_SET => offset as usize,
        SEEK_CUR => (file.position as isize + offset as isize) as usize,
        SEEK_END => {
            match super::io_stubs::get_file_size(file.handle) {
                Ok(size) => (size as isize + offset as isize) as usize,
                Err(_) => {
                    file.error = true;
                    return -1;
                }
            }
        }
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

#[no_mangle]
pub unsafe extern "C" fn ftell(stream: *mut FILE) -> c_long {
    if stream.is_null() {
        return -1;
    }
    (*stream).position as c_long
}

#[no_mangle]
pub unsafe extern "C" fn rewind(stream: *mut FILE) {
    if !stream.is_null() {
        fseek(stream, 0, SEEK_SET);
        (*stream).error = false;
    }
}

#[no_mangle]
pub unsafe extern "C" fn feof(stream: *mut FILE) -> c_int {
    if stream.is_null() {
        return 0;
    }
    if (*stream).eof { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn ferror(stream: *mut FILE) -> c_int {
    if stream.is_null() {
        return 0;
    }
    if (*stream).error { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn clearerr(stream: *mut FILE) {
    if !stream.is_null() {
        (*stream).eof = false;
        (*stream).error = false;
    }
}

#[no_mangle]
pub unsafe extern "C" fn fflush(_stream: *mut FILE) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn fgetc(stream: *mut FILE) -> c_int {
    if stream.is_null() {
        return EOF;
    }
    let mut ch: u8 = 0;
    if fread(&mut ch as *mut u8 as *mut c_void, 1, 1, stream) == 1 {
        ch as c_int
    } else {
        EOF
    }
}

#[no_mangle]
pub unsafe extern "C" fn fputc(c: c_int, stream: *mut FILE) -> c_int {
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

#[no_mangle]
pub unsafe extern "C" fn fgets(s: *mut c_char, n: c_int, stream: *mut FILE) -> *mut c_char {
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
        *s.add(i as usize) = c as c_char;
        i += 1;
        if c == b'\n' as c_int {
            break;
        }
    }
    *s.add(i as usize) = 0;
    s
}

#[no_mangle]
pub unsafe extern "C" fn fputs(s: *const c_char, stream: *mut FILE) -> c_int {
    if s.is_null() || stream.is_null() {
        return EOF;
    }
    let len = strlen(s);
    if fwrite(s as *const c_void, 1, len, stream) == len {
        0
    } else {
        EOF
    }
}

#[no_mangle]
pub unsafe extern "C" fn getc(stream: *mut FILE) -> c_int {
    fgetc(stream)
}

#[no_mangle]
pub unsafe extern "C" fn putc(c: c_int, stream: *mut FILE) -> c_int {
    fputc(c, stream)
}

#[no_mangle]
pub unsafe extern "C" fn getchar() -> c_int {
    fgetc(stdin)
}

#[no_mangle]
pub unsafe extern "C" fn putchar(c: c_int) -> c_int {
    fputc(c, stdout)
}

#[no_mangle]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    if s.is_null() {
        return EOF;
    }
    if fputs(s, stdout) == EOF {
        return EOF;
    }
    if fputc(b'\n' as c_int, stdout) == EOF {
        return EOF;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn ungetc(c: c_int, stream: *mut FILE) -> c_int {
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

#[no_mangle]
pub unsafe extern "C" fn sprintf(s: *mut c_char, format: *const c_char, _args: ...) -> c_int {
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
    i as c_int
}

#[no_mangle]
pub unsafe extern "C" fn snprintf(s: *mut c_char, n: size_t, format: *const c_char, _args: ...) -> c_int {
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
    i as c_int
}

#[no_mangle]
pub unsafe extern "C" fn vsprintf(_s: *mut c_char, _format: *const c_char, _ap: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn vsnprintf(_s: *mut c_char, _n: size_t, _format: *const c_char, _ap: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn printf(format: *const c_char, _args: ...) -> c_int {
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
    i as c_int
}

#[no_mangle]
pub unsafe extern "C" fn fprintf(stream: *mut FILE, format: *const c_char, _args: ...) -> c_int {
    if stream.is_null() || format.is_null() {
        return -1;
    }

    let mut i = 0;
    loop {
        let ch = *format.add(i);
        if ch == 0 {
            break;
        }
        fputc(ch as c_int, stream);
        i += 1;
    }
    i as c_int
}

#[no_mangle]
pub unsafe extern "C" fn vprintf(_format: *const c_char, _ap: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn vfprintf(_stream: *mut FILE, _format: *const c_char, _ap: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn sscanf(_s: *const c_char, _format: *const c_char, _args: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn scanf(_format: *const c_char, _args: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn fscanf(_stream: *mut FILE, _format: *const c_char, _args: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn vsscanf(_s: *const c_char, _format: *const c_char, _ap: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn vscanf(_format: *const c_char, _ap: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn vfscanf(_stream: *mut FILE, _format: *const c_char, _ap: ...) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn remove(filename: *const c_char) -> c_int {
    if filename.is_null() {
        return -1;
    }
    match super::io_stubs::delete_file(filename) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rename(old: *const c_char, new: *const c_char) -> c_int {
    if old.is_null() || new.is_null() {
        return -1;
    }
    match super::io_stubs::rename_file(old, new) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn tmpfile() -> *mut FILE {
    let temp_name = b"/tmp/tmpXXXXXX\0";
    fopen(temp_name.as_ptr() as *const c_char, b"w+b\0".as_ptr() as *const c_char)
}

#[no_mangle]
pub unsafe extern "C" fn tmpnam(s: *mut c_char) -> *mut c_char {
    static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);
    TMP_COUNTER += 1;

    let template = b"/tmp/tmp00000000\0";
    for i in 0..template.len() {
        *s.add(i) = template[i] as c_char;
    }
    s
}
