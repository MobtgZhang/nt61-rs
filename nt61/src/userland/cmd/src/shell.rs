use crate::arch;

pub fn run() -> ! {
    print_bytes(b"Microsoft Windows [Version 6.1.7601]\r\n");
    print_bytes(b"(c) Microsoft Corporation. All rights reserved.\r\n\r\n");
    loop {
        arch::print_prompt();
        let mut buffer = [0u8; 256];
        let len = arch::read_line(&mut buffer);
        let line = &buffer[..len.min(buffer.len())];
        execute(line);
    }
}

fn execute(line: &[u8]) {
    let _ = arch::execute_command(line);
}

fn print_bytes(bytes: &[u8]) {
    for &byte in bytes {
        arch::put_char(byte);
    }
}
