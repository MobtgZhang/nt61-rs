use crate::arch;

const BANNER: &[u8] = b"Microsoft Windows [Version 6.1.7601]\r\n";
const COPYRIGHT: &[u8] =
    b"Copyright (c) 2009 Microsoft Corporation. All rights reserved.\r\n";
const ECHO_IS_ON: &[u8] = b"ECHO is on.\r\n";

const LINE_BUFFER_SIZE: usize = 256;

#[derive(Default)]
struct Shell;

enum Dispatch {
    Handled,
    External,
    Exit,
}

impl Shell {
    fn run(self) -> ! {
        print_bytes(BANNER);
        print_bytes(COPYRIGHT);
        loop {
            arch::print_prompt();

            let mut buffer = [0u8; LINE_BUFFER_SIZE];
            let length = arch::read_line(&mut buffer);
            let line = trim_line(&buffer[..length.min(buffer.len())]);

            match self.interpret(line) {
                Dispatch::Exit => break,
                Dispatch::Handled | Dispatch::External => {}
            }
        }

        arch::halt()
    }

    fn interpret(&self, line: &[u8]) -> Dispatch {
        if line.is_empty() {
            return Dispatch::Handled;
        }

        if line.eq_ignore_ascii_case(b"echo.") {
            print_bytes(b"\r\n");
            return Dispatch::Handled;
        }

        let command_end = line
            .iter()
            .position(|byte| *byte == b' ' || *byte == b'\t')
            .unwrap_or(line.len());
        let command = &line[..command_end];
        let arguments = &line[command_end..];

        if command.eq_ignore_ascii_case(b"cls") {
            arch::clear_screen();
            Dispatch::Handled
        } else if command.eq_ignore_ascii_case(b"ver") {
            print_bytes(BANNER);
            print_bytes(COPYRIGHT);
            Dispatch::Handled
        } else if command.eq_ignore_ascii_case(b"echo") {
            let arguments = trim_line(arguments);
            if arguments.is_empty() {
                print_bytes(ECHO_IS_ON);
            } else {
                print_bytes(arguments);
                print_bytes(b"\r\n");
            }
            Dispatch::Handled
        } else if command.eq_ignore_ascii_case(b"exit") {
            Dispatch::Exit
        } else if arch::execute_command(line) {
            Dispatch::Exit
        } else {
            Dispatch::External
        }
    }
}

fn trim_line(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 {
        let byte = line[end - 1];
        if byte == 0 || byte == b'\r' || byte == b'\n' {
            end -= 1;
        } else {
            break;
        }
    }
    &line[..end]
}

fn print_bytes(bytes: &[u8]) {
    for &byte in bytes {
        arch::put_char(byte);
    }
}

pub fn run() -> ! {
    Shell::default().run()
}
