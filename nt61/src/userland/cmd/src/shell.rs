use crate::arch;

const BANNER: &[u8] = b"Microsoft Windows [Version 6.1.7601]\r\n";
const COPYRIGHT: &[u8] = b"Copyright (c) 2009 Microsoft Corporation. All rights reserved.\r\n";

const LINE_BUFFER_SIZE: usize = 256;

#[derive(Default)]
struct Shell;

enum Dispatch {
    Handled,
    Exit,
}

impl Shell {
    fn run(self) -> ! {
        for &byte in BANNER {
            arch::put_char(byte);
        }
        for &byte in COPYRIGHT {
            arch::put_char(byte);
        }
        loop {
            arch::print_prompt();

            let mut buffer = [0u8; LINE_BUFFER_SIZE];
            let length = arch::read_line(&mut buffer);
            let line = trim_line(&buffer[..length.min(buffer.len())]);

            match self.interpret(line) {
                Dispatch::Exit => break,
                Dispatch::Handled => {}
            }
        }

        arch::halt()
    }

    fn interpret(&self, line: &[u8]) -> Dispatch {
        if line.is_empty() {
            return Dispatch::Handled;
        }

        if arch::execute_command(line) {
            Dispatch::Exit
        } else {
            Dispatch::Handled
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

pub fn run() -> ! {
    Shell::default().run()
}
