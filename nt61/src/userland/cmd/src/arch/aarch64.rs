pub const SYS_PUTCHAR: u32 = 0x0202;
pub const SYS_RETURN_TO_FIRMWARE: u32 = 0x0214;
pub const SYS_READ_LINE: u32 = 0x0211;
pub const SYS_CMD_EXECUTE: u32 = 0x0215;
pub const SYS_PRINT_PROMPT: u32 = 0x0216;

#[unsafe(naked)]
unsafe extern "C" fn syscall5_raw(
    number: u32,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> u64 {
    core::arch::naked_asm!(
        "mov x16, x0",
        "mov x0, x1",
        "mov x1, x2",
        "mov x2, x3",
        "mov x3, x4",
        "mov x4, x5",
        "mov x5, xzr",
        "mov x6, xzr",
        "mov x7, xzr",
        "svc #0",
        "mov x8, x0",
        "ret",
    );
}

#[inline(always)]
pub fn syscall5(
    number: u32,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> u64 {
    unsafe { syscall5_raw(number, arg0, arg1, arg2, arg3, arg4) }
}

#[inline(never)]
pub fn put_char(byte: u8) {
    syscall5(SYS_PUTCHAR, byte as usize, 0, 0, 0, 0);
}

#[inline(always)]
pub fn read_line(buffer: &mut [u8]) -> usize {
    syscall5(
        SYS_READ_LINE,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
    ) as usize
}

#[inline(never)]
pub fn execute_command(command: &[u8]) -> bool {
    let mut buffer = [0u8; 256];
    let length = command.len().min(buffer.len() - 1);
    buffer[..length].copy_from_slice(&command[..length]);
    syscall5(
        SYS_CMD_EXECUTE,
        buffer.as_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
    ) != 0
}

#[inline(always)]
pub fn print_prompt() {
    syscall5(SYS_PRINT_PROMPT, 0, 0, 0, 0, 0);
}

#[inline(always)]
pub fn return_to_firmware(mode: u32) -> ! {
    syscall5(SYS_RETURN_TO_FIRMWARE, mode as usize, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop()
    }
}

#[inline(always)]
pub fn halt() -> ! {
    return_to_firmware(0)
}
