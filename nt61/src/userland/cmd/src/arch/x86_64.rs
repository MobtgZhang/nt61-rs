pub const SYS_PUTCHAR: u32 = 0x0202;
pub const SYS_CLEARSCREEN: u32 = 0x0205;
pub const SYS_RETURN_TO_FIRMWARE: u32 = 0x0214;
pub const SYS_READ_LINE: u32 = 0x0211;
pub const SYS_CMD_EXECUTE: u32 = 0x0215;
pub const SYS_PRINT_PROMPT: u32 = 0x0216;

#[unsafe(naked)]
unsafe extern "sysv64" fn syscall5_raw(
    number: u32,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> u64 {
    core::arch::naked_asm!(
        "mov r10, rsi",
        "mov r9, r8",
        "mov r8, rcx",
        "mov rax, rdi",
        "syscall",
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

#[inline(always)]
pub fn put_char(byte: u8) {
    syscall5(SYS_PUTCHAR, byte as usize, 0, 0, 0, 0);
}

/// Clear the text console (the console ABI's SYS_CLEARSCREEN; the
/// kernel routes it through the HAL text console and bootvid).
#[inline(always)]
pub fn clear_screen() {
    syscall5(SYS_CLEARSCREEN, 0, 0, 0, 0, 0);
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

#[inline]
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
