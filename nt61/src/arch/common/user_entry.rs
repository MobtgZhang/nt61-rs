//! Architecture-common Ring-0 to Ring-3 entry API.
//!
//! Callers only use the functions in this module. ISA-specific
//! instructions, processor state, and privilege transitions live in
//! `arch/<isa>/user_entry.rs`.

/// Machine code used by the phase-0 ring-transition smoke stub.
///
/// The bytes intentionally loop forever after issuing the marker
/// syscall; ownership of ISA-specific encodings belongs here rather
/// than in user-mode subsystem code.
pub const MINIMAL_USER_ENTRY_BYTES: [u8; 8] = machine_code();

#[cfg(target_arch = "x86_64")]
const fn machine_code() -> [u8; 8] {
    [
        0xb8, 0xef, 0xbe, 0xad, 0xde, // mov eax, 0xDEADBEEF
        0x90, // nop
        0xeb, 0xfd, // jmp $-2
    ]
}

#[cfg(target_arch = "aarch64")]
const fn machine_code() -> [u8; 8] {
    [
        0x00, 0x00, 0xa8, 0xd2, // mov x0, #0xDEAD
        0xff, 0xff, 0xff, 0x17, // b .
    ]
}

#[cfg(target_arch = "riscv64")]
const fn machine_code() -> [u8; 8] {
    [
        0x97, 0x35, 0x05, 0x00, // li a0, 0xDEADBEEF
        0x6f, 0x00, 0x00, 0x00, // j .
    ]
}

#[cfg(target_arch = "loongarch64")]
const fn machine_code() -> [u8; 8] {
    [
        0x14, 0x00, 0x37, 0x1a, // lu12i.w $a0, ...
        0x40, 0xff, 0xff, 0x5c, // b .
    ]
}

/// Transfer a prepared thread to user mode. Never returns.
#[inline(always)]
pub unsafe fn enter_user_mode(user_rip: u64, user_rsp: u64) -> ! {
    dispatch_enter_user_mode(user_rip, user_rsp)
}

/// Enter a prepared process after attaching its root page table.
///
/// The root-table argument is the platform's canonical root-table
/// physical address: PML4 on x86_64, TTBR0 on AArch64, satp on
/// RISC-V, and PGD on LoongArch64.
#[inline(always)]
pub unsafe fn enter_first_user_thread(root_table_phys: u64, user_rip: u64, user_rsp: u64) -> ! {
    dispatch_enter_first_user_thread(root_table_phys, user_rip, user_rsp)
}

/// Bring up the built-in minimal user process and dispatch it.
///
/// This is the only first-user-thread fallback path. It creates the
/// process, maps the stub, selects the BSP thread, and transfers to
/// user mode through the architecture-specific entry implementation.
pub fn enter_first_stub_process() -> ! {
    let process = create_stub_process();
    if process.is_null() {
        crate::boot_println!("FATAL: no user process was created");
        crate::arch::halt_loop();
    }

    unsafe {
        let root_table_phys = (*process).pml4_phys;
        let user_rip = (*process).user_rip;
        let user_rsp = (*process).user_rsp;
        let main_thread = (*process).main_thread;

        crate::boot_println!(
            "User process: root=0x{:x} RIP=0x{:x} RSP=0x{:x}",
            root_table_phys,
            user_rip,
            user_rsp
        );

        if !main_thread.is_null() {
            crate::ke::scheduler::setup_bsp(main_thread);
            let current = crate::ps::thread::KeGetCurrentEthread();
            crate::boot_println!("setup_bsp done; KeGetCurrentEthread=0x{:x}", current as u64);
        } else {
            crate::boot_println!("WARNING: process has no main_thread");
        }

        crate::boot_println!("Dispatching into Ring 3...");
        enter_first_user_thread(root_table_phys, user_rip, user_rsp)
    }
}

/// Run the kernel-side command interpreter as the Ring-3 fallback.
///
/// All non-x86 architectures currently use this path so that command
/// behavior remains identical while their user-mode subsystems mature.
pub fn enter_kernel_cmd_fallback() -> ! {
    crate::boot_println!("[SAFE-CMD] Entering kernel-side cmd shell");
    crate::servers::cmd::run_shell(crate::servers::cmd::ShellMode::SafeModeCmd)
}

fn create_stub_process() -> *mut crate::ps::process::Eprocess {
    crate::boot_println!("Creating ring3 stub process");
    let process = crate::ps::process::create_user_process(
        b"\\SystemRoot\\System32\\ring3_stub.exe",
        0x1F00,
        Some(crate::userspace::minimal_stub::USER_ENTRY_RIP),
    )
    .unwrap_or_else(|| {
        crate::boot_println!("FATAL: create_user_process (stub) returned None");
        crate::arch::halt_loop();
    });

    let root_table_phys = (*process).pml4_phys;
    if !crate::userspace::minimal_stub::install_into_pml4(root_table_phys) {
        crate::boot_println!("FATAL: install_into_pml4 failed");
        crate::arch::halt_loop();
    }

    process
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn dispatch_enter_user_mode(user_rip: u64, user_rsp: u64) -> ! {
    unsafe { crate::arch::x86_64::user_entry::__user_entry_enter(user_rip, user_rsp) }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn dispatch_enter_first_user_thread(
    root_table_phys: u64,
    user_rip: u64,
    user_rsp: u64,
) -> ! {
    unsafe {
        crate::arch::x86_64::user_entry::__user_entry_enter_first(
            root_table_phys,
            user_rip,
            user_rsp,
        )
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn dispatch_enter_user_mode(user_rip: u64, user_rsp: u64) -> ! {
    unsafe { crate::arch::aarch64::user_entry::__user_entry_enter(user_rip, user_rsp) }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn dispatch_enter_first_user_thread(
    root_table_phys: u64,
    user_rip: u64,
    user_rsp: u64,
) -> ! {
    unsafe {
        crate::arch::aarch64::user_entry::__user_entry_enter_first(
            root_table_phys,
            user_rip,
            user_rsp,
        )
    }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
unsafe fn dispatch_enter_user_mode(user_rip: u64, user_rsp: u64) -> ! {
    unsafe { crate::arch::riscv64::user_entry::__user_entry_enter(user_rip, user_rsp) }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
unsafe fn dispatch_enter_first_user_thread(
    root_table_phys: u64,
    user_rip: u64,
    user_rsp: u64,
) -> ! {
    unsafe {
        crate::arch::riscv64::user_entry::__user_entry_enter_first(
            root_table_phys,
            user_rip,
            user_rsp,
        )
    }
}

#[cfg(target_arch = "loongarch64")]
#[inline(always)]
unsafe fn dispatch_enter_user_mode(user_rip: u64, user_rsp: u64) -> ! {
    unsafe { crate::arch::loongarch64::user_entry::__user_entry_enter(user_rip, user_rsp) }
}

#[cfg(target_arch = "loongarch64")]
#[inline(always)]
unsafe fn dispatch_enter_first_user_thread(
    root_table_phys: u64,
    user_rip: u64,
    user_rsp: u64,
) -> ! {
    unsafe {
        crate::arch::loongarch64::user_entry::__user_entry_enter_first(
            root_table_phys,
            user_rip,
            user_rsp,
        )
    }
}
