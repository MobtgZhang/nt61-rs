
// =============================================================================
// Process Management API for Commands Module
// =============================================================================

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub memory_usage: u64,
    pub cpu_time: u64,
    pub session_id: u32,
    pub status: String,
    pub user_name: String,
    pub window_title: String,
    pub services: Vec<String>,
}

pub fn get_process_list() -> Vec<ProcessInfo> {
    use crate::ps::process::get_all_processes;

    let mut processes = Vec::new();

    match get_all_processes() {
        Ok(kernel_processes) => {
            for kproc in kernel_processes {
                processes.push(ProcessInfo {
                    pid: kproc.pid as u32,
                    name: kproc.name,
                    memory_usage: kproc.memory_usage,
                    cpu_time: kproc.cpu_time,
                    session_id: kproc.session_id,
                    status: kproc.status,
                    user_name: kproc.user_name,
                    window_title: kproc.window_title,
                    services: kproc.services,
                });
            }
        }
        Err(_) => {
            processes.push(ProcessInfo {
                pid: 0,
                name: String::from("System Idle Process"),
                memory_usage: 8 * 1024,
                cpu_time: 0,
                session_id: 0,
                status: String::from("Running"),
                user_name: String::from("NT AUTHORITY\\SYSTEM"),
                window_title: String::from("N/A"),
                services: Vec::new(),
            });

            processes.push(ProcessInfo {
                pid: 4,
                name: String::from("System"),
                memory_usage: 256 * 1024,
                cpu_time: 0,
                session_id: 0,
                status: String::from("Running"),
                user_name: String::from("NT AUTHORITY\\SYSTEM"),
                window_title: String::from("N/A"),
                services: Vec::new(),
            });
        }
    }

    processes.push(ProcessInfo {
        pid: 264,
        name: String::from("smss.exe"),
        memory_usage: 512 * 1024, // 512 KB
        cpu_time: 0,
        session_id: 0,
        status: String::from("Running"),
        user_name: String::from("NT AUTHORITY\\SYSTEM"),
        window_title: String::from("N/A"),
        services: Vec::new(),
    });

    processes.push(ProcessInfo {
        pid: 352,
        name: String::from("csrss.exe"),
        memory_usage: 2 * 1024 * 1024, // 2 MB
        cpu_time: 0,
        session_id: 0,
        status: String::from("Running"),
        user_name: String::from("NT AUTHORITY\\SYSTEM"),
        window_title: String::from("N/A"),
        services: Vec::new(),
    });

    processes.push(ProcessInfo {
        pid: 400,
        name: String::from("wininit.exe"),
        memory_usage: 1024 * 1024, // 1 MB
        cpu_time: 0,
        session_id: 0,
        status: String::from("Running"),
        user_name: String::from("NT AUTHORITY\\SYSTEM"),
        window_title: String::from("N/A"),
        services: Vec::new(),
    });

    processes.push(ProcessInfo {
        pid: 472,
        name: String::from("services.exe"),
        memory_usage: 4 * 1024 * 1024, // 4 MB
        cpu_time: 0,
        session_id: 0,
        status: String::from("Running"),
        user_name: String::from("NT AUTHORITY\\SYSTEM"),
        window_title: String::from("N/A"),
        services: vec![String::from("Dhcp"), String::from("Dnscache")],
    });

    processes.push(ProcessInfo {
        pid: 488,
        name: String::from("lsass.exe"),
        memory_usage: 3 * 1024 * 1024, // 3 MB
        cpu_time: 0,
        session_id: 0,
        status: String::from("Running"),
        user_name: String::from("NT AUTHORITY\\SYSTEM"),
        window_title: String::from("N/A"),
        services: Vec::new(),
    });

    processes.push(ProcessInfo {
        pid: 496,
        name: String::from("winlogon.exe"),
        memory_usage: 2 * 1024 * 1024, // 2 MB
        cpu_time: 0,
        session_id: 1,
        status: String::from("Running"),
        user_name: String::from("NT AUTHORITY\\SYSTEM"),
        window_title: String::from("N/A"),
        services: Vec::new(),
    });

    processes.push(ProcessInfo {
        pid: 1024,
        name: String::from("explorer.exe"),
        memory_usage: 24 * 1024 * 1024, // 24 MB
        cpu_time: 0,
        session_id: 1,
        status: String::from("Running"),
        user_name: String::from("Administrator"),
        window_title: String::from("Program Manager"),
        services: Vec::new(),
    });

    processes
}

pub fn find_processes_by_name(name: &str) -> Vec<u32> {
    let processes = get_process_list();
    let name_lower = name.to_lowercase();

    processes
        .iter()
        .filter(|p| p.name.to_lowercase() == name_lower)
        .map(|p| p.pid)
        .collect()
}

pub fn terminate_process(pid: u32) -> bool {
    use crate::ps::process::terminate_process_by_pid;

    if pid == 0 || pid == 4 || pid < 260 {
        return false;
    }

    terminate_process_by_pid(pid as u64, false).is_ok()
}

pub fn kill_process_forced(pid: u32) -> bool {

    if pid == 0 || pid == 4 {
        return false;
    }

    terminate_process_by_pid(pid as u64, true).is_ok()
}

pub fn create_process(
    command: &str,
    work_dir: Option<&str>,
    priority: u8,
    minimized: bool,
    maximized: bool,
) -> Option<u32> {
    use crate::ps::process::create_user_process;

    match create_user_process(command, work_dir, priority) {
        Ok(pid) => Some(pid as u32),
        Err(_) => None,
    }
}

pub fn wait_for_process(pid: u32) {
    use crate::ps::process::wait_for_process_exit;

    let _ = wait_for_process_exit(pid as u64, None);
}

pub fn get_child_processes(parent_pid: u32) -> Vec<u32> {
    // TODO: Implement child process enumeration
    Vec::new()
}
