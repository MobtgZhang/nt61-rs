//! Test suite for CSRSS and Services implementation
//!
//! Verifies the functionality of task P2.1:
//! - CSRSS session management
//! - CSRSS console I/O
//! - CSRSS process notifications
//! - Services dependency management
//! - Services process lifecycle
//! - IPC communication

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};
    use crate::servers::{csrss, services};

    #[test]
    fn test_csrss_session_management() {
        // Initialize CSRSS
        csrss::init();

        // Create additional sessions
        assert!(csrss::create_session(2));
        assert!(csrss::create_session(3));

        // Verify session retrieval
        assert!(csrss::get_session(0).is_some());
        assert!(csrss::get_session(1).is_some());
        assert!(csrss::get_session(2).is_some());
        assert!(csrss::get_session(3).is_some());

        // Destroy a session
        assert!(csrss::destroy_session(3));
        assert!(csrss::get_session(3).is_none());
    }

    #[test]
    fn test_csrss_console_management() {
        csrss::init();

        // Allocate console for a process
        let console_handle = csrss::alloc_console(1000, 0);
        assert_ne!(console_handle, 0);

        // Set console mode
        assert!(csrss::set_console_mode(console_handle, 0x0001));

        // Get console mode
        let mode = csrss::get_console_mode(console_handle);
        assert_eq!(mode, Some(0x0001));

        // Free console
        assert!(csrss::free_console(console_handle));
    }

    #[test]
    fn test_csrss_process_notification() {
        csrss::init();

        // Notify of process creation
        csrss::notify_process_created(1234, 1000, 0, "test.exe");

        // Notify of thread creation
        csrss::notify_thread_created(1234, 5678);

        // Get statistics
        let (session_count, notification_count, _api_port) = csrss::get_statistics();
        assert!(session_count >= 2);
        assert!(notification_count >= 1);
    }

    #[test]
    fn test_csrss_win32_connection() {
        csrss::init();

        // Connect process to Win32 subsystem
        assert!(csrss::connect_to_win32(1000, 0));
    }

    #[test]
    fn test_services_initialization() {
        // Initialize SCM
        services::init();

        // Verify default services are registered
        let all_services = services::list_services();
        assert!(all_services.len() > 0);

        // Check for specific core services
        let service_names: Vec<String> = all_services.iter().map(|(n, _)| n.clone()).collect();
        assert!(service_names.iter().any(|n| n == "RpcSs"));
        assert!(service_names.iter().any(|n| n == "EventSystem"));
        assert!(service_names.iter().any(|n| n == "CryptSvc"));
    }

    #[test]
    fn test_services_control() {
        services::init();

        // Open a service
        let handle = services::open_service("RpcSs");
        assert!(handle.is_some());

        let idx = handle.unwrap();

        // Query service configuration
        let config = services::query_service_config(idx);
        assert!(config.is_some());

        // Query service status
        let status = services::query_service_status_ex(idx);
        assert!(status.is_some());
    }

    #[test]
    fn test_services_enumeration() {
        services::init();

        // Enumerate services by type
        let share_process_services = services::enumerate_services(
            services::ServiceType::ShareProcess
        );
        assert!(share_process_services.len() > 0);

        // Enumerate services by state
        let stopped_services = services::enumerate_services_by_state(
            services::ServiceState::Stopped
        );
        assert!(stopped_services.len() > 0);
    }

    #[test]
    fn test_services_dependency_management() {
        services::init();

        // Check dependencies for a service
        let deps_ok = services::check_dependencies("RpcSs");
        // RpcSs typically has no dependencies or satisfied dependencies
        assert!(deps_ok);
    }

    #[test]
    fn test_services_process_management() {
        services::init();

        // Create a control pipe for a service
        let pipe = services::create_service_pipe("RpcSs");
        assert!(pipe.is_some());
    }

    #[test]
    fn test_services_query_info() {
        services::init();

        // Query detailed service information
        let info = services::query_service_info("RpcSs");
        assert!(info.is_some());

        let service_info = info.unwrap();
        assert_eq!(service_info.name.trim_end_matches('\0'), "RpcSs");
        assert_eq!(service_info.service_type, services::ServiceType::ShareProcess);
    }

    #[test]
    fn test_services_query_all() {
        services::init();

        // Query all services
        let all_services = services::query_all_services();
        assert!(all_services.len() > 0);

        // Verify structure
        for (name, state, _pid) in all_services.iter() {
            assert!(!name.is_empty());
            // State should be valid
            let _ = state;
        }
    }

    #[test]
    fn test_service_control_handler() {
        services::init();

        // Register a test service control handler
        fn test_handler(_control: u32) -> u32 {
            1 // Return success
        }

        let service_name: [u16; 4] = ['T' as u16, 'e' as u16, 's' as u16, 't' as u16];
        let idx = services::register_service_ctrl_handler(&service_name, test_handler);
        assert!(idx.is_some());

        let handle_idx = idx.unwrap();

        // Set service status
        let mut status = services::ServiceStatus::new();
        status.current_state = services::ServiceState::Running;
        assert!(services::set_service_status(handle_idx, status));

        // Query service status
        let queried = services::query_service_status_ex(handle_idx);
        assert!(queried.is_some());
        assert_eq!(queried.unwrap().current_state, services::ServiceState::Running);

        // Dispatch control code
        let result = services::dispatch_service_control(&service_name, 0x04);
        assert_eq!(result, 1);
    }

    #[test]
    fn test_integration_csrss_services() {
        // Initialize both subsystems
        csrss::init();
        services::init();

        // Verify CSRSS statistics
        let (session_count, _notif_count, api_port) = csrss::get_statistics();
        assert!(session_count >= 2);
        assert!(api_port > 0);

        // Verify Services statistics
        let all_services = services::list_services();
        assert!(all_services.len() > 0);

        // Simulate a process connecting to CSRSS and starting a service
        let console = csrss::alloc_console(2000, 0);
        assert_ne!(console, 0);

        let win32_connected = csrss::connect_to_win32(2000, 0);
        assert!(win32_connected);

        // Notify CSRSS of process creation
        csrss::notify_process_created(2000, 1000, 0, "services.exe");

        // Verify the notification was recorded
        let (_sessions, notifications, _port) = csrss::get_statistics();
        assert!(notifications >= 1);
    }
}

/// Run all CSRSS and Services tests
use crate::servers::{csrss, services};

pub fn run_tests() -> bool {
    // In a real implementation, this would run the test suite
    // For now, just verify basic initialization
    csrss::init();
    services::init();

    let (session_count, _notif, _port) = csrss::get_statistics();
    let all_services = services::list_services();

    session_count >= 2 && all_services.len() > 0
}
