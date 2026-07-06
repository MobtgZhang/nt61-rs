//! services — Service Control Manager (re-export from servers::services)
pub use crate::servers::services::init;
pub use crate::servers::services::start_service;
pub use crate::servers::services::stop_service;
pub use crate::servers::services::query_service_status;
pub use crate::servers::services::list_services;
pub use crate::servers::services::enumerate_services;
pub use crate::servers::services::enumerate_services_by_state;
pub use crate::servers::services::ServiceType;
pub use crate::servers::services::ServiceStartType;
pub use crate::servers::services::ServiceState;
pub use crate::servers::services::ServiceControl;
pub use crate::servers::services::ServiceStatus;
pub use crate::servers::services::ServiceEntry;
pub use crate::servers::services::ScmState;
pub use crate::servers::services::SCM_STATE;

/// Smoke test — delegates to the real servers::services::init().
pub fn smoke_test() -> bool {
    init();
    true
}
