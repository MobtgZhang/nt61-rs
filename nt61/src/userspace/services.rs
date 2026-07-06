//! services.exe — Service Control Manager (user-mode side)
//!
//! Re-exports from `crate::libs::server::services`, which in turn
//! re-exports the real implementation from `crate::servers::services`.

pub use crate::libs::server::services::init;
pub use crate::libs::server::services::start_service;
pub use crate::libs::server::services::stop_service;
pub use crate::libs::server::services::query_service_status;
pub use crate::libs::server::services::list_services;
pub use crate::libs::server::services::enumerate_services;
pub use crate::libs::server::services::enumerate_services_by_state;
