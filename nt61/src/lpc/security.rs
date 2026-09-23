//! Security and impersonation support
//!
//! ALPC security features:
//! - Security descriptors for ports
//! - Access control checks
//! - Impersonation context
//! - Security quality of service

/// Security descriptor (simplified for bootstrap)

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecurityDescriptor {
    /// Owner SID (Security Identifier)
    pub owner_sid: u64,
    /// Group SID
    pub group_sid: u64,
    /// Discretionary ACL flags
    pub dacl_flags: u32,
    /// System ACL flags
    pub sacl_flags: u32,
}

impl SecurityDescriptor {
    pub const fn empty() -> Self {
        Self {
            owner_sid: 0,
            group_sid: 0,
            dacl_flags: 0,
            sacl_flags: 0,
        }
    }

    pub const fn system() -> Self {
        Self {
            owner_sid: 0, // SYSTEM SID
            group_sid: 0,
            dacl_flags: 0xFFFFFFFF, // Full access
            sacl_flags: 0,
        }
    }
}

/// Access rights for ALPC ports
pub const PORT_ACCESS_CONNECT: u32 = 0x0001;
pub const PORT_ACCESS_SEND: u32 = 0x0002;
pub const PORT_ACCESS_RECEIVE: u32 = 0x0004;
pub const PORT_ACCESS_ALL: u32 = 0x0007;

/// Security Quality of Service levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SecurityQos {
    /// Anonymous - server cannot impersonate or identify client
    Anonymous = 0,
    /// Identification - server can identify but not impersonate
    Identification = 1,
    /// Impersonation - server can impersonate on local system
    Impersonation = 2,
    /// Delegation - server can impersonate on remote systems

    Delegation = 3,
}

/// Impersonation context
#[repr(C)]
pub struct ImpersonationContext {
    /// Client process ID being impersonated
    pub client_pid: u64,
    /// Client thread ID being impersonated
    pub client_tid: u64,
    /// Security quality of service
    pub security_qos: SecurityQos,
    /// Whether impersonation is active
    pub active: bool,
    /// Impersonation level granted
    pub granted_level: SecurityQos,
}

impl ImpersonationContext {
    pub const fn empty() -> Self {
        Self {
            client_pid: 0,
            client_tid: 0,
            security_qos: SecurityQos::Anonymous,
            active: false,
            granted_level: SecurityQos::Anonymous,
        }
    }
}

/// Port security context
#[repr(C)]
pub struct PortSecurity {
    /// Security descriptor
    pub descriptor: SecurityDescriptor,
    /// Whether impersonation is allowed
    pub allow_impersonation: bool,
    /// Maximum impersonation level allowed
    pub max_impersonation_level: SecurityQos,
    /// Current impersonation context (if any)
    pub impersonation: ImpersonationContext,
}

impl PortSecurity {
    pub const fn system() -> Self {
        Self {
            descriptor: SecurityDescriptor::system(),
            allow_impersonation: true,
            max_impersonation_level: SecurityQos::Impersonation,
            impersonation: ImpersonationContext::empty(),
        }
    }

    pub const fn empty() -> Self {
        Self {
            descriptor: SecurityDescriptor::empty(),
            allow_impersonation: false,
            max_impersonation_level: SecurityQos::Anonymous,
            impersonation: ImpersonationContext::empty(),
        }
    }
}

/// Check if a process has access to a port
pub fn check_port_access(
    security: &PortSecurity,
    pid: u64,
    requested_access: u32,
) -> bool {
    // Simplified access check for bootstrap
    // In real NT, this would do full SID-based ACL checks

    // SYSTEM (PID 0 or 4) has full access
    if pid == 0 || pid == 4 {
        return true;
    }

    // Check if owner
    if security.descriptor.owner_sid == pid {
        return true;
    }

    // Check DACL flags (simplified)
    let allowed = security.descriptor.dacl_flags;
    (allowed & requested_access) == requested_access
}

/// Begin impersonating a client
pub fn impersonate_client(
    security: &mut PortSecurity,
    client_pid: u64,
    client_tid: u64,
    requested_level: SecurityQos,
) -> bool {
    if !security.allow_impersonation {
        return false;
    }

    // Check if requested level is allowed
    if requested_level as u32 > security.max_impersonation_level as u32 {
        return false;
    }

    security.impersonation.client_pid = client_pid;
    security.impersonation.client_tid = client_tid;
    security.impersonation.security_qos = requested_level;
    security.impersonation.granted_level = requested_level;
    security.impersonation.active = true;

    true
}

/// Stop impersonating
pub fn revert_to_self(security: &mut PortSecurity) -> bool {
    if !security.impersonation.active {
        return false;
    }

    security.impersonation.active = false;
    security.impersonation.client_pid = 0;
    security.impersonation.client_tid = 0;

    true
}
