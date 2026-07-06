//! Panic Handling
//
//! Kernel panic and crash handling

/// Trigger kernel panic
pub fn panic(_msg: &str) -> ! {
    crate::ke::bugcheck::bugcheck(
        crate::ke::bugcheck::BugCheckCode::SystemUninit,
    );
}
