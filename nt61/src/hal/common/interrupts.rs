//! Interrupt Handling Support
//! The canonical IRQL table lives in `crate::ke::irql`: NT 6.1 defines 32
//! IRQLs (0..31), with device IRQLs starting at 4. This module used to
//! define a second, incompatible 15-level table, which meant the same
//! numeric IRQL could mean different things depending on which module a
//! caller imported. The duplicate is removed; this module re-exports the
//! canonical table and delegates to the single implementation.

pub use crate::ke::irql::Irql;

/// Register an interrupt handler
#[allow(dead_code)]
pub fn register_handler(_vector: u8, _handler: fn()) {
    // Register interrupt handler
}

/// Raise IRQL to `level`, returning the previous level.
#[allow(dead_code)]
pub fn raise_irql(level: Irql) -> Irql {
    crate::ke::irql::raise_irql(level)
}

/// Lower IRQL back to a level previously returned by `raise_irql`.
#[allow(dead_code)]
pub fn lower_irql(level: Irql) {
    crate::ke::irql::lower_irql(level);
}
