//! Interrupt Handling Support

/// Interrupt request levels (IRQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Irql {
    PassivelyLevel = 0,
    APC = 1,
    Dispatch = 2,
    CMCI = 5,
    Profile = 8,
    Clock = 13,
    Synch = 14,
    Highest = 15,
}

/// Register an interrupt handler
#[allow(dead_code)]
pub fn register_handler(_vector: u8, _handler: fn()) {
    // Register interrupt handler
}

/// Raise IRQL
#[allow(dead_code)]
pub fn raise_irql(level: Irql) -> Irql {
    level
}

/// Lower IRQL
#[allow(dead_code)]
pub fn lower_irql(_level: Irql) {
    // Restore IRQL
}
