//! Unwrap replacement utilities
//!
//! Provides safe alternatives to unwrap() for kernel code.
//! In kernel context, panic is fatal (BSOD), so we must handle errors properly.

/// Macro to replace unwrap() with proper error handling
#[macro_export]
macro_rules! unwrap_or_return {
    ($expr:expr, $err:expr) => {
        match $expr {
            Some(val) => val,
            None => return $err,
        }
    };
}

/// Macro to replace unwrap() on Result with proper error handling
#[macro_export]
macro_rules! try_or_return {
    ($expr:expr, $err:expr) => {
        match $expr {
            Ok(val) => val,
            Err(_) => return $err,
        }
    };
}

/// Macro to replace expect() with logging and return
#[macro_export]
macro_rules! expect_or_return {
    ($expr:expr, $msg:expr, $err:expr) => {
        match $expr {
            Some(val) => val,
            None => {
                $crate::kprintln_error!("Expectation failed: {}", $msg);
                return $err;
            }
        }
    };
}

/// Safe unwrap for Option that returns a default value
#[inline]
pub fn unwrap_or_default<T: Default>(opt: Option<T>) -> T {
    match opt {
        Some(val) => val,
        None => T::default(),
    }
}

/// Safe unwrap for Result that returns a default value
#[inline]
pub fn result_or_default<T: Default, E>(res: Result<T, E>) -> T {
    match res {
        Ok(val) => val,
        Err(_) => T::default(),
    }
}
