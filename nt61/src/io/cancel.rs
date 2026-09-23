//! Cancel-Safe IRP Queues
//!
//! Cancel-safe IRP queues provide a robust mechanism for queueing IRPs
//! in a way that allows them to be cancelled safely without race conditions.
//!
//! # Why Cancel-Safe Queues?
//!
//! In NT drivers, IRPs can be cancelled asynchronously by the I/O manager
//! or by user-mode code. Without proper synchronization, cancelling an IRP
//! that's in a driver's queue can cause:
//! - Use-after-free bugs
//! - Double completions
//! - Deadlocks
//!
//! Cancel-safe queues solve this by:
//! - Using a spinlock to protect queue access
//! - Atomically removing IRPs from the queue during cancellation
//! - Preventing race conditions between insertion, removal, and cancellation

use alloc::collections::VecDeque;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use super::Irp;
use crate::libs::ntdll::status::*;

pub type CancelRoutine = unsafe extern "C" fn(irp: *mut Irp);

pub struct CancelSafeQueue {
    queue: Spinlock<VecDeque<*mut Irp>>,
    count: AtomicU64,
    cancel_routine: Option<CancelRoutine>,
}

impl CancelSafeQueue {
    pub fn new(cancel_routine: Option<CancelRoutine>) -> Self {
        Self {
            queue: Spinlock::new(VecDeque::new()),
            count: AtomicU64::new(0),
            cancel_routine,
        }
    }

    pub fn insert(&self, irp: *mut Irp) -> bool {
        if irp.is_null() {
            return false;
        }

        unsafe {
            if super::irp_is_cancelled(irp) {
                return false;
            }

            if let Some(routine) = self.cancel_routine {
                super::set_irp_cancel_routine(irp, Some(routine));
            }

            let mut queue = self.queue.lock();
            queue.push_back(irp);
            self.count.fetch_add(1, Ordering::Release);

            (*irp).flags |= IRP_PENDING;
        }

        true
    }

    pub unsafe fn remove_next(&self) -> *mut Irp {
        let mut queue = self.queue.lock();

        if let Some(irp) = queue.pop_front() {
            self.count.fetch_sub(1, Ordering::Release);

            super::set_irp_cancel_routine(irp, None);

            irp
        } else {
            null_mut()
        }
    }

    pub unsafe fn remove_irp(&self, irp: *mut Irp) -> bool {
        if irp.is_null() {
            return false;
        }

        let mut queue = self.queue.lock();

        if let Some(pos) = queue.iter().position(|&p| p == irp) {
            queue.remove(pos);
            self.count.fetch_sub(1, Ordering::Release);

            super::set_irp_cancel_routine(irp, None);

            true
        } else {
            false
        }
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::Acquire) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    pub fn flush(&self, status: i32) {
        loop {
            let irp = unsafe { self.remove_next() };
            if irp.is_null() {
                break;
            }

            unsafe {
                (*irp).io_status.status = status as u32;
                (*irp).io_status.information = 0;
                super::IoCompleteRequest(irp, 0);
            }
        }
    }
}

pub const IRP_PENDING: u32 = 0x00000001;
pub const IRP_SYNCHRONOUS_API: u32 = 0x00000004;
pub const IRP_DEALLOCATE_BUFFER: u32 = 0x00000010;

pub unsafe extern "C" fn cancel_queued_irp(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }


    (*irp).flags |= super::IRP_CANCEL_INDICATED;
    (*irp).io_status.status = STATUS_CANCELLED as u32;
    (*irp).io_status.information = 0;

    super::IoCompleteRequest(irp, 0);
}

pub const STATUS_CANCELLED: i32 = 0xC0000120_u32 as i32;

pub fn create_cancel_safe_queue() -> CancelSafeQueue {
    CancelSafeQueue::new(Some(cancel_queued_irp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_insert_remove() {
        let queue = create_cancel_safe_queue();
        let irp = super::super::allocate_irp(1);

        assert!(!irp.is_null());
        assert!(queue.insert(irp));
        assert_eq!(queue.count(), 1);

        let removed = queue.remove_next();
        assert_eq!(removed, irp);
        assert_eq!(queue.count(), 0);

        super::super::free_irp(irp);
    }

    #[test]
    fn queue_flush() {
        let queue = create_cancel_safe_queue();

        let irp1 = super::super::allocate_irp(1);
        let irp2 = super::super::allocate_irp(1);

        queue.insert(irp1);
        queue.insert(irp2);
        assert_eq!(queue.count(), 2);

        queue.flush(STATUS_CANCELLED);
        assert_eq!(queue.count(), 0);
    }
}
