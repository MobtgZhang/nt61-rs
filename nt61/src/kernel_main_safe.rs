use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};


use core::sync::atomic::{AtomicBool, Ordering};

pub struct SystemImageDb {
    db: Option<crate::loader::ImageDatabase>,
    initialized: AtomicBool,
}

impl SystemImageDb {
    const fn new() -> Self {
        Self {
            db: None,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, db: crate::loader::ImageDatabase) {
        self.db = Some(db);
        self.initialized.store(true, Ordering::Release);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    pub fn get(&self) -> Option<&crate::loader::ImageDatabase> {
        if self.is_initialized() {
            self.db.as_ref()
        } else {
            None
        }
    }

    pub fn get_mut(&mut self) -> Option<&mut crate::loader::ImageDatabase> {
        if self.is_initialized() {
            self.db.as_mut()
        } else {
            None
        }
    }
}

static SYSTEM_IMAGE_DB: Lazy<Mutex<SystemImageDb>> = Lazy::new(|| {
    Mutex::new(SystemImageDb::new())
});

pub fn init_system_image_db(db: crate::loader::ImageDatabase) {
    SYSTEM_IMAGE_DB.lock().init(db);
}

pub fn is_system_image_db_initialized() -> bool {
    SYSTEM_IMAGE_DB.lock().is_initialized()
}

pub fn with_system_image_db<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&crate::loader::ImageDatabase) -> R,
{
    let db = SYSTEM_IMAGE_DB.lock();
    db.get().map(f)
}

pub fn with_system_image_db_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut crate::loader::ImageDatabase) -> R,
{
    let mut db = SYSTEM_IMAGE_DB.lock();
    db.get_mut().map(f)
}
