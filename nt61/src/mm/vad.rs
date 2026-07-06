//! VAD (Virtual Address Descriptor) Manager
//
//! Manages virtual address descriptors for process address spaces.
//! NT-style AVL tree based VAD management.
//
//! The VAD tree tracks the regions of a process's address space -
//! image, heap, stack, mapped files, etc. - and the protection that
//! applies to each. When a page fault fires in user mode, the
//! `Memory Manager` walks the VAD tree to decide whether the access
//! is allowed, and to back the fault with the right kind of page
//! (anonymous zero-fill, copy-on-write image, mapped file page, ...).
//
//! ## Implementation
//
//! This is a self-balancing AVL tree keyed on `starting_vpn`.
//! Each node stores explicit balance factors and uses rotations
//! to maintain the AVL invariant: |height(left) - height(right)| <= 1.
//
//! Balance factor values: -1 (left-heavy), 0 (balanced), +1 (right-heavy)
//
//! ## Thread Safety
//
//! All tree operations are protected by a Spinlock (VadLock).
//! The lock must be held during any modification or concurrent read.

use crate::ke::sync::Spinlock;
use crate::mm::vm::{MemFlags, PAGE_SIZE};
use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

/// VAD types matching Windows definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VadType {
    VadNone = 0,
    VadDevice = 1,
    VadImage = 2,
    VadWriteWatch = 3,
    VadRoot = 4,
    VadLarge = 5,
    VadRotatePhysical = 6,
}

/// VAD flags.
#[derive(Debug, Clone, Copy)]
pub struct VadFlags(u32);

impl VadFlags {
    pub const NONE: Self = Self(0);
    pub const SEC_COMMIT: Self = Self(0x00000040);
    pub const SEC_RESERVE: Self = Self(0x08000000);
    pub const SEC_NO_CHANGE: Self = Self(0x40000000);
    pub const SEC_ZERO_DOWN: Self = Self(0x80000000);
    pub const SEC_GUARD: Self = Self(0x80000000); // Guard page flag

    /// Check if any of the given bits are set.
    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Check if the guard page flag is set.
    pub fn is_guard(&self) -> bool {
        (self.0 & 0x80000000) != 0
    }

    /// Return the raw flag bits.
    pub const fn bits(&self) -> u32 {
        self.0
    }
}

/// VAD protection flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VadProtection(u8);

impl VadProtection {
    pub const NO_ACCESS: Self = Self(0);
    pub const READONLY: Self = Self(1);
    pub const EXECUTE: Self = Self(2);
    pub const EXECUTE_READ: Self = Self(3);
    pub const READWRITE: Self = Self(4);
    pub const WRITECOPY: Self = Self(5);
    pub const EXECUTE_READWRITE: Self = Self(6);
    pub const EXECUTE_WRITECOPY: Self = Self(7);
    pub const NO_CACHE: Self = Self(8);
    pub const READ: Self = Self(9);
    pub const WRITE: Self = Self(10);

    pub fn as_memflags(&self) -> MemFlags {
        match *self {
            Self::NO_ACCESS => MemFlags::NONE,
            Self::READONLY | Self::READ => MemFlags::READ,
            Self::EXECUTE => MemFlags::EXECUTE,
            Self::EXECUTE_READ => MemFlags::READ | MemFlags::EXECUTE,
            Self::READWRITE | Self::WRITE => MemFlags::READ | MemFlags::WRITE,
            Self::WRITECOPY => MemFlags::READ | MemFlags::WRITE,
            Self::EXECUTE_READWRITE => MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
            Self::EXECUTE_WRITECOPY => MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
            _ => MemFlags::READ,
        }
    }
}

/// VAD (Virtual Address Descriptor) entry.
/// Aligned to 32 bytes for x64.
/// AVL tree node with explicit balance factor.
#[repr(C)]
#[repr(align(32))]
pub struct VadEntry {
    pub starting_vpn: u64,
    pub ending_vpn: u64,
    pub parent: *mut VadEntry,
    pub left: *mut VadEntry,
    pub right: *mut VadEntry,
    pub balance_factor: i8,      // AVL balance: -1, 0, +1
    pub _pad0: u8,
    pub _pad1: u16,
    pub flags: VadFlags,
    pub vad_type: VadType,
    pub protection: VadProtection,
    pub _padding: [u8; 4],
}

impl VadEntry {
    pub const fn new() -> Self {
        Self {
            starting_vpn: 0,
            ending_vpn: 0,
            parent: null_mut(),
            left: null_mut(),
            right: null_mut(),
            balance_factor: 0,
            _pad0: 0,
            _pad1: 0,
            flags: VadFlags::NONE,
            vad_type: VadType::VadNone,
            protection: VadProtection::NO_ACCESS,
            _padding: [0; 4],
        }
    }

    pub fn set_range(&mut self, start: u64, end: u64) {
        self.starting_vpn = start >> 12;
        self.ending_vpn = end >> 12;
    }

    /// Compute the height of the subtree rooted at this node.
    #[allow(unused)]
    fn height(node: *mut VadEntry) -> i32 {
        if node.is_null() {
            return 0;
        }
        unsafe {
            let left_h = Self::height((*node).left);
            let _ = &left_h;
            let _ = &left_h;
            let right_h = Self::height((*node).right);
            let _ = &right_h;
            let _ = &right_h;
            1 + core::cmp::max(left_h, right_h)
        }
    }

    /// Compute the balance factor: height(left) - height(right).
    #[allow(unused)]
    fn balance(&self) -> i32 {
        let left_h = Self::height(self.left);
        let _ = &left_h;
        let _ = &left_h;
        let right_h = Self::height(self.right);
        let _ = &right_h;
        let _ = &right_h;
        left_h - right_h
    }

    pub fn start_addr(&self) -> u64 {
        self.starting_vpn << 12
    }
    pub fn end_addr(&self) -> u64 {
        (self.ending_vpn << 12) + PAGE_SIZE - 1
    }
    pub fn contains(&self, addr: u64) -> bool {
        let vpn = addr >> 12;
        let _ = &vpn;
        let _ = &vpn;
        self.starting_vpn <= vpn && vpn <= self.ending_vpn
    }
    pub fn is_free(&self) -> bool {
        self.vad_type == VadType::VadNone
    }
}

/// VAD tree root with embedded lock for thread safety.
pub struct VadTree {
    pub root: *mut VadEntry,
    pub node_count: AtomicU64,
    pub lock: Spinlock<()>,
}

impl VadTree {
    pub const fn new() -> Self {
        Self {
            root: null_mut(),
            node_count: AtomicU64::new(0),
            lock: Spinlock::new(()),
        }
    }

    // =========================================================================
    // AVL Rotation Helpers
    // =========================================================================

    /// Right rotation at node `y`. Used for Left-Left imbalance.
    /// Before:      After:
    ///     y            x
    ///    / \         / \
    ///   x   T3  =>  T1  y
    ///  / \             / \
    /// T1  T2          T2  T3
    fn rotate_right_locked(&self, y: *mut VadEntry) {
        // SAFETY: caller must hold `self.lock`. We have exclusive
        // access to `self` for the duration of the lock.
        let self_mut: *mut Self = unsafe { core::mem::transmute::<*const Self, *mut Self>(self as *const Self) };
        let root_ptr: *mut *mut VadEntry = unsafe { &raw mut (*self_mut).root };
        unsafe {
            let x = (*y).left;
            let _ = &x;
            let _ = &x;
            let t2 = (*x).right;
            let _ = &t2;
            let _ = &t2;

            // Swap parent pointer
            (*x).parent = (*y).parent;

            if (*y).parent.is_null() {
                *root_ptr = x;
            } else if (*(*y).parent).left == y {
                (*(*y).parent).left = x;
            } else {
                (*(*y).parent).right = x;
            }

            // Perform rotation
            (*x).right = y;
            (*y).parent = x;
            (*y).left = t2;
            if !t2.is_null() {
                (*t2).parent = y;
            }

            // Update balance factors (after right rotation at y):
            // x gains +1, y gains +1, so net: x=0, y=0
            (*y).balance_factor = 0;
            (*x).balance_factor = 0;
        }
    }

    /// Left rotation at node `x`. Used for Right-Right imbalance.
    /// Before:      After:
    ///     x            y
    ///    / \         / \
    ///   T1  y   =>  x   T3
    ///      / \     / \
    ///     T2 T3  T1  T2
    fn rotate_left_locked(&self, x: *mut VadEntry) {
        // SAFETY: caller must hold `self.lock`.
        let self_mut: *mut Self = unsafe { core::mem::transmute::<*const Self, *mut Self>(self as *const Self) };
        let root_ptr: *mut *mut VadEntry = unsafe { &raw mut (*self_mut).root };
        unsafe {
            let y = (*x).right;
            let _ = &y;
            let _ = &y;
            let t2 = (*y).left;
            let _ = &t2;
            let _ = &t2;

            // Swap parent pointer
            (*y).parent = (*x).parent;

            if (*x).parent.is_null() {
                *root_ptr = y;
            } else if (*(*x).parent).right == x {
                (*(*x).parent).right = y;
            } else {
                (*(*x).parent).left = y;
            }

            // Perform rotation
            (*y).left = x;
            (*x).parent = y;
            (*x).right = t2;
            if !t2.is_null() {
                (*t2).parent = x;
            }

            // Update balance factors (after left rotation at x):
            // y gains -1, x gains -1, so net: x=0, y=0
            (*x).balance_factor = 0;
            (*y).balance_factor = 0;
        }
    }

    /// Left-Right double rotation: left rotate at child, then right rotate at parent.
    /// Used for Left-Right imbalance case.
    fn rotate_left_right_locked(&self, node: *mut VadEntry) {
        // SAFETY: caller must hold `self.lock`.
        unsafe {
            let child = (*node).left;
            let _ = &child;
            let _ = &child;
            let old_child_balance = (*child).balance_factor;
            let _ = &old_child_balance;
            let _ = &old_child_balance;

            // Left rotate at child
            self.rotate_left_locked(child);

            // Right rotate at node
            self.rotate_right_locked(node);

            // After LR: if old child balance was -1, node becomes +1
            if old_child_balance == -1 {
                (*node).balance_factor = 1;
            }
        }
    }

    /// Right-Left double rotation: right rotate at child, then left rotate at parent.
    /// Used for Right-Left imbalance case.
    fn rotate_right_left_locked(&self, node: *mut VadEntry) {
        // SAFETY: caller must hold `self.lock`.
        unsafe {
            let child = (*node).right;
            let _ = &child;
            let _ = &child;
            let old_child_balance = (*child).balance_factor;
            let _ = &old_child_balance;
            let _ = &old_child_balance;

            // Right rotate at child
            self.rotate_right_locked(child);

            // Left rotate at node
            self.rotate_left_locked(node);

            // After RL: if old child balance was +1, node becomes -1
            if old_child_balance == 1 {
                (*node).balance_factor = -1;
            }
        }
    }

    /// Right rotation at node `y`. Used for Left-Left imbalance.
    /// Before:      After:
    ///     y            x
    ///    / \         / \
    ///   x   T3  =>  T1  y
    ///  / \             / \
    /// T1  T2          T2  T3
    fn rotate_right(&mut self, y: *mut VadEntry) {
        unsafe {
            let x = (*y).left;
            let _ = &x;
            let _ = &x;
            let t2 = (*x).right;
            let _ = &t2;
            let _ = &t2;

            // Swap parent pointer
            (*x).parent = (*y).parent;

            if (*y).parent.is_null() {
                self.root = x;
            } else if (*(*y).parent).left == y {
                (*(*y).parent).left = x;
            } else {
                (*(*y).parent).right = x;
            }

            // Perform rotation
            (*x).right = y;
            (*y).parent = x;
            (*y).left = t2;
            if !t2.is_null() {
                (*t2).parent = y;
            }

            (*y).balance_factor = 0;
            (*x).balance_factor = 0;
        }
    }

    /// Left rotation at node `x`. Used for Right-Right imbalance.
    fn rotate_left(&mut self, x: *mut VadEntry) {
        unsafe {
            let y = (*x).right;
            let _ = &y;
            let _ = &y;
            let t2 = (*y).left;
            let _ = &t2;
            let _ = &t2;

            // Swap parent pointer
            (*y).parent = (*x).parent;

            if (*x).parent.is_null() {
                self.root = y;
            } else if (*(*x).parent).right == x {
                (*(*x).parent).right = y;
            } else {
                (*(*x).parent).left = y;
            }

            // Perform rotation
            (*y).left = x;
            (*x).parent = y;
            (*x).right = t2;
            if !t2.is_null() {
                (*t2).parent = x;
            }

            (*x).balance_factor = 0;
            (*y).balance_factor = 0;
        }
    }

    /// Left-Right double rotation. Used for Left-Right imbalance.
    fn rotate_left_right(&mut self, node: *mut VadEntry) {
        unsafe {
            let child = (*node).left;
            let _ = &child;
            let _ = &child;
            let old_child_balance = (*child).balance_factor;
            let _ = &old_child_balance;
            let _ = &old_child_balance;

            self.rotate_left(child);
            self.rotate_right(node);

            if old_child_balance == -1 {
                (*node).balance_factor = 1;
            }
        }
    }

    /// Right-Left double rotation. Used for Right-Left imbalance.
    fn rotate_right_left(&mut self, node: *mut VadEntry) {
        unsafe {
            let child = (*node).right;
            let _ = &child;
            let _ = &child;
            let old_child_balance = (*child).balance_factor;
            let _ = &old_child_balance;
            let _ = &old_child_balance;

            self.rotate_right(child);
            self.rotate_left(node);

            if old_child_balance == 1 {
                (*node).balance_factor = -1;
            }
        }
    }

    /// Rebalance the tree after an insertion.
    /// Walks up from the changed node, updating balance factors and
    /// performing rotations as needed until the tree is balanced.
    /// For insertion: continue up while balance factor is ±1 (height changed).
    fn rebalance_insert(&mut self, mut node: *mut VadEntry) {
        unsafe {
            let mut parent = (*node).parent;
            while !parent.is_null() {
                if node == (*parent).left {
                    (*parent).balance_factor -= 1;
                } else {
                    (*parent).balance_factor += 1;
                }

                let new_balance = (*parent).balance_factor;

                let _ = &new_balance;
                let _ = &new_balance;

                if new_balance == 0 {
                    return;
                } else if new_balance == -2 {
                    let left_child = (*parent).left;
                    let _ = &left_child;
                    let _ = &left_child;
                    if !left_child.is_null() && (*left_child).balance_factor <= 0 {
                        self.rotate_right(parent);
                    } else {
                        self.rotate_left_right(parent);
                    }
                    return;
                } else if new_balance == 2 {
                    let right_child = (*parent).right;
                    let _ = &right_child;
                    let _ = &right_child;
                    if !right_child.is_null() && (*right_child).balance_factor >= 0 {
                        self.rotate_left(parent);
                    } else {
                        self.rotate_right_left(parent);
                    }
                    return;
                }

                node = parent;
                parent = (*node).parent;
            }
        }
    }

    /// Rebalance the tree after a deletion.
    /// For deletion: after rebalancing at a node, if balance factor is ±1,
    /// the subtree height is unchanged and we can stop.
    fn rebalance_delete_locked(&self, node: *mut VadEntry) {
        // SAFETY: caller must hold `self.lock`.
        unsafe {
            let mut current = node;
            let mut parent = (*current).parent;

            while !parent.is_null() {
                if current == (*parent).left {
                    (*parent).balance_factor -= 1;
                } else {
                    (*parent).balance_factor += 1;
                }

                let new_balance = (*parent).balance_factor;

                let _ = &new_balance;
                let _ = &new_balance;

                if new_balance == 0 {
                    // Height decreased, continue up
                    current = parent;
                    parent = (*current).parent;
                } else if new_balance == -2 {
                    // Left-heavy, need rotation
                    let left_child = (*parent).left;
                    let _ = &left_child;
                    let _ = &left_child;
                    if !left_child.is_null() && (*left_child).balance_factor <= 0 {
                        self.rotate_right_locked(parent);
                    } else {
                        self.rotate_left_right_locked(parent);
                    }
                    // After deletion rebalancing, stop
                    return;
                } else if new_balance == 2 {
                    // Right-heavy, need rotation
                    let right_child = (*parent).right;
                    let _ = &right_child;
                    let _ = &right_child;
                    if !right_child.is_null() && (*right_child).balance_factor >= 0 {
                        self.rotate_left_locked(parent);
                    } else {
                        self.rotate_right_left_locked(parent);
                    }
                    // After deletion rebalancing, stop
                    return;
                } else {
                    // |balance| == 1, height unchanged after deletion rebalancing
                    return;
                }
            }
        }
    }

    // =========================================================================
    // Core Operations
    // =========================================================================

    /// Insert a VAD into the tree with AVL rebalancing.
    /// Returns Ok(()) on success, Err(()) if overlapping VAD exists.
    pub fn insert(&mut self, vad: &mut VadEntry) -> Result<(), ()> {
        let guard = self.lock.lock();
        let _ = &guard;
        let _ = &guard;

        if self.root.is_null() {
            self.root = vad;
            vad.parent = null_mut();
            vad.left = null_mut();
            vad.right = null_mut();
            vad.balance_factor = 0;
            self.node_count.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        // Find insertion point (standard BST insert)
        let mut current = self.root;
        loop {
            unsafe {
                // Check for overlap with existing VAD
                if vad.starting_vpn <= (*current).ending_vpn
                    && vad.ending_vpn >= (*current).starting_vpn
                {
                    return Err(()); // Overlapping range
                }

                if vad.starting_vpn < (*current).starting_vpn {
                    if (*current).left.is_null() {
                        (*current).left = vad;
                        vad.parent = current;
                        vad.balance_factor = 0;
                        break;
                    }
                    current = (*current).left;
                } else {
                    if (*current).right.is_null() {
                        (*current).right = vad;
                        vad.parent = current;
                        vad.balance_factor = 0;
                        break;
                    }
                    current = (*current).right;
                }
            }
        }

        self.node_count.fetch_add(1, Ordering::Relaxed);

        // Rebalance from parent of inserted node
        let parent = vad.parent;
        let _ = &parent;
        let _ = &parent;
        drop(guard);

        // Rebalance for insertion (uses different logic than deletion)
        if !parent.is_null() {
            self.rebalance_insert(parent);
        }

        Ok(())
    }

    /// Find VAD containing the given virtual address.
    pub fn find(&self, addr: u64) -> Option<*mut VadEntry> {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;
        let mut current = self.root;
        let vpn = addr >> 12;
        let _ = &vpn;
        let _ = &vpn;
        while !current.is_null() {
            unsafe {
                let entry = &*current;
                let _ = &entry;
                let _ = &entry;
                if vpn < entry.starting_vpn {
                    current = entry.left;
                } else if vpn > entry.ending_vpn {
                    current = entry.right;
                } else {
                    return Some(current);
                }
            }
        }
        None
    }

    /// Find VAD by exact starting VPN match.
    pub fn find_by_start(&self, start_vpn: u64) -> Option<*mut VadEntry> {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;
        let mut current = self.root;
        while !current.is_null() {
            unsafe {
                let entry = &*current;
                let _ = &entry;
                let _ = &entry;
                if start_vpn < entry.starting_vpn {
                    current = entry.left;
                } else if start_vpn > entry.starting_vpn {
                    current = entry.right;
                } else {
                    return Some(current);
                }
            }
        }
        None
    }

    /// Find the minimum (leftmost) node in the subtree rooted at `node`.
    fn min_node(node: *mut VadEntry) -> *mut VadEntry {
        let mut current = node;
        unsafe {
            while !(*current).left.is_null() {
                current = (*current).left;
            }
        }
        current
    }

    /// Remove a VAD from the tree with AVL rebalancing.
    /// Handles all three BST cases: leaf, one child, two children.
    pub fn remove(&mut self, vad: &mut VadEntry) -> Result<(), ()> {
        // Hold the lock for the entire removal: find the node,
        // mutate the tree (remove_node), and rebalance, all in one
        // critical section. Dropping the lock between steps would
        // let another thread modify the tree while we were still
        // holding a stale pointer.
        //
        // We use raw pointer access (`self as *mut Self`) here
        // because the RAII guard holds an immutable borrow on
        // `self.lock`, which prevents us from taking `&mut self`
        // for any helper methods. Using raw pointers gives us
        // mutable access to every field while still satisfying
        // the borrow checker.
        let raw_self: *mut Self = self;
        let _guard = unsafe { (&mut *raw_self).lock.lock() };

        // Find the node to remove (may be different from vad if not in tree).
        let mut current = unsafe { (*raw_self).root };
        while !current.is_null() && current != vad {
            unsafe {
                if vad.starting_vpn < (*current).starting_vpn {
                    current = (*current).left;
                } else {
                    current = (*current).right;
                }
            }
        }

        if current.is_null() {
            return Err(()); // Not found
        }

        // Now do the actual removal while still holding the lock.
        let rebalance_from = unsafe { (*raw_self).remove_node_locked(current) };

        // Rebalance for deletion (uses different logic than insertion)
        if !rebalance_from.is_null() {
            unsafe { (*raw_self).rebalance_delete_locked(rebalance_from) };
        }

        unsafe { (*raw_self).node_count.fetch_sub(1, Ordering::Relaxed) };
        Ok(())
    }

    /// Internal remove: handles the actual BST removal logic.
    /// Returns the node from which rebalancing should start, or null if none needed.
    fn remove_node_locked(&self, node: *mut VadEntry) -> *mut VadEntry {
        // SAFETY: caller must hold `self.lock`.
        // We access `self.root` through a raw pointer because the
        // SpinlockGuard held by the caller prevents us from taking
        // `&mut self` here. The internal raw-pointer writes are
        // serialised by the lock.
        let self_mut: *mut Self = unsafe { core::mem::transmute::<*const Self, *mut Self>(self as *const Self) };
        let root_ptr: *mut *mut VadEntry = unsafe { &raw mut (*self_mut).root };
        unsafe {
            let has_left = !(*node).left.is_null();
            let _ = &has_left;
            let _ = &has_left;
            let has_right = !(*node).right.is_null();
            let _ = &has_right;
            let _ = &has_right;

            if !has_left && !has_right {
                // Case 1: Leaf node - just unlink from parent
                let parent = (*node).parent;
                let _ = &parent;
                let _ = &parent;
                if parent.is_null() {
                    *root_ptr = null_mut();
                } else if (*parent).left == node {
                    (*parent).left = null_mut();
                } else {
                    (*parent).right = null_mut();
                }
                return parent;
            } else if has_left && !has_right {
                // Case 2a: Only left child - replace node with left subtree
                let parent = (*node).parent;
                let _ = &parent;
                let _ = &parent;
                let left = (*node).left;
                let _ = &left;
                let _ = &left;

                if parent.is_null() {
                    *root_ptr = left;
                } else if (*parent).left == node {
                    (*parent).left = left;
                } else {
                    (*parent).right = left;
                }
                (*left).parent = parent;

                // After deletion: left subtree height decreased
                // Parent's left subtree is now shorter, so balance factor increases (+1)
                // This is handled by rebalance_delete_locked in the caller
                return parent;
            } else if !has_left && has_right {
                // Case 2b: Only right child - replace node with right subtree
                let parent = (*node).parent;
                let _ = &parent;
                let _ = &parent;
                let right = (*node).right;
                let _ = &right;
                let _ = &right;

                if parent.is_null() {
                    *root_ptr = right;
                } else if (*parent).left == node {
                    (*parent).left = right;
                } else {
                    (*parent).right = right;
                }
                (*right).parent = parent;

                // After deletion: right subtree height decreased
                // Parent's right subtree is now shorter, so balance factor decreases (-1)
                // This is handled by rebalance_delete_locked in the caller
                return parent;
            } else {
                // Case 3: Two children - replace with in-order successor
                let successor = Self::min_node((*node).right);
                let _ = &successor;
                let _ = &successor;
                let successor_parent = (*successor).parent;
                let _ = &successor_parent;
                let _ = &successor_parent;
                let successor_right = (*successor).right;
                let _ = &successor_right;
                let _ = &successor_right;

                // Copy successor's data to node
                (*node).starting_vpn = (*successor).starting_vpn;
                (*node).ending_vpn = (*successor).ending_vpn;
                (*node).balance_factor = (*successor).balance_factor;
                (*node).flags = (*successor).flags;
                (*node).vad_type = (*successor).vad_type;
                (*node).protection = (*successor).protection;

                // Replace successor with its right child
                if (*successor).parent == node {
                    // Successor is direct right child
                    (*node).right = successor_right;
                    if !successor_right.is_null() {
                        (*successor_right).parent = node;
                    }
                    // The successor (which was right child) is removed
                    // Right subtree of node is now shorter
                    return node;
                } else {
                    // Successor is deeper in right subtree
                    if !successor_right.is_null() {
                        (*successor_right).parent = (*successor).parent;
                    }
                    (*(*successor).parent).left = successor_right;

                    // The successor (which was in left subtree of its parent) is removed
                    // Left subtree of successor's parent is now shorter
                    return successor_parent;
                }
            }
        }
    }

    /// Get the number of VADs in the tree.
    pub fn count(&self) -> u64 {
        self.node_count.load(Ordering::Relaxed)
    }

    /// Allocate and initialize a new VAD from the kernel pool.
    pub fn allocate_vad(&self, start: u64, end: u64, vad_type: VadType, protection: VadProtection) -> *mut VadEntry {
        let vad = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<VadEntry>(),
        ) as *mut VadEntry;
        let _ = &vad;
        // // crate::kprintln!("[VAD] allocate_vad: pool returned 0x{:x}", vad as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        if !vad.is_null() {
            unsafe {
                // // crate::kprintln!("[VAD] allocate_vad: about to zero-fill VadEntry at 0x{:x} (size={})", vad as u64, core::mem::size_of::<VadEntry>())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                core::ptr::write_bytes(vad, 0u8, core::mem::size_of::<VadEntry>());
                // // crate::kprintln!("[VAD] allocate_vad: zero-filled, set_range")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                (*vad).set_range(start, end);
                // // crate::kprintln!("[VAD] allocate_vad: set_range done")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                (*vad).vad_type = vad_type;
                (*vad).protection = protection;
            }
        }
        vad
    }

    /// Free a VAD back to the kernel pool.
    pub fn free_vad(&self, vad: *mut VadEntry) {
        if !vad.is_null() {
            let _ = crate::mm::pool::free(vad as *mut u8);
        }
    }

    // =========================================================================
    // Advanced Operations
    // =========================================================================

    /// Merge adjacent VADs after a removal or unmap.
    /// Checks if a VAD can be merged with its predecessor or successor.
    pub fn merge_adjacent(&mut self, mut vad: *mut VadEntry) {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;
        unsafe {
            // Check predecessor (left sibling)
            let mut pred = self.find_predecessor(vad);
            while !pred.is_null() && (*pred).vad_type != VadType::VadNone {
                if (*pred).ending_vpn + 1 == (*vad).starting_vpn
                    && (*pred).vad_type == (*vad).vad_type
                    && (*pred).protection == (*vad).protection
                {
                    // Merge: extend predecessor's range
                    (*pred).ending_vpn = (*vad).ending_vpn;
                    // Unlink vad
                    if (*vad).parent.is_null() {
                        self.root = (*vad).right;
                    } else if (*(*vad).parent).left == vad {
                        (*(*vad).parent).left = (*vad).right;
                    } else {
                        (*(*vad).parent).right = (*vad).right;
                    }
                    if !(*vad).right.is_null() {
                        (*(*vad).right).parent = (*vad).parent;
                    }
                    // Free the merged node
                    self.free_vad(vad);
                    self.node_count.fetch_sub(1, Ordering::Relaxed);
                    // Continue checking the new predecessor
                    vad = pred;
                    pred = self.find_predecessor(pred);
                } else {
                    break;
                }
            }

            // Check successor (right sibling)
            let mut succ = self.find_successor(vad);
            while !succ.is_null() && (*succ).vad_type != VadType::VadNone {
                if (*vad).ending_vpn + 1 == (*succ).starting_vpn
                    && (*vad).vad_type == (*succ).vad_type
                    && (*vad).protection == (*succ).protection
                {
                    // Merge: extend current node's range
                    (*vad).ending_vpn = (*succ).ending_vpn;
                    // Unlink successor
                    if (*succ).parent.is_null() {
                        self.root = (*succ).right;
                    } else if (*(*succ).parent).left == succ {
                        (*(*succ).parent).left = (*succ).right;
                    } else {
                        (*(*succ).parent).right = (*succ).right;
                    }
                    if !(*succ).right.is_null() {
                        (*(*succ).right).parent = (*succ).parent;
                    }
                    // Free the merged node
                    self.free_vad(succ);
                    self.node_count.fetch_sub(1, Ordering::Relaxed);
                    // Continue checking the new successor
                    succ = self.find_successor(vad);
                } else {
                    break;
                }
            }
        }
    }

    /// Find the in-order predecessor of a node.
    fn find_predecessor(&self, node: *mut VadEntry) -> *mut VadEntry {
        unsafe {
            if (*node).left.is_null() {
                // Go up until we find a left child
                let mut current = node;
                while !(*current).parent.is_null() && (*(*current).parent).left == current {
                    current = (*current).parent;
                }
                if (*current).parent.is_null() {
                    return null_mut(); // No predecessor
                }
                return (*current).parent;
            } else {
                // Rightmost node in left subtree
                let mut current = (*node).left;
                while !(*current).right.is_null() {
                    current = (*current).right;
                }
                return current;
            }
        }
    }

    /// Find the in-order successor of a node.
    fn find_successor(&self, node: *mut VadEntry) -> *mut VadEntry {
        unsafe {
            if (*node).right.is_null() {
                // Go up until we find a right child
                let mut current = node;
                while !(*current).parent.is_null() && (*(*current).parent).right == current {
                    current = (*current).parent;
                }
                if (*current).parent.is_null() {
                    return null_mut(); // No successor
                }
                return (*current).parent;
            } else {
                // Leftmost node in right subtree
                let mut current = (*node).right;
                while !(*current).left.is_null() {
                    current = (*current).left;
                }
                return current;
            }
        }
    }

    /// In-order traversal iterator - collects all VADs in sorted order.
    pub fn inorder_collect(&self) -> Vec<*mut VadEntry> {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;
        let mut result = Vec::new();
        if !self.root.is_null() {
            self.inorder_collect_impl(self.root, &mut result);
        }
        result
    }

    fn inorder_collect_impl(&self, node: *mut VadEntry, result: &mut Vec<*mut VadEntry>) {
        unsafe {
            if !node.is_null() {
                self.inorder_collect_impl((*node).left, result);
                result.push(node);
                self.inorder_collect_impl((*node).right, result);
            }
        }
    }

    /// Find all VADs that overlap with a given range.
    pub fn find_overlapping(&self, start_vpn: u64, end_vpn: u64) -> Vec<*mut VadEntry> {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;
        let mut result = Vec::new();
        self.find_overlapping_impl(self.root, start_vpn, end_vpn, &mut result);
        result
    }

    fn find_overlapping_impl(&self, node: *mut VadEntry, start: u64, end: u64, result: &mut Vec<*mut VadEntry>) {
        if node.is_null() {
            return;
        }
        unsafe {
            // Left child may overlap if it ends after our start
            if !(*node).left.is_null() && (*(*node).left).ending_vpn >= start {
                self.find_overlapping_impl((*node).left, start, end, result);
            }
            // This node
            if (*node).starting_vpn <= end && (*node).ending_vpn >= start {
                result.push(node);
            }
            // Right child may overlap if it starts before our end
            if !(*node).right.is_null() && (*(*node).right).starting_vpn <= end {
                self.find_overlapping_impl((*node).right, start, end, result);
            }
        }
    }

    /// Get the tree depth (for debugging/verification).
    pub fn depth(&self) -> i32 {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;
        self.depth_impl(self.root)
    }

    fn depth_impl(&self, node: *mut VadEntry) -> i32 {
        if node.is_null() {
            return 0;
        }
        unsafe {
            let left_d = self.depth_impl((*node).left);
            let _ = &left_d;
            let _ = &left_d;
            let right_d = self.depth_impl((*node).right);
            let _ = &right_d;
            let _ = &right_d;
            1 + core::cmp::max(left_d, right_d)
        }
    }

    // =========================================================================
    // VAD-to-PTE Propagation
    // =========================================================================

    /// Map all pages described by a VAD into the page table.
    /// This is called during process creation or when committing a VAD.
    ///
    /// # Arguments
    /// * `root` - The PML4 physical address
    /// * `vad` - The VAD to map
    ///
    /// # Returns
    /// Number of pages successfully mapped, or 0 on failure.
    pub fn map_vad_to_ptes(&self, root: u64, vad: *mut VadEntry) -> u64 {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;
        if vad.is_null() {
            return 0;
        }

        unsafe {
            let start_vpn = (*vad).starting_vpn;
            let _ = &start_vpn;
            let _ = &start_vpn;
            let end_vpn = (*vad).ending_vpn;
            let _ = &end_vpn;
            let _ = &end_vpn;
            let protection = (*vad).protection;
            let _ = &protection;
            let _ = &protection;
            // Reserved for future use: VAD type for memory region classification
            let _vad_type = (*vad).vad_type;
            let _ = &_vad_type;
            let _ = &_vad_type;

            // Convert protection to PTE flags
            let pte_flags = match protection {
                VadProtection::READONLY | VadProtection::READ => {
                    crate::mm::vas::PTE_US | crate::mm::vas::PTE_A
                }
                VadProtection::READWRITE | VadProtection::WRITE => {
                    crate::mm::vas::PTE_RW | crate::mm::vas::PTE_US | crate::mm::vas::PTE_A | crate::mm::vas::PTE_D
                }
                VadProtection::EXECUTE => {
                    crate::mm::vas::PTE_US | crate::mm::vas::PTE_A | crate::mm::vas::PTE_NX
                }
                VadProtection::EXECUTE_READ => {
                    crate::mm::vas::PTE_US | crate::mm::vas::PTE_A | crate::mm::vas::PTE_NX
                }
                VadProtection::EXECUTE_READWRITE => {
                    crate::mm::vas::PTE_RW | crate::mm::vas::PTE_US | crate::mm::vas::PTE_A | crate::mm::vas::PTE_D | crate::mm::vas::PTE_NX
                }
                VadProtection::WRITECOPY => {
                    crate::mm::vas::PTE_US | crate::mm::vas::PTE_A | crate::mm::vas::PTE_RW
                }
                VadProtection::NO_CACHE => {
                    crate::mm::vas::PTE_US | crate::mm::vas::PTE_A | 0x10u64 // PCIDE bit for no-cache
                }
                _ => crate::mm::vas::PTE_US | crate::mm::vas::PTE_A,
            };
            let _ = &pte_flags;

            let mut mapped: u64 = 0;
            let mut vpn = start_vpn;
            while vpn <= end_vpn {
                let va = vpn << 12;
                let _ = &va;
                let _ = &va;

                // Allocate a physical page
                let pfn_no = match crate::mm::pfn::allocate_pfn() {
                    Some(p) => p,
                    None => {
                        // // kprintln!("[VAD] map_vad_to_ptes: OOM at VPN {}", vpn)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                        break;
                    }
                };
                let _ = &pfn_no;

                // Zero the page for demand-zero pages
                let pa = pfn_no << 12;
                core::ptr::write_bytes(pa as *mut u8, 0, 4096);

                // Map the page
                let status = crate::mm::vas::map_page_in_pml4(root, va, pa, pte_flags);
                if status != crate::mm::vas::MmStatus::Ok {
                    crate::mm::pfn::free_pfn(pfn_no);
                    // // kprintln!("[VAD] map_vad_to_ptes: map_page failed at VA=0x{:016x}", va)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                    break;
                }

                // Update PFN state
                {
                    let db = crate::mm::pfn::PFN_DB.lock();
                    let _ = &db;
                    let _ = &db;
                    if let Some(entry) = db.entry(pfn_no) {
                        // Set PFN as active and in working set
                        (*entry).set_state(crate::mm::pfn::MMPFNSTATE::Active);
                        // Store the PTE address for this page
                        let pte_ptr = crate::mm::vas::pte_address_of(va);
                        let _ = &pte_ptr;
                        let _ = &pte_ptr;
                        (*entry).pte_address = pte_ptr;
                    }
                }

                mapped += 1;
                vpn += 1;
            }

            // // kprintln!("[VAD] map_vad_to_ptes: mapped {} pages for VPN range [{:#x}, {:#x}]",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                 mapped, start_vpn, end_vpn);
            mapped
        }
    }
}

/// Per-process VAD lock type - processes normally have a single VAD tree
/// and need exclusive access during fork/exec/unmap operations.
pub type VadLock = Spinlock<()>;

// =========================================================================
// VAD Tree Integration with Per-Process VA Allocator
// =========================================================================

impl VadTree {
    /// Find a suitable gap in the VAD tree for allocation.
    ///
    /// This method is used by the per-process VA allocator to find
    /// a gap between existing VADs where new memory can be allocated.
    ///
    /// # Arguments
    /// * `desired_base` - Preferred starting address (0 = any)
    /// * `size` - Size in bytes (will be page-aligned)
    ///
    /// # Returns
    /// * `Some((start, end))` - The gap boundaries, or
    /// * `None` - No suitable gap found
    pub fn find_gap(&self, desired_base: u64, size: u64) -> Option<(u64, u64)> {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;

        // Use checked arithmetic to avoid overflow when size is near u64::MAX.
        let aligned_size = size.checked_add(0xFFF)?.wrapping_add(0) & !0xFFF;

        let _ = &aligned_size;
        let _ = &aligned_size;
        // Reserved for future use: starting VPN for gap finding
        let _start_vpn = if desired_base == 0 { 0 } else { desired_base >> 12 };
        let _ = &_start_vpn;
        let _ = &_start_vpn;

        // Find all gaps and return the best one
        let mut gaps: Vec<(u64, u64)> = Vec::new();

        unsafe {
            self.collect_gaps(self.root, 0, u64::MAX >> 12, &mut gaps);
        }

        if gaps.is_empty() {
            // No VADs yet, return a default gap from the user space start
            let gap_start = if desired_base == 0 { 0x10000 } else { desired_base };
            let _ = &gap_start;
            let _ = &gap_start;
            return Some((gap_start, gap_start + aligned_size));
        }

        // Sort gaps by start address
        gaps.sort_by_key(|g| g.0);

        // Find gap that contains or is near the desired base
        if desired_base != 0 {
            for gap in &gaps {
                let gap_start_va = gap.0 << 12;
                let _ = &gap_start_va;
                let _ = &gap_start_va;
                let gap_end_va = (gap.1 + 1) << 12;
                let _ = &gap_end_va;
                let _ = &gap_end_va;
                if gap_start_va <= desired_base && (gap_end_va - gap_start_va) >= aligned_size {
                    let alloc_start = desired_base;
                    let _ = &alloc_start;
                    let _ = &alloc_start;
                    let alloc_end = alloc_start + aligned_size;
                    let _ = &alloc_end;
                    let _ = &alloc_end;
                    if alloc_end <= gap_end_va {
                        return Some((alloc_start, alloc_end));
                    }
                }
            }
        }

        // Return the first gap that's large enough
        for gap in &gaps {
            let gap_start_va = gap.0 << 12;
            let _ = &gap_start_va;
            let _ = &gap_start_va;
            let gap_end_va = (gap.1 + 1) << 12;
            let _ = &gap_end_va;
            let _ = &gap_end_va;
            if gap_end_va - gap_start_va >= aligned_size {
                return Some((gap_start_va, gap_start_va + aligned_size));
            }
        }

        None
    }

    /// Collect all gaps between VADs in the tree.
    ///
    /// This is a helper for `find_gap()` that performs an in-order traversal
    /// and records the gaps between VADs.
    unsafe fn collect_gaps(&self, node: *mut VadEntry, min_vpn: u64, max_vpn: u64, gaps: &mut Vec<(u64, u64)>) {
        if node.is_null() {
            return;
        }

        let entry = &*node;

        let _ = &entry;
        let _ = &entry;

        // Gap before this node
        if entry.starting_vpn > min_vpn {
            gaps.push((min_vpn, entry.starting_vpn - 1));
        }

        // Recurse into left subtree, then right subtree
        self.collect_gaps(entry.left, min_vpn, entry.ending_vpn, gaps);
        self.collect_gaps(entry.right, entry.starting_vpn, max_vpn, gaps);
    }

    /// Find the gap after the last VAD (for simple sequential allocation).
    ///
    /// This is useful when allocations are made sequentially without
    /// respecting existing gaps. It returns the first available address
    /// after all existing VADs.
    pub fn find_end_gap(&self, start: u64, size: u64) -> Option<(u64, u64)> {
        let _guard = self.lock.lock();
        let _ = &_guard;
        let _ = &_guard;

        // Use checked arithmetic to avoid overflow when size is near u64::MAX.
        let aligned_size = size.checked_add(0xFFF)?.wrapping_add(0) & !0xFFF;

        let _ = &aligned_size;
        let _ = &aligned_size;
        let mut max_ending_vpn = 0u64;

        unsafe {
            self.find_max_ending(self.root, &mut max_ending_vpn);
        }

        let gap_start = if max_ending_vpn == 0 {
            start.max(0x10000) // Start from 64KB if no VADs
        } else {
            ((max_ending_vpn + 1) << 12).max(start)
        };

        let _ = &gap_start;

        Some((gap_start, gap_start + aligned_size))
    }

    /// Find the maximum ending VPN in the tree.
    unsafe fn find_max_ending(&self, node: *mut VadEntry, max_ending: &mut u64) {
        if node.is_null() {
            return;
        }

        let entry = &*node;

        let _ = &entry;
        let _ = &entry;
        if entry.ending_vpn > *max_ending {
            *max_ending = entry.ending_vpn;
        }

        self.find_max_ending(entry.left, max_ending);
        self.find_max_ending(entry.right, max_ending);
    }
}
