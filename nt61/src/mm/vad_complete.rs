//! Memory Management - VAD Tree Complete Implementation
//!
//! AVL-balanced Virtual Address Descriptor tree for efficient
//! address space management.

use alloc::boxed::Box;
use core::cmp::{max, Ordering};

#[derive(Debug, Clone)]
pub struct VadEntry {
    pub start_address: u64,
    pub end_address: u64,
    pub protection: u32,
    pub commit_charge: usize,
    pub flags: VadFlags,
    pub file_object: Option<u64>,
    pub offset: u64,
}

bitflags::bitflags! {
    pub struct VadFlags: u32 {
        const COMMITTED = 0x0001;
        const PRIVATE = 0x0002;
        const MAPPED = 0x0004;
        const IMAGE = 0x0008;
        const NO_CACHE = 0x0010;
        const LARGE_PAGES = 0x0020;
    }
}

struct VadNode {
    entry: VadEntry,
    left: Option<Box<VadNode>>,
    right: Option<Box<VadNode>>,
    height: i32,
}

impl VadNode {
    fn new(entry: VadEntry) -> Self {
        Self {
            entry,
            left: None,
            right: None,
            height: 1,
        }
    }

    fn update_height(&mut self) {
        let left_height = self.left.as_ref().map_or(0, |n| n.height);
        let right_height = self.right.as_ref().map_or(0, |n| n.height);
        self.height = 1 + max(left_height, right_height);
    }

    fn balance_factor(&self) -> i32 {
        let left_height = self.left.as_ref().map_or(0, |n| n.height);
        let right_height = self.right.as_ref().map_or(0, |n| n.height);
        left_height - right_height
    }
}

pub struct VadTree {
    root: Option<Box<VadNode>>,
    count: usize,
}

impl VadTree {
    pub const fn new() -> Self {
        Self {
            root: None,
            count: 0,
        }
    }

    pub fn insert(&mut self, entry: VadEntry) -> Result<(), &'static str> {
        if self.find_overlapping(entry.start_address, entry.end_address).is_some() {
            return Err("Address range overlaps with existing VAD");
        }

        self.root = Some(Self::insert_node(self.root.take(), entry)?);
        self.count += 1;
        Ok(())
    }

    fn insert_node(
        node: Option<Box<VadNode>>,
        entry: VadEntry,
    ) -> Result<Box<VadNode>, &'static str> {
        let mut node = match node {
            None => return Ok(Box::new(VadNode::new(entry))),
            Some(n) => n,
        };

        match entry.start_address.cmp(&node.entry.start_address) {
            Ordering::Less => {
                node.left = Some(Self::insert_node(node.left.take(), entry)?);
            }
            Ordering::Greater => {
                node.right = Some(Self::insert_node(node.right.take(), entry)?);
            }
            Ordering::Equal => {
                return Err("Duplicate VAD entry");
            }
        }

        node.update_height();
        Ok(Self::balance(node))
    }

    pub fn find_vad(&self, address: u64) -> Option<&VadEntry> {
        Self::find_node(self.root.as_ref(), address)
    }

    fn find_node(node: Option<&Box<VadNode>>, address: u64) -> Option<&VadEntry> {
        let node = node?;

        if address >= node.entry.start_address && address <= node.entry.end_address {
            return Some(&node.entry);
        }

        if address < node.entry.start_address {
            Self::find_node(node.left.as_ref(), address)
        } else {
            Self::find_node(node.right.as_ref(), address)
        }
    }

    pub fn find_overlapping(&self, start: u64, end: u64) -> Option<&VadEntry> {
        Self::find_overlapping_node(self.root.as_ref(), start, end)
    }

    fn find_overlapping_node(
        node: Option<&Box<VadNode>>,
        start: u64,
        end: u64,
    ) -> Option<&VadEntry> {
        let node = node?;

        if start <= node.entry.end_address && end >= node.entry.start_address {
            return Some(&node.entry);
        }

        if let Some(entry) = Self::find_overlapping_node(node.left.as_ref(), start, end) {
            return Some(entry);
        }

        Self::find_overlapping_node(node.right.as_ref(), start, end)
    }

    pub fn remove(&mut self, start_address: u64) -> Option<VadEntry> {
        let (new_root, removed) = Self::remove_node(self.root.take(), start_address);
        self.root = new_root;
        if removed.is_some() {
            self.count -= 1;
        }
        removed
    }

    fn remove_node(
        node: Option<Box<VadNode>>,
        start_address: u64,
    ) -> (Option<Box<VadNode>>, Option<VadEntry>) {
        let mut node = match node {
            None => return (None, None),
            Some(n) => n,
        };

        match start_address.cmp(&node.entry.start_address) {
            Ordering::Less => {
                let (new_left, removed) = Self::remove_node(node.left.take(), start_address);
                node.left = new_left;
                node.update_height();
                (Some(Self::balance(node)), removed)
            }
            Ordering::Greater => {
                let (new_right, removed) = Self::remove_node(node.right.take(), start_address);
                node.right = new_right;
                node.update_height();
                (Some(Self::balance(node)), removed)
            }
            Ordering::Equal => {
                let entry = node.entry.clone();

                if node.left.is_none() {
                    return (node.right.take(), Some(entry));
                } else if node.right.is_none() {
                    return (node.left.take(), Some(entry));
                }

                let (new_right, successor_entry) = Self::remove_min(node.right.take().unwrap());
                node.entry = successor_entry;
                node.right = new_right;
                node.update_height();

                (Some(Self::balance(node)), Some(entry))
            }
        }
    }

    fn remove_min(mut node: Box<VadNode>) -> (Option<Box<VadNode>>, VadEntry) {
        if node.left.is_none() {
            return (node.right.take(), node.entry.clone());
        }

        let (new_left, entry) = Self::remove_min(node.left.take().unwrap());
        node.left = new_left;
        node.update_height();
        (Some(Self::balance(node)), entry)
    }

    fn balance(mut node: Box<VadNode>) -> Box<VadNode> {
        let balance_factor = node.balance_factor();

        if balance_factor > 1 {
            if let Some(ref left) = node.left {
                if left.balance_factor() < 0 {
                    node.left = Some(Self::rotate_left(node.left.take().unwrap()));
                }
            }
            return Self::rotate_right(node);
        }

        if balance_factor < -1 {
            if let Some(ref right) = node.right {
                if right.balance_factor() > 0 {
                    node.right = Some(Self::rotate_right(node.right.take().unwrap()));
                }
            }
            return Self::rotate_left(node);
        }

        node
    }

    fn rotate_left(mut node: Box<VadNode>) -> Box<VadNode> {
        let mut new_root = node.right.take().unwrap();
        node.right = new_root.left.take();
        node.update_height();
        new_root.left = Some(node);
        new_root.update_height();
        new_root
    }

    fn rotate_right(mut node: Box<VadNode>) -> Box<VadNode> {
        let mut new_root = node.left.take().unwrap();
        node.left = new_root.right.take();
        node.update_height();
        new_root.right = Some(node);
        new_root.update_height();
        new_root
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn collect_all(&self) -> alloc::vec::Vec<&VadEntry> {
        let mut result = alloc::vec::Vec::new();
        Self::inorder_traverse(self.root.as_ref(), &mut result);
        result
    }

    fn inorder_traverse<'a>(
        node: Option<&'a Box<VadNode>>,
        result: &mut alloc::vec::Vec<&'a VadEntry>,
    ) {
        if let Some(node) = node {
            Self::inorder_traverse(node.left.as_ref(), result);
            result.push(&node.entry);
            Self::inorder_traverse(node.right.as_ref(), result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vad_insert_and_find() {
        let mut tree = VadTree::new();

        let entry1 = VadEntry {
            start_address: 0x1000,
            end_address: 0x2000,
            protection: 0,
            commit_charge: 0,
            flags: VadFlags::COMMITTED,
            file_object: None,
            offset: 0,
        };

        assert!(tree.insert(entry1).is_ok());
        assert_eq!(tree.count(), 1);

        assert!(tree.find_vad(0x1500).is_some());
        assert!(tree.find_vad(0x3000).is_none());
    }

    #[test]
    fn test_vad_overlap_detection() {
        let mut tree = VadTree::new();

        let entry1 = VadEntry {
            start_address: 0x1000,
            end_address: 0x2000,
            protection: 0,
            commit_charge: 0,
            flags: VadFlags::COMMITTED,
            file_object: None,
            offset: 0,
        };

        tree.insert(entry1).unwrap();

        let overlapping = VadEntry {
            start_address: 0x1500,
            end_address: 0x2500,
            protection: 0,
            commit_charge: 0,
            flags: VadFlags::COMMITTED,
            file_object: None,
            offset: 0,
        };

        assert!(tree.insert(overlapping).is_err());
    }

    #[test]
    fn test_vad_remove() {
        let mut tree = VadTree::new();

        let entry = VadEntry {
            start_address: 0x1000,
            end_address: 0x2000,
            protection: 0,
            commit_charge: 0,
            flags: VadFlags::COMMITTED,
            file_object: None,
            offset: 0,
        };

        tree.insert(entry).unwrap();
        assert_eq!(tree.count(), 1);

        let removed = tree.remove(0x1000);
        assert!(removed.is_some());
        assert_eq!(tree.count(), 0);
    }
}
