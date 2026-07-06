//! Virtual File System (VFS)
//
//! Provides the abstraction layer between file operations and file systems
//! Implements NT-style object-based file system interface

use crate::fs::{FileObject, Vcb, UnicodeString};
use crate::ke::sync::Spinlock;
use core::ptr::null_mut;

/// Path separator
pub const PATH_SEPARATOR: u16 = b'\\' as u16;
pub const PATH_SEPARATOR_STR: &str = "\\";

/// VFS node types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsNodeType {
    Unknown = 0,
    File = 1,
    Directory = 2,
    Symlink = 3,
    MountPoint = 4,
}

/// VFS node (inode equivalent)
pub struct VfsNode {
    pub node_type: VfsNodeType,
    pub flags: u32,
    pub reference_count: u32,
    pub file_object: *mut FileObject,
    pub vcb: *mut Vcb,
    pub parent: *mut VfsNode,
    pub name: UnicodeString,
    pub byte_offset: i64,
    pub allocation_size: i64,
}

impl VfsNode {
    pub fn new() -> Self {
        Self {
            node_type: VfsNodeType::Unknown,
            flags: 0,
            reference_count: 0,
            file_object: null_mut(),
            vcb: null_mut(),
            parent: null_mut(),
            name: UnicodeString::new(),
            byte_offset: 0,
            allocation_size: 0,
        }
    }
}

/// Root directory entries
static ROOT_DIR: Spinlock<VfsRoot> = Spinlock::new(VfsRoot::new());

/// Maximum number of VFS nodes (increased for larger systems)
pub const MAX_VFS_NODES: usize = 1024;

/// Maximum number of mounted volumes
pub const MAX_VFS_VOLUMES: usize = 256;

pub struct VfsRoot {
    pub nodes: [*mut VfsNode; MAX_VFS_NODES],
    pub volumes: [*mut VfsNode; MAX_VFS_VOLUMES],
    pub node_count: usize,
    pub volume_count: usize,
}

impl VfsRoot {
    pub const fn new() -> Self {
        Self {
            nodes: [core::ptr::null_mut(); MAX_VFS_NODES],
            volumes: [core::ptr::null_mut(); MAX_VFS_VOLUMES],
            node_count: 0,
            volume_count: 0,
        }
    }

    /// Check if the node table has space for a new node.
    pub fn has_space(&self) -> bool {
        self.node_count < MAX_VFS_NODES
    }

    /// Check if the volume table has space for a new volume.
    pub fn has_volume_space(&self) -> bool {
        self.volume_count < MAX_VFS_VOLUMES
    }

    /// Add a node to the table.
    /// Returns the index of the added node, or None if no space.
    pub fn add_node(&mut self, node: *mut VfsNode) -> Option<usize> {
        if self.node_count < MAX_VFS_NODES {
            let idx = self.node_count;
            self.nodes[idx] = node;
            self.node_count += 1;
            Some(idx)
        } else {
            None
        }
    }

    /// Add a volume to both the volume and node tables.
    /// Returns true on success.
    pub fn add_volume(&mut self, volume: *mut VfsNode) -> bool {
        if self.volume_count < MAX_VFS_VOLUMES {
            self.volumes[self.volume_count] = volume;
            self.volume_count += 1;
        }
        if self.node_count < MAX_VFS_NODES {
            self.nodes[self.node_count] = volume;
            self.node_count += 1;
            true
        } else {
            false
        }
    }

    /// Find a node by index.
    pub fn get_node(&self, index: usize) -> Option<&'static mut VfsNode> {
        if index < self.node_count {
            let ptr = self.nodes[index];
            if !ptr.is_null() {
                return Some(unsafe { &mut *ptr });
            }
        }
        None
    }

    /// Get the number of nodes.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Get the number of volumes.
    pub fn volume_count(&self) -> usize {
        self.volume_count
    }
}

/// Open modes
#[derive(Debug, Clone, Copy)]
pub enum OpenMode {
    Read = 0,
    Write = 1,
    ReadWrite = 2,
    Append = 3,
    Execute = 4,
}

/// Create options
#[derive(Debug, Clone, Copy)]
pub enum CreateOption {
    None = 0,
    CreateNew = 1,
    CreateAlways = 2,
    OpenExisting = 3,
    OpenAlways = 4,
    TruncateExisting = 5,
    /// Replace existing file (alias for CreateAlways)
    FileSupersede,
    /// Fail if file exists (alias for CreateNew)
    FileCreate,
    /// Open if exists, create if not (alias for OpenAlways)
    FileOpenIf,
    /// Open and truncate if exists (alias for TruncateExisting)
    FileOverwriteIf,
}

/// Open file request
pub struct OpenRequest {
    pub file_name: UnicodeString,
    pub desired_access: u32,
    pub create_options: CreateOption,
    pub file_attributes: u32,
    pub root_directory: *mut VfsNode,
}

/// Maximum path length (per NTFS specification)
pub const MAX_PATH_LENGTH: usize = 32767;

/// Path component type for iteration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathComponentType {
    Normal,     // Regular name component
    Dot,        // Current directory "."
    DotDot,     // Parent directory ".."
}

/// A single path component with its type
pub struct PathComponent<'a> {
    pub component_type: PathComponentType,
    pub name: &'a [u16],
}

/// Path iterator for iterating over path components
pub struct PathIterator<'a> {
    path: &'a [u16],
    position: usize,
}

impl<'a> PathIterator<'a> {
    /// Create a new path iterator
    pub fn new(path: &'a [u16]) -> Self {
        Self { path, position: 0 }
    }

    /// Check if this is an absolute path (starts with separator)
    pub fn is_absolute(&self) -> bool {
        self.path.iter().any(|&c| c == PATH_SEPARATOR)
    }

    /// Get next path component
    pub fn next_component(&mut self) -> Option<PathComponent<'a>> {
        // Skip consecutive separators
        while self.position < self.path.len() && self.path[self.position] == PATH_SEPARATOR {
            self.position += 1;
        }

        if self.position >= self.path.len() {
            return None;
        }

        // Find end of component
        let start = self.position;
        let mut end = start;

        // Check for "." or ".."
        if self.path[end] == b'.' as u16 {
            if end + 1 < self.path.len() {
                if self.path[end + 1] == b'.' as u16 {
                    // ".." found
                    if end + 2 >= self.path.len() || self.path[end + 2] == PATH_SEPARATOR {
                        self.position = end + 2;
                        return Some(PathComponent {
                            component_type: PathComponentType::DotDot,
                            name: &self.path[start..end + 2],
                        });
                    }
                } else if self.path[end + 1] == PATH_SEPARATOR || end + 1 == self.path.len() {
                    // "." found
                    self.position = end + 1;
                    return Some(PathComponent {
                        component_type: PathComponentType::Dot,
                        name: &self.path[start..end + 1],
                    });
                }
            }
        }

        // Normal component - find next separator
        while end < self.path.len() && self.path[end] != PATH_SEPARATOR {
            end += 1;
        }

        let name = &self.path[start..end];
        self.position = end;

        Some(PathComponent {
            component_type: PathComponentType::Normal,
            name,
        })
    }
}

/// Parse path and return an iterator over its components
/// This properly handles:
/// - Absolute paths (starting with \)
/// - Relative paths
/// - "." and ".." components
/// - Multiple consecutive separators
pub fn parse_path(path: &[u16]) -> PathIterator<'_> {
    PathIterator::new(path)
}

/// Validate path length
pub fn validate_path(path: &[u16]) -> Result<(), ()> {
    if path.len() > MAX_PATH_LENGTH {
        Err(())
    } else {
        Ok(())
    }
}

/// Compare two names case-insensitively (for Windows file systems)
/// Handles ASCII characters only; non-ASCII characters are compared as-is
pub fn compare_name_insensitive(a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for i in 0..a.len() {
        let ca = a[i];
        let cb = b[i];
        // For ASCII (0-127), convert to lowercase; for others, compare as-is
        let ca_lower = if ca < 128 {
            if ca >= b'A' as u16 && ca <= b'Z' as u16 {
                ca + 32  // Convert 'A'-'Z' to 'a'-'z'
            } else {
                ca
            }
        } else {
            ca
        };
        let cb_lower = if cb < 128 {
            if cb >= b'A' as u16 && cb <= b'Z' as u16 {
                cb + 32  // Convert 'A'-'Z' to 'a'-'z'
            } else {
                cb
            }
        } else {
            cb
        };
        if ca_lower != cb_lower {
            return false;
        }
    }
    true
}

/// Resolve a path to a VfsNode, handling "." and ".." properly
/// Returns the final node after resolving all components
pub fn resolve_path(path: &[u16]) -> Option<&'static mut VfsNode> {
    if path.is_empty() {
        return None;
    }

    // Validate path length
    if path.len() > MAX_PATH_LENGTH {
        return None;
    }

    let mut path_iter = parse_path(path);
    let is_absolute = path_iter.is_absolute();

    // Start from root if absolute path, otherwise from current (root for now)
    let mut current = if is_absolute {
        get_root()?
    } else {
        get_root()?
    };

    // Process each component
    while let Some(component) = path_iter.next_component() {
        match component.component_type {
            PathComponentType::Dot => {
                // "." means current directory - stay where we are
                continue;
            }
            PathComponentType::DotDot => {
                // ".." means parent directory
                unsafe {
                    if !(*current).parent.is_null() {
                        current = &mut *(*current).parent;
                    }
                }
            }
            PathComponentType::Normal => {
                // Find child with matching name
                let child = find_child_internal(current, component.name)?;
                current = child;
            }
        }
    }

    Some(current)
}

/// Internal helper to find child without holding locks twice
fn find_child_internal(parent: &VfsNode, name: &[u16]) -> Option<&'static mut VfsNode> {
    let root = ROOT_DIR.lock();

    for i in 0..root.node_count {
        let node_ptr = root.nodes[i];
        if node_ptr.is_null() {
            continue;
        }

        unsafe {
            if (*node_ptr).parent != parent as *const VfsNode as *mut VfsNode {
                continue;
            }

            let node_name = &(*node_ptr).name;
            let node_name_slice = core::slice::from_raw_parts(
                node_name.Buffer,
                node_name.Length as usize / 2
            );

            if compare_name_insensitive(node_name_slice, name) {
                return Some(&mut *node_ptr);
            }
        }
    }

    None
}

/// Get root node
pub fn get_root() -> Option<&'static mut VfsNode> {
    let root = ROOT_DIR.lock();
    if root.node_count > 0 {
        let ptr = root.nodes[0];
        if !ptr.is_null() {
            return unsafe { ptr.as_mut() };
        }
    }
    None
}

/// Create VFS node
pub fn create_node(node_type: VfsNodeType, name: &[u16]) -> Option<&'static mut VfsNode> {
    let mut root = ROOT_DIR.lock();

    let node = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<VfsNode>(),
    ) as *mut VfsNode;

    if !node.is_null() {
        // Avoid `core::ptr::write(node, VfsNode::new())` for
        // the same reason as `init()`: the pool backs onto
        // heap memory which can be UC-typed, and the
        // aggregate-write gets emitted as a non-temporal SSE
        // store that silently fails on UC memory. Field-by-field
        // assignment is safe.
        unsafe {
            (*node).node_type = node_type;
            (*node).flags = 0;
            (*node).reference_count = 1;
            (*node).file_object = core::ptr::null_mut();
            (*node).vcb = core::ptr::null_mut();
            (*node).parent = core::ptr::null_mut();
            (*node).name.Buffer = name.as_ptr() as *mut u16;
            (*node).name.Length = (name.len() * 2) as u16;
            (*node).name.MaximumLength = (name.len() * 2) as u16;
            (*node).byte_offset = 0;
            (*node).allocation_size = 0;
        }

        if root.node_count < root.nodes.len() {
            let idx = root.node_count;
            root.nodes[idx] = node;
            root.node_count += 1;
        }

        return unsafe { node.as_mut() };
    }

    None
}

/// Add volume to VFS
pub fn add_volume(volume: *mut VfsNode) {
    let mut root = ROOT_DIR.lock();
    if root.volume_count < root.volumes.len() {
        let vidx = root.volume_count;
        root.volumes[vidx] = volume;
        root.volume_count += 1;
    }
    if root.node_count < root.nodes.len() {
        let nidx = root.node_count;
        root.nodes[nidx] = volume;
        root.node_count += 1;
    }
}

/// Lookup path
pub fn lookup_path(path: &[u16]) -> Option<&'static mut VfsNode> {
    resolve_path(path)
}

/// Find child node by name
/// Searches through all VFS nodes to find a child with the matching name
pub fn find_child(parent: *mut VfsNode, name: &[u16]) -> Option<&'static mut VfsNode> {
    lookup_child(parent, name)
}

/// Lookup a child node by name in the given parent.
/// This is a wrapper around find_child kept for compatibility with
/// earlier call sites.
pub fn lookup_child(parent: *mut VfsNode, name: &[u16]) -> Option<&'static mut VfsNode> {
    if parent.is_null() {
        return None;
    }

    let root = ROOT_DIR.lock();

    // Search all nodes to find children of the given parent
    for i in 0..root.node_count {
        let node_ptr = root.nodes[i];
        if node_ptr.is_null() {
            continue;
        }

        // Check if this node is a child of the parent
        unsafe {
            if (*node_ptr).parent == parent {
                // Compare names using UnicodeString comparison
                let node_name = &(*node_ptr).name;
                if node_name.Length == (name.len() * 2) as u16 {
                    // Compare the name buffers
                    let node_name_slice = core::slice::from_raw_parts(
                        node_name.Buffer,
                        node_name.Length as usize / 2
                    );
                    if node_name_slice == name {
                        // Found matching child
                        return Some(&mut *node_ptr);
                    }
                }
            }
        }
    }

    None
}

/// Find node by name (absolute path from root)
/// Searches for a node by name regardless of parent
pub fn find_by_name(name: &[u16]) -> Option<&'static mut VfsNode> {
    let root = ROOT_DIR.lock();

    for i in 0..root.node_count {
        let node_ptr = root.nodes[i];
        if node_ptr.is_null() {
            continue;
        }

        unsafe {
            let node_name = &(*node_ptr).name;
            if node_name.Length == (name.len() * 2) as u16 {
                let node_name_slice = core::slice::from_raw_parts(
                    node_name.Buffer,
                    node_name.Length as usize / 2
                );
                if node_name_slice == name {
                    return Some(&mut *node_ptr);
                }
            }
        }
    }

    None
}

/// Get children of a directory node
/// Returns an array of indices pointing to child nodes
pub fn get_children(parent: *mut VfsNode, buffer: &mut [usize]) -> usize {
    let mut count = 0;

    if parent.is_null() {
        return 0;
    }

    let root = ROOT_DIR.lock();

    for i in 0..root.node_count {
        let node_ptr = root.nodes[i];
        if node_ptr.is_null() {
            continue;
        }

        unsafe {
            if (*node_ptr).parent == parent {
                if count < buffer.len() {
                    buffer[count] = i;
                    count += 1;
                }
            }
        }
    }

    count
}

/// Create a volume mount point
pub fn create_volume(name: &[u16]) -> Option<&'static mut VfsNode> {
    let mut root = ROOT_DIR.lock();

    // Check if volume already exists
    for i in 0..root.volume_count {
        let vol_ptr = root.volumes[i];
        if !vol_ptr.is_null() {
            unsafe {
                let vol_name = &(*vol_ptr).name;
                if vol_name.Length == (name.len() * 2) as u16 {
                    let vol_name_slice = core::slice::from_raw_parts(
                        vol_name.Buffer,
                        vol_name.Length as usize / 2
                    );
                    if vol_name_slice == name {
                        return Some(&mut *vol_ptr);
                    }
                }
            }
        }
    }

    // Allocate new volume node
    let node_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<VfsNode>(),
    ) as *mut VfsNode;

    if !node_ptr.is_null() {
        unsafe {
            (*node_ptr).node_type = VfsNodeType::Directory;
            (*node_ptr).flags = 0x00000001; // NODE_FLAG_VOLUME
            (*node_ptr).reference_count = 1;
            (*node_ptr).file_object = core::ptr::null_mut();
            (*node_ptr).vcb = core::ptr::null_mut();
            (*node_ptr).parent = core::ptr::null_mut(); // Volumes have no parent
            (*node_ptr).name.Buffer = name.as_ptr() as *mut u16;
            (*node_ptr).name.Length = (name.len() * 2) as u16;
            (*node_ptr).name.MaximumLength = (name.len() * 2) as u16;
            (*node_ptr).byte_offset = 0;
            (*node_ptr).allocation_size = 0;
        }

        // Add to volumes array
        if root.volume_count < root.volumes.len() {
            let vidx = root.volume_count;
            root.volumes[vidx] = node_ptr;
            root.volume_count += 1;
        }

        // Also add to nodes array
        if root.node_count < root.nodes.len() {
            let nidx = root.node_count;
            root.nodes[nidx] = node_ptr;
            root.node_count += 1;
        }

        return unsafe { node_ptr.as_mut() };
    }

    None
}

/// Create file
/// Creates a new file node under the specified parent directory.
/// The `create_option` parameter specifies behavior when the file already exists:
/// - FileSupersede: Replace existing file
/// - FileCreate: Fail if exists
/// - FileOpenIf: Open if exists, create if not
/// - FileOverwriteIf: Open and truncate if exists
pub fn create_file(
    parent: *mut VfsNode,
    name: &[u16],
    create_option: CreateOption,
) -> Option<&'static mut VfsNode> {
    // First, try to find existing file
    let existing = lookup_child(parent, name);
    
    match create_option {
        CreateOption::FileSupersede | CreateOption::CreateAlways => {
            // Delete existing file if found
            if let Some(node) = existing {
                delete_node(node);
            }
            // Create new file
            let node = create_node(VfsNodeType::File, name)?;
            unsafe {
                (*node).parent = parent;
                if !parent.is_null() {
                    (*node).vcb = (*parent).vcb;
                }
            }
            Some(node)
        }
        CreateOption::FileCreate | CreateOption::CreateNew => {
            // Fail if file already exists
            if existing.is_some() {
                return None;
            }
            let node = create_node(VfsNodeType::File, name)?;
            unsafe {
                (*node).parent = parent;
                if !parent.is_null() {
                    (*node).vcb = (*parent).vcb;
                }
            }
            Some(node)
        }
        CreateOption::FileOpenIf | CreateOption::OpenAlways => {
            // Open if exists, create if not
            if let Some(node) = existing {
                return Some(node);
            }
            let node = create_node(VfsNodeType::File, name)?;
            unsafe {
                (*node).parent = parent;
                if !parent.is_null() {
                    (*node).vcb = (*parent).vcb;
                }
            }
            Some(node)
        }
        CreateOption::FileOverwriteIf | CreateOption::TruncateExisting => {
            // Open and truncate if exists
            if let Some(node) = existing {
                node.allocation_size = 0;
                node.byte_offset = 0;
                return Some(node);
            }
            // For TruncateExisting, fail if not exists
            if matches!(create_option, CreateOption::FileOverwriteIf) {
                let node = create_node(VfsNodeType::File, name)?;
                unsafe {
                    (*node).parent = parent;
                    if !parent.is_null() {
                        (*node).vcb = (*parent).vcb;
                    }
                }
                Some(node)
            } else {
                None
            }
        }
        CreateOption::OpenExisting => {
            // Open only if exists
            existing
        }
        CreateOption::None => {
            // No creation - just lookup
            existing
        }
    }
}

/// Create directory
pub fn create_directory(parent: *mut VfsNode, name: &[u16]) -> Option<&'static mut VfsNode> {
    let node = create_node(VfsNodeType::Directory, name)?;
    
    unsafe {
        (*node).parent = parent;
        (*node).vcb = (*parent).vcb;
    }
    
    Some(node)
}

/// Delete node
pub fn delete_node(node: *mut VfsNode) {
    unsafe {
        (*node).reference_count -= 1;
        if (*node).reference_count == 0 {
            // Free resources
            let _ = crate::mm::pool::free(node as *mut u8);
        }
    }
}

/// Result of a file sector read/write operation
pub struct SectorResult {
    pub status: u32,
    pub bytes_read: usize,
    pub bytes_written: usize,
}

impl SectorResult {
    pub const fn success(bytes: usize) -> Self {
        Self {
            status: 0, // STATUS_SUCCESS
            bytes_read: bytes,
            bytes_written: bytes,
        }
    }
    pub const fn error(status: u32) -> Self {
        Self {
            status,
            bytes_read: 0,
            bytes_written: 0,
        }
    }
}

/// Read sectors from a file.
/// `file_ctx` is the filesystem-specific file context (e.g., cluster number).
/// `buffer` is the destination buffer physical address.
/// `byte_offset` is the byte offset within the file.
/// Returns the number of bytes read or an error.
pub fn read_file_sectors(file_ctx: u64, buffer: u64, length: u32, byte_offset: u64) -> SectorResult {
    // Route to RAM disk for bootstrap filesystem operations
    if file_ctx != 0 {
        // file_ctx contains the sector number to read from
        let sector = file_ctx as usize;
        
        // Allocate temporary buffer on stack for small reads, use provided buffer for larger
        let mut temp_buf = [0u8; 512];
        let buf_ptr = if buffer != 0 {
            buffer as *mut u8
        } else {
            temp_buf.as_mut_ptr()
        };
        
        // Read from RAM disk
        if crate::drivers::storage::ramdisk::read(sector, &mut temp_buf) {
            // Copy data to destination buffer
            if buffer != 0 {
                let bytes_to_copy = core::cmp::min(length as usize, 512);
                unsafe {
                    core::ptr::copy_nonoverlapping(temp_buf.as_ptr(), buf_ptr, bytes_to_copy);
                }
            }
            SectorResult::success(core::cmp::min(length as usize, 512))
        } else {
            SectorResult::error(0xC000000D) // STATUS_DATA_ERROR
        }
    } else {
        // Try reading from the global RAM disk at the specified byte offset
        let sector = (byte_offset / 512) as usize;
        let offset_in_sector = (byte_offset % 512) as usize;
        let bytes_to_read = core::cmp::min(length as usize, 512 - offset_in_sector);
        
        let mut temp_buf = [0u8; 512];
        if crate::drivers::storage::ramdisk::read(sector, &mut temp_buf) {
            if buffer != 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        temp_buf.as_ptr().add(offset_in_sector),
                        buffer as *mut u8,
                        bytes_to_read
                    );
                }
            }
            SectorResult::success(bytes_to_read)
        } else {
            SectorResult::error(0xC000000D) // STATUS_DATA_ERROR
        }
    }
}

/// Write sectors to a file.
/// `file_ctx` is the filesystem-specific file context.
/// `buffer` is the source buffer physical address.
/// `byte_offset` is the byte offset within the file.
/// Returns the number of bytes written or an error.
pub fn write_file_sectors(file_ctx: u64, buffer: u64, length: u32, byte_offset: u64) -> SectorResult {
    if buffer == 0 || length == 0 {
        return SectorResult::error(0xC000000D); // STATUS_DATA_ERROR
    }
    
    // Route to RAM disk for bootstrap filesystem operations
    if file_ctx != 0 {
        // file_ctx contains the sector number to write to
        let sector = file_ctx as usize;
        
        // For single sector writes, we need to copy data
        if length >= 512 {
            // Read-modify-write for proper sector update
            let mut temp_buf = [0u8; 512];
            let _ = crate::drivers::storage::ramdisk::read(sector, &mut temp_buf);
            
            // Copy user data
            unsafe {
                core::ptr::copy_nonoverlapping(buffer as *const u8, temp_buf.as_mut_ptr(), 512);
            }
            
            // Write back
            if crate::drivers::storage::ramdisk::write(sector, &temp_buf) {
                SectorResult::success(512)
            } else {
                SectorResult::error(0xC000000D) // STATUS_DATA_ERROR
            }
        } else {
            // Partial sector write - read, modify, write
            let mut temp_buf = [0u8; 512];
            let _ = crate::drivers::storage::ramdisk::read(sector, &mut temp_buf);
            
            // Copy partial data
            unsafe {
                core::ptr::copy_nonoverlapping(buffer as *const u8, temp_buf.as_mut_ptr(), length as usize);
            }
            
            // Write back
            if crate::drivers::storage::ramdisk::write(sector, &temp_buf) {
                SectorResult::success(length as usize)
            } else {
                SectorResult::error(0xC000000D) // STATUS_DATA_ERROR
            }
        }
    } else {
        // Write at byte_offset within the RAM disk
        let sector = (byte_offset / 512) as usize;
        let offset_in_sector = (byte_offset % 512) as usize;
        let bytes_to_write = core::cmp::min(length as usize, 512 - offset_in_sector);
        
        // Read-modify-write
        let mut temp_buf = [0u8; 512];
        let _ = crate::drivers::storage::ramdisk::read(sector, &mut temp_buf);
        
        // Copy partial data
        unsafe {
            core::ptr::copy_nonoverlapping(
                buffer as *const u8,
                temp_buf.as_mut_ptr().add(offset_in_sector),
                bytes_to_write
            );
        }
        
        // Write back
        if crate::drivers::storage::ramdisk::write(sector, &temp_buf) {
            SectorResult::success(bytes_to_write)
        } else {
            SectorResult::error(0xC000000D) // STATUS_DATA_ERROR
        }
    }
}

/// Initialize VFS
pub fn init() {
    // crate::kprintln!("    Initializing VFS...")  // kprintln disabled (memcpy crash workaround);

    // Initialize RAM disk
    crate::drivers::storage::ramdisk::init();

    // Create root directory
    let mut root = ROOT_DIR.lock();

    // Allocate VfsNode from pool
    let node_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<VfsNode>(),
    ) as *mut VfsNode;

    if !node_ptr.is_null() {
        // The pool already zeroed the user region. We avoid
        // `core::ptr::write(node_ptr, VfsNode::new())` for the
        // same SSE / UC-memory reason that the timer and
        // driver modules work around (see ke::timer and
        // io::register_driver). Field-by-field assignment is
        // both safer and clearer about the layout.
        unsafe {
            (*node_ptr).node_type = VfsNodeType::Directory;
            (*node_ptr).flags = 0;
            (*node_ptr).reference_count = 1;
            (*node_ptr).file_object = core::ptr::null_mut();
            (*node_ptr).vcb = core::ptr::null_mut();
            (*node_ptr).parent = core::ptr::null_mut();
            (*node_ptr).name.Length = 0;
            (*node_ptr).name.MaximumLength = 0;
            (*node_ptr).name.Buffer = core::ptr::null_mut();
            (*node_ptr).byte_offset = 0;
            (*node_ptr).allocation_size = 0;
        }

        if root.node_count < root.nodes.len() {
            let idx = root.node_count;
            root.nodes[idx] = node_ptr;
            root.node_count += 1;
        }
    }

    // crate::kprintln!("    VFS initialized")  // kprintln disabled (memcpy crash workaround);
}