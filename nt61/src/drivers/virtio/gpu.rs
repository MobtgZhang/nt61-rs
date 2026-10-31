//! virtio-gpu display driver (virtio spec 4.4; Linux
//! include/uapi/linux/virtio_gpu.h).
//!
//! Two virtqueues: control (index 0) and cursor (index 1). Commands
//! follow a 24-byte header (type, flags, fence_id, ctx_id, ring_idx,
//! padding) followed by command-specific payloads.

use super::{queue::QueueBuffer, status, Transport, FEATURE_VERSION_1};

// virtio_gpu.h feature bits.
pub const F_VIRGL: u64 = 0;
pub const F_EDID: u64 = 1;

// Control queue command types (virtio_gpu_ctrl_type).
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0001;
pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0003;
pub const CMD_RESOURCE_UNREF: u32 = 0x0004;
pub const CMD_SET_SCANOUT: u32 = 0x0006;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0007;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0008;
pub const CMD_GET_EDID: u32 = 0x000a;
pub const CMD_RESP_OK_NODATA: u32 = 0x1200;

// virtio_gpu.h format values (virtio_gpu_formats).
pub const FORMAT_B8G8R8X8_UNORM: u32 = 2;

// Device configuration offsets (virtio_gpu.h virtio_gpu_config).
pub const CFG_EVENTS_READ: u64 = 0;
pub const CFG_EVENTS_CLEAR: u64 = 4;
pub const CFG_NUM_SCANOUTS: u64 = 8;

// Resource flags.
pub const RESOURCE_FLAG_2D: u32 = 0x0001;

/// virtio_gpu_ctrl_hdr: 24-byte command preamble.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CtrlHeader {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub ring_idx: u8,
    pub _padding: [u8; 3],
}

/// virtio_gpu_resource_create_2d payload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResourceCreate2d {
    pub hdr: CtrlHeader,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

/// virtio_gpu_resource_set_scanout payload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetScanout {
    pub hdr: CtrlHeader,
    pub r_scanout_id: u32,
    pub r_resource_id: u32,
    pub r_width: u32,
    pub r_height: u32,
    pub r_x: u32,
    pub r_y: u32,
}

/// virtio_gpu_transfer_to_host_2d payload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TransferToHost2d {
    pub hdr: CtrlHeader,
    pub rect_x: u32,
    pub rect_y: u32,
    pub rect_width: u32,
    pub rect_height: u32,
    pub offset: u64,
    pub resource_id: u32,
    pub _padding: u32,
}

/// virtio_gpu_resource_flush payload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResourceFlush {
    pub hdr: CtrlHeader,
    pub rect_x: u32,
    pub rect_y: u32,
    pub rect_width: u32,
    pub rect_height: u32,
    pub resource_id: u32,
    pub _padding: u32,
}

/// One configured virtio-gpu device.
pub struct VirtioGpu {
    transport_index: usize,
    ctrl_queue: super::queue::QueueLayout,
    num_scanouts: u32,
    next_resource_id: u32,
}

impl VirtioGpu {
    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Bring up a virtio-gpu device over the given transport.
    pub unsafe fn probe(
        transport_index: usize,
        transport: &mut dyn Transport,
    ) -> Option<VirtioGpu> {
        transport.reset();
        transport.write_status(status::ACKNOWLEDGE);
        transport.write_status(status::ACKNOWLEDGE | status::DRIVER);

        let features = FEATURE_VERSION_1;
        transport.write_driver_features(features);
        transport.write_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

        if transport.read_status() & status::FAILED != 0 {
            return None;
        }

        let max = transport.max_queue_size(0);
        let ctrl_queue = super::queue::QueueLayout::allocate(max as u16)?;
        if !transport.setup_queue(0, &ctrl_queue) {
            return None;
        }

        transport.write_status(
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );

        let num_scanouts = transport.config_read_u32(CFG_NUM_SCANOUTS);
        Some(VirtioGpu {
            transport_index,
            ctrl_queue,
            num_scanouts,
            next_resource_id: 1,
        })
    }

    pub fn num_scanouts(&self) -> u32 {
        self.num_scanouts
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Create a 2D resource and attach it to a scanout, then upload
    /// the framebuffer contents and flush to display.
    pub unsafe fn present_framebuffer(
        &mut self,
        transport: &mut dyn Transport,
        scanout_id: u32,
        fb_addr: *const u8,
        width: u32,
        height: u32,
    ) -> bool {
        let resource_id = self.next_resource_id;
        self.next_resource_id += 1;

        // Step 1: resource_create_2d
        let mut create = ResourceCreate2d {
            hdr: CtrlHeader {
                cmd_type: CMD_RESOURCE_CREATE_2D,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                _padding: [0; 3],
            },
            resource_id,
            format: FORMAT_B8G8R8X8_UNORM,
            width,
            height,
        };

        // Response buffer (status only).
        let mut response: u32 = 0;

        let head = match self.ctrl_queue.add_chain(&[
            QueueBuffer::new(
                &mut create as *mut ResourceCreate2d as *mut u8,
                core::mem::size_of::<ResourceCreate2d>(),
                false,
            ),
            QueueBuffer::new(fb_addr as *mut u8, (width * height * 4) as usize, false),
            QueueBuffer::new(
                &mut response as *mut u32 as *mut u8,
                core::mem::size_of::<u32>(),
                true,
            ),
        ]) {
            Some(h) => h,
            None => return false,
        };
        unsafe { transport.notify(0) };
        match self.wait_completion(head) {
            Some(_) => {}
            None => return false,
        }

        // Step 2: set_scanout
        let mut scanout = SetScanout {
            hdr: CtrlHeader {
                cmd_type: CMD_SET_SCANOUT,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                _padding: [0; 3],
            },
            r_scanout_id: scanout_id,
            r_resource_id: resource_id,
            r_width: width,
            r_height: height,
            r_x: 0,
            r_y: 0,
        };
        let head = match self.ctrl_queue.add_chain(&[
            QueueBuffer::new(
                &mut scanout as *mut SetScanout as *mut u8,
                core::mem::size_of::<SetScanout>(),
                false,
            ),
            QueueBuffer::new(
                &mut response as *mut u32 as *mut u8,
                core::mem::size_of::<u32>(),
                true,
            ),
        ]) {
            Some(h) => h,
            None => return false,
        };
        unsafe { transport.notify(0) };
        match self.wait_completion(head) {
            Some(_) => {}
            None => return false,
        }

        // Step 3: transfer_to_host_2d — upload the framebuffer content
        let mut transfer = TransferToHost2d {
            hdr: CtrlHeader {
                cmd_type: CMD_TRANSFER_TO_HOST_2D,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                _padding: [0; 3],
            },
            rect_x: 0,
            rect_y: 0,
            rect_width: width,
            rect_height: height,
            offset: 0,
            resource_id,
            _padding: 0,
        };
        let head = match self.ctrl_queue.add_chain(&[
            QueueBuffer::new(
                &mut transfer as *mut TransferToHost2d as *mut u8,
                core::mem::size_of::<TransferToHost2d>(),
                false,
            ),
            QueueBuffer::new(
                &mut response as *mut u32 as *mut u8,
                core::mem::size_of::<u32>(),
                true,
            ),
        ]) {
            Some(h) => h,
            None => return false,
        };
        unsafe { transport.notify(0) };
        match self.wait_completion(head) {
            Some(_) => {}
            None => return false,
        }

        // Step 4: resource_flush — display the uploaded content
        let mut flush = ResourceFlush {
            hdr: CtrlHeader {
                cmd_type: CMD_RESOURCE_FLUSH,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                _padding: [0; 3],
            },
            rect_x: 0,
            rect_y: 0,
            rect_width: width,
            rect_height: height,
            resource_id,
            _padding: 0,
        };
        let head = match self.ctrl_queue.add_chain(&[
            QueueBuffer::new(
                &mut flush as *mut ResourceFlush as *mut u8,
                core::mem::size_of::<ResourceFlush>(),
                false,
            ),
            QueueBuffer::new(
                &mut response as *mut u32 as *mut u8,
                core::mem::size_of::<u32>(),
                true,
            ),
        ]) {
            Some(h) => h,
            None => return false,
        };
        unsafe { transport.notify(0) };
        match self.wait_completion(head) {
            Some(_) => {}
            None => return false,
        }

        true
    }

    /// Wait for one completion on the control queue.
    fn wait_completion(&mut self, expected_head: u16) -> Option<()> {
        loop {
            if let Some((head_idx, _)) = self.ctrl_queue.pop_used() {
                if head_idx == expected_head {
                    return Some(());
                }
            }
        }
    }

    pub fn transport_index(&self) -> usize {
        self.transport_index
    }
}
