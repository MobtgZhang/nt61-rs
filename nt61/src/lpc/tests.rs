//! Comprehensive ALPC tests
//!
//! Tests for all ALPC subsystem features including:
//! - Port attributes and security
//! - Callbacks
//! - Sections (shared memory)
//! - Wait queues
//! - Connection accept/reject
//! - Asynchronous operations
//! - Direct buffers
//! - Message attributes

use super::async_ops::{async_send, AsyncQueue};
use super::attributes::AlpcMessageAttributes;
use super::callback::{
    invoke_callbacks, register_callback, unregister_callback, CallbackContext, CallbackEvent,
    CallbackRegistry,
};
use super::connection::{reject_connection_request, send_connection_request, ConnectionQueue};
use super::direct::{direct_receive, direct_send, DirectBufferRegistry};
use super::port::{close_port, create_port_ex, get_port_state, PortAttributes, PortState};
use super::queue::{allocate_message_id, MessageFilter};
use super::section::{close_section, create_section, map_section_view, SectionRegistry};
use super::security::{PortSecurity, SecurityQos};
use super::waitqueue::{wait_on_port, wake_port_waiters, wake_thread, WaitQueue, WaitReason};
use super::*;

pub fn test_port_attributes() -> bool {
    let attrs = PortAttributes {
        max_message_length: 512,
        max_pool_usage: 128 * 1024,
        memory_reserve: 4096,
        flags: port::PORT_FLAG_WAITABLE | port::PORT_FLAG_ALLOW_IMPERSONATION,
        security_qos: 2,
    };

    let name: [u16; 10] = [
        b'\\' as u16,
        b'T' as u16,
        b'e' as u16,
        b's' as u16,
        b't' as u16,
        b'A' as u16,
        b't' as u16,
        b't' as u16,
        b'r' as u16,
        b's' as u16,
    ];

    let mut reg = LpcRegistry::new();
    let port_index = match create_port_ex(&name, 0, &attrs, &mut reg) {
        Some(i) => i,
        None => return false,
    };
    if reg.count != 1 {
        return false;
    }
    if get_port_state(port_index, &reg) != PortState::Initializing {
        return false;
    }
    if !close_port(port_index, &mut reg) {
        return false;
    }
    if get_port_state(port_index, &reg) != PortState::Closed {
        return false;
    }

    true
}

pub fn test_callbacks() -> bool {
    let mut registry = CallbackRegistry::new();

    static INVOKED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    fn test_callback(_ctx: &CallbackContext) {
        INVOKED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    let cb_id = match register_callback(0, test_callback, 0x1234, &mut registry) {
        Some(id) => id,
        None => return false,
    };

    if registry.count != 1 {
        return false;
    }

    invoke_callbacks(0, CallbackEvent::MessageReceived, None, 0, &registry);
    if INVOKED.load(core::sync::atomic::Ordering::Relaxed) != 1 {
        return false;
    }

    if !unregister_callback(cb_id, &mut registry) {
        return false;
    }

    if registry.count != 0 {
        return false;
    }

    invoke_callbacks(0, CallbackEvent::MessageReceived, None, 0, &registry);
    if INVOKED.load(core::sync::atomic::Ordering::Relaxed) != 1 {
        return false;
    }

    true
}

pub fn test_sections() -> bool {
    let mut registry = SectionRegistry::new();

    let section_handle = match create_section(4096, section::SECTION_FLAG_SECURE, 0, &mut registry)
    {
        Some(h) => h,
        None => return false,
    };

    if registry.count != 1 {
        return false;
    }

    let view = match map_section_view(section_handle, 4096, 0, 0, &registry) {
        Some(v) => v,
        None => return false,
    };

    if view.section_handle != section_handle {
        return false;
    }

    if view.view_size != 4096 {
        return false;
    }

    if !close_section(section_handle, &mut registry) {
        return false;
    }

    true
}

pub fn test_wait_queue() -> bool {
    let mut queue = WaitQueue::new();

    let wait_id = match wait_on_port(0x1000, 5, WaitReason::Message, 0, &mut queue) {
        Some(id) => id,
        None => return false,
    };

    if queue.count != 1 {
        return false;
    }

    if !waitqueue::is_thread_waiting(0x1000, &queue) {
        return false;
    }

    if !wake_thread(wait_id, &mut queue) {
        return false;
    }

    if queue.count != 0 {
        return false;
    }

    wait_on_port(0x2000, 10, WaitReason::Message, 0, &mut queue);
    wait_on_port(0x2001, 10, WaitReason::Message, 0, &mut queue);
    wait_on_port(0x2002, 10, WaitReason::Message, 0, &mut queue);

    let woken = wake_port_waiters(10, &mut queue);
    if woken != 3 {
        return false;
    }

    if queue.count != 0 {
        return false;
    }

    true
}

pub fn test_connection_management() -> bool {
    let mut conn_queue = ConnectionQueue::new();

    let client_data = [1u8, 2, 3, 4];
    let req_id = match send_connection_request(0, 100, 200, &client_data, &mut conn_queue) {
        Some(id) => id,
        None => return false,
    };

    if conn_queue.count != 1 {
        return false;
    }

    let found = match connection::get_next_connection_request(0, &conn_queue) {
        Some(id) => id,
        None => return false,
    };

    if found != req_id {
        return false;
    }

    if !reject_connection_request(req_id, &mut conn_queue) {
        return false;
    }

    if conn_queue.count != 0 {
        return false;
    }

    let (_accept_count, reject_count) = connection::connection_stats();
    if reject_count < 1 {
        return false;
    }

    true
}

pub fn test_message_attributes() -> bool {
    let mut attrs = AlpcMessageAttributes::new();

    if attrs.valid_attrs != 0 {
        return false;
    }

    attrs.set_attribute(attributes::ALPC_ATTR_SECURITY);
    if !attrs.has_attribute(attributes::ALPC_ATTR_SECURITY) {
        return false;
    }

    attrs.context.message_id = 12345;
    attrs.context.sequence = 1;
    attrs.set_attribute(attributes::ALPC_ATTR_CONTEXT);

    if !attrs.has_attribute(attributes::ALPC_ATTR_CONTEXT) {
        return false;
    }

    attrs.clear_attribute(attributes::ALPC_ATTR_SECURITY);
    if attrs.has_attribute(attributes::ALPC_ATTR_SECURITY) {
        return false;
    }

    if !attributes::validate_attributes(&attrs) {
        return false;
    }

    true
}

pub fn test_message_queue() -> bool {
    let id1 = allocate_message_id();
    let id2 = allocate_message_id();

    if id2 != id1 + 1 {
        return false;
    }

    let mut msg =
        queue::create_queued_message(LpcMessage::empty(), queue::PRIORITY_NORMAL, false, 0);
    msg.message.header.sender_pid = 100;
    msg.message.header.message_type = LpcMessageType::Data as u32;

    let filter_any = MessageFilter::Any;
    if !filter_any.matches(&msg) {
        return false;
    }

    let filter_type = MessageFilter::Type(LpcMessageType::Data);
    if !filter_type.matches(&msg) {
        return false;
    }

    let filter_wrong_type = MessageFilter::Type(LpcMessageType::Reply);
    if filter_wrong_type.matches(&msg) {
        return false;
    }

    let filter_pid = MessageFilter::FromPid(100);
    if !filter_pid.matches(&msg) {
        return false;
    }

    true
}

pub fn test_security() -> bool {
    let mut port_sec = PortSecurity::system();

    if !port_sec.allow_impersonation {
        return false;
    }

    let system_token = crate::se::token::Token::new_primary(crate::se::sid::SID_LOCAL_SYSTEM);
    if !security::check_port_access_with_token(
        &port_sec,
        &system_token,
        security::PORT_ACCESS_ALL,
    ) {
        return false;
    }

    if !security::impersonate_client(&mut port_sec, 100, 200, SecurityQos::Impersonation) {
        return false;
    }

    if !port_sec.impersonation.active {
        return false;
    }

    if port_sec.impersonation.client_pid != 100 {
        return false;
    }

    if !security::revert_to_self(&mut port_sec) {
        return false;
    }

    if port_sec.impersonation.active {
        return false;
    }

    true
}

pub fn test_async_operations() -> bool {
    let mut async_queue = AsyncQueue::new();

    let msg = LpcMessage::empty();
    let op_id = match async_send(5, &msg, None, &mut async_queue) {
        Some(id) => id,
        None => return false,
    };

    if async_queue.count != 1 {
        return false;
    }

    let op = match async_ops::get_async_operation(op_id, &async_queue) {
        Some(o) => o,
        None => return false,
    };

    if op.status != async_ops::AsyncStatus::Pending {
        return false;
    }

    if !async_ops::complete_async_operation(
        op_id,
        async_ops::AsyncStatus::Completed,
        0,
        256,
        &mut async_queue,
    ) {
        return false;
    }

    if async_queue.count != 0 {
        return false;
    }

    true
}

pub fn test_direct_buffers() -> bool {
    let mut registry = DirectBufferRegistry::new();

    let buf_id = match direct::allocate_direct_buffer(10, &mut registry) {
        Some(id) => id,
        None => return false,
    };

    if registry.count != 1 {
        return false;
    }

    let mut msg = LpcMessage::empty();
    msg.data[0] = 0xAA;
    msg.data[1] = 0xBB;
    msg.data_len = 2;

    let sent = match direct_send(buf_id, &msg, true, &mut registry) {
        Some(n) => n,
        None => return false,
    };

    if sent != 2 {
        return false;
    }

    let received = match direct_receive(buf_id, false, &registry) {
        Some(m) => m,
        None => return false,
    };

    if received.data[0] != 0xAA || received.data[1] != 0xBB {
        return false;
    }

    if !direct::free_direct_buffer(buf_id, &mut registry) {
        return false;
    }

    true
}

pub fn run_extended_tests() -> bool {
    let mut all_passed = true;

    all_passed &= test_port_attributes();
    all_passed &= test_callbacks();
    all_passed &= test_sections();
    all_passed &= test_wait_queue();
    all_passed &= test_connection_management();
    all_passed &= test_message_attributes();
    all_passed &= test_message_queue();
    all_passed &= test_security();
    all_passed &= test_async_operations();
    all_passed &= test_direct_buffers();

    all_passed
}

#[cfg(test)]
mod tests {
    use super::*;

    // The global registry is pool-backed, so under libtest it stays null unless
    // a heap region is configured; without one `lock_registry()` returns `None`
    // and every assertion below would trivially pass.
    fn ensure_test_heap() {
        if crate::mm::heap::KERNEL_HEAP.configured_region().is_some() {
            return;
        }
        const TEST_HEAP_LEN: usize = 1024 * 1024;
        static mut TEST_HEAP: [u8; TEST_HEAP_LEN] = [0u8; TEST_HEAP_LEN];
        let base = core::ptr::addr_of_mut!(TEST_HEAP) as *mut u8;
        crate::mm::heap::KERNEL_HEAP.configure(base, TEST_HEAP_LEN);
    }

    // The LPC registry is a process-global pool allocation. Run the port
    // creation and oversized-message checks as one lifecycle so parallel
    // tests cannot interleave operations against the same registry.
    #[test]
    fn port_lifecycle_and_message_limits() {
        ensure_test_heap();
        crate::lpc::init();

        let connection_attrs = PortAttributes {
            max_message_length: 512,
            max_pool_usage: 128 * 1024,
            memory_reserve: 4096,
            flags: port::PORT_FLAG_WAITABLE | port::PORT_FLAG_ALLOW_IMPERSONATION,
            security_qos: 2,
        };
        let connection_name: [u16; 12] = [
            b'\\' as u16,
            b'T' as u16,
            b'e' as u16,
            b's' as u16,
            b't' as u16,
            b'A' as u16,
            b't' as u16,
            b't' as u16,
            b'r' as u16,
            b's' as u16,
            b'2' as u16,
            0,
        ];

        {
            let g = lock_registry().expect("LPC registry not initialised");
            let reg = &mut *g.reg;
            let idx = create_port_ex(&connection_name, 0, &connection_attrs, reg)
                .expect("create_port_ex failed");
            assert_eq!(reg.ports[idx as usize].attributes.max_message_length, 512);
            assert_eq!(
                reg.ports[idx as usize].attributes.max_pool_usage,
                128 * 1024
            );
            assert_eq!(
                reg.ports[idx as usize].attributes.flags,
                port::PORT_FLAG_WAITABLE | port::PORT_FLAG_ALLOW_IMPERSONATION
            );
        }

        let oversized_attrs = PortAttributes {
            max_message_length: 64,
            max_pool_usage: 64 * 1024,
            memory_reserve: 0,
            flags: 0,
            security_qos: 0,
        };
        let oversized_name: [u16; 12] = [
            b'\\' as u16,
            b'T' as u16,
            b'e' as u16,
            b's' as u16,
            b't' as u16,
            b'O' as u16,
            b'v' as u16,
            b'e' as u16,
            b'r' as u16,
            0,
            0,
            0,
        ];

        // `lock_registry()` is a non-reentrant spinlock, so the guard has to be
        // released before any call that takes it again (`connect_port`, `send`).
        let server;
        {
            let g = lock_registry().expect("LPC registry not initialised");
            let reg = &mut *g.reg;
            server = create_port_ex(&oversized_name, 1, &oversized_attrs, reg)
                .expect("create_port_ex failed");
            assert_eq!(reg.ports[server as usize].attributes.max_message_length, 64);
        }

        let mut server_comm = 0;
        let client = connect_port(server, 2, &mut server_comm).expect("connect_port failed");
        {
            let g = lock_registry().expect("LPC registry not initialised");
            let reg = &mut *g.reg;
            assert!(reg.ports[client as usize].connected);
            assert_eq!(reg.ports[client as usize].peer_index, server_comm);
            reg.ports[client as usize].attributes = oversized_attrs;
        }

        let mut msg = LpcMessage {
            header: LpcMessageHeader::new(LpcMessageType::Data, 65, 2, 0),
            data: [0u8; 256],
            data_len: 65,
        };
        assert_eq!(
            send(client, &msg),
            None,
            "message over the port limit must be rejected"
        );

        msg.header.data_length = 64;
        msg.header.total_length = 64;
        msg.data_len = 64;
        assert_eq!(send(client, &msg), Some(64));
    }
}
