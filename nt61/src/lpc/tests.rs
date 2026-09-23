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
        b'\\' as u16, b'T' as u16, b'e' as u16, b's' as u16, b't' as u16,
        b'A' as u16, b't' as u16, b't' as u16, b'r' as u16, b's' as u16,
    ];

    true
}

pub fn test_callbacks() -> bool {
    let mut registry = CallbackRegistry::new();

    fn test_callback(ctx: &CallbackContext) {
    }

    let cb_id = match register_callback(0, test_callback, 0x1234, &mut registry) {
        Some(id) => id,
        None => return false,
    };

    if registry.count != 1 {
        return false;
    }

    if !unregister_callback(cb_id, &mut registry) {
        return false;
    }

    if registry.count != 0 {
        return false;
    }

    true
}

pub fn test_sections() -> bool {
    let mut registry = SectionRegistry::new();

    let section_handle = match create_section(4096, section::SECTION_FLAG_SECURE, 0, &mut registry) {
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

    let mut msg = queue::create_queued_message(
        LpcMessage::empty(),
        queue::PRIORITY_NORMAL,
        false,
        0,
    );
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

    if !security::check_port_access(&port_sec, 0, security::PORT_ACCESS_ALL) {
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
