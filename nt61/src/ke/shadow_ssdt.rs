//! Shadow SSDT (Win32k) Implementation
//
//! The Shadow SSDT contains system services provided by win32k.sys,
//! the kernel-mode part of the Windows subsystem. These services
//! handle graphics (GDI) and window management (USER).
//
//! ## Syscall Numbers
//
//! All syscall numbers are based on j00ru/windows-syscalls project
//! for Windows 7 SP1 x64.
//
//! ## References
//! - j00ru/windows-syscalls: https://github.com/j00ru/windows-syscalls

#![cfg(target_arch = "x86_64")]


/// Maximum number of shadow services (0x1000 entries for 0x1000-0x1FFF range)
pub const SHADOW_MAX_SERVICES: usize = 0x1000;

/// Shadow service table entry
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShadowServiceEntry {
    pub handler: *const (),
}

impl ShadowServiceEntry {
    pub const fn new() -> Self {
        Self { handler: core::ptr::null() }
    }
    
    pub const fn is_null(&self) -> bool {
        self.handler.is_null()
    }
}

/// Shadow SSDT - Win32k service table
static mut SHADOW_SERVICE_TABLE: [ShadowServiceEntry; SHADOW_MAX_SERVICES] = {
    [ShadowServiceEntry::new(); SHADOW_MAX_SERVICES]
};

/// Shadow argument count table
static mut SHADOW_ARGUMENT_TABLE: [u8; SHADOW_MAX_SERVICES] = [0; SHADOW_MAX_SERVICES];

// =====================================================================
// Shadow SSDT Initialization
// =====================================================================

/// Initialize the Shadow SSDT
pub fn init() {
    crate::hal::serial::write_string("[ke.shadow_ssdt] enter\r\n");
    // // kprintln!("[SHADOW SSDT] Initializing Shadow System Service Dispatch Table...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("[SHADOW SSDT] Shadow SSDT initialized with {} max services", SHADOW_MAX_SERVICES)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Initialize and register all win32k shadow services
///
/// This function should be called during kernel initialization to register
/// all GDI and USER service handlers with the Shadow SSDT.
///
/// # Safety
/// This function modifies static mutable arrays. It should only be called
/// during initialization when no other cores are running.
pub unsafe fn init_shadow_services() {
    // // kprintln!("[SHADOW SSDT] Registering win32k shadow services...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Import syscall module
    use crate::libs::win32k::syscall;

    // USER services (indices 0x000-0x0FF after masking 0x1xxx)
    // Full syscall numbers are 0x1000-0x10FF, masked = 0x000-0x0FF
    register_shadow_service(0x000, syscall::nt_user_set_thread_state as *const (), 8);    // 0x1000
    register_shadow_service(0x001, syscall::nt_user_peek_message as *const (), 16);       // 0x1001
    register_shadow_service(0x002, syscall::nt_user_call_one_param as *const (), 8);      // 0x1002
    register_shadow_service(0x003, syscall::nt_user_get_key_state as *const (), 8);      // 0x1003
    register_shadow_service(0x004, syscall::nt_user_invalidate_rect as *const (), 12);    // 0x1004
    register_shadow_service(0x005, syscall::nt_user_call_no_param as *const (), 4);       // 0x1005
    register_shadow_service(0x006, syscall::nt_user_get_message as *const (), 16);         // 0x1006
    register_shadow_service(0x007, syscall::nt_user_message_call as *const (), 24);        // 0x1007
    register_shadow_service(0x00a, syscall::nt_user_get_dc as *const (), 8);               // 0x100a
    register_shadow_service(0x00c, syscall::nt_user_wait_message as *const (), 4);          // 0x100c
    register_shadow_service(0x00d, syscall::nt_user_translate_message as *const (), 8);     // 0x100d
    register_shadow_service(0x00e, syscall::nt_user_get_prop as *const (), 8);              // 0x100e
    register_shadow_service(0x00f, syscall::nt_user_post_message as *const (), 16);         // 0x100f
    register_shadow_service(0x010, syscall::nt_user_query_window as *const (), 8);          // 0x1010
    register_shadow_service(0x011, syscall::nt_user_translate_accelerator as *const (), 16);// 0x1011
    register_shadow_service(0x013, syscall::nt_user_redraw_window as *const (), 16);       // 0x1013
    register_shadow_service(0x014, syscall::nt_user_window_from_point as *const (), 8);     // 0x1014
    register_shadow_service(0x015, syscall::nt_user_call_msg_filter as *const (), 8);      // 0x1015
    register_shadow_service(0x016, syscall::nt_user_validate_timer_callback as *const (), 8);// 0x1016
    register_shadow_service(0x017, syscall::nt_user_begin_paint as *const (), 8);           // 0x1017
    register_shadow_service(0x018, syscall::nt_user_set_timer as *const (), 16);           // 0x1018
    register_shadow_service(0x019, syscall::nt_user_end_paint as *const (), 8);             // 0x1019
    register_shadow_service(0x01a, syscall::nt_user_set_cursor as *const (), 8);            // 0x101a
    register_shadow_service(0x01b, syscall::nt_user_kill_timer as *const (), 8);            // 0x101b
    register_shadow_service(0x01c, syscall::nt_user_build_hwnd_list as *const (), 24);      // 0x101c
    register_shadow_service(0x01d, syscall::nt_user_select_palette as *const (), 8);        // 0x101d
    register_shadow_service(0x01e, syscall::nt_user_call_next_hook_ex as *const (), 16);    // 0x101e
    register_shadow_service(0x01f, syscall::nt_user_hide_caret as *const (), 4);             // 0x101f
    register_shadow_service(0x021, syscall::nt_user_call_hwnd_lock as *const (), 4);        // 0x1021
    register_shadow_service(0x022, syscall::nt_user_get_process_window_station as *const (), 4); // 0x1022
    register_shadow_service(0x024, syscall::nt_user_set_window_pos as *const (), 32);       // 0x1024
    register_shadow_service(0x025, syscall::nt_user_show_caret as *const (), 4);            // 0x1025
    register_shadow_service(0x026, syscall::nt_user_end_defer_window_pos_ex as *const (), 8); // 0x1026
    register_shadow_service(0x027, syscall::nt_user_call_hwnd_param_lock as *const (), 12); // 0x1027
    register_shadow_service(0x028, syscall::nt_user_vk_key_scan_ex as *const (), 16);       // 0x1028
    register_shadow_service(0x02a, syscall::nt_user_call_two_param as *const (), 12);        // 0x102a
    register_shadow_service(0x02c, syscall::nt_user_copy_accelerator_table as *const (), 12);// 0x102c
    register_shadow_service(0x02d, syscall::nt_user_notify_win_event as *const (), 16);    // 0x102d
    register_shadow_service(0x02f, syscall::nt_user_is_clipboard_format_available as *const (), 4); // 0x102f
    register_shadow_service(0x030, syscall::nt_user_set_scroll_info as *const (), 16);      // 0x1030
    register_shadow_service(0x032, syscall::nt_user_create_caret as *const (), 16);         // 0x1032
    register_shadow_service(0x036, syscall::nt_user_dispatch_message as *const (), 8);       // 0x1036
    register_shadow_service(0x037, syscall::nt_user_register_window_message as *const (), 8); // 0x1037
    register_shadow_service(0x03c, syscall::nt_user_get_foreground_window as *const (), 4);  // 0x103c
    register_shadow_service(0x03d, syscall::nt_user_show_scroll_bar as *const (), 12);      // 0x103d
    register_shadow_service(0x03e, syscall::nt_user_find_existing_cursor_icon as *const (), 16); // 0x103e
    register_shadow_service(0x042, syscall::nt_user_system_parameters_info as *const (), 16); // 0x1042
    register_shadow_service(0x044, syscall::nt_user_get_async_key_state as *const (), 8);    // 0x1044
    register_shadow_service(0x045, syscall::nt_user_change_clipboard_chain as *const (), 8);               // 0x1045
    register_shadow_service(0x046, syscall::nt_user_remove_prop as *const (), 8);             // 0x1046
    register_shadow_service(0x049, syscall::nt_user_set_capture as *const (), 8);            // 0x1049
    register_shadow_service(0x04a, syscall::nt_user_enum_display_devices as *const (), 16);   // 0x104a
    register_shadow_service(0x04c, syscall::nt_user_set_prop as *const (), 12);             // 0x104c
    register_shadow_service(0x04e, syscall::nt_user_sb_get_parms as *const (), 8);           // 0x104e
    register_shadow_service(0x04f, syscall::nt_user_get_icon_info as *const (), 8);           // 0x104f
    register_shadow_service(0x050, syscall::nt_user_exclude_update_rgn as *const (), 12);     // 0x1050
    register_shadow_service(0x051, syscall::nt_user_set_focus as *const (), 8);              // 0x1051
    register_shadow_service(0x053, syscall::nt_user_defer_window_pos as *const (), 32);      // 0x1053
    register_shadow_service(0x054, syscall::nt_user_get_update_rect as *const (), 12);        // 0x1054
    register_shadow_service(0x056, syscall::nt_user_get_clipboard_sequence_number as *const (), 4); // 0x1056
    register_shadow_service(0x058, syscall::nt_user_show_window as *const (), 8);             // 0x1058
    register_shadow_service(0x059, syscall::nt_user_get_keyboard_layout_list as *const (), 8); // 0x1059
    register_shadow_service(0x05b, syscall::nt_user_map_virtual_key_ex as *const (), 16);     // 0x105b
    register_shadow_service(0x05c, syscall::nt_user_set_window_long as *const (), 16);        // 0x105c
    register_shadow_service(0x05e, syscall::nt_user_move_window as *const (), 24);          // 0x105e
    register_shadow_service(0x05f, syscall::nt_user_post_thread_message as *const (), 16);   // 0x105f
    register_shadow_service(0x060, syscall::nt_user_draw_icon_ex as *const (), 40);            // 0x1060
    register_shadow_service(0x061, syscall::nt_user_get_system_menu as *const (), 8);          // 0x1061
    register_shadow_service(0x063, syscall::nt_user_internal_get_window_text as *const (), 12);// 0x1063
    register_shadow_service(0x064, syscall::nt_user_get_window_dc as *const (), 8);          // 0x1064
    register_shadow_service(0x06b, syscall::nt_user_scroll_dc as *const (), 28);             // 0x106b
    register_shadow_service(0x06c, syscall::nt_user_get_object_information as *const (), 16); // 0x106c
    register_shadow_service(0x06e, syscall::nt_user_find_window_ex as *const (), 24);         // 0x106e
    register_shadow_service(0x070, syscall::nt_user_unhook_windows_hook_ex as *const (), 8); // 0x1070
    register_shadow_service(0x076, syscall::nt_user_create_window_ex as *const (), 44);       // 0x1076
    register_shadow_service(0x077, syscall::nt_user_set_parent as *const (), 12);            // 0x1077
    register_shadow_service(0x078, syscall::nt_user_get_keyboard_state as *const (), 8);     // 0x1078
    register_shadow_service(0x079, syscall::nt_user_to_unicode_ex as *const (), 24);         // 0x1079
    register_shadow_service(0x07a, syscall::nt_user_get_control_brush as *const (), 8);      // 0x107a
    register_shadow_service(0x07b, syscall::nt_user_get_class_name as *const (), 12);         // 0x107b
    register_shadow_service(0x07f, syscall::nt_user_def_set_text as *const (), 12);           // 0x107f
    register_shadow_service(0x082, syscall::nt_user_send_input as *const (), 16);            // 0x1082
    register_shadow_service(0x083, syscall::nt_user_get_thread_desktop as *const (), 8);      // 0x1083
    register_shadow_service(0x086, syscall::nt_user_get_update_rgn as *const (), 12);          // 0x1086
    register_shadow_service(0x088, syscall::nt_user_get_icon_size as *const (), 12);         // 0x1088
    register_shadow_service(0x089, syscall::nt_user_fill_window as *const (), 16);            // 0x1089
    register_shadow_service(0x08c, syscall::nt_user_set_windows_hook_ex as *const (), 24);   // 0x108c
    register_shadow_service(0x08d, syscall::nt_user_notify_process_create as *const (), 16); // 0x108d
    register_shadow_service(0x08f, syscall::nt_user_get_title_bar_info as *const (), 8);    // 0x108f
    register_shadow_service(0x091, syscall::nt_user_set_thread_desktop as *const (), 8);     // 0x1091
    register_shadow_service(0x092, syscall::nt_user_get_dcex as *const (), 16);               // 0x1092
    register_shadow_service(0x093, syscall::nt_user_get_scroll_bar_info as *const (), 8);    // 0x1093
    register_shadow_service(0x095, syscall::nt_user_set_window_fnid as *const (), 8);         // 0x1095
    register_shadow_service(0x097, syscall::nt_user_calc_menu_bar as *const (), 20);          // 0x1097
    register_shadow_service(0x098, syscall::nt_user_thunked_menu_item_info as *const (), 24); // 0x1098
    register_shadow_service(0x099, syscall::nt_gdi_exclude_clip_rect as *const (), 24);      // 0x1099
    register_shadow_service(0x09a, syscall::nt_gdi_create_dib_section as *const (), 28);      // 0x109a
    register_shadow_service(0x09b, syscall::nt_gdi_get_dc_for_bitmap as *const (), 4);       // 0x109b
    register_shadow_service(0x09c, syscall::nt_user_destroy_cursor as *const (), 8);          // 0x109c
    register_shadow_service(0x09d, syscall::nt_user_destroy_window as *const (), 4);          // 0x109d
    register_shadow_service(0x09e, syscall::nt_user_call_hwnd_param as *const (), 12);        // 0x109e
    register_shadow_service(0x09f, syscall::nt_gdi_create_dibitmap_internal as *const (), 24); // 0x109f
    register_shadow_service(0x0a0, syscall::nt_user_open_window_station as *const (), 12);    // 0x10a0
    register_shadow_service(0x0a4, syscall::nt_user_set_cursor_icon_data as *const (), 24);   // 0x10a4
    register_shadow_service(0x0a6, syscall::nt_user_close_desktop as *const (), 8);           // 0x10a6
    register_shadow_service(0x0a7, syscall::nt_user_open_desktop as *const (), 28);           // 0x10a7
    register_shadow_service(0x0a8, syscall::nt_user_set_process_window_station as *const (), 8); // 0x10a8
    register_shadow_service(0x0a9, syscall::nt_user_get_atom_name as *const (), 8);           // 0x10a9
    register_shadow_service(0x0ae, syscall::nt_user_build_hwnd_list as *const (), 12);        // 0x10ae
    register_shadow_service(0x0b0, syscall::nt_user_register_class_ex_wow as *const (), 32); // 0x10b0
    register_shadow_service(0x0b2, syscall::nt_user_get_ancestor as *const (), 8);           // 0x10b2
    register_shadow_service(0x0b5, syscall::nt_user_close_window_station as *const (), 8);   // 0x10b5
    register_shadow_service(0x0b6, syscall::nt_user_get_double_click_time as *const (), 4);  // 0x10b6
    register_shadow_service(0x0b7, syscall::nt_user_enable_scroll_bar as *const (), 12);     // 0x10b7
    register_shadow_service(0x0b9, syscall::nt_user_get_class_info_ex as *const (), 16);    // 0x10b9
    register_shadow_service(0x0bb, syscall::nt_user_unregister_class as *const (), 12);     // 0x10bb
    register_shadow_service(0x0bc, syscall::nt_user_delete_menu as *const (), 8);           // 0x10bc
    register_shadow_service(0x0be, syscall::nt_user_scroll_window_ex as *const (), 32);      // 0x10be
    register_shadow_service(0x0c0, syscall::nt_user_set_class_long as *const (), 16);         // 0x10c0
    register_shadow_service(0x0c1, syscall::nt_user_get_menu_bar_info as *const (), 12);     // 0x10c1
    register_shadow_service(0x0c8, syscall::nt_user_invalidate_rgn as *const (), 12);        // 0x10c8
    register_shadow_service(0x0c9, syscall::nt_user_get_clipboard_owner as *const (), 4);   // 0x10c9
    register_shadow_service(0x0ca, syscall::nt_user_set_window_rgn as *const (), 12);        // 0x10ca
    register_shadow_service(0x0cd, syscall::nt_user_validate_rect as *const (), 8);          // 0x10cd
    register_shadow_service(0x0ce, syscall::nt_user_close_clipboard as *const (), 4);         // 0x10ce
    register_shadow_service(0x0cf, syscall::nt_user_open_clipboard as *const (), 8);          // 0x10cf
    register_shadow_service(0x0d1, syscall::nt_user_set_clipboard_data as *const (), 8);      // 0x10d1
    register_shadow_service(0x0d2, syscall::nt_user_enable_menu_item as *const (), 12);       // 0x10d2
    register_shadow_service(0x0d3, syscall::nt_user_alter_window_style as *const (), 12);     // 0x10d3
    register_shadow_service(0x0d5, syscall::nt_user_get_window_placement as *const (), 8);   // 0x10d5
    register_shadow_service(0x0d8, syscall::nt_user_get_open_clipboard_window as *const (), 4); // 0x10d8
    register_shadow_service(0x0d9, syscall::nt_user_set_thread_state as *const (), 8);       // 0x10d9
    register_shadow_service(0x0db, syscall::nt_user_track_mouse_event as *const (), 16);      // 0x10db
    register_shadow_service(0x0dd, syscall::nt_user_destroy_menu as *const (), 4);             // 0x10dd
    register_shadow_service(0x0df, syscall::nt_user_console_control as *const (), 16);        // 0x10df
    register_shadow_service(0x0e0, syscall::nt_user_set_active_window as *const (), 8);        // 0x10e0
    register_shadow_service(0x0e1, syscall::nt_user_set_information_thread as *const (), 16);  // 0x10e1
    register_shadow_service(0x0e2, syscall::nt_user_set_window_placement as *const (), 8);     // 0x10e2
    register_shadow_service(0x0e3, syscall::nt_user_get_control_color as *const (), 8);        // 0x10e3
    register_shadow_service(0x0e8, syscall::nt_user_set_window_word as *const (), 12);         // 0x10e8
    register_shadow_service(0x0e9, syscall::nt_user_get_clipboard_format_name as *const (), 12); // 0x10e9
    register_shadow_service(0x0ea, syscall::nt_user_real_internal_get_message as *const (), 24); // 0x10ea
    register_shadow_service(0x0eb, syscall::nt_user_create_local_mem_handle as *const (), 8); // 0x10eb
    register_shadow_service(0x0ec, syscall::nt_user_attach_thread_input as *const (), 12);   // 0x10ec
    register_shadow_service(0x0ee, syscall::nt_user_paint_menu_bar as *const (), 20);        // 0x10ee
    register_shadow_service(0x0ef, syscall::nt_user_set_keyboard_state as *const (), 8);     // 0x10ef
    register_shadow_service(0x0f1, syscall::nt_user_create_accelerator_table as *const (), 8); // 0x10f1
    register_shadow_service(0x0f3, syscall::nt_user_get_alt_tab_info as *const (), 20);       // 0x10f3
    register_shadow_service(0x0f4, syscall::nt_user_get_caret_blink_time as *const (), 4);   // 0x10f4
    register_shadow_service(0x0f6, syscall::nt_user_process_connect as *const (), 16);        // 0x10f6
    register_shadow_service(0x0f7, syscall::nt_user_enum_display_devices as *const (), 16);   // 0x10f7
    register_shadow_service(0x0f8, syscall::nt_user_empty_clipboard as *const (), 4);         // 0x10f8
    register_shadow_service(0x0f9, syscall::nt_user_get_clipboard_data as *const (), 8);      // 0x10f9
    register_shadow_service(0x0fa, syscall::nt_user_remove_menu as *const (), 8);             // 0x10fa
    register_shadow_service(0x0fd, syscall::nt_user_convert_mem_handle as *const (), 12);      // 0x10fd
    register_shadow_service(0x0fe, syscall::nt_user_destroy_accelerator_table as *const (), 4); // 0x10fe
    register_shadow_service(0x0ff, syscall::nt_user_get_gui_thread_info as *const (), 8);   // 0x10ff

    // GDI services (indices 0x008-0x280 after masking 0x1xxx)
    // Full syscall numbers are 0x1008-0x1280, masked = 0x008-0x280
    register_shadow_service(0x008, syscall::nt_gdi_bit_blt as *const (), 48);                // 0x1008
    register_shadow_service(0x009, syscall::nt_gdi_get_char_set as *const (), 8);              // 0x1009
    register_shadow_service(0x00b, syscall::nt_gdi_select_object as *const (), 8);             // 0x100b
    register_shadow_service(0x012, syscall::nt_gdi_combine_rgn as *const (), 4);                      // 0x1012
    register_shadow_service(0x020, syscall::nt_gdi_exclude_clip_rect as *const (), 20);      // 0x1020
    register_shadow_service(0x023, syscall::nt_gdi_delete_object as *const (), 4);             // 0x1023
    register_shadow_service(0x02b, syscall::nt_gdi_invert_rgn as *const (), 8);           // 0x102b
    register_shadow_service(0x031, syscall::nt_gdi_stretch_blt as *const (), 44);              // 0x1031
    register_shadow_service(0x034, syscall::nt_gdi_combine_rgn as *const (), 16);             // 0x1034
    register_shadow_service(0x035, syscall::nt_gdi_get_dc_object as *const (), 8);            // 0x1035
    register_shadow_service(0x038, syscall::nt_gdi_ext_text_out as *const (), 32);            // 0x1038
    register_shadow_service(0x039, syscall::nt_gdi_select_font as *const (), 8);               // 0x1039
    register_shadow_service(0x03a, syscall::nt_gdi_restore_dc as *const (), 8);                // 0x103a
    register_shadow_service(0x03b, syscall::nt_gdi_save_dc as *const (), 4);                  // 0x103b
    register_shadow_service(0x03f, syscall::nt_gdi_get_dc_dword as *const (), 12);             // 0x103f
    register_shadow_service(0x041, syscall::nt_gdi_line_to as *const (), 12);                  // 0x1041
    register_shadow_service(0x043, syscall::nt_gdi_get_app_clip_box as *const (), 8);         // 0x1043
    register_shadow_service(0x047, syscall::nt_gdi_do_palette as *const (), 20);                // 0x1047
    register_shadow_service(0x04b, syscall::nt_gdi_create_compatible_bitmap as *const (), 16); // 0x104b
    register_shadow_service(0x04d, syscall::nt_gdi_get_text_charset_info as *const (), 8);    // 0x104d
    register_shadow_service(0x052, syscall::nt_gdi_ext_get_object_w as *const (), 12);        // 0x1052
    register_shadow_service(0x055, syscall::nt_gdi_create_compatible_dc as *const (), 8);       // 0x1055
    register_shadow_service(0x057, syscall::nt_gdi_create_pen as *const (), 16);               // 0x1057
    register_shadow_service(0x05a, syscall::nt_gdi_pat_blt as *const (), 32);                  // 0x105a
    register_shadow_service(0x05d, syscall::nt_gdi_hfont_create as *const (), 16);             // 0x105d
    register_shadow_service(0x062, syscall::nt_gdi_draw_stream as *const (), 24);              // 0x1062
    register_shadow_service(0x066, syscall::nt_gdi_invert_rgn as *const (), 12);               // 0x1066
    register_shadow_service(0x067, syscall::nt_gdi_get_rgn_box as *const (), 8);               // 0x1067
    register_shadow_service(0x069, syscall::nt_gdi_mask_blt as *const (), 44);                  // 0x1069
    register_shadow_service(0x06a, syscall::nt_gdi_get_width_table as *const (), 20);           // 0x106a
    register_shadow_service(0x06f, syscall::nt_gdi_poly_pat_blt as *const (), 24);             // 0x106f
    register_shadow_service(0x071, syscall::nt_gdi_get_nearest_color as *const (), 12);        // 0x1071
    register_shadow_service(0x072, syscall::nt_gdi_transform_points as *const (), 20);           // 0x1072
    register_shadow_service(0x073, syscall::nt_gdi_get_dc_point as *const (), 8);             // 0x1073
    register_shadow_service(0x074, syscall::nt_gdi_create_dib_brush as *const (), 20);        // 0x1074
    register_shadow_service(0x075, syscall::nt_gdi_get_text_metrics_w as *const (), 8);       // 0x1075
    register_shadow_service(0x07c, syscall::nt_gdi_alpha_blend as *const (), 40);             // 0x107c
    register_shadow_service(0x07d, syscall::nt_gdi_dd_blt as *const (), 48);                  // 0x107d
    register_shadow_service(0x07e, syscall::nt_gdi_offset_rgn as *const (), 8);               // 0x107e
    register_shadow_service(0x080, syscall::nt_gdi_get_text_face_w as *const (), 12);          // 0x1080
    register_shadow_service(0x081, syscall::nt_gdi_stretch_dibits_internal as *const (), 44);   // 0x1081
    register_shadow_service(0x084, syscall::nt_gdi_create_rect_rgn as *const (), 20);          // 0x1084
    register_shadow_service(0x085, syscall::nt_gdi_get_dibits_internal as *const (), 28);       // 0x1085
    register_shadow_service(0x087, syscall::nt_gdi_delete_client_obj as *const (), 4);         // 0x1087
    register_shadow_service(0x08a, syscall::nt_gdi_ext_create_region as *const (), 20);       // 0x108a
    register_shadow_service(0x08b, syscall::nt_gdi_compute_xform_coefficients as *const (), 8); // 0x108b
    register_shadow_service(0x08e, syscall::nt_gdi_unrealize_object as *const (), 4);         // 0x108e
    register_shadow_service(0x090, syscall::nt_gdi_rectangle as *const (), 24);              // 0x1090
    register_shadow_service(0x094, syscall::nt_gdi_get_text_extent as *const (), 16);         // 0x1094
    register_shadow_service(0x096, syscall::nt_gdi_set_layout as *const (), 8);              // 0x1096
    register_shadow_service(0x09a, syscall::nt_gdi_create_dib_section as *const (), 28);      // 0x109a
    register_shadow_service(0x09f, syscall::nt_gdi_create_dibitmap_internal as *const (), 24); // 0x109f
    register_shadow_service(0x0a1, syscall::nt_gdi_dd_delete_surface_object as *const (), 4);   // 0x10a1
    register_shadow_service(0x0a2, syscall::nt_gdi_dd_can_create_surface as *const (), 8);    // 0x10a2
    register_shadow_service(0x0a3, syscall::nt_gdi_dd_create_surface as *const (), 32);        // 0x10a3
    register_shadow_service(0x0a5, syscall::nt_gdi_dd_destroy_surface as *const (), 4);        // 0x10a5
    register_shadow_service(0x0aa, syscall::nt_gdi_dd_reset_visrgn as *const (), 4);           // 0x10aa
    register_shadow_service(0x0ab, syscall::nt_gdi_ext_create_pen as *const (), 32);         // 0x10ab
    register_shadow_service(0x0ac, syscall::nt_gdi_create_palette_internal as *const (), 8);   // 0x10ac
    register_shadow_service(0x0ad, syscall::nt_gdi_set_brush_org as *const (), 8);             // 0x10ad
    register_shadow_service(0x0af, syscall::nt_gdi_set_pixel as *const (), 16);                // 0x10af
    register_shadow_service(0x0b1, syscall::nt_gdi_create_pattern_brush_internal as *const (), 16); // 0x10b1
    register_shadow_service(0x0b3, syscall::nt_gdi_get_outline_text_metrics_internal_w as *const (), 12); // 0x10b3
    register_shadow_service(0x0b4, syscall::nt_gdi_set_bitmap_bits as *const (), 12);          // 0x10b4
    register_shadow_service(0x0b8, syscall::nt_gdi_create_solid_brush as *const (), 4);       // 0x10b8
    register_shadow_service(0x0ba, syscall::nt_gdi_create_client_obj as *const (), 8);        // 0x10ba
    register_shadow_service(0x0bd, syscall::nt_gdi_rect_in_region as *const (), 8);           // 0x10bd
    register_shadow_service(0x0bf, syscall::nt_gdi_get_pixel as *const (), 12);               // 0x10bf
    register_shadow_service(0x0d4, syscall::nt_gdi_poly_pat_blt as *const (), 16);                  // 0x10d4
    register_shadow_service(0x0d6, syscall::nt_gdi_invert_rgn as *const (), 16);   // 0x10d6
    register_shadow_service(0x0da, syscall::nt_gdi_compute_xform_coefficients as *const (), 28);                 // 0x10da
    register_shadow_service(0x0de, syscall::nt_gdi_set_bitmap_bits as *const (), 12);         // 0x10de
    register_shadow_service(0x0e4, syscall::nt_gdi_save_dc as *const (), 4);              // 0x10e4
    register_shadow_service(0x0e5, syscall::nt_gdi_get_app_clip_box as *const (), 8);            // 0x10e5
    register_shadow_service(0x0ed, syscall::nt_gdi_create_palette_internal as *const (), 8);   // 0x10ed
    register_shadow_service(0x0fb, syscall::nt_gdi_restore_dc as *const (), 12);        // 0x10fb

    // // kprintln!("[SHADOW SSDT] Registered {} win32k shadow services", SHADOW_MAX_SERVICES)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Register a shadow (win32k) service handler
/// 
/// # Safety
/// This function modifies a static mutable array. It should only be
/// called during initialization when no other cores are running.
pub unsafe fn register_shadow_service(service_index: u32, handler: *const (), arg_size: u8) {
    if service_index as usize >= SHADOW_MAX_SERVICES {
        // // kprintln!("[SHADOW SSDT] ERROR: Service index 0x{:03x} out of range", service_index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return;
    }
    
    SHADOW_SERVICE_TABLE[service_index as usize].handler = handler;
    SHADOW_ARGUMENT_TABLE[service_index as usize] = arg_size;
    
    // // kprintln!("[SHADOW SSDT] Registered shadow service 0x{:04x} at index {} (args={})",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               service_index, service_index, arg_size);
}

/// Get a shadow service handler
pub fn get_shadow_service(service_index: u32) -> Option<*const ()> {
    if service_index as usize >= SHADOW_MAX_SERVICES {
        return None;
    }
    
    unsafe {
        let entry = &SHADOW_SERVICE_TABLE[service_index as usize];
        if entry.handler.is_null() {
            None
        } else {
            Some(entry.handler)
        }
    }
}

// =====================================================================
// Win32k Syscall Numbers - Windows 7 SP1 x64
// Based on j00ru/windows-syscalls project
// =====================================================================

// ----------------------------------------------------------------------------
// GDI Services - Graphics Device Interface
// ----------------------------------------------------------------------------

pub const NtGdiBitBlt: u32 = 0x1008;
pub const NtGdiGetCharSet: u32 = 0x1009;
pub const NtGdiSelectBitmap: u32 = 0x100b;
pub const NtGdiFlush: u32 = 0x1012;
pub const NtGdiIntersectClipRect: u32 = 0x1020;
pub const NtGdiDeleteObjectApp: u32 = 0x1023;
pub const NtGdiSetDIBitsToDeviceInternal: u32 = 0x1029;
pub const NtGdiGetRandomRgn: u32 = 0x102b;
pub const NtGdiExtSelectClipRgn: u32 = 0x102e;
pub const NtGdiStretchBlt: u32 = 0x1031;
pub const NtGdiRectVisible: u32 = 0x1033;
pub const NtGdiCombineRgn: u32 = 0x1034;
pub const NtGdiGetDCObject: u32 = 0x1035;
pub const NtGdiExtTextOutW: u32 = 0x1038;
pub const NtGdiSelectFont: u32 = 0x1039;
pub const NtGdiRestoreDC: u32 = 0x103a;
pub const NtGdiSaveDC: u32 = 0x103b;
pub const NtGdiGetDCDword: u32 = 0x103f;
pub const NtGdiGetRegionData: u32 = 0x1040;
pub const NtGdiLineTo: u32 = 0x1041;
pub const NtGdiGetAppClipBox: u32 = 0x1043;
pub const NtGdiDoPalette: u32 = 0x1047;
pub const NtGdiPolyPolyDraw: u32 = 0x1048;
pub const NtGdiCreateCompatibleBitmap: u32 = 0x104b;
pub const NtGdiGetTextCharsetInfo: u32 = 0x104d;
pub const NtGdiExtGetObjectW: u32 = 0x1052;
pub const NtGdiCreateCompatibleDC: u32 = 0x1055;
pub const NtGdiCreatePen: u32 = 0x1057;
pub const NtGdiPatBlt: u32 = 0x105a;
pub const NtGdiHfontCreate: u32 = 0x105d;
pub const NtGdiDrawStream: u32 = 0x1062;
pub const NtGdiD3dDrawPrimitives2: u32 = 0x1065;
pub const NtGdiInvertRgn: u32 = 0x1066;
pub const NtGdiGetRgnBox: u32 = 0x1067;
pub const NtGdiGetAndSetDCDword: u32 = 0x1068;
pub const NtGdiMaskBlt: u32 = 0x1069;
pub const NtGdiGetWidthTable: u32 = 0x106a;
pub const NtGdiCreateBitmap: u32 = 0x106d;
pub const NtGdiPolyPatBlt: u32 = 0x106f;
pub const NtGdiGetNearestColor: u32 = 0x1071;
pub const NtGdiTransformPoints: u32 = 0x1072;
pub const NtGdiGetDCPoint: u32 = 0x1073;
pub const NtGdiCreateDIBBrush: u32 = 0x1074;
pub const NtGdiGetTextMetricsW: u32 = 0x1075;
pub const NtGdiAlphaBlend: u32 = 0x107c;
pub const NtGdiDdBlt: u32 = 0x107d;
pub const NtGdiOffsetRgn: u32 = 0x107e;
pub const NtGdiGetTextFaceW: u32 = 0x1080;
pub const NtGdiStretchDIBitsInternal: u32 = 0x1081;
pub const NtGdiCreateRectRgn: u32 = 0x1084;
pub const NtGdiGetDIBitsInternal: u32 = 0x1085;
pub const NtGdiDeleteClientObj: u32 = 0x1087;
pub const NtGdiExtCreateRegion: u32 = 0x108a;
pub const NtGdiComputeXformCoefficients: u32 = 0x108b;
pub const NtGdiUnrealizeObject: u32 = 0x108e;
pub const NtGdiRectangle: u32 = 0x1090;
pub const NtGdiGetTextExtent: u32 = 0x1094;
pub const NtGdiSetLayout: u32 = 0x1096;
pub const NtGdiExcludeClipRect: u32 = 0x1099;
pub const NtGdiCreateDIBSection: u32 = 0x109a;
pub const NtGdiGetDCforBitmap: u32 = 0x109b;
pub const NtGdiCreateDIBitmapInternal: u32 = 0x109f;
pub const NtGdiDdDeleteSurfaceObject: u32 = 0x10a1;
pub const NtGdiDdCanCreateSurface: u32 = 0x10a2;
pub const NtGdiDdCreateSurface: u32 = 0x10a3;
pub const NtGdiDdDestroySurface: u32 = 0x10a5;
pub const NtGdiDdResetVisrgn: u32 = 0x10aa;
pub const NtGdiExtCreatePen: u32 = 0x10ab;
pub const NtGdiCreatePaletteInternal: u32 = 0x10ac;
pub const NtGdiSetBrushOrg: u32 = 0x10ad;
pub const NtGdiSetPixel: u32 = 0x10af;
pub const NtGdiCreatePatternBrushInternal: u32 = 0x10b1;
pub const NtGdiGetOutlineTextMetricsInternalW: u32 = 0x10b3;
pub const NtGdiSetBitmapBits: u32 = 0x10b4;
pub const NtGdiCreateSolidBrush: u32 = 0x10b8;
pub const NtGdiCreateClientObj: u32 = 0x10ba;
pub const NtGdiRectInRegion: u32 = 0x10bd;
pub const NtGdiGetPixel: u32 = 0x10bf;
pub const NtGdiDdCreateSurfaceEx: u32 = 0x10c2;
pub const NtGdiDdCreateSurfaceObject: u32 = 0x10c3;
pub const NtGdiGetNearestPaletteIndex: u32 = 0x10c4;
pub const NtGdiDdLockD3D: u32 = 0x10c5;
pub const NtGdiDdUnlockD3D: u32 = 0x10c6;
pub const NtGdiGetCharWidthW: u32 = 0x10c7;
pub const NtGdiGetCharWidthInfo: u32 = 0x10cc;
pub const NtGdiGetStockObject: u32 = 0x10d0;
pub const NtGdiFillRgn: u32 = 0x10d4;
pub const NtGdiModifyWorldTransform: u32 = 0x10d6;
pub const NtGdiGetFontData: u32 = 0x10d7;
pub const NtGdiOpenDCW: u32 = 0x10da;
pub const NtGdiGetTransform: u32 = 0x10dc;
pub const NtGdiGetBitmapBits: u32 = 0x10de;
pub const NtGdiSetMetaRgn: u32 = 0x10e4;
pub const NtGdiSetMiterLimit: u32 = 0x10e5;
pub const NtGdiSetVirtualResolution: u32 = 0x10e6;
pub const NtGdiGetRasterizerCaps: u32 = 0x10e7;
pub const NtGdiCreateHalftonePalette: u32 = 0x10ed;
pub const NtGdiCombineTransform: u32 = 0x10f0;
pub const NtGdiQueryFontAssocInfo: u32 = 0x10f5;
pub const NtGdiSetBoundsRect: u32 = 0x10fb;
pub const NtGdiGetBitmapDimension: u32 = 0x10fc;
pub const NtGdiCloseFigure: u32 = 0x1100;
pub const NtGdiBeginPath: u32 = 0x1109;
pub const NtGdiEndPath: u32 = 0x110a;
pub const NtGdiFillPath: u32 = 0x110b;
pub const NtGdiAddFontMemResourceEx: u32 = 0x1110;
pub const NtGdiEqualRgn: u32 = 0x1111;
pub const NtGdiGetSystemPaletteUse: u32 = 0x1112;
pub const NtGdiRemoveFontMemResourceEx: u32 = 0x1113;
pub const NtGdiExtEscape: u32 = 0x1116;
pub const NtGdiSetBitmapDimension: u32 = 0x1117;
pub const NtGdiSetFontEnumeration: u32 = 0x1118;
pub const NtGdiCreateColorSpace: u32 = 0x111c;
pub const NtGdiDeleteColorSpace: u32 = 0x111d;
pub const NtGdiAbortDoc: u32 = 0x111f;
pub const NtGdiAbortPath: u32 = 0x1120;
pub const NtGdiAddEmbFontToDC: u32 = 0x1121;
pub const NtGdiAddFontResourceW: u32 = 0x1122;
pub const NtGdiAddRemoteFontToDC: u32 = 0x1123;
pub const NtGdiAddRemoteMMInstanceToDC: u32 = 0x1124;
pub const NtGdiAngleArc: u32 = 0x1125;
pub const NtGdiAnyLinkedFonts: u32 = 0x1126;
pub const NtGdiArcInternal: u32 = 0x1127;
pub const NtGdiBRUSHOBJ_DeleteRbrush: u32 = 0x1128;
pub const NtGdiBRUSHOBJ_hGetColorTransform: u32 = 0x1129;
pub const NtGdiBRUSHOBJ_pvAllocRbrush: u32 = 0x112a;
pub const NtGdiBRUSHOBJ_pvGetRbrush: u32 = 0x112b;
pub const NtGdiBRUSHOBJ_ulGetBrushColor: u32 = 0x112c;
pub const NtGdiBeginGdiRendering: u32 = 0x112d;
pub const NtGdiCLIPOBJ_bEnum: u32 = 0x112e;
pub const NtGdiCLIPOBJ_cEnumStart: u32 = 0x112f;
pub const NtGdiCLIPOBJ_ppoGetPath: u32 = 0x1130;
pub const NtGdiCancelDC: u32 = 0x1131;
pub const NtGdiChangeGhostFont: u32 = 0x1132;
pub const NtGdiCheckBitmapBits: u32 = 0x1133;
pub const NtGdiClearBitmapAttributes: u32 = 0x1134;
pub const NtGdiClearBrushAttributes: u32 = 0x1135;
pub const NtGdiColorCorrectPalette: u32 = 0x1136;
pub const NtGdiConfigureOPMProtectedOutput: u32 = 0x1137;
pub const NtGdiConvertMetafileRect: u32 = 0x1138;
pub const NtGdiCreateBitmapFromDxSurface: u32 = 0x1139;
pub const NtGdiCreateColorTransform: u32 = 0x113a;
pub const NtGdiCreateEllipticRgn: u32 = 0x113b;
pub const NtGdiCreateHatchBrushInternal: u32 = 0x113c;
pub const NtGdiCreateMetafileDC: u32 = 0x113d;
pub const NtGdiCreateOPMProtectedOutputs: u32 = 0x113e;
pub const NtGdiCreateRoundRectRgn: u32 = 0x113f;
pub const NtGdiCreateServerMetaFile: u32 = 0x1140;
pub const NtGdiD3dContextCreate: u32 = 0x1141;
pub const NtGdiD3dContextDestroy: u32 = 0x1142;
pub const NtGdiD3dContextDestroyAll: u32 = 0x1143;
pub const NtGdiD3dValidateTextureStageState: u32 = 0x1144;
pub const NtGdiDDCCIGetCapabilitiesString: u32 = 0x1145;
pub const NtGdiDDCCIGetCapabilitiesStringLength: u32 = 0x1146;
pub const NtGdiDDCCIGetTimingReport: u32 = 0x1147;
pub const NtGdiDDCCIGetVCPFeature: u32 = 0x1148;
pub const NtGdiDDCCISaveCurrentSettings: u32 = 0x1149;
pub const NtGdiDDCCISetVCPFeature: u32 = 0x114a;
pub const NtGdiDdAddAttachedSurface: u32 = 0x114b;
pub const NtGdiDdAlphaBlt: u32 = 0x114c;
pub const NtGdiDdAttachSurface: u32 = 0x114d;
pub const NtGdiDdBeginMoCompFrame: u32 = 0x114e;
pub const NtGdiDdCanCreateD3DBuffer: u32 = 0x114f;
pub const NtGdiDdColorControl: u32 = 0x1150;
pub const NtGdiDdCreateD3DBuffer: u32 = 0x1151;
pub const NtGdiDdCreateDirectDrawObject: u32 = 0x1152;
pub const NtGdiDdCreateFullscreenSprite: u32 = 0x1153;
pub const NtGdiDdCreateMoComp: u32 = 0x1154;
pub const NtGdiDdDDIAcquireKeyedMutex: u32 = 0x1155;
pub const NtGdiDdDDICheckExclusiveOwnership: u32 = 0x1156;
pub const NtGdiDdDDICheckMonitorPowerState: u32 = 0x1157;
pub const NtGdiDdDDICheckOcclusion: u32 = 0x1158;
pub const NtGdiDdDDICheckSharedResourceAccess: u32 = 0x1159;
pub const NtGdiDdDDICheckVidPnExclusiveOwnership: u32 = 0x115a;
pub const NtGdiDdDDICloseAdapter: u32 = 0x115b;
pub const NtGdiDdDDIConfigureSharedResource: u32 = 0x115c;
pub const NtGdiDdDDICreateAllocation: u32 = 0x115d;
pub const NtGdiDdDDICreateContext: u32 = 0x115e;
pub const NtGdiDdDDICreateDCFromMemory: u32 = 0x115f;
pub const NtGdiDdDDICreateDevice: u32 = 0x1160;
pub const NtGdiDdDDICreateKeyedMutex: u32 = 0x1161;
pub const NtGdiDdDDICreateOverlay: u32 = 0x1162;
pub const NtGdiDdDDICreateSynchronizationObject: u32 = 0x1163;
pub const NtGdiDdDDIDestroyAllocation: u32 = 0x1164;
pub const NtGdiDdDDIDestroyContext: u32 = 0x1165;
pub const NtGdiDdDDIDestroyDCFromMemory: u32 = 0x1166;
pub const NtGdiDdDDIDestroyDevice: u32 = 0x1167;
pub const NtGdiDdDDIDestroyKeyedMutex: u32 = 0x1168;
pub const NtGdiDdDDIDestroyOverlay: u32 = 0x1169;
pub const NtGdiDdDDIDestroySynchronizationObject: u32 = 0x116a;
pub const NtGdiDdDDIEscape: u32 = 0x116b;
pub const NtGdiDdDDIFlipOverlay: u32 = 0x116c;
pub const NtGdiDdDDIGetContextSchedulingPriority: u32 = 0x116d;
pub const NtGdiDdDDIGetDeviceState: u32 = 0x116e;
pub const NtGdiDdDDIGetDisplayModeList: u32 = 0x116f;
pub const NtGdiDdDDIGetMultisampleMethodList: u32 = 0x1170;
pub const NtGdiDdDDIGetOverlayState: u32 = 0x1171;
pub const NtGdiDdDDIGetPresentHistory: u32 = 0x1172;
pub const NtGdiDdDDIGetPresentQueueEvent: u32 = 0x1173;
pub const NtGdiDdDDIGetProcessSchedulingPriorityClass: u32 = 0x1174;
pub const NtGdiDdDDIGetRuntimeData: u32 = 0x1175;
pub const NtGdiDdDDIGetScanLine: u32 = 0x1176;
pub const NtGdiDdDDIGetSharedPrimaryHandle: u32 = 0x1177;
pub const NtGdiDdDDIInvalidateActiveVidPn: u32 = 0x1178;
pub const NtGdiDdDDILock: u32 = 0x1179;
pub const NtGdiDdDDIOpenAdapterFromDeviceName: u32 = 0x117a;
pub const NtGdiDdDDIOpenAdapterFromHdc: u32 = 0x117b;
pub const NtGdiDdDDIOpenKeyedMutex: u32 = 0x117c;
pub const NtGdiDdDDIOpenResource: u32 = 0x117d;
pub const NtGdiDdDDIOpenSynchronizationObject: u32 = 0x117e;
pub const NtGdiDdDDIPollDisplayChildren: u32 = 0x117f;
pub const NtGdiDdDDIPresent: u32 = 0x1180;
pub const NtGdiDdDDIQueryAdapterInfo: u32 = 0x1181;
pub const NtGdiDdDDIQueryAllocationResidency: u32 = 0x1182;
pub const NtGdiDdDDIQueryResourceInfo: u32 = 0x1183;
pub const NtGdiDdDDIQueryStatistics: u32 = 0x1184;
pub const NtGdiDdDDIReleaseKeyedMutex: u32 = 0x1185;
pub const NtGdiDdDDIReleaseProcessVidPnSourceOwners: u32 = 0x1186;
pub const NtGdiDdDDIRender: u32 = 0x1187;
pub const NtGdiDdDDISetAllocationPriority: u32 = 0x1188;
pub const NtGdiDdDDISetContextSchedulingPriority: u32 = 0x1189;
pub const NtGdiDdDDISetDisplayMode: u32 = 0x118a;
pub const NtGdiDdDDISetDisplayPrivateDriverFormat: u32 = 0x118b;
pub const NtGdiDdDDISetGammaRamp: u32 = 0x118c;
pub const NtGdiDdDDISetProcessSchedulingPriorityClass: u32 = 0x118d;
pub const NtGdiDdDDISetQueuedLimit: u32 = 0x118e;
pub const NtGdiDdDDISetVidPnSourceOwner: u32 = 0x118f;
pub const NtGdiDdDDISharedPrimaryLockNotification: u32 = 0x1190;
pub const NtGdiDdDDISharedPrimaryUnLockNotification: u32 = 0x1191;
pub const NtGdiDdDDISignalSynchronizationObject: u32 = 0x1192;
pub const NtGdiDdDDIUnlock: u32 = 0x1193;
pub const NtGdiDdDDIUpdateOverlay: u32 = 0x1194;
pub const NtGdiDdDDIWaitForIdle: u32 = 0x1195;
pub const NtGdiDdDDIWaitForSynchronizationObject: u32 = 0x1196;
pub const NtGdiDdDDIWaitForVerticalBlankEvent: u32 = 0x1197;
pub const NtGdiDdDeleteDirectDrawObject: u32 = 0x1198;
pub const NtGdiDdDestroyD3DBuffer: u32 = 0x1199;
pub const NtGdiDdDestroyFullscreenSprite: u32 = 0x119a;
pub const NtGdiDdDestroyMoComp: u32 = 0x119b;
pub const NtGdiDdEndMoCompFrame: u32 = 0x119c;
pub const NtGdiDdFlip: u32 = 0x119d;
pub const NtGdiDdFlipToGDISurface: u32 = 0x119e;
pub const NtGdiDdGetAvailDriverMemory: u32 = 0x119f;
pub const NtGdiDdGetBltStatus: u32 = 0x11a0;
pub const NtGdiDdGetDC: u32 = 0x11a1;
pub const NtGdiDdGetDriverInfo: u32 = 0x11a2;
pub const NtGdiDdGetDriverState: u32 = 0x11a3;
pub const NtGdiDdGetDxHandle: u32 = 0x11a4;
pub const NtGdiDdGetFlipStatus: u32 = 0x11a5;
pub const NtGdiDdGetInternalMoCompInfo: u32 = 0x11a6;
pub const NtGdiDdGetMoCompBuffInfo: u32 = 0x11a7;
pub const NtGdiDdGetMoCompFormats: u32 = 0x11a8;
pub const NtGdiDdGetMoCompGuids: u32 = 0x11a9;
pub const NtGdiDdGetScanLine: u32 = 0x11aa;
pub const NtGdiDdLock: u32 = 0x11ab;
pub const NtGdiDdNotifyFullscreenSpriteUpdate: u32 = 0x11ac;
pub const NtGdiDdQueryDirectDrawObject: u32 = 0x11ad;
pub const NtGdiDdQueryMoCompStatus: u32 = 0x11ae;
pub const NtGdiDdQueryVisRgnUniqueness: u32 = 0x11af;
pub const NtGdiDdReenableDirectDrawObject: u32 = 0x11b0;
pub const NtGdiDdReleaseDC: u32 = 0x11b1;
pub const NtGdiDdRenderMoComp: u32 = 0x11b2;
pub const NtGdiDdSetColorKey: u32 = 0x11b3;
pub const NtGdiDdSetExclusiveMode: u32 = 0x11b4;
pub const NtGdiDdSetGammaRamp: u32 = 0x11b5;
pub const NtGdiDdSetOverlayPosition: u32 = 0x11b6;
pub const NtGdiDdUnattachSurface: u32 = 0x11b7;
pub const NtGdiDdUnlock: u32 = 0x11b8;
pub const NtGdiDdUpdateOverlay: u32 = 0x11b9;
pub const NtGdiDdWaitForVerticalBlank: u32 = 0x11ba;
pub const NtGdiDeleteColorTransform: u32 = 0x11bb;
pub const NtGdiDescribePixelFormat: u32 = 0x11bc;
pub const NtGdiDestroyOPMProtectedOutput: u32 = 0x11bd;
pub const NtGdiDestroyPhysicalMonitor: u32 = 0x11be;
pub const NtGdiDoBanding: u32 = 0x11bf;
pub const NtGdiDrawEscape: u32 = 0x11c0;
pub const NtGdiDvpAcquireNotification: u32 = 0x11c1;
pub const NtGdiDvpCanCreateVideoPort: u32 = 0x11c2;
pub const NtGdiDvpColorControl: u32 = 0x11c3;
pub const NtGdiDvpCreateVideoPort: u32 = 0x11c4;
pub const NtGdiDvpDestroyVideoPort: u32 = 0x11c5;
pub const NtGdiDvpFlipVideoPort: u32 = 0x11c6;
pub const NtGdiDvpGetVideoPortBandwidth: u32 = 0x11c7;
pub const NtGdiDvpGetVideoPortConnectInfo: u32 = 0x11c8;
pub const NtGdiDvpGetVideoPortField: u32 = 0x11c9;
pub const NtGdiDvpGetVideoPortFlipStatus: u32 = 0x11ca;
pub const NtGdiDvpGetVideoPortInputFormats: u32 = 0x11cb;
pub const NtGdiDvpGetVideoPortLine: u32 = 0x11cc;
pub const NtGdiDvpGetVideoPortOutputFormats: u32 = 0x11cd;
pub const NtGdiDvpGetVideoSignalStatus: u32 = 0x11ce;
pub const NtGdiDvpReleaseNotification: u32 = 0x11cf;
pub const NtGdiDvpUpdateVideoPort: u32 = 0x11d0;
pub const NtGdiDvpWaitForVideoPortSync: u32 = 0x11d1;
pub const NtGdiDxgGenericThunk: u32 = 0x11d2;
pub const NtGdiEllipse: u32 = 0x11d3;
pub const NtGdiEnableEudc: u32 = 0x11d4;
pub const NtGdiEndDoc: u32 = 0x11d5;
pub const NtGdiEndGdiRendering: u32 = 0x11d6;
pub const NtGdiEndPage: u32 = 0x11d7;
pub const NtGdiEngAlphaBlend: u32 = 0x11d8;
pub const NtGdiEngAssociateSurface: u32 = 0x11d9;
pub const NtGdiEngBitBlt: u32 = 0x11da;
pub const NtGdiEngCheckAbort: u32 = 0x11db;
pub const NtGdiEngComputeGlyphSet: u32 = 0x11dc;
pub const NtGdiEngCopyBits: u32 = 0x11dd;
pub const NtGdiEngCreateBitmap: u32 = 0x11de;
pub const NtGdiEngCreateClip: u32 = 0x11df;
pub const NtGdiEngCreateDeviceBitmap: u32 = 0x11e0;
pub const NtGdiEngCreateDeviceSurface: u32 = 0x11e1;
pub const NtGdiEngCreatePalette: u32 = 0x11e2;
pub const NtGdiEngDeleteClip: u32 = 0x11e3;
pub const NtGdiEngDeletePalette: u32 = 0x11e4;
pub const NtGdiEngDeletePath: u32 = 0x11e5;
pub const NtGdiEngDeleteSurface: u32 = 0x11e6;
pub const NtGdiEngEraseSurface: u32 = 0x11e7;
pub const NtGdiEngFillPath: u32 = 0x11e8;
pub const NtGdiEngGradientFill: u32 = 0x11e9;
pub const NtGdiEngLineTo: u32 = 0x11ea;
pub const NtGdiEngLockSurface: u32 = 0x11eb;
pub const NtGdiEngMarkBandingSurface: u32 = 0x11ec;
pub const NtGdiEngPaint: u32 = 0x11ed;
pub const NtGdiEngPlgBlt: u32 = 0x11ee;
pub const NtGdiEngStretchBlt: u32 = 0x11ef;
pub const NtGdiEngStretchBltROP: u32 = 0x11f0;
pub const NtGdiEngStrokeAndFillPath: u32 = 0x11f1;
pub const NtGdiEngStrokePath: u32 = 0x11f2;
pub const NtGdiEngTextOut: u32 = 0x11f3;
pub const NtGdiEngTransparentBlt: u32 = 0x11f4;
pub const NtGdiEngUnlockSurface: u32 = 0x11f5;
pub const NtGdiEnumFonts: u32 = 0x11f6;
pub const NtGdiEnumObjects: u32 = 0x11f7;
pub const NtGdiEudcLoadUnloadLink: u32 = 0x11f8;
pub const NtGdiExtFloodFill: u32 = 0x11f9;
pub const NtGdiFONTOBJ_cGetAllGlyphHandles: u32 = 0x11fa;
pub const NtGdiFONTOBJ_cGetGlyphs: u32 = 0x11fb;
pub const NtGdiFONTOBJ_pQueryGlyphAttrs: u32 = 0x11fc;
pub const NtGdiFONTOBJ_pfdg: u32 = 0x11fd;
pub const NtGdiFONTOBJ_pifi: u32 = 0x11fe;
pub const NtGdiFONTOBJ_pvTrueTypeFontFile: u32 = 0x11ff;
pub const NtGdiFONTOBJ_pxoGetXform: u32 = 0x1200;
pub const NtGdiFONTOBJ_vGetInfo: u32 = 0x1201;
pub const NtGdiFlattenPath: u32 = 0x1202;
pub const NtGdiFontIsLinked: u32 = 0x1203;
pub const NtGdiForceUFIMapping: u32 = 0x1204;
pub const NtGdiFrameRgn: u32 = 0x1205;
pub const NtGdiFullscreenControl: u32 = 0x1206;
pub const NtGdiGetBoundsRect: u32 = 0x1207;
pub const NtGdiGetCOPPCompatibleOPMInformation: u32 = 0x1208;
pub const NtGdiGetCertificate: u32 = 0x1209;
pub const NtGdiGetCertificateSize: u32 = 0x120a;
pub const NtGdiGetCharABCWidthsW: u32 = 0x120b;
pub const NtGdiGetCharacterPlacementW: u32 = 0x120c;
pub const NtGdiGetColorAdjustment: u32 = 0x120d;
pub const NtGdiGetColorSpaceforBitmap: u32 = 0x120e;
pub const NtGdiGetDeviceCaps: u32 = 0x120f;
pub const NtGdiGetDeviceCapsAll: u32 = 0x1210;
pub const NtGdiGetDeviceGammaRamp: u32 = 0x1211;
pub const NtGdiGetDeviceWidth: u32 = 0x1212;
pub const NtGdiGetDhpdev: u32 = 0x1213;
pub const NtGdiGetETM: u32 = 0x1214;
pub const NtGdiGetEmbUFI: u32 = 0x1215;
pub const NtGdiGetEmbedFonts: u32 = 0x1216;
pub const NtGdiGetEudcTimeStampEx: u32 = 0x1217;
pub const NtGdiGetFontFileData: u32 = 0x1218;
pub const NtGdiGetFontFileInfo: u32 = 0x1219;
pub const NtGdiGetFontResourceInfoInternalW: u32 = 0x121a;
pub const NtGdiGetFontUnicodeRanges: u32 = 0x121b;
pub const NtGdiGetGlyphIndicesW: u32 = 0x121c;
pub const NtGdiGetGlyphIndicesWInternal: u32 = 0x121d;
pub const NtGdiGetGlyphOutline: u32 = 0x121e;
pub const NtGdiGetKerningPairs: u32 = 0x121f;
pub const NtGdiGetLinkedUFIs: u32 = 0x1220;
pub const NtGdiGetMiterLimit: u32 = 0x1221;
pub const NtGdiGetMonitorID: u32 = 0x1222;
pub const NtGdiGetNumberOfPhysicalMonitors: u32 = 0x1223;
pub const NtGdiGetOPMInformation: u32 = 0x1224;
pub const NtGdiGetOPMRandomNumber: u32 = 0x1225;
pub const NtGdiGetObjectBitmapHandle: u32 = 0x1226;
pub const NtGdiGetPath: u32 = 0x1227;
pub const NtGdiGetPerBandInfo: u32 = 0x1228;
pub const NtGdiGetPhysicalMonitorDescription: u32 = 0x1229;
pub const NtGdiGetPhysicalMonitors: u32 = 0x122a;
pub const NtGdiGetRealizationInfo: u32 = 0x122b;
pub const NtGdiGetServerMetaFileBits: u32 = 0x122c;
pub const NtGdiGetSpoolMessage: u32 = 0x122d;
pub const NtGdiGetStats: u32 = 0x122e;
pub const NtGdiGetStringBitmapW: u32 = 0x122f;
pub const NtGdiGetSuggestedOPMProtectedOutputArraySize: u32 = 0x1230;
pub const NtGdiGetTextExtentExW: u32 = 0x1231;
pub const NtGdiGetUFI: u32 = 0x1232;
pub const NtGdiGetUFIPathname: u32 = 0x1233;
pub const NtGdiGradientFill: u32 = 0x1234;
pub const NtGdiHLSurfGetInformation: u32 = 0x1235;
pub const NtGdiHLSurfSetInformation: u32 = 0x1236;
pub const NtGdiHT_Get8BPPFormatPalette: u32 = 0x1237;
pub const NtGdiHT_Get8BPPMaskPalette: u32 = 0x1238;
pub const NtGdiIcmBrushInfo: u32 = 0x1239;
pub const NtGdiInit: u32 = 0x123a;
pub const NtGdiInitSpool: u32 = 0x123b;
pub const NtGdiMakeFontDir: u32 = 0x123c;
pub const NtGdiMakeInfoDC: u32 = 0x123d;
pub const NtGdiMakeObjectUnXferable: u32 = 0x123e;
pub const NtGdiMakeObjectXferable: u32 = 0x123f;
pub const NtGdiMirrorWindowOrg: u32 = 0x1240;
pub const NtGdiMonoBitmap: u32 = 0x1241;
pub const NtGdiMoveTo: u32 = 0x1242;
pub const NtGdiOffsetClipRgn: u32 = 0x1243;
pub const NtGdiPATHOBJ_bEnum: u32 = 0x1244;
pub const NtGdiPATHOBJ_bEnumClipLines: u32 = 0x1245;
pub const NtGdiPATHOBJ_vEnumStart: u32 = 0x1246;
pub const NtGdiPATHOBJ_vEnumStartClipLines: u32 = 0x1247;
pub const NtGdiPATHOBJ_vGetBounds: u32 = 0x1248;
pub const NtGdiPathToRegion: u32 = 0x1249;
pub const NtGdiPlgBlt: u32 = 0x124a;
pub const NtGdiPolyDraw: u32 = 0x124b;
pub const NtGdiPolyTextOutW: u32 = 0x124c;
pub const NtGdiPtInRegion: u32 = 0x124d;
pub const NtGdiPtVisible: u32 = 0x124e;
pub const NtGdiQueryFonts: u32 = 0x124f;
pub const NtGdiRemoveFontResourceW: u32 = 0x1250;
pub const NtGdiRemoveMergeFont: u32 = 0x1251;
pub const NtGdiResetDC: u32 = 0x1252;
pub const NtGdiResizePalette: u32 = 0x1253;
pub const NtGdiRoundRect: u32 = 0x1254;
pub const NtGdiSTROBJ_bEnum: u32 = 0x1255;
pub const NtGdiSTROBJ_bEnumPositionsOnly: u32 = 0x1256;
pub const NtGdiSTROBJ_bGetAdvanceWidths: u32 = 0x1257;
pub const NtGdiSTROBJ_dwGetCodePage: u32 = 0x1258;
pub const NtGdiSTROBJ_vEnumStart: u32 = 0x1259;
pub const NtGdiScaleViewportExtEx: u32 = 0x125a;
pub const NtGdiScaleWindowExtEx: u32 = 0x125b;
pub const NtGdiSelectBrush: u32 = 0x125c;
pub const NtGdiSelectClipPath: u32 = 0x125d;
pub const NtGdiSelectPen: u32 = 0x125e;
pub const NtGdiSetBitmapAttributes: u32 = 0x125f;
pub const NtGdiSetBrushAttributes: u32 = 0x1260;
pub const NtGdiSetColorAdjustment: u32 = 0x1261;
pub const NtGdiSetColorSpace: u32 = 0x1262;
pub const NtGdiSetDeviceGammaRamp: u32 = 0x1263;
pub const NtGdiSetFontXform: u32 = 0x1264;
pub const NtGdiSetIcmMode: u32 = 0x1265;
pub const NtGdiSetLinkedUFIs: u32 = 0x1266;
pub const NtGdiSetMagicColors: u32 = 0x1267;
pub const NtGdiSetOPMSigningKeyAndSequenceNumbers: u32 = 0x1268;
pub const NtGdiSetPUMPDOBJ: u32 = 0x1269;
pub const NtGdiSetPixelFormat: u32 = 0x126a;
pub const NtGdiSetRectRgn: u32 = 0x126b;
pub const NtGdiSetSizeDevice: u32 = 0x126c;
pub const NtGdiSetSystemPaletteUse: u32 = 0x126d;
pub const NtGdiSetTextJustification: u32 = 0x126e;
pub const NtGdiSfmGetNotificationTokens: u32 = 0x126f;
pub const NtGdiStartDoc: u32 = 0x1270;
pub const NtGdiStartPage: u32 = 0x1271;
pub const NtGdiStrokeAndFillPath: u32 = 0x1272;
pub const NtGdiStrokePath: u32 = 0x1273;
pub const NtGdiSwapBuffers: u32 = 0x1274;
pub const NtGdiTransparentBlt: u32 = 0x1275;
pub const NtGdiUMPDEngFreeUserMem: u32 = 0x1276;
pub const NtGdiUnloadPrinterDriver: u32 = 0x1277;
pub const NtGdiUnmapMemFont: u32 = 0x1278;
pub const NtGdiUpdateColors: u32 = 0x1279;
pub const NtGdiUpdateTransform: u32 = 0x127a;
pub const NtGdiWidenPath: u32 = 0x127b;
pub const NtGdiXFORMOBJ_bApplyXform: u32 = 0x127c;
pub const NtGdiXFORMOBJ_iGetXform: u32 = 0x127d;
pub const NtGdiXLATEOBJ_cGetPalette: u32 = 0x127e;
pub const NtGdiXLATEOBJ_hGetColorTransform: u32 = 0x127f;
pub const NtGdiXLATEOBJ_iXlate: u32 = 0x1280;

// ----------------------------------------------------------------------------
// USER Services - Window Management
// ----------------------------------------------------------------------------

pub const NtUserGetThreadState: u32 = 0x1000;
pub const NtUserPeekMessage: u32 = 0x1001;
pub const NtUserCallOneParam: u32 = 0x1002;
pub const NtUserGetKeyState: u32 = 0x1003;
pub const NtUserInvalidateRect: u32 = 0x1004;
pub const NtUserCallNoParam: u32 = 0x1005;
pub const NtUserGetMessage: u32 = 0x1006;
pub const NtUserMessageCall: u32 = 0x1007;
pub const NtUserGetDC: u32 = 0x100a;
pub const NtUserWaitMessage: u32 = 0x100c;
pub const NtUserTranslateMessage: u32 = 0x100d;
pub const NtUserGetProp: u32 = 0x100e;
pub const NtUserPostMessage: u32 = 0x100f;
pub const NtUserQueryWindow: u32 = 0x1010;
pub const NtUserTranslateAccelerator: u32 = 0x1011;
pub const NtUserRedrawWindow: u32 = 0x1013;
pub const NtUserWindowFromPoint: u32 = 0x1014;
pub const NtUserCallMsgFilter: u32 = 0x1015;
pub const NtUserValidateTimerCallback: u32 = 0x1016;
pub const NtUserBeginPaint: u32 = 0x1017;
pub const NtUserSetTimer: u32 = 0x1018;
pub const NtUserEndPaint: u32 = 0x1019;
pub const NtUserSetCursor: u32 = 0x101a;
pub const NtUserKillTimer: u32 = 0x101b;
pub const NtUserBuildHwndList: u32 = 0x101c;
pub const NtUserSelectPalette: u32 = 0x101d;
pub const NtUserCallNextHookEx: u32 = 0x101e;
pub const NtUserHideCaret: u32 = 0x101f;
pub const NtUserCallHwndLock: u32 = 0x1021;
pub const NtUserGetProcessWindowStation: u32 = 0x1022;
pub const NtUserSetWindowPos: u32 = 0x1024;
pub const NtUserShowCaret: u32 = 0x1025;
pub const NtUserEndDeferWindowPosEx: u32 = 0x1026;
pub const NtUserCallHwndParamLock: u32 = 0x1027;
pub const NtUserVkKeyScanEx: u32 = 0x1028;
pub const NtUserCallTwoParam: u32 = 0x102a;
pub const NtUserCopyAcceleratorTable: u32 = 0x102c;
pub const NtUserNotifyWinEvent: u32 = 0x102d;
pub const NtUserIsClipboardFormatAvailable: u32 = 0x102f;
pub const NtUserSetScrollInfo: u32 = 0x1030;
pub const NtUserCreateCaret: u32 = 0x1032;
pub const NtUserDispatchMessage: u32 = 0x1036;
pub const NtUserRegisterWindowMessage: u32 = 0x1037;
pub const NtUserGetForegroundWindow: u32 = 0x103c;
pub const NtUserShowScrollBar: u32 = 0x103d;
pub const NtUserFindExistingCursorIcon: u32 = 0x103e;
pub const NtUserSystemParametersInfo: u32 = 0x1042;
pub const NtUserGetAsyncKeyState: u32 = 0x1044;
pub const NtUserGetCPD: u32 = 0x1045;
pub const NtUserRemoveProp: u32 = 0x1046;
pub const NtUserSetCapture: u32 = 0x1049;
pub const NtUserEnumDisplayMonitors: u32 = 0x104a;
pub const NtUserSetProp: u32 = 0x104c;
pub const NtUserSBGetParms: u32 = 0x104e;
pub const NtUserGetIconInfo: u32 = 0x104f;
pub const NtUserExcludeUpdateRgn: u32 = 0x1050;
pub const NtUserSetFocus: u32 = 0x1051;
pub const NtUserDeferWindowPos: u32 = 0x1053;
pub const NtUserGetUpdateRect: u32 = 0x1054;
pub const NtUserGetClipboardSequenceNumber: u32 = 0x1056;
pub const NtUserShowWindow: u32 = 0x1058;
pub const NtUserGetKeyboardLayoutList: u32 = 0x1059;
pub const NtUserMapVirtualKeyEx: u32 = 0x105b;
pub const NtUserSetWindowLong: u32 = 0x105c;
pub const NtUserMoveWindow: u32 = 0x105e;
pub const NtUserPostThreadMessage: u32 = 0x105f;
pub const NtUserDrawIconEx: u32 = 0x1060;
pub const NtUserGetSystemMenu: u32 = 0x1061;
pub const NtUserInternalGetWindowText: u32 = 0x1063;
pub const NtUserGetWindowDC: u32 = 0x1064;
pub const NtUserScrollDC: u32 = 0x106b;
pub const NtUserGetObjectInformation: u32 = 0x106c;
pub const NtUserFindWindowEx: u32 = 0x106e;
pub const NtUserUnhookWindowsHookEx: u32 = 0x1070;
pub const NtUserCreateWindowEx: u32 = 0x1076;
pub const NtUserSetParent: u32 = 0x1077;
pub const NtUserGetKeyboardState: u32 = 0x1078;
pub const NtUserToUnicodeEx: u32 = 0x1079;
pub const NtUserGetControlBrush: u32 = 0x107a;
pub const NtUserGetClassName: u32 = 0x107b;
pub const NtUserDefSetText: u32 = 0x107f;
pub const NtUserSendInput: u32 = 0x1082;
pub const NtUserGetThreadDesktop: u32 = 0x1083;
pub const NtUserGetUpdateRgn: u32 = 0x1086;
pub const NtUserGetIconSize: u32 = 0x1088;
pub const NtUserFillWindow: u32 = 0x1089;
pub const NtUserSetWindowsHookEx: u32 = 0x108c;
pub const NtUserNotifyProcessCreate: u32 = 0x108d;
pub const NtUserGetTitleBarInfo: u32 = 0x108f;
pub const NtUserSetThreadDesktop: u32 = 0x1091;
pub const NtUserGetDCEx: u32 = 0x1092;
pub const NtUserGetScrollBarInfo: u32 = 0x1093;
pub const NtUserSetWindowFNID: u32 = 0x1095;
pub const NtUserCalcMenuBar: u32 = 0x1097;
pub const NtUserThunkedMenuItemInfo: u32 = 0x1098;
pub const NtUserDestroyCursor: u32 = 0x109c;
pub const NtUserDestroyWindow: u32 = 0x109d;
pub const NtUserCallHwndParam: u32 = 0x109e;
pub const NtUserOpenWindowStation: u32 = 0x10a0;
pub const NtUserSetCursorIconData: u32 = 0x10a4;
pub const NtUserCloseDesktop: u32 = 0x10a6;
pub const NtUserOpenDesktop: u32 = 0x10a7;
pub const NtUserSetProcessWindowStation: u32 = 0x10a8;
pub const NtUserGetAtomName: u32 = 0x10a9;
pub const NtUserBuildNameList: u32 = 0x10ae;
pub const NtUserRegisterClassExWOW: u32 = 0x10b0;
pub const NtUserGetAncestor: u32 = 0x10b2;
pub const NtUserCloseWindowStation: u32 = 0x10b5;
pub const NtUserGetDoubleClickTime: u32 = 0x10b6;
pub const NtUserEnableScrollBar: u32 = 0x10b7;
pub const NtUserGetClassInfoEx: u32 = 0x10b9;
pub const NtUserUnregisterClass: u32 = 0x10bb;
pub const NtUserDeleteMenu: u32 = 0x10bc;
pub const NtUserScrollWindowEx: u32 = 0x10be;
pub const NtUserSetClassLong: u32 = 0x10c0;
pub const NtUserGetMenuBarInfo: u32 = 0x10c1;
pub const NtUserInvalidateRgn: u32 = 0x10c8;
pub const NtUserGetClipboardOwner: u32 = 0x10c9;
pub const NtUserSetWindowRgn: u32 = 0x10ca;
pub const NtUserBitBltSysBmp: u32 = 0x10cb;
pub const NtUserValidateRect: u32 = 0x10cd;
pub const NtUserCloseClipboard: u32 = 0x10ce;
pub const NtUserOpenClipboard: u32 = 0x10cf;
pub const NtUserSetClipboardData: u32 = 0x10d1;
pub const NtUserEnableMenuItem: u32 = 0x10d2;
pub const NtUserAlterWindowStyle: u32 = 0x10d3;
pub const NtUserGetWindowPlacement: u32 = 0x10d5;
pub const NtUserGetOpenClipboardWindow: u32 = 0x10d8;
pub const NtUserSetThreadState: u32 = 0x10d9;
pub const NtUserTrackMouseEvent: u32 = 0x10db;
pub const NtUserDestroyMenu: u32 = 0x10dd;
pub const NtUserConsoleControl: u32 = 0x10df;
pub const NtUserSetActiveWindow: u32 = 0x10e0;
pub const NtUserSetInformationThread: u32 = 0x10e1;
pub const NtUserSetWindowPlacement: u32 = 0x10e2;
pub const NtUserGetControlColor: u32 = 0x10e3;
pub const NtUserSetWindowWord: u32 = 0x10e8;
pub const NtUserGetClipboardFormatName: u32 = 0x10e9;
pub const NtUserRealInternalGetMessage: u32 = 0x10ea;
pub const NtUserCreateLocalMemHandle: u32 = 0x10eb;
pub const NtUserAttachThreadInput: u32 = 0x10ec;
pub const NtUserPaintMenuBar: u32 = 0x10ee;
pub const NtUserSetKeyboardState: u32 = 0x10ef;
pub const NtUserCreateAcceleratorTable: u32 = 0x10f1;
pub const NtUserGetCursorFrameInfo: u32 = 0x10f2;
pub const NtUserGetAltTabInfo: u32 = 0x10f3;
pub const NtUserGetCaretBlinkTime: u32 = 0x10f4;
pub const NtUserProcessConnect: u32 = 0x10f6;
pub const NtUserEnumDisplayDevices: u32 = 0x10f7;
pub const NtUserEmptyClipboard: u32 = 0x10f8;
pub const NtUserGetClipboardData: u32 = 0x10f9;
pub const NtUserRemoveMenu: u32 = 0x10fa;
pub const NtUserConvertMemHandle: u32 = 0x10fd;
pub const NtUserDestroyAcceleratorTable: u32 = 0x10fe;
pub const NtUserGetGUIThreadInfo: u32 = 0x10ff;
pub const NtUserSetWindowsHookAW: u32 = 0x1101;
pub const NtUserSetMenuDefaultItem: u32 = 0x1102;
pub const NtUserCheckMenuItem: u32 = 0x1103;
pub const NtUserSetWinEventHook: u32 = 0x1104;
pub const NtUserUnhookWinEvent: u32 = 0x1105;
pub const NtUserLockWindowUpdate: u32 = 0x1106;
pub const NtUserSetSystemMenu: u32 = 0x1107;
pub const NtUserThunkedMenuInfo: u32 = 0x1108;
pub const NtUserCallHwnd: u32 = 0x110c;
pub const NtUserDdeInitialize: u32 = 0x110d;
pub const NtUserModifyUserStartupInfoFlags: u32 = 0x110e;
pub const NtUserCountClipboardFormats: u32 = 0x110f;
pub const NtUserEnumDisplaySettings: u32 = 0x1114;
pub const NtUserPaintDesktop: u32 = 0x1115;
pub const NtUserChangeClipboardChain: u32 = 0x1119;
pub const NtUserSetClipboardViewer: u32 = 0x111a;
pub const NtUserShowWindowAsync: u32 = 0x111b;
pub const NtUserActivateKeyboardLayout: u32 = 0x111e;
pub const NtUserAddClipboardFormatListener: u32 = 0x1281;
pub const NtUserAssociateInputContext: u32 = 0x1282;
pub const NtUserBlockInput: u32 = 0x1283;
pub const NtUserBuildHimcList: u32 = 0x1284;
pub const NtUserBuildPropList: u32 = 0x1285;
pub const NtUserCalculatePopupWindowPosition: u32 = 0x1286;
pub const NtUserCallHwndOpt: u32 = 0x1287;
pub const NtUserChangeDisplaySettings: u32 = 0x1288;
pub const NtUserChangeWindowMessageFilterEx: u32 = 0x1289;
pub const NtUserCheckAccessForIntegrityLevel: u32 = 0x128a;
pub const NtUserCheckDesktopByThreadId: u32 = 0x128b;
pub const NtUserCheckWindowThreadDesktop: u32 = 0x128c;
pub const NtUserChildWindowFromPointEx: u32 = 0x128d;
pub const NtUserClipCursor: u32 = 0x128e;
pub const NtUserCreateDesktopEx: u32 = 0x128f;
pub const NtUserCreateInputContext: u32 = 0x1290;
pub const NtUserCreateWindowStation: u32 = 0x1291;
pub const NtUserCtxDisplayIOCtl: u32 = 0x1292;
pub const NtUserDestroyInputContext: u32 = 0x1293;
pub const NtUserDisableThreadIme: u32 = 0x1294;
pub const NtUserDisplayConfigGetDeviceInfo: u32 = 0x1295;
pub const NtUserDisplayConfigSetDeviceInfo: u32 = 0x1296;
pub const NtUserDoSoundConnect: u32 = 0x1297;
pub const NtUserDoSoundDisconnect: u32 = 0x1298;
pub const NtUserDragDetect: u32 = 0x1299;
pub const NtUserDragObject: u32 = 0x129a;
pub const NtUserDrawAnimatedRects: u32 = 0x129b;
pub const NtUserDrawCaption: u32 = 0x129c;
pub const NtUserDrawCaptionTemp: u32 = 0x129d;
pub const NtUserDrawMenuBarTemp: u32 = 0x129e;
pub const NtUserDwmStartRedirection: u32 = 0x129f;
pub const NtUserDwmStopRedirection: u32 = 0x12a0;
pub const NtUserEndMenu: u32 = 0x12a1;
pub const NtUserEndTouchOperation: u32 = 0x12a2;
pub const NtUserEvent: u32 = 0x12a3;
pub const NtUserFlashWindowEx: u32 = 0x12a4;
pub const NtUserFrostCrashedWindow: u32 = 0x12a5;
pub const NtUserGetAppImeLevel: u32 = 0x12a6;
pub const NtUserGetCaretPos: u32 = 0x12a7;
pub const NtUserGetClipCursor: u32 = 0x12a8;
pub const NtUserGetClipboardViewer: u32 = 0x12a9;
pub const NtUserGetComboBoxInfo: u32 = 0x12aa;
pub const NtUserGetCursorInfo: u32 = 0x12ab;
pub const NtUserGetDisplayConfigBufferSizes: u32 = 0x12ac;
pub const NtUserGetGestureConfig: u32 = 0x12ad;
pub const NtUserGetGestureExtArgs: u32 = 0x12ae;
pub const NtUserGetGestureInfo: u32 = 0x12af;
pub const NtUserGetGuiResources: u32 = 0x12b0;
pub const NtUserGetImeHotKey: u32 = 0x12b1;
pub const NtUserGetImeInfoEx: u32 = 0x12b2;
pub const NtUserGetInputLocaleInfo: u32 = 0x12b3;
pub const NtUserGetInternalWindowPos: u32 = 0x12b4;
pub const NtUserGetKeyNameText: u32 = 0x12b5;
pub const NtUserGetKeyboardLayoutName: u32 = 0x12b6;
pub const NtUserGetLayeredWindowAttributes: u32 = 0x12b7;
pub const NtUserGetListBoxInfo: u32 = 0x12b8;
pub const NtUserGetMenuIndex: u32 = 0x12b9;
pub const NtUserGetMenuItemRect: u32 = 0x12ba;
pub const NtUserGetMouseMovePointsEx: u32 = 0x12bb;
pub const NtUserGetPriorityClipboardFormat: u32 = 0x12bc;
pub const NtUserGetRawInputBuffer: u32 = 0x12bd;
pub const NtUserGetRawInputData: u32 = 0x12be;
pub const NtUserGetRawInputDeviceInfo: u32 = 0x12bf;
pub const NtUserGetRawInputDeviceList: u32 = 0x12c0;
pub const NtUserGetRegisteredRawInputDevices: u32 = 0x12c1;
pub const NtUserGetTopLevelWindow: u32 = 0x12c2;
pub const NtUserGetTouchInputInfo: u32 = 0x12c3;
pub const NtUserGetUpdatedClipboardFormats: u32 = 0x12c4;
pub const NtUserGetWOWClass: u32 = 0x12c5;
pub const NtUserGetWindowCompositionAttribute: u32 = 0x12c6;
pub const NtUserGetWindowCompositionInfo: u32 = 0x12c7;
pub const NtUserGetWindowDisplayAffinity: u32 = 0x12c8;
pub const NtUserGetWindowMinimizeRect: u32 = 0x12c9;
pub const NtUserGetWindowRgnEx: u32 = 0x12ca;
pub const NtUserGhostWindowFromHungWindow: u32 = 0x12cb;
pub const NtUserHardErrorControl: u32 = 0x12cc;
pub const NtUserHiliteMenuItem: u32 = 0x12cd;
pub const NtUserHungWindowFromGhostWindow: u32 = 0x12ce;
pub const NtUserHwndQueryRedirectionInfo: u32 = 0x12cf;
pub const NtUserHwndSetRedirectionInfo: u32 = 0x12d0;
pub const NtUserImpersonateDdeClientWindow: u32 = 0x12d1;
pub const NtUserInitTask: u32 = 0x12d2;
pub const NtUserInitialize: u32 = 0x12d3;
pub const NtUserInitializeClientPfnArrays: u32 = 0x12d4;
pub const NtUserInjectGesture: u32 = 0x12d5;
pub const NtUserInternalGetWindowIcon: u32 = 0x12d6;
pub const NtUserIsTopLevelWindow: u32 = 0x12d7;
pub const NtUserIsTouchWindow: u32 = 0x12d8;
pub const NtUserLoadKeyboardLayoutEx: u32 = 0x12d9;
pub const NtUserLockWindowStation: u32 = 0x12da;
pub const NtUserLockWorkStation: u32 = 0x12db;
pub const NtUserLogicalToPhysicalPoint: u32 = 0x12dc;
pub const NtUserMNDragLeave: u32 = 0x12dd;
pub const NtUserMNDragOver: u32 = 0x12de;
pub const NtUserMagControl: u32 = 0x12df;
pub const NtUserMagGetContextInformation: u32 = 0x12e0;
pub const NtUserMagSetContextInformation: u32 = 0x12e1;
pub const NtUserManageGestureHandlerWindow: u32 = 0x12e2;
pub const NtUserMenuItemFromPoint: u32 = 0x12e3;
pub const NtUserMinMaximize: u32 = 0x12e4;
pub const NtUserModifyWindowTouchCapability: u32 = 0x12e5;
pub const NtUserNotifyIMEStatus: u32 = 0x12e6;
pub const NtUserOpenInputDesktop: u32 = 0x12e7;
pub const NtUserOpenThreadDesktop: u32 = 0x12e8;
pub const NtUserPaintMonitor: u32 = 0x12e9;
pub const NtUserPhysicalToLogicalPoint: u32 = 0x12ea;
pub const NtUserPrintWindow: u32 = 0x12eb;
pub const NtUserQueryDisplayConfig: u32 = 0x12ec;
pub const NtUserQueryInformationThread: u32 = 0x12ed;
pub const NtUserQueryInputContext: u32 = 0x12ee;
pub const NtUserQuerySendMessage: u32 = 0x12ef;
pub const NtUserRealChildWindowFromPoint: u32 = 0x12f0;
pub const NtUserRealWaitMessageEx: u32 = 0x12f1;
pub const NtUserRegisterErrorReportingDialog: u32 = 0x12f2;
pub const NtUserRegisterHotKey: u32 = 0x12f3;
pub const NtUserRegisterRawInputDevices: u32 = 0x12f4;
pub const NtUserRegisterServicesProcess: u32 = 0x12f5;
pub const NtUserRegisterSessionPort: u32 = 0x12f6;
pub const NtUserRegisterTasklist: u32 = 0x12f7;
pub const NtUserRegisterUserApiHook: u32 = 0x12f8;
pub const NtUserRemoteConnect: u32 = 0x12f9;
pub const NtUserRemoteRedrawRectangle: u32 = 0x12fa;
pub const NtUserRemoteRedrawScreen: u32 = 0x12fb;
pub const NtUserRemoteStopScreenUpdates: u32 = 0x12fc;
pub const NtUserRemoveClipboardFormatListener: u32 = 0x12fd;
pub const NtUserResolveDesktopForWOW: u32 = 0x12fe;
pub const NtUserSendTouchInput: u32 = 0x12ff;
pub const NtUserSetAppImeLevel: u32 = 0x1300;
pub const NtUserSetChildWindowNoActivate: u32 = 0x1301;
pub const NtUserSetClassWord: u32 = 0x1302;
pub const NtUserSetCursorContents: u32 = 0x1303;
pub const NtUserSetDisplayConfig: u32 = 0x1304;
pub const NtUserSetGestureConfig: u32 = 0x1305;
pub const NtUserSetImeHotKey: u32 = 0x1306;
pub const NtUserSetImeInfoEx: u32 = 0x1307;
pub const NtUserSetImeOwnerWindow: u32 = 0x1308;
pub const NtUserSetInternalWindowPos: u32 = 0x1309;
pub const NtUserSetLayeredWindowAttributes: u32 = 0x130a;
pub const NtUserSetMenu: u32 = 0x130b;
pub const NtUserSetMenuContextHelpId: u32 = 0x130c;
pub const NtUserSetMenuFlagRtoL: u32 = 0x130d;
pub const NtUserSetMirrorRendering: u32 = 0x130e;
pub const NtUserSetObjectInformation: u32 = 0x130f;
pub const NtUserSetProcessDPIAware: u32 = 0x1310;
pub const NtUserSetShellWindowEx: u32 = 0x1311;
pub const NtUserSetSysColors: u32 = 0x1312;
pub const NtUserSetSystemCursor: u32 = 0x1313;
pub const NtUserSetSystemTimer: u32 = 0x1314;
pub const NtUserSetThreadLayoutHandles: u32 = 0x1315;
pub const NtUserSetWindowCompositionAttribute: u32 = 0x1316;
pub const NtUserSetWindowDisplayAffinity: u32 = 0x1317;
pub const NtUserSetWindowRgnEx: u32 = 0x1318;
pub const NtUserSetWindowStationUser: u32 = 0x1319;
pub const NtUserSfmDestroyLogicalSurfaceBinding: u32 = 0x131a;
pub const NtUserSfmDxBindSwapChain: u32 = 0x131b;
pub const NtUserSfmDxGetSwapChainStats: u32 = 0x131c;
pub const NtUserSfmDxOpenSwapChain: u32 = 0x131d;
pub const NtUserSfmDxQuerySwapChainBindingStatus: u32 = 0x131e;
pub const NtUserSfmDxReleaseSwapChain: u32 = 0x131f;
pub const NtUserSfmDxReportPendingBindingsToDwm: u32 = 0x1320;
pub const NtUserSfmDxSetSwapChainBindingStatus: u32 = 0x1321;
pub const NtUserSfmDxSetSwapChainStats: u32 = 0x1322;
pub const NtUserSfmGetLogicalSurfaceBinding: u32 = 0x1323;
pub const NtUserShowSystemCursor: u32 = 0x1324;
pub const NtUserSoundSentry: u32 = 0x1325;
pub const NtUserSwitchDesktop: u32 = 0x1326;
pub const NtUserTestForInteractiveUser: u32 = 0x1327;
pub const NtUserTrackPopupMenuEx: u32 = 0x1328;
pub const NtUserUnloadKeyboardLayout: u32 = 0x1329;
pub const NtUserUnlockWindowStation: u32 = 0x132a;
pub const NtUserUnregisterHotKey: u32 = 0x132b;
pub const NtUserUnregisterSessionPort: u32 = 0x132c;
pub const NtUserUnregisterUserApiHook: u32 = 0x132d;
pub const NtUserUpdateInputContext: u32 = 0x132e;
pub const NtUserUpdateInstance: u32 = 0x132f;
pub const NtUserUpdateLayeredWindow: u32 = 0x1330;
pub const NtUserUpdatePerUserSystemParameters: u32 = 0x1331;
pub const NtUserUpdateWindowTransform: u32 = 0x1332;
pub const NtUserUserHandleGrantAccess: u32 = 0x1333;
pub const NtUserValidateHandleSecure: u32 = 0x1334;
pub const NtUserWaitForInputIdle: u32 = 0x1335;
pub const NtUserWaitForMsgAndEvent: u32 = 0x1336;
pub const NtUserWindowFromPhysicalPoint: u32 = 0x1337;
pub const NtUserYieldTask: u32 = 0x1338;
pub const NtUserSetClassLongPtr: u32 = 0x1339;
pub const NtUserSetWindowLongPtr: u32 = 0x133a;

// =====================================================================
// Shadow SSDT Dispatch
// =====================================================================

/// Dispatch a shadow system service call
/// 
/// The syscall number contains the table index in the high bits:
/// - High 16 bits (bits 31-16): Table index (0x1 for win32k)
/// - Low 16 bits (bits 15-0): Service index within the table
/// 
/// For win32k, we extract the low 12 bits as the service index.
pub fn dispatch_shadow_service(service_number: u32, trap_frame: *mut ()) -> u64 {
    // Extract the service index from the syscall number
    let service_index = service_number & 0xFFF;
    
    match get_shadow_service(service_index) {
        Some(handler) => {
            unsafe {
                let fn_ptr: extern "C" fn(*mut ()) -> u64 = 
                    core::mem::transmute(handler);
                fn_ptr(trap_frame)
            }
        }
        None => {
            // // kprintln!("[SHADOW SSDT] Unimplemented shadow service 0x{:04x}",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                       service_number);
            0xC0000001u32 as u64 // STATUS_NOT_IMPLEMENTED
        }
    }
}

/// Check if a syscall number is a shadow (win32k) syscall
#[inline(always)]
pub fn is_win32k_syscall(syscall_num: u32) -> bool {
    // Win32k syscalls have high nibble = 0x1 (range 0x1000-0x1FFF)
    (syscall_num & 0xF000) == 0x1000
}

/// Get the service index from a win32k syscall number
#[inline(always)]
pub fn get_win32k_service_index(syscall_num: u32) -> u32 {
    syscall_num & 0x0FFF
}

// =====================================================================
// Smoke Test
// =====================================================================

/// Run Shadow SSDT smoke test
pub fn smoke_test() -> bool {
    // // kprintln!("  [SHADOW SSDT SMOKE] running Shadow SSDT smoke test...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    let table_ptr = unsafe { SHADOW_SERVICE_TABLE.as_ptr() };
    if table_ptr.is_null() {
        // // kprintln!("  [SHADOW SSDT SMOKE FAIL] ShadowServiceTable is null")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    
    let arg_ptr = unsafe { SHADOW_ARGUMENT_TABLE.as_ptr() };
    if arg_ptr.is_null() {
        // // kprintln!("  [SHADOW SSDT SMOKE FAIL] ShadowArgumentTable is null")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    
    // // kprintln!("  [SHADOW SSDT SMOKE] ShadowServiceTable: {:p}", table_ptr)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  [SHADOW SSDT SMOKE] ShadowArgumentTable: {:p}", arg_ptr)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  [SHADOW SSDT SMOKE] Max shadow services: {}", SHADOW_MAX_SERVICES)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  [SHADOW SSDT SMOKE] is_win32k_syscall(0x1234) = {}", is_win32k_syscall(0x1234))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  [SHADOW SSDT SMOKE OK]")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    true
}
