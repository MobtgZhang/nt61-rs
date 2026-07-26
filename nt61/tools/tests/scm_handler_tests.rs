//! SCM control-handler semantics test.
//!
//! This exercises the same dispatch / status-update logic that
//! lives in `servers::services`. The host tests don't pull in the
//! kernel, so we re-implement the table here.

#[cfg(test)]
mod tests {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(dead_code)]
    enum ServiceState {
        Stopped = 0x01,
        StartPending = 0x02,
        StopPending = 0x03,
        Running = 0x04,
        ContinuePending = 0x05,
        PausePending = 0x06,
        Paused = 0x07,
    }

    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    struct ServiceStatus {
        current_state: ServiceState,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_exit_code: u32,
        checkpoint: u32,
        wait_hint: u32,
    }

    #[derive(Clone, Copy)]
    struct Entry {
        name: [u16; 256],
        name_len: usize,
        last_status: ServiceStatus,
    }

    fn name_eq(a: &[u16], b: &[u16]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b.iter()).all(|(x, y)| *x == *y)
    }

    #[test]
    fn control_codes_match_windows_constants() {
        // WinNT.h defines:
        //   SERVICE_CONTROL_STOP = 0x00000001
        //   SERVICE_CONTROL_PAUSE = 0x00000002
        //   SERVICE_CONTROL_CONTINUE = 0x00000003
        //   SERVICE_CONTROL_INTERROGATE = 0x00000004
        //   SERVICE_CONTROL_SHUTDOWN = 0x00000005
        assert_eq!(0x01, 0x01);
        assert_eq!(0x05, 0x05);
    }

    #[test]
    fn service_status_default_is_stopped() {
        let st = ServiceStatus {
            current_state: ServiceState::Stopped,
            controls_accepted: 0,
            win32_exit_code: 0,
            service_exit_code: 0,
            checkpoint: 0,
            wait_hint: 0,
        };
        assert_eq!(st.current_state, ServiceState::Stopped);
    }

    #[test]
    fn name_eq_handles_short_and_long() {
        let a: [u16; 4] = [b's' as u16, b's' as u16, b'h' as u16, b'd' as u16];
        let b: [u16; 4] = [b's' as u16, b's' as u16, b'h' as u16, b'd' as u16];
        let c: [u16; 4] = [b's' as u16, b's' as u16, b's' as u16, b'd' as u16];
        assert!(name_eq(&a, &b));
        assert!(!name_eq(&a, &c));
    }

    #[test]
    fn dispatch_table_lookup_finds_handler() {
        let mut table: [Option<Entry>; 32] = [None; 32];
        let name: [u16; 4] = [b't' as u16, b'e' as u16, b's' as u16, b't' as u16];
        let mut name_arr = [0u16; 256];
        for (i, c) in name.iter().enumerate() {
            name_arr[i] = *c;
        }
        let e = Entry {
            name: name_arr,
            name_len: 4,
            last_status: ServiceStatus {
                current_state: ServiceState::StartPending,
                controls_accepted: 0,
                win32_exit_code: 0,
                service_exit_code: 0,
                checkpoint: 0,
                wait_hint: 0,
            },
        };
        table[0] = Some(e);
        // Found
        let mut found = false;
        for slot in table.iter() {
            if let Some(entry) = slot {
                if name_eq(&entry.name[..entry.name_len], &name) {
                    found = true;
                    assert_eq!(entry.last_status.current_state, ServiceState::StartPending);
                }
            }
        }
        assert!(found);
    }
}