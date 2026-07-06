//! Windows Event Log XML Export
//
//! Implements the Windows Event Log XML format as specified in [MS-EVENTXSD].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{EventChannel, EventRecord};

/// Convert event records to Windows Event Log XML
pub fn records_to_xml(records: &[EventRecord], channel: EventChannel) -> Vec<u8> {
    let mut xml: Vec<u8> = Vec::new();
    xml.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n");
    xml.extend_from_slice(b"<Events>\r\n");
    for record in records {
        xml.extend_from_slice(&event_to_xml(record, channel));
    }
    xml.extend_from_slice(b"</Events>\r\n");
    xml
}

/// Convert a single event record to XML
fn event_to_xml(record: &EventRecord, channel: EventChannel) -> Vec<u8> {
    let mut xml: Vec<u8> = Vec::new();
    xml.extend_from_slice(b"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\r\n");
    xml.extend_from_slice(b"  <System>\r\n");

    let mut provider = String::new();
    provider.push_str("<Provider Name=\"");
    for &b in &record.source[..record.source_len as usize] {
        if b == 0 { break; }
        provider.push(b as char);
    }
    provider.push_str("\" />");
    xml.extend_from_slice(provider.as_bytes());
    xml.extend_from_slice(b"\r\n");

    let mut eid = String::new();
    eid.push_str("<EventID>");
    eid.push_str(core::str::from_utf8(&itoa(record.event_id as u32)).unwrap_or("0"));
    eid.push_str("</EventID>");
    xml.extend_from_slice(eid.as_bytes());
    xml.extend_from_slice(b"\r\n");

    xml.extend_from_slice(b"    <Version>");
    xml.extend_from_slice(itoa(record.version as u32).as_slice());
    xml.extend_from_slice(b"</Version>\r\n");

    xml.extend_from_slice(b"    <Level>");
    xml.extend_from_slice(record.level.as_str().as_bytes());
    xml.extend_from_slice(b"</Level>\r\n");

    xml.extend_from_slice(b"    <Task>");
    xml.extend_from_slice(itoa(record.task as u32).as_slice());
    xml.extend_from_slice(b"</Task>\r\n");

    xml.extend_from_slice(b"    <Opcode>0</Opcode>\r\n");
    xml.extend_from_slice(b"    <Keywords>0x");
    xml.extend_from_slice(u64_to_hex(record.keywords.0).as_slice());
    xml.extend_from_slice(b"</Keywords>\r\n");

    xml.extend_from_slice(b"    <TimeCreated SystemTime=\"");
    let ts = filetime_to_iso8601(record.timestamp);
    xml.extend_from_slice(ts.as_bytes());
    xml.extend_from_slice(b"\" />\r\n");

    let mut rid = String::new();
    rid.push_str("<EventRecordID>");
    rid.push_str(core::str::from_utf8(&u64_to_decimal(record.record_id)).unwrap_or("0"));
    rid.push_str("</EventRecordID>");
    xml.extend_from_slice(rid.as_bytes());
    xml.extend_from_slice(b"\r\n");

    xml.extend_from_slice(b"    <Channel>");
    xml.extend_from_slice(channel.name());
    xml.extend_from_slice(b"</Channel>\r\n");

    let mut comp = String::new();
    comp.push_str("<Computer>");
    for &b in &record.computer[..record.computer_len as usize] {
        if b == 0 { break; }
        comp.push(b as char);
    }
    comp.push_str("</Computer>");
    xml.extend_from_slice(comp.as_bytes());
    xml.extend_from_slice(b"\r\n");

    if record.user_len == 0 {
        xml.extend_from_slice(b"    <Security />\r\n");
    } else {
        let mut sec = String::new();
        sec.push_str("<Security UserID=\"");
        for &b in &record.user[..record.user_len as usize] {
            if b == 0 { break; }
            sec.push(b as char);
        }
        sec.push_str("\" />");
        xml.extend_from_slice(sec.as_bytes());
        xml.extend_from_slice(b"\r\n");
    }

    xml.extend_from_slice(b"  </System>\r\n");

    let desc = utf16le_to_string(&record.event_data[..record.event_data_len as usize]);
    xml.extend_from_slice(b"  <EventData>\r\n    <Data>");
    xml.extend_from_slice(desc.as_bytes());
    xml.extend_from_slice(b"</Data>\r\n  </EventData>\r\n");
    xml.extend_from_slice(b"</Event>\r\n");
    xml
}

/// Convert UTF-16LE to UTF-8 String
fn utf16le_to_string(data: &[u16]) -> String {
    let mut s = String::new();
    for &cu in data {
        if cu == 0 { break; }
        if let Some(c) = char::from_u32(cu as u32) {
            s.push(c);
        }
    }
    s
}

/// Format FILETIME to ISO 8601 string
fn filetime_to_iso8601(filetime: u64) -> String {
    const TICKS_PER_SEC: u64 = 10_000_000;
    const SECS_1601_TO_1970: u64 = 11_644_473_600;
    let total_secs = filetime / TICKS_PER_SEC;
    if total_secs < SECS_1601_TO_1970 {
        return "1601-01-01T00:00:00.0000000Z".to_string();
    }
    let secs = (total_secs - SECS_1601_TO_1970) as u32;
    let t = TimeParts::from_unix(secs);
    let mut s = String::new();
    s.push_str(&u32_to_string(t.year as u32));
    s.push('-');
    if t.month < 10 { s.push('0'); }
    s.push_str(&u32_to_string(t.month as u32));
    s.push('-');
    if t.day < 10 { s.push('0'); }
    s.push_str(&u32_to_string(t.day as u32));
    s.push('T');
    if t.hour < 10 { s.push('0'); }
    s.push_str(&u32_to_string(t.hour as u32));
    s.push(':');
    if t.minute < 10 { s.push('0'); }
    s.push_str(&u32_to_string(t.minute as u32));
    s.push(':');
    if t.second < 10 { s.push('0'); }
    s.push_str(&u32_to_string(t.second as u32));
    s.push('.');
    s.push_str("0000000");
    s.push('Z');
    s
}

fn u32_to_string(mut n: u32) -> String {
    if n == 0 { return "0".to_string(); }
    let mut buf: Vec<u8> = Vec::new();
    while n > 0 {
        buf.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    buf.reverse();
    String::from_utf8(buf).unwrap_or_else(|_| "0".to_string())
}

struct TimeParts {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl TimeParts {
    fn from_unix(secs: u32) -> Self {
        let s = secs;
        let second = (s % 60) as u8;
        let m = s / 60;
        let minute = (m % 60) as u8;
        let h = m / 60;
        let hour = (h % 24) as u8;
        let mut days = h / 24;
        // Year/month/day computation (Gregorian, starting 1970-01-01)
        let mut year: u16 = 1970;
        loop {
            let dy = if is_leap(year) { 366 } else { 365 };
            if days >= dy { days -= dy; year += 1; } else { break; }
        }
        let months = [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut month: u8 = 1;
        for &ml in months.iter() {
            let ml = if month == 2 && is_leap(year) { 29 } else { ml };
            if days >= ml { days -= ml; month += 1; } else { break; }
        }
        let day = (days + 1) as u8;
        Self { year, month, day, hour, minute, second }
    }
}

fn is_leap(y: u16) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn itoa(mut n: u32) -> Vec<u8> {
    if n == 0 { return b"0".to_vec(); }
    let mut buf: Vec<u8> = Vec::new();
    while n > 0 {
        buf.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    buf.reverse();
    buf
}

fn u64_to_decimal(mut n: u64) -> Vec<u8> {
    if n == 0 { return b"0".to_vec(); }
    let mut buf: Vec<u8> = Vec::new();
    while n > 0 {
        buf.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    buf.reverse();
    buf
}

fn u64_to_hex(n: u64) -> Vec<u8> {
    const HEX: &[u8] = b"0123456789ABCDEF";
    if n == 0 { return b"0".to_vec(); }
    let mut buf: Vec<u8> = Vec::new();
    let mut v = n;
    while v > 0 {
        buf.push(HEX[(v & 0xF) as usize]);
        v >>= 4;
    }
    buf.reverse();
    buf
}

/// Generate Windows Event Log Query XML
pub fn generate_query_xml(channel: &str, query: &str) -> Vec<u8> {
    let mut xml: Vec<u8> = Vec::new();
    xml.extend_from_slice(b"<?xml version=\"1.0\"?>\r\n<QueryList>\r\n  <Query Path=\"");
    xml.extend_from_slice(channel.as_bytes());
    xml.extend_from_slice(b"\">\r\n    <Select>");
    xml.extend_from_slice(query.as_bytes());
    xml.extend_from_slice(b"</Select>\r\n  </Query>\r\n</QueryList>\r\n");
    xml
}

/// Export events as CSV
pub fn records_to_csv(records: &[EventRecord], channel: EventChannel) -> Vec<u8> {
    let mut csv: Vec<u8> = Vec::new();
    csv.extend_from_slice(b"RecordID,TimeCreated,Source,EventID,Level,Channel,Computer,Description\r\n");
    for record in records {
        csv.extend_from_slice(u64_to_decimal(record.record_id).as_slice());
        csv.push(b',');
        csv.extend_from_slice(filetime_to_iso8601(record.timestamp).as_bytes());
        csv.push(b',');
        csv.extend_from_slice(&record.source[..record.source_len as usize]);
        csv.push(b',');
        csv.extend_from_slice(itoa(record.event_id as u32).as_slice());
        csv.push(b',');
        csv.extend_from_slice(record.level.as_str().as_bytes());
        csv.push(b',');
        csv.extend_from_slice(channel.name());
        csv.push(b',');
        csv.extend_from_slice(&record.computer[..record.computer_len as usize]);
        csv.push(b',');
        let desc = utf16le_to_string(&record.event_data[..record.event_data_len as usize]);
        for c in desc.chars() {
            if c == ',' || c == '"' { csv.push(b'"'); }
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            csv.extend_from_slice(s.as_bytes());
            if c == '"' { csv.push(b'"'); }
        }
        csv.extend_from_slice(b"\r\n");
    }
    csv
}
