//! Process environment access backed by the real `RTL_USER_PROCESS_PARAMETERS`.

use crate::userspace::peb_teb::current_peb;

fn lowercase(value: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&value) {
        value + (b'a' as u16 - b'A' as u16)
    } else {
        value
    }
}

fn parameters() -> Option<*mut crate::ps::process::RtlUserProcessParameters> {
    let peb = current_peb();
    if peb.is_null() {
        return None;
    }

    let parameters = unsafe { (*peb).process_parameters };
    if parameters.is_null() {
        return None;
    }

    Some(parameters)
}

fn environment_entries() -> Option<core::slice::Split<'static, u16, fn(&u16) -> bool>> {
    let parameters = parameters()?;
    let base = unsafe { (*parameters).environment } as *mut u16;
    if base.is_null() {
        return None;
    }

    let length = unsafe { (*parameters).environment_size } as usize / size_of::<u16>();
    let data = unsafe { core::slice::from_raw_parts(base, length) };
    Some(data.split(|value| *value == 0))
}

fn variable_length(name: &[u16]) -> Option<usize> {
    environment_entries()?.find_map(|entry| {
        let separator = entry.iter().position(|value| *value == b'=' as u16)?;
        let candidate = &entry[..separator];
        if candidate.len() == name.len()
            && candidate
                .iter()
                .zip(name)
                .all(|(left, right)| lowercase(*left) == lowercase(*right))
        {
            Some(entry.len() - separator - 1)
        } else {
            None
        }
    })
}

fn copy_variable(entry: &[u16], separator: usize, buffer: &mut [u16]) -> u32 {
    let value = &entry[separator + 1..];
    if buffer.len() < value.len() + 1 {
        return (value.len() + 1) as u32;
    }

    buffer[..value.len()].copy_from_slice(value);
    buffer[value.len()] = 0;
    0
}

pub fn get_environment_strings_w() -> *mut u16 {
    parameters()
        .map(|parameters| unsafe { (*parameters).environment } as *mut u16)
        .unwrap_or(core::ptr::null_mut())
}

pub fn get_environment_variable_w(name: &[u16], buffer: &mut [u16]) -> u32 {
    let Some(required_length) = variable_length(name) else {
        return 0;
    };

    if buffer.len() < required_length + 1 {
        return (required_length + 1) as u32;
    }

    environment_entries()
        .and_then(|entries| {
            entries.into_iter().find_map(|entry| {
                let separator = entry.iter().position(|value| *value == b'=' as u16)?;
                let candidate = &entry[..separator];
                if candidate.len() != name.len()
                    || !candidate
                        .iter()
                        .zip(name)
                        .all(|(left, right)| lowercase(*left) == lowercase(*right))
                {
                    return None;
                }

                Some(copy_variable(entry, separator, buffer))
            })
        })
        .unwrap_or(0)
}

pub fn set_environment_variable_w(name: &[u16], value: Option<&[u16]>) -> i32 {
    let Some(parameters) = parameters() else {
        return 0;
    };

    let base = unsafe { (*parameters).environment } as *mut u16;
    if base.is_null() {
        return 0;
    }

    let mut cursor = base;
    loop {
        let start = cursor;
        let entry_length = {
            let mut length = 0usize;
            while unsafe { *cursor.add(length) } != 0 {
                length += 1;
                if length >= u16::MAX as usize {
                    return 0;
                }
            }
            length
        };

        if entry_length == 0 {
            break;
        }

        let entry = unsafe { core::slice::from_raw_parts(start, entry_length) };
        if let Some(separator) = entry.iter().position(|item| *item == b'=' as u16) {
            let variable = &entry[..separator];
            if variable.len() == name.len()
                && variable
                    .iter()
                    .zip(name)
                    .all(|(left, right)| lowercase(*left) == lowercase(*right))
            {
                let Some(value) = value else {
                    let remaining = unsafe { (*parameters).environment_size } as usize / 2;
                    let entry_bytes = entry_length + 1;
                    unsafe {
                        core::ptr::copy(
                            start.add(entry_bytes),
                            start,
                            remaining.saturating_sub(entry_bytes),
                        );
                    }
                    unsafe {
                        (*parameters).environment_size = ((remaining - entry_bytes) * 2) as u32;
                    }
                    return 1;
                };

                if value.len() < entry_length - separator {
                    let old_length = entry_length - separator - 1;
                    unsafe {
                        for (offset, item) in value.iter().enumerate() {
                            start.add(separator + 1 + offset).write(*item);
                        }
                        for offset in value.len()..old_length {
                            start.add(separator + 1 + offset).write(0);
                        }
                        for offset in (value.len()..old_length).rev() {
                            let source = start.add(separator + 2 + offset);
                            let target = start.add(separator + 1 + offset);
                            target.write(source.read());
                        }
                        start.add(entry_length).write(0);
                    }
                    return 1;
                }

                return 0;
            }
        }

        unsafe { cursor = cursor.add(entry_length + 1) };
    }

    0
}

pub fn get_current_directory_w(buffer: &mut [u16]) -> u32 {
    let Some(parameters) = parameters() else {
        return 0;
    };

    let path = unsafe { &(*parameters).current_directory.dos_path };
    let length = (path.length as usize) / 2;
    let required_length = length + 1;
    if buffer.len() < required_length {
        return required_length as u32;
    }

    let source = path.buffer;
    if source.is_null() {
        return 0;
    }

    buffer[..length].copy_from_slice(unsafe { core::slice::from_raw_parts(source, length) });
    buffer[length] = 0;
    required_length as u32
}

pub fn set_current_directory_w(directory: &[u16]) -> i32 {
    let Some(parameters) = parameters() else {
        return 0;
    };

    let target = unsafe { &mut (*parameters).current_directory.dos_path };
    let maximum_length = (target.maximum_length as usize) / 2;
    if directory.len() + 1 > maximum_length {
        return 0;
    }

    let buffer = target.buffer;
    if buffer.is_null() {
        return 0;
    }

    unsafe {
        for (offset, value) in directory.iter().enumerate() {
            buffer.add(offset).write(*value);
        }
        buffer.add(directory.len()).write(0);
    }
    target.length = (directory.len() * 2) as u16;
    1
}
