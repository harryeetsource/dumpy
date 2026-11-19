//! Symbol-independent first-pass process-list traversal. Process field values
//! remain candidates until a matched Windows layout/PDB validates them.
use crate::discovery::RootCandidate;
use crate::memory::PhysicalMemory;
use std::collections::HashSet;
use std::collections::HashMap;
use std::io;

#[derive(Debug)]
pub struct ProcessCandidate {
    pub links: u64,
    pub pid_hint: Option<u64>,
    pub dtb_candidates: Vec<u64>,
    pub dtb_field_offsets: Vec<i64>,
    pub image_name_hint: Option<String>,
    pub image_name_offset: Option<usize>,
}

#[derive(Debug)]
pub struct ProcessReport {
    pub processes: Vec<ProcessCandidate>,
    pub complete: bool,
    pub warning: Option<String>,
}

fn read_qword(mem: &mut PhysicalMemory<'_>, dtb: u64, va: u64) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    mem.read_virtual(dtb, va, &mut bytes, 4)?;
    Ok(u64::from_le_bytes(bytes))
}

fn links(mem: &mut PhysicalMemory<'_>, dtb: u64, va: u64) -> io::Result<(u64, u64)> {
    let mut bytes = [0u8; 16];
    mem.read_virtual(dtb, va, &mut bytes, 4)?;
    Ok((u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..].try_into().unwrap())))
}

fn plausible_name(bytes: &[u8]) -> Option<(String, usize)> {
    // An IMAGE_FILE_NAME field is at most 15 bytes plus the terminating NUL.
    let mut names = Vec::new();
    for (index, window) in bytes.windows(16).enumerate() {
        let Some(end) = window.iter().position(|x| *x == 0) else { continue };
        if !(4..=15).contains(&end) { continue; }
        let text = &window[..end];
        if !text.iter().all(|x| x.is_ascii_alphanumeric() || matches!(*x, b'.' | b'_' | b'-')) {
            continue;
        }
        let value = String::from_utf8_lossy(text).into_owned();
        if value.to_ascii_lowercase().ends_with(".exe") || matches!(value.as_str(), "System" | "Registry") {
            if !names.iter().any(|item: &(String, usize)| item.0 == value) {
                names.push((value, index));
            }
        }
    }
    if names.len() == 1 { names.into_iter().next() } else { None }
}

fn name_at_offset(mem: &mut PhysicalMemory<'_>, dtb: u64, links: u64,
                  offset: usize) -> Option<String> {
    let va = links.checked_add(offset as u64)?;
    let mut field = [0u8; 16];
    mem.read_virtual(dtb, va, &mut field, 4).ok()?;
    let count = field.iter().position(|v| *v == 0).unwrap_or(15).min(15);
    if count < 3 { return None; }
    let text = &field[..count];
    if !text.iter().all(|b| b.is_ascii_alphanumeric() || matches!(*b, b' ' | b'.' | b'_' | b'-')) {
        return None;
    }
    Some(String::from_utf8_lossy(text).into_owned())
}

pub fn enumerate(mem: &mut PhysicalMemory<'_>, kernel_dtb: u64, head: u64,
                 roots: &[RootCandidate], limit: usize) -> io::Result<ProcessReport> {
    let (first, tail) = links(mem, kernel_dtb, head)?;
    let allowed: HashSet<u64> = roots.iter().map(|r| r.physical).collect();
    let mut seen = HashSet::new();
    let mut current = first;
    let mut previous = head;
    let mut processes = Vec::new();
    let mut warning = None;
    while current != head {
        if current == 0 || !seen.insert(current) || seen.len() > limit {
            warning = Some(format!("process list cycle/null/limit at 0x{current:x}"));
            break;
        }
        let (next, back) = match links(mem, kernel_dtb, current) {
            Ok(v) => v,
            Err(e) => { warning = Some(format!("unreadable process links at 0x{current:x}: {e}")); break; }
        };
        if back != previous {
            warning = Some(format!("process backlink mismatch at 0x{current:x}: actual=0x{back:x} expected=0x{previous:x}"));
            break;
        }
        // Windows typically stores UniqueProcessId immediately before
        // ActiveProcessLinks. This is a hint until a matched symbol layout
        // confirms the EPROCESS offsets.
        let pid_hint = current.checked_sub(8).and_then(|va| read_qword(mem, kernel_dtb, va).ok())
            .filter(|pid| *pid <= u32::MAX as u64);
        let mut dtb_candidates = Vec::new();
        let mut dtb_field_offsets = Vec::new();
        let mut image_name_hint = None;
        let mut image_name_offset = None;
        if let Some(scan_start) = current.checked_sub(0x600) {
            let mut region = vec![0u8; 0x600];
            if mem.read_virtual(kernel_dtb, scan_start, &mut region, 4).is_ok() {
                for (index, block) in region.chunks_exact(8).enumerate() {
                    let candidate = u64::from_le_bytes(block.try_into().unwrap()) & 0x000f_ffff_ffff_f000;
                    if candidate == 0 || !allowed.contains(&candidate) || dtb_candidates.contains(&candidate) {
                        continue;
                    }
                    // Confirm the candidate process DTB can map the known
                    // kernel process-list head to the same forward pointer.
                    if let Ok((forward, _)) = links(mem, candidate, head) {
                        if forward == first {
                            dtb_candidates.push(candidate);
                            dtb_field_offsets.push(index as i64 * 8 - 0x600);
                        }
                    }
                }
            }
        }
        // ImageFileName frequently lies *after* ActiveProcessLinks, not before.
        let mut following = vec![0u8; 0x500];
        if mem.read_virtual(kernel_dtb, current, &mut following, 4).is_ok() {
            if let Some((name, offset)) = plausible_name(&following) {
                image_name_hint = Some(name);
                image_name_offset = Some(offset);
            }
        }
        processes.push(ProcessCandidate { links: current, pid_hint, dtb_candidates,
            dtb_field_offsets, image_name_hint, image_name_offset });
        previous = current;
        current = next;
    }
    // A name found inside a larger string is not necessarily the beginning
    // of IMAGE_FILE_NAME. Use agreement across objects to infer its offset,
    // then re-read the *whole* fixed-size field at that offset.
    let mut offsets = HashMap::<usize, usize>::new();
    for process in &processes {
        if let Some(offset) = process.image_name_offset {
            *offsets.entry(offset).or_default() += 1;
        }
    }
    let consensus = offsets.into_iter().max_by_key(|(offset, count)| (*count, usize::MAX - *offset))
        .and_then(|(offset, count)| if count >= 2 { Some(offset) } else { None });
    if let Some(offset) = consensus {
        for process in &mut processes {
            process.image_name_hint = name_at_offset(mem, kernel_dtb, process.links, offset);
            process.image_name_offset = process.image_name_hint.as_ref().map(|_| offset);
        }
    }
    let complete = warning.is_none() && current == head && previous == tail;
    if !complete && warning.is_none() {
        warning = Some(format!("process list tail mismatch: final=0x{previous:x} tail=0x{tail:x}"));
    }
    Ok(ProcessReport { processes, complete, warning })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_process_names() {
        assert!(plausible_name(&[0u8; 16]).is_none());
    }
    #[test]
    fn extracts_name_and_relative_offset() {
        let mut data = [0u8; 96];
        data[32..46].copy_from_slice(b"exampleapp.exe");
        assert_eq!(plausible_name(&data), Some(("exampleapp.exe".into(), 32)));
    }
}
