//! Bounded discovery of Windows kernel modules from PsLoadedModuleList.
//! Entry layout is probed and validated against in-memory PE signatures.
use crate::memory::PhysicalMemory;
use std::collections::HashSet;
use std::io::{self, ErrorKind};

#[derive(Debug)]
pub struct KernelModule {
    pub entry: u64,
    pub image_base: u64,
    pub image_size: u32,
    pub name: Option<String>,
    pub name_status: &'static str,
}

#[derive(Debug)]
pub struct ModuleScanReport {
    pub modules: Vec<KernelModule>,
    pub complete: bool,
    pub traversed: usize,
    pub warning: Option<String>,
}

fn invalid(message: &'static str) -> io::Error { io::Error::new(ErrorKind::InvalidData, message) }
fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

fn list_links(memory: &mut PhysicalMemory<'_>, dtb: u64, va: u64) -> io::Result<(u64, u64)> {
    let mut b = [0u8; 16];
    memory.read_virtual(dtb, va, &mut b, 4)?;
    Ok((u64_at(&b, 0).unwrap(), u64_at(&b, 8).unwrap()))
}

fn valid_mapped_pe(memory: &mut PhysicalMemory<'_>, dtb: u64, base: u64) -> bool {
    if base == 0 || base & 0xfff != 0 { return false; }
    let mut b = [0u8; 4096];
    if memory.read_virtual(dtb, base, &mut b, 4).is_err() { return false; }
    if b.get(..2) != Some(b"MZ") { return false; }
    let Some(nt) = u32_at(&b, 0x3c).map(|x| x as usize) else { return false };
    if nt < 0x40 || nt > 0x800 { return false; }
    if b.get(nt..nt + 4) != Some(b"PE\0\0") { return false; }
    matches!(u16_at(&b, nt + 24), Some(0x10b | 0x20b))
}

fn read_unicode_name(memory: &mut PhysicalMemory<'_>, dtb: u64, b: &[u8], at: usize) -> Option<String> {
    let length = u16_at(b, at)? as usize;
    let maximum = u16_at(b, at + 2)? as usize;
    let pointer = u64_at(b, at + 8)?;
    if length == 0 || length > 1024 || length % 2 != 0 || length > maximum || pointer == 0 {
        return None;
    }
    let mut text = vec![0; length];
    memory.read_virtual(dtb, pointer, &mut text, 4).ok()?;
    let words: Vec<u16> = text.chunks_exact(2).map(|x| u16::from_le_bytes([x[0], x[1]])).collect();
    let name = String::from_utf16(&words).ok()?;
    if name.chars().all(|c| !c.is_control()) { Some(name) } else { None }
}

fn parse_entry(memory: &mut PhysicalMemory<'_>, dtb: u64, entry: u64) -> io::Result<KernelModule> {
    let mut bytes = [0u8; 0x100];
    memory.read_virtual(dtb, entry, &mut bytes, 4)?;
    // Candidate offsets cover common x64 KLDR_DATA_TABLE_ENTRY variants.
    // Select only a layout whose DllBase maps to a valid PE header.
    for (base_offset, size_offset, name_offset) in [(0x30, 0x40, 0x58), (0x30, 0x40, 0x48),
        (0x18, 0x28, 0x48)] {
        let Some(base) = u64_at(&bytes, base_offset) else { continue };
        let Some(size) = u32_at(&bytes, size_offset) else { continue };
        if size == 0 || size > 600 * 1024 * 1024 || !valid_mapped_pe(memory, dtb, base) { continue; }
        let name = read_unicode_name(memory, dtb, &bytes, name_offset);
        return Ok(KernelModule { entry, image_base: base, image_size: size,
            name_status: if name.is_some() { "read" } else { "unavailable" }, name });
    }
    Err(invalid("module entry has no validated image base"))
}

pub fn enumerate(memory: &mut PhysicalMemory<'_>, dtb: u64, head: u64,
                 maximum: usize) -> io::Result<ModuleScanReport> {
    let (first, tail) = list_links(memory, dtb, head)?;
    println!("[module-list] head=0x{head:016x} flink=0x{first:016x} blink=0x{tail:016x} dtb=0x{dtb:016x}");
    let mut current = first;
    let mut previous = head;
    let mut visited = HashSet::new();
    let mut modules = Vec::new();
    let mut warning = None;
    while current != head {
        if current == 0 || !visited.insert(current) || visited.len() > maximum {
            warning = Some(format!("kernel module list cycle, null pointer or entry limit at 0x{current:x}"));
            break;
        }
        let (next, back) = match list_links(memory, dtb, current) {
            Ok(links) => links,
            Err(e) => {
                warning = Some(format!("unreadable module links at 0x{current:x}: {e}"));
                break;
            }
        };
        if back != previous {
            warning = Some(format!(
                "kernel module list backlink mismatch at node=0x{current:016x}: next=0x{next:016x}, \
                 actual_blink=0x{back:016x}, expected_blink=0x{previous:016x}; \
                 head=0x{head:016x}, tail=0x{tail:016x}, traversed={} modules={}",
                visited.len(), modules.len()
            ));
            break;
        }
        match parse_entry(memory, dtb, current) {
            Ok(module) => modules.push(module),
            Err(e) => eprintln!("[module] 0x{current:x}: {e}"),
        }
        previous = current;
        current = next;
    }
    let complete = warning.is_none() && current == head && previous == tail;
    if !complete && warning.is_none() {
        warning = Some(format!("kernel module list tail mismatch: reached=0x{previous:x} expected=0x{tail:x}"));
    }
    Ok(ModuleScanReport { modules, complete, traversed: visited.len(), warning })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_little_endian_list_fields() {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&0xffff_f806_ccef_54c0u64.to_le_bytes());
        b[8..].copy_from_slice(&0xffff_e60e_f82e_5620u64.to_le_bytes());
        assert_eq!(u64_at(&b, 0), Some(0xffff_f806_ccef_54c0));
        assert_eq!(u64_at(&b, 8), Some(0xffff_e60e_f82e_5620));
        assert_eq!(u64_at(&b, 10), None);
    }
}
