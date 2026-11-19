//! Conservative, symbol-free *candidate* detection for AMD64 PML4 roots.
//! A self-referential PML4 entry is one useful signal, not proof that a page
//! belongs to a particular process. Windows versions/configurations may lack it.
use std::io;
use crate::memory::PhysicalMemory;

const PAGE_SIZE: usize = 4096;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const BUFFER_PAGES: usize = 1024;

#[derive(Debug, Clone)]
pub struct RootCandidate {
    pub physical: u64,
    pub self_index: usize,
    pub present_entries: usize,
    pub kernel_entries: usize,
    pub user_entries: usize,
    pub valid_children: usize,
}

fn entry(page: &[u8], index: usize) -> u64 {
    let pos = index * 8;
    u64::from_le_bytes(page[pos..pos + 8].try_into().expect("fixed 8-byte entry"))
}

/// Validates a physical page as a *plausible* PML4, without attributing it to a process.
fn candidate_at(page: &[u8], physical: u64, dump_size: u64) -> Option<RootCandidate> {
    if page.len() != PAGE_SIZE { return None; }
    let mut present = 0;
    let mut kernel = 0;
    let mut user = 0;
    let mut children = 0;
    let mut self_index = None;
    for index in 0..512 {
        let value = entry(page, index);
        if value & 1 == 0 { continue; }
        // A PML4 entry cannot use the huge-page (PS) bit.
        if value & (1 << 7) != 0 { return None; }
        let child = value & ADDRESS_MASK;
        if child >= dump_size || child & 0xfff != 0 { return None; }
        present += 1;
        if index >= 256 { kernel += 1; } else { user += 1; }
        if child == physical { self_index = Some(index); }
        if child != 0 { children += 1; }
    }
    let self_index = self_index?;
    if present < 3 || kernel < 2 || children < 3 { return None; }
    Some(RootCandidate {
        physical, self_index, present_entries: present,
        kernel_entries: kernel, user_entries: user, valid_children: children,
    })
}

/// Scan a verified, flat physical image using bounded memory and no process-specific offsets.
/// Results are hints for later kernel validation, NEVER automatically trusted process DTBs.
pub fn discover_candidate_roots(physical_memory: &mut PhysicalMemory<'_>, max_results: usize) -> io::Result<Vec<RootCandidate>> {
    let ranges = physical_memory.segments().to_vec();
    let size = ranges.iter().filter_map(|s| s.physical.checked_add(s.length)).max().unwrap_or(0);
    let mut buffer = vec![0u8; PAGE_SIZE * BUFFER_PAGES];
    let mut results = Vec::new();
    for range in ranges {
        let mut physical = range.physical;
        let end = range.physical.saturating_add(range.length);
        while physical + PAGE_SIZE as u64 <= end {
            let available = ((end - physical) as usize).min(buffer.len());
            let aligned = available / PAGE_SIZE * PAGE_SIZE;
            if aligned == 0 { break; }
            physical_memory.read_exact_at(physical, &mut buffer[..aligned])?;
            for index in 0..(aligned / PAGE_SIZE) {
                let address = physical + (index * PAGE_SIZE) as u64;
                if let Some(root) = candidate_at(&buffer[index * PAGE_SIZE..(index + 1) * PAGE_SIZE], address, size) {
                    results.push(root);
                    if results.len() >= max_results { return Ok(results); }
                }
            }
            physical += aligned as u64;
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_structurally_plausible_self_reference() {
        let mut p = [0u8; PAGE_SIZE];
        for (i, addr) in [(0usize, 0x2000u64), (256, 0x3000), (300, 0x4000), (510, 0x1000)] {
            p[i * 8..i * 8 + 8].copy_from_slice(&(addr | 3).to_le_bytes());
        }
        let found = candidate_at(&p, 0x1000, 0x10000).unwrap();
        assert_eq!(found.self_index, 510);
        assert_eq!(found.kernel_entries, 3);
    }
    #[test]
    fn rejects_page_without_self_reference() {
        let p = [0u8; PAGE_SIZE];
        assert!(candidate_at(&p, 0x1000, 0x10000).is_none());
    }
}
