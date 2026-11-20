//! Bounded, symbol-independent PE discovery within a process's AMD64 user mappings.
//! Discovery is based on present USER page-table entries, not physical-file offsets.
use crate::memory::{self, EntryKind, PhysicalMemory};
use crate::peb::{self, KnownModules, PebProcess};
use std::collections::HashMap;
use crate::rebuild::MAX_IMAGE;
use std::collections::HashSet;
use std::io;

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const MAX_TABLES: usize = 200_000;
const DEFAULT_MAPPED_PAGES: usize = 500_000;
const NX: u64 = 1 << 63;

#[derive(Debug)]
pub struct UserImage {
    pub base: u64,
    pub size: u32,
}

/// A run of contiguous user pages whose PTEs have NX clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableRegion {
    pub start: u64,
    pub length: u64,
}

#[derive(Debug)]
pub struct ScanResult {
    pub images: Vec<UserImage>,
    pub processes: Vec<PebProcess>,
    pub peb_candidates: usize,
    pub peb_rejected: usize,
    /// Why candidates were rejected, by first failing check.
    pub peb_reject_reasons: HashMap<&'static str, usize>,
    /// Rejected candidate PEB addresses with their reason, for a later retry
    /// once more module identities are known.
    pub rejected_pebs: Vec<(u64, &'static str)>,
    /// Pages whose PTE is writable, NX and 4 KiB: the only pages that can
    /// hold a PEB or TEB, and the only ones read in full for that purpose.
    pub private_rw_pages: usize,
    /// TEBs recognised by the Self pointer at +0x30; each yields a PEB
    /// pointer at +0x60 without having to land on the PEB page itself.
    pub teb_hits: usize,
    pub mapped_pages_examined: usize,
    pub readable_pages: usize,
    pub unavailable_pages: usize,
    /// Pages reached only through a Windows transition PTE.
    pub transition_pages: usize,
    pub mz_signatures: usize,
    pub rejected_pe_headers: usize,
    pub unaligned_images: usize,
    pub tables_examined: usize,
    pub unavailable_tables: usize,
    pub unavailable_headers: usize,
    /// Every executable (NX clear) user page seen, coalesced into runs.
    /// Includes pages that belong to discovered images; see
    /// `orphan_executable_regions` to subtract known mappings.
    pub executable_regions: Vec<ExecutableRegion>,
    pub executable_pages: usize,
    /// `(va, bytes)` of every 2 MiB / 1 GiB user mapping encountered.
    pub huge_mappings: Vec<(u64, u64)>,
    pub truncated: bool,
}

/// Executable bytes of `regions` that fall inside `[base, base+size)`.
pub fn executable_bytes_in(regions: &[ExecutableRegion], base: u64, size: u64) -> u64 {
    let end = base.saturating_add(size);
    regions.iter().map(|r| {
        let lo = r.start.max(base);
        let hi = (r.start + r.length).min(end);
        hi.saturating_sub(lo)
    }).sum()
}

/// Coalesce sorted page addresses into contiguous runs.
pub fn coalesce_pages(mut pages: Vec<u64>) -> Vec<ExecutableRegion> {
    pages.sort_unstable();
    pages.dedup();
    let mut regions = Vec::<ExecutableRegion>::new();
    for page in pages {
        match regions.last_mut() {
            Some(last) if last.start + last.length == page => last.length += 4096,
            _ => regions.push(ExecutableRegion { start: page, length: 4096 }),
        }
    }
    regions
}

/// Join runs separated by at most `gap` bytes. A single allocation often
/// shows as several runs because a guard or data page sits between its
/// executable pages; the merged span is what a reviewer wants to look at.
/// The gap pages themselves are included in `length`.
pub fn merge_gaps(regions: &[ExecutableRegion], gap: u64) -> Vec<ExecutableRegion> {
    let mut out = Vec::<ExecutableRegion>::new();
    for region in regions {
        match out.last_mut() {
            Some(last) if region.start.saturating_sub(last.start + last.length) <= gap =>
                last.length = region.start + region.length - last.start,
            _ => out.push(region.clone()),
        }
    }
    out
}

/// Subtract known image mappings `(base, size)` from executable runs. What
/// remains is executable memory with no PE header and no loader record:
/// JIT regions, trampolines, or a reflectively loaded image whose headers
/// were wiped. These are review candidates, not claimed images.
pub fn orphan_executable_regions(regions: &[ExecutableRegion],
                                 covered: &[(u64, u64)]) -> Vec<ExecutableRegion> {
    let mut covered = covered.iter()
        .filter(|(_, size)| *size != 0)
        .map(|(base, size)| (*base & !0xfff, base.saturating_add(*size).saturating_add(0xfff) & !0xfff))
        .collect::<Vec<_>>();
    covered.sort_unstable();
    let mut out = Vec::new();
    for region in regions {
        let mut cursor = region.start;
        let end = region.start.saturating_add(region.length);
        for (cover_start, cover_end) in &covered {
            if *cover_end <= cursor { continue; }
            if *cover_start >= end { break; }
            if *cover_start > cursor {
                out.push(ExecutableRegion { start: cursor, length: cover_start - cursor });
            }
            cursor = cursor.max(*cover_end);
            if cursor >= end { break; }
        }
        if cursor < end {
            out.push(ExecutableRegion { start: cursor, length: end - cursor });
        }
    }
    out
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}
fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?))
}

fn pe_size(header: &[u8]) -> Option<u32> {
    if header.get(..2)? != b"MZ" { return None; }
    let nt = u32_at(header, 0x3c)? as usize;
    if !(0x40..=0x800).contains(&nt) || header.get(nt..nt.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let count = u16_at(header, nt + 6)?;
    let optional_size = u16_at(header, nt + 20)? as usize;
    let optional = nt.checked_add(24)?;
    let magic = u16_at(header, optional)?;
    if !matches!(magic, 0x10b | 0x20b) || count == 0 || count > 96 { return None; }
    let min_optional = if magic == 0x20b { 112 } else { 96 };
    if optional_size < min_optional { return None; }
    let table_end = optional.checked_add(optional_size)?.checked_add(count as usize * 40)?;
    let size = u32_at(header, optional + 56)?;
    let header_size = u32_at(header, optional + 60)? as usize;
    if size == 0 || size as usize > MAX_IMAGE || header_size < table_end ||
        header_size > size as usize || table_end > header.len() { return None; }
    Some(size)
}

fn try_peb(mem: &mut PhysicalMemory<'_>, dtb: u64, peb_va: u64, looks64: bool,
           looks32: bool, report: &mut ScanResult, tried: &mut HashSet<u64>,
           known: &KnownModules) {
    if !tried.insert(peb_va) { return; }
    if report.processes.iter().any(|existing| existing.peb == peb_va) { return; }
    report.peb_candidates += 1;
    let attempt = if looks64 { peb::inspect(mem, dtb, peb_va, known) } else { Err("not-peb64") };
    let attempt = match attempt {
        Ok(p) => Ok(p),
        Err(e64) if looks32 => peb::inspect32(mem, dtb, peb_va, known).map_err(|_| e64),
        Err(e) => Err(e),
    };
    match attempt {
        Ok(process) => report.processes.push(process),
        Err(reason) => {
            report.peb_rejected += 1;
            *report.peb_reject_reasons.entry(reason).or_default() += 1;
            if report.rejected_pebs.len() < 1024 { report.rejected_pebs.push((peb_va, reason)); }
        }
    }
}

fn inspect_base(mem: &mut PhysicalMemory<'_>, dtb: u64, base: u64,
                physical: u64, kind: EntryKind, private_rw: bool,
                report: &mut ScanResult, find_processes: bool,
                tried: &mut HashSet<u64>, known: &KnownModules) {
    // The PEB and TEB are private, writable, non-executable 4 KiB pages.
    // Only such pages are read in full; image pages (RX/RO, often huge)
    // only have their first two bytes checked for MZ. This is what lets a
    // bounded scan reach the PEB in a process with a 350 MiB DLL mapped.
    let peb_page = find_processes && private_rw && report.processes.len() < 64 &&
        report.peb_candidates < 4096;
    let mut page = [0u8; 4096];
    let bytes = if peb_page { &mut page[..] } else { &mut page[..2] };
    if mem.read_exact_at(physical, bytes).is_err() {
        report.unavailable_pages += 1;
        return;
    }
    report.readable_pages += 1;
    if kind == EntryKind::Transition { report.transition_pages += 1; }
    if peb_page {
        report.private_rw_pages += 1;
        // TEB: NT_TIB.Self at +0x30 points at the TEB itself; the PEB
        // pointer is at +0x60. TEBs are page-aligned, so a self-pointer
        // equal to this page's VA is a near-unambiguous signature.
        if u64_at(&page, 0x30) == Some(base) {
            if let Some(peb_va) = u64_at(&page, 0x60) {
                if peb::user_pointer(peb_va) {
                    report.teb_hits += 1;
                    let mut prefix = [0u8; 0x40];
                    if mem.read_virtual(dtb, peb_va, &mut prefix, 4).is_ok() {
                        try_peb(mem, dtb, peb_va, peb::maybe_peb_prefix(&prefix),
                            peb::maybe_peb_prefix32(&prefix), report, tried, known);
                    }
                }
            }
        }
        // A PEB is not guaranteed to start at the beginning of its page.
        for offset in (0..=page.len() - 64).step_by(8) {
            if report.processes.len() >= 64 || report.peb_candidates >= 4096 { break; }
            let prefix = &page[offset..offset + 64];
            let looks64 = peb::maybe_peb_prefix(prefix);
            let looks32 = peb::maybe_peb_prefix32(prefix);
            if !looks64 && !looks32 { continue; }
            let Some(peb_va) = base.checked_add(offset as u64) else { continue };
            try_peb(mem, dtb, peb_va, looks64, looks32, report, tried, known);
        }
    }
    if page[..2] != *b"MZ" { return; }
    report.mz_signatures += 1;
    let mut header = [0u8; 4096];
    if mem.read_virtual(dtb, base, &mut header, 4).is_err() {
        report.unavailable_headers += 1;
        return;
    }
    if let Some(size) = pe_size(&header) {
        if base & 0xffff != 0 { report.unaligned_images += 1; }
        report.images.push(UserImage { base, size });
    } else {
        report.rejected_pe_headers += 1;
    }
}

/// Walk only present user entries in a four-level x64 page tree.
/// Every present logical 4 KiB user page is checked for MZ, including non-64-KiB
/// aligned addresses and subpages of huge mappings. Absent physical pages are
/// counted distinctly from present page-table entries.
pub fn scan_limited(mem: &mut PhysicalMemory<'_>, dtb: u64,
                    maximum_pages: Option<usize>, max_images: usize) -> io::Result<ScanResult> {
    scan_limited_inner(mem, dtb, maximum_pages, max_images, false, &KnownModules::new())
}

/// Scan a DTB for both ordinary PE-header candidates and PEB loader records.
/// Loader-listed modules are process-associated only after PEB and list
/// integrity, module headers and primary ImageBaseAddress are all validated.
pub fn scan_process_aware(mem: &mut PhysicalMemory<'_>, dtb: u64,
                          maximum_pages: Option<usize>, known: &KnownModules) -> io::Result<ScanResult> {
    scan_limited_inner(mem, dtb, maximum_pages, 4096, true, known)
}

fn scan_limited_inner(mem: &mut PhysicalMemory<'_>, dtb: u64,
                      maximum_pages: Option<usize>, max_images: usize,
                      find_processes: bool, known: &KnownModules) -> io::Result<ScanResult> {
    let root = dtb & ADDRESS_MASK;
    if root == 0 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "null process DTB")); }
    let limit = maximum_pages.unwrap_or(DEFAULT_MAPPED_PAGES).max(1);
    let max_images = max_images.clamp(1, 4096);
    let mut result = ScanResult { images: Vec::new(), processes: Vec::new(),
        peb_candidates: 0, peb_rejected: 0, peb_reject_reasons: HashMap::new(),
        rejected_pebs: Vec::new(), private_rw_pages: 0, teb_hits: 0,
        mapped_pages_examined: 0,
        readable_pages: 0, unavailable_pages: 0, transition_pages: 0, mz_signatures: 0,
        rejected_pe_headers: 0, unaligned_images: 0,
        tables_examined: 0, unavailable_tables: 0, unavailable_headers: 0,
        executable_regions: Vec::new(), executable_pages: 0, huge_mappings: Vec::new(),
        truncated: false };
    let allow_transition = mem.allow_transition;
    let mut executable_pages = Vec::<u64>::new();
    let mut tried_pebs = HashSet::new();
    // (physical page-table address, level, virtual prefix).
    let mut stack = vec![(root, 4u8, 0u64)];
    let mut visited = HashSet::new();
    while let Some((table, level, prefix)) = stack.pop() {
        if result.tables_examined >= MAX_TABLES || result.mapped_pages_examined >= limit ||
            result.images.len() >= max_images {
            result.truncated = true;
            break;
        }
        // A shared table may be mapped more than once. The virtual prefix is significant.
        if !visited.insert((table, level, prefix)) { continue; }
        let mut bytes = [0u8; 4096];
        if mem.read_exact_at(table, &mut bytes).is_err() {
            result.unavailable_tables += 1;
            continue;
        }
        result.tables_examined += 1;
        let entries = if level == 4 { 256 } else { 512 };
        for position in 0..entries {
            // PEB and loader mappings are commonly near the top of user VA;
            // reverse traversal priority for the process-aware scan. Stack
            // insertion order is reversed by the LIFO walker.
            let index = if find_processes { position } else { entries - 1 - position };
            let offset = index * 8;
            let entry = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            // Present (or Windows transition) and user accessible; the Owner
            // bit must be set on each level. Transition PTEs keep bit 2.
            let Some(kind) = memory::classify_entry(entry, allow_transition) else { continue };
            if entry & 4 == 0 { continue; }
            let shift = 12 + 9 * (level as u64 - 1);
            let va = prefix | ((index as u64) << shift);
            if level == 1 || (level == 2 || level == 3) && (entry & (1 << 7) != 0) {
                let pages = if level == 1 { 1u64 } else { 1u64 << (shift - 12) };
                let page_mask = (pages << 12) - 1;
                let phys = (entry & ADDRESS_MASK) & !page_mask;
                let executable = entry & NX == 0;
                if level != 1 && result.huge_mappings.len() < 65536 {
                    result.huge_mappings.push((va, pages << 12));
                }
                // Writable, NX, 4 KiB: the only shape a PEB/TEB page has.
                let private_rw = level == 1 && entry & 2 != 0 && !executable;
                for page in 0..pages {
                    if result.mapped_pages_examined >= limit || result.images.len() >= max_images {
                        result.truncated = true;
                        break;
                    }
                    result.mapped_pages_examined += 1;
                    if executable {
                        result.executable_pages += 1;
                        if executable_pages.len() < limit { executable_pages.push(va + page * 4096); }
                    }
                    inspect_base(mem, dtb, va + page * 4096, phys + page * 4096, kind,
                        private_rw, &mut result, find_processes, &mut tried_pebs, known);
                }
                if result.truncated { break; }
            } else if level > 1 {
                // Reverse insertion preserves ascending virtual addresses when popped.
                stack.push((entry & ADDRESS_MASK, level - 1, va));
            }
        }
        if result.truncated { break; }
    }
    if !stack.is_empty() { result.truncated = true; }
    result.images.sort_by_key(|image| image.base);
    result.images.dedup_by_key(|image| image.base);
    result.executable_regions = coalesce_pages(executable_pages);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    #[test]
    fn rejects_fake_mz_and_bogus_lengths() {
        let mut b = [0u8; 4096];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(pe_size(&b), None);
    }

    #[test]
    fn coalesces_pages_and_subtracts_known_images() {
        let regions = coalesce_pages(vec![0x3000, 0x1000, 0x2000, 0x9000, 0x2000]);
        assert_eq!(regions, vec![
            ExecutableRegion { start: 0x1000, length: 0x3000 },
            ExecutableRegion { start: 0x9000, length: 0x1000 }]);
        // Image covers 0x2000..0x3000 (size rounds up to a page); the run
        // splits into the pages before and after it.
        let orphans = orphan_executable_regions(&regions, &[(0x2000, 0x800)]);
        assert_eq!(orphans, vec![
            ExecutableRegion { start: 0x1000, length: 0x1000 },
            ExecutableRegion { start: 0x3000, length: 0x1000 },
            ExecutableRegion { start: 0x9000, length: 0x1000 }]);
        // A covering image that spans the whole run removes it entirely.
        assert!(orphan_executable_regions(&regions[1..], &[(0x8000, 0x3000)]).is_empty());
        assert_eq!(executable_bytes_in(&regions, 0x2000, 0x800), 0x800);
        assert_eq!(executable_bytes_in(&regions, 0x0, 0x20000), 0x4000);
        assert_eq!(executable_bytes_in(&regions, 0x5000, 0x1000), 0);
        // Gap merge: 0x1000..0x4000 and 0x9000 are 0x5000 apart.
        assert_eq!(merge_gaps(&regions, 0x4000).len(), 2);
        assert_eq!(merge_gaps(&regions, 0x5000),
            vec![ExecutableRegion { start: 0x1000, length: 0x9000 }]);
    }

    #[test]
    fn finds_non_64k_aligned_pe_and_counts_missing_physical_pages() {
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("dumpy_user_scan_{}_{}",
            std::process::id(), unique));
        let mut file = OpenOptions::new().create_new(true).read(true).write(true)
            .open(&path).expect("create synthetic memory file");
        file.set_len(0x6000).unwrap();
        // PML4 -> PDPT -> PD -> PT. Map VA 0x11000 to PA 0x5000;
        // VA 0x12000 is present in the page tables but absent from the capture.
        for (address, value) in [(0x1000, 0x2007u64), (0x2000, 0x3007),
            (0x3000, 0x4007), (0x4000 + 0x11 * 8, 0x5007),
            (0x4000 + 0x12 * 8, 0x6007),
            // VA 0x13000: Windows transition PTE (Valid=0, Transition=1,
            // Owner=1) to the same header page; NX set so it is not an
            // executable page.
            (0x4000 + 0x13 * 8, 0x5000 | (1 << 11) | 4 | (1 << 63))] {
            file.seek(SeekFrom::Start(address)).unwrap();
            file.write_all(&value.to_le_bytes()).unwrap();
        }
        let mut header = [0u8; 4096];
        header[..2].copy_from_slice(b"MZ");
        header[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        header[0x80..0x84].copy_from_slice(b"PE\0\0");
        header[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        header[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        header[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        header[0x98 + 56..0x98 + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        header[0x98 + 60..0x98 + 64].copy_from_slice(&0x400u32.to_le_bytes());
        file.seek(SeekFrom::Start(0x5000)).unwrap();
        file.write_all(&header).unwrap();
        file.flush().unwrap();
        {
            let mut memory = PhysicalMemory::new(&mut file).unwrap();
            memory.allow_transition = true;
            let result = scan_limited(&mut memory, 0x1000, None, 128).unwrap();
            assert_eq!(result.mapped_pages_examined, 3);
            assert_eq!(result.readable_pages, 2);
            assert_eq!(result.unavailable_pages, 1);
            assert_eq!(result.transition_pages, 1);
            assert_eq!(result.mz_signatures, 2);
            assert_eq!(result.unaligned_images, 2);
            assert_eq!(result.images.len(), 2);
            assert_eq!(result.images[0].base, 0x11000);
            assert_eq!(result.images[1].base, 0x13000);
            // Present PTEs above have NX clear; the transition one has NX set.
            assert_eq!(result.executable_pages, 2);
            assert_eq!(result.executable_regions,
                vec![ExecutableRegion { start: 0x11000, length: 0x2000 }]);
            // Strict mode ignores the transition entry entirely.
            memory.allow_transition = false;
            let strict = scan_limited(&mut memory, 0x1000, None, 128).unwrap();
            assert_eq!(strict.mapped_pages_examined, 2);
            assert_eq!(strict.transition_pages, 0);
            assert_eq!(strict.images.len(), 1);
            // read_virtual honours the same policy.
            let mut two = [0u8; 2];
            assert!(memory.read_virtual(0x1000, 0x13000, &mut two, 4).is_err());
            memory.allow_transition = true;
            let before = memory.transition_translations;
            memory.read_virtual(0x1000, 0x13000, &mut two, 4).unwrap();
            assert_eq!(&two, b"MZ");
            assert_eq!(memory.transition_translations, before + 1);
        }
        drop(file);
        fs::remove_file(path).unwrap();
    }
}
