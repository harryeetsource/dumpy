//! Bounded, symbol-independent PE discovery within a process's AMD64 user mappings.
//! Discovery is based on present USER page-table entries, not physical-file offsets.
use crate::memory::PhysicalMemory;
use crate::rebuild::MAX_IMAGE;
use std::collections::HashSet;
use std::io;

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const MAX_TABLES: usize = 200_000;
const DEFAULT_MAPPED_PAGES: usize = 500_000;

#[derive(Debug)]
pub struct UserImage {
    pub base: u64,
    pub size: u32,
}

#[derive(Debug)]
pub struct ScanResult {
    pub images: Vec<UserImage>,
    pub mapped_pages_examined: usize,
    pub readable_pages: usize,
    pub unavailable_pages: usize,
    pub mz_signatures: usize,
    pub rejected_pe_headers: usize,
    pub unaligned_images: usize,
    pub tables_examined: usize,
    pub unavailable_tables: usize,
    pub unavailable_headers: usize,
    pub truncated: bool,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
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

fn inspect_base(mem: &mut PhysicalMemory<'_>, dtb: u64, base: u64,
                physical: u64, report: &mut ScanResult) {
    let mut mz = [0u8; 2];
    if mem.read_exact_at(physical, &mut mz).is_err() {
        report.unavailable_pages += 1;
        return;
    }
    report.readable_pages += 1;
    if mz != *b"MZ" { return; }
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
    let root = dtb & ADDRESS_MASK;
    if root == 0 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "null process DTB")); }
    let limit = maximum_pages.unwrap_or(DEFAULT_MAPPED_PAGES).max(1);
    let max_images = max_images.clamp(1, 4096);
    let mut result = ScanResult { images: Vec::new(), mapped_pages_examined: 0,
        readable_pages: 0, unavailable_pages: 0, mz_signatures: 0,
        rejected_pe_headers: 0, unaligned_images: 0,
        tables_examined: 0, unavailable_tables: 0, unavailable_headers: 0, truncated: false };
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
        for index in (0..entries).rev() {
            let offset = index * 8;
            let entry = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            // Both present and user accessible; page-table bits must be set on each level.
            if entry & 5 != 5 { continue; }
            let shift = 12 + 9 * (level as u64 - 1);
            let va = prefix | ((index as u64) << shift);
            if level == 1 || (level == 2 || level == 3) && (entry & (1 << 7) != 0) {
                let pages = if level == 1 { 1u64 } else { 1u64 << (shift - 12) };
                let page_mask = (pages << 12) - 1;
                let phys = (entry & ADDRESS_MASK) & !page_mask;
                for page in 0..pages {
                    if result.mapped_pages_examined >= limit || result.images.len() >= max_images {
                        result.truncated = true;
                        break;
                    }
                    result.mapped_pages_examined += 1;
                    inspect_base(mem, dtb, va + page * 4096, phys + page * 4096, &mut result);
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
    fn finds_non_64k_aligned_pe_and_counts_missing_physical_pages() {
        let path = std::env::temp_dir().join(format!("dumpy_user_scan_{}_{}",
            std::process::id(), std::thread::current().name().unwrap_or("test")));
        let mut file = OpenOptions::new().create_new(true).read(true).write(true)
            .open(&path).expect("create synthetic memory file");
        file.set_len(0x6000).unwrap();
        // PML4 -> PDPT -> PD -> PT. Map VA 0x11000 to PA 0x5000;
        // VA 0x12000 is present in the page tables but absent from the capture.
        for (address, value) in [(0x1000, 0x2007u64), (0x2000, 0x3007),
            (0x3000, 0x4007), (0x4000 + 0x11 * 8, 0x5007),
            (0x4000 + 0x12 * 8, 0x6007)] {
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
            let result = scan_limited(&mut memory, 0x1000, None, 128).unwrap();
            assert_eq!(result.mapped_pages_examined, 2);
            assert_eq!(result.readable_pages, 1);
            assert_eq!(result.unavailable_pages, 1);
            assert_eq!(result.mz_signatures, 1);
            assert_eq!(result.unaligned_images, 1);
            assert_eq!(result.images.len(), 1);
            assert_eq!(result.images[0].base, 0x11000);
        }
        drop(file);
        fs::remove_file(path).unwrap();
    }
}
