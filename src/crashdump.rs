//! Windows AMD64 crash-dump page mapping (PAGE/DU64).
//! Supports full run dumps (type 1) and bitmap dumps (types 5 and 6).
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

const PAGE: u64 = 4096;

#[derive(Debug, Clone)]
pub struct Segment {
    pub physical: u64,
    pub file_offset: u64,
    pub length: u64,
}

#[derive(Debug)]
pub struct DumpInfo {
    pub dump_type: u32,
    pub dtb: u64,
    pub major: u32,
    pub minor: u32,
    pub kernel_module_list: u64,
    pub active_process_head: u64,
    pub segments: Vec<Segment>,
}

fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
fn u32_at(b: &[u8], i: usize) -> io::Result<u32> {
    let a: [u8; 4] = b.get(i..i + 4).ok_or_else(|| invalid("truncated dump field"))?
        .try_into().map_err(|_| invalid("invalid dump field"))?;
    Ok(u32::from_le_bytes(a))
}
fn u64_at(b: &[u8], i: usize) -> io::Result<u64> {
    let a: [u8; 8] = b.get(i..i + 8).ok_or_else(|| invalid("truncated dump field"))?
        .try_into().map_err(|_| invalid("invalid dump field"))?;
    Ok(u64::from_le_bytes(a))
}

fn push_segment(result: &mut Vec<Segment>, physical: u64, file_offset: u64, length: u64,
                total: u64) -> io::Result<()> {
    let end = file_offset.checked_add(length).ok_or_else(|| invalid("file offset overflow"))?;
    physical.checked_add(length).ok_or_else(|| invalid("physical address overflow"))?;
    if length == 0 || end > total { return Err(invalid("dump page range exceeds file")); }
    result.push(Segment { physical, file_offset, length });
    Ok(())
}

pub fn parse(file: &mut File) -> io::Result<DumpInfo> {
    let length = file.metadata()?.len();
    if length < 8192 { return Err(invalid("short Windows crash dump")); }
    let mut header = vec![0u8; 8192];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    if &header[0..8] != b"PAGEDU64" { return Err(invalid("not an AMD64 PAGE/DU64 dump")); }
    if u32_at(&header, 0x30)? != 0x8664 { return Err(invalid("unsupported crash dump architecture")); }
    let dump_type = u32_at(&header, 0xf98)?;
    let dtb = u64_at(&header, 0x10)?;
    let mut segments = Vec::new();
    match dump_type {
        1 => {
            let count = u32_at(&header, 0x88)? as usize;
            if count == 0 || count > 43 { return Err(invalid("invalid physical run count")); }
            let mut file_page = 2u64;
            for i in 0..count {
                let base = u64_at(&header, 0x98 + i * 16)?;
                let pages = u64_at(&header, 0xa0 + i * 16)?;
                if pages == 0 { return Err(invalid("empty physical run")); }
                push_segment(&mut segments,
                    base.checked_mul(PAGE).ok_or_else(|| invalid("physical run overflow"))?,
                    file_page.checked_mul(PAGE).ok_or_else(|| invalid("file page overflow"))?,
                    pages.checked_mul(PAGE).ok_or_else(|| invalid("run length overflow"))?, length)?;
                file_page = file_page.checked_add(pages).ok_or_else(|| invalid("run count overflow"))?;
            }
        }
        5 | 6 => {
            // Modern SDMP/FDMP bitmap header, located at file offset 0x2000.
            // The earlier _SUMMARY_DUMP64 assumptions (u32 fields at +0x0c)
            // do not apply to this header layout.
            let mut summary = [0u8; 56];
            file.seek(SeekFrom::Start(0x2000))?;
            file.read_exact(&mut summary)?;
            if (&summary[0..4] != b"SDMP" && &summary[0..4] != b"FDMP")
                || &summary[4..8] != b"DUMP" {
                return Err(invalid("invalid SDMP/FDMP bitmap signature"));
            }
            let first_page_hint = u64_at(&summary, 0x20)?;
            let expected_pages = u64_at(&summary, 0x28)?;
            let bitmap_bits = u64_at(&summary, 0x30)?;
            if bitmap_bits == 0 || expected_pages == 0 || expected_pages > bitmap_bits {
                return Err(invalid("invalid SDMP bitmap page counts"));
            }
            let bitmap_bytes = bitmap_bits.div_ceil(32).checked_mul(4)
                .ok_or_else(|| invalid("bitmap length overflow"))?;
            let page_data_bytes = expected_pages.checked_mul(PAGE)
                .ok_or_else(|| invalid("present page byte count overflow"))?;
            let page_data_start = length.checked_sub(page_data_bytes)
                .ok_or_else(|| invalid("present pages exceed dump size"))?;
            // Captures like CrowdStrike's observed SDMP dump use a 256-byte
            // FirstPage unit. Some writers encode the byte offset directly.
            // Only accept a location that agrees with the file's page count.
            let hint_matches = [Some(first_page_hint), first_page_hint.checked_mul(256),
                first_page_hint.checked_mul(PAGE)].into_iter().flatten()
                .any(|candidate| candidate == page_data_start);
            if !hint_matches {
                return Err(invalid("SDMP first-page location disagrees with dump size"));
            }
            if bitmap_bytes > 256 * 1024 * 1024 || 0x2000 + 56 + bitmap_bytes > page_data_start {
                return Err(invalid("invalid summary bitmap length"));
            }
            let mut bitmap = vec![0u8; bitmap_bytes as usize];
            file.seek(SeekFrom::Start(0x2000 + 56))?;
            file.read_exact(&mut bitmap)?;
            let mut file_offset = page_data_start;
            let mut count = 0u64;
            for page in 0..bitmap_bits {
                if bitmap[(page / 8) as usize] & (1 << (page % 8)) == 0 { continue; }
                let physical = page.checked_mul(PAGE).ok_or_else(|| invalid("bitmap physical overflow"))?;
                if let Some(last) = segments.last_mut() {
                    if last.physical + last.length == physical &&
                        last.file_offset + last.length == file_offset {
                        last.length += PAGE;
                    } else {
                        push_segment(&mut segments, physical, file_offset, PAGE, length)?;
                    }
                } else { push_segment(&mut segments, physical, file_offset, PAGE, length)?; }
                file_offset = file_offset.checked_add(PAGE).ok_or_else(|| invalid("bitmap file overflow"))?;
                count += 1;
            }
            if count != expected_pages { return Err(invalid("bitmap page-count mismatch")); }
            if file_offset != length { return Err(invalid("bitmap page data length mismatch")); }
        }
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported,
            format!("unsupported Windows crash DumpType {dump_type}; supported: 1, 5, 6"))),
    }
    segments.sort_unstable_by_key(|s| s.physical);
    for pair in segments.windows(2) {
        if pair[0].physical + pair[0].length > pair[1].physical {
            return Err(invalid("overlapping physical ranges"));
        }
    }
    Ok(DumpInfo { dump_type, dtb, major: u32_at(&header, 8)?, minor: u32_at(&header, 12)?,
        kernel_module_list: u64_at(&header, 0x20)?, active_process_head: u64_at(&header, 0x28)?, segments })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn parses_run_based_dump() {
        let mut data = vec![0u8; 8192 + 4096];
        data[0..8].copy_from_slice(b"PAGEDU64");
        data[0x30..0x34].copy_from_slice(&0x8664u32.to_le_bytes());
        data[0x10..0x18].copy_from_slice(&0x123000u64.to_le_bytes());
        data[0x88..0x8c].copy_from_slice(&1u32.to_le_bytes());
        data[0x90..0x98].copy_from_slice(&1u64.to_le_bytes());
        data[0x98..0xa0].copy_from_slice(&7u64.to_le_bytes());
        data[0xa0..0xa8].copy_from_slice(&1u64.to_le_bytes());
        data[0xf98..0xf9c].copy_from_slice(&1u32.to_le_bytes());
        let filename = std::env::temp_dir().join(format!("dumpy-test-{}-{}.dmp", std::process::id(), 1));
        {
            let mut f = File::create(&filename).unwrap();
            f.write_all(&data).unwrap();
        }
        let mut f = File::open(&filename).unwrap();
        let parsed = parse(&mut f).unwrap();
        assert_eq!(parsed.dtb, 0x123000);
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0].physical, 7 * PAGE);
        assert_eq!(parsed.segments[0].file_offset, 8192);
        drop(f);
        std::fs::remove_file(filename).unwrap();
    }

    #[test]
    fn parses_bitmap_kernel_dump_type_six() {
        let mut data = vec![0u8; 0x4000];
        data[0..8].copy_from_slice(b"PAGEDU64");
        data[0x30..0x34].copy_from_slice(&0x8664u32.to_le_bytes());
        data[0xf98..0xf9c].copy_from_slice(&6u32.to_le_bytes());
        let summary = 0x2000;
        data[summary..summary + 8].copy_from_slice(b"SDMPDUMP");
        data[summary + 0x20..summary + 0x28].copy_from_slice(&0x30u64.to_le_bytes());
        data[summary + 0x28..summary + 0x30].copy_from_slice(&1u64.to_le_bytes());
        data[summary + 0x30..summary + 0x38].copy_from_slice(&16u64.to_le_bytes());
        data[summary + 0x38] = 1 << 7;
        let filename = std::env::temp_dir().join(format!("dumpy-test-{}-bitmap.dmp", std::process::id()));
        {
            let mut f = File::create(&filename).unwrap();
            f.write_all(&data).unwrap();
        }
        let mut f = File::open(&filename).unwrap();
        let parsed = parse(&mut f).unwrap();
        assert_eq!(parsed.dump_type, 6);
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0].physical, 7 * PAGE);
        assert_eq!(parsed.segments[0].file_offset, 0x3000);
        drop(f);
        std::fs::remove_file(filename).unwrap();
    }
}
