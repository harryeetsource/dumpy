//! Physical dump format probing and AMD64 page-table translation.
//! This layer never assumes that consecutive physical bytes are consecutive virtual bytes.
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use crate::crashdump;

pub const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpFormat {
    RawOrPadded,
    WindowsCrashDump,
    Minidump,
}

pub fn identify(file: &mut File) -> io::Result<DumpFormat> {
    let mut header = [0u8; 8];
    file.seek(SeekFrom::Start(0))?;
    let bytes = file.read(&mut header)?;
    Ok(if bytes >= 4 && &header[..4] == b"MDMP" {
        DumpFormat::Minidump
    } else if bytes >= 8 && &header[..4] == b"PAGE" &&
        (&header[4..8] == b"DUMP" || &header[4..8] == b"DU64") {
        DumpFormat::WindowsCrashDump
    } else {
        DumpFormat::RawOrPadded
    })
}

pub struct PhysicalMemory<'a> {
    file: &'a mut File,
    segments: Vec<crashdump::Segment>,
}

impl<'a> PhysicalMemory<'a> {
    pub fn new(file: &'a mut File) -> io::Result<Self> {
        let size = file.metadata()?.len();
        let segments = match identify(file)? {
            DumpFormat::WindowsCrashDump => crashdump::parse(file)?.segments,
            DumpFormat::RawOrPadded => vec![crashdump::Segment { physical: 0, file_offset: 0, length: size }],
            DumpFormat::Minidump => return Err(io::Error::new(io::ErrorKind::Unsupported,
                "minidump virtual memory streams require a separate acquisition reader")),
        };
        Ok(Self { file, segments })
    }

    pub fn segments(&self) -> &[crashdump::Segment] { &self.segments }

    pub fn read_exact_at(&mut self, physical: u64, target: &mut [u8]) -> io::Result<()> {
        let mut completed = 0usize;
        while completed < target.len() {
            let address = physical.checked_add(completed as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "physical address overflow"))?;
            let index = self.segments.partition_point(|s| s.physical <= address);
            let Some(segment) = index.checked_sub(1).and_then(|i| self.segments.get(i)) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "physical page absent"));
            };
            let displacement = address - segment.physical;
            if displacement >= segment.length {
                return Err(io::Error::new(io::ErrorKind::NotFound, "physical page absent"));
            }
            let available = ((segment.length - displacement) as usize).min(target.len() - completed);
            self.file.seek(SeekFrom::Start(segment.file_offset + displacement))?;
            self.file.read_exact(&mut target[completed..completed + available])?;
            completed += available;
        }
        Ok(())
    }

    fn entry(&mut self, table: u64, index: u64) -> io::Result<u64> {
        let position = (table & 0x000f_ffff_ffff_f000)
            .checked_add(index * 8)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "page-table overflow"))?;
        let mut bytes = [0u8; 8];
        self.read_exact_at(position, &mut bytes)?;
        let entry = u64::from_le_bytes(bytes);
        if entry & 1 == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "page not present"));
        }
        Ok(entry)
    }

    /// Translate a canonical x64 virtual address using a caller-provided DTB/CR3.
    /// `levels` is 4 for conventional x64 paging or 5 for LA57.
    pub fn translate(&mut self, dtb: u64, va: u64, levels: u8) -> io::Result<u64> {
        if levels != 4 && levels != 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "paging levels must be 4 or 5"));
        }
        let canonical_bits = if levels == 5 { 57 } else { 48 };
        let top = va >> (canonical_bits - 1);
        let expected = if (va >> (canonical_bits - 1)) & 1 == 1 {
            (1u64 << (65 - canonical_bits)) - 1
        } else { 0 };
        if top != expected {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "noncanonical virtual address"));
        }
        let mut table = dtb & 0x000f_ffff_ffff_f000;
        for level in (1..=levels).rev() {
            let shift = 12 + 9 * (level as u64 - 1);
            let entry = self.entry(table, (va >> shift) & 0x1ff)?;
            let phys_base = entry & 0x000f_ffff_ffff_f000;
            if level == 3 && entry & (1 << 7) != 0 {
                // 1 GiB page, including physical address bits [51:30].
                return Ok((entry & 0x000f_ffff_c000_0000) | (va & 0x3fff_ffff));
            }
            if level == 2 && entry & (1 << 7) != 0 {
                // 2 MiB page, including physical address bits [51:21].
                return Ok((entry & 0x000f_ffff_ffe0_0000) | (va & 0x1f_ffff));
            }
            if level > 3 && entry & (1 << 7) != 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "reserved huge-page bit"));
            }
            table = phys_base;
        }
        Ok(table | (va & 0xfff))
    }

    /// Read a contiguous *virtual* range from noncontiguous physical pages.
    /// Fails closed on missing/paged-out pages instead of silently filling with zeroes.
    pub fn read_virtual(&mut self, dtb: u64, va: u64, output: &mut [u8], levels: u8) -> io::Result<()> {
        let mut done = 0;
        while done < output.len() {
            let current_va = va.checked_add(done as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "virtual address overflow"))?;
            let physical = self.translate(dtb, current_va, levels)?;
            let amount = ((PAGE - (current_va & (PAGE - 1))) as usize).min(output.len() - done);
            self.read_exact_at(physical, &mut output[done..done + amount])?;
            done += amount;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_top_half() {
        // Sign-extended x64 kernel address.
        let va = 0xffff_8000_0000_0000u64;
        let bits = 48u32;
        let top = va >> (bits - 1);
        assert_eq!(top, (1u64 << (65 - bits)) - 1);
    }
}
