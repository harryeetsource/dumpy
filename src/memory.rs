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

/// How a page-table entry was accepted for translation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// Hardware Valid bit set.
    Present,
    /// Windows software PTE with Valid=0, Transition=1, Prototype=0.
    /// The PFN still names a physical page (standby/modified list) whose
    /// contents are the last state of that virtual page.
    Transition,
}

/// Accept hardware-present entries and, when enabled, Windows transition
/// PTEs. Transition PTEs keep the hardware bit layout for Owner (bit 2) and
/// the PFN, so the user/supervisor test and address extraction stay valid.
/// Pagefile-backed and prototype software PTEs are never resolvable here.
pub fn classify_entry(entry: u64, allow_transition: bool) -> Option<EntryKind> {
    if entry & 1 != 0 { return Some(EntryKind::Present); }
    const TRANSITION: u64 = 1 << 11;
    const PROTOTYPE: u64 = 1 << 10;
    if allow_transition && entry & TRANSITION != 0 && entry & PROTOTYPE == 0 &&
        entry & 0x000f_ffff_ffff_f000 != 0 {
        return Some(EntryKind::Transition);
    }
    None
}

pub struct PhysicalMemory<'a> {
    file: &'a mut File,
    segments: Vec<crashdump::Segment>,
    /// Honour Windows transition PTEs during translation (default on).
    pub allow_transition: bool,
    /// Number of successful translations that went through at least one
    /// transition entry. Callers snapshot this around a read to attribute
    /// provenance to recovered bytes.
    pub transition_translations: u64,
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
        let allow_transition = std::env::var_os("DUMPY_STRICT_PTE").is_none();
        Ok(Self { file, segments, allow_transition, transition_translations: 0 })
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

    fn entry(&mut self, table: u64, index: u64) -> io::Result<(u64, EntryKind)> {
        let position = (table & 0x000f_ffff_ffff_f000)
            .checked_add(index * 8)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "page-table overflow"))?;
        let mut bytes = [0u8; 8];
        self.read_exact_at(position, &mut bytes)?;
        let entry = u64::from_le_bytes(bytes);
        match classify_entry(entry, self.allow_transition) {
            Some(kind) => Ok((entry, kind)),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "page not present")),
        }
    }

    /// Translate a canonical x64 virtual address using a caller-provided DTB/CR3.
    /// `levels` is 4 for conventional x64 paging or 5 for LA57.
    pub fn translate(&mut self, dtb: u64, va: u64, levels: u8) -> io::Result<u64> {
        self.translate_detailed(dtb, va, levels).map(|(physical, _)| physical)
    }

    /// As `translate`, also reporting whether any level of the walk relied on
    /// a transition (non-present) entry.
    pub fn translate_detailed(&mut self, dtb: u64, va: u64, levels: u8) -> io::Result<(u64, EntryKind)> {
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
        let mut kind = EntryKind::Present;
        let finish = |this: &mut Self, physical: u64, kind: EntryKind| {
            if kind == EntryKind::Transition { this.transition_translations += 1; }
            Ok((physical, kind))
        };
        for level in (1..=levels).rev() {
            let shift = 12 + 9 * (level as u64 - 1);
            let (entry, entry_kind) = self.entry(table, (va >> shift) & 0x1ff)?;
            if entry_kind == EntryKind::Transition { kind = EntryKind::Transition; }
            let phys_base = entry & 0x000f_ffff_ffff_f000;
            if level == 3 && entry & (1 << 7) != 0 {
                // 1 GiB page, including physical address bits [51:30].
                return finish(self, (entry & 0x000f_ffff_c000_0000) | (va & 0x3fff_ffff), kind);
            }
            if level == 2 && entry & (1 << 7) != 0 {
                // 2 MiB page, including physical address bits [51:21].
                return finish(self, (entry & 0x000f_ffff_ffe0_0000) | (va & 0x1f_ffff), kind);
            }
            if level > 3 && entry & (1 << 7) != 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "reserved huge-page bit"));
            }
            table = phys_base;
        }
        finish(self, table | (va & 0xfff), kind)
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
    fn transition_pte_is_resolvable_but_prototype_and_pagefile_are_not() {
        let pfn = 0x1234_5000u64;
        assert_eq!(classify_entry(pfn | 1, true), Some(EntryKind::Present));
        assert_eq!(classify_entry(pfn | (1 << 11), true), Some(EntryKind::Transition));
        assert_eq!(classify_entry(pfn | (1 << 11), false), None);
        assert_eq!(classify_entry(pfn | (1 << 11) | (1 << 10), true), None);
        assert_eq!(classify_entry(pfn | (1 << 10), true), None);
        // Pagefile PTE: Valid=0, Transition=0, PageFileHigh nonzero.
        assert_eq!(classify_entry(0x0000_0001_0000_0080, true), None);
        assert_eq!(classify_entry(0, true), None);
    }
    #[test]
    fn canonical_top_half() {
        // Sign-extended x64 kernel address.
        let va = 0xffff_8000_0000_0000u64;
        let bits = 48u32;
        let top = va >> (bits - 1);
        assert_eq!(top, (1u64 << (65 - bits)) - 1);
    }
}
