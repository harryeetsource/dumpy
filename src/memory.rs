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
    /// Windows prototype-pointer PTE (Valid=0, Prototype=1): the process has
    /// not touched this shared page yet, so its PTE points at the section's
    /// prototype PTE in kernel memory, which in turn names the physical page
    /// every mapper of the file shares. Resolved through the kernel root.
    Prototype,
    /// No PTE at all; resolved through the process's VAD tree to the
    /// section's prototype PTE (shared page the process never touched).
    Vad,
}

/// Per-address-space VAD roots plus the learned MMVAD.FirstPrototypePte
/// offset; see `vad.rs`.
pub struct VadState {
    pub roots: std::collections::HashMap<u64, u64>,
    pub first_proto_offset: u64,
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

/// Name the reason a non-present entry stops a walk, so missing-page reports
/// say which mechanism would recover the page.
fn describe_absent(entry: u64, level: u8) -> String {
    let name = match level { 5 => "PML5", 4 => "PML4", 3 => "PDPT", 2 => "PD", _ => "PT" };
    let kind = if entry == 0 { "zero: never touched, VAD/section only" }
        else if entry & (1 << 10) != 0 { "prototype bit above PT level" }
        else if entry & (1 << 11) != 0 { "transition with null PFN" }
        else if entry >> 32 != 0 { "pagefile" }
        else if entry & 0x3e0 != 0 && entry >> 12 == 0 { "demand zero (protection only)" }
        else { "other software PTE" };
    format!("page not present ({name} {kind})")
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
    /// Page-table root that maps kernel space (System process CR3). Needed
    /// to follow prototype-pointer PTEs; None disables that.
    pub kernel_root: Option<u64>,
    /// Translations that resolved a leaf PTE through a prototype PTE.
    pub prototype_translations: u64,
    /// Highest physical address + 1 covered by the capture; used to detect
    /// swizzled PFNs in software PTEs.
    top_of_memory: u64,
    following_prototype: bool,
    /// VAD fallback for user pages with no PTE; None until `vad::setup`.
    pub vad: Option<VadState>,
    /// Translations resolved through a VAD.
    pub vad_translations: u64,
    last_absent_zero: bool,
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
        let top_of_memory = segments.iter().map(|s| s.physical + s.length).max().unwrap_or(0);
        Ok(Self { file, segments, allow_transition, transition_translations: 0,
                  kernel_root: None, prototype_translations: 0, top_of_memory, following_prototype: false,
                  vad: None, vad_translations: 0, last_absent_zero: false })
    }

    pub fn segments(&self) -> &[crashdump::Segment] { &self.segments }

    /// Highest physical address + 1 covered by the capture.
    pub fn physical_end(&self) -> u64 { self.top_of_memory }

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

    fn entry(&mut self, table: u64, index: u64, level: u8) -> io::Result<(u64, EntryKind)> {
        let position = (table & 0x000f_ffff_ffff_f000)
            .checked_add(index * 8)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "page-table overflow"))?;
        let mut bytes = [0u8; 8];
        self.read_exact_at(position, &mut bytes)?;
        let entry = u64::from_le_bytes(bytes);
        match classify_entry(entry, self.allow_transition) {
            Some(EntryKind::Transition) => Ok((self.unswizzle(entry), EntryKind::Transition)),
            Some(kind) => Ok((entry, kind)),
            None if level == 1 && entry & (1 << 10) != 0 => self.follow_prototype(entry),
            None => {
                self.last_absent_zero = entry == 0;
                Err(io::Error::new(io::ErrorKind::NotFound, describe_absent(entry, level)))
            }
        }
    }

    /// Software PTEs on systems with "PTE swizzling" store the PFN with its
    /// upper bits inverted when SwizzleBit (bit 4) is clear. A transition PFN
    /// that lands beyond the capture with that bit clear is unswizzled by
    /// dropping the bits above the capture's highest address.
    fn unswizzle(&self, entry: u64) -> u64 {
        const PFN_MASK: u64 = 0x000f_ffff_ffff_f000;
        if entry & (1 << 4) != 0 || self.top_of_memory == 0 { return entry; }
        let pfn_addr = entry & PFN_MASK;
        if pfn_addr < self.top_of_memory { return entry; }
        let keep = (1u64 << (64 - self.top_of_memory.leading_zeros())) - 1;
        (entry & !PFN_MASK) | (pfn_addr & keep & PFN_MASK)
    }

    /// Valid=0, Prototype=1, not a transition: `_MMPTE_PROTOTYPE`. Bits 16..63
    /// hold the sign-extended kernel address of the prototype PTE. Read that
    /// PTE through the kernel root; a hardware-valid or transition prototype
    /// names the shared physical page. Pagefile, subsection (never read from
    /// file) and demand-zero prototypes stay unresolvable. The special
    /// VAD-prototype encoding (ProtoAddress == 0xFFFFFFFF0000) is not followed.
    fn follow_prototype(&mut self, entry: u64) -> io::Result<(u64, EntryKind)> {
        const PROTOTYPE: u64 = 1 << 10;
        let not_present = |why: &str| io::Error::new(io::ErrorKind::NotFound, format!("page not present (PT {why})"));
        if !self.allow_transition || self.following_prototype || entry & PROTOTYPE == 0 || entry & 1 != 0 {
            return Err(not_present("prototype pointer, not followed"));
        }
        if self.kernel_root.is_none() { return Err(not_present("prototype pointer, no kernel root")); }
        let proto_va = ((entry as i64) >> 16) as u64;
        if proto_va == 0xffff_ffff_0000 { return Err(not_present("VAD prototype")); }
        if proto_va >> 47 != 0x1ffff || proto_va & 7 != 0 {
            return Err(not_present("prototype pointer, bad address"));
        }
        self.resolve_proto_pte(proto_va).map(|proto| (proto, EntryKind::Prototype))
    }

    /// Read a prototype PTE at a kernel VA and return it as a leaf entry when
    /// it names a physical page.
    fn resolve_proto_pte(&mut self, proto_va: u64) -> io::Result<u64> {
        const PROTOTYPE: u64 = 1 << 10;
        let Some(root) = self.kernel_root else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "page not present (no kernel root)"));
        };
        self.following_prototype = true;
        let result = (|| {
            let phys = self.translate(root, proto_va, 4).map_err(|_|
                io::Error::new(io::ErrorKind::NotFound, "page not present (PT prototype PTE itself unmapped)"))?;
            let mut bytes = [0u8; 8];
            self.read_exact_at(phys, &mut bytes)?;
            let proto = u64::from_le_bytes(bytes);
            match classify_entry(proto, true) {
                Some(EntryKind::Present) => Ok(proto),
                Some(EntryKind::Transition) => Ok(self.unswizzle(proto)),
                _ => Err(io::Error::new(io::ErrorKind::NotFound,
                    if proto & PROTOTYPE != 0 { "page not present (PT prototype: file-backed, not in RAM)" }
                    else if proto == 0 { "page not present (PT prototype: demand zero)" }
                    else { "page not present (PT prototype: paged out)" })),
            }
        })();
        self.following_prototype = false;
        result
    }

    /// No PTE: find the VAD covering `va` and read its prototype PTE.
    fn resolve_vad(&mut self, dtb: u64, va: u64) -> io::Result<u64> {
        let miss = |why: &str| io::Error::new(io::ErrorKind::NotFound, format!("page not present (VAD: {why})"));
        let (root, off) = match &self.vad {
            Some(state) => match state.roots.get(&(dtb & 0x000f_ffff_ffff_f000)) {
                Some(r) => (*r, state.first_proto_offset),
                None => return Err(miss("no VAD root for this address space")),
            },
            None => return Err(miss("not loaded")),
        };
        self.following_prototype = true;
        let found = crate::vad::lookup(self, root, va >> 12);
        let first = found.and_then(|(node, _, _)| {
            let mut b = [0u8; 16];
            let k = self.kernel_root?;
            self.read_virtual(k, node + off, &mut b, 4).ok()?;
            Some((u64::from_le_bytes(b[..8].try_into().unwrap()), u64::from_le_bytes(b[8..].try_into().unwrap())))
        });
        self.following_prototype = false;
        let Some((_, start, _)) = found else { return Err(miss("no VAD covers address")) };
        let Some((first, last)) = first else { return Err(miss("node unreadable")) };
        if first == 0 { return Err(miss("private memory, never touched")); }
        if !crate::vad::is_kernel_pointer(first) { return Err(miss("bad FirstPrototypePte")); }
        let proto_va = first + 8 * ((va >> 12) - start);
        // LastContiguousPte bounds data-file views made of several subsections.
        if crate::vad::is_kernel_pointer(last) && last >= first && proto_va > last {
            return Err(miss("beyond contiguous prototype PTEs"));
        }
        self.resolve_proto_pte(proto_va)
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
        match self.walk(dtb, va, levels) {
            Err(e) if self.last_absent_zero && va >> 47 == 0 && self.vad.is_some() && !self.following_prototype => {
                match self.resolve_vad(dtb, va) {
                    Ok(leaf) => {
                        self.vad_translations += 1;
                        Ok(((leaf & 0x000f_ffff_ffff_f000) | (va & 0xfff), EntryKind::Vad))
                    }
                    // Keep the more specific VAD reason unless no VAD covers it.
                    Err(v) if v.to_string().contains("no VAD covers") => Err(e),
                    Err(v) => Err(v),
                }
            }
            other => other,
        }
    }

    fn walk(&mut self, dtb: u64, va: u64, levels: u8) -> io::Result<(u64, EntryKind)> {
        self.last_absent_zero = false;
        let mut table = dtb & 0x000f_ffff_ffff_f000;
        let mut kind = EntryKind::Present;
        let finish = |this: &mut Self, physical: u64, kind: EntryKind| {
            match kind {
                EntryKind::Transition => this.transition_translations += 1,
                EntryKind::Prototype => this.prototype_translations += 1,
                EntryKind::Present | EntryKind::Vad => {}
            }
            Ok((physical, kind))
        };
        for level in (1..=levels).rev() {
            let shift = 12 + 9 * (level as u64 - 1);
            let (entry, entry_kind) = self.entry(table, (va >> shift) & 0x1ff, level)?;
            if entry_kind == EntryKind::Prototype && level != 1 {
                return Err(io::Error::new(io::ErrorKind::NotFound, "page not present"));
            }
            if entry_kind != EntryKind::Present { kind = entry_kind; }
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
