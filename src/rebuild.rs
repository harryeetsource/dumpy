use std::cmp::max;

pub const MAX_IMAGE: usize = 600 * 1024 * 1024;
const MAX_SECTIONS: usize = 96;

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    let a: [u8; 2] = b.get(o..o.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(a))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    let a: [u8; 4] = b.get(o..o.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(a))
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub raw_offset: usize,
    pub raw_size: usize,
    pub characteristics: u32,
}

#[derive(Debug)]
pub struct Pe {
    pub is_64: bool,
    pub size_of_image: usize,
    pub headers_size: usize,
    pub raw_file_size: usize,
    pub sections: Vec<Section>,
    pub import: (u32, u32),
    pub export: (u32, u32),
    pub resource: (u32, u32),
    pub timestamp: u32,
    pub characteristics: u16,
    pub machine: u16,
    pub entry_point: u32,
}

impl Pe {
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        if b.get(..2) != Some(b"MZ") { return Err("missing MZ".into()); }
        let nt = usize::try_from(u32_at(b, 0x3c).ok_or("short DOS header")?)
            .map_err(|_| "invalid e_lfanew")?;
        if nt < 0x40 || nt > 1024 * 1024 || b.get(nt..nt.checked_add(4).ok_or("NT overflow")?) != Some(b"PE\0\0") {
            return Err("invalid PE signature or e_lfanew".into());
        }
        let coff = nt + 4;
        let count = u16_at(b, coff + 2).ok_or("short COFF header")? as usize;
        let machine = u16_at(b, coff).ok_or("short COFF header")?;
        let timestamp = u32_at(b, coff + 4).ok_or("short COFF header")?;
        let characteristics = u16_at(b, coff + 18).ok_or("short COFF header")?;
        if count == 0 || count > MAX_SECTIONS { return Err("invalid section count".into()); }
        let opt_size = u16_at(b, coff + 16).ok_or("short COFF header")? as usize;
        let opt = coff + 20;
        let opt_end = opt.checked_add(opt_size).ok_or("optional header overflow")?;
        b.get(opt..opt_end).ok_or("truncated optional header")?;
        let magic = u16_at(b, opt).ok_or("missing optional header")?;
        let (is_64, min_opt, dir_start, dir_count_offset) = match magic {
            0x10b => (false, 96, 96, 92),
            0x20b => (true, 112, 112, 108),
            _ => return Err("unknown optional header magic".into()),
        };
        if opt_size < min_opt { return Err("short optional header".into()); }
        let entry_point = u32_at(b, opt + 16).ok_or("missing AddressOfEntryPoint")?;
        let size_of_image = u32_at(b, opt + 56).ok_or("missing SizeOfImage")? as usize;
        let headers_size = u32_at(b, opt + 60).ok_or("missing SizeOfHeaders")? as usize;
        let section_alignment = u32_at(b, opt + 32).ok_or("missing SectionAlignment")?;
        let file_alignment = u32_at(b, opt + 36).ok_or("missing FileAlignment")?;
        if size_of_image == 0 || size_of_image > MAX_IMAGE || headers_size < opt_end || headers_size > size_of_image
            || section_alignment == 0 || file_alignment == 0 {
            return Err("invalid image size, headers size, or alignment".into());
        }
        let table_end = opt_end.checked_add(count.checked_mul(40).ok_or("section count overflow")?)
            .ok_or("section table overflow")?;
        if table_end > headers_size { return Err("section table exceeds SizeOfHeaders".into()); }
        b.get(..headers_size).ok_or("truncated headers")?;
        let dirs = u32_at(b, opt + dir_count_offset).ok_or("missing directory count")? as usize;
        let directory = |i: usize| -> (u32, u32) {
            if i >= dirs || dir_start + (i + 1) * 8 > opt_size { return (0, 0); }
            (u32_at(b, opt + dir_start + i * 8).unwrap_or(0),
             u32_at(b, opt + dir_start + i * 8 + 4).unwrap_or(0))
        };
        let mut sections = Vec::with_capacity(count);
        let mut raw_file_size = headers_size;
        for i in 0..count {
            let off = opt_end + i * 40;
            let name_bytes = b.get(off..off + 8).ok_or("short section name")?;
            let name_end = name_bytes.iter().position(|v| *v == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
            let virtual_size = u32_at(b, off + 8).ok_or("short section")? as usize;
            let virtual_address = u32_at(b, off + 12).ok_or("short section")? as usize;
            let raw_size = u32_at(b, off + 16).ok_or("short section")? as usize;
            let raw_offset = u32_at(b, off + 20).ok_or("short section")? as usize;
            if raw_size != 0 {
                let raw_end = raw_offset.checked_add(raw_size).ok_or("raw size overflow")?;
                if raw_offset < headers_size || raw_end > MAX_IMAGE { return Err("invalid raw section range".into()); }
                raw_file_size = max(raw_file_size, raw_end);
            }
            let virtual_end = virtual_address.checked_add(max(virtual_size, raw_size)).ok_or("virtual size overflow")?;
            if virtual_end > size_of_image.saturating_add(section_alignment as usize) {
                return Err("virtual section exceeds image".into());
            }
            let characteristics = u32_at(b, off + 36).ok_or("short section flags")?;
            sections.push(Section { name, virtual_address, virtual_size, raw_offset, raw_size,
                characteristics });
        }
        Ok(Self { is_64, size_of_image, headers_size, raw_file_size, sections,
            import: directory(1), export: directory(0), resource: directory(2),
            timestamp, characteristics, machine, entry_point })
    }

    /// DLL names from the import descriptor table, in order, at most `max`.
    pub fn import_dll_names(&self, b: &[u8], max: usize) -> (Vec<String>, usize) {
        let mut names = Vec::new();
        let mut total = 0usize;
        if self.import.0 == 0 { return (names, 0); }
        let Some(base) = self.rva_to_raw_range(self.import.0, 20) else { return (names, 0) };
        for i in 0..4096usize {
            let at = base + i * 20;
            let (Some(oft), Some(name_rva), Some(ft)) = (u32_at(b, at), u32_at(b, at + 12), u32_at(b, at + 16)) else { break };
            if oft == 0 && name_rva == 0 && ft == 0 { break; }
            total += 1;
            if names.len() >= max { continue; }
            let Some((pos, avail)) = self.rva_to_raw_span(name_rva) else { continue };
            let Some(bytes) = b.get(pos..pos + avail.min(128)) else { continue };
            let Some(end) = bytes.iter().position(|v| *v == 0) else { continue };
            if end > 0 && bytes[..end].iter().all(|v| v.is_ascii_graphic()) {
                names.push(String::from_utf8_lossy(&bytes[..end]).into_owned());
            }
        }
        (names, total)
    }

    /// One-line triage summary of recovered file-layout bytes.
    pub fn summary(&self, b: &[u8]) -> String {
        let secs = self.sections.iter().map(|s| s.name.replace([' ', ';', '='], "_")).collect::<Vec<_>>().join(",");
        let (imports, total) = self.import_dll_names(b, 4);
        let any_code = self.sections.iter().any(|s| s.characteristics & 0x2000_0020 != 0);
        // Resource-only images (MUI files, satellite assemblies) have no
        // entry point, no imports and no executable section; they are loaded
        // as data files and never appear in a loader list.
        let kind = if self.entry_point == 0 && total == 0 && !any_code { "resource-only" }
            else if self.characteristics & 0x2000 != 0 { "dll" } else { "exe" };
        let machine = match self.machine { 0x14c => "i386", 0x8664 => "amd64", 0xaa64 => "arm64", _ => "other" };
        let imports = if total > imports.len() { format!("{}(+{})", imports.join(","), total - imports.len()) }
            else { imports.join(",") };
        let exports = if self.export.0 != 0 {
            self.rva_to_raw_range(self.export.0, 40).and_then(|d| u32_at(b, d + 20)).unwrap_or(0)
        } else { 0 };
        format!("{kind} {machine} ts=0x{:08x} secs={secs} imports={imports} exports={exports}", self.timestamp)
    }

    /// `OriginalFilename` (else `InternalName`) from VS_VERSIONINFO, located
    /// through the resource directory: root → RT_VERSION (16) → first name
    /// → first language → data entry. Every step is bounds-checked against
    /// recovered file-layout bytes; a resource section that was not resident
    /// simply yields None. Naming fallback only, never identity.
    pub fn version_name(&self, b: &[u8]) -> Option<String> {
        let (root_rva, dir_size) = self.resource;
        if root_rva == 0 || dir_size < 16 { return None; }
        let root = self.rva_to_raw_range(root_rva, 16)?;
        // Walk one directory level: return the entry's OffsetToData for the
        // entry whose ID matches `want`, or the first entry when None.
        let child = |dir: usize, want: Option<u32>| -> Option<u32> {
            let named = u16_at(b, dir + 12)? as usize;
            let ids = u16_at(b, dir + 14)? as usize;
            let count = named.checked_add(ids)?.min(256);
            for i in 0..count {
                let at = dir.checked_add(16 + i * 8)?;
                let id = u32_at(b, at)?;
                let offset = u32_at(b, at + 4)?;
                if want.map_or(true, |w| id == w) { return Some(offset); }
            }
            None
        };
        let sub = |offset: u32| -> Option<usize> {
            if offset & 0x8000_0000 == 0 { return None; }
            let rel = (offset & 0x7fff_ffff) as usize;
            if rel >= dir_size as usize { return None; }
            self.rva_to_raw_range(root_rva.checked_add(rel as u32)?, 16)
        };
        let type_dir = sub(child(root, Some(16))?)?;
        let name_dir = sub(child(type_dir, None)?)?;
        let leaf = child(name_dir, None)?;
        if leaf & 0x8000_0000 != 0 { return None; }
        let data_entry = self.rva_to_raw_range(root_rva.checked_add(leaf)?, 16)?;
        let data_rva = u32_at(b, data_entry)?;
        let data_size = u32_at(b, data_entry + 4)? as usize;
        if data_size < 64 || data_size > 1 << 20 { return None; }
        let data_at = self.rva_to_raw_range(data_rva, data_size)?;
        let blob = b.get(data_at..data_at + data_size)?;
        let find = |key: &str| -> Option<String> {
            let needle: Vec<u8> = key.encode_utf16().chain([0u16]).flat_map(u16::to_le_bytes).collect();
            let at = blob.windows(needle.len()).position(|w| w == needle.as_slice())?;
            // Key, NUL, then pad to a 4-byte boundary, then the value string.
            let mut pos = (at + needle.len() + 3) & !3;
            let mut units = Vec::new();
            while let Some(pair) = blob.get(pos..pos + 2) {
                let unit = u16::from_le_bytes([pair[0], pair[1]]);
                if unit == 0 { break; }
                units.push(unit);
                pos += 2;
                if units.len() > 260 { return None; }
            }
            let value = String::from_utf16(&units).ok()?;
            let trimmed = value.trim();
            (!trimmed.is_empty() && trimmed.chars().all(|c| !c.is_control()))
                .then(|| trimmed.to_owned())
        };
        find("OriginalFilename").or_else(|| find("InternalName"))
    }

    pub fn rva_to_raw(&self, rva: u32) -> Option<usize> {
        let r = rva as usize;
        if r < self.headers_size { return Some(r); }
        self.sections.iter().find_map(|s| {
            let delta = r.checked_sub(s.virtual_address)?;
            if delta < s.raw_size && delta < max(s.virtual_size, s.raw_size) {
                s.raw_offset.checked_add(delta)
            } else { None }
        })
    }

    /// Map an RVA range only when *every byte* is contained in the PE
    /// headers or in one section's initialized raw data. An RVA's starting
    /// offset alone is insufficient: allowing a read to cross a raw section
    /// boundary can reinterpret unrelated bytes as a valid PE table.
    pub fn rva_to_raw_span(&self, rva: u32) -> Option<(usize, usize)> {
        let start = rva as usize;
        if start < self.headers_size {
            return Some((start, self.headers_size - start));
        }
        self.sections.iter().find_map(|section| {
            let offset = start.checked_sub(section.virtual_address)?;
            if offset < section.raw_size &&
               offset < max(section.virtual_size, section.raw_size) {
                Some((section.raw_offset.checked_add(offset)?, section.raw_size - offset))
            } else { None }
        })
    }

    pub fn rva_to_raw_range(&self, rva: u32, length: usize) -> Option<usize> {
        let (raw, remaining) = self.rva_to_raw_span(rva)?;
        (length <= remaining).then_some(raw)
    }

    pub fn rva_to_mapped(&self, rva: u32) -> Option<usize> {
        let r = rva as usize;
        if r < self.size_of_image { Some(r) } else { None }
    }

    fn directory_score(&self, b: &[u8], mapped: bool) -> usize {
        let mut score = 0;
        for (rva, size, minimum) in [(self.import.0, self.import.1, 20usize), (self.export.0, self.export.1, 40usize)] {
            if rva == 0 || size == 0 { continue; }
            let off = if mapped { self.rva_to_mapped(rva) } else { self.rva_to_raw(rva) };
            if off.and_then(|o| b.get(o..o.checked_add(minimum)?)).is_some() { score += 1; }
        }
        score
    }

    pub fn recover(&self, image: &[u8]) -> Result<(Vec<u8>, &'static str), String> {
        let raw_possible = image.len() >= self.raw_file_size;
        let mapped_possible = image.len() >= self.size_of_image && self.sections.iter().all(|s| {
            s.raw_size == 0 || s.virtual_address.checked_add(s.raw_size).is_some_and(|end| end <= image.len())
        });
        if !raw_possible && !mapped_possible { return Err("incomplete raw and mapped image".into()); }
        // Prefer raw when both layouts are plausible: it preserves overlays and original directory bytes.
        let raw_score = if raw_possible { self.directory_score(image, false) } else { 0 };
        let mapped_score = if mapped_possible { self.directory_score(image, true) } else { 0 };
        if raw_possible && (raw_score >= mapped_score || !mapped_possible) {
            return Ok((image[..self.raw_file_size].to_vec(), "raw"));
        }
        Ok((self.recover_mapped(image)?, "mapped"))
    }

    pub fn recover_mapped(&self, image: &[u8]) -> Result<Vec<u8>, String> {
        if image.len() < self.size_of_image { return Err("truncated mapped image".into()); }
        let mut result = vec![0; self.raw_file_size];
        result[..self.headers_size].copy_from_slice(&image[..self.headers_size]);
        for s in &self.sections {
            if s.raw_size == 0 { continue; }
            let source = image.get(s.virtual_address..s.virtual_address + s.raw_size)
                .ok_or("truncated mapped section")?;
            let destination = result.get_mut(s.raw_offset..s.raw_offset + s.raw_size)
                .ok_or("invalid destination section")?;
            destination.copy_from_slice(source);
        }
        // Import/export directory entries and their internal pointers are RVAs, not file offsets.
        // They must not be rewritten when converting mapped section bytes to raw layout.
        Ok(result)
    }

    /// The module name recorded in the export directory, if the directory
    /// and the name string are both inside recovered file-layout bytes.
    /// Used only as a naming fallback; it is never trusted for identity.
    /// Data directory `index` read straight from the optional header.
    pub fn data_directory(&self, b: &[u8], index: usize) -> Option<(u32, u32)> {
        let nt = u32_at(b, 0x3c)? as usize;
        let opt = nt.checked_add(24)?;
        let count = u32_at(b, opt + if self.is_64 { 108 } else { 92 })? as usize;
        if index >= count.min(16) { return None; }
        let at = opt + if self.is_64 { 112 } else { 96 } + index * 8;
        let (rva, size) = (u32_at(b, at)?, u32_at(b, at + 4)?);
        (rva != 0 && size != 0).then_some((rva, size))
    }

    /// CodeView record from the debug directory: (PDB path, symbol-server
    /// key = GUID without dashes + age in hex). RSDS (PDB 7) and NB10 (PDB 2).
    pub fn pdb_info(&self, b: &[u8]) -> Option<(String, String)> {
        let (rva, size) = self.data_directory(b, 6)?;
        let dir = self.rva_to_raw_range(rva, 28)?;
        for i in 0..(size as usize / 28).min(32) {
            let e = dir.checked_add(i * 28)?;
            if u32_at(b, e + 12)? != 2 { continue; } // IMAGE_DEBUG_TYPE_CODEVIEW
            let len = u32_at(b, e + 16)? as usize;
            let data_rva = u32_at(b, e + 20)?;
            if len < 24 || len > 4096 || data_rva == 0 { continue; }
            let Some(at) = self.rva_to_raw_range(data_rva, len) else { continue };
            let rec = b.get(at..at + len)?;
            let (key, path_at) = match &rec[..4] {
                b"RSDS" => {
                    let g = &rec[4..20];
                    let d1 = u32::from_le_bytes(g[0..4].try_into().ok()?);
                    let d2 = u16::from_le_bytes(g[4..6].try_into().ok()?);
                    let d3 = u16::from_le_bytes(g[6..8].try_into().ok()?);
                    let tail: String = g[8..16].iter().map(|x| format!("{x:02X}")).collect();
                    let age = u32::from_le_bytes(rec[20..24].try_into().ok()?);
                    (format!("{d1:08X}{d2:04X}{d3:04X}{tail}{age:X}"), 24)
                }
                b"NB10" if len >= 16 => {
                    let sig = u32::from_le_bytes(rec[8..12].try_into().ok()?);
                    let age = u32::from_le_bytes(rec[12..16].try_into().ok()?);
                    (format!("{sig:08X}{age:X}"), 16)
                }
                _ => continue,
            };
            let path = &rec[path_at..];
            let end = path.iter().position(|v| *v == 0).unwrap_or(path.len());
            let path = std::str::from_utf8(&path[..end]).ok()?;
            if path.is_empty() || !path.chars().all(|c| !c.is_control()) { continue; }
            return Some((path.to_string(), key));
        }
        None
    }

    /// File name of a PDB path, for naming: `D:\x\foo.pdb` -> `foo.pdb`.
    pub fn pdb_leaf(path: &str) -> &str {
        path.rsplit(['\\', '/']).next().unwrap_or(path)
    }

    /// .NET: the Module table's name (the assembly's file name, e.g.
    /// `System.Foo.dll`) from the CLI metadata. Module is table 0, so its
    /// first row follows the #~ header and row counts directly.
    pub fn clr_module_name(&self, b: &[u8]) -> Option<String> {
        let (rva, _) = self.data_directory(b, 14)?;
        let cor = self.rva_to_raw_range(rva, 72)?;
        let (md_rva, md_size) = (u32_at(b, cor + 8)?, u32_at(b, cor + 12)? as usize);
        let root = self.rva_to_raw_range(md_rva, md_size.min(1 << 20))?;
        if u32_at(b, root)? != 0x424A_5342 { return None; } // "BSJB"
        let vlen = u32_at(b, root + 12)? as usize;
        if vlen > 256 { return None; }
        let mut at = root + 16 + vlen;
        let streams = u16_at(b, at + 2)? as usize;
        at += 4;
        let (mut tables, mut strings) = (None, None);
        for _ in 0..streams.min(16) {
            let (off, size) = (u32_at(b, at)? as usize, u32_at(b, at + 4)? as usize);
            let name_start = at + 8;
            let name_len = b.get(name_start..name_start + 32)?.iter().position(|v| *v == 0)?;
            let name = &b[name_start..name_start + name_len];
            if name == b"#~" || name == b"#-" { tables = Some((root + off, size)); }
            if name == b"#Strings" { strings = Some((root + off, size)); }
            at = name_start + (name_len + 4) / 4 * 4;
        }
        let ((t, _), (st, st_size)) = (tables?, strings?);
        let heap_sizes = *b.get(t + 6)?;
        let valid = u64::from_le_bytes(b.get(t + 8..t + 16)?.try_into().ok()?);
        if valid & 1 == 0 { return None; }
        let first_row = t + 24 + 4 * valid.count_ones() as usize;
        let idx = if heap_sizes & 1 != 0 { u32_at(b, first_row + 2)? as usize } else { u16_at(b, first_row + 2)? as usize };
        if idx == 0 || idx >= st_size { return None; }
        let bytes = b.get(st + idx..st + st_size.min(idx + 256))?;
        let end = bytes.iter().position(|v| *v == 0)?;
        let name = std::str::from_utf8(&bytes[..end]).ok()?;
        // Any printable UTF-8: compilers emit non-ASCII module names, e.g.
        // Roslyn scripting's "ℛ*<guid>#<n>-<m>.dll".
        (!name.is_empty() && !name.chars().any(|c| c.is_control())).then(|| name.to_string())
    }

    pub fn export_name(&self, b: &[u8]) -> Option<String> {
        if self.export.0 == 0 || self.export.1 < 40 { return None; }
        let dir = self.rva_to_raw_range(self.export.0, 40)?;
        let name_rva = u32_at(b, dir + 12)?;
        // A zero or in-header Name RVA (seen on damaged tables) would resolve
        // to the DOS header and yield "MZ…" as a name.
        if (name_rva as usize) < self.headers_size { return None; }
        let (at, available) = self.rva_to_raw_span(name_rva)?;
        let bytes = b.get(at..at + available.min(256))?;
        let end = bytes.iter().position(|v| *v == 0)?;
        if end == 0 || !bytes[..end].iter().all(|v| v.is_ascii_graphic()) { return None; }
        Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    pub fn directory_report(&self, b: &[u8]) -> String {
        let mut report = Vec::new();
        for (label, (rva, size), needed) in [("imports", self.import, 20usize), ("exports", self.export, 40usize)] {
            if rva == 0 || size == 0 { report.push(format!("{label}=absent")); continue; }
            let valid = self.rva_to_raw(rva).and_then(|o| b.get(o..o.checked_add(needed)?)).is_some();
            // Basic structural validation: directory pointers must resolve as RVAs.
            let details_valid = match label {
                "imports" if valid => self.validate_import_descriptors(b),
                "exports" if valid => self.validate_export_directory(b),
                _ => valid,
            };
            report.push(format!("{label}={}", if details_valid { "present" } else { "damaged/unmapped" }));
        }
        report.join(", ")
    }

    fn validate_import_descriptors(&self, b: &[u8]) -> bool {
        let Some(base) = self.rva_to_raw(self.import.0) else { return false };
        let count = ((self.import.1 as usize) / 20).min(4096);
        if count == 0 { return false; }
        for i in 0..count {
            let Some(off) = i.checked_mul(20).and_then(|n| base.checked_add(n)) else { return false };
            let (Some(original_thunk), Some(name), Some(first_thunk)) =
                (u32_at(b, off), u32_at(b, off + 12), u32_at(b, off + 16)) else { return false };
            if original_thunk == 0 && name == 0 && first_thunk == 0 { return true; }
            if name == 0 || self.rva_to_raw(name).and_then(|p| b.get(p)).is_none() { return false; }
            let thunk = if original_thunk != 0 { original_thunk } else { first_thunk };
            if thunk == 0 || self.rva_to_raw(thunk).and_then(|p| b.get(p)).is_none() { return false; }
        }
        false
    }

    fn validate_export_directory(&self, b: &[u8]) -> bool {
        let Some(off) = self.rva_to_raw(self.export.0) else { return false };
        let (Some(name), Some(function_count), Some(name_count), Some(functions), Some(names), Some(ordinals)) =
            (u32_at(b, off + 12), u32_at(b, off + 20), u32_at(b, off + 24),
             u32_at(b, off + 28), u32_at(b, off + 32), u32_at(b, off + 36)) else { return false };
        let table_ok = |rva: u32, count: u32, stride: usize| -> bool {
            if count == 0 { return true; }
            if count as usize > 1_000_000 { return false; }
            self.rva_to_raw(rva).and_then(|p| p.checked_add((count as usize).checked_mul(stride)?).and_then(|end| b.get(p..end))).is_some()
        };
        name != 0 && self.rva_to_raw(name).and_then(|p| b.get(p)).is_some()
            && name_count <= function_count && table_ok(functions, function_count, 4)
            && table_ok(names, name_count, 4) && table_ok(ordinals, name_count, 2)
    }
}

#[cfg(test)]
mod tests {
    fn put32(b: &mut [u8], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_le_bytes()); }
    fn put16(b: &mut [u8], o: usize, v: u16) { b[o..o + 2].copy_from_slice(&v.to_le_bytes()); }

    /// PE32+ with one .rdata section holding a CodeView record and CLI metadata.
    fn naming_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x600];
        b[..2].copy_from_slice(b"MZ"); put32(&mut b, 0x3c, 0x80); b[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut b, 0x84, 0x8664); put16(&mut b, 0x86, 1); put16(&mut b, 0x94, 0xf0);
        let opt = 0x98; put16(&mut b, opt, 0x20b);
        put32(&mut b, opt + 32, 0x1000); put32(&mut b, opt + 36, 0x200);
        put32(&mut b, opt + 56, 0x2000); put32(&mut b, opt + 60, 0x200); put32(&mut b, opt + 108, 16);
        put32(&mut b, opt + 112 + 6 * 8, 0x1000); put32(&mut b, opt + 112 + 6 * 8 + 4, 28);
        put32(&mut b, opt + 112 + 14 * 8, 0x1100); put32(&mut b, opt + 112 + 14 * 8 + 4, 72);
        let s = 0x188; b[s..s + 6].copy_from_slice(b".rdata");
        put32(&mut b, s + 8, 0x400); put32(&mut b, s + 12, 0x1000); put32(&mut b, s + 16, 0x400);
        put32(&mut b, s + 20, 0x200); put32(&mut b, s + 36, 0x4000_0040);
        // debug directory entry -> RSDS at RVA 0x1040
        let path = b"C:\\b\\foo.pdb\0";
        put32(&mut b, 0x200 + 12, 2); put32(&mut b, 0x200 + 16, (24 + path.len()) as u32); put32(&mut b, 0x200 + 20, 0x1040);
        b[0x240..0x244].copy_from_slice(b"RSDS");
        for i in 0..16 { b[0x244 + i] = i as u8 + 1; }
        put32(&mut b, 0x254, 3); b[0x258..0x258 + path.len()].copy_from_slice(path);
        // COR20 header at RVA 0x1100 -> metadata at RVA 0x1140
        put32(&mut b, 0x300, 72); put32(&mut b, 0x308, 0x1140); put32(&mut b, 0x30c, 0x100);
        let root = 0x340; put32(&mut b, root, 0x424A_5342); put32(&mut b, root + 12, 12);
        b[root + 16..root + 26].copy_from_slice(b"v4.0.30319");
        put16(&mut b, root + 30, 2);
        put32(&mut b, root + 32, 0x40); put32(&mut b, root + 36, 0x40); b[root + 40..root + 42].copy_from_slice(b"#~");
        put32(&mut b, root + 44, 0x80); put32(&mut b, root + 48, 0x20); b[root + 52..root + 60].copy_from_slice(b"#Strings");
        let t = root + 0x40; b[t + 4] = 2; b[t + 7] = 1; put32(&mut b, t + 8, 1); put32(&mut b, t + 24, 1);
        put16(&mut b, t + 28, 0); put16(&mut b, t + 30, 1);
        b[root + 0x81..root + 0x88].copy_from_slice(b"Foo.dll");
        b
    }

    #[test]
    fn pdb_and_clr_names() {
        let b = naming_pe();
        let pe = Pe::parse(&b).unwrap();
        let (path, key) = pe.pdb_info(&b).unwrap();
        assert_eq!(path, "C:\\b\\foo.pdb");
        assert_eq!(key, "040302010605080709 0A0B0C0D0E0F103".replace(' ', ""));
        assert_eq!(Pe::pdb_leaf(&path), "foo.pdb");
        assert_eq!(pe.clr_module_name(&b).as_deref(), Some("Foo.dll"));
        // Roslyn script submission name (non-ASCII prefix).
        let mut r = naming_pe();
        let name = "ℛ*ab#3-0.dll".as_bytes();
        r[0x340 + 0x81..0x340 + 0x81 + name.len()].copy_from_slice(name);
        r[0x340 + 0x81 + name.len()] = 0;
        let pe = Pe::parse(&r).unwrap();
        assert_eq!(pe.clr_module_name(&r).as_deref(), Some("ℛ*ab#3-0.dll"));
    }

    use super::*;
    #[test]
    fn rejects_negative_e_lfanew() {
        let mut b = [0u8; 128];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Pe::parse(&b).is_err());
    }
    #[test]
    fn rejects_truncated_input() { assert!(Pe::parse(b"MZ").is_err()); }
    #[test]
    fn version_name_walks_resource_tree_to_original_filename() {
        // .rsrc at RVA 0x2000 / raw 0x400: root dir -> RT_VERSION subdir
        // (+0x20) -> name subdir (+0x40) -> data entry (+0x60) -> blob (+0x100).
        let pe = Pe { is_64: true, size_of_image: 0x3000, headers_size: 0x200,
            raw_file_size: 0x800, sections: vec![Section { name: ".rsrc".into(),
                virtual_address: 0x2000, virtual_size: 0x400, raw_offset: 0x400,
                raw_size: 0x400, characteristics: 0x4000_0040 }],
            import: (0, 0), export: (0, 0), resource: (0x2000, 0x400), timestamp: 0, characteristics: 0, machine: 0x8664, entry_point: 0x1000 };
        let mut b = vec![0u8; 0x800];
        let w16 = |b: &mut [u8], at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        let w32 = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let r = 0x400;
        w16(&mut b, r + 14, 1); w32(&mut b, r + 16, 16); w32(&mut b, r + 20, 0x8000_0020);
        w16(&mut b, r + 0x20 + 14, 1); w32(&mut b, r + 0x20 + 16, 1); w32(&mut b, r + 0x20 + 20, 0x8000_0040);
        w16(&mut b, r + 0x40 + 14, 1); w32(&mut b, r + 0x40 + 16, 0x409); w32(&mut b, r + 0x40 + 20, 0x60);
        w32(&mut b, r + 0x60, 0x2100); w32(&mut b, r + 0x60 + 4, 0x100);
        let mut blob = Vec::new();
        for ch in "VS_VERSION_INFO".encode_utf16() { blob.extend(ch.to_le_bytes()); }
        blob.extend([0, 0]);
        while blob.len() % 4 != 0 { blob.push(0); }
        for ch in "OriginalFilename".encode_utf16() { blob.extend(ch.to_le_bytes()); }
        blob.extend([0, 0]);
        while blob.len() % 4 != 0 { blob.push(0); }
        for ch in "widget.dll".encode_utf16() { blob.extend(ch.to_le_bytes()); }
        blob.extend([0, 0]);
        b[r + 0x100..r + 0x100 + blob.len()].copy_from_slice(&blob);
        assert_eq!(pe.version_name(&b).as_deref(), Some("widget.dll"));
        // A non-resident data page (zeroed) yields nothing rather than junk.
        for x in &mut b[r + 0x100..r + 0x200] { *x = 0; }
        assert_eq!(pe.version_name(&b), None);
    }
    #[test]
    fn export_name_reads_only_inside_mapped_raw_bytes() {
        let pe = Pe { is_64: true, size_of_image: 0x2000, headers_size: 0x200,
            raw_file_size: 0x400, sections: vec![Section { name: ".edata".into(),
                virtual_address: 0x1000, virtual_size: 0x200, raw_offset: 0x200,
                raw_size: 0x200, characteristics: 0x4000_0040 }],
            import: (0, 0), export: (0x1000, 40), resource: (0, 0), timestamp: 0, characteristics: 0, machine: 0x8664, entry_point: 0x1000 };
        let mut b = vec![0u8; 0x400];
        b[0x20c..0x210].copy_from_slice(&0x1100u32.to_le_bytes());
        b[0x300..0x30a].copy_from_slice(b"ntdll.dll\0");
        assert_eq!(pe.export_name(&b).as_deref(), Some("ntdll.dll"));
        b[0x20c..0x210].copy_from_slice(&0x1f00u32.to_le_bytes());
        assert_eq!(pe.export_name(&b), None);
        // Name RVA 0 points at the DOS header: must not produce "MZ...".
        b[0x20c..0x210].copy_from_slice(&0u32.to_le_bytes());
        b[..3].copy_from_slice(b"MZx");
        assert_eq!(pe.export_name(&b), None);
    }
    #[test]
    fn raw_rva_range_never_crosses_section_or_header_boundaries() {
        let pe = Pe { is_64: true, size_of_image: 0x3000, headers_size: 0x200,
            raw_file_size: 0x600, sections: vec![Section {
                name: ".idata".into(), virtual_address: 0x1000,
                virtual_size: 0x200, raw_offset: 0x400, raw_size: 0x200,
                characteristics: 0x4000_0040 }],
            import: (0, 0), export: (0, 0), resource: (0, 0), timestamp: 0, characteristics: 0, machine: 0x8664, entry_point: 0x1000 };
        assert_eq!(pe.rva_to_raw_range(0x11f0, 16), Some(0x5f0));
        assert_eq!(pe.rva_to_raw_range(0x11f0, 17), None);
        assert_eq!(pe.rva_to_raw_range(0x1f0, 16), Some(0x1f0));
        assert_eq!(pe.rva_to_raw_range(0x1f0, 17), None);
    }
}
