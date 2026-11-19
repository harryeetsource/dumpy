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
            import: directory(1), export: directory(0) })
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
}
