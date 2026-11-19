//! Bounded, read-only validation of import and export references in rebuilt PE
//! file-layout bytes. This never invents missing names or edits the IAT.
use crate::rebuild::Pe;

#[derive(Debug, Default)]
pub struct TableAudit {
    pub status: &'static str,
    pub entries: usize,
    pub symbols: usize,
    pub invalid_references: usize,
    pub resolved_iat_suspected: bool,
}

#[derive(Debug, Default)]
pub struct PeAudit {
    pub imports: TableAudit,
    pub exports: TableAudit,
}

fn read_u16(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(p..p.checked_add(2)?)?.try_into().ok()?))
}
fn read_u32(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(p..p.checked_add(4)?)?.try_into().ok()?))
}
fn read_u64(b: &[u8], p: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(p..p.checked_add(8)?)?.try_into().ok()?))
}
fn ascii_name(b: &[u8], start: usize, max: usize) -> bool {
    let Some(bytes) = b.get(start..start.saturating_add(max).min(b.len())) else { return false };
    let Some(end) = bytes.iter().position(|byte| *byte == 0) else { return false };
    end > 0 && bytes[..end].iter().all(|byte| byte.is_ascii_graphic())
}
fn name_at(pe: &Pe, b: &[u8], rva: u32) -> bool {
    pe.rva_to_raw(rva).is_some_and(|offset| ascii_name(b, offset, 512))
}
fn range_at(pe: &Pe, b: &[u8], rva: u32, length: usize) -> Option<usize> {
    let at = pe.rva_to_raw(rva)?;
    b.get(at..at.checked_add(length)?)?;
    Some(at)
}

pub fn validate(pe: &Pe, b: &[u8]) -> PeAudit {
    PeAudit { imports: validate_imports(pe, b), exports: validate_exports(pe, b) }
}

fn validate_imports(pe: &Pe, b: &[u8]) -> TableAudit {
    let mut out = TableAudit { status: "absent", ..Default::default() };
    if pe.import.0 == 0 || pe.import.1 == 0 { return out; }
    out.status = "invalid";
    // Some linkers leave a small directory size despite a terminating descriptor.
    let Some(base) = range_at(pe, b, pe.import.0, 20) else { return out };
    let stride = if pe.is_64 { 8usize } else { 4usize };
    let mut terminated = false;
    let descriptor_limit = (pe.import.1 as usize / 20).saturating_add(1).clamp(1, 4096);
    for index in 0..descriptor_limit {
        let Some(offset) = base.checked_add(index * 20) else { break };
        let (Some(oft), Some(name), Some(ft)) = (read_u32(b, offset),
            read_u32(b, offset + 12), read_u32(b, offset + 16)) else { break };
        if oft == 0 && name == 0 && ft == 0 {
            terminated = true;
            break;
        }
        out.entries += 1;
        if !name_at(pe, b, name) { out.invalid_references += 1; }
        let table_rva = if oft != 0 { oft } else { ft };
        if oft == 0 { out.resolved_iat_suspected = true; }
        let mut thunk_terminated = false;
        for thunk_index in 0..16384usize {
            if out.symbols >= 1_000_000 { break; }
            let Some(thunk_rva) = (table_rva as usize).checked_add(thunk_index * stride)
                .and_then(|n| u32::try_from(n).ok()) else { break };
            let Some(pos) = range_at(pe, b, thunk_rva, stride) else { break };
            let entry = if pe.is_64 { read_u64(b, pos) } else {
                read_u32(b, pos).map(u64::from)
            };
            let Some(entry) = entry else { break };
            if entry == 0 { thunk_terminated = true; break; }
            out.symbols += 1;
            let ordinal_mask = if pe.is_64 { 1u64 << 63 } else { 1u64 << 31 };
            if entry & ordinal_mask != 0 {
                // Ordinal imports contain no name; lower 16 bits hold ordinal.
                if entry & !(ordinal_mask | 0xffff) != 0 { out.invalid_references += 1; }
            } else if let Ok(name_rva) = u32::try_from(entry) {
                // IMAGE_IMPORT_BY_NAME: 2-byte hint, then ASCII name.
                let valid = range_at(pe, b, name_rva, 3)
                    .is_some_and(|pos| ascii_name(b, pos + 2, 512));
                if !valid { out.invalid_references += 1; }
            } else {
                out.invalid_references += 1;
            }
        }
        if !thunk_terminated { out.invalid_references += 1; }
    }
    if !terminated { out.invalid_references += 1; }
    out.status = if out.invalid_references == 0 { "valid" } else { "invalid" };
    out
}

fn validate_exports(pe: &Pe, b: &[u8]) -> TableAudit {
    let mut out = TableAudit { status: "absent", ..Default::default() };
    if pe.export.0 == 0 || pe.export.1 == 0 { return out; }
    out.status = "invalid";
    let Some(dir) = range_at(pe, b, pe.export.0, 40) else { return out };
    let (Some(name), Some(functions), Some(names), Some(func_table), Some(name_table), Some(ord_table)) =
        (read_u32(b, dir + 12), read_u32(b, dir + 20), read_u32(b, dir + 24),
         read_u32(b, dir + 28), read_u32(b, dir + 32), read_u32(b, dir + 36)) else { return out };
    if functions > 65536 || names > functions { return out; }
    out.entries = functions as usize;
    out.symbols = names as usize;
    if !name_at(pe, b, name) { out.invalid_references += 1; }
    let function_pos = if functions == 0 { Some(0) } else {
        range_at(pe, b, func_table, functions as usize * 4)
    };
    let name_pos = if names == 0 { Some(0) } else {
        range_at(pe, b, name_table, names as usize * 4)
    };
    let ordinal_pos = if names == 0 { Some(0) } else {
        range_at(pe, b, ord_table, names as usize * 2)
    };
    let (Some(function_pos), Some(name_pos), Some(ordinal_pos)) =
        (function_pos, name_pos, ordinal_pos) else { out.invalid_references += 1; return out };
    for i in 0..functions as usize {
        let Some(rva) = read_u32(b, function_pos + i * 4) else { out.invalid_references += 1; break };
        if rva == 0 { continue; }
        let forwarder = (pe.export.0 as u64..pe.export.0 as u64 + pe.export.1 as u64)
            .contains(&(rva as u64));
        if forwarder {
            if !name_at(pe, b, rva) { out.invalid_references += 1; }
        } else if rva as usize >= pe.size_of_image {
            out.invalid_references += 1;
        }
    }
    for i in 0..names as usize {
        let (Some(name_rva), Some(ordinal)) =
            (read_u32(b, name_pos + i * 4), read_u16(b, ordinal_pos + i * 2)) else {
                out.invalid_references += 1;
                break;
            };
        if ordinal as u32 >= functions || !name_at(pe, b, name_rva) {
            out.invalid_references += 1;
        }
    }
    out.status = if out.invalid_references == 0 { "valid" } else { "invalid" };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rebuild::Section;
    #[test]
    fn names_require_ascii_and_null_termination() {
        assert!(ascii_name(b"kernel32.dll\0", 0, 128));
        assert!(!ascii_name(b"kernel32.dll", 0, 128));
        assert!(!ascii_name(b"\0", 0, 128));
    }
    #[test]
    fn validates_named_import_and_rejects_corrupted_name_rva() {
        let pe = Pe { is_64: true, size_of_image: 0x2000, headers_size: 0x200,
            raw_file_size: 0xa00, sections: vec![Section { name: ".rdata".into(),
                virtual_address: 0x1000, virtual_size: 0x800,
                raw_offset: 0x200, raw_size: 0x800, characteristics: 0x4000_0040 }],
            import: (0x1000, 40), export: (0, 0) };
        let mut bytes = vec![0u8; 0xa00];
        bytes[0x200..0x204].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[0x20c..0x210].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[0x210..0x214].copy_from_slice(&0x1300u32.to_le_bytes());
        bytes[0x300..0x30d].copy_from_slice(b"kernel32.dll\0");
        bytes[0x400..0x408].copy_from_slice(&0x1400u64.to_le_bytes());
        bytes[0x602..0x611].copy_from_slice(b"GetProcAddress\0");
        let audit = validate(&pe, &bytes);
        assert_eq!(audit.imports.status, "valid");
        assert_eq!(audit.imports.entries, 1);
        assert_eq!(audit.imports.symbols, 1);
        bytes[0x400..0x408].copy_from_slice(&0x7fff_ffffu64.to_le_bytes());
        assert_eq!(validate(&pe, &bytes).imports.status, "invalid");
    }
}
