//! Recover kernel PE image sections from validated module mappings.
//! Missing virtual pages are zero-filled *only in explicitly partial outputs*.
use crate::kernel_modules::KernelModule;
use crate::coherence;
use crate::memory::PhysicalMemory;
use crate::rebuild::{Pe, MAX_IMAGE};
use crate::pe_verify::{self, PeAudit};
use std::fs;
use std::io;
use std::path::Path;
use std::collections::HashSet;

#[derive(Debug)]
pub struct SectionCoverage {
    pub name: String,
    pub virtual_address: usize,
    pub raw_size: usize,
    pub executable: bool,
    pub pages: usize,
    pub missing_pages: usize,
}

#[derive(Debug)]
pub struct RecoveryRecord {
    pub name: String,
    pub base: u64,
    pub image_size: usize,
    pub available_pages: usize,
    pub missing_pages: Vec<(u64, String)>,
    pub output: Option<String>,
    pub diagnostics: String,
    pub missing_header_pages: usize,
    pub missing_import_pages: usize,
    pub missing_export_pages: usize,
    pub fallback_pages: usize,
    pub fallback_sources: Vec<(u64, u64)>,
    /// Fallback pages that lie in headers or non-writable sections: image
    /// pages the loader shares copy-on-write between processes, so another
    /// process's copy is the same bytes unless somebody patched them.
    pub fallback_shared_pages: usize,
    /// Fallback pages in writable sections (.data, .bss): per-process state,
    /// so a page borrowed from another process is not this process's data.
    pub fallback_private_pages: usize,
    /// Shared-section fallback pages that read differently from a third
    /// root: a per-process patch (hook) or a relocation difference.
    pub fallback_conflicts: usize,
    pub file_backed_pages: usize,
    pub missing_file_backed_pages: usize,
    pub executable_pages: usize,
    pub missing_executable_pages: usize,
    /// Pages whose translation went through a Windows transition PTE
    /// (standby/modified list). Their bytes are the page's last contents,
    /// but the page was not hardware-valid at acquisition time.
    pub transition_pages: usize,
    /// Pages reached through a prototype PTE: shared file-backed pages this
    /// process never touched, resolved via the section's prototype PTEs.
    pub prototype_pages: usize,
    /// Pages with no PTE, resolved through the VAD tree.
    pub vad_pages: usize,
    /// exact | code-complete | merged | partial | unavailable
    pub completeness: &'static str,
    pub sections: Vec<SectionCoverage>,
    pub audit: Option<PeAudit>,
    pub priority: &'static str,
    pub layout: &'static str,
    pub layout_evidence: LayoutEvidence,
    pub executable_utf16_ratio: f64,
    pub incoherent_warning: bool,
}

#[derive(Debug, Default, Clone)]
pub struct LayoutEvidence {
    pub raw_import: &'static str,
    pub raw_import_entries: usize,
    pub raw_import_symbols: usize,
    pub mapped_import: &'static str,
    pub mapped_import_entries: usize,
    pub mapped_import_symbols: usize,
    pub raw_export: &'static str,
    pub mapped_export: &'static str,
}

/// A virtual address range can expose either an image view (section RVAs)
/// or a file view (section raw offsets). Select a raw file view only when
/// real import/export structures give positive evidence for that layout.
/// Missing or absent directories do not vote for raw layout.
pub fn choose_layout(pe: &Pe, source: &[u8]) -> Result<(Vec<u8>, &'static str), String> {
    choose_layout_detailed(pe, source).map(|(bytes, layout, _)| (bytes, layout))
}

pub fn choose_layout_detailed(pe: &Pe, source: &[u8])
    -> Result<(Vec<u8>, &'static str, LayoutEvidence), String> {
    let mapped = pe.recover_mapped(source)?;
    if source.len() < pe.raw_file_size {
        return Ok((mapped, "mapped-image", LayoutEvidence::default()));
    }
    let raw = &source[..pe.raw_file_size];
    let raw_audit = pe_verify::validate(pe, raw);
    let mapped_audit = pe_verify::validate(pe, &mapped);
    let evidence = LayoutEvidence {
        raw_import: raw_audit.imports.status,
        raw_import_entries: raw_audit.imports.entries,
        raw_import_symbols: raw_audit.imports.symbols,
        mapped_import: mapped_audit.imports.status,
        mapped_import_entries: mapped_audit.imports.entries,
        mapped_import_symbols: mapped_audit.imports.symbols,
        raw_export: raw_audit.exports.status,
        mapped_export: mapped_audit.exports.status,
    };
    // A nonzero import directory that immediately contains a null descriptor
    // is not evidence of a raw file view: zero-filled uncaptured memory can
    // produce exactly that pattern. Demand at least one real descriptor and
    // symbol (or a nonempty export function table) as affirmative evidence.
    let score = |audit: &PeAudit| -> usize {
        usize::from(audit.imports.status == "valid" && audit.imports.entries > 0 &&
            audit.imports.symbols > 0)
        + usize::from(audit.exports.status == "valid" && audit.exports.entries > 0)
    };
    let raw_valid = score(&raw_audit);
    let mapped_valid = score(&mapped_audit);
    if raw_valid > mapped_valid {
        return Ok((raw.to_vec(), "raw-file-view", evidence));
    }
    Ok((mapped, "mapped-image", evidence))
}

fn intersects(page_start: u64, range_start: u64, range_size: u64) -> bool {
    if range_size == 0 { return false; }
    let page_end = page_start.saturating_add(4096);
    let range_end = range_start.saturating_add(range_size);
    page_start < range_end && range_start < page_end
}

fn safe_name(name: &str) -> String {
    let leaf = name.rsplit(|c| c == '\\' || c == '/').next().unwrap_or("unnamed");
    let sanitized: String = leaf.chars().map(|c| {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }
    }).take(100).collect();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "unnamed".into()
    } else { sanitized }
}

fn clean_field(s: &str) -> String {
    s.chars().map(|c| if matches!(c, '\t' | '\r' | '\n') { ' ' } else { c }).collect()
}

pub fn recover(memory: &mut PhysicalMemory<'_>, dtb: u64,
               module: &KernelModule, dir: &Path) -> io::Result<RecoveryRecord> {
    recover_from_roots(memory, &[dtb], module, dir)
}

/// Merge only pages absent from the primary root using alternate roots with
/// an identical full first-page PE header. The caller must validate identity.
/// Merged results are intentionally never marked as pristine executable files.
pub fn recover_from_roots(memory: &mut PhysicalMemory<'_>, dtbs: &[u64],
                          module: &KernelModule, dir: &Path) -> io::Result<RecoveryRecord> {
    if dtbs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no DTB supplied"));
    }
    let name = module.name.clone().unwrap_or_else(|| format!("module_{:x}", module.image_base));
    let size = module.image_size as usize;
    let mut record = RecoveryRecord { name: name.clone(), base: module.image_base,
        image_size: size, available_pages: 0, missing_pages: Vec::new(),
        output: None, diagnostics: String::new(), missing_header_pages: 0,
        missing_import_pages: 0, missing_export_pages: 0, fallback_pages: 0,
        fallback_sources: Vec::new(), fallback_shared_pages: 0, fallback_private_pages: 0,
        fallback_conflicts: 0, file_backed_pages: 0,
        missing_file_backed_pages: 0, executable_pages: 0,
        missing_executable_pages: 0, transition_pages: 0, prototype_pages: 0, vad_pages: 0, completeness: "unavailable", sections: Vec::new(), audit: None,
        priority: "unavailable", layout: "unknown", layout_evidence: LayoutEvidence::default(),
        executable_utf16_ratio: 0.0, incoherent_warning: false };
    if size == 0 || size > MAX_IMAGE {
        record.diagnostics = "image size exceeds recovery limit".into();
        return Ok(record);
    }
    let mut mapped = vec![0u8; size];
    for (index, page) in mapped.chunks_mut(4096).enumerate() {
        let Some(va) = module.image_base.checked_add((index as u64) * 4096) else {
            record.diagnostics = "virtual address overflow".into();
            return Ok(record);
        };
        let mut recovered = false;
        let mut original_error = None;
        for (root_index, dtb) in dtbs.iter().enumerate() {
            let before = memory.transition_translations;
            let before_proto = memory.prototype_translations;
            let before_vad = memory.vad_translations;
            match memory.read_virtual(*dtb, va, page, 4) {
                Ok(()) => {
                    record.available_pages += 1;
                    if memory.transition_translations != before { record.transition_pages += 1; }
                    if memory.prototype_translations != before_proto { record.prototype_pages += 1; }
                    if memory.vad_translations != before_vad { record.vad_pages += 1; }
                    if root_index > 0 {
                        record.fallback_pages += 1;
                        record.fallback_sources.push((va, *dtb));
                    }
                    recovered = true;
                    break;
                }
                Err(e) if root_index == 0 => original_error = Some(e.to_string()),
                Err(_) => {}
            }
        }
        if !recovered {
            record.missing_pages.push((va, original_error.unwrap_or_else(|| "page unavailable".into())));
        }
    }
    let pe = match Pe::parse(&mapped) {
        Ok(pe) => pe,
        Err(e) => { record.diagnostics = format!("PE header unavailable or invalid: {e}"); return Ok(record); }
    };
    // Classify every borrowed page by the section it lands in. Pages were
    // read at virtual addresses, so section virtual ranges apply whatever
    // layout the rebuild chooses below.
    for (va, from_dtb) in record.fallback_sources.clone() {
        let rva = va.wrapping_sub(module.image_base);
        let in_headers = rva < pe.headers_size as u64;
        let writable = pe.sections.iter().any(|s| s.characteristics & 0x8000_0000 != 0 &&
            intersects(rva, s.virtual_address as u64, s.virtual_size.max(s.raw_size) as u64));
        if !in_headers && writable {
            record.fallback_private_pages += 1;
            continue;
        }
        record.fallback_shared_pages += 1;
        // Second opinion: does another root that maps this page agree?
        let offset = rva as usize;
        let Some(ours) = mapped.get(offset..offset + 4096) else { continue };
        let mut other = [0u8; 4096];
        let mut checked = 0;
        for dtb in dtbs.iter().filter(|d| **d != from_dtb) {
            if checked >= 2 { break; }
            if memory.read_virtual(*dtb, va, &mut other, 4).is_ok() {
                checked += 1;
                if other[..] != *ours { record.fallback_conflicts += 1; break; }
            }
        }
    }
    let (rebuilt, layout, evidence) = match choose_layout_detailed(&pe, &mapped) {
        Ok(result) => result,
        Err(e) => { record.diagnostics = format!("section reconstruction failed: {e}"); return Ok(record); }
    };
    record.layout = layout;
    record.layout_evidence = evidence;
    let mut audit = pe_verify::validate(&pe, &rebuilt);
    let raw_view = layout == "raw-file-view";
    let directory_start = |rva: u32| -> u64 {
        if raw_view { pe.rva_to_raw(rva).unwrap_or(usize::MAX) as u64 }
        else { rva as u64 }
    };
    for (missing_va, _) in &record.missing_pages {
        if intersects(*missing_va, module.image_base, pe.headers_size as u64) {
            record.missing_header_pages += 1;
        }
        // A linker may declare more directory bytes than the actual number
        // of descriptors, including padding beyond the terminating entry.
        // Only the consumed descriptor span is relevant to a *valid* table.
        let import_length = if audit.imports.status == "valid" &&
            audit.imports.directory_bytes_consumed > 0 {
            audit.imports.directory_bytes_consumed as u64
        } else { pe.import.1 as u64 };
        if pe.import.0 != 0 && intersects(*missing_va,
            module.image_base.saturating_add(directory_start(pe.import.0)), import_length) {
            record.missing_import_pages += 1;
        }
        if pe.export.0 != 0 && intersects(*missing_va,
            module.image_base.saturating_add(directory_start(pe.export.0)), pe.export.1 as u64) {
            record.missing_export_pages += 1;
        }
    }
    // Classify only initialized, file-backed section bytes. Uninitialized
    // virtual tails are omitted from this metric but still counted above.
    // A unique page overlapping multiple sections is counted once globally.
    let missing_set = record.missing_pages.iter().map(|(va, _)| *va)
        .collect::<HashSet<_>>();
    for section in &pe.sections {
        let executable = section.characteristics & 0x2000_0000 != 0;
        let mut coverage = SectionCoverage { name: section.name.clone(),
            virtual_address: section.virtual_address, raw_size: section.raw_size,
            executable, pages: 0, missing_pages: 0 };
        let start = if raw_view { section.raw_offset } else { section.virtual_address };
        let first = start / 4096;
        let last = start.saturating_add(section.raw_size)
            .saturating_add(4095) / 4096;
        for index in first..last.min(mapped.len().div_ceil(4096)) {
            let relative = (index as u64) * 4096;
            if intersects(relative, start as u64, section.raw_size as u64) {
                coverage.pages += 1;
                if missing_set.contains(&module.image_base.saturating_add(relative)) {
                    coverage.missing_pages += 1;
                }
            }
        }
        record.sections.push(coverage);
    }
    for (index, _) in mapped.chunks(4096).enumerate() {
        let relative = index as u64 * 4096;
        let file_backed = intersects(relative, 0, pe.headers_size as u64) ||
            pe.sections.iter().any(|s| intersects(relative,
                if raw_view { s.raw_offset as u64 } else { s.virtual_address as u64 }, s.raw_size as u64));
        let executable = pe.sections.iter().any(|s| s.characteristics & 0x2000_0000 != 0 &&
            intersects(relative, if raw_view { s.raw_offset as u64 } else { s.virtual_address as u64 }, s.raw_size as u64));
        let missing = missing_set.contains(&module.image_base.saturating_add(relative));
        if file_backed {
            record.file_backed_pages += 1;
            if missing { record.missing_file_backed_pages += 1; }
        }
        if executable {
            record.executable_pages += 1;
            if missing { record.missing_executable_pages += 1; }
        }
    }
    if record.missing_import_pages > 0 && audit.imports.status != "absent" {
        audit.imports.status = "incomplete";
    }
    if record.missing_export_pages > 0 && audit.exports.status != "absent" {
        audit.exports.status = "incomplete";
    }
    let profile = coherence::executable_text_profile(&pe, &rebuilt);
    record.executable_utf16_ratio = profile.ratio();
    record.incoherent_warning = profile.strongly_text_like() &&
        audit.imports.status == "invalid" && audit.exports.status == "invalid" &&
        record.missing_file_backed_pages == 0 && record.fallback_private_pages == 0;
    let tables_ok = matches!(audit.imports.status, "valid" | "absent") &&
        matches!(audit.exports.status, "valid" | "absent");
    record.priority = if record.incoherent_warning {
        "incoherent-review"
    } else if record.file_backed_pages > 0 &&
        record.missing_file_backed_pages == 0 && tables_ok {
        "file-backed-complete"
    } else if record.executable_pages > 0 && record.missing_executable_pages == 0 && tables_ok {
        "executable-complete"
    } else if record.file_backed_pages > 0 &&
        record.missing_file_backed_pages * 20 <= record.file_backed_pages && tables_ok {
        "high-coverage"
    } else { "partial-review" };
    record.audit = Some(audit);
    let complete = record.missing_pages.is_empty();
    // Borrowing only shared image pages that no other mapping disputes
    // yields the same bytes a single process would have given: a real
    // recovery. Borrowed writable pages or disputed pages do not.
    let coherent_merge = record.fallback_private_pages == 0 && record.fallback_conflicts == 0;
    // Code-complete: headers, every executable page and the import/export
    // directories came from memory and validate; only non-executable data
    // (typically .rsrc/.reloc/.data the process never touched) is
    // zero-filled. Loadable and analysable, but not byte-identical to disk.
    let code_complete = !complete && coherent_merge && !record.incoherent_warning &&
        record.missing_header_pages == 0 && record.executable_pages > 0 &&
        record.missing_executable_pages == 0 && record.missing_import_pages == 0 &&
        record.missing_export_pages == 0 && tables_ok;
    record.completeness = if record.fallback_pages > 0 && !coherent_merge { "merged" }
        else if complete { "exact" } else if code_complete { "code-complete" } else { "partial" };
    let filename = format!("{}_0x{:016x}.{}", safe_name(&name), module.image_base,
        match record.completeness { "merged" => "merged.bin", "exact" => "recovered.pe",
            "code-complete" => "code-complete.pe", _ => "partial.bin" });
    let zero_filled = record.sections.iter().filter(|s| s.missing_pages > 0)
        .map(|s| format!("{} {}/{}", s.name, s.missing_pages, s.pages)).collect::<Vec<_>>();
    let destination = dir.join(filename);
    fs::create_dir_all(dir)?;
    fs::write(&destination, &rebuilt)?;
    record.output = Some(destination.to_string_lossy().into_owned());
    record.diagnostics = format!("{}; layout={}; priority={}; fallback_pages={} (shared={} private={} conflicts={}); transition_pages={} prototype_pages={} vad_pages={}; missing_header={} missing_import={} missing_export={}; file_backed={}/{} executable={}/{}; {}",
        match (record.completeness, record.fallback_pages > 0) {
            ("merged", _) => "merged process mappings (not guaranteed coherent)".to_string(),
            ("exact", true) => "complete pages (shared image pages borrowed from other processes)".to_string(),
            ("exact", false) => "complete pages".to_string(),
            ("code-complete", _) => format!("code-complete: headers, code and import/export tables from memory; zero-filled: {}", zero_filled.join(" ")),
            (_, true) => "partial pages (shared image pages borrowed from other processes)".to_string(),
            _ => "partial pages".to_string(),
        }, record.layout, record.priority,
        record.fallback_pages, record.fallback_shared_pages, record.fallback_private_pages, record.fallback_conflicts,
        record.transition_pages, record.prototype_pages, record.vad_pages,
        record.missing_header_pages, record.missing_import_pages, record.missing_export_pages,
        record.file_backed_pages - record.missing_file_backed_pages, record.file_backed_pages,
        record.executable_pages - record.missing_executable_pages, record.executable_pages,
        pe.directory_report(&rebuilt));
    Ok(record)
}

pub fn write_report(dir: &Path, records: &[RecoveryRecord]) -> io::Result<()> {
    let mut report = String::from("name\tbase\timage_bytes\tavailable_pages\tmissing_pages\tfallback_pages\tmissing_header\tmissing_import\tmissing_export\tfile_backed_pages\tmissing_file_backed_pages\texecutable_pages\tmissing_executable_pages\toutput\tdiagnostics\tpriority\timport_status\texport_status\tlayout\traw_import_status\traw_import_descriptors\traw_import_symbols\tmapped_import_status\tmapped_import_descriptors\tmapped_import_symbols\traw_export_status\tmapped_export_status\texecutable_utf16_ascii_ratio\tincoherent_warning\ttransition_pages\tfallback_shared_pages\tfallback_private_pages\tfallback_conflicts\tprototype_pages\tvad_pages\tcompleteness\n");
    for item in records {
        let imports = item.audit.as_ref().map(|a| a.imports.status).unwrap_or("unavailable");
        let exports = item.audit.as_ref().map(|a| a.exports.status).unwrap_or("unavailable");
        report.push_str(&format!("{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            clean_field(&item.name), item.base, item.image_size, item.available_pages,
            item.missing_pages.len(), item.fallback_pages, item.missing_header_pages, item.missing_import_pages,
            item.missing_export_pages, item.file_backed_pages, item.missing_file_backed_pages,
            item.executable_pages, item.missing_executable_pages,
            clean_field(item.output.as_deref().unwrap_or("")),
            clean_field(&item.diagnostics), item.priority, imports, exports, item.layout,
            item.layout_evidence.raw_import, item.layout_evidence.raw_import_entries,
            item.layout_evidence.raw_import_symbols, item.layout_evidence.mapped_import,
            item.layout_evidence.mapped_import_entries, item.layout_evidence.mapped_import_symbols,
            item.layout_evidence.raw_export, item.layout_evidence.mapped_export,
            item.executable_utf16_ratio, item.incoherent_warning, item.transition_pages,
            item.fallback_shared_pages, item.fallback_private_pages, item.fallback_conflicts,
            item.prototype_pages, item.vad_pages, item.completeness));
    }
    fs::create_dir_all(dir)?;
    fs::write(dir.join("dumpy_recovery.tsv"), report)?;
    let mut missing = String::from("name\tvirtual_address\treason\n");
    for item in records {
        for (address, reason) in &item.missing_pages {
            missing.push_str(&format!("{}\t0x{:x}\t{}\n", safe_name(&item.name), address,
                clean_field(reason)));
        }
    }
    fs::write(dir.join("dumpy_missing_pages.tsv"), missing)?;
    let mut sources = String::from("name\tvirtual_address\tfallback_dtb\n");
    for item in records {
        for (va, dtb) in &item.fallback_sources {
            sources.push_str(&format!("{}\t0x{:x}\t0x{:x}\n", safe_name(&item.name), va, dtb));
        }
    }
    fs::write(dir.join("dumpy_page_sources.tsv"), sources)?;
    let mut section_report = String::from("name\tbase\tsection\tvirtual_address\traw_bytes\texecutable\tfile_backed_pages\tmissing_file_backed_pages\n");
    for item in records {
        for section in &item.sections {
            section_report.push_str(&format!("{}\t0x{:x}\t{}\t0x{:x}\t{}\t{}\t{}\t{}\n",
                clean_field(&item.name), item.base, clean_field(&section.name), section.virtual_address,
                section.raw_size, section.executable, section.pages, section.missing_pages));
        }
    }
    fs::write(dir.join("dumpy_sections.tsv"), section_report)?;
    let mut validation = String::from("name\tbase\tpriority\timports\timport_descriptors\timport_symbols\timport_invalid_references\tresolved_iat_suspected\texports\texport_functions\texport_names\texport_invalid_references\timport_bad_names\timport_bad_table_ranges\timport_unterminated_tables\timport_bad_ordinals\texport_bad_names\texport_bad_table_ranges\texport_bad_ordinals\texport_bad_forwarders\tlayout\n");
    for item in records {
        if let Some(audit) = &item.audit {
            validation.push_str(&format!("{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean_field(&item.name), item.base, item.priority,
                audit.imports.status, audit.imports.entries, audit.imports.symbols,
                audit.imports.invalid_references, audit.imports.resolved_iat_suspected,
                audit.exports.status, audit.exports.entries, audit.exports.symbols,
                audit.exports.invalid_references,
                audit.imports.bad_names, audit.imports.bad_table_ranges,
                audit.imports.unterminated_tables, audit.imports.bad_ordinals,
                audit.exports.bad_names, audit.exports.bad_table_ranges,
                audit.exports.bad_ordinals, audit.exports.bad_forwarders, item.layout));
        }
    }
    fs::write(dir.join("dumpy_pe_validation.tsv"), validation)?;
    let rank = |value: &str| match value {
        "file-backed-complete" => 0usize, "executable-complete" => 1,
        "high-coverage" => 2, "partial-review" => 3, "incoherent-review" => 4, _ => 5,
    };
    let mut sorted = records.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| {
        rank(a.priority).cmp(&rank(b.priority))
            .then(a.missing_file_backed_pages.cmp(&b.missing_file_backed_pages))
            .then(a.name.cmp(&b.name))
    });
    let mut triage = String::from("priority\tname\tbase\tfile_backed_available\tfile_backed_total\texecutable_available\texecutable_total\tmissing_import_pages\tmissing_export_pages\timport_status\texport_status\toutput\tlayout\texecutable_utf16_ascii_ratio\tincoherent_warning\n");
    for item in sorted {
        triage.push_str(&format!("{}\t{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{}\n",
            item.priority, clean_field(&item.name), item.base,
            item.file_backed_pages.saturating_sub(item.missing_file_backed_pages),
            item.file_backed_pages,
            item.executable_pages.saturating_sub(item.missing_executable_pages),
            item.executable_pages, item.missing_import_pages, item.missing_export_pages,
            item.audit.as_ref().map(|a| a.imports.status).unwrap_or("unavailable"),
            item.audit.as_ref().map(|a| a.exports.status).unwrap_or("unavailable"),
            clean_field(item.output.as_deref().unwrap_or("")), item.layout,
            item.executable_utf16_ratio, item.incoherent_warning));
    }
    fs::write(dir.join("dumpy_triage.tsv"), triage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rebuild::Section;

    fn test_image(raw: bool) -> (Pe, Vec<u8>) {
        let pe = Pe { is_64: true, size_of_image: 0x2000, headers_size: 0x200,
            raw_file_size: 0x800, sections: vec![Section {
                name: ".idata".into(), virtual_address: 0x1000,
                virtual_size: 0x600, raw_offset: 0x200, raw_size: 0x600,
                characteristics: 0x4000_0040 }],
            import: (0x1100, 40), export: (0, 0), resource: (0, 0), timestamp: 0, characteristics: 0, machine: 0x8664, entry_point: 0x1000 };
        let mut source = vec![0u8; 0x2000];
        let origin = if raw { 0x200usize } else { 0x1000usize };
        source[origin + 0x100..origin + 0x104].copy_from_slice(&0x11a0u32.to_le_bytes());
        source[origin + 0x10c..origin + 0x110].copy_from_slice(&0x1180u32.to_le_bytes());
        source[origin + 0x110..origin + 0x114].copy_from_slice(&0x11a0u32.to_le_bytes());
        source[origin + 0x180..origin + 0x18d].copy_from_slice(b"kernel32.dll\0");
        source[origin + 0x1a0..origin + 0x1a8].copy_from_slice(&0x11c0u64.to_le_bytes());
        source[origin + 0x1c2..origin + 0x1ce].copy_from_slice(b"CreateFileA\0");
        (pe, source)
    }

    #[test]
    fn selects_raw_file_view_from_valid_imports() {
        let (pe, source) = test_image(true);
        let (rebuilt, layout) = choose_layout(&pe, &source).unwrap();
        assert_eq!(layout, "raw-file-view");
        assert_eq!(pe_verify::validate(&pe, &rebuilt).imports.status, "valid");
    }
    #[test]
    fn preserves_mapped_image_view_from_valid_imports() {
        let (pe, source) = test_image(false);
        let (rebuilt, layout) = choose_layout(&pe, &source).unwrap();
        assert_eq!(layout, "mapped-image");
        assert_eq!(pe_verify::validate(&pe, &rebuilt).imports.status, "valid");
    }
    #[test]
    fn empty_raw_descriptor_cannot_outvote_damaged_mapped_imports() {
        let (pe, mut source) = test_image(false);
        // The raw-file candidate consists of zeros, so its first import
        // descriptor looks like a valid empty terminator. The mapped image
        // contains real but damaged import records and must remain selected.
        source[0x1180] = 0xff;
        let (_, layout) = choose_layout(&pe, &source).unwrap();
        assert_eq!(layout, "mapped-image");
    }
    #[test]
    fn filename_never_escapes_output_directory() {
        assert_eq!(safe_name("C:\\Windows\\System32\\drivers\\foo.sys"), "foo.sys");
        assert_eq!(safe_name("../../bad:name"), "bad_name");
        assert_eq!(safe_name(".."), "unnamed");
    }
    #[test]
    fn detects_page_overlap_with_directory() {
        assert!(intersects(0x2000, 0x2ff0, 0x40));
        assert!(!intersects(0x2000, 0x3000, 0x40));
    }
    #[test]
    fn file_backed_boundary_does_not_count_uninitialized_tail() {
        assert!(intersects(0x3000, 0x2800, 0x900));
        assert!(!intersects(0x4000, 0x2800, 0x900));
        assert!(!intersects(0x3000, 0x2800, 0));
    }
}
