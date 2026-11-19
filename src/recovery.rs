//! Recover kernel PE image sections from validated module mappings.
//! Missing virtual pages are zero-filled *only in explicitly partial outputs*.
use crate::kernel_modules::KernelModule;
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
    pub file_backed_pages: usize,
    pub missing_file_backed_pages: usize,
    pub executable_pages: usize,
    pub missing_executable_pages: usize,
    pub sections: Vec<SectionCoverage>,
    pub audit: Option<PeAudit>,
    pub priority: &'static str,
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
        fallback_sources: Vec::new(), file_backed_pages: 0,
        missing_file_backed_pages: 0, executable_pages: 0,
        missing_executable_pages: 0, sections: Vec::new(), audit: None,
        priority: "unavailable" };
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
            match memory.read_virtual(*dtb, va, page, 4) {
                Ok(()) => {
                    record.available_pages += 1;
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
    for (missing_va, _) in &record.missing_pages {
        if intersects(*missing_va, module.image_base, pe.headers_size as u64) {
            record.missing_header_pages += 1;
        }
        if intersects(*missing_va, module.image_base.saturating_add(pe.import.0 as u64), pe.import.1 as u64) {
            record.missing_import_pages += 1;
        }
        if intersects(*missing_va, module.image_base.saturating_add(pe.export.0 as u64), pe.export.1 as u64) {
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
        let first = section.virtual_address / 4096;
        let last = section.virtual_address.saturating_add(section.raw_size)
            .saturating_add(4095) / 4096;
        for index in first..last.min(mapped.len().div_ceil(4096)) {
            let relative = (index as u64) * 4096;
            if intersects(relative, section.virtual_address as u64, section.raw_size as u64) {
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
            pe.sections.iter().any(|s| intersects(relative, s.virtual_address as u64, s.raw_size as u64));
        let executable = pe.sections.iter().any(|s| s.characteristics & 0x2000_0000 != 0 &&
            intersects(relative, s.virtual_address as u64, s.raw_size as u64));
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
    let rebuilt = match pe.recover_mapped(&mapped) {
        Ok(bytes) => bytes,
        Err(e) => { record.diagnostics = format!("section reconstruction failed: {e}"); return Ok(record); }
    };
    let mut audit = pe_verify::validate(&pe, &rebuilt);
    if record.missing_import_pages > 0 && audit.imports.status != "absent" {
        audit.imports.status = "incomplete";
    }
    if record.missing_export_pages > 0 && audit.exports.status != "absent" {
        audit.exports.status = "incomplete";
    }
    let tables_ok = matches!(audit.imports.status, "valid" | "absent") &&
        matches!(audit.exports.status, "valid" | "absent");
    record.priority = if record.file_backed_pages > 0 &&
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
    let filename = format!("{}_0x{:016x}.{}", safe_name(&name), module.image_base,
        if record.fallback_pages > 0 { "merged.bin" }
        else if complete { "recovered.pe" } else { "partial.bin" });
    let destination = dir.join(filename);
    fs::create_dir_all(dir)?;
    fs::write(&destination, &rebuilt)?;
    record.output = Some(destination.to_string_lossy().into_owned());
    record.diagnostics = format!("{}; priority={}; fallback_pages={}; missing_header={} missing_import={} missing_export={}; file_backed={}/{} executable={}/{}; {}",
        if record.fallback_pages > 0 { "merged process mappings (not guaranteed coherent)" }
        else if complete { "complete pages" } else { "partial pages" }, record.priority,
        record.fallback_pages,
        record.missing_header_pages, record.missing_import_pages, record.missing_export_pages,
        record.file_backed_pages - record.missing_file_backed_pages, record.file_backed_pages,
        record.executable_pages - record.missing_executable_pages, record.executable_pages,
        pe.directory_report(&rebuilt));
    Ok(record)
}

pub fn write_report(dir: &Path, records: &[RecoveryRecord]) -> io::Result<()> {
    let mut report = String::from("name\tbase\timage_bytes\tavailable_pages\tmissing_pages\tfallback_pages\tmissing_header\tmissing_import\tmissing_export\tfile_backed_pages\tmissing_file_backed_pages\texecutable_pages\tmissing_executable_pages\toutput\tdiagnostics\tpriority\timport_status\texport_status\n");
    for item in records {
        let imports = item.audit.as_ref().map(|a| a.imports.status).unwrap_or("unavailable");
        let exports = item.audit.as_ref().map(|a| a.exports.status).unwrap_or("unavailable");
        report.push_str(&format!("{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            clean_field(&item.name), item.base, item.image_size, item.available_pages,
            item.missing_pages.len(), item.fallback_pages, item.missing_header_pages, item.missing_import_pages,
            item.missing_export_pages, item.file_backed_pages, item.missing_file_backed_pages,
            item.executable_pages, item.missing_executable_pages,
            clean_field(item.output.as_deref().unwrap_or("")),
            clean_field(&item.diagnostics), item.priority, imports, exports));
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
    let mut validation = String::from("name\tbase\tpriority\timports\timport_descriptors\timport_symbols\timport_invalid_references\tresolved_iat_suspected\texports\texport_functions\texport_names\texport_invalid_references\n");
    for item in records {
        if let Some(audit) = &item.audit {
            validation.push_str(&format!("{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean_field(&item.name), item.base, item.priority,
                audit.imports.status, audit.imports.entries, audit.imports.symbols,
                audit.imports.invalid_references, audit.imports.resolved_iat_suspected,
                audit.exports.status, audit.exports.entries, audit.exports.symbols,
                audit.exports.invalid_references));
        }
    }
    fs::write(dir.join("dumpy_pe_validation.tsv"), validation)?;
    let rank = |value: &str| match value {
        "file-backed-complete" => 0usize, "executable-complete" => 1,
        "high-coverage" => 2, "partial-review" => 3, _ => 4,
    };
    let mut sorted = records.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| {
        rank(a.priority).cmp(&rank(b.priority))
            .then(a.missing_file_backed_pages.cmp(&b.missing_file_backed_pages))
            .then(a.name.cmp(&b.name))
    });
    let mut triage = String::from("priority\tname\tbase\tfile_backed_available\tfile_backed_total\texecutable_available\texecutable_total\tmissing_import_pages\tmissing_export_pages\timport_status\texport_status\toutput\n");
    for item in sorted {
        triage.push_str(&format!("{}\t{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            item.priority, clean_field(&item.name), item.base,
            item.file_backed_pages.saturating_sub(item.missing_file_backed_pages),
            item.file_backed_pages,
            item.executable_pages.saturating_sub(item.missing_executable_pages),
            item.executable_pages, item.missing_import_pages, item.missing_export_pages,
            item.audit.as_ref().map(|a| a.imports.status).unwrap_or("unavailable"),
            item.audit.as_ref().map(|a| a.exports.status).unwrap_or("unavailable"),
            clean_field(item.output.as_deref().unwrap_or(""))));
    }
    fs::write(dir.join("dumpy_triage.tsv"), triage)
}

#[cfg(test)]
mod tests {
    use super::*;
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
