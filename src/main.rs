mod crashdump;
mod discovery;
mod io;
mod kernel_modules;
mod memory;
mod processes;
mod pe_verify;
mod recovery;
mod rebuild;
mod user_images;

use rebuild::{Pe, MAX_IMAGE};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

fn hex_number(s: &str) -> Result<u64, String> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16).map_err(|e| format!("invalid hexadecimal value {s}: {e}"))
}

fn inspect_dump(path: &Path) -> std::io::Result<()> {
    let mut file = File::open(path)?;
    let format = memory::identify(&mut file)?;
    println!("Acquisition: {format:?}");
    println!("Size: {} bytes", file.metadata()?.len());
    if format == memory::DumpFormat::WindowsCrashDump {
        let dump = crashdump::parse(&mut file)?;
        println!("DumpType: {} | Windows version: {}.{}", dump.dump_type, dump.major, dump.minor);
        println!("Kernel DTB: 0x{:x} | Loaded modules: 0x{:x} | Active processes: 0x{:x}",
            dump.dtb, dump.kernel_module_list, dump.active_process_head);
        println!("Captured physical ranges: {}", dump.segments.len());
        println!("Captured physical pages: {}", dump.segments.iter().map(|s| s.length / 4096).sum::<u64>());
        if dump.dtb != 0 && dump.kernel_module_list != 0 {
            let mut memory = memory::PhysicalMemory::new(&mut file)?;
            let mut links = [0u8; 16];
            match memory.read_virtual(dump.dtb, dump.kernel_module_list, &mut links, 4) {
                Ok(()) => {
                    let flink = u64::from_le_bytes(links[..8].try_into().unwrap());
                    let blink = u64::from_le_bytes(links[8..].try_into().unwrap());
                    println!("Kernel module-list page translation: successful; flink=0x{flink:x} blink=0x{blink:x}");
                }
                Err(e) => println!("Kernel module-list page translation unavailable: {e}"),
            }
        }
    } else {
        println!("Note: RawOrPadded is a fallback classification, not proof of a raw image.");
    }
    Ok(())
}

fn discover_dump(path: &Path) -> std::io::Result<()> {
    let mut file = File::open(path)?;
    let mut physical = memory::PhysicalMemory::new(&mut file)?;
    println!("Scanning for plausible self-referencing AMD64 PML4 roots...");
    let roots = discovery::discover_candidate_roots(&mut physical, 4096)?;
    println!("{} structural candidates (not yet validated process DTBs)", roots.len());
    for root in roots.iter().take(100) {
        println!("candidate=0x{:x} self_ref={} present={} kernel={} user={} children={}",
            root.physical, root.self_index, root.present_entries, root.kernel_entries,
            root.user_entries, root.valid_children);
    }
    if roots.len() > 100 { println!("Additional candidates omitted from console output"); }
    Ok(())
}

fn list_kernel_modules(path: &Path) -> std::io::Result<()> {
    let mut file = File::open(path)?;
    if memory::identify(&mut file)? != memory::DumpFormat::WindowsCrashDump {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
            "--modules currently requires a PAGE/DU64 Windows crash dump"));
    }
    let info = crashdump::parse(&mut file)?;
    if info.dtb == 0 || info.kernel_module_list == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "kernel DTB or module list head missing from dump header"));
    }
    let mut physical = memory::PhysicalMemory::new(&mut file)?;
    let report = kernel_modules::enumerate(&mut physical, info.dtb, info.kernel_module_list, 4096)?;
    for (index, module) in report.modules.iter().enumerate() {
        println!("[{}] name={} base=0x{:x} size={} entry=0x{:x} name_status={}",
            index + 1, module.name.as_deref().unwrap_or("<unavailable>"), module.image_base,
            module.image_size, module.entry, module.name_status);
    }
    println!("Validated kernel modules: {}", report.modules.len());
    println!("Traversed list entries: {}", report.traversed);
    println!("Enumeration status: {}", if report.complete { "COMPLETE" } else { "PARTIAL" });
    if let Some(warning) = report.warning { eprintln!("[module-list] WARNING: {warning}"); }
    Ok(())
}

fn list_processes(path: &Path) -> std::io::Result<()> {
    let mut file = File::open(path)?;
    if memory::identify(&mut file)? != memory::DumpFormat::WindowsCrashDump {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
            "--processes currently requires a Windows PAGE/DU64 dump"));
    }
    let info = crashdump::parse(&mut file)?;
    let mut physical = memory::PhysicalMemory::new(&mut file)?;
    println!("Discovering page-table candidates...");
    let roots = discovery::discover_candidate_roots(&mut physical, 8192)?;
    println!("Candidate roots: {}", roots.len());
    let report = processes::enumerate(&mut physical, info.dtb, info.active_process_head, &roots, 65536)?;
    for (index, process) in report.processes.iter().enumerate() {
        let dtbs = process.dtb_candidates.iter().map(|v| format!("0x{v:x}"))
            .collect::<Vec<_>>().join(",");
        let field_offsets = process.dtb_field_offsets.iter().map(|v| {
            format!("{}0x{:x}", if *v < 0 { "-" } else { "+" }, v.unsigned_abs())
        })
            .collect::<Vec<_>>().join(",");
        println!("[{}] pid_hint={} name_hint={} name_offset={} links=0x{:x} dtb_candidates=[{}] dtb_offsets=[{}]",
            index + 1, process.pid_hint.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
            process.image_name_hint.as_deref().unwrap_or("?"),
            process.image_name_offset.map(|v| format!("+0x{v:x}")).unwrap_or_else(|| "?".into()),
            process.links, dtbs, field_offsets);
    }
    println!("Processes traversed: {} | integrity: {}", report.processes.len(),
        if report.complete { "COMPLETE" } else { "PARTIAL" });
    if let Some(warning) = report.warning { eprintln!("[process-list] WARNING: {warning}"); }
    println!("Note: PIDs, names and DTBs are hints until matched EPROCESS layouts are available.");
    Ok(())
}

fn recover_user_images(path: &Path, output: &Path, maximum_pages: Option<usize>,
                       max_roots: Option<usize>, max_images: Option<usize>) -> std::io::Result<()> {
    let mut file = File::open(path)?;
    match memory::identify(&mut file)? {
        memory::DumpFormat::RawOrPadded => {
            return recover_raw_user_images(&mut file, output, maximum_pages, max_roots, max_images);
        }
        memory::DumpFormat::Minidump => {
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
                "MDMP minidump memory streams need a dedicated address-space reader"));
        }
        memory::DumpFormat::WindowsCrashDump => {}
    }
    let info = crashdump::parse(&mut file)?;
    if info.dtb == 0 || info.active_process_head == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "kernel DTB or active process list absent from crash header"));
    }
    let mut physical = memory::PhysicalMemory::new(&mut file)?;
    println!("Discovering DTB candidates and enumerating active processes...");
    let roots = discovery::discover_candidate_roots(&mut physical, 8192)?;
    let report = processes::enumerate(&mut physical, info.dtb, info.active_process_head, &roots, 65536)?;
    println!("Candidate roots: {} | processes: {} | integrity: {}",
        roots.len(), report.processes.len(), if report.complete { "COMPLETE" } else { "PARTIAL" });
    if let Some(warning) = report.warning { eprintln!("[process-list] WARNING: {warning}"); }
    fs::create_dir_all(output)?;
    let mut all_records = 0usize;
    for process in &report.processes {
        if process.dtb_candidates.len() != 1 {
            println!("[user] pid={:?}: skipped (ambiguous/missing DTB: {})",
                process.pid_hint, process.dtb_candidates.len());
            continue;
        }
        let dtb = process.dtb_candidates[0];
        let pid = process.pid_hint.map(|p| p.to_string()).unwrap_or_else(|| format!("unknown_{:x}", process.links));
        println!("[user] pid={} name={} dtb=0x{:x}: scanning user mappings...",
            pid, process.image_name_hint.as_deref().unwrap_or("?"), dtb);
        let scan = user_images::scan_limited(&mut physical, dtb, maximum_pages,
            max_images.unwrap_or(128))?;
        println!("[user] pid={} mapped_pages={} readable_pages={} missing_physical_pages={} mz_hits={} rejected_pe={} unaligned_pe={} page_tables={} missing_tables={} missing_headers={} images={} truncated={}",
            pid, scan.mapped_pages_examined, scan.readable_pages, scan.unavailable_pages,
            scan.mz_signatures, scan.rejected_pe_headers, scan.unaligned_images,
            scan.tables_examined, scan.unavailable_tables, scan.unavailable_headers,
            scan.images.len(), scan.truncated);
        let process_dir = output.join(format!("pid_{pid}_dtb_{dtb:x}"));
        let mut records = Vec::new();
        for image in &scan.images {
            let module = kernel_modules::KernelModule { entry: 0, image_base: image.base,
                image_size: image.size, name: Some(format!("image_{:x}", image.base)),
                name_status: "PE header" };
            let record = recovery::recover(&mut physical, dtb, &module, &process_dir)?;
            println!("[user-image] pid={} base=0x{:x} size={} available={} missing={} {}",
                pid, record.base, record.image_size, record.available_pages,
                record.missing_pages.len(), record.diagnostics);
            records.push(record);
        }
        recovery::write_report(&process_dir, &records)?;
        all_records += records.len();
    }
    println!("User-image recovery attempted for {} PE candidates. Reports: {}", all_records, output.display());
    println!("Warning: scans use a finite page budget and require readable, page-aligned PE headers. A kernel-only capture may contain no user image data.");
    Ok(())
}

/// The acquisition format is unknown. Only attempt a tentative flat-physical
/// mapping if multiple independent PML4 roots share a self-ref slot and one
/// identical non-self kernel mapping. This is evidence, not definitive proof.
fn recover_raw_user_images(file: &mut File, output: &Path,
                           maximum_pages: Option<usize>, max_roots: Option<usize>,
                           max_images: Option<usize>) -> std::io::Result<()> {
    println!("[raw] Unknown acquisition format; probing for flat physical-address mapping.");
    println!("[raw] File offsets are tentatively treated as physical addresses; results require independent validation.");
    let mut physical = memory::PhysicalMemory::new(file)?;
    let roots = discovery::discover_candidate_roots(&mut physical, 8192)?;
    println!("[raw] Structural PML4 candidates: {}", roots.len());
    // A shared kernel PML4 entry provides a cross-root consistency check.
    // Ignore the self-reference itself; it would only confirm each root alone.
    let mut groups = HashMap::<(usize, usize, u64), Vec<u64>>::new();
    for root in &roots {
        let mut page = [0u8; 4096];
        if physical.read_exact_at(root.physical, &mut page).is_err() { continue; }
        for slot in 256..512usize {
            if slot == root.self_index { continue; }
            let value = u64::from_le_bytes(page[slot * 8..slot * 8 + 8].try_into().unwrap());
            if value & 1 != 0 {
                groups.entry((root.self_index, slot, value)).or_default().push(root.physical);
            }
        }
    }
    let Some((_, cohort)) = groups.into_iter().max_by_key(|(_, roots)| roots.len()) else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "no coherent PML4 roots: acquisition may not be flat physical memory"));
    };
    if cohort.len() < 2 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "only one coherent PML4 root: cannot infer flat physical mapping"));
    }
    let allowed = cohort.into_iter().collect::<HashSet<_>>();
    let mut candidates = roots.into_iter().filter(|r| allowed.contains(&r.physical) && r.user_entries > 0)
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| b.user_entries.cmp(&a.user_entries).then(a.physical.cmp(&b.physical)));
    println!("[raw] Consistent page-table cohort: {} user-capable roots", candidates.len());
    if candidates.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "coherent roots have no present user mappings; physical layout unverified"));
    }
    let max_raw_roots = max_roots.unwrap_or(32);
    const DEFAULT_RAW_PAGES: usize = 100_000;
    if candidates.len() > max_raw_roots {
        println!("[raw] Limiting exploratory root scans to {} of {}", max_raw_roots, candidates.len());
    }
    // Group by (VA, SizeOfImage, complete first-page fingerprint).
    // The same DLL often appears in many roots; identical VAs alone are NOT
    // sufficient because different processes can independently reuse a VA.
    struct ImageChoice {
        dtb: u64,
        base: u64,
        size: u32,
        coverage_score: usize,
        dtbs: Vec<(u64, usize)>,
    }
    let mut choices = HashMap::<(u64, u32, u64), ImageChoice>::new();
    let mut total_images = 0usize;
    for root in candidates.iter().take(max_raw_roots) {
        println!("[raw] scanning dtb=0x{:x} user_pml4_entries={}", root.physical, root.user_entries);
        let scan = user_images::scan_limited(&mut physical, root.physical,
            Some(maximum_pages.unwrap_or(DEFAULT_RAW_PAGES)), max_images.unwrap_or(128))?;
        println!("[raw] dtb=0x{:x} mapped_pages={} readable_pages={} missing_physical_pages={} mz_hits={} rejected_pe={} images={} truncated={}",
            root.physical, scan.mapped_pages_examined, scan.readable_pages,
            scan.unavailable_pages, scan.mz_signatures, scan.rejected_pe_headers,
            scan.images.len(), scan.truncated);
        for image in scan.images {
            let mut header = [0u8; 4096];
            if physical.read_virtual(root.physical, image.base, &mut header, 4).is_err() { continue; }
            // Stable FNV-1a fingerprint of all captured PE header page bytes.
            let fingerprint = header.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
            });
            let key = (image.base, image.size, fingerprint);
            let new_score = raw_image_coverage_sample(&mut physical, root.physical, image.base, image.size);
            match choices.entry(key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(ImageChoice { dtb: root.physical, base: image.base,
                        size: image.size, coverage_score: new_score,
                        dtbs: vec![(root.physical, new_score)] });
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let choice = entry.get_mut();
                    choice.dtbs.push((root.physical, new_score));
                    if new_score > choice.coverage_score {
                        choice.dtb = root.physical;
                        choice.coverage_score = new_score;
                    }
                }
            }
            total_images += 1;
        }
    }
    println!("[raw] {} candidates clustered into {} distinct header identities ({} aliases suppressed)",
        total_images, choices.len(), total_images.saturating_sub(choices.len()));
    let dir = output.join("raw_deduplicated");
    fs::create_dir_all(&dir)?;
    let mut aliases = String::from("base\tsize\tfingerprint\tselected_dtb\tcoverage_sample\talias_dtbs\n");
    let mut chosen = choices.into_iter().collect::<Vec<_>>();
    chosen.sort_by_key(|((base, size, fingerprint), _)| (*base, *size, *fingerprint));
    let mut records = Vec::new();
    for ((_, _, fingerprint), mut item) in chosen {
        item.dtbs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let others = item.dtbs.iter().map(|(dtb, _)| format!("0x{dtb:x}"))
            .collect::<Vec<_>>().join(",");
        aliases.push_str(&format!("0x{:x}\t{}\t0x{:x}\t0x{:x}\t{}\t{}\n",
            item.base, item.size, fingerprint, item.dtb, item.coverage_score, others));
        let module = kernel_modules::KernelModule { entry: 0, image_base: item.base,
            image_size: item.size,
            name: Some(format!("image_{:x}_h{:016x}", item.base, fingerprint)),
            name_status: "PE header" };
        let mut ordered_dtbs = vec![item.dtb];
        ordered_dtbs.extend(item.dtbs.iter().filter(|(dtb, _)| *dtb != item.dtb)
            .take(7).map(|(dtb, _)| *dtb));
        let record = recovery::recover_from_roots(&mut physical, &ordered_dtbs, &module, &dir)?;
        println!("[raw-image] dtb=0x{:x} base=0x{:x} aliases={} fallback_pages={} available={} missing={} {}",
            item.dtb, record.base, item.dtbs.len(), record.fallback_pages,
            record.available_pages, record.missing_pages.len(), record.diagnostics);
        records.push(record);
    }
    recovery::write_report(&dir, &records)?;
    fs::write(dir.join("dumpy_raw_aliases.tsv"), aliases)?;
    println!("[raw] Examined {} DTBs; {} PE candidates; {} unique outputs. Reports: {}",
        candidates.len().min(max_raw_roots), total_images, records.len(), dir.display());
    Ok(())
}

/// Rank candidate address spaces cheaply before reconstructing the entire PE.
/// Test up to 256 evenly spaced pages, including the first and last page.
fn raw_image_coverage_sample(mem: &mut memory::PhysicalMemory<'_>, dtb: u64,
                             base: u64, size: u32) -> usize {
    let pages = (size as usize).div_ceil(4096);
    let samples = pages.min(256);
    let mut score = 0usize;
    for sample in 0..samples {
        let page_index = if samples == 1 { 0 } else { sample * (pages - 1) / (samples - 1) };
        let va = base.saturating_add(page_index as u64 * 4096);
        let mut byte = [0u8; 1];
        if mem.read_virtual(dtb, va, &mut byte, 4).is_ok() { score += 1; }
    }
    score
}

fn recover_kernel_modules(path: &Path, output: &Path) -> std::io::Result<()> {
    let mut file = File::open(path)?;
    if memory::identify(&mut file)? != memory::DumpFormat::WindowsCrashDump {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
            "kernel module recovery currently requires a Windows PAGE/DU64 dump"));
    }
    let info = crashdump::parse(&mut file)?;
    let mut physical = memory::PhysicalMemory::new(&mut file)?;
    let scan = kernel_modules::enumerate(&mut physical, info.dtb, info.kernel_module_list, 4096)?;
    println!("Kernel module list: {} validated; traversal={}", scan.modules.len(),
        if scan.complete { "COMPLETE" } else { "PARTIAL" });
    if let Some(warning) = scan.warning { eprintln!("[module-list] WARNING: {warning}"); }
    let mut records = Vec::with_capacity(scan.modules.len());
    for module in &scan.modules {
        let record = recovery::recover(&mut physical, info.dtb, module, output)?;
        println!("[recover] {} base=0x{:x} available_pages={} missing_pages={} {}",
            record.name, record.base, record.available_pages, record.missing_pages.len(),
            record.diagnostics);
        records.push(record);
    }
    recovery::write_report(output, &records)?;
    println!("Recovery results: {} modules examined, {} files written; reports in {}",
        records.len(), records.iter().filter(|r| r.output.is_some()).count(), output.display());
    Ok(())
}

fn verify_existing_images(dir: &Path) -> std::io::Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut results = String::from("file\tstatus\timports\timport_descriptors\timport_symbols\timport_invalid_references\tresolved_iat_suspected\texports\texport_functions\texport_names\texport_invalid_references\n");
    let mut checked = 0usize;
    let mut invalid = 0usize;
    for entry in entries {
        if !entry.file_type()?.is_file() { continue; }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !file_name.ends_with(".recovered.pe") && !file_name.ends_with(".partial.bin") &&
            !file_name.ends_with(".merged.bin") { continue; }
        let metadata = entry.metadata()?;
        if metadata.len() > MAX_IMAGE as u64 { continue; }
        let image = fs::read(entry.path())?;
        let (status, audit) = match Pe::parse(&image) {
            Ok(pe) => ("parsed", Some(pe_verify::validate(&pe, &image))),
            Err(_) => ("invalid-pe", None),
        };
        checked += 1;
        if status != "parsed" { invalid += 1; }
        let imports = audit.as_ref().map(|a| &a.imports);
        let exports = audit.as_ref().map(|a| &a.exports);
        results.push_str(&format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            file_name.replace('\t', "_").replace('\n', "_").replace('\r', "_"), status,
            imports.map(|a| a.status).unwrap_or("unavailable"),
            imports.map(|a| a.entries).unwrap_or(0),
            imports.map(|a| a.symbols).unwrap_or(0),
            imports.map(|a| a.invalid_references).unwrap_or(0),
            imports.is_some_and(|a| a.resolved_iat_suspected),
            exports.map(|a| a.status).unwrap_or("unavailable"),
            exports.map(|a| a.entries).unwrap_or(0),
            exports.map(|a| a.symbols).unwrap_or(0),
            exports.map(|a| a.invalid_references).unwrap_or(0)));
        if checked % 500 == 0 { println!("[verify] {} files examined...", checked); }
    }
    fs::write(dir.join("dumpy_existing_validation.tsv"), results)?;
    println!("[verify] {} images examined; {} failed PE parsing; report={}",
        checked, invalid, dir.join("dumpy_existing_validation.tsv").display());
    Ok(())
}

/// Recover a PE from a known process DTB and virtual image base.
/// Address-space discovery will be a separate, symbol-aware layer.
fn extract_virtual(path: &Path, dtb: u64, va: u64, output: &Path, levels: u8) -> std::io::Result<()> {
    let mut file = File::open(path)?;
    let mut phys = memory::PhysicalMemory::new(&mut file)?;
    let mut header = vec![0u8; 4096];
    phys.read_virtual(dtb, va, &mut header, levels)?;
    let nt = header.get(0x3c..0x40)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "short DOS header"))?;
    let hpos = nt.checked_add(24 + 60)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "NT offset overflow"))?;
    let hsize = header.get(hpos..hpos + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "NT header beyond first page"))?;
    if hsize > rebuild::MAX_IMAGE || hsize < 64 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid SizeOfHeaders"));
    }
    if hsize > header.len() {
        header.resize(hsize, 0);
        phys.read_virtual(dtb, va, &mut header, levels)?;
    }
    let pe = Pe::parse(&header).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut mapped = vec![0u8; pe.size_of_image];
    phys.read_virtual(dtb, va, &mut mapped, levels)?;
    // We know this source is a mapped virtual image: do not guess between layouts.
    let result = pe.recover_mapped(&mapped)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = output.parent() { fs::create_dir_all(parent)?; }
    fs::write(output, &result)?;
    println!("Recovered {} bytes; {}", result.len(), pe.directory_report(&result));
    Ok(())
}

/// Read just enough data to parse headers first, then retrieve the candidate image.
fn extract_candidate(file: &mut File, offset: u64) -> Result<(Vec<u8>, Pe, &'static str), String> {
    let prefix = io::read_at(file, offset, 64).map_err(|e| e.to_string())?;
    if prefix.len() < 64 { return Err("short DOS header".into()); }
    let nt = u32::from_le_bytes(prefix[0x3c..0x40].try_into().unwrap()) as usize;
    if !(0x40..=1024 * 1024).contains(&nt) { return Err("invalid e_lfanew".into()); }
    // Bound header reads before interpreting any size or section fields.
    let preliminary_size = nt.checked_add(24).and_then(|v| v.checked_add(4096))
        .ok_or("header overflow")?;
    let preliminary = io::read_at(file, offset, preliminary_size).map_err(|e| e.to_string())?;
    let opt_size_at = nt + 4 + 16;
    let sections_at = nt + 4 + 2;
    let opt_size = preliminary.get(opt_size_at..opt_size_at + 2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]) as usize).ok_or("short COFF")?;
    let count = preliminary.get(sections_at..sections_at + 2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]) as usize).ok_or("short COFF")?;
    if count == 0 || count > 96 || opt_size > 4096 { return Err("invalid section table".into()); }
    let table_end = nt + 24 + opt_size + count * 40;
    let headers = io::read_at(file, offset, table_end.max(4096)).map_err(|e| e.to_string())?;
    // SizeOfHeaders may exceed section-table size; read enough to satisfy the parser.
    let hdr_size_offset = nt + 24 + 60;
    let hdr_size = headers.get(hdr_size_offset..hdr_size_offset + 4)
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()) as usize).ok_or("short optional header")?;
    if hdr_size > MAX_IMAGE || hdr_size < table_end { return Err("invalid SizeOfHeaders".into()); }
    let full_header = if headers.len() < hdr_size {
        io::read_at(file, offset, hdr_size).map_err(|e| e.to_string())?
    } else { headers };
    let pe = Pe::parse(&full_header)?;
    let needed = pe.size_of_image.max(pe.raw_file_size);
    let candidate = io::read_at(file, offset, needed).map_err(|e| e.to_string())?;
    let (recovered, layout) = pe.recover(&candidate)?;
    Ok((recovered, pe, layout))
}

fn run(input: &Path, output: &Path) -> std::io::Result<()> {
    let mut probe = File::open(input)?;
    if memory::identify(&mut probe)? == memory::DumpFormat::WindowsCrashDump {
        println!("Windows crash dump: recovering validated kernel modules.");
        inspect_dump(input)?;
        return recover_kernel_modules(input, output);
    }
    fs::create_dir_all(output)?;
    let mut input_file = File::open(input)?;
    let mut found = 0usize;
    let mut valid = 0usize;
    let mut dedup = HashSet::<(u64, usize)>::new();
    io::find_candidates(&mut input_file, |file, offset| {
        found += 1;
        match extract_candidate(file, offset) {
            Ok((image, pe, layout)) => {
                // Deduplicate at the same offset only; distinct files may share PE headers.
                if !dedup.insert((offset, image.len())) { return Ok(()); }
                let path = output.join(format!("extracted_{offset:016x}_{}.exe", if pe.is_64 { "x64" } else { "x86" }));
                let mut destination = File::create(&path)?;
                destination.write_all(&image)?;
                valid += 1;
                println!("[{}] offset=0x{offset:x} layout={} bytes={} {} -> {}",
                    valid, layout, image.len(), pe.directory_report(&image), path.display());
            }
            Err(reason) => {
                if reason != "missing MZ" { eprintln!("Skipping 0x{offset:x}: {reason}"); }
            }
        }
        Ok(())
    })?;
    println!("Finished: {found} MZ candidates, {valid} PE images extracted");
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == "--info" {
        if let Err(e) = inspect_dump(Path::new(&args[2])) { eprintln!("Inspection failed: {e}"); std::process::exit(1); }
        return;
    }
    if args.len() == 3 && args[1] == "--discover" {
        if let Err(e) = discover_dump(Path::new(&args[2])) {
            eprintln!("Discovery failed: {e}"); std::process::exit(1);
        }
        return;
    }
    if args.len() == 3 && args[1] == "--modules" {
        if let Err(e) = list_kernel_modules(Path::new(&args[2])) {
            eprintln!("Module enumeration failed: {e}"); std::process::exit(1);
        }
        return;
    }
    if args.len() == 3 && args[1] == "--processes" {
        if let Err(e) = list_processes(Path::new(&args[2])) {
            eprintln!("Process enumeration failed: {e}"); std::process::exit(1);
        }
        return;
    }
    if args.len() == 4 && args[1] == "--recover-kernel" {
        if let Err(e) = recover_kernel_modules(Path::new(&args[2]), Path::new(&args[3])) {
            eprintln!("Kernel PE recovery failed: {e}"); std::process::exit(1);
        }
        return;
    }
    if args.len() == 3 && args[1] == "--verify-dir" {
        if let Err(e) = verify_existing_images(Path::new(&args[2])) {
            eprintln!("PE verification failed: {e}"); std::process::exit(1);
        }
        return;
    }
    if (4..=7).contains(&args.len()) && args[1] == "--recover-user" {
        let read_limit = |position: usize, maximum: usize, label: &str| -> Option<usize> {
            if position >= args.len() { return None; }
            match args[position].to_string_lossy().parse::<usize>() {
                Ok(n) if n > 0 && n <= maximum => Some(n),
                _ => { eprintln!("Invalid {label}; expected 1..={maximum}"); std::process::exit(2); }
            }
        };
        let pages = read_limit(4, 100_000_000, "max_mapped_pages");
        let roots = read_limit(5, 8192, "max_roots");
        let images = read_limit(6, 4096, "max_images_per_root");
        if let Err(e) = recover_user_images(Path::new(&args[2]), Path::new(&args[3]), pages, roots, images) {
            eprintln!("User PE recovery failed: {e}"); std::process::exit(1);
        }
        return;
    }
    if (args.len() == 6 || args.len() == 7) && args[1] == "--virtual" {
        let dtb = hex_number(&args[3].to_string_lossy());
        let va = hex_number(&args[4].to_string_lossy());
        let levels = if args.len() == 7 { args[6].to_string_lossy().parse::<u8>().unwrap_or(0) } else { 4 };
        match (dtb, va) {
            (Ok(dtb), Ok(va)) => {
                if let Err(e) = extract_virtual(Path::new(&args[2]), dtb, va, Path::new(&args[5]), levels) {
                    eprintln!("Virtual extraction failed: {e}"); std::process::exit(1);
                }
            }
            (d, v) => { eprintln!("Invalid address: {d:?} {v:?}"); std::process::exit(2); }
        }
        return;
    }
    if args.len() != 3 {
        eprintln!("Usage: {} <input_file> <output_directory>", args.first().map(|s| s.to_string_lossy()).unwrap_or_default());
        eprintln!("       --info <dump>");
        eprintln!("       --discover <verified_flat_dump>");
        eprintln!("       --modules <windows_crash_dump>");
        eprintln!("       --processes <windows_crash_dump>");
        eprintln!("       --recover-kernel <windows_crash_dump> <output_directory>");
        eprintln!("       --verify-dir <directory_of_recovered_pes>");
        eprintln!("       --recover-user <dump> <output_directory> [max_mapped_pages] [max_roots] [max_images_per_root]");
        eprintln!("       --virtual <flat_dump> <dtb_hex> <image_base_hex> <output.exe> [4|5]");
        std::process::exit(2);
    }
    if let Err(err) = run(Path::new(&args[1]), Path::new(&args[2])) {
        eprintln!("Extraction failed: {err}");
        std::process::exit(1);
    }
}
