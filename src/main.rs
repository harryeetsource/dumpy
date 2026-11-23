mod crashdump;
mod coherence;
mod discovery;
mod io;
mod kernel_modules;
mod memory;
mod offline_coverage;
mod peb;
mod eprocess;
mod process_aware;
mod processes;
mod pe_verify;
mod recovery;
mod rebuild;
mod user_images;
mod vad;

use rebuild::{Pe, MAX_IMAGE};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Bumped on every report-format change so a log line identifies the build.
pub const VERSION: &str = "0.12.0 (2026-11-23 code-complete tier: headers+code+tables from memory -> .code-complete.pe)";

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

/// A coherent root cohort is needed for tentative flat-physical acquisitions.
/// Matching kernel mappings are evidence, not definitive acquisition metadata.
fn coherent_raw_roots(physical: &mut memory::PhysicalMemory<'_>)
    -> std::io::Result<(Vec<discovery::RootCandidate>, Option<u64>)> {
    let roots = discovery::discover_candidate_roots(physical, 8192)?;
    let kernel_root = roots.iter().max_by_key(|r| (r.kernel_entries, r.user_entries)).map(|r| r.physical);
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
    if candidates.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "coherent roots have no present user mappings; physical layout unverified"));
    }
    Ok((candidates, kernel_root))
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
    let (candidates, kernel_root) = coherent_raw_roots(&mut physical)?;
    physical.kernel_root = kernel_root;
    println!("[raw] Consistent page-table cohort: {} user-capable roots", candidates.len());
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

/// Process-aware recovery: require a structurally verified PEB loader list
/// before treating a user mapping as a loaded image. MZ carving remains the
/// separate --recover-user fallback path. The heavy lifting is in
/// `process_aware`; this resolves roots and the EPROCESS pid/name hints.
fn recover_process_aware(input: &Path, output: &Path, limits: &process_aware::Limits)
                         -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    if limits.page_limit == 0 || limits.root_limit == 0 {
        return Err(Error::new(ErrorKind::InvalidInput,
            "page and root limits must both be positive"));
    }
    let workload = limits.page_limit.checked_mul(limits.root_limit).ok_or_else(||
        Error::new(ErrorKind::InvalidInput, "process scan budget overflow"))?;
    if workload > process_aware::MAX_TOTAL_SCANNED_PAGES {
        return Err(Error::new(ErrorKind::InvalidInput,
            format!("process scan budget {} pages exceeds safe cap {}; use a smaller per-root budget and batched root ranges",
                workload, process_aware::MAX_TOTAL_SCANNED_PAGES)));
    }
    let mut file = File::open(input)?;
    let format = memory::identify(&mut file)?;
    if format == memory::DumpFormat::Minidump {
        return Err(Error::new(ErrorKind::Unsupported,
            "process-aware scanning of MDMP memory streams is not implemented"));
    }
    let crash = if format == memory::DumpFormat::WindowsCrashDump {
        Some(crashdump::parse(&mut file)?)
    } else { None };
    let mut physical = memory::PhysicalMemory::new(&mut file)?;
    let mut pid_by_dtb = HashMap::<u64, (String, String)>::new();
    let (mut roots, kernel_root) = if let Some(info) = &crash {
        let roots = discovery::discover_candidate_roots(&mut physical, 8192)?;
        let kernel_root = roots.iter().max_by_key(|r| (r.kernel_entries, r.user_entries)).map(|r| r.physical);
        if info.dtb != 0 && info.active_process_head != 0 {
            match processes::enumerate(&mut physical, info.dtb, info.active_process_head,
                                        &roots, 65536) {
                Ok(processes) => {
                    if let Some(warning) = &processes.warning {
                        eprintln!("[process-aware] process list partial: {warning}");
                    }
                    for process in processes.processes {
                        for dtb in process.dtb_candidates {
                            pid_by_dtb.insert(dtb,
                                (process.pid_hint.map(|id| id.to_string())
                                    .unwrap_or_else(|| "unknown".into()),
                                 process.image_name_hint.clone()
                                    .unwrap_or_else(|| "unknown".into())));
                        }
                    }
                }
                Err(e) => eprintln!("[process-aware] kernel process list unavailable: {e}"),
            }
        }
        (roots.into_iter().filter(|r| r.user_entries > 0).collect::<Vec<_>>(), kernel_root)
    } else {
        println!("[process-aware] Unknown dump type; using only coherent tentative flat roots");
        coherent_raw_roots(&mut physical)?
    };
    roots.sort_by(|a, b| b.user_entries.cmp(&a.user_entries)
        .then(a.physical.cmp(&b.physical)));
    if limits.root_start >= roots.len() {
        return Err(Error::new(ErrorKind::InvalidInput,
            format!("root start {} exceeds discovered root count {}", limits.root_start, roots.len())));
    }
    drop(physical);
    process_aware::run(input, output, roots.into_iter().map(|r| r.physical).collect(), kernel_root,
        &pid_by_dtb, limits)
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
    let coverage = if let Some(report) = offline_coverage::find_report(dir) {
        let map = offline_coverage::load(&report)?;
        println!("[verify] recovery context: {} records from {}", map.len(), report.display());
        Some(map)
    } else {
        eprintln!("[verify] WARNING: no dumpy_recovery.tsv in this directory or its parent; coverage-aware classifications unavailable");
        None
    };
    let mut results = String::from("file\tstatus\timports\timport_descriptors\timport_symbols\timport_invalid_references\tresolved_iat_suspected\texports\texport_functions\texport_names\texport_invalid_references\timport_bad_names\timport_bad_table_ranges\timport_unterminated_tables\timport_bad_ordinals\texport_bad_names\texport_bad_table_ranges\texport_bad_ordinals\texport_bad_forwarders\tcoverage_found\tmissing_import_pages\tmissing_export_pages\tmissing_file_backed_pages\tfallback_pages\teffective_imports\teffective_exports\texecutable_utf16_ascii_ratio\tincoherent_warning\n");
    let mut checked = 0usize;
    let mut invalid = 0usize;
    let mut matched = 0usize;
    let mut complete_invalid = Vec::<(usize, String)>::new();
    for entry in entries {
        if !entry.file_type()?.is_file() { continue; }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !file_name.ends_with(".recovered.pe") && !file_name.ends_with(".code-complete.pe") &&
            !file_name.ends_with(".partial.bin") && !file_name.ends_with(".merged.bin") { continue; }
        let metadata = entry.metadata()?;
        if metadata.len() > MAX_IMAGE as u64 { continue; }
        let image = fs::read(entry.path())?;
        let (status, audit, profile) = match Pe::parse(&image) {
            Ok(pe) => ("parsed", Some(pe_verify::validate(&pe, &image)),
                coherence::executable_text_profile(&pe, &image)),
            Err(_) => ("invalid-pe", None, coherence::ExecutableTextProfile::default()),
        };
        checked += 1;
        if status != "parsed" { invalid += 1; }
        let imports = audit.as_ref().map(|a| &a.imports);
        let exports = audit.as_ref().map(|a| &a.exports);
        let context = coverage.as_ref().and_then(|map| map.get(&file_name.to_ascii_lowercase()));
        if context.is_some() { matched += 1; }
        let raw_import = imports.map(|a| a.status).unwrap_or("unavailable");
        let raw_export = exports.map(|a| a.status).unwrap_or("unavailable");
        let effective_import = context.map(|c| offline_coverage::effective(raw_import,
            c.missing_import, c.missing_file_backed)).unwrap_or("unknown-coverage");
        let effective_export = context.map(|c| offline_coverage::effective(raw_export,
            c.missing_export, c.missing_file_backed)).unwrap_or("unknown-coverage");
        let incoherent_warning = profile.strongly_text_like() &&
            raw_import == "invalid" && raw_export == "invalid" &&
            context.is_some_and(|c| c.missing_file_backed == 0 && c.fallback_pages == 0);
        if effective_import == "invalid-complete-file-pages" ||
           effective_export == "invalid-complete-file-pages" {
            let errors = imports.map(|a| a.invalid_references).unwrap_or(0)
                .saturating_add(exports.map(|a| a.invalid_references).unwrap_or(0));
            let row = format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                file_name.replace('\t', "_").replace('\n', "_").replace('\r', "_"),
                effective_import, effective_export,
                imports.map(|a| a.bad_names).unwrap_or(0),
                imports.map(|a| a.bad_ordinals).unwrap_or(0),
                imports.map(|a| a.unterminated_tables).unwrap_or(0),
                exports.map(|a| a.bad_names).unwrap_or(0),
                exports.map(|a| a.bad_table_ranges).unwrap_or(0),
                exports.map(|a| a.bad_forwarders).unwrap_or(0),
                context.map(|c| c.fallback_pages).unwrap_or(0));
            complete_invalid.push((errors, row));
        }
        results.push_str(&format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{}\n",
            file_name.replace('\t', "_").replace('\n', "_").replace('\r', "_"), status,
            raw_import,
            imports.map(|a| a.entries).unwrap_or(0),
            imports.map(|a| a.symbols).unwrap_or(0),
            imports.map(|a| a.invalid_references).unwrap_or(0),
            imports.is_some_and(|a| a.resolved_iat_suspected),
            raw_export,
            exports.map(|a| a.entries).unwrap_or(0),
            exports.map(|a| a.symbols).unwrap_or(0),
            exports.map(|a| a.invalid_references).unwrap_or(0),
            imports.map(|a| a.bad_names).unwrap_or(0),
            imports.map(|a| a.bad_table_ranges).unwrap_or(0),
            imports.map(|a| a.unterminated_tables).unwrap_or(0),
            imports.map(|a| a.bad_ordinals).unwrap_or(0),
            exports.map(|a| a.bad_names).unwrap_or(0),
            exports.map(|a| a.bad_table_ranges).unwrap_or(0),
            exports.map(|a| a.bad_ordinals).unwrap_or(0),
            exports.map(|a| a.bad_forwarders).unwrap_or(0),
            context.is_some(), context.map(|c| c.missing_import).unwrap_or(0),
            context.map(|c| c.missing_export).unwrap_or(0),
            context.map(|c| c.missing_file_backed).unwrap_or(0),
            context.map(|c| c.fallback_pages).unwrap_or(0),
            effective_import, effective_export, profile.ratio(), incoherent_warning));
        if checked % 500 == 0 { println!("[verify] {} files examined...", checked); }
    }
    fs::write(dir.join("dumpy_existing_validation.tsv"), results)?;
    complete_invalid.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut triage = String::from("file\teffective_imports\teffective_exports\timport_bad_names\timport_bad_ordinals\timport_unterminated_tables\texport_bad_names\texport_bad_table_ranges\texport_bad_forwarders\tfallback_pages\n");
    for (_, row) in &complete_invalid { triage.push_str(row); }
    fs::write(dir.join("dumpy_complete_invalid.tsv"), triage)?;
    println!("[verify] {} images with invalid tables and complete file-backed coverage; triage={}",
        complete_invalid.len(), dir.join("dumpy_complete_invalid.tsv").display());
    println!("[verify] {} images examined; {} failed PE parsing; {} matched recovery context; report={}",
        checked, invalid, matched, dir.join("dumpy_existing_validation.tsv").display());
    Ok(())
}

/// Extract exactly one virtual-address candidate, retaining the original
/// bytes as well as both candidate PE layouts. This is intentionally a
/// diagnostic operation: no source bytes are rewritten and neither candidate
/// is claimed coherent solely because a page-table walk succeeded.
fn probe_image(input: &Path, dtb: u64, base: u64, output: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    if dtb == 0 || dtb & 0xfff != 0 || base == 0 || base & 0xfff != 0 {
        return Err(Error::new(ErrorKind::InvalidInput,
            "DTB and virtual base must be nonzero, 4096-byte-aligned addresses"));
    }
    let mut file = File::open(input)?;
    let mut memory = memory::PhysicalMemory::new(&mut file)?;
    let mut header = vec![0u8; 4096];
    memory.read_virtual(dtb, base, &mut header, 4)?;
    let nt = header.get(0x3c..0x40)
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()) as usize)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "short DOS header"))?;
    let header_size_at = nt.checked_add(24 + 60)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "NT offset overflow"))?;
    let header_size = header.get(header_size_at..header_size_at.saturating_add(4))
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()) as usize)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "header size outside first page"))?;
    if header_size > rebuild::MAX_IMAGE || header_size < 64 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid SizeOfHeaders"));
    }
    if header_size > header.len() {
        header.resize(header_size, 0);
        memory.read_virtual(dtb, base, &mut header, 4)?;
    }
    let pe = Pe::parse(&header).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    let mut source = vec![0u8; pe.size_of_image];
    let mut unavailable = Vec::<usize>::new();
    for (index, page) in source.chunks_mut(4096).enumerate() {
        let address = base.checked_add(index as u64 * 4096)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "virtual page address overflow"))?;
        if memory.read_virtual(dtb, address, page, 4).is_err() {
            unavailable.push(index);
        }
    }
    let mapped = pe.recover_mapped(&source)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    let raw = source.get(..pe.raw_file_size)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "raw view extends past source image"))?;
    let raw_audit = pe_verify::validate(&pe, raw);
    let mapped_audit = pe_verify::validate(&pe, &mapped);
    let raw_profile = coherence::executable_text_profile(&pe, raw);
    let mapped_profile = coherence::executable_text_profile(&pe, &mapped);
    let (_, selected_layout) = recovery::choose_layout(&pe, &source)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    fs::create_dir_all(output)?;
    for filename in ["source_virtual.bin", "candidate_raw.pe", "candidate_mapped.pe", "probe_report.tsv"] {
        if output.join(filename).exists() {
            return Err(Error::new(ErrorKind::AlreadyExists,
                format!("probe output already exists: {}", output.join(filename).display())));
        }
    }
    // Store raw virtual memory separately so layout hypotheses can be
    // independently tested without resampling the 19+ GB dump.
    fs::write(output.join("source_virtual.bin"), &source)?;
    fs::write(output.join("candidate_raw.pe"), raw)?;
    fs::write(output.join("candidate_mapped.pe"), &mapped)?;
    let mut report = String::from("dtb\tbase\tsize_of_image\tmissing_pages\tmissing_page_indices\tselected_layout\traw_imports\traw_descriptors\traw_symbols\traw_exports\tmapped_imports\tmapped_descriptors\tmapped_symbols\tmapped_exports\traw_executable_utf16_ratio\tmapped_executable_utf16_ratio\n");
    report.push_str(&format!("0x{:x}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{:.4}\n",
        dtb, base, pe.size_of_image, unavailable.len(),
        unavailable.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","),
        selected_layout,
        raw_audit.imports.status, raw_audit.imports.entries, raw_audit.imports.symbols,
        raw_audit.exports.status, mapped_audit.imports.status,
        mapped_audit.imports.entries, mapped_audit.imports.symbols,
        mapped_audit.exports.status, raw_profile.ratio(), mapped_profile.ratio()));
    fs::write(output.join("probe_report.tsv"), report)?;
    println!("[probe] dtb=0x{:x} base=0x{:x} pages={} unreadable={} layout={} report={}",
        dtb, base, pe.size_of_image.div_ceil(4096), unavailable.len(),
        selected_layout, output.join("probe_report.tsv").display());
    Ok(())
}

/// `--eprocess-scan`: find _EPROCESS objects without symbols, anchored on
/// the DTB/PEB pairs an earlier process-aware run validated, and fill the
/// PID / parent / name / time columns of dumpy_processes.tsv in place.
fn eprocess_scan(input: &Path, out_dir: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    let processes_path = out_dir.join("dumpy_processes.tsv");
    let text = fs::read_to_string(&processes_path).map_err(|e|
        Error::new(ErrorKind::NotFound, format!("{}: {e}; run --recover-process-aware first", processes_path.display())))?;
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap_or("").split('\t').collect();
    let col = |name: &str| header.iter().position(|h| *h == name);
    let (Some(c_dtb), Some(c_peb), Some(c_bits)) = (col("dtb"), col("peb"), col("bitness")) else {
        return Err(Error::new(ErrorKind::InvalidData, "dumpy_processes.tsv lacks dtb/peb/bitness columns"));
    };
    let hex = |v: &str| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok();
    let mut anchors = HashMap::<u64, Vec<u64>>::new();
    let rows: Vec<Vec<String>> = lines.map(|l| l.split('\t').map(str::to_owned).collect()).collect();
    for row in &rows {
        let (Some(dtb), Some(peb)) = (row.get(c_dtb).and_then(|v| hex(v)), row.get(c_peb).and_then(|v| hex(v))) else { continue };
        let entry = anchors.entry(dtb).or_default();
        if row.get(c_bits).map(String::as_str) == Some("64") { entry.insert(0, peb); } else { entry.push(peb); }
    }
    let mut file = File::open(input)?;
    let mut physical = memory::PhysicalMemory::new(&mut file)?;
    let roots = discovery::discover_candidate_roots(&mut physical, 8192)?;
    let mut live: std::collections::HashSet<u64> = roots.iter().map(|r| r.physical).collect();
    live.extend(anchors.keys().copied());
    let kernel_root = roots.iter().max_by_key(|r| (r.kernel_entries, r.user_entries)).map(|r| r.physical);
    physical.kernel_root = kernel_root;
    println!("[eprocess] anchors={} live roots={} kernel root={}", anchors.len(), live.len(),
        kernel_root.map(|r| format!("0x{r:x}")).unwrap_or_else(|| "none".into()));
    let report = eprocess::scan(&mut physical, &live, &anchors, kernel_root)?;
    let l = &report.layout;
    let show = |v: Option<i64>| v.map(|d| format!("{:+#x}", d)).unwrap_or_else(|| "?".into());
    println!("[eprocess] PEB distance candidates (distance:support): {}",
        report.peb_delta_candidates.iter().map(|(d, c)| format!("{d:+#x}:{c}")).collect::<Vec<_>>().join(" "));
    for ((d, support, confirmed, ok), attempt) in report.layout_attempts.iter().zip(&report.attempt_layouts) {
        println!("[eprocess]   tried {d:+#x} support={support} confirmed={confirmed} distinct={} layout={} scores: {}",
            attempt.distinct_objects, if *ok { "learned" } else { "incomplete" },
            attempt.scores.iter().map(|(f, c, o)| format!("{f}={c}@{o:+#x}")).collect::<Vec<_>>().join(" "));
    }
    println!("[eprocess] dtb hits={} rejected={} confirmed={} shape candidates={} objects={}",
        report.dtb_hits, report.rejected_hits, l.confirmed_objects, report.shape_candidates, report.processes.len());
    println!("[eprocess] kernel-CR3 evidence (UserDirectoryTableBase offset tried: PML4-shaped/tried, read virtually): {}",
        l.field_evidence.iter().map(|(o, h, t)| format!("{o:#x}:{h}/{t}")).collect::<Vec<_>>().join(" "));
    println!("[eprocess] DISPATCHER_HEADER Type=3 at field-0x28: {}/{} objects (field is KPROCESS.DirectoryTableBase when this holds)",
        l.dispatcher_header_evidence.0, l.dispatcher_header_evidence.1);
    if l.pid.is_none() || l.field_offset != 0x28 { for line in &report.head_dumps { println!("[eprocess]   {line}"); } }
    println!("[eprocess] matched DTB field at EPROCESS+{:#x} ({}); offsets relative to it: peb={} pid={} links={} ppid={} create={} name={}",
        l.field_offset, if l.field_offset == 0x28 { "DirectoryTableBase; KPROCESS size follows from UniqueProcessId" } else { "UserDirectoryTableBase: KVA shadowing, roots are user CR3s" },
        show(l.peb), show(l.pid), show(l.links), show(l.ppid), show(l.create_time), show(l.name));
    if l.pid.is_some() {
        let abs = |v: Option<i64>| v.map(|d| format!("{:#x}", d + l.field_offset as i64)).unwrap_or_else(|| "?".into());
        println!("[eprocess] absolute EPROCESS offsets: Peb={} UniqueProcessId={} ActiveProcessLinks={} InheritedFrom={} CreateTime={} ExitTime={} ImageFileName={}",
            abs(l.peb), abs(l.pid), abs(l.links), abs(l.ppid), abs(l.create_time), abs(l.exit_time), abs(l.name));
    }
    if let Some(dbg) = &report.debug {
        println!("[eprocess] debug: pid {} has {} object(s); offsets differing between the first two (relative to the DTB field): {}",
            dbg.pid, dbg.windows.len(), dbg.differing_offsets.iter().map(|o| format!("{o:+#x}")).collect::<Vec<_>>().join(" "));
        for (phys, bytes) in &dbg.windows {
            let path = out_dir.join(format!("eprocess_debug_0x{phys:x}.bin"));
            fs::write(&path, bytes)?;
            println!("[eprocess] debug: wrote {} ({} bytes, starts at field-0x40)", path.display(), bytes.len());
            // Qword table of the first 0x340 bytes after the field.
            let mut line = String::new();
            for (i, chunk) in bytes[0x40..bytes.len().min(0x380)].chunks(8).enumerate() {
                let v = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
                line.push_str(&format!("{:+#05x}={v:#018x} ", i * 8));
                if i % 4 == 3 { println!("[eprocess]   {line}"); line.clear(); }
            }
            if !line.is_empty() { println!("[eprocess]   {line}"); }
        }
    }
    if report.processes.is_empty() {
        return Err(Error::new(ErrorKind::NotFound, "no EPROCESS objects confirmed; the PEB offset could not be learned"));
    }
    let dups = report.processes.iter().filter(|p| p.duplicate_of.is_some()).count();
    if dups > 0 {
        println!("[eprocess] {} objects are duplicates of another (same PID and CreateTime); physical spacing (bytes:count): {}",
            dups, report.duplicate_spacing.iter().map(|(d, c)| format!("0x{d:x}:{c}")).collect::<Vec<_>>().join(" "));
        if report.duplicate_spacing.first().is_some_and(|(_, c)| *c * 2 > dups) {
            println!("[eprocess]   one spacing dominates: a region of this capture appears twice at different times (acquisition artefact), not kernel-side copies");
        }
    }
    // Objects that only contain a DTB value but do not read as a process
    // (PFN lists, pool copies) go to a sidecar so the main table is the
    // process list. DUMPY_EPROCESS_ALL=1 keeps them in the main table.
    let keep_all = std::env::var_os("DUMPY_EPROCESS_ALL").is_some();
    let lookalikes = report.processes.iter().filter(|p| !p.plausible).count();
    if lookalikes > 0 {
        println!("[eprocess] {lookalikes} dtb-anchored objects do not read as processes (implausible pid/ppid/time/name); {}",
            if keep_all { "kept in dumpy_eprocess.tsv" } else { "written to dumpy_eprocess_lookalikes.tsv" });
    }
    let ep_header = "source\tstate\tpid\tppid\tname\tdtb\tother_dtb\tlive_address_space\tcreate_time_utc\texit_time_utc\tin_active_list\tgroup_linked\teprocess_va\teprocess_phys\tpeb\tpeb_confirmed\tduplicate_of\tplausible\n";
    let mut out = String::from(ep_header);
    let mut side = String::from(ep_header);
    for p in &report.processes {
        let dst = if p.plausible || keep_all { &mut out } else { &mut side };
        // Root found in RAM is not the same as process alive: a freed PML4
        // page keeps its self-reference until reused.
        let state = match (p.exit_time.is_some(), p.live_root, report.layout.exit_time.is_some()) {
            (true, _, _) if p.exit_from_duplicate => "exited(this copy imaged before exit)",
            (true, true, _) => "exited(page tables still in RAM)",
            (true, false, _) => "exited",
            (false, true, _) => "running",
            (false, false, true) => "no-exit-time,root-missing",
            (false, false, false) => "root-missing",
        };
        dst.push_str(&format!("{}\t{}\t{}\t{}\t{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t0x{:x}\t0x{:x}\t{}\t{}\t{}\n",
            p.source, state, p.pid.map(|v| v.to_string()).unwrap_or_default(), p.ppid.map(|v| v.to_string()).unwrap_or_default(),
            p.name.clone().unwrap_or_default().replace('\t', " "), p.dtb,
            p.other_dtb.map(|v| format!("0x{v:x}")).unwrap_or_default(), p.live_root,
            p.create_time.map(eprocess::filetime_iso).unwrap_or_default(),
            p.exit_time.map(eprocess::filetime_iso).unwrap_or_default(),
            p.in_active_list.map(|v| v.to_string()).unwrap_or_default(),
            p.group_linked.map(|v| v.to_string()).unwrap_or_default(),
            p.eprocess_va.map(|v| format!("0x{v:x}")).unwrap_or_default(),
            p.physical.saturating_sub(report.layout.field_offset), p.peb, p.peb_confirmed,
            p.duplicate_of.map(|d| format!("0x{:x}", d.saturating_sub(report.layout.field_offset))).unwrap_or_default(),
            p.plausible));
    }
    fs::write(out_dir.join("dumpy_eprocess.tsv"), &out)?;
    if !keep_all && lookalikes > 0 { fs::write(out_dir.join("dumpy_eprocess_lookalikes.tsv"), &side)?; }
    // Fill pid/name hints in dumpy_processes.tsv and append the new columns.
    let mut by_dtb: HashMap<u64, &eprocess::Process> = HashMap::new();
    for p in report.processes.iter().filter(|p| p.source == "dtb-anchored" && p.plausible) {
        let e = by_dtb.entry(p.dtb).or_insert(p);
        // Prefer the copy that is linked and PEB-confirmed over the first-seen copy.
        let score = |q: &eprocess::Process| (q.in_active_list == Some(true)) as u8 * 2 + q.peb_confirmed as u8;
        if score(p) > score(e) { *e = p; }
    }
    let (c_pid, c_name) = (col("pid_hint"), col("name_hint"));
    let mut rewritten = header.join("\t") + "\tppid\tcreate_time_utc\texit_time_utc\tin_active_list\tstate\n";
    for row in &rows {
        let mut row = row.clone();
        let p = row.get(c_dtb).and_then(|v| hex(v)).and_then(|d| by_dtb.get(&d));
        let state = match p {
            Some(p) if p.exit_time.is_some() => "exited(page tables still in RAM)",
            Some(_) => "running",
            None => "",
        };
        let (ppid, create, exit, linked) = match p {
            Some(p) => {
                if let (Some(c), Some(pid)) = (c_pid, p.pid) { if c < row.len() { row[c] = pid.to_string(); } }
                if let (Some(c), Some(n)) = (c_name, &p.name) { if c < row.len() { row[c] = n.clone(); } }
                (p.ppid.map(|v| v.to_string()).unwrap_or_default(),
                 p.create_time.map(eprocess::filetime_iso).unwrap_or_default(),
                 p.exit_time.map(eprocess::filetime_iso).unwrap_or_default(),
                 p.group_linked.or(p.in_active_list).map(|v| v.to_string()).unwrap_or_default())
            }
            None => (String::new(), String::new(), String::new(), String::new()),
        };
        rewritten.push_str(&format!("{}\t{ppid}\t{create}\t{exit}\t{linked}\t{state}\n", row.join("\t")));
    }
    fs::write(&processes_path, rewritten)?;
    let exited = report.processes.iter().filter(|p| p.exit_time.is_some()).count();
    let dead_scanned = rows.iter().filter(|row| row.get(c_dtb).and_then(|v| hex(v)).and_then(|d| by_dtb.get(&d)).is_some_and(|p| p.exit_time.is_some())).count();
    println!("[eprocess] {dead_scanned} rows of dumpy_processes.tsv belong to exited processes (marked state=exited); exited address spaces usually have no PEB left and so no row");
    // Only PEB-confirmed, non-duplicate objects can be meaningfully "unlinked".
    let unlinked = report.processes.iter().filter(|p| p.group_linked == Some(false) && p.exit_time.is_none() &&
        p.live_root && p.peb_confirmed && p.duplicate_of.is_none()).count();
    let linked = report.processes.iter().filter(|p| p.in_active_list == Some(true)).count();
    println!("[eprocess] ActiveProcessLinks resolved for {linked} objects");
    if report.layout.exit_time.is_none() {
        println!("[eprocess] ExitTime offset not learned ({} plausible objects have no live address space); exit_time_utc is empty, not zero", report.exit_dead_total);
        for l in &report.after_create { println!("[eprocess]   qwords from CreateTime on a dead object: {l}"); }
        if let Some((s, nz, nd, ord, n)) = report.exit_next_qword {
            println!("[eprocess]   CreateTime+8 (usual ExitTime slot): shaped={s}/{n} nonzero={nz} nonzero-among-dead={nd} exit>=create={ord}");
        }
    } else {
        if let Some((s, nz, nd, ord, n)) = report.exit_next_qword {
            println!("[eprocess] CreateTime+8 (usual ExitTime slot): shaped={s}/{n} nonzero={nz} nonzero-among-dead={nd} exit>=create={ord}");
        }
        for l in &report.after_create { println!("[eprocess]   qwords from CreateTime on a dead object: {l}"); }
        println!("[eprocess] ExitTime candidates (delta:nonzero/nonzero-among-dead of {}): {}", report.exit_dead_total,
            report.exit_candidates.iter().map(|(d, nz, nd)| format!("+{d:#x}:{nz}/{nd}")).collect::<Vec<_>>().join(" "));
    }
    println!("[eprocess] wrote {}; exited={} live-but-unlinked(per duplicate group)={}", out_dir.join("dumpy_eprocess.tsv").display(), exited, unlinked);
    Ok(())
}

/// Dump an arbitrary virtual range of one address space, page by page.
/// Non-resident pages are zero-filled and listed in a sidecar TSV so the
/// output is never mistaken for a contiguous capture.
fn dump_range(path: &Path, dtb: u64, va: u64, length: u64, output: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    if length == 0 || length > 1 << 30 {
        return Err(Error::new(ErrorKind::InvalidInput, "length must be 1..=1 GiB"));
    }
    let mut file = File::open(path)?;
    let mut phys = memory::PhysicalMemory::new(&mut file)?;
    let start = va & !0xfff;
    let end = va.checked_add(length).ok_or_else(|| Error::new(ErrorKind::InvalidInput, "range overflow"))?
        .next_multiple_of(4096);
    let mut bytes = vec![0u8; (end - start) as usize];
    let mut missing = String::from("virtual_address\treason\n");
    let mut readable = 0usize;
    let mut transition = 0usize;
    for (i, page) in bytes.chunks_mut(4096).enumerate() {
        let before = phys.transition_translations;
        match phys.read_virtual(dtb, start + i as u64 * 4096, page, 4) {
            Ok(()) => { readable += 1; if phys.transition_translations != before { transition += 1; } }
            Err(e) => missing.push_str(&format!("0x{:x}\t{}\n", start + i as u64 * 4096, e)),
        }
    }
    if let Some(parent) = output.parent() { fs::create_dir_all(parent)?; }
    fs::write(output, &bytes)?;
    let sidecar = output.with_extension("missing.tsv");
    fs::write(&sidecar, missing)?;
    println!("[dump-range] dtb=0x{dtb:x} va=0x{start:x}..0x{end:x} pages={} readable={} transition={} -> {} (missing pages: {})",
        bytes.len() / 4096, readable, transition, output.display(), sidecar.display());
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
    // Virtual memory may contain a mapped image view or a raw file view.
    let (result, layout) = recovery::choose_layout(&pe, &mapped)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = output.parent() { fs::create_dir_all(parent)?; }
    fs::write(output, &result)?;
    println!("Recovered {} bytes; layout={}; {}", result.len(), layout, pe.directory_report(&result));
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
    if args.len() == 2 && args[1] == "--version" {
        println!("dumpy {VERSION}");
        return;
    }
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
    if args.len() == 6 && args[1] == "--probe-image" {
        match (hex_number(&args[3].to_string_lossy()),
               hex_number(&args[4].to_string_lossy())) {
            (Ok(dtb), Ok(base)) => {
                if let Err(e) = probe_image(Path::new(&args[2]), dtb, base, Path::new(&args[5])) {
                    eprintln!("Image probe failed: {e}"); std::process::exit(1);
                }
            }
            (dtb, base) => {
                eprintln!("Invalid probe addresses: dtb={dtb:?}, base={base:?}");
                std::process::exit(2);
            }
        }
        return;
    }
    if (4..=9).contains(&args.len()) &&
        (args[1] == "--recover-process-aware" || args[1] == "--process-scan") {
        let parse_limit = |position: usize, fallback: usize, max: usize| -> usize {
            if position >= args.len() { return fallback; }
            match args[position].to_string_lossy().parse::<usize>() {
                Ok(value) if value > 0 && value <= max => value,
                _ => { eprintln!("Invalid process scan limit at argument {position}"); std::process::exit(2); }
            }
        };
        let page_limit = parse_limit(4, 100_000, 100_000_000);
        let root_limit = parse_limit(5, 8, 8192);
        let root_start = if args.len() >= 7 {
            match args[6].to_string_lossy().parse::<usize>() {
                Ok(index) if index < 8192 => index,
                _ => { eprintln!("Invalid root start index"); std::process::exit(2); }
            }
        } else { 0 };
        let max_recoveries = parse_limit(7, 4096, 1_000_000);
        let max_module_mib = parse_limit(8, MAX_IMAGE / (1024 * 1024), MAX_IMAGE / (1024 * 1024));
        let limits = process_aware::Limits { page_limit, root_limit, root_start,
            max_recoveries, max_module_bytes: max_module_mib as u64 * 1024 * 1024,
            scan_only: args[1] == "--process-scan" };
        if let Err(e) = recover_process_aware(Path::new(&args[2]), Path::new(&args[3]), &limits) {
            eprintln!("Process-aware recovery failed: {e}"); std::process::exit(1);
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
    if args.len() == 4 && args[1] == "--eprocess-scan" {
        if let Err(e) = eprocess_scan(Path::new(&args[2]), Path::new(&args[3])) {
            eprintln!("EPROCESS scan failed: {e}"); std::process::exit(1);
        }
        return;
    }
    if args.len() == 7 && args[1] == "--dump-range" {
        match (hex_number(&args[3].to_string_lossy()), hex_number(&args[4].to_string_lossy()),
               hex_number(&args[5].to_string_lossy())) {
            (Ok(dtb), Ok(va), Ok(len)) => {
                if let Err(e) = dump_range(Path::new(&args[2]), dtb, va, len, Path::new(&args[6])) {
                    eprintln!("Range dump failed: {e}"); std::process::exit(1);
                }
            }
            _ => { eprintln!("Invalid --dump-range arguments; dtb, va and length are hex"); std::process::exit(2); }
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
        eprintln!("       --probe-image <dump> <dtb_hex> <image_base_hex> <output_directory>");
        eprintln!("       --process-scan <dump> <output_dir> [pages_per_root=100000] [roots=8] [root_start=0]");
        eprintln!("       --recover-process-aware <dump> <output_dir> [pages_per_root=100000] [roots=8] [root_start=0] [max_recoveries=4096] [max_module_mib=600]");
        eprintln!("       --recover-user <dump> <output_directory> [max_mapped_pages] [max_roots] [max_images_per_root]");
        eprintln!("       --virtual <flat_dump> <dtb_hex> <image_base_hex> <output.exe> [4|5]");
        eprintln!("       --dump-range <dump> <dtb_hex> <va_hex> <length_hex> <output.bin>");
        eprintln!("       --eprocess-scan <dump> <output_dir>   (after --recover-process-aware; fills PID/name)");
        std::process::exit(2);
    }
    if let Err(err) = run(Path::new(&args[1]), Path::new(&args[2])) {
        eprintln!("Extraction failed: {err}");
        std::process::exit(1);
    }
}
