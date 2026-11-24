//! Two-phase process-aware recovery.
//!
//! Phase 1 scans every selected address space once and records PEB loader
//! lists, MZ-headed images and executable runs. Phase 2 builds a global
//! module identity map `(base, SizeOfImage, header fingerprint)` across all
//! address spaces so that a DLL shared by forty processes is recovered once,
//! then recovers in priority order: main executables, images a validated
//! loader list does *not* claim, shared listed modules, and finally images
//! in address spaces where no PEB was found.
use crate::kernel_modules::KernelModule;
use crate::memory::PhysicalMemory;
use crate::peb::{self, KnownModules};
use crate::rebuild::Pe;
use crate::recovery;
use crate::user_images::{self, ExecutableRegion, ScanResult};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const MAX_TOTAL_SCANNED_PAGES: usize = 8_000_000;
const MAX_ORPHANS_PER_ROOT: usize = 32;
const MAX_ORPHAN_BYTES: u64 = 16 * 1024 * 1024;
const ORPHAN_GAP: u64 = 64 * 1024;

pub struct Limits {
    pub page_limit: usize,
    pub root_limit: usize,
    pub root_start: usize,
    pub max_recoveries: usize,
    pub max_module_bytes: u64,
    pub scan_only: bool,
}

type Key = (u64, u32, u64);

#[derive(Default)]
struct Identity {
    names: BTreeSet<String>,
    /// Address spaces whose PEB loader list records this module.
    listed_in: Vec<u64>,
    /// Address spaces where the MZ scan saw it (listed or not).
    seen_in: Vec<u64>,
    main_exe_of: Vec<u64>,
    /// Listed by a loader list in an earlier batch of this output directory.
    persisted_listed: bool,
}

struct RootScan {
    dtb: u64,
    scan: ScanResult,
}

/// An identity recovered by an earlier batch into the same output directory.
/// `batch`: the root range that recovered this identity (empty if none yet).
struct Persisted { name: String, output: String, listed: bool, batch: String }

const IDENTITIES_FILE: &str = "dumpy_identities.tsv";

fn load_persisted(images_dir: &Path) -> HashMap<Key, Persisted> {
    let mut map = HashMap::new();
    let Ok(text) = fs::read_to_string(images_dir.join(IDENTITIES_FILE)) else { return map };
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 6 { continue; }
        let hex = |v: &str| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok();
        let (Some(base), Some(size), Some(fp)) = (hex(f[0]), f[1].parse::<u32>().ok(), hex(f[2])) else { continue };
        map.insert((base, size, fp), Persisted { name: f[3].to_owned(), output: f[4].to_owned(),
            listed: f[5] == "true", batch: f.get(6).copied().unwrap_or("").to_owned() });
    }
    map
}

/// Concatenate `<stem>.r*.tsv` batch files in `dir` into `<stem>.tsv`,
/// keeping the header of the first. Lets several root ranges share one
/// output directory without overwriting each other.
fn merge_batches(dir: &Path, stem: &str) -> io::Result<()> {
    let mut parts = fs::read_dir(dir)?.filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(&format!("{stem}.r")) && n.ends_with(".tsv")))
        .collect::<Vec<_>>();
    parts.sort();
    let mut merged = String::new();
    for (i, part) in parts.iter().enumerate() {
        let text = fs::read_to_string(part)?;
        let mut lines = text.lines();
        let header = lines.next().unwrap_or("");
        if i == 0 { merged.push_str(header); merged.push('\n'); }
        for line in lines { merged.push_str(line); merged.push('\n'); }
    }
    if !parts.is_empty() { fs::write(dir.join(format!("{stem}.tsv")), merged)?; }
    Ok(())
}

fn fingerprint(mem: &mut PhysicalMemory<'_>, dtb: u64, base: u64) -> u64 {
    let mut header = [0u8; 4096];
    if mem.read_virtual(dtb, base, &mut header, 4).is_err() { return 0; }
    header.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn clean(s: &str) -> String {
    s.chars().map(|c| if matches!(c, '\t' | '\r' | '\n') { ' ' } else { c }).collect()
}

fn coverage_sample(mem: &mut PhysicalMemory<'_>, dtb: u64, base: u64, size: u32) -> usize {
    let pages = (size as usize).div_ceil(4096);
    let samples = pages.min(256);
    let mut score = 0usize;
    for sample in 0..samples {
        let page_index = if samples == 1 { 0 } else { sample * (pages - 1) / (samples - 1) };
        let mut byte = [0u8; 1];
        if mem.read_virtual(dtb, base.saturating_add(page_index as u64 * 4096), &mut byte, 4).is_ok() {
            score += 1;
        }
    }
    score
}

/// Recover one identity once: best-covered address space first, the others
/// as page-level fallbacks (labelled `.merged.bin` by `recover_from_roots`).
fn recover_identity(mem: &mut PhysicalMemory<'_>, key: Key, identity: &Identity,
                    dir: &Path, status: &'static str)
                    -> io::Result<recovery::RecoveryRecord> {
    let (base, size, _) = key;
    // The System address space has no user image mappings of its own; a
    // user page that translates through it is a stale entry, never a source.
    let kernel_root = mem.kernel_root;
    let mut dtbs = identity.listed_in.iter().chain(identity.seen_in.iter())
        .copied().filter(|d| Some(*d) != kernel_root).collect::<Vec<_>>();
    if dtbs.is_empty() { dtbs = identity.listed_in.iter().chain(identity.seen_in.iter()).copied().collect(); }
    dtbs.sort_unstable();
    dtbs.dedup();
    let mut ranked = dtbs.into_iter()
        .map(|dtb| (coverage_sample(mem, dtb, base, size), dtb)).collect::<Vec<_>>();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let ordered = ranked.iter().take(8).map(|(_, dtb)| *dtb).collect::<Vec<_>>();
    let name = identity.names.iter().next().cloned()
        .unwrap_or_else(|| format!("image_{base:x}_h{:016x}", key.2));
    let module = KernelModule { entry: 0, image_base: base, image_size: size,
        name: Some(name), name_status: status };
    let mut record = recovery::recover_from_roots(mem, &ordered, &module, dir)?;
    // Synthetic name: export directory, then the version resource
    // (OriginalFilename/InternalName), of what was just written.
    if identity.names.is_empty() {
        if let Some(path) = record.output.clone() {
            if let Ok(bytes) = fs::read(&path) {
                // Export name, then VERSIONINFO, then the .NET Module name
                // (the assembly's own file name), then the CodeView PDB name.
                let found = Pe::parse(&bytes).ok().and_then(|pe|
                    pe.export_name(&bytes).map(|n| (n, "export name"))
                        .or_else(|| pe.version_name(&bytes).map(|n| (n, "version resource")))
                        .or_else(|| pe.clr_module_name(&bytes).map(|n| {
                            let kind = if n.starts_with('ℛ') { ".NET module, Roslyn script submission" } else { ".NET module" };
                            (n, kind)
                        }))
                        .or_else(|| pe.pdb_info(&bytes).map(|(p, _)| (Pe::pdb_leaf(&p).to_string(), "pdb name"))));
                if let Some((name, source)) = found {
                    let safe: String = name.chars().map(|c|
                        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
                        .take(100).collect();
                    let old = PathBuf::from(&path);
                    let file_name = old.file_name().map(|f| f.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let new = old.with_file_name(format!("{safe}__{file_name}"));
                    if fs::rename(&old, &new).is_ok() {
                        record.output = Some(new.to_string_lossy().into_owned());
                        record.name = format!("{safe} ({source})");
                    }
                }
            }
        }
    }
    Ok(record)
}

/// FNV-1a over one 4 KiB page; None for an all-zero page, which would
/// otherwise match every zero-filled hole in every image.
fn page_hash(page: &[u8]) -> Option<u64> {
    if page.iter().all(|b| *b == 0) { return None; }
    Some(page.iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)))
}

/// Coarse content class of sampled pages: executable mappings that hold
/// text or XML are either data mis-flagged executable or an acquisition
/// smear (PTEs captured at one time, physical pages at another).
fn classify_pages(pages: &[Vec<u8>]) -> &'static str {
    if pages.is_empty() { return "unsampled"; }
    let (mut total, mut zero, mut printable, mut codeish) = (0usize, 0usize, 0usize, 0usize);
    for page in pages {
        for &b in page.iter() {
            total += 1;
            if b == 0 { zero += 1; }
            if (0x20..=0x7e).contains(&b) || matches!(b, b'\r' | b'\n' | b'\t') { printable += 1; }
            // REX prefixes, mov/call/ret/push/pop/lea families: dense in x64 code.
            if matches!(b, 0x48 | 0x4c | 0x8b | 0x89 | 0xe8 | 0xc3 | 0xff | 0x8d | 0x55 | 0x5d | 0x41 | 0x45 | 0xcc | 0x0f) { codeish += 1; }
        }
    }
    if total == 0 { return "unsampled"; }
    let nonzero = total - zero;
    if nonzero * 10 < total { return "mostly-zero"; }
    let printable_ratio = printable as f64 / nonzero as f64;
    let code_ratio = codeish as f64 / nonzero as f64;
    if printable_ratio > 0.75 { "text" }
    else if code_ratio > 0.28 { "code" }
    else if printable_ratio > 0.45 { "text-mixed" }
    else { "binary" }
}

/// Index every page of every executable section of the recovered images so
/// an orphan run can be matched by content: a large-page remap or a copied
/// image has no header at its new address but identical code bytes.
fn build_page_index(sources: &[(String, PathBuf)]) -> HashMap<u64, (String, u32)> {
    const MAX_PAGES: usize = 4_000_000;
    let mut index = HashMap::new();
    for (label, path) in sources {
        let Ok(bytes) = fs::read(path) else { continue };
        let Ok(pe) = Pe::parse(&bytes) else { continue };
        let label = label.clone();
        for section in &pe.sections {
            if section.characteristics & 0x2000_0020 == 0 || section.raw_size == 0 { continue; }
            let mut rva = section.virtual_address.next_multiple_of(4096);
            while rva + 4096 <= section.virtual_address + section.raw_size {
                let at = section.raw_offset + (rva - section.virtual_address);
                let Some(page) = bytes.get(at..at + 4096) else { break };
                if let Some(h) = page_hash(page) {
                    index.entry(h).or_insert_with(|| (label.clone(), rva as u32));
                }
                if index.len() >= MAX_PAGES { return index; }
                rva += 4096;
            }
        }
    }
    index
}

fn report_vad(r: &crate::vad::Report) {
    match (r.root_offset, r.first_proto_offset) {
        (Some(root), Some(fp)) => println!(
            "[vad] EPROCESS.VadRoot=+{root:#x} (trees covering PEB {}/{}, {} nodes) MMVAD.FirstPrototypePte=+{fp:#x} ({}/{} PFN matches); installed for {} of {} address spaces",
            r.root_support.0, r.root_support.1, r.nodes, r.proto_matches.0, r.proto_matches.1, r.installed, r.candidates),
        _ => println!("[vad] VAD resolution off: {}", r.note),
    }
}

pub fn run(input: &Path, output: &Path, roots: Vec<u64>, kernel_root: Option<u64>,
           pid_by_dtb: &HashMap<u64, (String, String)>, limits: &Limits) -> io::Result<()> {
    let mut file = fs::File::open(input)?;
    let mut physical = PhysicalMemory::new(&mut file)?;
    physical.kernel_root = kernel_root;
    println!("[process-aware] kernel root {} (prototype PTEs {})",
        kernel_root.map(|k| format!("0x{k:x}")).unwrap_or_else(|| "unknown".into()),
        if kernel_root.is_some() && physical.allow_transition { "followed" } else { "not followed" });
    fs::create_dir_all(output)?;
    let eprocess_path = output.join("dumpy_eprocess.tsv");
    let mut vad_pending = false;
    if physical.allow_transition {
        if eprocess_path.exists() { report_vad(&crate::vad::setup(&mut physical, output)); }
        else {
            vad_pending = true;
            println!("[vad] {} not found; it will be built from this batch's processes after the scan phase", eprocess_path.display());
        }
    }
    fs::create_dir_all(output)?;
    let end_root = limits.root_start.saturating_add(limits.root_limit).min(roots.len());
    println!("[process-aware] dumpy {} ", crate::VERSION);
    println!("[process-aware] {} roots discovered; scanning indices {}..{} pages/root={} mode={}",
        roots.len(), limits.root_start, end_root, limits.page_limit,
        if limits.scan_only { "discovery-only" } else { "bounded-recovery" });

    let batch = format!("r{}-{}", limits.root_start, end_root);
    // Re-running a finished batch into the same folder would treat its own
    // images as already recovered and overwrite its tables with what is
    // left: refuse unless asked.
    let done_marker = output.join(format!(".dumpy_batch_{batch}.done"));
    if done_marker.exists() && std::env::var_os("DUMPY_RERUN").is_none() {
        println!("[process-aware] batch {batch} already completed in {}; skipping. Use a new output folder, or set DUMPY_RERUN=1 to redo it (its tables are then rebuilt from scratch).",
            output.display());
        return Ok(());
    }
    if done_marker.exists() { println!("[process-aware] DUMPY_RERUN set: redoing batch {batch}"); }
    let shared_dir = output.join("images");
    let mut persisted = load_persisted(&shared_dir);
    if done_marker.exists() {
        // Forced rerun: identities this batch recovered last time are
        // recovered again instead of being treated as done elsewhere.
        let before = persisted.len();
        persisted.retain(|_, p| p.batch != batch);
        println!("[process-aware] {} identities from the previous run of {batch} will be recovered again", before - persisted.len());
    }
    if !persisted.is_empty() {
        println!("[process-aware] {} identities carried over from earlier batches", persisted.len());
    }
    // (DllBase, SizeOfImage) pairs validated anywhere so far: lets a process
    // whose module header pages are not resident still be attributed.
    let mut known: KnownModules = persisted.iter().filter(|(_, p)| p.listed)
        .map(|(k, _)| (k.0, k.1)).collect();

    // ── Phase 1: scan ──────────────────────────────────────────────────
    let mut scans = Vec::<RootScan>::new();
    let mut manifest = String::from("dtb\tpeb\tbitness\timage_base\tpid_hint\tname_hint\tldr\tmodules\tldr_entries\tldr_complete\tskipped_headers\tknown_identity_headers\tpass\treadable_pages\tprivate_rw_pages\tteb_hits\ttransition_pages\ttruncated\twow64_peer\n");
    let mut seen_pebs = HashSet::<u64>::new();
    let mut reject_reasons = HashMap::<&'static str, usize>::new();
    // A WOW64 process has a PEB64 and a PEB32 in the same address space for
    // the same image; report both, cross-linked, rather than as two processes.
    let manifest_row = |manifest: &mut String, dtb: u64, process: &peb::PebProcess, scan: &ScanResult, pass: u8| {
        let (pid, name) = pid_by_dtb.get(&dtb).cloned().unwrap_or_else(|| ("unknown".into(), "unknown".into()));
        let peer = scan.processes.iter().find(|o| o.peb != process.peb && o.image_base == process.image_base &&
            o.bitness != process.bitness).map(|o| format!("0x{:x}", o.peb)).unwrap_or_default();
        manifest.push_str(&format!("0x{dtb:x}\t0x{:x}\t{}\t0x{:x}\t{}\t{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            process.peb, process.bitness, process.image_base, pid, clean(&name), process.ldr,
            process.modules.len(), process.ldr_entries, process.ldr_complete, process.skipped_headers,
            process.modules.iter().filter(|m| m.header_from_known_identity).count(), pass,
            scan.readable_pages, scan.private_rw_pages, scan.teb_hits, scan.transition_pages, scan.truncated, peer));
    };
    for (index, dtb) in roots.iter().enumerate().skip(limits.root_start).take(limits.root_limit) {
        println!("[process-aware] root {}/{} dtb=0x{dtb:x} scanning", index + 1, roots.len());
        let _ = io::stdout().flush();
        let mut scan = user_images::scan_process_aware(&mut physical, *dtb, Some(limits.page_limit), &known)?;
        let mut reasons = scan.peb_reject_reasons.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>();
        reasons.sort();
        println!("[process-aware] dtb=0x{dtb:x} pages={} readable={} missing={} rw_pages={} teb_hits={} peb_candidates={} peb_rejected={} PEBs={} mz_images={} exec_pages={} truncated={} rejects=[{}]",
            scan.mapped_pages_examined, scan.readable_pages, scan.unavailable_pages,
            scan.private_rw_pages, scan.teb_hits, scan.peb_candidates, scan.peb_rejected,
            scan.processes.len(), scan.images.len(), scan.executable_pages, scan.truncated, reasons.join(" "));
        for (k, v) in &scan.peb_reject_reasons { *reject_reasons.entry(k).or_default() += v; }
        // One process can own two roots (kernel/user CR3 under KVA shadowing);
        // the PEB address identifies it, so keep the first root that reached it.
        scan.processes.retain(|p| seen_pebs.insert(p.peb));
        for process in &scan.processes {
            for module in &process.modules {
                if !module.header_from_known_identity { known.insert((module.base, module.size)); }
            }
            manifest_row(&mut manifest, *dtb, process, &scan, 1);
            println!("[process-aware] PEB=0x{:x} image=0x{:x} validated_modules={} ldr_entries={} complete={}",
                process.peb, process.image_base, process.modules.len(), process.ldr_entries, process.ldr_complete);
        }
        scans.push(RootScan { dtb: *dtb, scan });
        fs::write(output.join(format!("dumpy_processes.{batch}.tsv")), &manifest)?;
    }
    // ── Pass 2: retry rejected PEB candidates with the full known set ───
    // A process whose module header pages were all paged out is rejected in
    // pass 1 but validates once other processes have named those bases.
    let mut retried = 0usize;
    let mut rescued = 0usize;
    for root in scans.iter_mut().filter(|r| r.scan.processes.is_empty()) {
        let candidates = root.scan.rejected_pebs.clone();
        for (peb_va, reason) in candidates {
            if !matches!(reason, "image-base-header-unreadable" | "no-module-header-validated" |
                                 "main-image-not-in-validated-modules") { continue; }
            retried += 1;
            let attempt = peb::inspect(&mut physical, root.dtb, peb_va, &known)
                .or_else(|_| peb::inspect32(&mut physical, root.dtb, peb_va, &known));
            if let Ok(process) = attempt {
                if seen_pebs.insert(process.peb) {
                    println!("[process-aware] pass2 dtb=0x{:x} PEB=0x{:x} image=0x{:x} validated_modules={} (known-identity headers={})",
                        root.dtb, process.peb, process.image_base, process.modules.len(),
                        process.modules.iter().filter(|m| m.header_from_known_identity).count());
                    manifest_row(&mut manifest, root.dtb, &process, &root.scan, 2);
                    root.scan.processes.push(process);
                    rescued += 1;
                }
            }
        }
    }
    fs::write(output.join(format!("dumpy_processes.{batch}.tsv")), &manifest)?;
    let mut reasons = reject_reasons.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>();
    reasons.sort();
    println!("[process-aware] pass2: retried={retried} rescued={rescued}; reject reasons overall: {}", reasons.join(" "));
    let found = scans.iter().map(|r| r.scan.processes.len()).sum::<usize>();

    // ── EPROCESS bootstrap for VAD resolution ──────────────────────────
    // First batch into a fresh directory: learn the EPROCESS layout from the
    // PEBs just validated, write dumpy_eprocess.tsv for this and later
    // batches, then switch VAD resolution on before recovery.
    if vad_pending {
        let mut anchors = HashMap::<u64, Vec<u64>>::new();
        for root in &scans {
            for process in &root.scan.processes {
                let entry = anchors.entry(root.dtb).or_default();
                if process.bitness == 64 { entry.insert(0, process.peb); } else { entry.push(process.peb); }
            }
        }
        let mut live: HashSet<u64> = roots.iter().copied().collect();
        live.extend(anchors.keys().copied());
        println!("[vad] building {} from {} anchored address spaces", eprocess_path.display(), anchors.len());
        let _ = io::stdout().flush();
        match crate::eprocess::scan(&mut physical, &live, &anchors, kernel_root) {
            Ok(report) => {
                // Another batch may have written it meanwhile; keep theirs.
                if !eprocess_path.exists() { crate::eprocess::write_tsv(&report, output)?; }
                report_vad(&crate::vad::setup(&mut physical, output));
            }
            Err(e) => println!("[vad] VAD resolution off: EPROCESS scan failed ({e})"),
        }
    }

    // ── Identity map ───────────────────────────────────────────────────
    let mut identities = HashMap::<Key, Identity>::new();
    // (dtb, base) -> key, so per-root lookups do not recompute fingerprints.
    let mut key_of = HashMap::<(u64, u64), Key>::new();
    // (base, size) -> key of the first identity seen with a readable header,
    // so a process whose header page is absent (fingerprint 0) joins it.
    let mut by_base_size = HashMap::<(u64, u32), Key>::new();
    for (k, _) in &persisted { by_base_size.entry((k.0, k.1)).or_insert(*k); }
    let key_for = |physical: &mut PhysicalMemory<'_>, by_base_size: &mut HashMap<(u64, u32), Key>, dtb: u64, base: u64, size: u32| -> Key {
        let fp = fingerprint(physical, dtb, base);
        if fp == 0 { if let Some(k) = by_base_size.get(&(base, size)) { return *k; } }
        let key = (base, size, fp);
        if fp != 0 { by_base_size.entry((base, size)).or_insert(key); }
        key
    };
    for root in &scans {
        for process in &root.scan.processes {
            for module in &process.modules {
                let key = key_for(&mut physical, &mut by_base_size, root.dtb, module.base, module.size);
                key_of.insert((root.dtb, module.base), key);
                let entry = identities.entry(key).or_default();
                if !module.name.starts_with("module_") { entry.names.insert(module.name.clone()); }
                entry.listed_in.push(root.dtb);
                if module.base == process.image_base { entry.main_exe_of.push(root.dtb); }
            }
        }
        for image in &root.scan.images {
            let key = match key_of.get(&(root.dtb, image.base)) {
                Some(k) => *k,
                None => {
                    let k = key_for(&mut physical, &mut by_base_size, root.dtb, image.base, image.size);
                    key_of.insert((root.dtb, image.base), k);
                    k
                }
            };
            identities.entry(key).or_default().seen_in.push(root.dtb);
        }
    }
    // Identities from earlier batches: names for attribution and the known
    // set; `persisted_listed` stands in for a loader-list sighting.
    for (key, p) in &persisted {
        let entry = identities.entry(*key).or_default();
        if !p.name.is_empty() && !p.name.starts_with("image_") { entry.names.insert(p.name.clone()); }
        if p.listed { entry.persisted_listed = true; }
    }
    // Spread PEB names to the same identity's nameless records.
    // ── Unlisted / unattributed images ─────────────────────────────────
    #[derive(Clone)]
    struct Unlisted { dtb: u64, key: Key, pebs_in_root: usize, known_elsewhere: bool,
        rx_pages: u64, in_memory_order: bool, in_init_order: bool, ldr_complete: bool }
    let mut unlisted_rows = Vec::<Unlisted>::new();
    for root in &scans {
        let listed: HashSet<u64> = root.scan.processes.iter()
            .flat_map(|p| p.modules.iter().map(|m| m.base)).collect();
        for image in root.scan.images.iter().filter(|i| !listed.contains(&i.base)) {
            let key = key_of[&(root.dtb, image.base)];
            // Absent from InLoadOrder but present in another list is the
            // classic partial-unlink pattern; worth recording either way.
            let in_memory_order = root.scan.processes.iter().any(|p| p.memory_order_bases.contains(&image.base));
            let in_init_order = root.scan.processes.iter().any(|p| p.init_order_bases.contains(&image.base));
            unlisted_rows.push(Unlisted { dtb: root.dtb, key,
                pebs_in_root: root.scan.processes.len(),
                known_elsewhere: !identities[&key].listed_in.is_empty() || identities[&key].persisted_listed,
                rx_pages: user_images::executable_bytes_in(&root.scan.executable_regions,
                    image.base, image.size as u64) / 4096,
                in_memory_order, in_init_order,
                ldr_complete: root.scan.processes.iter().all(|p| p.ldr_complete) });
        }
    }

    // ── Phase 2: recovery in priority order ────────────────────────────
    let mut done = HashMap::<Key, Option<String>>::new();
    for (key, p) in &persisted {
        if !p.output.is_empty() { done.insert(*key, Some(p.output.clone())); }
    }
    let mut attempted = 0usize;
    let mut records = Vec::new();
    let mut skipped = String::from("base\tsize\tname\treason\n");
    let mut recover = |physical: &mut PhysicalMemory<'_>, key: Key, status: &'static str,
                       attempted: &mut usize, records: &mut Vec<recovery::RecoveryRecord>,
                       skipped: &mut String| -> io::Result<Option<String>> {
        if let Some(existing) = done.get(&key) { return Ok(existing.clone()); }
        let identity = &identities[&key];
        let name = identity.names.iter().next().cloned().unwrap_or_default();
        let reason = if *attempted >= limits.max_recoveries { Some("total recovery cap") }
            else if key.1 as u64 > limits.max_module_bytes { Some("module exceeds size cap") }
            else { None };
        if let Some(reason) = reason {
            skipped.push_str(&format!("0x{:x}\t{}\t{}\t{}\n", key.0, key.1, clean(&name), reason));
            done.insert(key, None);
            return Ok(None);
        }
        *attempted += 1;
        fs::create_dir_all(&shared_dir)?;
        let record = recover_identity(physical, key, identity, &shared_dir, status)?;
        println!("[recover] {} base=0x{:x} size={} available={} missing={} {}",
            record.name, record.base, record.image_size, record.available_pages,
            record.missing_pages.len(), record.diagnostics);
        let out = record.output.clone();
        records.push(record);
        done.insert(key, out.clone());
        Ok(out)
    };
    if !limits.scan_only {
        // 1. Main executables.
        let mut keys = identities.iter().filter(|(_, i)| !i.main_exe_of.is_empty())
            .map(|(k, _)| *k).collect::<Vec<_>>();
        keys.sort_unstable();
        for key in keys { recover(&mut physical, key, "PEB main image", &mut attempted, &mut records, &mut skipped)?; }
        // 2. Images a validated loader list does not claim: the review set.
        let mut keys = unlisted_rows.iter().filter(|u| u.pebs_in_root > 0).map(|u| u.key).collect::<Vec<_>>();
        keys.sort_unstable(); keys.dedup();
        for key in keys { recover(&mut physical, key, "PE header, not in this process's loader list", &mut attempted, &mut records, &mut skipped)?; }
        // 3. Listed shared modules, once each, most-shared first.
        let mut keys = identities.iter().filter(|(_, i)| !i.listed_in.is_empty())
            .map(|(k, i)| (usize::MAX - i.listed_in.len(), *k)).collect::<Vec<_>>();
        keys.sort_unstable();
        for (_, key) in keys { recover(&mut physical, key, "PEB loader-validated", &mut attempted, &mut records, &mut skipped)?; }
        // 4. Images in address spaces with no validated PEB.
        let mut keys = unlisted_rows.iter().filter(|u| u.pebs_in_root == 0).map(|u| u.key).collect::<Vec<_>>();
        keys.sort_unstable(); keys.dedup();
        for key in keys { recover(&mut physical, key, "PE header, no loader list in address space", &mut attempted, &mut records, &mut skipped)?; }
        if !records.is_empty() {
            // Why pages are missing, by mechanism: tells which resolver to build next.
            let mut reasons = HashMap::<String, usize>::new();
            for r in &records { for (_, why) in &r.missing_pages { *reasons.entry(why.clone()).or_default() += 1; } }
            let mut reasons = reasons.into_iter().collect::<Vec<_>>();
            reasons.sort_by(|a, b| b.1.cmp(&a.1));
            let total: usize = reasons.iter().map(|r| r.1).sum();
            println!("[missing-census] {total} missing pages in this batch:");
            for (why, n) in reasons.iter().take(12) {
                println!("[missing-census]   {n:>8} ({:>5.1}%) {why}", 100.0 * *n as f64 / total.max(1) as f64);
            }
            let batch_dir = shared_dir.join(format!("batch_{batch}"));
            recovery::write_report(&batch_dir, &records)?;
            // Merge every batch's reports into images/ so --verify-dir works.
            for stem in ["dumpy_recovery", "dumpy_missing_pages", "dumpy_page_sources",
                         "dumpy_sections", "dumpy_pe_validation", "dumpy_triage"] {
                let mut merged = String::new();
                let mut dirs = fs::read_dir(&shared_dir)?.filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.is_dir()).collect::<Vec<_>>();
                dirs.sort();
                for (i, d) in dirs.iter().enumerate() {
                    let Ok(text) = fs::read_to_string(d.join(format!("{stem}.tsv"))) else { continue };
                    let mut lines = text.lines();
                    let header = lines.next().unwrap_or("");
                    if i == 0 || merged.is_empty() { merged.push_str(header); merged.push('\n'); }
                    for line in lines { merged.push_str(line); merged.push('\n'); }
                }
                if !merged.is_empty() { fs::write(shared_dir.join(format!("{stem}.tsv")), merged)?; }
            }
        }
    }
    fs::write(output.join(format!("dumpy_skipped_modules.{batch}.tsv")), &skipped)?;
    // Persist identities for later batches sharing this output directory.
    {
        let mut text = String::from("base\tsize_of_image\tfingerprint\tname\toutput\tlisted\tbatch\n");
        let mut keys = identities.keys().copied().chain(persisted.keys().copied()).collect::<Vec<_>>();
        keys.sort_unstable(); keys.dedup();
        for key in keys {
            let identity = identities.get(&key);
            let prior = persisted.get(&key);
            let name = identity.and_then(|i| i.names.iter().next().cloned())
                .or_else(|| records.iter().find(|r| r.base == key.0 && r.image_size == key.1 as usize)
                    .map(|r| r.name.split(" (").next().unwrap_or(&r.name).to_owned()))
                .or_else(|| prior.map(|p| p.name.clone())).unwrap_or_default();
            let out = done.get(&key).cloned().flatten()
                .or_else(|| prior.map(|p| p.output.clone())).unwrap_or_default();
            let listed = identity.is_some_and(|i| !i.listed_in.is_empty() || i.persisted_listed)
                || prior.is_some_and(|p| p.listed);
            let owner = if done.contains_key(&key) { batch.clone() }
                else { prior.map(|p| p.batch.clone()).unwrap_or_default() };
            text.push_str(&format!("0x{:x}\t{}\t0x{:016x}\t{}\t{}\t{}\t{}\n", key.0, key.1, key.2, clean(&name), out, listed, owner));
        }
        fs::create_dir_all(&shared_dir)?;
        fs::write(shared_dir.join(IDENTITIES_FILE), text)?;
    }

    // Recovered-file names (export/version resource) for identities the
    // loader lists never named.
    let recovered_name: HashMap<Key, String> = records.iter().filter_map(|r| {
        let key = identities.iter().find(|(k, _)| k.0 == r.base && k.1 as usize == r.image_size)
            .map(|(k, _)| *k)?;
        (!r.name.starts_with("image_")).then(|| (key, r.name.clone()))
    }).chain(persisted.iter().filter(|(_, p)| !p.name.is_empty() && !p.name.starts_with("image_"))
        .map(|(k, p)| (*k, p.name.clone()))).collect();
    let mut modules_report = String::from("dtb\tpeb\tbase\tsize_of_image\tname\tldr_lists\theader_source\tfingerprint\tlisted_in_roots\trx_pages\tldr_complete\n");
    for root in &scans {
        for process in &root.scan.processes {
            for module in &process.modules {
                let key = key_of[&(root.dtb, module.base)];
                let identity = &identities[&key];
                let name = if module.name.starts_with("module_") {
                    identity.names.iter().next().cloned()
                        .or_else(|| recovered_name.get(&key).cloned())
                        .unwrap_or_else(|| module.name.clone())
                } else { module.name.clone() };
                let lists = format!("load{}{}",
                    if module.in_memory_order { ",mem" } else { "" },
                    if module.in_init_order { ",init" } else { "" });
                modules_report.push_str(&format!("0x{:x}\t0x{:x}\t0x{:x}\t{}\t{}\t{}\t{}\t0x{:016x}\t{}\t{}\t{}\n",
                    root.dtb, process.peb, module.base, module.size, clean(&name), lists,
                    if module.header_from_known_identity { "known-identity" } else { "header" }, key.2,
                    identity.listed_in.len(),
                    user_images::executable_bytes_in(&root.scan.executable_regions, module.base,
                        module.size as u64) / 4096, process.ldr_complete));
            }
        }
    }
    fs::write(output.join(format!("dumpy_modules.{batch}.tsv")), &modules_report)?;


    // Same 4 KiB header seen at a different base in a *named* identity:
    // a relocated copy, a second mapping, or a header-only copy of a known
    // image. Looked up by (SizeOfImage, fingerprint) alone.
    let mut by_header = HashMap::<(u32, u64), Vec<(u64, String)>>::new();
    for (key, identity) in &identities {
        if key.2 == 0 { continue; }
        let name = identity.names.iter().next().cloned().or_else(|| recovered_name.get(key).cloned());
        if let Some(name) = name { by_header.entry((key.1, key.2)).or_default().push((key.0, name)); }
    }
    let same_header_as = |key: &Key| -> String {
        by_header.get(&(key.1, key.2)).map(|v| v.iter().filter(|(b, _)| *b != key.0)
            .map(|(b, n)| format!("{n}@0x{b:x}")).take(3).collect::<Vec<_>>().join("|")).unwrap_or_default()
    };
    let pe_summary = |key: &Key| -> String {
        let Some(Some(path)) = done.get(key) else { return String::new() };
        let Ok(bytes) = fs::read(path) else { return String::new() };
        Pe::parse(&bytes).map(|pe| pe.summary(&bytes)).unwrap_or_default()
    };
    // Review order: code mapped in a PEB-validated process whose loader list
    // was walked completely first; "unlisted" with an incomplete list is weak
    // evidence (the entry may simply sit behind a non-resident page), so
    // those rows are labelled and sorted after.
    let mut unlisted = String::from("dtb\tbase\tsize_of_image\tpebs_in_root\tattribution\trx_pages\taligned_64k\tldr_lists\tknown_elsewhere\tknown_name\tsame_header_as\tfingerprint\tpe_summary\toutput\n");
    unlisted_rows.sort_by_key(|u| (u.pebs_in_root == 0, !u.ldr_complete, u.rx_pages == 0, u.known_elsewhere, u.dtb, u.key.0));
    for u in &unlisted_rows {
        let identity = &identities[&u.key];
        let mut names = identity.names.iter().cloned().collect::<Vec<_>>();
        if names.is_empty() { names.extend(recovered_name.get(&u.key).cloned()); }
        let lists = match (u.in_memory_order, u.in_init_order) {
            (false, false) => "none".to_owned(),
            (m, i) => format!("{}{}", if m { "mem" } else { "" }, if i { if m { ",init" } else { "init" } } else { "" }),
        };
        let attribution = if u.pebs_in_root == 0 { "unattributed" }
            else if u.ldr_complete { "unlisted" } else { "unlisted-ldr-incomplete" };
        unlisted.push_str(&format!("0x{:x}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t0x{:016x}\t{}\t{}\n",
            u.dtb, u.key.0, u.key.1, u.pebs_in_root, attribution,
            u.rx_pages, u.key.0 & 0xffff == 0, lists, u.known_elsewhere, names.join("|"),
            same_header_as(&u.key), u.key.2, pe_summary(&u.key),
            done.get(&u.key).cloned().flatten().unwrap_or_default()));
    }
    fs::write(output.join(format!("dumpy_unlisted_images.{batch}.tsv")), &unlisted)?;

    // Content index of everything recovered, for orphan attribution.
    let mut index_sources = records.iter().filter_map(|r| r.output.as_ref().map(|o|
        (r.name.split(" (").next().unwrap_or(&r.name).to_owned(), PathBuf::from(o)))).collect::<Vec<_>>();
    for p in persisted.values().filter(|p| !p.output.is_empty()) {
        index_sources.push((p.name.clone(), PathBuf::from(&p.output)));
    }
    let page_index = if limits.scan_only { HashMap::new() } else { build_page_index(&index_sources) };
    println!("[process-aware] page index: {} executable pages from {} images",
        page_index.len(), index_sources.len());

    // ── Orphan executable regions ──────────────────────────────────────
    // Every known identity's VA range, applied to every address space:
    // system DLL bases are per-boot constants, so a run inside a range that
    // another process lists is almost always that DLL with its header page
    // not resident here. It stays in the report, attributed, not removed.
    let mut known_ranges = identities.iter().map(|(k, i)| (k.0, k.1 as u64,
        i.names.iter().next().cloned().unwrap_or_else(|| format!("image_{:x}", k.0))))
        .collect::<Vec<_>>();
    known_ranges.sort_unstable();
    let attribute = |region: &ExecutableRegion| -> Option<String> {
        let at = known_ranges.partition_point(|(base, _, _)| *base <= region.start);
        at.checked_sub(1).and_then(|i| known_ranges.get(i)).and_then(|(base, size, name)| {
            (region.start < base.saturating_add(*size)).then(|| format!("{name}@0x{base:x}"))
        })
    };
    // Summarise content matches as "name+0xrva (k/n)" for the dominant image.
    let summarise = |hits: &HashMap<String, (u32, usize)>, sampled: usize| -> String {
        let Some((name, (rva, count))) = hits.iter().max_by_key(|(_, (_, c))| *c) else { return String::new() };
        format!("{name}+0x{rva:x} ({count}/{sampled})")
    };
    let all_dtbs = scans.iter().map(|r| r.dtb).collect::<Vec<_>>();
    let capture_end = physical.segments().iter().map(|s| s.physical + s.length).max().unwrap_or(u64::MAX);
    // Managed/JIT runtimes allocate executable heaps with no PE header; name
    // the runtime so such regions can be triaged as expected rather than foreign.
    let runtime_hint = |root: &RootScan| -> String {
        let mut hints = BTreeSet::new();
        for process in &root.scan.processes {
            let main_size = process.modules.iter().find(|m| m.base == process.image_base).map(|m| m.size).unwrap_or(0);
            for module in &process.modules {
                let n = module.name.to_ascii_lowercase();
                let hint = if n == "coreclr.dll" || n == "hostpolicy.dll" || n == "clrjit.dll" || n == "system.private.corelib.dll" { "dotnet-core" }
                    else if n == "clr.dll" || n == "mscorwks.dll" || n == "mscoreei.dll" { "dotnet-framework" }
                    else if n.starts_with("system.") && n.ends_with(".dll") { "dotnet" } // self-contained apps: no coreclr.dll
                    else if n == "msedge.dll" || n == "chrome.dll" || n == "msedgewebview2.exe" { "chromium-v8" }
                    else if n.ends_with(".node") || n == "ffmpeg.dll" && main_size > 64 << 20 { "electron-v8" }
                    else if n == "jscript9.dll" || n == "chakra.dll" || n == "chakracore.dll" { "jscript" }
                    else if n == "jvm.dll" { "jvm" } else if n.starts_with("umppc") { "crowdstrike-umppc" }
                    else if n == "libcef.dll" { "cef-v8" } else { continue };
                hints.insert(hint);
            }
        }
        // "dotnet" is implied by the more specific tags.
        if hints.contains("dotnet-core") || hints.contains("dotnet-framework") { hints.remove("dotnet"); }
        hints.into_iter().collect::<Vec<_>>().join(",")
    };
    let mut orphans = String::from("dtb\tpebs_in_root\tprocess_runtime\tstart\tspan_bytes\texecutable_pages\treadable_pages\tlarge_page\tfirst_page_physical\tcontent_class\toverlaps_known_module\tcontent_match\tprobable_base\tprobable_base_status\toutput\n");
    for root in &scans {
        let huge = root.scan.huge_mappings.clone();
        let runtime = runtime_hint(root);
        let covered = root.scan.processes.iter()
            .flat_map(|p| p.modules.iter().map(|m| (m.base, m.size as u64)))
            .chain(root.scan.images.iter().map(|i| (i.base, i.size as u64)))
            .collect::<Vec<_>>();
        // Subtract first, then merge: merging first would pull the data
        // pages between two known images into an "executable" span.
        let orphan = user_images::orphan_executable_regions(&root.scan.executable_regions, &covered);
        let mut regions = user_images::merge_gaps(&orphan, ORPHAN_GAP)
            .into_iter().map(|r| {
                let exec_bytes = orphan.iter().filter(|o| o.start >= r.start &&
                    o.start < r.start + r.length).map(|o| o.length).sum::<u64>();
                let a = attribute(&r);
                (r, a, exec_bytes)
            }).collect::<Vec<_>>();
        regions.sort_by(|a, b| a.1.is_some().cmp(&b.1.is_some()).then(b.2.cmp(&a.2)));
        let mut written = 0usize;
        let unlisted_dir = output.join(format!("dtb_{:x}_orphans", root.dtb));
        for (region, attribution, exec_bytes) in &regions {
            let pages = region.length / 4096;
            let mut readable = 0u64;
            let mut path = String::new();
            let mut hits = HashMap::<String, (u32, usize)>::new();
            let mut sampled = 0usize;
            let mut classified = Vec::<Vec<u8>>::new();
            let mut consider = |page: &[u8], hits: &mut HashMap<String, (u32, usize)>| {
                sampled += 1;
                if classified.len() < 16 { classified.push(page.to_vec()); }
                if let Some((name, rva)) = page_hash(page).and_then(|h| page_index.get(&h)) {
                    let e = hits.entry(name.clone()).or_insert((*rva, 0));
                    e.1 += 1;
                }
            };
            let dump = !limits.scan_only && attribution.is_none() && written < MAX_ORPHANS_PER_ROOT &&
                region.length <= MAX_ORPHAN_BYTES;
            if dump {
                let mut bytes = vec![0u8; region.length as usize];
                for (i, page) in bytes.chunks_mut(4096).enumerate() {
                    if physical.read_virtual(root.dtb, region.start + i as u64 * 4096, page, 4).is_ok() {
                        readable += 1;
                        consider(page, &mut hits);
                    }
                }
                fs::create_dir_all(&unlisted_dir)?;
                let file = unlisted_dir.join(format!("orphan_exec_0x{:016x}_{}.bin", region.start, region.length));
                fs::write(&file, &bytes)?;
                path = file.to_string_lossy().into_owned();
                written += 1;
            } else {
                // Not dumped: still sample up to 64 evenly spaced pages for
                // readability and (when unattributed) content matching.
                let samples = pages.min(64);
                for s in 0..samples {
                    let i = if samples <= 1 { 0 } else { s * (pages - 1) / (samples - 1) };
                    let mut page = [0u8; 4096];
                    if physical.read_virtual(root.dtb, region.start + i * 4096, &mut page, 4).is_ok() {
                        readable += 1;
                        consider(&page, &mut hits);
                    }
                }
                if samples < pages && readable > 0 {
                    // Scale the sampled readability estimate to the full span.
                    readable = readable * pages / samples;
                }
            }
            let large_page = huge.iter().any(|(va, len)| region.start < va + len && *va < region.start + region.length);
            // Physical address behind the first page: equal across processes
            // means a shared section; different with identical content means
            // the capture is not internally consistent.
            let first_physical = match physical.translate(root.dtb, region.start, 4) {
                Ok(p) if p >= capture_end => format!("0x{p:x} (beyond capture: stale PTE)"),
                Ok(p) => format!("0x{p:x}"),
                Err(_) => String::new(),
            };
            let content_class = classify_pages(&classified);
            // A run starting one page past a 64 KiB boundary is usually a DLL
            // whose header page is NX or not resident here.
            let (probable_base, probable_status) = if region.start & 0xffff == 0x1000 && attribution.is_none() {
                let candidate = region.start - 0x1000;
                let status = if let Some((k, i)) = identities.iter().find(|(k, _)| k.0 == candidate) {
                    format!("known:{}", i.names.iter().next().cloned().unwrap_or_else(|| format!("image_{:x}", k.0)))
                } else {
                    let mut two = [0u8; 2];
                    let here = physical.read_virtual(root.dtb, candidate, &mut two, 4);
                    if here.is_ok() && &two == b"MZ" { "mz-here-rejected-header".to_owned() }
                    else {
                        let elsewhere = all_dtbs.iter().filter(|d| **d != root.dtb).find(|d|
                            physical.read_virtual(**d, candidate, &mut two, 4).is_ok() && &two == b"MZ");
                        match elsewhere {
                            Some(d) => format!("mz-in-dtb-0x{d:x}"),
                            None if here.is_ok() => "no-mz".to_owned(),
                            None => "unreadable".to_owned(),
                        }
                    }
                };
                (format!("0x{candidate:x}"), status)
            } else { (String::new(), String::new()) };
            orphans.push_str(&format!("0x{:x}\t{}\t{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                root.dtb, root.scan.processes.len(), runtime, region.start, region.length,
                exec_bytes / 4096, readable, large_page, first_physical, content_class,
                attribution.clone().unwrap_or_default(),
                summarise(&hits, sampled), probable_base, probable_status, path));
        }
        if !regions.is_empty() {
            println!("[orphan-exec] dtb=0x{:x} regions={} unattributed={} executable_pages={}",
                root.dtb, regions.len(), regions.iter().filter(|(_, a, _)| a.is_none()).count(),
                regions.iter().map(|(_, _, e)| e / 4096).sum::<u64>());
        }
    }
    fs::write(output.join(format!("dumpy_orphan_executable.{batch}.tsv")), orphans)?;
    for stem in ["dumpy_processes", "dumpy_modules", "dumpy_unlisted_images", "dumpy_orphan_executable", "dumpy_skipped_modules"] {
        merge_batches(output, stem)?;
    }
    fs::write(&done_marker, format!("{}\n", crate::VERSION))?;

    println!("[process-aware] validated PEB processes={} identities={} recovered={} skipped={} report={}",
        found, identities.len(), records.iter().filter(|r| r.output.is_some()).count(),
        skipped.lines().count().saturating_sub(1), output.join("dumpy_processes.tsv").display());
    if found == 0 {
        eprintln!("[process-aware] no validated PEB loader lists were readable; nothing attributed. Try a larger page budget or confirm the acquisition includes user pages.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::classify_pages;
    #[test]
    fn classifies_text_code_and_zero_pages() {
        let text = vec![b"<Resolve package=\"Package_for_RollupFix~31bf3856ad364e35~amd64\"/>\r\n".repeat(60)];
        assert_eq!(classify_pages(&text), "text");
        let mut code = Vec::new();
        for _ in 0..300 { code.extend_from_slice(&[0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x20, 0xe8, 0x10, 0x00, 0x00, 0x00, 0xc3, 0xcc]); }
        assert_eq!(classify_pages(&[code]), "code");
        assert_eq!(classify_pages(&[vec![0u8; 4096]]), "mostly-zero");
        assert_eq!(classify_pages(&[]), "unsampled");
    }
}
