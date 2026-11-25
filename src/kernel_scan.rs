//! Kernel-space extraction without symbols.
//!
//! 1. Walk the kernel half of a page-table root and list every mapped leaf
//!    (4 KiB, 2 MiB, 1 GiB) with its effective NX and writable bits.
//! 2. Find PE headers at page starts. One of them exports its own name as
//!    ntoskrnl (or a variant); its export `PsLoadedModuleList` is the head of
//!    the loaded-module list, which `kernel_modules::enumerate` walks. For
//!    crash dumps the header already gives the list head.
//! 3. Recover every listed module (same tiers and naming as user images).
//! 4. Headers outside every listed module whose code pages are mapped
//!    executable are unlisted kernel images: recovered and reported.
//!    Headers with no executable mapping are data (file-cache views, pool
//!    copies) and only counted.
//! 5. Executable kernel pages outside every image are dumped as raw regions
//!    and classified by content.

use crate::kernel_modules::{self, KernelModule};
use crate::memory::PhysicalMemory;
use crate::process_aware;
use crate::recovery::{self, RecoveryRecord};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const PFN: u64 = 0x000f_ffff_ffff_f000;
const MAX_LEAVES: usize = 24_000_000;
const MAX_IMAGE: u32 = 512 * 1024 * 1024;
const MAX_ORPHAN_REGIONS: usize = 4096;
const MAX_ORPHAN_REGION_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ORPHAN_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Leaf { pub va: u64, pub phys: u64, pub size: u32, pub exec: bool, pub writable: bool }

fn canonical(va: u64) -> u64 { if va & (1 << 47) != 0 { va | 0xffff_0000_0000_0000 } else { va } }

#[derive(Default)]
pub struct WalkStats {
    /// Tables reached a second time through another entry (shared or
    /// self-referencing tables), not descended into again.
    pub aliased_tables: usize,
    /// Pages referenced as tables whose present entries mostly point outside
    /// the capture or carry reserved bits: not page tables.
    pub rejected_tables: usize,
    /// (PML4 slot, leaves, executable leaves) for slots with leaves.
    pub slots: Vec<(usize, usize, usize)>,
}

/// Every present leaf in PML4 slots 256..511 of `root` (4-level paging),
/// sorted by VA. The self-reference slot (page tables) is skipped, every
/// table is descended into once, and pages that do not look like page tables
/// are rejected, so shared or bogus tables cannot multiply the walk.
pub fn walk_kernel(mem: &mut PhysicalMemory<'_>, root: u64) -> io::Result<(Vec<Leaf>, WalkStats)> {
    let root = root & PFN;
    let mut leaves = Vec::new();
    let mut stats = WalkStats::default();
    let mut seen = HashSet::new();
    seen.insert(root);
    let mut table = vec![0u8; 4096];
    mem.read_exact_at(root, &mut table)?;
    let pml4: Vec<u64> = table.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    let end = mem.physical_end();
    for i in 256..512usize {
        let e = pml4[i];
        if e & 1 == 0 || e & PFN == root { continue; }
        let before = leaves.len();
        walk_level(mem, e, 3, canonical((i as u64) << 39), e >> 63 != 0, e & 2 != 0, &mut leaves, &mut seen, &mut stats, end);
        let added = &leaves[before..];
        if !added.is_empty() {
            stats.slots.push((i, added.len(), added.iter().filter(|l: &&Leaf| l.exec).count()));
        }
        if leaves.len() >= MAX_LEAVES { break; }
    }
    leaves.sort_by_key(|l| l.va);
    Ok((leaves, stats))
}

/// A page whose present entries mostly name frames outside the capture, or
/// set reserved high bits, is data rather than a page table.
fn looks_like_table(t: &[u8; 4096], end: u64) -> bool {
    let (mut present, mut bad) = (0usize, 0usize);
    for c in t.chunks_exact(8) {
        let e = u64::from_le_bytes(c.try_into().unwrap());
        if e & 1 == 0 { continue; }
        present += 1;
        // Bits 52..62 are ignored/protection-key bits; 51..48 must be zero
        // on machines with <= 48-bit physical addressing.
        if e & 0x000f_0000_0000_0000 != 0 || (end != 0 && (e & PFN) >= end.saturating_add(1 << 30)) { bad += 1; }
    }
    bad * 4 <= present
}

#[allow(clippy::too_many_arguments)]
fn walk_level(mem: &mut PhysicalMemory<'_>, parent: u64, level: u8, va: u64, nx: bool, w: bool, out: &mut Vec<Leaf>,
              seen: &mut HashSet<u64>, stats: &mut WalkStats, end: u64) {
    let phys = parent & PFN;
    if !seen.insert(phys) { stats.aliased_tables += 1; return; }
    let mut table = [0u8; 4096];
    if mem.read_exact_at(phys, &mut table).is_err() { return; }
    if !looks_like_table(&table, end) { stats.rejected_tables += 1; return; }
    let shift = 12 + 9 * (level as u64 - 1);
    for i in 0..512usize {
        let e = u64::from_le_bytes(table[i * 8..i * 8 + 8].try_into().unwrap());
        // Transition PTE (Valid=0, Transition=1, Prototype=0): the page is on
        // the standby/modified list and still in RAM. Kept as a
        // non-executable leaf so headers on such pages are found.
        if e & 1 == 0 {
            if level == 1 && e & (1 << 11) != 0 && e & (1 << 10) == 0 && e & PFN != 0 {
                out.push(Leaf { va: va | ((i as u64) << shift), phys: e & PFN, size: 4096, exec: false, writable: false });
            }
            continue;
        }
        let child_va = va | ((i as u64) << shift);
        let (cnx, cw) = (nx || e >> 63 != 0, w && e & 2 != 0);
        let large = level > 1 && e & 0x80 != 0;
        if level == 1 || large {
            let size = 1u64 << shift;
            out.push(Leaf { va: child_va, phys: e & PFN & !(size - 1), size: size as u32, exec: !cnx, writable: cw });
            if out.len() >= MAX_LEAVES { return; }
        } else {
            walk_level(mem, e, level - 1, child_va, cnx, cw, out, seen, stats, end);
            if out.len() >= MAX_LEAVES { return; }
        }
    }
}

fn leaf_for(leaves: &[Leaf], va: u64) -> Option<&Leaf> {
    let i = leaves.partition_point(|l| l.va <= va);
    leaves.get(i.checked_sub(1)?).filter(|l| va < l.va + l.size as u64)
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> { Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?)) }
fn u32_at(b: &[u8], i: usize) -> Option<u32> { Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?)) }

/// Fields of a PE header page needed here.
#[derive(Clone, Debug)]
pub struct Header {
    pub base: u64,
    pub size_of_image: u32,
    pub entry: u32,
    pub export_rva: u32,
    /// (rva, virtual size) of sections flagged executable.
    pub exec_sections: Vec<(u32, u32)>,
}

fn parse_header(base: u64, b: &[u8]) -> Option<Header> {
    if b.get(..2)? != b"MZ" { return None; }
    let nt = u32_at(b, 0x3c)? as usize;
    if !(0x40..=0x300).contains(&nt) || b.get(nt..nt + 4)? != b"PE\0\0" { return None; }
    let machine = u16_at(b, nt + 4)?;
    if !matches!(machine, 0x8664 | 0x14c | 0xaa64) { return None; }
    let sections = u16_at(b, nt + 6)? as usize;
    let opt_size = u16_at(b, nt + 20)? as usize;
    let opt = nt + 24;
    let magic = u16_at(b, opt)?;
    if !matches!(magic, 0x10b | 0x20b) || !(1..=96).contains(&sections) { return None; }
    let size_of_image = u32_at(b, opt + 56)?;
    if !(0x1000..=MAX_IMAGE).contains(&size_of_image) { return None; }
    let entry = u32_at(b, opt + 16)?;
    let dirs = opt + if magic == 0x20b { 112 } else { 96 };
    let export_rva = u32_at(b, dirs).unwrap_or(0);
    let mut exec_sections = Vec::new();
    for s in 0..sections {
        let at = opt + opt_size + s * 40;
        let (vsize, rva, ch) = (u32_at(b, at + 8)?, u32_at(b, at + 12)?, u32_at(b, at + 36)?);
        if ch & 0x2000_0000 != 0 && vsize > 0 { exec_sections.push((rva, vsize)); }
    }
    Some(Header { base, size_of_image, entry, export_rva, exec_sections })
}

/// True when some page of the image's code is mapped executable.
fn code_is_executable(leaves: &[Leaf], h: &Header) -> bool {
    let mut probes = vec![h.entry];
    for (rva, size) in &h.exec_sections {
        for k in 0..(size.div_ceil(4096)).min(8) { probes.push(rva + k * 4096); }
    }
    probes.into_iter().filter(|r| *r != 0 && *r < h.size_of_image)
        .any(|rva| leaf_for(leaves, h.base + rva as u64).is_some_and(|l| l.exec))
}

/// PE headers at the start of every 4 KiB leaf and every large-page leaf.
/// Reads are issued in physical order so the OS read-ahead helps.
pub fn find_headers(mem: &mut PhysicalMemory<'_>, leaves: &[Leaf]) -> Vec<Header> {
    let mut order: Vec<(u64, u64)> = leaves.iter().filter(|l| l.size <= 2 << 20).map(|l| (l.phys, l.va)).collect();
    order.sort_unstable();
    let mut found = Vec::new();
    // The whole header page: large images (ntoskrnl has 30+ sections)
    // carry section tables well past the first 0x400 bytes.
    let mut buf = [0u8; 0x1000];
    for (phys, va) in order {
        let mut mz = [0u8; 2];
        if mem.read_exact_at(phys, &mut mz).is_err() || mz != *b"MZ" { continue; }
        if mem.read_exact_at(phys, &mut buf).is_err() { continue; }
        if let Some(h) = parse_header(va, &buf) { found.push(h); }
    }
    found.sort_by_key(|h| h.base);
    found.dedup_by_key(|h| h.base);
    found
}

fn read_cstr(mem: &mut PhysicalMemory<'_>, root: u64, va: u64) -> Option<String> {
    // Never read across into the next page: it may be absent.
    let len = (4096 - (va & 0xfff) as usize).min(96);
    let mut b = vec![0u8; len];
    mem.read_virtual(root, va, &mut b, 4).ok()?;
    let end = b.iter().position(|c| *c == 0)?;
    std::str::from_utf8(&b[..end]).ok().map(str::to_owned)
}

/// (DLL name, export directory fields) read through virtual memory.
fn export_dir(mem: &mut PhysicalMemory<'_>, root: u64, h: &Header) -> Option<(String, [u32; 10])> {
    if h.export_rva == 0 || h.export_rva >= h.size_of_image { return None; }
    let mut d = [0u8; 40];
    mem.read_virtual(root, h.base + h.export_rva as u64, &mut d, 4).ok()?;
    let f: [u32; 10] = std::array::from_fn(|i| u32::from_le_bytes(d[i * 4..i * 4 + 4].try_into().unwrap()));
    let name = read_cstr(mem, root, h.base + f[3] as u64)?;
    Some((name, f))
}

/// Address of an exported symbol, by name.
fn export_address(mem: &mut PhysicalMemory<'_>, root: u64, h: &Header, f: &[u32; 10], wanted: &str) -> Option<u64> {
    let (functions, names_count, fn_rva, names_rva, ords_rva) = (f[5], f[6].min(65536), f[7], f[8], f[9]);
    for i in 0..names_count as u64 {
        let mut r = [0u8; 4];
        mem.read_virtual(root, h.base + names_rva as u64 + 4 * i, &mut r, 4).ok()?;
        let name_va = h.base + u32::from_le_bytes(r) as u64;
        if read_cstr(mem, root, name_va).as_deref() != Some(wanted) { continue; }
        let mut o = [0u8; 2];
        mem.read_virtual(root, h.base + ords_rva as u64 + 2 * i, &mut o, 4).ok()?;
        let ordinal = u16::from_le_bytes(o) as u32;
        if ordinal >= functions { return None; }
        mem.read_virtual(root, h.base + fn_rva as u64 + 4 * ordinal as u64, &mut r, 4).ok()?;
        return Some(h.base + u32::from_le_bytes(r) as u64);
    }
    None
}

/// Find the loaded-module list without ntoskrnl's header: scan physical
/// memory for a KLDR_DATA_TABLE_ENTRY whose DllBase (+0x30) and SizeOfImage
/// (+0x40) match an image found in kernel space, then follow Flink around the
/// ring. The one node that is not an entry (its DllBase is not a known image)
/// is the list head, PsLoadedModuleList.
fn find_list_structurally(mem: &mut PhysicalMemory<'_>, root: u64, images: &[Header]) -> Option<u64> {
    use std::collections::HashMap;
    let sizes: HashMap<u64, u32> = images.iter().map(|h| (h.base, h.size_of_image)).collect();
    if sizes.is_empty() { return None; }
    let end = mem.physical_end();
    const CHUNK: usize = 8 << 20;
    let mut buf = vec![0u8; CHUNK + 0x50];
    let mut checked = 0usize;
    let mut at = 0u64;
    while at < end {
        let len = ((end - at) as usize).min(CHUNK + 0x50);
        if mem.read_exact_at(at, &mut buf[..len]).is_err() { at += CHUNK as u64; continue; }
        let mut off = 0x30usize;
        while off + 0x18 <= len.min(CHUNK + 0x30) {
            let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            // Kernel image bases: canonical high half, 4 KiB aligned.
            if v >> 48 == 0xffff && v & 0xfff == 0 {
                if let Some(size) = sizes.get(&v) {
                    let e = off - 0x30;
                    let flink = u64::from_le_bytes(buf[e..e + 8].try_into().unwrap());
                    let blink = u64::from_le_bytes(buf[e + 8..e + 16].try_into().unwrap());
                    let sz = u32::from_le_bytes(buf[off + 0x10..off + 0x14].try_into().unwrap());
                    if sz == *size && is_kptr(flink) && is_kptr(blink) {
                        checked += 1;
                        if let Some(head) = ring_head(mem, root, flink, &sizes) {
                            println!("[kernel] module list found by structure (entry for 0x{v:x} at physical 0x{:x}; {checked} candidates checked)", at + e as u64);
                            return Some(head);
                        }
                        if checked > 4096 { return None; }
                    }
                }
            }
            off += 8;
        }
        at += CHUNK as u64;
    }
    None
}

fn is_kptr(v: u64) -> bool { v >> 48 == 0xffff && v & 7 == 0 }

/// Walk Flink from `start` (an entry VA); return the head when the ring
/// closes with exactly one non-entry node and every back link agrees.
fn ring_head(mem: &mut PhysicalMemory<'_>, root: u64, start: u64, sizes: &std::collections::HashMap<u64, u32>) -> Option<u64> {
    let mut node = start;
    let (mut heads, mut entries) = (Vec::new(), 0usize);
    for _ in 0..8192 {
        let mut b = [0u8; 0x48];
        mem.read_virtual(root, node, &mut b, 4).ok()?;
        let q = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let (flink, base) = (q(0), q(0x30));
        let size = u32::from_le_bytes(b[0x40..0x44].try_into().unwrap());
        if !is_kptr(flink) { return None; }
        // Blink of the next node must point back here.
        let mut nb = [0u8; 8];
        mem.read_virtual(root, flink + 8, &mut nb, 4).ok()?;
        if u64::from_le_bytes(nb) != node { return None; }
        if sizes.get(&base) == Some(&size) || (base >> 48 == 0xffff && base & 0xfff == 0 && size >= 0x1000) {
            entries += 1;
        } else {
            heads.push(node);
        }
        node = flink;
        if node == start { break; }
    }
    (node == start && heads.len() == 1 && entries >= 2).then(|| heads[0])
}

const KERNEL_NAMES: [&str; 4] = ["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrla57.exe"];

/// Readable pages of an image through one root, sampled.
fn coverage(mem: &mut PhysicalMemory<'_>, root: u64, base: u64, size: u32) -> usize {
    let pages = (size as usize).div_ceil(4096);
    let step = (pages / 64).max(1);
    let mut b = [0u8; 1];
    (0..pages).step_by(step).filter(|p| mem.read_virtual(root, base + (*p as u64) * 4096, &mut b, 4).is_ok()).count()
}

pub struct Summary {
    pub listed: usize,
    pub unlisted: usize,
    pub data_views: usize,
    pub orphan_regions: usize,
}

/// Run the kernel phase into `out` (created). `list_head` comes from a
/// crash-dump header when available; otherwise it is found via ntoskrnl's
/// export. `session_root` (any user root) serves session-space drivers.
pub fn run(mem: &mut PhysicalMemory<'_>, root: u64, session_root: Option<u64>,
           list_head: Option<u64>, out: &Path) -> io::Result<Summary> {
    fs::create_dir_all(out)?;
    let started = std::time::Instant::now();
    println!("[kernel] walking kernel page tables of root 0x{root:x}");
    let _ = io::stdout().flush();
    let (leaves, stats) = walk_kernel(mem, root)?;
    if leaves.len() >= MAX_LEAVES {
        println!("[kernel] WARNING: leaf cap {MAX_LEAVES} reached; kernel space beyond it was not scanned");
    }
    println!("[kernel] tables: {} aliased (shared, walked once), {} rejected (not page tables)",
        stats.aliased_tables, stats.rejected_tables);
    let mut busiest = stats.slots.clone();
    busiest.sort_by(|a, b| b.1.cmp(&a.1));
    println!("[kernel] leaves per PML4 slot (slot:leaves/executable): {}",
        busiest.iter().take(12).map(|(s, n, x)| format!("{s}:{n}/{x}")).collect::<Vec<_>>().join(" "));
    let exec_leaves = leaves.iter().filter(|l| l.exec).count();
    println!("[kernel] {} kernel leaves ({} executable, {} large); {:.0?}", leaves.len(), exec_leaves,
        leaves.iter().filter(|l| l.size > 4096).count(), started.elapsed());
    let headers = find_headers(mem, &leaves);
    println!("[kernel] {} PE headers at kernel page starts; {:.0?}", headers.len(), started.elapsed());

    // Module list head: crash-dump header, else ntoskrnl's export. Several
    // images can export the kernel's name (hotpatch images such as
    // ntkrnlmp_hotpatch.exe do), and their PsLoadedModuleList export is not
    // the live list: try each and keep the head that yields the longest
    // complete list.
    let mut head = list_head;
    let mut kernel_image = None;
    if head.is_none() {
        let mut best: Option<(usize, u64, u64, String)> = None;
        for h in &headers {
            let Some((name, f)) = export_dir(mem, root, h) else { continue };
            if !KERNEL_NAMES.iter().any(|k| name.eq_ignore_ascii_case(k)) { continue; }
            let Some(candidate) = export_address(mem, root, h, &f, "PsLoadedModuleList") else {
                println!("[kernel] {name} at 0x{:x}: PsLoadedModuleList not resolved", h.base);
                continue;
            };
            let count = match kernel_modules::enumerate(mem, root, candidate, 4096) {
                Ok(scan) if scan.complete => scan.modules.len(),
                Ok(scan) => scan.modules.len() / 2,
                Err(_) => 0,
            };
            println!("[kernel] {name} at 0x{:x}: PsLoadedModuleList=0x{candidate:x} -> {count} modules", h.base);
            if count >= 2 && best.as_ref().is_none_or(|b| count > b.0) {
                best = Some((count, candidate, h.base, name));
            }
        }
        if let Some((count, candidate, base, name)) = best {
            println!("[kernel] using the module list of {name} at 0x{base:x} ({count} modules)");
            head = Some(candidate);
            kernel_image = Some(name);
        }
    }
    if head.is_none() {
        if kernel_image.is_none() {
            println!("[kernel] no kernel-named image yields a module list through its export; searching for the module list by structure");
        }
        let executable: Vec<Header> = headers.iter().filter(|h| code_is_executable(&leaves, h)).cloned().collect();
        head = find_list_structurally(mem, root, &executable);
        if head.is_none() { println!("[kernel] module list not found by structure either"); }
    }
    let mut modules: Vec<KernelModule> = Vec::new();
    let mut list_note = String::from("module list unavailable");
    if let Some(head) = head {
        match kernel_modules::enumerate(mem, root, head, 4096) {
            Ok(scan) => {
                list_note = format!("{} modules, traversal {}", scan.modules.len(),
                    if scan.complete { "complete" } else { "partial" });
                if let Some(w) = &scan.warning { println!("[kernel] module list warning: {w}"); }
                if let Some(first) = scan.modules.first() {
                    let mut mz = [0u8; 2];
                    let seen = mem.read_virtual(root, first.image_base, &mut mz, 4).is_ok() && mz == *b"MZ";
                    println!("[kernel] first module (the kernel): {} at 0x{:x} size 0x{:x}; header page {}",
                        first.name.clone().unwrap_or_default(), first.image_base, first.image_size,
                        if seen { "readable" } else { "not readable in the capture" });
                    if kernel_image.is_none() {
                        // Why the export route missed it.
                        let found = headers.iter().find(|h| h.base == first.image_base);
                        let leaf = leaf_for(&leaves, first.image_base);
                        let why = match found {
                            None => format!("header not at a scanned leaf start (leaf {})",
                                leaf.map(|l| format!("va=0x{:x} size=0x{:x}", l.va, l.size)).unwrap_or_else(|| "absent".into())),
                            Some(h) if h.export_rva == 0 => "header has no export directory".into(),
                            Some(h) => match export_dir(mem, root, h) {
                                Some((name, _)) => format!("export directory names it {name:?}"),
                                None => format!("export directory at rva 0x{:x} unreadable", h.export_rva),
                            },
                        };
                        println!("[kernel] export route diagnosis: {why}");
                    }
                }
                modules = scan.modules;
            }
            Err(e) => list_note = format!("module list unreadable: {e}"),
        }
    }
    println!("[kernel] {list_note}");

    // Recover listed modules.
    let mut records: Vec<RecoveryRecord> = Vec::new();
    let mut index = String::new();
    let roots_for = |mem: &mut PhysicalMemory<'_>, base: u64, size: u32| -> u64 {
        match session_root {
            Some(s) if s != root && coverage(mem, s, base, size) > coverage(mem, root, base, size) => s,
            _ => root,
        }
    };
    let listed: HashSet<u64> = modules.iter().map(|m| m.image_base).collect();
    for m in &modules {
        let via = roots_for(mem, m.image_base, m.image_size);
        let mut record = recovery::recover_from_roots(mem, &[via], m, out)?;
        // No header to rebuild from: keep the mapped bytes anyway, so the
        // module's code is not lost (it is excluded from orphan regions).
        if record.output.is_none() {
            let span = (m.image_size as u64).min(64 << 20);
            let mut bytes = vec![0u8; span as usize];
            let mut present = 0usize;
            for k in 0..span / 4096 {
                let range = (k * 4096) as usize..((k + 1) * 4096) as usize;
                if mem.read_virtual(via, m.image_base + k * 4096, &mut bytes[range], 4).is_ok() { present += 1; }
            }
            if present > 0 {
                let safe: String = m.name.clone().unwrap_or_default().chars()
                    .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).collect();
                let path = out.join(format!("{safe}_0x{:016x}.headerless.bin", m.image_base));
                fs::write(&path, &bytes)?;
                record.output = Some(path.to_string_lossy().into_owned());
                record.completeness = "headerless";
                println!("[kernel-module] {}: no header; wrote {present}/{} mapped pages raw", record.name, span / 4096);
            }
        }
        println!("[kernel-module] {} base=0x{:x} {} missing={} {}", record.name, record.base,
            record.completeness, record.missing_pages.len(),
            if via != root { "(session space)" } else { "" });
        index_row(&mut index, "kernel-module", &record, if via != root { "session space" } else { "" });
        records.push(record);
    }

    // Unlisted kernel images.
    let ranges: Vec<(u64, u64)> = modules.iter().map(|m| (m.image_base, m.image_base + m.image_size as u64)).collect();
    let inside_listed = |va: u64| ranges.iter().any(|(s, e)| va >= *s && va < *e);
    let (mut unlisted, mut data_views, mut embedded) = (Vec::new(), 0usize, 0usize);
    let mut unlisted_tsv = String::from("base\tsize_of_image\tcode_executable\twritable_header\tname\tcompleteness\toutput\n");
    for h in &headers {
        if listed.contains(&h.base) { continue; }
        if inside_listed(h.base) { embedded += 1; continue; }
        if !code_is_executable(&leaves, h) { data_views += 1; continue; }
        unlisted.push(h.clone());
    }
    for h in &unlisted {
        let module = KernelModule { entry: 0, image_base: h.base, image_size: h.size_of_image,
            name: Some(format!("kimage_{:x}", h.base)), name_status: "unlisted" };
        let mut record = recovery::recover_from_roots(mem, &[root], &module, out)?;
        process_aware::apply_recovered_name(&mut record);
        println!("[kernel-unlisted] {} base=0x{:x} size=0x{:x} {}", record.name, h.base, h.size_of_image, record.completeness);
        let writable = leaf_for(&leaves, h.base).is_some_and(|l| l.writable);
        unlisted_tsv.push_str(&format!("0x{:x}\t{}\ttrue\t{}\t{}\t{}\t{}\n", h.base, h.size_of_image, writable,
            record.name.replace('\t', " "), record.completeness, record.output.clone().unwrap_or_default()));
        index_row(&mut index, "kernel-unlisted", &record,
            if writable { "header page writable" } else { "" });
        records.push(record);
    }
    println!("[kernel] unlisted executable images: {}; PE headers in data (cache views, pool copies): {}; headers inside listed modules: {}",
        unlisted.len(), data_views, embedded);
    fs::write(out.join("dumpy_kernel_unlisted.tsv"), unlisted_tsv)?;
    recovery::write_report(out, &records)?;

    // Executable kernel pages outside every image.
    let mut images: Vec<(u64, u64, String)> = modules.iter()
        .map(|m| (m.image_base, m.image_base + m.image_size as u64, m.name.clone().unwrap_or_default())).collect();
    images.extend(unlisted.iter().map(|h| (h.base, h.base + h.size_of_image as u64, format!("kimage_{:x}", h.base))));
    images.sort();
    let covered = |va: u64, end: u64| images.iter().any(|(s, e, _)| va >= *s && end <= *e);
    let mut regions: Vec<(u64, u64, bool)> = Vec::new();
    for l in leaves.iter().filter(|l| l.exec) {
        // Split large pages against image ranges at 4 KiB granularity.
        let mut va = l.va;
        while va < l.va + l.size as u64 {
            let page_end = va + 4096;
            if !covered(va, page_end) {
                match regions.last_mut() {
                    Some((_, end, large)) if *end == va => { *end = page_end; *large |= l.size > 4096; }
                    _ => regions.push((va, page_end, l.size > 4096)),
                }
            }
            va = page_end;
            if l.size > 4096 && regions.len() > 1_000_000 { break; }
        }
    }
    let orphan_dir = out.join("orphans");
    fs::create_dir_all(&orphan_dir)?;
    let mut orphan_tsv = String::from("start\tspan_bytes\tlarge_page\tcontent_class\tafter_module\trelation\toutput\n");
    let mut written_total = 0u64;
    for (start, end, large) in regions.iter().take(MAX_ORPHAN_REGIONS) {
        let span = end - start;
        let mut samples = Vec::new();
        let pages = span / 4096;
        for k in 0..pages.min(16) {
            let va = start + k * (pages / pages.min(16)).max(1) * 4096;
            let mut page = vec![0u8; 4096];
            if mem.read_virtual(root, va, &mut page, 4).is_ok() { samples.push(page); }
        }
        let class = process_aware::classify_pages(&samples);
        let prev = images.iter().filter(|(s, _, _)| s <= start).next_back();
        let after = prev.map(|(_, _, n)| n.clone()).unwrap_or_default();
        // A page or two of code just past a module's end appears for most
        // modules on current builds: loader-made stubs, not injected code.
        let relation = match prev {
            Some((_, e, _)) if *start >= *e && *start - *e < 0x10000 && span <= 0x4000 => format!("module tail (+0x{:x} past end)", start - e),
            Some(_) => "gap".to_string(),
            None => "before first image".to_string(),
        };
        let mut output = String::new();
        let take = span.min(MAX_ORPHAN_REGION_BYTES);
        if written_total + take <= MAX_ORPHAN_TOTAL_BYTES && class != "mostly-zero" {
            let mut bytes = vec![0u8; take as usize];
            for k in 0..(take / 4096) {
                let _ = mem.read_virtual(root, start + k * 4096, &mut bytes[(k * 4096) as usize..((k + 1) * 4096) as usize], 4);
            }
            let path = orphan_dir.join(format!("kcode_{start:016x}.bin"));
            fs::write(&path, &bytes)?;
            written_total += take;
            output = path.to_string_lossy().into_owned();
        }
        orphan_tsv.push_str(&format!("0x{start:x}\t{span}\t{large}\t{class}\t{after}\t{relation}\t{output}\n"));
        index.push_str(&format!("kernel-orphan-code\tkcode_{start:x}\t\tkernel\t0x{start:x}\t{span}\traw-region\t{output}\t{class}; {relation}{}{}\n",
            if after.is_empty() { String::new() } else { format!("; after {after}") },
            if *large { "; large page" } else { "" }));
    }
    let tails = orphan_tsv.lines().filter(|l| l.contains("\tmodule tail")).count();
    println!("[kernel] of the executable regions outside images, {tails} are module-tail stubs (<= 16 KiB within 64 KiB past a module's end)");
    fs::write(out.join("dumpy_kernel_orphans.tsv"), orphan_tsv)?;
    fs::write(out.join("dumpy_kernel_index.tsv"), index)?;
    println!("[kernel] executable regions outside every image: {} ({} bytes dumped); {:.0?}",
        regions.len(), written_total, started.elapsed());
    Ok(Summary { listed: modules.len(), unlisted: unlisted.len(), data_views, orphan_regions: regions.len() })
}

fn index_row(index: &mut String, category: &str, r: &RecoveryRecord, note: &str) {
    let (name, mut source) = split_name(&r.name);
    if source == "loader list" { source = "kernel module list".into(); }
    index.push_str(&format!("{category}\t{name}\t{source}\tkernel\t0x{:x}\t{}\t{}\t{}\t{note}\n",
        r.base, r.image_size, r.completeness, r.output.clone().unwrap_or_default()));
}

/// "foo.dll (export name)" -> ("foo.dll", "export name"); plain names come
/// from a loader list.
pub fn split_name(name: &str) -> (String, String) {
    if let (Some(open), true) = (name.rfind(" ("), name.ends_with(')')) {
        return (name[..open].to_owned(), name[open + 2..name.len() - 1].to_owned());
    }
    (name.to_owned(), if name.starts_with("image_") || name.starts_with("kimage_") { String::new() } else { "loader list".into() })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn splits_name_sources() {
        assert_eq!(split_name("foo.dll (export name)"), ("foo.dll".into(), "export name".into()));
        assert_eq!(split_name("ntoskrnl.exe"), ("ntoskrnl.exe".into(), "loader list".into()));
        assert_eq!(split_name("image_1000_h00"), ("image_1000_h00".into(), String::new()));
    }
    #[test]
    fn parses_headers_with_long_section_tables() {
        let mut b = vec![0u8; 0x1000];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x108u32.to_le_bytes());
        b[0x108..0x10c].copy_from_slice(b"PE\0\0");
        b[0x10c..0x10e].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x10e..0x110].copy_from_slice(&36u16.to_le_bytes());      // 36 sections, like ntoskrnl
        b[0x11c..0x11e].copy_from_slice(&0xf0u16.to_le_bytes());
        let opt = 0x120;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[opt + 56..opt + 60].copy_from_slice(&0x145_0000u32.to_le_bytes());
        // last section is executable, at the very end of the table (> 0x400)
        let last = opt + 0xf0 + 35 * 40;
        b[last + 8..last + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[last + 12..last + 16].copy_from_slice(&0x20_0000u32.to_le_bytes());
        b[last + 36..last + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let h = parse_header(0xfffff806cc000000, &b).expect("36-section header parses");
        assert_eq!(h.exec_sections, vec![(0x20_0000, 0x1000)]);
        assert!(parse_header(0, &b[..0x400]).is_none());               // the old 0x400 read failed here
    }
    #[test]
    fn leaf_lookup_handles_large_pages() {
        let leaves = vec![
            Leaf { va: 0x1000, phys: 0, size: 0x1000u32, exec: true, writable: false },
            Leaf { va: 0x20_0000, phys: 0, size: 0x20_0000, exec: false, writable: true },
        ];
        assert!(leaf_for(&leaves, 0x1fff).is_some_and(|l| l.exec));
        assert!(leaf_for(&leaves, 0x2000).is_none());
        assert!(leaf_for(&leaves, 0x3f_ffff).is_some_and(|l| l.writable));
        assert!(leaf_for(&leaves, 0x40_0000).is_none());
    }
}
