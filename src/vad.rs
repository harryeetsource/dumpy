//! VAD-tree resolution for user pages that have no page-table entry.
//!
//! Windows builds a PTE only when a process touches a page. A mapped image
//! the process has not touched has no PTE (often not even a page table); the
//! only description of it is the process's VAD tree: an AVL tree of MMVAD
//! nodes rooted at EPROCESS.VadRoot. For a section-backed VAD the node holds
//! FirstPrototypePte, the kernel address of the prototype PTE for the VAD's
//! first page; for an image view those prototype PTEs are one contiguous
//! array, so page i of the view is described by FirstPrototypePte[i]. A
//! valid or transition prototype PTE names the physical page every mapper
//! shares, which is in the capture whether or not this process touched it.
//!
//! Nothing here assumes symbols. The node header (RTL_BALANCED_NODE + the
//! VPN fields of MMVAD_SHORT) has been stable since Windows 10; it is checked
//! by structure (a valid binary search tree that covers the PEB). The two
//! build-specific offsets — VadRoot in EPROCESS and FirstPrototypePte in
//! MMVAD — are learned from the capture:
//! * VadRoot: the EPROCESS qword that roots the largest valid VAD tree
//!   covering the process's PEB, agreed across processes.
//! * FirstPrototypePte: the MMVAD qword whose prototype PTEs name the same
//!   physical frames as the hardware PTEs of the image pages the process did
//!   touch.

use crate::memory::{PhysicalMemory, VadState};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const LEFT: u64 = 0x0;
const RIGHT: u64 = 0x8;
const START: u64 = 0x18;
const END: u64 = 0x1c;
const START_HIGH: u64 = 0x20;
const END_HIGH: u64 = 0x21;
const MAX_NODES: usize = 200_000;
const PFN: u64 = 0x000f_ffff_ffff_f000;

#[derive(Debug, Default)]
pub struct Report {
    pub candidates: usize,
    pub root_offset: Option<u64>,
    pub root_support: (usize, usize),
    pub first_proto_offset: Option<u64>,
    pub proto_matches: (usize, usize),
    pub installed: usize,
    pub nodes: usize,
    pub note: String,
}

pub fn is_kernel_pointer(v: u64) -> bool { v >> 47 == 0x1ffff && v & 7 == 0 && v != u64::MAX & !7 }

fn kread(mem: &mut PhysicalMemory<'_>, va: u64, out: &mut [u8]) -> bool {
    let Some(root) = mem.kernel_root else { return false };
    mem.read_virtual(root, va, out, 4).is_ok()
}

fn kread_u64(mem: &mut PhysicalMemory<'_>, va: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    kread(mem, va, &mut b).then(|| u64::from_le_bytes(b))
}

/// (left, right, start_vpn, end_vpn) of one node, or None when it does not
/// read as a VAD node.
pub fn node(mem: &mut PhysicalMemory<'_>, va: u64) -> Option<(u64, u64, u64, u64)> {
    let mut b = [0u8; 0x28];
    if !kread(mem, va, &mut b) { return None; }
    let q = |o: u64| u64::from_le_bytes(b[o as usize..o as usize + 8].try_into().unwrap());
    let d = |o: u64| u32::from_le_bytes(b[o as usize..o as usize + 4].try_into().unwrap()) as u64;
    let (left, right) = (q(LEFT), q(RIGHT));
    let start = d(START) | (b[START_HIGH as usize] as u64) << 32;
    let end = d(END) | (b[END_HIGH as usize] as u64) << 32;
    // User VPNs are below 2^35 (128 TiB / 4 KiB).
    if start > end || end >= 1 << 35 { return None; }
    if (left != 0 && !is_kernel_pointer(left)) || (right != 0 && !is_kernel_pointer(right)) { return None; }
    Some((left, right, start, end))
}

/// In-order walk; None unless the whole tree is a valid, non-overlapping BST.
fn walk(mem: &mut PhysicalMemory<'_>, root: u64) -> Option<Vec<(u64, u64, u64)>> {
    let mut out = Vec::new();
    let mut stack = Vec::new();
    let mut current = root;
    let mut last_end: Option<u64> = None;
    loop {
        while current != 0 {
            if stack.len() > 96 { return None; }
            stack.push(current);
            current = node(mem, current)?.0;
        }
        let Some(n) = stack.pop() else { break };
        let (_, right, start, end) = node(mem, n)?;
        if last_end.is_some_and(|e| start <= e) { return None; }
        last_end = Some(end);
        out.push((n, start, end));
        if out.len() > MAX_NODES { return None; }
        current = right;
    }
    Some(out)
}

pub fn lookup(mem: &mut PhysicalMemory<'_>, root: u64, vpn: u64) -> Option<(u64, u64, u64)> {
    let mut current = root;
    for _ in 0..96 {
        if current == 0 { return None; }
        let (left, right, start, end) = node(mem, current)?;
        if vpn < start { current = left; } else if vpn > end { current = right; } else { return Some((current, start, end)); }
    }
    None
}

struct Candidate { dtb: u64, eprocess: u64, peb: u64 }

/// Read `dumpy_eprocess.tsv` from the output directory, learn the VAD
/// offsets and install per-DTB VAD roots on `mem`. Must run before any
/// translation whose results should use VAD resolution, and learns with VAD
/// resolution off so hardware PTEs are the ground truth.
pub fn setup(mem: &mut PhysicalMemory<'_>, out_dir: &Path) -> Report {
    let mut report = Report::default();
    if mem.kernel_root.is_none() { report.note = "no kernel root".into(); return report; }
    let path = out_dir.join("dumpy_eprocess.tsv");
    let Ok(text) = fs::read_to_string(&path) else {
        report.note = format!("{} not found; run --eprocess-scan once and copy dumpy_eprocess.tsv into the output directory", path.display());
        return report;
    };
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap_or_default().split('\t').collect();
    let col = |n: &str| header.iter().position(|h| *h == n);
    let (Some(c_dtb), Some(c_va), Some(c_peb)) = (col("dtb"), col("eprocess_va"), col("peb")) else {
        report.note = "dumpy_eprocess.tsv lacks dtb/eprocess_va/peb columns (older dumpy?)".into();
        return report;
    };
    let (c_state, c_plaus) = (col("state"), col("plausible"));
    let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok();
    let mut by_dtb = HashMap::<u64, Candidate>::new();
    for line in lines {
        let f: Vec<&str> = line.split('\t').collect();
        let get = |c: usize| f.get(c).copied().unwrap_or("");
        if c_state.is_some_and(|c| get(c) != "running") { continue; }
        if c_plaus.is_some_and(|c| get(c) != "true") { continue; }
        let (Some(dtb), Some(ep), Some(peb)) = (hex(get(c_dtb)), hex(get(c_va)), hex(get(c_peb))) else { continue };
        if peb == 0 || !is_kernel_pointer(ep & !7) { continue; }
        by_dtb.entry(dtb).or_insert(Candidate { dtb, eprocess: ep, peb });
    }
    report.candidates = by_dtb.len();
    if by_dtb.is_empty() { report.note = "no running processes with EPROCESS VA and PEB".into(); return report; }
    let mut sample: Vec<&Candidate> = by_dtb.values().collect();
    sample.sort_by_key(|c| c.dtb);
    let sample: Vec<&Candidate> = sample.into_iter().take(24).collect();

    // VadRoot: offset whose tree is valid, covers the PEB and is largest.
    let mut best = (0usize, 0usize, None);
    for off in (0x300u64..0xb00).step_by(8) {
        let (mut ok, mut nodes) = (0usize, 0usize);
        for c in &sample {
            let Some(root) = kread_u64(mem, c.eprocess + off) else { continue };
            if !is_kernel_pointer(root) { continue; }
            let Some(tree) = walk(mem, root) else { continue };
            if tree.len() < 3 { continue; }
            let pv = c.peb >> 12;
            if tree.iter().any(|(_, s, e)| *s <= pv && pv <= *e) { ok += 1; nodes += tree.len(); }
        }
        if ok > best.0 || (ok == best.0 && nodes > best.1) { best = (ok, nodes, Some(off)); }
    }
    let Some(root_offset) = best.2.filter(|_| best.0 > 0 && (best.0 * 2 >= sample.len() || best.0 >= 8)) else {
        report.note = format!("VadRoot offset not learned (best support {}/{})", best.0, sample.len());
        return report;
    };
    report.root_offset = Some(root_offset);
    report.root_support = (best.0, sample.len());
    report.nodes = best.1;

    // FirstPrototypePte: compare prototype PFNs to hardware PFNs over the
    // main image of each sampled process.
    let saved = mem.vad.take();
    let mut scores = HashMap::<u64, (usize, usize)>::new();
    for c in &sample {
        let Some(root) = kread_u64(mem, c.eprocess + root_offset) else { continue };
        let mut b = [0u8; 8];
        if mem.read_virtual(c.dtb, c.peb + 0x10, &mut b, 4).is_err() { continue; }
        let image = u64::from_le_bytes(b);
        let Some((vad, start, end)) = lookup(mem, root, image >> 12) else { continue };
        let mut hw = Vec::new();
        for i in 0..(end - start + 1).min(64) {
            if let Ok((phys, crate::memory::EntryKind::Present)) = mem.translate_detailed(c.dtb, (start + i) << 12, 4) {
                hw.push((i, phys & PFN));
            }
        }
        if hw.is_empty() { continue; }
        for off in (0x38u64..0xa0).step_by(8) {
            let Some(fp) = kread_u64(mem, vad + off) else { continue };
            if !is_kernel_pointer(fp) { continue; }
            let e = scores.entry(off).or_default();
            for (i, pfn) in &hw {
                e.1 += 1;
                if kread_u64(mem, fp + 8 * i).is_some_and(|p| p & 1 != 0 && p & PFN == *pfn) { e.0 += 1; }
            }
        }
    }
    mem.vad = saved;
    let Some((&off, &(m, t))) = scores.iter().max_by_key(|(o, (m, _))| (*m, std::cmp::Reverse(**o))) else {
        report.note = "FirstPrototypePte offset not learned (no image pages to compare)".into();
        return report;
    };
    report.proto_matches = (m, t);
    if m * 2 <= t || m < 2 {
        report.note = format!("FirstPrototypePte offset not learned (best +{off:#x}: {m}/{t} PFN matches)");
        return report;
    }
    report.first_proto_offset = Some(off);

    let mut roots = HashMap::new();
    for c in by_dtb.values() {
        if let Some(root) = kread_u64(mem, c.eprocess + root_offset).filter(|r| is_kernel_pointer(*r)) {
            if node(mem, root).is_some() { roots.insert(c.dtb, root); }
        }
    }
    report.installed = roots.len();
    mem.vad = Some(VadState { roots, first_proto_offset: off });
    report
}
