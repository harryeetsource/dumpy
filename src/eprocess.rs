//! Symbol-free `_EPROCESS` discovery, anchored on facts already validated:
//! each live address space's page-table root (DTB) and, where found, its
//! PEB address. `KPROCESS.DirectoryTableBase` holds the DTB and `EPROCESS.Peb`
//! holds the PEB, so a physical scan for known DTB values, confirmed by the
//! matching PEB a fixed distance away, pins the object without symbols. The
//! distance and every other field offset are then learned by consensus over
//! the confirmed objects, and a second pass finds objects of the same shape
//! whose DTB is no longer a live root (exited processes).
use crate::memory::PhysicalMemory;
use std::collections::{HashMap, HashSet};
use std::io;

/// Byte offset of DirectoryTableBase inside EPROCESS (KPROCESS +0x28);
/// unchanged on x64 since Vista. Everything else is learned.
const WINDOW_BEFORE: u64 = 0x40;
const WINDOW_AFTER: u64 = 0x900;
const MAX_CANDIDATES: usize = 4_000_000;

#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// All offsets are relative to the DirectoryTableBase field.
    pub peb: Option<i64>,
    pub name: Option<i64>,
    pub pid: Option<i64>,
    pub ppid: Option<i64>,
    pub create_time: Option<i64>,
    pub exit_time: Option<i64>,
    pub links: Option<i64>,
    pub confirmed_objects: usize,
    /// Confirmed objects after removing byte-identical duplicates.
    pub distinct_objects: usize,
    /// Best (count, offset) seen for each field while learning, for diagnosis.
    pub scores: Vec<(&'static str, usize, i64)>,
    /// (candidate UserDirectoryTableBase offset, sampled objects whose
    /// kernel-CR3 slot looked like a PML4) for the log.
    pub field_evidence: Vec<(u64, usize, usize)>,
    /// (objects with DISPATCHER_HEADER.Type == 3 at field-0x28, objects tested).
    pub dispatcher_header_evidence: (usize, usize),
    /// Offset inside EPROCESS of the DTB field the scan matched: 0x28 for
    /// KPROCESS.DirectoryTableBase (kernel CR3) or the build's
    /// UserDirectoryTableBase offset when the anchored roots are user CR3s
    /// (KVA shadowing). Everything relative is converted with this.
    pub field_offset: u64,
}

/// Does this physical page look like a PML4: a present entry that points
/// back at the page itself (the self-map every Windows PML4 carries)?
fn looks_like_pml4(mem: &mut PhysicalMemory<'_>, physical: u64) -> bool {
    if physical == 0 || physical & 0xfff != 0 { return false; }
    let mut page = [0u8; 4096];
    if mem.read_exact_at(physical, &mut page).is_err() { return false; }
    page.chunks_exact(8).any(|e| {
        let v = u64::from_le_bytes(e.try_into().unwrap());
        v & 1 != 0 && v & 0x000f_ffff_ffff_f000 == physical
    })
}

#[derive(Debug, Clone)]
pub struct Process {
    pub physical: u64,
    pub eprocess_va: Option<u64>,
    pub dtb: u64,
    /// The other CR3 of the pair when KVA shadowing splits them.
    pub other_dtb: Option<u64>,
    pub live_root: bool,
    pub peb: u64,
    pub peb_confirmed: bool,
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
    pub name: Option<String>,
    pub create_time: Option<u64>,
    pub exit_time: Option<u64>,
    pub in_active_list: Option<bool>,
    pub source: &'static str,
    /// Physical address of an earlier object with the same PID and CreateTime.
    pub duplicate_of: Option<u64>,
    /// Field values look like a real process (small 4-aligned PID and PPID,
    /// 2005-2040 CreateTime, printable name). Objects that merely contain a
    /// known DTB value — PFN lists, pool copies, debugger scratch — fail this.
    pub plausible: bool,
    /// Any copy of this object (same PID + CreateTime) is reachable from
    /// ActiveProcessLinks. Linkage is a property of the process, not of the
    /// particular physical copy, so this is the value to judge "unlinked" by.
    pub group_linked: Option<bool>,
    /// ExitTime taken from another imaged copy of this object; this copy predates the exit.
    pub exit_from_duplicate: bool,
}

/// Windows PIDs are multiples of 4 below 2^20 in practice; Idle and System
/// (0 and 4) have no CreateTime worth checking and are accepted by name.
pub fn plausible_process(p: &Process) -> bool {
    let small = |v: Option<u64>| v.is_some_and(|v| v % 4 == 0 && v < 0x10_0000);
    let name_ok = p.name.as_deref().is_some_and(|n| {
        !n.is_empty() && n.len() <= 15 && n.bytes().all(|b| (0x20..0x7f).contains(&b)) && !n.starts_with(' ')
    });
    if !name_ok || !small(p.pid) { return false; }
    // Idle and System have no CreateTime/parent worth checking, so they are
    // accepted by their exact names only.
    match (p.pid, p.name.as_deref()) {
        (Some(0), Some(n)) => return n == "Idle",
        (Some(4), Some(n)) => return n == "System",
        _ => {}
    }
    small(p.ppid) && p.create_time.is_some_and(plausible_filetime)
}

#[derive(Debug, Default)]
pub struct DebugDump {
    pub pid: u64,
    /// (physical address of the DTB field, bytes from field-0x40 onward)
    pub windows: Vec<(u64, Vec<u8>)>,
    pub differing_offsets: Vec<i64>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub debug: Option<DebugDump>,
    /// (delta, nonzero objects, nonzero among dead) for ExitTime candidates.
    pub exit_candidates: Vec<(i64, usize, usize)>,
    pub exit_dead_total: usize,
    /// (shaped, nonzero, nonzero-among-dead, exit>=create, n) at CreateTime+8, the usual ExitTime slot.
    pub exit_next_qword: Option<(usize, usize, usize, usize, usize)>,
    pub after_create: Vec<String>,
    pub layout: Layout,
    pub processes: Vec<Process>,
    pub dtb_hits: usize,
    pub rejected_hits: usize,
    pub shape_candidates: usize,
    /// (distance, support) for every PEB distance considered.
    pub peb_delta_candidates: Vec<(i64, usize)>,
    /// (distance, support, confirmed objects, layout learned) per attempt.
    pub layout_attempts: Vec<(i64, usize, usize, bool)>,
    /// The learned (possibly partial) layout of each attempt, for diagnosis.
    pub attempt_layouts: Vec<Layout>,
    /// (physical spacing, count) of duplicate objects, most common first.
    pub duplicate_spacing: Vec<(u64, usize)>,
    /// Virtual reads of the bytes preceding the matched field, for the log.
    pub head_dumps: Vec<String>,
}

fn q(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn kernel_pointer(v: u64) -> bool { v >= 0xffff_8000_0000_0000 && v & 7 == 0 }
fn user_page(v: u64) -> bool { (0x10000..0x0000_8000_0000_0000).contains(&v) && v & 0xfff == 0 }
/// FILETIME between 2005 and 2040.
fn plausible_filetime(v: u64) -> bool { (0x01c5_0000_0000_0000..0x01f4_0000_0000_0000).contains(&v) }
fn plausible_pid(v: u64) -> bool { v != 0 && v < 0x10_0000 && v & 3 == 0 }

/// 1..=15 printable bytes then NUL, ending in a known executable suffix or a
/// kernel pseudo-process name.
fn image_name(b: &[u8]) -> Option<String> {
    let field = b.get(..16)?;
    let end = field.iter().position(|v| *v == 0)?;
    if !(3..=15).contains(&end) { return None; }
    let text = &field[..end];
    if !text.iter().all(|v| v.is_ascii_graphic() || *v == b' ') { return None; }
    let s = String::from_utf8_lossy(text).into_owned();
    let lower = s.to_ascii_lowercase();
    // Names are truncated to 15 bytes, so a suffix test alone misses long
    // names; accept anything with an extension-looking dot or a known kernel name.
    // ImageFileName keeps 14 characters, so a long name loses its extension
    // ("msedgewebview2.exe" -> "msedgewebview2"): a full-length name is
    // accepted without a dot.
    let ok = lower.ends_with(".exe") || lower.ends_with(".scr") || lower.contains('.') ||
        (end >= 14 && text[0].is_ascii_alphanumeric()) ||
        matches!(s.as_str(), "System" | "Registry" | "MemCompression" | "Secure System");
    ok.then_some(s)
}

/// Most common value, with its count.
#[allow(dead_code)]
fn mode(values: impl Iterator<Item = i64>) -> Option<(i64, usize)> {
    let mut counts = HashMap::<i64, usize>::new();
    for v in values { *counts.entry(v).or_default() += 1; }
    counts.into_iter().max_by_key(|(k, c)| (*c, -*k))
}

struct Candidate { physical: u64, dtb: u64, window: Vec<u8>, window_base: u64 }

fn read_window(mem: &mut PhysicalMemory<'_>, physical: u64) -> Option<(Vec<u8>, u64)> {
    let base = physical.checked_sub(WINDOW_BEFORE)?;
    let mut window = vec![0u8; (WINDOW_BEFORE + WINDOW_AFTER) as usize];
    // Tolerate a window that runs past a segment: shrink until it reads.
    let mut len = window.len();
    while len >= 0x300 {
        if mem.read_exact_at(base, &mut window[..len]).is_ok() {
            window.truncate(len);
            return Some((window, base));
        }
        len -= 0x100;
    }
    None
}

fn at(c: &Candidate, delta: i64) -> Option<u64> {
    let pos = (c.physical as i64 + delta - c.window_base as i64) as usize;
    q(&c.window, pos)
}

fn name_at(c: &Candidate, delta: i64) -> Option<String> {
    let pos = (c.physical as i64 + delta - c.window_base as i64) as usize;
    c.window.get(pos..).and_then(image_name)
}

/// Once the offset is known, any printable 1..=15-byte string is the name
/// (long names are truncated and need not contain a dot).
fn name_at_lenient(c: &Candidate, delta: i64) -> Option<String> {
    let pos = (c.physical as i64 + delta - c.window_base as i64) as usize;
    let field = c.window.get(pos..pos + 16)?;
    let end = field.iter().position(|v| *v == 0)?;
    if end == 0 || end > 15 { return None; }
    let text = &field[..end];
    text.iter().all(|v| v.is_ascii_graphic() || *v == b' ').then(|| String::from_utf8_lossy(text).into_owned())
}

/// Pass 1: physical scan for known DTB values. `anchors` maps a DTB to the
/// PEB addresses validated in that address space (64-bit PEB first).
pub fn scan(mem: &mut PhysicalMemory<'_>, live_dtbs: &HashSet<u64>, anchors: &HashMap<u64, Vec<u64>>,
            kernel_root: Option<u64>) -> io::Result<Report> {
    let mut report = Report::default();
    let segments = mem.segments().to_vec();
    let mut hits = Vec::<(u64, u64)>::new();
    let mut buffer = vec![0u8; 4 << 20];
    for segment in &segments {
        let mut offset = 0u64;
        while offset < segment.length {
            let len = (segment.length - offset).min(buffer.len() as u64) as usize;
            let physical = segment.physical + offset;
            if mem.read_exact_at(physical, &mut buffer[..len]).is_err() { break; }
            for i in (0..len.saturating_sub(7)).step_by(8) {
                let v = u64::from_le_bytes(buffer[i..i + 8].try_into().unwrap());
                if v >> 52 != 0 { continue; }
                let masked = v & 0x000f_ffff_ffff_f000;
                if masked == 0 || !live_dtbs.contains(&masked) { continue; }
                let hit = physical + i as u64;
                // The root's own self-referencing PML4 entry carries its DTB.
                if hit & !0xfff == masked { continue; }
                hits.push((hit, masked));
                if hits.len() >= MAX_CANDIDATES { break; }
            }
            offset += len as u64;
            if hits.len() >= MAX_CANDIDATES { break; }
        }
    }
    report.dtb_hits = hits.len();

    // Read a window around every hit and learn the PEB offset from hits whose
    // address space has a validated PEB.
    let mut candidates = Vec::new();
    for (physical, dtb) in hits {
        if let Some((window, window_base)) = read_window(mem, physical) {
            candidates.push(Candidate { physical, dtb, window, window_base });
        }
    }
    let mut peb_deltas = Vec::new();
    let mut anchored_dtbs = HashSet::new();
    for c in &candidates {
        let Some(pebs) = anchors.get(&c.dtb) else { continue };
        anchored_dtbs.insert(c.dtb);
        for delta in (0..(WINDOW_AFTER as i64 - 8)).step_by(8) {
            if let Some(v) = at(c, delta) { if pebs.contains(&v) { peb_deltas.push(delta); } }
        }
    }
    // Rank candidate distances by support. Other structures also hold a DTB
    // with the process's PEB a fixed distance away (and can outnumber
    // EPROCESS several to one), so the most common distance is not trusted
    // on its own: each candidate must also let the rest of the layout learn.
    let mut by_delta = HashMap::<i64, usize>::new();
    for d in peb_deltas { *by_delta.entry(d).or_default() += 1; }
    let mut ranked: Vec<(i64, usize)> = by_delta.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let floor = 3.min(anchored_dtbs.len()).max(1);
    report.peb_delta_candidates = ranked.iter().filter(|(_, c)| *c >= floor).take(8).cloned().collect();
    let mut chosen: Option<(i64, Vec<(Candidate, u64, bool)>, Layout)> = None;
    let mut remaining: Vec<Candidate> = candidates;
    for (delta, count) in ranked.iter().filter(|(_, c)| *c >= floor && *c * 10 >= anchored_dtbs.len()) {
        let mut confirmed = Vec::new();
        let mut rejected = 0usize;
        let mut leftovers = Vec::new();
        for c in remaining.drain(..) {
            let Some(peb) = at(&c, *delta) else { rejected += 1; leftovers.push(c); continue };
            match anchors.get(&c.dtb) {
                Some(pebs) if pebs.contains(&peb) => confirmed.push((c, peb, true)),
                None if user_page(peb) || peb == 0 => confirmed.push((c, peb, false)),
                _ => { rejected += 1; leftovers.push(c); }
            }
        }
        // Learn from objects whose PEB matched a validated one; the rest
        // (unknown PEB, possibly stale copies) only get the layout applied.
        let trusted: Vec<&Candidate> = confirmed.iter().filter(|(_, _, ok)| *ok).map(|(c, _, _)| c).collect();
        let objs: Vec<&Candidate> = if trusted.len() >= 2 { trusted } else { confirmed.iter().map(|(c, _, _)| c).collect() };
        // Byte-identical objects (a range imaged twice, or a kernel-side
        // copy) would defeat the distinctness tests; learn from one of each.
        // Smeared copies differ in a few counters, so the body is not a
        // reliable key; the same DTB and PEB is the same process.
        let mut seen_bodies = HashSet::new();
        let objs: Vec<&Candidate> = objs.into_iter().filter(|c| {
            let start = (c.physical - c.window_base) as usize;
            let body = &c.window[start..c.window.len().min(start + 0x400)];
            let key = match at(c, *delta) {
                Some(peb) if anchors.contains_key(&c.dtb) => (c.dtb, peb),
                _ => (u64::MAX, body.iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x100000001b3))),
            };
            seen_bodies.insert(key)
        }).collect();
        let mut layout = Layout { peb: Some(*delta), confirmed_objects: confirmed.len(), ..Default::default() };
        layout.distinct_objects = objs.len();
        learn_layout(&objs, &mut layout);
        layout.field_offset = 0x28; // refined virtually once links are resolved
        let complete = layout.name.is_some() && layout.pid.is_some() && layout.create_time.is_some();
        report.layout_attempts.push((*delta, *count, confirmed.len(), complete));
        report.attempt_layouts.push(layout.clone());
        if complete {
            report.rejected_hits += rejected;
            chosen = Some((*delta, confirmed, layout));
            break;
        }
        // Diagnostics for an incomplete layout: raw windows of one PID's
        // objects (two per process on some captures) and where they differ.
        if let Some(pid_delta) = layout.pid.or_else(|| layout.scores.iter().find(|(f, _, _)| *f == "pid-distinct").map(|(_, _, o)| *o)) {
            let mut by_pid = HashMap::<u64, Vec<&Candidate>>::new();
            for c in &objs { if let Some(v) = at(c, pid_delta) { by_pid.entry(v).or_default().push(c); } }
            if let Some((pid, group)) = by_pid.iter().filter(|(_, g)| g.len() >= 2).min_by_key(|(p, _)| **p)
                .or_else(|| by_pid.iter().min_by_key(|(p, _)| **p)) {
                let mut dbg = DebugDump { pid: *pid, windows: Vec::new(), differing_offsets: Vec::new() };
                for c in group.iter().take(2) {
                    let start = (c.physical - c.window_base) as usize;
                    dbg.windows.push((c.physical, c.window[start.saturating_sub(0x40)..].to_vec()));
                }
                if dbg.windows.len() == 2 {
                    let (a, b) = (&dbg.windows[0].1, &dbg.windows[1].1);
                    for off in (0..a.len().min(b.len())).step_by(8) {
                        if a[off..off + 8] != b[off..off + 8] { dbg.differing_offsets.push(off as i64 - 0x40); }
                    }
                }
                report.debug = Some(dbg);
            }
        }
        // Not EPROCESS: give the candidates back for the next distance.
        remaining = leftovers;
        remaining.extend(confirmed.into_iter().map(|(c, _, _)| c));
    }
    let Some((peb_delta, confirmed, layout)) = chosen else { return Ok(report); };
    report.layout = layout;

    for (c, peb, peb_confirmed) in &confirmed {
        report.processes.push(describe(c, *peb, *peb_confirmed, true, &report.layout, "dtb-anchored"));
    }

    // Pass 2: same shape, any DTB. Cheap filter on CreateTime plausibility at
    // the learned offset, then name/pid/links checks.
    if let (Some(create), Some(name), Some(pid), Some(links)) =
        (report.layout.create_time, report.layout.name, report.layout.pid, report.layout.links) {
        let seen: HashSet<u64> = report.processes.iter().map(|p| p.physical).collect();
        let mut shape_hits = Vec::new();
        // Offsets of the other fields relative to the CreateTime qword, so the
        // whole shape test runs inside the scan buffer.
        let rel_pid = pid - create;
        let rel_links = links - create;
        let rel_name = name - create;
        let field_at = |buf: &[u8], i: usize, rel: i64| -> Option<u64> {
            let at = i as i64 + rel;
            if at < 0 { return None; }
            q(buf, at as usize)
        };
        for segment in &segments {
            let mut offset = 0u64;
            while offset < segment.length {
                let len = (segment.length - offset).min(buffer.len() as u64) as usize;
                let physical = segment.physical + offset;
                if mem.read_exact_at(physical, &mut buffer[..len]).is_err() { break; }
                for i in (0..len.saturating_sub(7)).step_by(8) {
                    let v = u64::from_le_bytes(buffer[i..i + 8].try_into().unwrap());
                    if !plausible_filetime(v) { continue; }
                    let Some(p) = field_at(&buffer[..len], i, rel_pid) else { continue };
                    if !plausible_pid(p) && p != 4 { continue; }
                    let (Some(f), Some(b)) = (field_at(&buffer[..len], i, rel_links), field_at(&buffer[..len], i, rel_links + 8)) else { continue };
                    if !kernel_pointer(f) || !kernel_pointer(b) { continue; }
                    let name_pos = i as i64 + rel_name;
                    if name_pos < 0 || buffer.get(name_pos as usize..name_pos as usize + 16).and_then(image_name).is_none() { continue; }
                    // v sits at create offset: the DTB field is `create` bytes before it.
                    let Some(dtb_field) = (physical + i as u64).checked_sub(create as u64) else { continue };
                    if seen.contains(&dtb_field) { continue; }
                    shape_hits.push(dtb_field);
                    if shape_hits.len() >= MAX_CANDIDATES { break; }
                }
                offset += len as u64;
                if shape_hits.len() >= MAX_CANDIDATES { break; }
            }
        }
        report.shape_candidates = shape_hits.len();
        for physical in shape_hits {
            let Some((window, window_base)) = read_window(mem, physical) else { continue };
            let dtb_raw = q(&window, (physical - window_base) as usize).unwrap_or(0);
            let dtb = dtb_raw & 0x000f_ffff_ffff_f000;
            let c = Candidate { physical, dtb, window, window_base };
            let Some(n) = name_at(&c, name) else { continue };
            let Some(p) = at(&c, pid) else { continue };
            if !plausible_pid(p) && n != "System" { continue; }
            let (Some(f), Some(b)) = (at(&c, links), at(&c, links + 8)) else { continue };
            if !kernel_pointer(f) || !kernel_pointer(b) { continue; }
            if dtb_raw >> 52 != 0 || dtb & 0xfff != 0 { continue; }
            let peb = at(&c, peb_delta).unwrap_or(0);
            if !(peb == 0 || user_page(peb)) { continue; }
            let live = live_dtbs.contains(&dtb);
            let mut p = describe(&c, peb, false, live, &report.layout, "shape");
            p.name = Some(n);
            report.processes.push(p);
        }
    }

    // ExitTime can only be learned from exited objects, which the anchored
    // set never contains: learn it now over everything found, then fill it.
    for p in report.processes.iter_mut() { p.plausible = plausible_process(p); }
    if report.layout.exit_time.is_none() && report.layout.create_time.is_some() {
        let mut all = Vec::new();
        for p in report.processes.iter().filter(|p| p.plausible) {
            if let Some((window, base)) = read_window(mem, p.physical) {
                all.push(Candidate { physical: p.physical, dtb: p.dtb, window, window_base: base });
            }
        }
        let refs: Vec<&Candidate> = all.iter().collect();
        let n = refs.len();
        let create = report.layout.create_time.unwrap();
        let dead: Vec<bool> = report.processes.iter().filter(|p| p.plausible).map(|p| !p.live_root).collect();
        let dead_total = dead.iter().filter(|d| **d).count();
        // Score: ExitTime is zero or a FILETIME on (almost) every object and is
        // non-zero mostly on objects whose address space is gone. The old
        // all-must-be-shaped rule let one smeared copy veto the field.
        let mut best = (0usize, None);
        let mut ranked = Vec::new();
        for d in (0..(WINDOW_AFTER as i64 - 16)).step_by(8) {
            if d == create { continue; }
            let shaped = refs.iter().filter(|c| at(c, d).is_some_and(|v| v == 0 || plausible_filetime(v))).count();
            let nonzero = refs.iter().filter(|c| at(c, d).is_some_and(plausible_filetime)).count();
            let nonzero_dead = refs.iter().zip(&dead).filter(|(c, dd)| **dd && at(c, d).is_some_and(plausible_filetime)).count();
            // An exit time precedes neither its own CreateTime nor is it older
            // than the newest CreateTime seen (the process ran during capture).
            let ordered = refs.iter().filter(|c| match (at(c, d), at(c, create)) {
                (Some(e), Some(cr)) if plausible_filetime(e) => e >= cr,
                _ => false,
            }).count();
            if d == create + 8 {
                report.exit_next_qword = Some((shaped, nonzero, nonzero_dead, ordered, n));
            }
            if shaped * 20 < n * 19 || nonzero == 0 || nonzero * 2 > n || ordered * 20 < nonzero * 19 { continue; }
            ranked.push((d, nonzero, nonzero_dead));
            if nonzero_dead > best.0 { best = (nonzero_dead, Some(d)); }
        }
        ranked.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));
        report.exit_candidates = ranked.into_iter().take(4).collect();
        report.exit_dead_total = dead_total;
        // What follows CreateTime on the first few dead objects, for the log.
        for (c, _) in refs.iter().zip(&dead).filter(|(_, dd)| **dd).take(6) {
            let words: Vec<String> = (0..6).map(|k| at(c, create + 8 * k).map(|v| format!("{v:#x}")).unwrap_or_else(|| "?".into())).collect();
            report.after_create.push(format!("phys {:#x}: {}", c.physical, words.join(" ")));
        }
        if let Some(d) = best.1 {
            report.layout.exit_time = Some(d);
            let by_phys: HashMap<u64, &Candidate> = all.iter().map(|c| (c.physical, c)).collect();
            for p in report.processes.iter_mut() {
                if let Some(c) = by_phys.get(&p.physical) {
                    p.exit_time = at(c, d).filter(|v| plausible_filetime(*v));
                }
            }
        }
    }

    // ActiveProcessLinks: resolve every Flink through a kernel-mapping root;
    // a Flink that lands on another object's links field also names that
    // object's virtual address. Objects nobody links to are flagged.
    if let (Some(root), Some(links)) = (kernel_root, report.layout.links) {
        let by_links_phys: HashMap<u64, usize> = report.processes.iter().enumerate()
            .map(|(i, p)| ((p.physical as i64 + links) as u64, i)).collect();
        let mut linked_to = vec![false; report.processes.len()];
        let mut field_vas: Vec<Option<u64>> = vec![None; report.processes.len()];
        // Roots that map the kernel: the chosen one plus every live root with
        // many kernel entries is tried, since under KVA shadowing a user CR3
        // does not map the pool.
        let mut kernel_roots = vec![root];
        kernel_roots.extend(live_dtbs.iter().copied().filter(|r| *r != root).take(64));
        let translate_any = |mem: &mut PhysicalMemory<'_>, va: u64| -> Option<u64> {
            kernel_roots.iter().find_map(|r| mem.translate(*r, va, 4).ok())
        };
        for i in 0..report.processes.len() {
            let p = &report.processes[i];
            let Some((window, base)) = read_window(mem, p.physical) else { continue };
            let c = Candidate { physical: p.physical, dtb: p.dtb, window, window_base: base };
            let Some(flink) = at(&c, links) else { continue };
            if !kernel_pointer(flink) { continue; }
            if let Some(phys) = translate_any(mem, flink) {
                if let Some(&j) = by_links_phys.get(&phys) {
                    linked_to[j] = true;
                    field_vas[j] = Some(flink.wrapping_sub(links as u64));
                }
            }
        }
        // Primary test: if the field is KPROCESS.DirectoryTableBase, the
        // object starts 0x28 earlier with a DISPATCHER_HEADER whose Type byte
        // is 3 (ProcessObject). Same physical page, so a plain window read.
        let mut header_hits = 0usize;
        let mut header_tried = 0usize;
        for p in report.processes.iter().filter(|p| p.peb_confirmed).take(128) {
            if p.physical & 0xfff < 0x28 { continue; }
            let Some((window, base)) = read_window(mem, p.physical) else { continue };
            let c = Candidate { physical: p.physical, dtb: p.dtb, window, window_base: base };
            header_tried += 1;
            if at(&c, -0x28).is_some_and(|h| h & 0xff == 3) { header_hits += 1; }
        }
        report.layout.dispatcher_header_evidence = (header_hits, header_tried);
        // Which field did the scan match? For each candidate offset X, the
        // object would start at field_va - X, and KPROCESS.DirectoryTableBase
        // at +0x28 of that must be a page-table root. Read virtually: the
        // head of the object is usually on a different physical page.
        let mut evidence = Vec::new();
        let mut best = (0usize, 0x28u64);
        for x in [0x298u64, 0x388, 0x280, 0x2a0, 0x390] {
            let mut hits = 0usize;
            let mut tried = 0usize;
            for (p, fva) in report.processes.iter().zip(&field_vas).filter(|(p, _)| p.peb_confirmed) {
                let Some(fva) = fva else { continue };
                if tried >= 64 { break; }
                tried += 1;
                let Some(phys) = translate_any(mem, fva.wrapping_sub(x).wrapping_add(0x28)) else { continue };
                let mut bytes = [0u8; 8];
                if mem.read_exact_at(phys, &mut bytes).is_err() { continue; }
                let v = u64::from_le_bytes(bytes);
                let root = v & 0x000f_ffff_ffff_f000;
                if v >> 52 == 0 && root != 0 && root != p.dtb && (live_dtbs.contains(&root) || looks_like_pml4(mem, root)) { hits += 1; }
            }
            evidence.push((x, hits, tried));
            if hits > best.0 && hits * 2 > tried.max(1) { best = (hits, x); }
        }
        report.layout.field_offset = if header_hits * 2 > header_tried.max(1) { 0x28 } else { best.1 };
        report.layout.field_evidence = evidence;
        // Head dumps for the log: what precedes the field in virtual memory.
        for (p, fva) in report.processes.iter().zip(&field_vas).filter(|(p, f)| p.peb_confirmed && f.is_some()).take(2) {
            let fva = fva.unwrap();
            for x in [0x298u64, 0x388] {
                let mut words = Vec::new();
                for k in 0..16u64 {
                    let va = fva.wrapping_sub(x).wrapping_add(k * 8);
                    let w = translate_any(mem, va).and_then(|phys| {
                        let mut b = [0u8; 8];
                        mem.read_exact_at(phys, &mut b).ok().map(|_| u64::from_le_bytes(b))
                    });
                    words.push(w.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "<unmapped>".into()));
                }
                report.head_dumps.push(format!("pid {:?} field_va={fva:#x} head@field-{x:#x}: {}", p.pid, words.join(" ")));
            }
        }
        let x = report.layout.field_offset;
        for (i, p) in report.processes.iter_mut().enumerate() {
            p.in_active_list = Some(linked_to[i]);
            if let Some(fva) = field_vas[i] {
                let va = fva.wrapping_sub(x);
                p.eprocess_va = Some(va);
                if x != 0x28 {
                    p.other_dtb = translate_any(mem, va + 0x28).and_then(|phys| {
                        let mut b = [0u8; 8];
                        mem.read_exact_at(phys, &mut b).ok().map(|_| u64::from_le_bytes(b) & 0x000f_ffff_ffff_f000)
                    });
                }
            }
        }
    }

    // Same PID + same CreateTime at two physical addresses: the same object
    // imaged twice. Mark later copies and record the physical spacing; a
    // constant spacing across pairs means a region of the capture is a
    // time-shifted duplicate rather than kernel-side copies.
    report.processes.sort_by_key(|p| (p.source != "dtb-anchored", p.pid.unwrap_or(u64::MAX), p.physical));
    let mut first_by_key = HashMap::<(u64, u64), u64>::new();
    let mut deltas = HashMap::<u64, usize>::new();
    for p in report.processes.iter_mut() {
        let (Some(pid), Some(create)) = (p.pid, p.create_time) else { continue };
        match first_by_key.get(&(pid, create)) {
            Some(first) => { p.duplicate_of = Some(*first); *deltas.entry(p.physical - first).or_default() += 1; }
            None => { first_by_key.insert((pid, create), p.physical); }
        }
    }
    let mut spacing: Vec<(u64, usize)> = deltas.into_iter().collect();
    spacing.sort_by(|a, b| b.1.cmp(&a.1));
    report.duplicate_spacing = spacing.into_iter().take(5).collect();
    // Linkage per duplicate group: a process is linked if any imaged copy of
    // its EPROCESS is reachable from the active list.
    // Likewise ExitTime: a copy imaged before the process exited still
    // belongs to a process that did exit.
    let mut linked_groups = HashMap::<(u64, u64), bool>::new();
    let mut exit_groups = HashMap::<(u64, u64), u64>::new();
    for p in &report.processes {
        let (Some(pid), Some(create)) = (p.pid, p.create_time) else { continue };
        let e = linked_groups.entry((pid, create)).or_insert(false);
        *e |= p.in_active_list == Some(true);
        if let Some(x) = p.exit_time {
            let g = exit_groups.entry((pid, create)).or_insert(0);
            *g = (*g).max(x);
        }
    }
    for p in report.processes.iter_mut() {
        if let (Some(pid), Some(create)) = (p.pid, p.create_time) {
            if p.in_active_list.is_some() { p.group_linked = linked_groups.get(&(pid, create)).copied(); }
            if let (None, Some(x)) = (p.exit_time, exit_groups.get(&(pid, create))) {
                p.exit_time = Some(*x);
                p.exit_from_duplicate = true;
            }
        }
    }
    Ok(report)
}

fn learn_layout(objs: &[&Candidate], layout: &mut Layout) {
    if objs.len() < 2 { return; }
    let n = objs.len();
    // Physical windows are only meaningful after the field (same page);
    // bytes before it may belong to an unrelated physical page.
    let deltas = || (0..(WINDOW_AFTER as i64 - 16)).step_by(8);
    // ImageFileName: the offset at which the most objects show a plausible name.
    let mut best_name = (0usize, 0i64);
    for d in deltas() {
        let count = objs.iter().filter(|c| name_at(c, d).is_some()).count();
        if count > best_name.0 { best_name = (count, d); }
    }
    layout.scores.push(("name", best_name.0, best_name.1));
    if best_name.0 * 2 >= n { layout.name = Some(best_name.1); }
    // CreateTime: the offset where the most objects hold a plausible FILETIME.
    // (ExitTime is not adjacent on current builds; learned separately below.)
    let mut best_time = (0usize, 0i64);
    for d in deltas() {
        let count = objs.iter().filter(|c| at(c, d).is_some_and(plausible_filetime)).count();
        if count > best_time.0 { best_time = (count, d); }
    }
    layout.scores.push(("create", best_time.0, best_time.1));
    if best_time.0 * 2 >= n { layout.create_time = Some(best_time.1); }
    // ExitTime: zero in running processes, a FILETIME in exited ones; pick the
    // offset (other than CreateTime) that is always one of those and shows at
    // least one FILETIME. Absent if no captured object had exited.
    if let Some(create) = layout.create_time {
        let mut best_exit = (0usize, None);
        for d in deltas() {
            if d == create { continue; }
            let shaped = objs.iter().filter(|c| at(c, d).is_some_and(|v| v == 0 || plausible_filetime(v))).count();
            let nonzero = objs.iter().filter(|c| at(c, d).is_some_and(plausible_filetime)).count();
            if shaped == n && nonzero > 0 && nonzero < n && nonzero > best_exit.0 { best_exit = (nonzero, Some(d)); }
        }
        layout.exit_time = best_exit.1;
        layout.scores.push(("exit", best_exit.0, best_exit.1.unwrap_or(0)));
    }
    // UniqueProcessId: small, 4-aligned, distinct across objects; followed by
    // ActiveProcessLinks (two kernel pointers).
    let mut best_pid = (0usize, 0usize, 0i64);
    for d in deltas() {
        let values: Vec<u64> = objs.iter().filter_map(|c| at(c, d)).collect();
        if values.len() < n { continue; }
        let plausible = values.iter().filter(|v| plausible_pid(**v)).count();
        let distinct = values.iter().collect::<HashSet<_>>().len();
        let links_ok = objs.iter().filter(|c| at(c, d + 8).is_some_and(kernel_pointer) &&
            at(c, d + 16).is_some_and(kernel_pointer)).count();
        // Ties on distinctness go to the offset where more values are
        // plausible PIDs (a list head or flags word scores lower there).
        if plausible * 10 >= n * 9 && links_ok * 10 >= n * 9 && (distinct, plausible) > (best_pid.0, best_pid.1) {
            best_pid = (distinct, plausible, d);
        }
    }
    layout.scores.push(("pid-distinct", best_pid.0, best_pid.2));
    // Captures can hold the same object more than once, so distinctness is a
    // floor (40%), not a near-identity test; the kernel-pointer pair after
    // the field is the stronger constraint.
    if best_pid.0 * 10 >= n * 4 {
        layout.pid = Some(best_pid.2);
        layout.links = Some(best_pid.2 + 8);
    }
    // InheritedFromUniqueProcessId: values drawn from the PID set (parents may
    // have exited, so allow a minority of unknowns); not the PID offset itself.
    if let Some(pid_delta) = layout.pid {
        let pids: HashSet<u64> = objs.iter().filter_map(|c| at(c, pid_delta)).collect();
        let mut best = (0usize, 0i64);
        for d in deltas() {
            if d == pid_delta { continue; }
            let count = objs.iter().filter(|c| at(c, d).is_some_and(|v| plausible_pid(v) && pids.contains(&v))).count();
            let small = objs.iter().filter(|c| at(c, d).is_some_and(|v| v == 0 || plausible_pid(v))).count();
            if small * 10 >= n * 9 && count > best.0 { best = (count, d); }
        }
        layout.scores.push(("ppid", best.0, best.1));
        if best.0 * 2 >= n { layout.ppid = Some(best.1); }
    }
}

fn describe(c: &Candidate, peb: u64, peb_confirmed: bool, live_root: bool, layout: &Layout,
            source: &'static str) -> Process {
    Process {
        physical: c.physical, eprocess_va: None, dtb: c.dtb, other_dtb: None, live_root, peb, peb_confirmed,
        pid: layout.pid.and_then(|d| at(c, d)),
        ppid: layout.ppid.and_then(|d| at(c, d)),
        name: layout.name.and_then(|d| name_at_lenient(c, d)),
        create_time: layout.create_time.and_then(|d| at(c, d)).filter(|v| plausible_filetime(*v)),
        exit_time: layout.exit_time.and_then(|d| at(c, d)).filter(|v| plausible_filetime(*v)),
        in_active_list: None, source, duplicate_of: None, plausible: false, group_linked: None, exit_from_duplicate: false,
    }
}

/// Write `dumpy_eprocess.tsv` (and the look-alikes sidecar) for a report.
pub fn write_tsv(report: &Report, out_dir: &std::path::Path) -> std::io::Result<()> {
    use std::fs;
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
            p.create_time.map(filetime_iso).unwrap_or_default(),
            p.exit_time.map(filetime_iso).unwrap_or_default(),
            p.in_active_list.map(|v| v.to_string()).unwrap_or_default(),
            p.group_linked.map(|v| v.to_string()).unwrap_or_default(),
            p.eprocess_va.map(|v| format!("0x{v:x}")).unwrap_or_default(),
            p.physical.saturating_sub(report.layout.field_offset), p.peb, p.peb_confirmed,
            p.duplicate_of.map(|d| format!("0x{:x}", d.saturating_sub(report.layout.field_offset))).unwrap_or_default(),
            p.plausible));
    }
    fs::write(out_dir.join("dumpy_eprocess.tsv"), &out)?;
    if !keep_all && lookalikes > 0 { fs::write(out_dir.join("dumpy_eprocess_lookalikes.tsv"), &side)?; }
    Ok(())
}

/// FILETIME → "YYYY-MM-DD HH:MM:SS" UTC.
pub fn filetime_iso(ft: u64) -> String {
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filetime_conversion() {
        // 2026-11-20 00:00:00 UTC = 133 985 088 000 * 10^7 ... derive via known epoch math.
        assert_eq!(filetime_iso(116_444_736_000_000_000), "1970-01-01 00:00:00");
        assert_eq!(filetime_iso(132_223_104_000_000_000), "2020-01-01 00:00:00");
    }
    #[test]
    fn image_name_rules() {
        assert_eq!(image_name(b"svchost.exe\0\0\0\0\0"), Some("svchost.exe".into()));
        assert_eq!(image_name(b"System\0\0\0\0\0\0\0\0\0\0"), Some("System".into()));
        assert_eq!(image_name(b"Some name\0\0\0\0\0\0\0"), None); // short, no dot, not kernel
        assert_eq!(image_name(b"msedgewebview2\0\0"), Some("msedgewebview2".into())); // truncated
        assert_eq!(image_name(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"), None);
    }
    #[test]
    fn learns_layout_from_synthetic_objects() {
        // Three objects with DTB field at window offset 0x40, PEB at +0x528,
        // PID at +0x418, links at +0x420, create at +0x458, ppid +0x518, name +0x580.
        let mut objs = Vec::new();
        for i in 0..3u64 {
            let mut w = vec![0u8; (WINDOW_BEFORE + WINDOW_AFTER) as usize];
            let put = |w: &mut Vec<u8>, d: i64, v: u64| { let p = (0x40 + d) as usize; w[p..p + 8].copy_from_slice(&v.to_le_bytes()); };
            put(&mut w, 0, 0x1000 * (i + 1));
            put(&mut w, 0x528, 0x7ff700000000 + i * 0x1000);
            put(&mut w, 0x418, 4 * (i + 1) * 100);
            put(&mut w, 0x420, 0xffff8000_0000_0000 + i * 0x100);
            put(&mut w, 0x428, 0xffff8000_0000_1000 + i * 0x100);
            put(&mut w, 0x458, 0x01dc_0000_0000_0000 + i);
            put(&mut w, 0x518, if i == 0 { 4 } else { 400 });
            let p = (0x40 + 0x580) as usize; w[p..p + 11].copy_from_slice(b"svchost.exe");
            objs.push(Candidate { physical: 0x10040 + i * 0x1000, dtb: 0x1000 * (i + 1), window: w, window_base: 0x10000 + i * 0x1000 });
        }
        let refs: Vec<&Candidate> = objs.iter().collect();
        let mut layout = Layout::default();
        learn_layout(&refs, &mut layout);

        assert_eq!(layout.name, Some(0x580));
        assert_eq!(layout.create_time, Some(0x458));
        assert_eq!(layout.pid, Some(0x418));
        assert_eq!(layout.links, Some(0x420));
        assert_eq!(layout.ppid, Some(0x518));
    }
}
