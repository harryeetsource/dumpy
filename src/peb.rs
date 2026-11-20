//! Process-aware user-module enumeration through a validated AMD64 PEB and
//! PEB_LDR_DATA list. Offsets here describe the x64 user-mode loader ABI;
//! they are checked against actual list links and PE headers before use.
//! This is not a substitute for symbol-resolved EPROCESS/VAD traversal.
use crate::memory::PhysicalMemory;
use crate::rebuild::Pe;
use std::collections::HashSet;

const MAX_MODULES: usize = 512;
const USER_LIMIT: u64 = 0x0000_8000_0000_0000;

#[derive(Clone, Debug)]
pub struct LoadedModule {
    pub base: u64,
    pub size: u32,
    pub name: String,
    /// Also linked in InMemoryOrderModuleList.
    pub in_memory_order: bool,
    /// Also linked in InInitializationOrderModuleList (the main image and
    /// not-yet-initialised DLLs are legitimately absent from this one).
    pub in_init_order: bool,
    /// Header page not resident here; accepted because another process's
    /// validated loader list has the same (base, SizeOfImage).
    pub header_from_known_identity: bool,
}

#[derive(Clone, Debug)]
pub struct PebProcess {
    pub peb: u64,
    pub bitness: u8,
    pub image_base: u64,
    pub ldr: u64,
    pub modules: Vec<LoadedModule>,
    /// DllBase values linked in InMemoryOrderModuleList, whether or not
    /// they are in InLoadOrderModuleList. Unlink detection compares these.
    pub memory_order_bases: HashSet<u64>,
    pub init_order_bases: HashSet<u64>,
    /// InLoadOrder list walked to its tail with every backlink consistent.
    pub ldr_complete: bool,
    /// Entries traversed (validated or not) before the walk ended.
    pub ldr_entries: usize,
    /// Entries whose module header could not be validated in this process.
    pub skipped_headers: usize,
}

/// Collect DllBase from every entry of one Ldr list. `link_offset` is where
/// this list's LIST_ENTRY sits inside LDR_DATA_TABLE_ENTRY, so the entry
/// start is `node - link_offset`. Bounded and cycle-safe; backlinks are not
/// enforced because this is corroborating evidence, not the primary list.
fn list_bases(mem: &mut PhysicalMemory<'_>, dtb: u64, head: u64, link_offset: u64,
              base_offset: usize, wide: bool) -> HashSet<u64> {
    let mut bases = HashSet::new();
    let ptr_size = if wide { 8 } else { 4 };
    let ptr = |b: &[u8], at: usize| if wide { qword(b, at) } else { dword(b, at).map(u64::from) };
    let ok = |v: u64| if wide { user_pointer(v) } else { user_pointer32(v) };
    let mut link = [0u8; 16];
    if mem.read_virtual(dtb, head, &mut link, 4).is_err() { return bases; }
    // Walk forward via Flink, then backward via Blink: one non-resident
    // entry page no longer hides everything behind it.
    for direction in [0usize, ptr_size] {
        let Some(mut current) = ptr(&link, direction) else { continue };
        let mut seen = HashSet::new();
        while current != head && ok(current) && seen.insert(current) && seen.len() <= MAX_MODULES {
            let Some(entry) = current.checked_sub(link_offset) else { break };
            let mut bytes = [0u8; 0x40];
            if mem.read_virtual(dtb, entry, &mut bytes, 4).is_err() { break; }
            if let Some(base) = ptr(&bytes, base_offset) { if base != 0 { bases.insert(base); } }
            let mut links = [0u8; 16];
            if mem.read_virtual(dtb, current, &mut links, 4).is_err() { break; }
            let Some(n) = ptr(&links, direction) else { break };
            current = n;
        }
    }
    bases
}

pub fn user_pointer(value: u64) -> bool {
    (0x10000..USER_LIMIT).contains(&value) && value & 7 == 0
}

fn user_pointer32(value: u64) -> bool {
    (0x10000..0x1_0000_0000).contains(&value) && value & 3 == 0
}

fn qword(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn dword(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn wide_name(mem: &mut PhysicalMemory<'_>, dtb: u64, length: usize,
             maximum: usize, address: u64) -> Option<String> {
    if length == 0 || length > 1024 || length & 1 != 0 || length > maximum ||
       !(0x10000..USER_LIMIT).contains(&address) || address & 1 != 0 {
        return None;
    }
    let mut bytes = vec![0u8; length];
    mem.read_virtual(dtb, address, &mut bytes, 4).ok()?;
    let units = bytes.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect::<Vec<_>>();
    let name = String::from_utf16(&units).ok()?;
    if name.is_empty() || name.chars().any(|ch| ch.is_control() || ch == '\t') {
        return None;
    }
    Some(name)
}

fn leaf(name: String) -> String {
    name.rsplit(['\\', '/']).next().map(str::to_owned).unwrap_or(name)
}

fn unicode_at(mem: &mut PhysicalMemory<'_>, dtb: u64, entry: &[u8], at: usize) -> Option<String> {
    let length = u16::from_le_bytes(entry.get(at..at + 2)?.try_into().ok()?) as usize;
    let maximum = u16::from_le_bytes(entry.get(at + 2..at + 4)?.try_into().ok()?) as usize;
    let address = qword(entry, at + 8)?;
    wide_name(mem, dtb, length, maximum, address)
}

fn unicode_at32(mem: &mut PhysicalMemory<'_>, dtb: u64, entry: &[u8], at: usize) -> Option<String> {
    let length = u16::from_le_bytes(entry.get(at..at + 2)?.try_into().ok()?) as usize;
    let maximum = u16::from_le_bytes(entry.get(at + 2..at + 4)?.try_into().ok()?) as usize;
    let address = dword(entry, at + 4)? as u64;
    wide_name(mem, dtb, length, maximum, address)
}

/// BaseDllName (+0x58) first; its buffer usually lives inside the FullDllName
/// buffer, but when that page is not resident FullDllName (+0x48) is a
/// separate allocation worth trying before giving up on the name.
fn unicode_name(mem: &mut PhysicalMemory<'_>, dtb: u64, entry: &[u8]) -> Option<String> {
    unicode_at(mem, dtb, entry, 0x58)
        .or_else(|| unicode_at(mem, dtb, entry, 0x48).map(leaf))
}

fn unicode_name32(mem: &mut PhysicalMemory<'_>, dtb: u64, entry: &[u8]) -> Option<String> {
    unicode_at32(mem, dtb, entry, 0x2c)
        .or_else(|| unicode_at32(mem, dtb, entry, 0x24).map(leaf))
}

/// Known `(DllBase, SizeOfImage)` pairs from loader lists already validated
/// in other address spaces. System DLL bases are per-boot constants, so a
/// matching pair is accepted as a module even when this process's copy of the
/// header page is not resident.
pub type KnownModules = HashSet<(u64, u32)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderCheck { Valid, KnownIdentity, Rejected }

fn pe_header(mem: &mut PhysicalMemory<'_>, dtb: u64, base: u64, expected_size: u32,
             known: &KnownModules) -> HeaderCheck {
    if !user_pointer(base) || expected_size == 0 || expected_size as usize > crate::rebuild::MAX_IMAGE {
        return HeaderCheck::Rejected;
    }
    let mut first = [0u8; 4096];
    let readable = mem.read_virtual(dtb, base, &mut first, 4).is_ok();
    if readable {
        let nt = dword(&first, 0x3c).unwrap_or(u32::MAX) as usize;
        if nt <= 0x800 && first.get(..2) == Some(b"MZ") &&
            first.get(nt..nt.saturating_add(4)) == Some(b"PE\0\0") {
            let size = dword(&first, nt + 24 + 56);
            let header_size = dword(&first, nt + 24 + 60);
            if size == Some(expected_size) && header_size.is_some_and(|h| h <= 4096) &&
                Pe::parse(&first).is_ok() {
                return HeaderCheck::Valid;
            }
        }
    }
    if known.contains(&(base, expected_size)) { HeaderCheck::KnownIdentity } else { HeaderCheck::Rejected }
}

/// Cheap candidate gate called while scanning user pages; expensive checks
/// only follow when plausible user-mode ImageBaseAddress and Ldr pointers
/// occur at the x64 PEB positions.
///
/// `PEB.Mutant` (+0x8 on x64, +0x4 on x86) is initialised to
/// INVALID_HANDLE_VALUE by MmCreatePeb and never changes. Requiring it here
/// rejects the two most common look-alikes: a PEB_LDR_DATA page (two list
/// heads at +0x10/+0x18) and a PE section table (VirtualSize/VirtualAddress
/// pairs), both of which otherwise pass the pointer-shape test.
pub fn maybe_peb_prefix(page: &[u8]) -> bool {
    let Some(mutant) = qword(page, 0x08) else { return false };
    let Some(base) = qword(page, 0x10) else { return false };
    let Some(ldr) = qword(page, 0x18) else { return false };
    mutant == u64::MAX &&
        user_pointer(base) && user_pointer(ldr) && base & 0xfff == 0 &&
        page.first().is_some_and(|v| *v <= 0x7f) &&
        page.get(2).is_some_and(|v| *v <= 1)
}

pub fn maybe_peb_prefix32(page: &[u8]) -> bool {
    let Some(mutant) = dword(page, 0x4) else { return false };
    let Some(base) = dword(page, 0x8) else { return false };
    let Some(ldr) = dword(page, 0xc) else { return false };
    mutant == u32::MAX &&
        base >= 0x10000 && base & 0xfff == 0 && ldr >= 0x10000 &&
        page.first().is_some_and(|v| *v <= 0x7f) &&
        page.get(2).is_some_and(|v| *v <= 1)
}

/// Field offsets for PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY of one bitness.
struct Layout {
    bitness: u8,
    prefix_len: usize,
    image_base: usize,
    ldr: usize,
    load_head: u64,
    mem_head: u64, mem_link: u64,
    init_head: u64, init_link: u64,
    entry_len: usize,
    entry_base: usize,
    entry_size: usize,
}
const LAYOUT64: Layout = Layout { bitness: 64, prefix_len: 0x40, image_base: 0x10, ldr: 0x18,
    load_head: 0x10, mem_head: 0x20, mem_link: 0x10, init_head: 0x30, init_link: 0x20,
    entry_len: 0x70, entry_base: 0x30, entry_size: 0x40 };
const LAYOUT32: Layout = Layout { bitness: 32, prefix_len: 0x20, image_base: 0x8, ldr: 0xc,
    load_head: 0x0c, mem_head: 0x14, mem_link: 0x8, init_head: 0x1c, init_link: 0x10,
    entry_len: 0x38, entry_base: 0x18, entry_size: 0x20 };

/// Walk a PEB. The InLoadOrder list is validated link by link; when it breaks
/// (unreadable entry, backlink mismatch) the modules validated so far are
/// kept and `ldr_complete` is false, instead of discarding the process. A
/// process is still rejected when nothing validates or the main image is not
/// among the validated modules. The `&'static str` names the first failure.
fn inspect_with(mem: &mut PhysicalMemory<'_>, dtb: u64, peb: u64, layout: &Layout,
                known: &KnownModules) -> Result<PebProcess, &'static str> {
    let wide = layout.bitness == 64;
    let ptr = |b: &[u8], at: usize| if wide { qword(b, at) } else { dword(b, at).map(u64::from) };
    let ok = |v: u64| if wide { user_pointer(v) } else { user_pointer32(v) };
    if !user_pointer(peb) || (!wide && peb >= u32::MAX as u64) { return Err("peb-not-user-pointer"); }
    let mut prefix = [0u8; 0x40];
    mem.read_virtual(dtb, peb, &mut prefix[..layout.prefix_len], 4).map_err(|_| "peb-page-unreadable")?;
    let gate = if wide { maybe_peb_prefix(&prefix) } else { maybe_peb_prefix32(&prefix) };
    if !gate { return Err("peb-prefix-mismatch"); }
    let image_base = ptr(&prefix, layout.image_base).ok_or("peb-short")?;
    let ldr = ptr(&prefix, layout.ldr).ok_or("peb-short")?;
    let mut signature = [0u8; 2];
    let image_mz = match mem.read_virtual(dtb, image_base, &mut signature, 4) {
        Ok(()) => signature == *b"MZ",
        Err(_) => false,
    };
    // Not fatal: the loader entry for ImageBaseAddress can still attribute
    // the process (see main_by_entry below); only used to name the failure.
    let image_known = image_mz || known.iter().any(|(b, _)| *b == image_base);
    let head = ldr.checked_add(layout.load_head).ok_or("ldr-overflow")?;
    let mut list = [0u8; 16];
    mem.read_virtual(dtb, head, &mut list, 4).map_err(|_| "ldr-page-unreadable")?;
    let first = ptr(&list, 0).ok_or("ldr-short")?;
    let tail = ptr(&list, if wide { 8 } else { 4 }).ok_or("ldr-short")?;
    if !ok(first) || !ok(tail) { return Err("ldr-head-not-user-pointer"); }
    let mut seen = HashSet::new();
    let mut modules: Vec<LoadedModule> = Vec::new();
    let mut ldr_complete = true;
    let mut entries = 0usize;
    let mut skipped_headers = 0usize;
    let ptr_size = if wide { 8 } else { 4 };
    // Forward from Flink, validating each Blink against the node we came
    // from; if that breaks, backward from Blink validating each Flink. The
    // list is complete only when the forward walk reaches the tail.
    let mut forward_reached_tail = false;
    for direction in [0usize, ptr_size] {
        let backward = direction != 0;
        let mut current = if backward { tail } else { first };
        let mut previous = head;
        loop {
            if current == head {
                if !backward { forward_reached_tail = previous == tail; }
                break;
            }
            if !ok(current) || !seen.insert(current) || seen.len() > MAX_MODULES {
                // Meeting an already-seen node on the backward walk means
                // the two walks joined up: nothing was lost.
                if !(backward && seen.contains(&current)) { ldr_complete = false; }
                break;
            }
            let mut entry = [0u8; 0x70];
            if mem.read_virtual(dtb, current, &mut entry[..layout.entry_len], 4).is_err() {
                ldr_complete = false;
                break;
            }
            let (Some(flink), Some(blink)) = (ptr(&entry, 0), ptr(&entry, ptr_size)) else {
                ldr_complete = false; break;
            };
            let (next, came_from) = if backward { (blink, flink) } else { (flink, blink) };
            if came_from != previous || (!ok(next) && next != head) { ldr_complete = false; break; }
            entries += 1;
            let (Some(base), Some(size)) = (ptr(&entry, layout.entry_base), dword(&entry, layout.entry_size)) else {
                ldr_complete = false; break;
            };
            let check = pe_header(mem, dtb, base, size, known);
            // The main image is attributed by PEB.ImageBaseAddress agreeing
            // with its own loader entry, even when its header is paged out.
            let main_by_entry = check == HeaderCheck::Rejected && base == image_base && size != 0;
            if check == HeaderCheck::Rejected && !main_by_entry {
                skipped_headers += 1;
            } else if !modules.iter().any(|m| m.base == base) {
                let name = (if wide { unicode_name(mem, dtb, &entry) } else { unicode_name32(mem, dtb, &entry) })
                    .unwrap_or_else(|| format!("module_{base:x}"));
                modules.push(LoadedModule { base, size, name, in_memory_order: false, in_init_order: false,
                    header_from_known_identity: check == HeaderCheck::KnownIdentity || main_by_entry });
            }
            previous = current;
            current = next;
        }
        if !backward && forward_reached_tail { break; }
    }
    if forward_reached_tail { ldr_complete = true; }
    if entries == 0 { return Err("ldr-list-empty-or-first-entry-unreadable"); }
    if modules.is_empty() {
        return Err(if skipped_headers > 0 { "no-module-header-validated" } else { "ldr-list-unreadable" });
    }
    if !modules.iter().any(|module| module.base == image_base) {
        return Err(if image_known { "main-image-not-in-validated-modules" } else { "image-base-header-unreadable" });
    }
    let memory_order_bases = list_bases(mem, dtb, ldr + layout.mem_head, layout.mem_link, layout.entry_base, wide);
    let init_order_bases = list_bases(mem, dtb, ldr + layout.init_head, layout.init_link, layout.entry_base, wide);
    for module in &mut modules {
        module.in_memory_order = memory_order_bases.contains(&module.base);
        module.in_init_order = init_order_bases.contains(&module.base);
    }
    Ok(PebProcess { peb, bitness: layout.bitness, image_base, ldr, modules, memory_order_bases,
        init_order_bases, ldr_complete, ldr_entries: entries, skipped_headers })
}

pub fn inspect(mem: &mut PhysicalMemory<'_>, dtb: u64, peb: u64, known: &KnownModules)
               -> Result<PebProcess, &'static str> {
    inspect_with(mem, dtb, peb, &LAYOUT64, known)
}

/// WOW64 PEB32 and LDR32 data have 32-bit pointers even though the DTB is
/// an AMD64 process page-table root.
pub fn inspect32(mem: &mut PhysicalMemory<'_>, dtb: u64, peb: u64, known: &KnownModules)
                 -> Result<PebProcess, &'static str> {
    inspect_with(mem, dtb, peb, &LAYOUT32, known)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    #[test]
    fn candidate_gate_checks_user_pointers_and_peb_flags() {
        let mut page = [0u8; 64];
        page[0x08..0x10].copy_from_slice(&u64::MAX.to_le_bytes());
        page[0x10..0x18].copy_from_slice(&0x140000000u64.to_le_bytes());
        page[0x18..0x20].copy_from_slice(&0x70000000u64.to_le_bytes());
        assert!(maybe_peb_prefix(&page));
        page[0x18..0x20].copy_from_slice(&0xfffff80000001000u64.to_le_bytes());
        assert!(!maybe_peb_prefix(&page));
    }

    #[test]
    fn full_name_fallback_keeps_only_the_leaf() {
        assert_eq!(leaf(r"C:\Windows\System32\ntdll.dll".into()), "ntdll.dll");
        assert_eq!(leaf("ntdll.dll".into()), "ntdll.dll");
    }

    #[test]
    fn candidate_gate_requires_invalid_handle_mutant() {
        // A PEB_LDR_DATA page has two user pointers at +0x10/+0x18 but no
        // INVALID_HANDLE_VALUE at +0x8; it must not become a PEB candidate.
        let mut page = [0u8; 64];
        page[0x10..0x18].copy_from_slice(&0x12000u64.to_le_bytes());
        page[0x18..0x20].copy_from_slice(&0x12000u64.to_le_bytes());
        assert!(!maybe_peb_prefix(&page));
        let mut page32 = [0u8; 64];
        page32[0x8..0xc].copy_from_slice(&0x400000u32.to_le_bytes());
        page32[0xc..0x10].copy_from_slice(&0x77000000u32.to_le_bytes());
        assert!(!maybe_peb_prefix32(&page32));
        page32[0x4..0x8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(maybe_peb_prefix32(&page32));
    }

    #[test]
    fn enumerates_loader_module_from_synthetic_address_space() {
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("dumpy_peb_{}_{}",
            std::process::id(), unique));
        let mut file = OpenOptions::new().create_new(true).read(true).write(true)
            .open(&path).expect("synthetic memory file");
        file.set_len(0xc000).unwrap();
        let put = |file: &mut std::fs::File, at: u64, bytes: &[u8]| {
            file.seek(SeekFrom::Start(at)).unwrap();
            file.write_all(bytes).unwrap();
        };
        for (at, next) in [(0x1000u64, 0x2007u64), (0x2000, 0x3007), (0x3000, 0x4007)] {
            put(&mut file, at, &next.to_le_bytes());
        }
        const NX: u64 = 1 << 63;
        // PEB page (0x10) is deliberately mapped read-only so the direct
        // prefix scan cannot see it; the TEB page (0x15, RW+NX) must lead
        // the scanner to it through NT_TIB.Self / ProcessEnvironmentBlock.
        // LDR/entry/name pages are RW+NX data; the PE header page is RX.
        for (va, pa, flags) in [(0x10usize, 0x5000u64, 5 | NX), (0x11, 0x6000, 7 | NX),
                                (0x12, 0x7000, 7 | NX), (0x13, 0x8000, 5),
                                (0x14, 0x9000, 7 | NX), (0x15, 0xa000, 7 | NX)] {
            put(&mut file, 0x4000 + (va as u64) * 8, &(pa | flags).to_le_bytes());
        }
        put(&mut file, 0xa000 + 0x30, &0x15000u64.to_le_bytes());
        put(&mut file, 0xa000 + 0x60, &0x10080u64.to_le_bytes());
        // Place the PEB 0x80 bytes into the mapped page. The page scanner
        // must find it without relying on a page-aligned PEB address.
        put(&mut file, 0x5000 + 0x80 + 0x08, &u64::MAX.to_le_bytes());
        put(&mut file, 0x5000 + 0x80 + 0x10, &0x13000u64.to_le_bytes());
        put(&mut file, 0x5000 + 0x80 + 0x18, &0x11000u64.to_le_bytes());
        put(&mut file, 0x6000 + 0x10, &0x12000u64.to_le_bytes());
        put(&mut file, 0x6000 + 0x18, &0x12000u64.to_le_bytes());
        put(&mut file, 0x7000, &0x11010u64.to_le_bytes());
        put(&mut file, 0x7008, &0x11010u64.to_le_bytes());
        // InMemoryOrderModuleList (LDR +0x20) links entry +0x10; leave
        // InInitializationOrderModuleList (LDR +0x30) empty like a main image.
        put(&mut file, 0x6000 + 0x20, &0x12010u64.to_le_bytes());
        put(&mut file, 0x6000 + 0x28, &0x12010u64.to_le_bytes());
        put(&mut file, 0x7010, &0x11020u64.to_le_bytes());
        put(&mut file, 0x7018, &0x11020u64.to_le_bytes());
        put(&mut file, 0x6000 + 0x30, &0x11030u64.to_le_bytes());
        put(&mut file, 0x6000 + 0x38, &0x11030u64.to_le_bytes());
        put(&mut file, 0x7000 + 0x30, &0x13000u64.to_le_bytes());
        put(&mut file, 0x7000 + 0x40, &0x2000u32.to_le_bytes());
        put(&mut file, 0x7000 + 0x58, &16u16.to_le_bytes());
        put(&mut file, 0x7000 + 0x5a, &16u16.to_le_bytes());
        put(&mut file, 0x7000 + 0x60, &0x14000u64.to_le_bytes());
        let name: Vec<u8> = "test.exe".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        put(&mut file, 0x9000, &name);
        let mut header = [0u8; 4096];
        header[..2].copy_from_slice(b"MZ");
        header[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        header[0x80..0x84].copy_from_slice(b"PE\0\0");
        header[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        header[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        header[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        header[0x98 + 32..0x98 + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        header[0x98 + 36..0x98 + 40].copy_from_slice(&0x200u32.to_le_bytes());
        header[0x98 + 56..0x98 + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        header[0x98 + 60..0x98 + 64].copy_from_slice(&0x400u32.to_le_bytes());
        header[0x188..0x18d].copy_from_slice(b".text");
        header[0x188 + 8..0x188 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        header[0x188 + 12..0x188 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        header[0x188 + 16..0x188 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        header[0x188 + 20..0x188 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        put(&mut file, 0x8000, &header);
        file.flush().unwrap();
        {
            let mut memory = PhysicalMemory::new(&mut file).unwrap();
            let process = inspect(&mut memory, 0x1000, 0x10080, &KnownModules::new()).unwrap();
            assert_eq!(process.modules.len(), 1);
            assert_eq!(process.modules[0].name, "test.exe");
            assert_eq!(process.modules[0].base, 0x13000);
            assert!(process.modules[0].in_memory_order);
            assert!(!process.modules[0].in_init_order);
            assert_eq!(process.bitness, 64);
            let scan = crate::user_images::scan_process_aware(&mut memory, 0x1000, Some(32), &KnownModules::new()).unwrap();
            assert_eq!(scan.processes.len(), 1);
            assert_eq!(scan.processes[0].peb, 0x10080);
            assert_eq!(scan.teb_hits, 1);
            assert_eq!(scan.peb_candidates, 1);
            assert_eq!(scan.peb_rejected, 0);
            // Only the four RW+NX pages were read in full.
            assert_eq!(scan.private_rw_pages, 4);
            assert_eq!(scan.processes[0].modules[0].name, "test.exe");
            assert!(scan.processes[0].ldr_complete);
        }
        // Unmap the module's header page: the process is rejected with a
        // named reason, unless another address space already validated the
        // same (base, size), in which case the module is accepted as a
        // known identity.
        put(&mut file, 0x4000 + 0x13 * 8, &0u64.to_le_bytes());
        {
            let mut memory = PhysicalMemory::new(&mut file).unwrap();
            // The main image is still attributed: PEB.ImageBaseAddress agrees
            // with its own loader entry, and that is flagged, not hidden.
            let by_entry = inspect(&mut memory, 0x1000, 0x10080, &KnownModules::new()).unwrap();
            assert_eq!(by_entry.modules.len(), 1);
            assert!(by_entry.modules[0].header_from_known_identity);
            let known: KnownModules = [(0x13000u64, 0x2000u32)].into_iter().collect();
            let process = inspect(&mut memory, 0x1000, 0x10080, &known).unwrap();
            assert_eq!(process.modules.len(), 1);
            assert!(process.modules[0].header_from_known_identity);
            assert_eq!(process.modules[0].name, "test.exe");
            // Break the list: entry1 -> entry2 (VA 0x1a000, unmapped) ->
            // entry3 (VA 0x16000) -> head. Forward stops at entry2; the
            // backward walk from head.Blink recovers entry3.
            put(&mut file, 0x7000, &0x1a000u64.to_le_bytes());          // entry1.Flink
            put(&mut file, 0x6000 + 0x18, &0x16000u64.to_le_bytes());  // head.Blink
            put(&mut file, 0x4000 + 0x16 * 8, &(0xb000u64 | 7 | (1 << 63)).to_le_bytes());
            put(&mut file, 0xb000, &0x11010u64.to_le_bytes());         // entry3.Flink = head
            put(&mut file, 0xb008, &0x1a000u64.to_le_bytes());         // entry3.Blink = entry2
            put(&mut file, 0xb000 + 0x30, &0x17000u64.to_le_bytes());  // DllBase (header absent)
            put(&mut file, 0xb000 + 0x40, &0x1000u32.to_le_bytes());
        }
        {
            let mut memory = PhysicalMemory::new(&mut file).unwrap();
            let known: KnownModules = [(0x13000u64, 0x2000u32), (0x17000, 0x1000)].into_iter().collect();
            let process = inspect(&mut memory, 0x1000, 0x10080, &known).unwrap();
            assert!(!process.ldr_complete);
            assert_eq!(process.ldr_entries, 2);
            let mut bases = process.modules.iter().map(|m| m.base).collect::<Vec<_>>();
            bases.sort();
            assert_eq!(bases, vec![0x13000, 0x17000]);
        }
        drop(file);
        fs::remove_file(path).unwrap();
    }
}
