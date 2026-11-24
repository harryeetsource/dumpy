//! INDEX.tsv: one row per extracted artifact, across user and kernel space.
//!
//! category  user-image | dotnet-assembly | dotnet-roslyn-script |
//!           user-orphan-code | kernel-module | kernel-unlisted | kernel-orphan-code
//! owner     processes that map it ("name(pid)"; first few, then "+N more"),
//!           or "kernel"
//! tier      exact | code-complete | inconsistent | merged | partial |
//!           unavailable | raw-region

use crate::kernel_scan::split_name;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::Path;

pub const HEADER: &str = "category\tname\tname_source\towner\tbase\tsize\ttier\toutput\tnotes\n";

fn table(path: &Path) -> Vec<HashMap<String, String>> {
    let Ok(text) = fs::read_to_string(path) else { return Vec::new() };
    let mut lines = text.lines();
    let header: Vec<String> = lines.next().unwrap_or_default().split('\t').map(str::to_owned).collect();
    lines.filter(|l| !l.is_empty()).map(|l| {
        header.iter().cloned().zip(l.split('\t').map(str::to_owned)).collect()
    }).collect()
}

fn hex(v: &str) -> Option<u64> { u64::from_str_radix(v.trim_start_matches("0x"), 16).ok() }

/// dtb -> "name(pid)" from the EPROCESS table, else the process table hints.
fn process_names(out: &Path) -> HashMap<u64, String> {
    let mut names = HashMap::new();
    for row in table(&out.join("dumpy_eprocess.tsv")) {
        if row.get("plausible").map(String::as_str) != Some("true") { continue; }
        let (Some(dtb), Some(name), Some(pid)) = (row.get("dtb").and_then(|v| hex(v)), row.get("name"), row.get("pid")) else { continue };
        let running = row.get("state").map(String::as_str) == Some("running");
        let label = format!("{name}({pid})");
        // Prefer a running copy's label.
        if running || !names.contains_key(&dtb) { names.insert(dtb, label); }
    }
    for row in table(&out.join("dumpy_processes.tsv")) {
        let Some(dtb) = row.get("dtb").and_then(|v| hex(v)) else { continue };
        names.entry(dtb).or_insert_with(|| {
            let n = row.get("name_hint").cloned().unwrap_or_default();
            let p = row.get("pid_hint").cloned().unwrap_or_default();
            if n.is_empty() || n == "unknown" { format!("dtb 0x{dtb:x}") } else { format!("{n}({p})") }
        });
    }
    names
}

fn owners(labels: &BTreeSet<String>) -> String {
    let all: Vec<&String> = labels.iter().collect();
    if all.len() <= 3 { return all.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "); }
    format!("{}, +{} more", all[..3].iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "), all.len() - 3)
}

pub fn write(out: &Path) -> io::Result<usize> {
    let names = process_names(out);
    let label = |dtb: u64| names.get(&dtb).cloned().unwrap_or_else(|| format!("dtb 0x{dtb:x}"));
    // (base, size) -> owning processes; base -> unlisted attribution.
    let mut owned = HashMap::<(u64, u64), BTreeSet<String>>::new();
    let mut unlisted_in = HashMap::<u64, BTreeSet<String>>::new();
    for row in table(&out.join("dumpy_modules.tsv")) {
        if let (Some(dtb), Some(base), Some(size)) = (row.get("dtb").and_then(|v| hex(v)), row.get("base").and_then(|v| hex(v)),
            row.get("size_of_image").and_then(|v| v.parse().ok())) {
            owned.entry((base, size)).or_default().insert(label(dtb));
        }
    }
    for row in table(&out.join("dumpy_unlisted_images.tsv")) {
        if let (Some(dtb), Some(base), Some(size)) = (row.get("dtb").and_then(|v| hex(v)), row.get("base").and_then(|v| hex(v)),
            row.get("size_of_image").and_then(|v| v.parse().ok())) {
            owned.entry((base, size)).or_default().insert(label(dtb));
            if row.get("attribution").map(String::as_str) == Some("unlisted") {
                unlisted_in.entry(base).or_default().insert(label(dtb));
            }
        }
    }
    let mut text = String::from(HEADER);
    let mut rows = 0usize;
    for row in table(&out.join("images").join("dumpy_recovery.tsv")) {
        let get = |k: &str| row.get(k).cloned().unwrap_or_default();
        let (name, source) = split_name(&get("name"));
        let category = if source.contains("Roslyn") { "dotnet-roslyn-script" }
            else if !get("clr_module").is_empty() { "dotnet-assembly" } else { "user-image" };
        let base = hex(&get("base")).unwrap_or(0);
        let size: u64 = get("image_bytes").parse().unwrap_or(0);
        let owner = owned.get(&(base, size)).map(owners).unwrap_or_default();
        let mut notes = Vec::new();
        if let Some(p) = unlisted_in.get(&base) { notes.push(format!("not in the loader list of {}", owners(p))); }
        if !get("pdb_key").is_empty() { notes.push(format!("pdb {}", get("pdb_key"))); }
        text.push_str(&format!("{category}\t{name}\t{source}\t{owner}\t0x{base:x}\t{size}\t{}\t{}\t{}\n",
            get("completeness"), get("output"), notes.join("; ")));
        rows += 1;
    }
    for row in table(&out.join("dumpy_orphan_executable.tsv")) {
        let get = |k: &str| row.get(k).cloned().unwrap_or_default();
        let dtb = hex(&get("dtb")).unwrap_or(0);
        let mut notes = vec![get("content_class")];
        if !get("process_runtime").is_empty() { notes.push(format!("runtime {}", get("process_runtime"))); }
        if get("content_match").len() > 1 { notes.push(format!("matches {}", get("content_match"))); }
        text.push_str(&format!("user-orphan-code\tcode_{}\t\t{}\t{}\t{}\traw-region\t{}\t{}\n",
            get("start").trim_start_matches("0x"), label(dtb), get("start"), get("span_bytes"), get("output"), notes.join("; ")));
        rows += 1;
    }
    if let Ok(kernel) = fs::read_to_string(out.join("kernel").join("dumpy_kernel_index.tsv")) {
        rows += kernel.lines().filter(|l| !l.is_empty()).count();
        text.push_str(&kernel);
    }
    fs::write(out.join("INDEX.tsv"), text)?;
    Ok(rows)
}
