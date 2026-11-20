//! Match offline PE verification results with original page-coverage evidence.
//! An offline file alone cannot distinguish zero-filled missing RAM from zeros
//! that were actually captured. The recovery TSV preserves that distinction.
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct Coverage {
    pub missing_import: usize,
    pub missing_export: usize,
    pub missing_file_backed: usize,
    pub fallback_pages: usize,
}

fn column(columns: &[&str], label: &str) -> io::Result<usize> {
    columns.iter().position(|value| *value == label).ok_or_else(||
        io::Error::new(io::ErrorKind::InvalidData,
            format!("recovery TSV lacks required column '{label}'")))
}

fn leaf(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

pub fn load(path: &Path) -> io::Result<HashMap<String, Coverage>> {
    let data = fs::read_to_string(path)?;
    let mut lines = data.lines();
    let header = lines.next().ok_or_else(||
        io::Error::new(io::ErrorKind::InvalidData, "empty recovery TSV"))?;
    let fields: Vec<_> = header.trim_end_matches('\r').split('\t').collect();
    let output = column(&fields, "output")?;
    let missing_import = column(&fields, "missing_import")?;
    let missing_export = column(&fields, "missing_export")?;
    let missing_file_backed = column(&fields, "missing_file_backed_pages")?;
    let fallback_pages = column(&fields, "fallback_pages")?;
    let mut map = HashMap::new();
    for line in lines {
        let row: Vec<_> = line.trim_end_matches('\r').split('\t').collect();
        let Some(name) = row.get(output).copied() else { continue };
        if name.is_empty() { continue; }
        let parse = |index: usize| row.get(index).and_then(|v| v.parse::<usize>().ok());
        let (Some(mi), Some(me), Some(mf), Some(fp)) =
            (parse(missing_import), parse(missing_export),
             parse(missing_file_backed), parse(fallback_pages)) else { continue };
        let key = leaf(name).to_ascii_lowercase();
        map.insert(key, Coverage { missing_import: mi, missing_export: me,
            missing_file_backed: mf, fallback_pages: fp });
    }
    Ok(map)
}

/// Distinguish a structurally malformed table from an untrustworthy partial
/// capture. No table is upgraded to `valid` based on coverage metadata.
pub fn effective(raw: &str, missing_directory: usize,
                 missing_file_backed: usize) -> &'static str {
    if raw == "absent" { return "absent"; }
    if raw == "unavailable" { return "unavailable"; }
    if missing_directory > 0 { return "incomplete-directory-pages"; }
    if missing_file_backed > 0 {
        return if raw == "valid" { "valid-partial-capture" }
            else { "unresolved-partial-capture" };
    }
    if raw == "valid" { "valid" } else { "invalid-complete-file-pages" }
}

pub fn find_report(dir: &Path) -> Option<std::path::PathBuf> {
    let local = dir.join("dumpy_recovery.tsv");
    if local.is_file() { return Some(local); }
    let parent = dir.parent()?.join("dumpy_recovery.tsv");
    if parent.is_file() { Some(parent) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handles_windows_and_unix_names() {
        assert_eq!(leaf(r"C:\temp\foo.partial.bin"), "foo.partial.bin");
        assert_eq!(leaf("/tmp/foo.partial.bin"), "foo.partial.bin");
    }
    #[test]
    fn does_not_assert_validity_from_missing_pages() {
        assert_eq!(effective("invalid", 1, 5), "incomplete-directory-pages");
        assert_eq!(effective("invalid", 0, 5), "unresolved-partial-capture");
        assert_eq!(effective("invalid", 0, 0), "invalid-complete-file-pages");
        assert_eq!(effective("valid", 0, 5), "valid-partial-capture");
    }
}
