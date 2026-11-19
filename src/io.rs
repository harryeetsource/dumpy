use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

const SCAN_CHUNK: usize = 8 * 1024 * 1024;

/// Scan every byte (including chunk boundaries) for MZ without loading the entire disk image.
pub fn find_candidates(file: &mut File, mut visit: impl FnMut(&mut File, u64) -> io::Result<()>) -> io::Result<()> {
    let length = file.metadata()?.len();
    let mut buf = vec![0u8; SCAN_CHUNK + 1];
    let mut start = 0u64;
    while start < length {
        file.seek(SeekFrom::Start(start))?;
        let n = file.read(&mut buf[..SCAN_CHUNK])?;
        if n == 0 { break; }
        let mut local = 0usize;
        while local + 1 < n {
            if buf[local] == b'M' && buf[local + 1] == b'Z' {
                visit(file, start + local as u64)?;
            }
            local += 1;
        }
        let advance = if n == SCAN_CHUNK { n - 1 } else { n };
        start += advance as u64;
    }
    Ok(())
}

/// Read exactly the candidate's available bytes without leaking reads into other file positions.
pub fn read_at(file: &mut File, offset: u64, max_len: usize) -> io::Result<Vec<u8>> {
    let length = file.metadata()?.len();
    if offset >= length { return Ok(Vec::new()); }
    let available = usize::try_from((length - offset).min(max_len as u64)).unwrap_or(max_len);
    let mut result = vec![0u8; available];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut result)?;
    Ok(result)
}
