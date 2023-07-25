
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use crate::*;
pub fn safe_read<T>(buffer: &[u8]) -> (Option<T>, bool) {
    if buffer.len() < std::mem::size_of::<T>() {
        return (None, false);
    }
    let mut value: T = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            buffer.as_ptr(),
            &mut value as *mut T as *mut u8,
            std::mem::size_of::<T>(),
        );
    }
    (Some(value), true)
}
pub fn extract_executables(input_path: &str, output_path: &str) {
    let mut file = File::open(input_path).expect("Failed to open file");
    let mut offset: usize = 0;
    let mut count = 0;
    let mut headers = HashSet::new();
    let overlap = vec![0; 0];

    loop {
        let (mut buffer, bytes_read, has_more_data) = read_file_chunk(&mut file, overlap.clone());
        let mz_offsets = find_mz_headers(&buffer);
        process_mz_offsets(&mut buffer, mz_offsets, &mut file, &mut offset, &mut count, &mut headers, output_path);
        let (bytes_read, _overlap) = handle_overlap(buffer, &mut file, bytes_read);

        offset += bytes_read;

        if !has_more_data {
            break;
        }
    }
}
pub fn handle_large_size(
    buffer: &mut Vec<u8>,
    file: &mut File,
    needed_size: usize,
    current_size: usize,
    effective_len: usize,
    offset: &usize,
    output_path: &str,
    count: &mut u32,
    headers: &mut HashSet<String>,
) {
    buffer.resize(needed_size, 0);
    let read_bytes = file
        .read(&mut buffer[current_size..])
        .expect("Failed to read data");

    if read_bytes < needed_size - current_size {
        log::warn!("Not enough data to read NT Header at position {} (absolute offset 0x{:x}). It may be corrupted.", needed_size, offset);
        eprintln!("{}", format!("Not enough data to read NT Header at position {} (absolute offset 0x{:x}). It may be corrupted.", needed_size, offset).red());
        return;
    }

    let mz_positions = find_mz_headers(&buffer[..effective_len]);

    for pos in mz_positions {
        let abs_offset = offset + pos;
        let message = if needed_size >= 1024 * 1024 * 1024 {
            let needed_size_gb = needed_size as f64 / 1024.0 / 1024.0 / 1024.0;
            format!(
                "[x] NT Header from executable file reported size of {:.2} GB at offset 0x{:x} in input file. Processing possibly corrupted ELF file or 16-bit binary...",
                needed_size_gb,
                abs_offset
            )
        } else {
            let needed_size_mb = needed_size as f64 / 1024.0 / 1024.0;
            format!(
                "[x] NT Header from executable file reported size of {:.2} MB at offset 0x{:x} in input file. Processing possibly corrupted file...",
                needed_size_mb,
                abs_offset
            )
        };
        log::warn!("{}", message);

        if validate_and_extract_image(buffer, pos, abs_offset, needed_size) {
            let header_str = format!("MZ at offset 0x{:x}", abs_offset);
            write_file(
                buffer,
                Cow::Borrowed(&header_str),
                needed_size,
                4096, // file alignment, adjust as per requirements
                true, // validity of file, adjust as per requirements
                0, // position
                *offset,
                output_path,
                count,
                headers,
            );
        }
    }
}
pub fn trim_or_extend_data(data: &[u8], image_size: usize) -> Vec<u8> {
    let original_size = data.len();

    let mut new_data = Vec::from(data);
    if original_size > image_size {
        let trimmed_length = data.iter().rposition(|&x| x != 0).map_or(0, |pos| pos + 1);
        new_data.truncate(trimmed_length);
        let trimmed_size = original_size - trimmed_length;

        if trimmed_size > 0 {
            let trimmed_mb = trimmed_size as f64 / 1_000_000.0;
            log::warn!("Trimmed {:.2} MB of trailing null bytes", trimmed_mb);
            let message = format!("Trimmed {:.2} MB of trailing null bytes", trimmed_mb);
            let _ = execute!(
                stdout(),
                SetForegroundColor(Color::Yellow),
                Print(message),
                ResetColor,
                Print("\n")
            );
        }
    } else if original_size < image_size {
        let padding_needed = image_size - original_size;
        new_data.resize(image_size, 0);

        let padding_mb = padding_needed as f64 / 1_000_000.0;
        log::warn!("Padded with {:.2} MB of trailing null bytes", padding_mb);
        let message = format!("Padded with {:.2} MB of trailing null bytes", padding_mb);
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Yellow),
            Print(message),
            ResetColor,
            Print("\n")
        );
    }

    new_data
}

pub fn read_file_chunk(file: &mut File, overlap: Vec<u8>) -> (Vec<u8>, usize, bool) {
    let offset: usize = 0;
    let mut buffer = vec![0; CHUNK_SIZE + overlap.len()];
    let bytes_read = file.read(&mut buffer[overlap.len()..]).unwrap_or(0);
    
    buffer.splice(..overlap.len(), overlap.iter().cloned());
    buffer.truncate(bytes_read + overlap.len());

    let effective_len = bytes_read + overlap.len();
    let _mz_offsets = find_mz_headers(&buffer[..effective_len]);

    if bytes_read == 0 && overlap.is_empty() {
        return (buffer, offset, false);
    }

    (buffer, offset, true)
}
pub fn read_and_extend_buffer(
    buffer: &mut Vec<u8>,
    file: &mut File,
    needed_size: usize,
    nt_header_pos: usize,
    offset: usize,
) -> bool {
    let current_size = buffer.len();
    let mut new_buffer = vec![0; needed_size];
    new_buffer[..current_size].copy_from_slice(&buffer[..current_size]);
    match file.read(&mut new_buffer[current_size..]) {
        Ok(read_bytes) if read_bytes >= needed_size - current_size => {
            *buffer = new_buffer;
            true
        }
        _ => {
            let message = format!("Not enough data to read NT Header at position {} (absolute offset 0x{:x}). It may be corrupted.", nt_header_pos, offset + nt_header_pos);
            log::warn!("{}", message);
            let _ = crossterm::execute!(
                std::io::stdout(),
                SetForegroundColor(Color::Red),
                Print(message),
                ResetColor,
                Print("\n")
            );
            false
        }
    }
}
pub fn handle_overlap(buffer: Vec<u8>, file: &mut File, bytes_read: usize) -> (usize, Vec<u8>) {
    let overlap_size = if bytes_read > 0 {
        buffer.len().saturating_sub(CHUNK_SIZE)
    } else {
        0
    };

    let mut overlap = vec![0; 0];
    if overlap_size > 0 {
        overlap = buffer[CHUNK_SIZE..].to_vec();
    }

    // Seek back if overlap exists
    if bytes_read > 0 && !overlap.is_empty() {
        file.seek(SeekFrom::Current(-(overlap.len() as i64)))
            .unwrap();
        return (bytes_read - overlap.len(), overlap);
    }

    (bytes_read, overlap)
}
pub fn write_file(
    data: &mut Vec<u8>,
    _header_str: Cow<str>,
    header_bytes: usize,
    file_alignment: usize,
    valid: bool,
    pos: usize,
    offset: usize,
    output_path: &str,
    count: &mut u32,
    headers: &mut HashSet<String>,
) {
    let mut hasher = Hasher::new(Algorithm::SHA256);

    let end = pos + header_bytes;
    if end > data.len() {
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("Header bytes exceed data length. Skipping...\n"),
            ResetColor
        );
        return;
    }

    hasher
        .write_all(&data[pos..end])
        .expect("Failed to write data");
    let result = hasher.finish();
    let header_hash = hex::encode(&result);

    if headers.insert(header_hash.clone()) {
        let offset_hex = format!("{:X}", offset);
        let filename = format!("{}/{}_{}.exe", output_path, count, offset_hex);
        *count += 1;

        let padding = if file_alignment == 0 {
            0
        } else {
            header_bytes % file_alignment
        };
        let end = pos + header_bytes + padding;

        if end > data.len() {
            let _ = execute!(
                stdout(),
                SetForegroundColor(Color::Yellow),
                Print(format!("File at offset {} is too large or corrupted. Skipping...\n", offset)),
                ResetColor
            );
            return;
        }

        let mut file = File::create(&filename).expect("Failed to create file");
        file.write_all(&data[pos..end])
            .expect("Failed to write data");

        if valid {
            let _ = execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!("Extracted file: {}\n", filename)),
                ResetColor
            );
        } else {
            let _ = execute!(
                stdout(),
                SetForegroundColor(Color::Yellow),
                Print(format!("Warning: Extracted possibly corrupted file: {}\n", filename)),
                ResetColor
            );
        }
    } else {
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Blue),
            Print(format!("Duplicate executable with header hash {} skipped\n", header_hash)),
            ResetColor
        );
    }
}