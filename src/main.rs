use core::mem::size_of;
use crypto_hash::{Algorithm, Hasher};
use hex;
use log::LevelFilter;
use simplelog::*;
use std::borrow::Cow;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use std::collections::HashSet;
use colored::*;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
const CHUNK_SIZE: usize = 1024 * 1024 * 1024; // 1GB

fn find_mz_headers(buffer: &[u8]) -> Vec<usize> {
    let dos_magic = b"MZ";
    let mut mz_positions = Vec::new();

    for pos in 0..buffer.len() - dos_magic.len() {
        if buffer[pos..pos + dos_magic.len()] == *dos_magic {
            mz_positions.push(pos);
        }
    }

    mz_positions
}

fn extract_executables(input_path: &str, output_path: &str) {
    let mut file = File::open(input_path).expect("Failed to open file");
    let mut offset: usize = 0;
    let mut overlap = vec![0; 0];

    loop {
        let mut buffer = vec![0; CHUNK_SIZE + 0x200];

        let bytes_read = file
            .read(&mut buffer[overlap.len()..])
            .expect("Failed to read data");

        // Check if there are no more bytes to read
        if bytes_read == 0 && overlap.is_empty() {
            break;
        }

        buffer.splice(..overlap.len(), overlap.iter().cloned());
        buffer.truncate(bytes_read + overlap.len());

        let effective_len = bytes_read + overlap.len(); // We store the effective length here before potentially enlarging the buffer
        let mz_offsets = find_mz_headers(&buffer[..effective_len]); // Search only within the effective length
        log::debug!("Found {} MZ headers.", mz_offsets.len());
        let mut count = 0;
        let mut headers = HashSet::new();

        for pos in mz_offsets {
            if pos + size_of::<IMAGE_DOS_HEADER>() > buffer.len() {
                log::warn!(
                    "Offset {} exceeds buffer size at absolute offset 0x{:x}. Skipping...",
                    pos,
                    offset + pos
                );                
                continue;
            }
        
            let (dos_header, valid) = safe_read::<IMAGE_DOS_HEADER>(&buffer[pos..pos + size_of::<IMAGE_DOS_HEADER>()]);
            if !valid {
                log::warn!("Warning: Failed to read IMAGE_DOS_HEADER at position {} (absolute position {}). It may be corrupted.", pos, offset + pos);
                continue;
            }

            let dos_header = match dos_header {
                Some(header) => header,
                None => continue,
            };

            if dos_header.e_magic != 0x5a4d {
                continue;
            }

            let nt_header_pos = pos + dos_header.e_lfanew as usize;
            if nt_header_pos + size_of::<IMAGE_NT_HEADERS32>() > buffer.len()
    || nt_header_pos + size_of::<IMAGE_NT_HEADERS64>() > buffer.len()
{
    let needed_size = nt_header_pos + std::cmp::max(size_of::<IMAGE_NT_HEADERS32>(), size_of::<IMAGE_NT_HEADERS64>());
    let current_size = buffer.len();
    if needed_size > current_size {
        let metadata = file.metadata().expect("Failed to retrieve file metadata");
        let file_size = metadata.len() as usize;
        if needed_size > file_size {
            log::warn!("Warning: Attempt to read beyond file size at absolute offset 0x{:x}. The file may be corrupted or incorrectly formatted. Skipping...", offset + nt_header_pos);
            eprintln!("{}", format!("Warning: Attempt to read beyond file size at absolute offset 0x{:x}. The file may be corrupted or incorrectly formatted. Skipping...", offset + nt_header_pos).red());
            continue;
        }
        if needed_size > 650 * 1024 * 1024 { // 650 MB
            let needed_size_mb = needed_size as f64 / 1024.0 / 1024.0;
            if needed_size_mb >= 1024.0 {
                let needed_size_gb = needed_size_mb / 1024.0;
                let message = format!("[x] Attempted to allocate a buffer of {:.2} GB at offset 0x{:x}. Skipping...", needed_size_gb, offset + nt_header_pos);
                log::warn!("{}", message);
                let _ = crossterm::execute!(
                    std::io::stdout(),
                    SetForegroundColor(Color::Red),
                    Print(message),
                    ResetColor,
                    Print("\n")
                );
            } else {
                let message = format!("[x] Attempted to allocate a buffer of {:.2} MB at offset 0x{:x}. Skipping...", needed_size_mb, offset + nt_header_pos);
                log::warn!("{}", message);
                let _ = crossterm::execute!(
                    std::io::stdout(),
                    SetForegroundColor(Color::Red),
                    Print(message),
                    ResetColor,
                    Print("\n")
                );
            }
            continue;
        }
        
        
        
        
        
        let mut new_buffer = vec![0; needed_size];
        new_buffer[..current_size].copy_from_slice(&buffer[..current_size]);
        let read_bytes = file.read(&mut new_buffer[current_size..]).expect("Failed to read data");
        if read_bytes < needed_size - current_size {
            log::warn!("Not enough data to read NT Header at position {} (absolute offset 0x{:x}). It may be corrupted.", nt_header_pos, offset + nt_header_pos);
            eprintln!("{}", format!("Not enough data to read NT Header at position {} (absolute offset 0x{:x}). It may be corrupted.", nt_header_pos, offset + nt_header_pos).red());
            continue;
        }
        buffer = new_buffer;
    }
}

        

            if buffer[nt_header_pos..nt_header_pos + 4] == [0x50, 0x45, 0x00, 0x00] {
                let (magic_option, valid_magic) = safe_read::<u16>(&buffer[nt_header_pos + 0x18..]);
                if !valid_magic {
                    log::warn!(
                        "Failed to read magic at position {}. Skipping...",
                        nt_header_pos + 0x18
                    );
                    continue;
                }

                let magic = match magic_option {
                    Some(m) => m,
                    None => continue,
                };

                if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
                    let (nt_headers_option, valid_nt_header) =
                        safe_read::<IMAGE_NT_HEADERS32>(&buffer[nt_header_pos..]);
                    if !valid_nt_header {
                        log::warn!("Warning: Failed to read IMAGE_NT_HEADERS32 at position {} (absolute position {}). It may be corrupted.", nt_header_pos, offset + nt_header_pos);
                        continue;
                    }

                    let nt_headers = match nt_headers_option {
                        Some(header) => header,
                        None => continue,
                    };

                    let header_end = pos + nt_headers.OptionalHeader.SizeOfHeaders as usize;

                    if header_end < pos {
                        println!("Invalid header end. Skipping...");
                        continue;
                    }

                    if header_end > buffer.len() {
                        let upper_bound = std::cmp::min(
                            buffer.len(),
                            pos + nt_headers.OptionalHeader.SizeOfImage as usize,
                        );
                        let mut new_buffer = vec![0; upper_bound - pos];
                        new_buffer.copy_from_slice(&buffer[pos..upper_bound]);

                        let remaining_upper_bound = std::cmp::min(buffer.len(), header_end);
                        let remaining_data = &buffer[remaining_upper_bound..];

                        new_buffer.extend_from_slice(remaining_data);

                        buffer = new_buffer;
                    }

                    let header_str_bound = std::cmp::min(buffer.len(), header_end);
                    if pos >= header_str_bound {
                        log::warn!("Invalid string range. Skipping...");
                        continue;
                    }

                    let header_str =
                        std::string::String::from_utf8_lossy(&buffer[pos..header_str_bound]);

                    let header_str_owned = header_str.to_string();
                    let valid = valid && valid_nt_header; // Both the DOS header and NT header must be valid for the file to be valid

                    write_file(
                        &mut buffer,
                        Cow::Borrowed(&header_str_owned),
                        nt_headers.OptionalHeader.SizeOfImage as usize,
                        nt_headers.OptionalHeader.FileAlignment as usize,
                        valid, // Propagate the validity flag
                        pos,
                        offset + pos,
                        output_path,
                        &mut count,
                        &mut headers,
                    );
                } else if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                    let (nt_headers_option, valid_nt_header) =
                        safe_read::<IMAGE_NT_HEADERS64>(&buffer[nt_header_pos..]);
                    if !valid_nt_header {
                        log::warn!("Warning: Failed to read IMAGE_NT_HEADERS64 at position {} (absolute position {}). It may be corrupted.", nt_header_pos, offset + nt_header_pos);
                        continue;
                    }

                    let nt_headers = match nt_headers_option {
                        Some(header) => header,
                        None => continue,
                    };

                    let header_end = pos + nt_headers.OptionalHeader.SizeOfHeaders as usize;

                    if header_end < pos {
                        println!("Invalid header end. Skipping...");
                        continue;
                    }

                    if header_end > buffer.len() {
                        let upper_bound = std::cmp::min(
                            buffer.len(),
                            pos + nt_headers.OptionalHeader.SizeOfImage as usize,
                        );
                        let mut new_buffer = vec![0; upper_bound - pos];
                        new_buffer.copy_from_slice(&buffer[pos..upper_bound]);

                        let remaining_upper_bound = std::cmp::min(buffer.len(), header_end);
                        let remaining_data = &buffer[remaining_upper_bound..];

                        new_buffer.extend_from_slice(remaining_data);

                        buffer = new_buffer;
                    }

                    let header_str_bound = std::cmp::min(buffer.len(), header_end);
                    if pos >= header_str_bound {
                        log::warn!("Invalid string range at position {} (absolute position {}). Skipping...", pos, offset + pos);
                        continue;
                    }

                    let header_str =
                        std::string::String::from_utf8_lossy(&buffer[pos..header_str_bound]);

                    let header_str_owned = header_str.to_string();
                    let valid = valid && valid_nt_header; // Both the DOS header and NT header must be valid for the file to be valid

                    write_file(
                        &mut buffer,
                        Cow::Borrowed(&header_str_owned),
                        nt_headers.OptionalHeader.SizeOfImage as usize,
                        nt_headers.OptionalHeader.FileAlignment as usize,
                        valid, // Propagate the validity flag
                        pos,
                        offset + pos,
                        output_path,
                        &mut count,
                        &mut headers,
                    );
                }
            }
        }

        offset += bytes_read;

        if count == 0 {
            println!("No more executables found in the memory chunk. Continuing to the next memory region.");
        } else {
            println!(
                "Extracted {} executables to output path: {}",
                count, output_path
            );
        }

        // Only set overlap if we actually read some bytes
        let overlap_size = if bytes_read > 0 {
            buffer.len().saturating_sub(CHUNK_SIZE)
        } else {
            0
        };
        
        if overlap_size > 0 {
            overlap = buffer[CHUNK_SIZE..].to_vec();

            // If no new bytes were read, don't seek backwards in the file
            if bytes_read > 0 {
                file.seek(SeekFrom::Current(-(overlap.len() as i64)))
                    .unwrap();
            }
        } else {
            overlap.clear();
        }
    }
}

fn safe_read<T>(buffer: &[u8]) -> (Option<T>, bool) {
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

fn write_file(
    data: &mut Vec<u8>,
    _header_str: Cow<str>,
    header_bytes: usize,
    file_alignment: usize,
    valid: bool,
    pos: usize,
    offset: usize,
    output_path: &str,
    count: &mut u32,
    headers: &mut std::collections::HashSet<String>,
) {
    let mut hasher = Hasher::new(Algorithm::SHA256);

    let end = pos + header_bytes;
    if end > data.len() {
        println!("Header bytes exceed data length. Skipping...");
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
            println!(
                "File at offset {} is too large or corrupted. Skipping...",
                offset
            );
            return;
        }

        let mut file = File::create(&filename).expect("Failed to create file");
        file.write_all(&data[pos..end])
            .expect("Failed to write data");

        if valid {
            println!("Extracted file: {}", filename);
        } else {
            println!("Warning: Extracted possibly corrupted file: {}", filename);
        }
    } else {
        println!(
            "Duplicate executable with header hash {} skipped",
            header_hash
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        println!("Usage: {} <input_file> <output_dir>", args[0]);
        return;
    }

    let input_path = &args[1];
    let output_path = &args[2];

    if !std::path::Path::new(input_path).exists() {
        println!("Input file does not exist: {}", input_path);
        return;
    }

    if let Ok(metadata) = fs::metadata(output_path) {
        if !metadata.is_dir() {
            println!("Output path is not a directory: {}", output_path);
            return;
        }
    } else {
        fs::create_dir_all(output_path).expect("Failed to create output directory");
    }
    let log_config = ConfigBuilder::new().set_time_to_local(true).build();

    let log_file = File::create("app.log").unwrap();

    WriteLogger::init(LevelFilter::Info, log_config, log_file).unwrap();
    extract_executables(input_path, output_path);
}