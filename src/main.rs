
use colored::*;
use core::mem::size_of;
use crossterm::{execute, style::{Print, SetForegroundColor, ResetColor, Color}};
use crypto_hash::{Algorithm, Hasher};
use hex;
use log::LevelFilter;
use simplelog::*;
use std::borrow::Cow;
use std::collections::HashSet;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use std::fs;
use crate::fs::File;
use std::io::Read;
mod io;
use crate::io::*;
use std::io::stdout;
const CHUNK_SIZE: usize = 1024 * 1024 * 1024; // 1GB
use twoway::find_bytes;
fn find_mz_headers(buffer: &[u8]) -> Vec<usize> {
    let dos_magic = b"MZ";
    let mut mz_positions = Vec::new();
    let mut start = 0;

    while let Some(pos) = find_bytes(&buffer[start..], dos_magic) {
        mz_positions.push(start + pos);
        start += pos + dos_magic.len();
    }

    mz_positions
}
fn validate_and_extract_image(buffer: &mut Vec<u8>, pos: usize, abs_offset: usize, _needed_size: usize) -> bool {
    // Calculate relative position of the MZ header in the buffer
    let mz_relative_pos = abs_offset - pos;

    // Get size of image from PE Optional Header
    if mz_relative_pos + 0x3F >= buffer.len() {
        log::error!("PE header offset exceeds buffer size");
        return false;
    }

    let pe_header_offset = u32::from_le_bytes([buffer[mz_relative_pos+0x3C], buffer[mz_relative_pos+0x3D], buffer[mz_relative_pos+0x3E], buffer[mz_relative_pos+0x3F]]) as usize;
    let optional_header_offset = pe_header_offset + 4 + 20;

    // Check if accessing image size exceeds buffer size
    if mz_relative_pos + optional_header_offset + 59 >= buffer.len() {
        log::error!("PE image size offset exceeds buffer size");
        return false;
    }

    let image_size = u32::from_le_bytes([
        buffer[mz_relative_pos+optional_header_offset+56],
        buffer[mz_relative_pos+optional_header_offset+57],
        buffer[mz_relative_pos+optional_header_offset+58],
        buffer[mz_relative_pos+optional_header_offset+59],
    ]) as usize;

    // Validate if the image size is under the limit and doesn't exceed the original buffer length
    if image_size > 600 * 1024 * 1024 || mz_relative_pos + image_size > buffer.len() {
        log::error!("PE image size exceeds the limit or original buffer length");
        return false;
    }

    // This will start from the MZ header and span the entire image size
    let corrupted_data = &buffer[mz_relative_pos..mz_relative_pos+image_size];

    // Verify MZ header
    let mz_header = [0x4D, 0x5A]; // MZ header in bytes
    if corrupted_data.get(0..2) != Some(&mz_header[..]) {
        log::debug!("Data at offset: {:?}", corrupted_data.get(0..2));
        log::warn!("MZ header not found at offset 0x{:x}. Skipping extraction of the corrupted file.", abs_offset);
        return false;
    }

    // Get a vector of bytes from the buffer to write
    let trimmed_data = trim_trailing_null_bytes(corrupted_data);

    // Convert this byte slice to Vec<u8>
    let trimmed_data_vec = trimmed_data.to_vec();

    // Replace the original buffer data with the trimmed data
    *buffer = trimmed_data_vec;
    true
}
fn process_mz_offsets(
    buffer: &mut Vec<u8>,
    mz_offsets: Vec<usize>,
    file: &mut File,
    offset: &mut usize,
    count: &mut u32,
    headers: &mut HashSet<String>,
    output_path: &str,
) {
    for pos in mz_offsets {
        if pos + size_of::<IMAGE_DOS_HEADER>() > buffer.len() {
            let message = format!(
                "Offset {} exceeds buffer size at absolute offset 0x{:x}. Skipping...",
                pos,
                *offset + pos
            );
            log::warn!("{}", message);
            let _ = crossterm::execute!(
                std::io::stdout(),
                SetForegroundColor(Color::Red),
                Print(message),
                ResetColor,
                Print("\n")
            );
            continue;
        }

        let (dos_header, valid) =
            safe_read::<IMAGE_DOS_HEADER>(&buffer[pos..pos + size_of::<IMAGE_DOS_HEADER>()]);
        if !valid {
            let message = format!(
                "Warning: Failed to read IMAGE_DOS_HEADER at position {} (absolute position {}). It may be corrupted, processing.", 
                pos, 
                *offset + pos
            );
            log::warn!("{}", message);
            let _ = crossterm::execute!(
                std::io::stdout(),
                SetForegroundColor(Color::Red),
                Print(message),
                ResetColor,
                Print("\n")
            );
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
            let needed_size = nt_header_pos
                + std::cmp::max(
                    size_of::<IMAGE_NT_HEADERS32>(),
                    size_of::<IMAGE_NT_HEADERS64>(),
                );
            let current_size = buffer.len();
            if needed_size > current_size {
                if needed_size > 650 * 1024 * 1024 {
                    if !validate_and_extract_image(buffer, pos, *offset, needed_size) {
                        continue;
                    }
                } else {
                    if !read_and_extend_buffer(buffer, file, needed_size, nt_header_pos, *offset) {
                        continue;
                    }
                }
            }

            let mut new_buffer = vec![0; needed_size];
            new_buffer[..current_size].copy_from_slice(&buffer[..current_size]);
            let read_bytes = file
                .read(&mut new_buffer[current_size..])
                .expect("Failed to read data");
            if read_bytes < needed_size - current_size {
                let message = format!("Not enough data to read NT Header at position {} (absolute offset 0x{:x}). It may be corrupted.", nt_header_pos, *offset + nt_header_pos);
                log::warn!("{}", message);
                let _ = crossterm::execute!(
                    std::io::stdout(),
                    SetForegroundColor(Color::Red),
                    Print(message),
                    ResetColor,
                    Print("\n")
                );
                continue;
            }
            *buffer = new_buffer; // Assign the new buffer to the dereferenced mutable reference
        }

        if buffer[nt_header_pos..nt_header_pos + 4] == [0x50, 0x45, 0x00, 0x00] {
            let (magic_option, valid_magic) = safe_read::<u16>(&buffer[nt_header_pos + 0x18..]);
            if !valid_magic {
                let message = format!(
                    "Failed to read magic at position {}. Skipping...",
                    nt_header_pos + 0x18
                );
                log::warn!("{}", message);
                let _ = crossterm::execute!(
                    std::io::stdout(),
                    SetForegroundColor(Color::Red),
                    Print(message),
                    ResetColor,
                    Print("\n")
                );
                continue;
            }

            let magic = match magic_option {
                Some(m) => m,
                None => continue,
            };

            match magic {
                IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                    let (nt_headers_option, valid_nt_header) =
                        safe_read::<IMAGE_NT_HEADERS32>(&buffer[nt_header_pos..]);
                    if !valid_nt_header {
                        let message = format!("Warning: Failed to read IMAGE_NT_HEADERS32 at position {} (absolute position {}). It may be corrupted.", nt_header_pos, *offset + nt_header_pos);
                        log::warn!("{}", message);
                        let _ = crossterm::execute!(
                            std::io::stdout(),
                            SetForegroundColor(Color::Red),
                            Print(message),
                            ResetColor,
                            Print("\n")
                        );
                        continue;
                    }

                    let nt_headers = match nt_headers_option {
                        Some(header) => header,
                        None => continue,
                    };

                    process_nt_headers32(
                        buffer,
                        nt_headers,
                        nt_header_pos,
                        pos,
                        *offset,
                        valid_nt_header,
                        output_path,
                        count,
                        headers,
                    );
                }
                IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                    let (nt_headers_option, valid_nt_header) =
                        safe_read::<IMAGE_NT_HEADERS64>(&buffer[nt_header_pos..]);
                    if !valid_nt_header {
                        let message = format!("Warning: Failed to read IMAGE_NT_HEADERS64 at position {} (absolute position {}). It may be corrupted.", nt_header_pos, *offset + nt_header_pos);
                        log::warn!("{}", message);
                        let _ = crossterm::execute!(
                            std::io::stdout(),
                            SetForegroundColor(Color::Red),
                            Print(message),
                            ResetColor,
                            Print("\n")
                        );
                        continue;
                    }

                    let nt_headers = match nt_headers_option {
                        Some(header) => header,
                        None => continue,
                    };

                    process_nt_headers64(
                        buffer,
                        nt_headers,
                        nt_header_pos,
                        pos,
                        *offset,
                        valid_nt_header,
                        output_path,
                        count,
                        headers,
                    );
                }
                _ => {
                    continue;
                }
            }
        }
    }
}
fn process_nt_headers64(
    buffer: &mut Vec<u8>,
    nt_headers: IMAGE_NT_HEADERS64,
    _nt_header_pos: usize,
    pos: usize,
    offset: usize,
    valid_nt_header: bool,
    output_path: &str,
    count: &mut u32,
    headers: &mut HashSet<String>,
) {
    let file_alignment = nt_headers.OptionalHeader.FileAlignment as usize;

    let header_end = pos + nt_headers.OptionalHeader.SizeOfHeaders as usize;
    if header_end < pos {
        println!("Invalid header end. Skipping...");
        return;
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

        *buffer = new_buffer;
    }

    let header_str_bound = std::cmp::min(buffer.len(), header_end);
    if pos >= header_str_bound {
        let message = format!("Invalid string range at position {} (absolute position {}). Skipping...", pos, offset + pos);
        log::warn!("{}", message);
        let _ = crossterm::execute!(
            std::io::stdout(),
            SetForegroundColor(Color::Red),
            Print(message),
            ResetColor,
            Print("\n")
        );
        return;
    }

    let header_str = std::string::String::from_utf8_lossy(&buffer[pos..header_str_bound]);
    let header_str_owned = header_str.to_string();

    write_file(
        buffer,
        Cow::Borrowed(&header_str_owned),
        nt_headers.OptionalHeader.SizeOfImage as usize,
        file_alignment,
        valid_nt_header, // Propagate the validity flag
        pos,
        offset + pos,
        output_path,
        count,
        headers,
    );
}

fn process_nt_headers32(
    buffer: &mut Vec<u8>,
    nt_headers: IMAGE_NT_HEADERS32,
    _nt_header_pos: usize,
    pos: usize,
    offset: usize,
    valid_nt_header: bool,
    output_path: &str,
    count: &mut u32,
    headers: &mut HashSet<String>,
) {
    let file_alignment = nt_headers.OptionalHeader.FileAlignment as usize;

    let header_end = pos + nt_headers.OptionalHeader.SizeOfHeaders as usize;
    if header_end < pos {
        println!("Invalid header end. Skipping...");
        return;
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

        *buffer = new_buffer;
    }

    let header_str_bound = std::cmp::min(buffer.len(), header_end);
    if pos >= header_str_bound {
        let message = format!("Invalid string range at position {} (absolute position {}). Skipping...", pos, offset + pos);
        log::warn!("{}", message);
        let _ = crossterm::execute!(
            std::io::stdout(),
            SetForegroundColor(Color::Red),
            Print(message),
            ResetColor,
            Print("\n")
        );
        return;
    }

    let header_str = std::string::String::from_utf8_lossy(&buffer[pos..header_str_bound]);
    let header_str_owned = header_str.to_string();

    write_file(
        buffer,
        Cow::Borrowed(&header_str_owned),
        nt_headers.OptionalHeader.SizeOfImage as usize,
        file_alignment,
        valid_nt_header, // Propagate the validity flag
        pos,
        offset + pos,
        output_path,
        count,
        headers,
    );
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

    let log_dir = "./logs";
    fs::create_dir_all(log_dir).expect("Failed to create directories");

    // Create log file
    let log_file_path = format!("{}/app.log", log_dir);
    let log_file = File::create(&log_file_path).expect("Failed to create log file");

    

    WriteLogger::init(LevelFilter::Info, log_config, log_file).unwrap();
    extract_executables(input_path, output_path);
}