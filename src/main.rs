use crate::fs::File;
use colored::*;
use core::mem::size_of;
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use crypto_hash::{Algorithm, Hasher};
use hex;
use log::LevelFilter;
use simplelog::*;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
    IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_SECTION_HEADER, IMAGE_FILE_HEADER, IMAGE_DIRECTORY_ENTRY_EXPORT,
};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_EXPORT_DIRECTORY};
mod io;
use crate::io::*;
use std::error::Error;
use std::io::stdout;
use std::path::Path;
const CHUNK_SIZE: usize = 1024 * 1024 * 1024; // 1GB
use twoway::find_bytes;
mod rebuild;
use rebuild::process_extracted_pe;
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


// validate_and_extract_image now returns a Result<(), String>
fn validate_and_extract_image(
    buffer: &mut Vec<u8>,
    pos: usize,
    abs_offset: usize,
    _needed_size: usize,
    output_path: &str,
    count: &mut u32,
    header_bytes: usize,
    file_alignment: usize,
    valid: bool,
    headers: &mut HashSet<String>,
) -> Result<(), String> {
    let mz_relative_pos = abs_offset.wrapping_sub(pos);

    if mz_relative_pos + 0x3C + 4 > buffer.len() {
        return Err("PE header offset exceeds buffer size".into());
    }

    let pe_header_offset = u32::from_le_bytes([
        buffer[mz_relative_pos + 0x3C],
        buffer[mz_relative_pos + 0x3D],
        buffer[mz_relative_pos + 0x3E],
        buffer[mz_relative_pos + 0x3F],
    ]) as usize;
    let optional_header_offset = pe_header_offset + 4 + 20;

    if mz_relative_pos + optional_header_offset + 59 >= buffer.len() {
        return Err("PE image size offset exceeds buffer size".into());
    }

    let image_size = u32::from_le_bytes([
        buffer[mz_relative_pos + optional_header_offset + 56],
        buffer[mz_relative_pos + optional_header_offset + 57],
        buffer[mz_relative_pos + optional_header_offset + 58],
        buffer[mz_relative_pos + optional_header_offset + 59],
    ]) as usize;

    if image_size > 600 * 1024 * 1024 || mz_relative_pos + image_size > buffer.len() {
        return Err("PE image size exceeds the limit or original buffer length".into());
    }

    let corrupted_data = &buffer[mz_relative_pos..mz_relative_pos + image_size];
    let mz_header = [0x4D, 0x5A];
    if corrupted_data.get(0..2) != Some(&mz_header[..]) {
        return Err(format!("MZ header not found at offset 0x{:x}", abs_offset));
    }

    let trimmed_data = trim_or_extend_data(corrupted_data, image_size);
    let trimmed_data_vec = trimmed_data.to_vec();
    log::debug!("Extracted PE image length: {}", trimmed_data_vec.len());

    // Now call handle_extracted_pe with the trimmed image.
    unsafe {
        handle_extracted_pe(
            trimmed_data_vec.clone(),
            output_path,
            count,
            header_bytes,
            file_alignment,
            valid,
            pos,
            abs_offset,
            headers,
        )?;

        *buffer = trimmed_data_vec;
        Ok(())
    }
}
fn process_mz_offsets(
    buffer: &mut Vec<u8>,
    mz_offsets: Vec<usize>,
    file: &mut File,
    offset: &mut usize,
    count: &mut u32,
    headers: &mut std::collections::HashSet<String>,
    output_path: &str,
) {
    const NT32_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR32_MAGIC.0;
    const NT64_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR64_MAGIC.0;

    for pos in mz_offsets {
        // Check that there are enough bytes for a DOS header.
        if pos + std::mem::size_of::<IMAGE_DOS_HEADER>() > buffer.len() {
            let message = format!(
                "Offset 0x{:x} exceeds buffer size at absolute offset 0x{:x}. Skipping...",
                pos,
                *offset + pos
            );
            log::warn!("{}", message);
            let _ = crossterm::execute!(
                std::io::stdout(),
                SetForegroundColor(Color::Red),
                Print(&message),
                ResetColor,
                Print("\n")
            );
            continue;
        }

        // Read the DOS header.
        let (dos_header_opt, valid) = safe_read::<IMAGE_DOS_HEADER>(
            &buffer[pos..pos + std::mem::size_of::<IMAGE_DOS_HEADER>()],
        );
        if !valid {
            log::warn!(
                "Warning: Failed to read IMAGE_DOS_HEADER at position {} (absolute offset 0x{:x}).",
                pos,
                *offset + pos
            );
            continue;
        }
        let dos_header = match dos_header_opt {
            Some(header) => header,
            None => continue,
        };

        if dos_header.e_magic != 0x5A4D {
            // Not a valid MZ header.
            continue;
        }

        // Candidate start.
        let candidate_start = pos;

        // Ensure we have enough data to read the PE header offset.
        let pe_offset_end = candidate_start + 0x3C + 4;
        if pe_offset_end > buffer.len() {
            if !read_and_extend_buffer(buffer, file, pe_offset_end, candidate_start, *offset) {
                log::error!(
                    "Failed to extend buffer for candidate starting at 0x{:x}",
                    candidate_start
                );
                continue;
            }
        }
        let pe_header_offset = u32::from_le_bytes([
            buffer[candidate_start + 0x3C],
            buffer[candidate_start + 0x3D],
            buffer[candidate_start + 0x3E],
            buffer[candidate_start + 0x3F],
        ]) as usize;
        let optional_header_offset = pe_header_offset + 4 + 20;

        // Ensure we have enough data for the image size field.
        let required_image_size_index = candidate_start + optional_header_offset + 59;
        if required_image_size_index >= buffer.len() {
            if !read_and_extend_buffer(
                buffer,
                file,
                required_image_size_index + 1,
                candidate_start,
                *offset,
            ) {
                log::error!(
                    "Failed to extend buffer for image size offset for candidate starting at 0x{:x}",
                    candidate_start
                );
                continue;
            }
        }
        let image_size = u32::from_le_bytes([
            buffer[candidate_start + optional_header_offset + 56],
            buffer[candidate_start + optional_header_offset + 57],
            buffer[candidate_start + optional_header_offset + 58],
            buffer[candidate_start + optional_header_offset + 59],
        ]) as usize;

        if image_size > 600 * 1024 * 1024 {
            log::error!(
                "Candidate image size out of range at candidate starting at 0x{:x}",
                candidate_start
            );
            continue;
        }

        // Ensure the full candidate image (up to image_size) is in the buffer.
        if candidate_start + image_size > buffer.len() {
            if !read_and_extend_buffer(
                buffer,
                file,
                candidate_start + image_size,
                candidate_start,
                *offset,
            ) {
                log::error!(
                    "Failed to extend buffer for candidate image starting at 0x{:x}",
                    candidate_start
                );
                continue;
            }
        }

        // Extract candidate image.
        let mut candidate_vec = buffer[candidate_start..candidate_start + image_size].to_vec();
        log::debug!(
            "Extracted candidate PE image from absolute offset 0x{:x} with size {} bytes",
            *offset + pos,
            candidate_vec.len()
        );

        // --- New step: Ensure candidate covers at least the headers (SizeOfHeaders) ---
        let nt_header_pos = dos_header.e_lfanew as usize;
        if candidate_vec.len() < nt_header_pos + 4 {
            log::error!(
                "Candidate too small for NT header at relative offset 0x{:x}",
                nt_header_pos
            );
            continue;
        }
        if candidate_vec[nt_header_pos..nt_header_pos + 4] != [0x50, 0x45, 0x00, 0x00] {
            log::error!(
                "PE signature not found in candidate at relative offset 0x{:x}",
                nt_header_pos
            );
            continue;
        }
        // Read magic value from Optional Header.
        let magic_offset = nt_header_pos + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>();
        if candidate_vec.len() < magic_offset + 2 {
            log::error!("Candidate too small to read Optional Header magic");
            continue;
        }
        let magic = u16::from_le_bytes([candidate_vec[magic_offset], candidate_vec[magic_offset + 1]]);
        let header_size = if magic == NT32_MAGIC {
            if candidate_vec.len() < nt_header_pos + size_of::<IMAGE_NT_HEADERS32>() {
                0
            } else {
                let nt_headers = unsafe {
                    &*(candidate_vec[nt_header_pos..].as_ptr() as *const IMAGE_NT_HEADERS32)
                };
                nt_headers.OptionalHeader.SizeOfHeaders as usize
            }
        } else if magic == NT64_MAGIC {
            if candidate_vec.len() < nt_header_pos + size_of::<IMAGE_NT_HEADERS64>() {
                0
            } else {
                let nt_headers = unsafe {
                    &*(candidate_vec[nt_header_pos..].as_ptr() as *const IMAGE_NT_HEADERS64)
                };
                nt_headers.OptionalHeader.SizeOfHeaders as usize
            }
        } else {
            0
        };

        if header_size == 0 {
            log::error!(
                "Unable to read SizeOfHeaders from candidate at absolute offset 0x{:x}",
                *offset + pos
            );
            continue;
        }

        // Extend candidate_vec if necessary so that it covers at least the header region.
        let required_total = candidate_start + std::cmp::max(image_size, header_size);
        if required_total > buffer.len() {
            if !read_and_extend_buffer(buffer, file, required_total, candidate_start, *offset) {
                log::error!(
                    "Failed to extend buffer to cover headers for candidate starting at 0x{:x}",
                    candidate_start
                );
                continue;
            }
            candidate_vec = buffer[candidate_start..required_total].to_vec();
        }
        // --- End new step ---

        // Primary path: validate and extract (which rebuilds the static PE)
        // NOTE: We now pass header_size as the header_bytes value.
        if let Err(e) = validate_and_extract_image(
            &mut candidate_vec.clone(),
            0,
            *offset + pos,
            image_size, // expected image size from header
            output_path,
            count,
            header_size, // pass the actual header size from the Optional Header
            4096,
            true,
            headers,
        ) {
            log::error!(
                "Error validating and extracting image at absolute offset 0x{:x}: {}",
                *offset + pos,
                e
            );
            // Fallback: try writing the candidate as-is.
            let header_str = format!("MZ at offset 0x{:x}", *offset + pos);
            if let Err(err) = write_file(
                &mut candidate_vec.clone(),
                Cow::Borrowed(&header_str),
                image_size,
                4096,
                true,
                0,
                *offset + pos,
                output_path,
                count,
                headers,
            ) {
                log::error!("Fallback write_file failed: {}", err);
            }
            // If the primary path failed, continue to NT header processing.
        } else {
            log::info!(
                "Candidate PE validated and extracted at absolute offset 0x{:x}",
                *offset + pos
            );
            // Skip further NT header processing for this candidate.
            continue;
        }

        // Fallback path: Process NT headers if validate_and_extract_image fails.
        if candidate_vec.len() < nt_header_pos + 4 {
            log::error!(
                "Candidate too small for NT header at relative offset 0x{:x}",
                nt_header_pos
            );
            continue;
        }
        if candidate_vec[nt_header_pos..nt_header_pos + 4] != [0x50, 0x45, 0x00, 0x00] {
            log::error!(
                "PE signature not found in candidate at relative offset 0x{:x}",
                nt_header_pos
            );
            continue;
        }
        let (magic_opt, valid_magic) = safe_read::<u16>(&candidate_vec[nt_header_pos + 0x18..]);
        if !valid_magic {
            log::error!("Failed to read NT header magic from candidate");
            continue;
        }
        let magic = match magic_opt {
            Some(m) => m,
            None => continue,
        };

        match magic {
            NT32_MAGIC => {
                process_nt_headers32(
                    &mut candidate_vec,
                    file,
                    nt_header_pos,
                    0, // candidate now starts at 0
                    *offset + pos,
                    output_path,
                    count,
                    headers,
                );
            }
            NT64_MAGIC => {
                process_nt_headers64(
                    &mut candidate_vec,
                    file,
                    nt_header_pos,
                    0, // candidate now starts at 0
                    *offset + pos,
                    output_path,
                    count,
                    headers,
                );
            }
            _ => continue,
        }
    }
}









pub unsafe fn handle_extracted_pe(
    extracted_pe: Vec<u8>,
    output_dir: &str, // expected to be a directory path
    count: &mut u32,
    header_bytes: usize,
    file_alignment: usize,
    valid: bool,
    pos: usize,
    offset: usize,
    headers: &mut HashSet<String>,
) -> Result<(), String> {
    // Build the full output file path.
    let output_file = format!("{}/extracted_static_{}.exe", output_dir, *count);
    process_extracted_pe(
        extracted_pe,
        &output_file, // pass the full file path here
        header_bytes,
        file_alignment,
        valid,
        pos,
        offset,
        count,
        headers,
    )
}




fn process_nt_headers64(
    buffer: &mut Vec<u8>,
    file: &mut File,
    nt_header_pos: usize,
    pos: usize,
    offset: usize,
    output_dir: &str, // expected to be a directory path
    count: &mut u32,
    headers: &mut HashSet<String>,
) {
    log::debug!(
        "(64-bit) Buffer length before NT header reading: {}. nt_header_pos: {}, required: {}",
        buffer.len(),
        nt_header_pos,
        nt_header_pos + std::mem::size_of::<IMAGE_NT_HEADERS64>()
    );
    if buffer.len() < nt_header_pos + std::mem::size_of::<IMAGE_NT_HEADERS64>() {
        log::warn!(
            "Buffer length {} is less than expected for IMAGE_NT_HEADERS64 ({}). Attempting to extend...",
            buffer.len(),
            nt_header_pos + std::mem::size_of::<IMAGE_NT_HEADERS64>()
        );
        if !read_and_extend_buffer(buffer, file, nt_header_pos + std::mem::size_of::<IMAGE_NT_HEADERS64>(), pos, offset) {
            log::error!(
                "Failed to extend candidate buffer for NT header reading at absolute offset 0x{:x}",
                offset
            );
            return;
        }
        log::debug!("Buffer length after extension: {}", buffer.len());
    }
    let (nt_headers_opt, valid_nt_header) =
        safe_read::<IMAGE_NT_HEADERS64>(&buffer[nt_header_pos..]);
    if !valid_nt_header {
        log::error!(
            "Failed to read IMAGE_NT_HEADERS64 from candidate at relative offset 0x{:x}",
            nt_header_pos
        );
        return;
    }
    let nt_headers = match nt_headers_opt {
        Some(h) => h,
        None => return,
    };

    let header_end = pos + nt_headers.OptionalHeader.SizeOfHeaders as usize;
    log::debug!(
        "(64-bit) Expected header_end: {}. Current buffer length: {}",
        header_end,
        buffer.len()
    );
    if header_end > buffer.len() {
        log::warn!(
            "Buffer length {} is less than expected header_end {}. Attempting to extend...",
            buffer.len(),
            header_end
        );
        if !read_and_extend_buffer(buffer, file, header_end, pos, offset) {
            log::error!(
                "Failed to extend candidate buffer for header extraction at absolute offset 0x{:x}",
                offset
            );
            return;
        }
        log::debug!("Buffer length after extension: {}", buffer.len());
    }

    let header_str = String::from_utf8_lossy(&buffer[pos..header_end]);
    log::info!(
        "Processing 64-bit NT headers at pos 0x{:x} (absolute offset 0x{:x}). Header length: {}. Buffer length: {}. Header:\n{}",
        pos,
        offset + pos,
        header_end - pos,
        buffer.len(),
        header_str
    );

    // Build full output file path from output_dir.
    let output_file = format!("{}/extracted_static_{}.exe", output_dir, *count);
    let out_path = Path::new(&output_file);
    if let Some(parent) = out_path.parent() {
        log::debug!("Output file parent directory: {}", parent.display());
        if let Err(e) = fs::create_dir_all(parent) {
            log::error!("Failed to create output directory {}: {}", parent.display(), e);
            return;
        }
    } else {
        log::error!("Failed to determine parent directory of output file: {}", output_file);
        return;
    }

    if let Err(e) = process_extracted_pe(
        buffer.clone(),
        &output_file,
        nt_headers.OptionalHeader.SizeOfImage as usize,
        nt_headers.OptionalHeader.FileAlignment as usize,
        valid_nt_header,
        pos,
        offset + pos,
        count,
        headers,
    ) {
        log::error!(
            "Error processing 64-bit NT headers. Output file: {}. Error: {}",
            output_file,
            e
        );
    }
}

fn process_nt_headers32(
    buffer: &mut Vec<u8>,
    file: &mut File,
    nt_header_pos: usize,
    pos: usize,
    offset: usize,
    output_dir: &str, // expected to be a directory path
    count: &mut u32,
    headers: &mut HashSet<String>,
) {
    log::debug!(
        "(32-bit) Buffer length before NT header reading: {}. nt_header_pos: {}, required: {}",
        buffer.len(),
        nt_header_pos,
        nt_header_pos + std::mem::size_of::<IMAGE_NT_HEADERS32>()
    );
    if buffer.len() < nt_header_pos + std::mem::size_of::<IMAGE_NT_HEADERS32>() {
        log::warn!(
            "Buffer length {} is less than expected for IMAGE_NT_HEADERS32 ({}). Attempting to extend...",
            buffer.len(),
            nt_header_pos + std::mem::size_of::<IMAGE_NT_HEADERS32>()
        );
        if !read_and_extend_buffer(buffer, file, nt_header_pos + std::mem::size_of::<IMAGE_NT_HEADERS32>(), pos, offset) {
            log::error!(
                "Failed to extend candidate buffer for NT header reading at absolute offset 0x{:x}",
                offset
            );
            return;
        }
        log::debug!("Buffer length after extension: {}", buffer.len());
    }
    let (nt_headers_opt, valid_nt_header) =
        safe_read::<IMAGE_NT_HEADERS32>(&buffer[nt_header_pos..]);
    if !valid_nt_header {
        log::error!(
            "Failed to read IMAGE_NT_HEADERS32 from candidate at relative offset 0x{:x}",
            nt_header_pos
        );
        return;
    }
    let nt_headers = match nt_headers_opt {
        Some(h) => h,
        None => return,
    };

    let header_end = pos + nt_headers.OptionalHeader.SizeOfHeaders as usize;
    log::debug!(
        "(32-bit) Expected header_end: {}. Current buffer length: {}",
        header_end,
        buffer.len()
    );
    if header_end > buffer.len() {
        log::warn!(
            "Buffer length {} is less than expected header_end {}. Attempting to extend...",
            buffer.len(),
            header_end
        );
        if !read_and_extend_buffer(buffer, file, header_end, pos, offset) {
            log::error!(
                "Failed to extend candidate buffer for header extraction at absolute offset 0x{:x}",
                offset
            );
            return;
        }
        log::debug!("Buffer length after extension: {}", buffer.len());
    }

    let header_str = String::from_utf8_lossy(&buffer[pos..header_end]);
    log::info!(
        "Processing 32-bit NT headers at pos 0x{:x} (absolute offset 0x{:x}). Header length: {}. Buffer length: {}. Header:\n{}",
        pos,
        offset + pos,
        header_end - pos,
        buffer.len(),
        header_str
    );

    // Build full output file path from output_dir.
    let output_file = format!("{}/extracted_static_{}.exe", output_dir, *count);
    let out_path = Path::new(&output_file);
    if let Some(parent) = out_path.parent() {
        log::debug!("Output file parent directory: {}", parent.display());
        if let Err(e) = fs::create_dir_all(parent) {
            log::error!("Failed to create output directory {}: {}", parent.display(), e);
            return;
        }
    } else {
        log::error!("Failed to determine parent directory of output file: {}", output_file);
        return;
    }

    if let Err(e) = process_extracted_pe(
        buffer.clone(),
        &output_file,
        nt_headers.OptionalHeader.SizeOfImage as usize,
        nt_headers.OptionalHeader.FileAlignment as usize,
        valid_nt_header,
        pos,
        offset + pos,
        count,
        headers,
    ) {
        log::error!(
            "Error processing 32-bit NT headers. Output file: {}. Error: {}",
            output_file,
            e
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

    if let Ok(metadata) = std::fs::metadata(output_path) {
        if !metadata.is_dir() {
            println!("Output path is not a directory: {}", output_path);
            return;
        }
    } else {
        std::fs::create_dir_all(output_path).expect("Failed to create output directory");
    }

    let log_config = simplelog::ConfigBuilder::new()
        .set_time_to_local(true)
        .build();
    let log_dir = "./logs";
    std::fs::create_dir_all(log_dir).expect("Failed to create directories");
    let log_file_path = format!("{}/app.log", log_dir);
    let log_file = std::fs::File::create(&log_file_path).expect("Failed to create log file");
    simplelog::WriteLogger::init(simplelog::LevelFilter::Info, log_config, log_file).unwrap();

    log::info!("Starting extraction...");

    // Call extract_executables directly:
    extract_executables(input_path, output_path);

    log::info!("Extraction completed successfully.");
}
