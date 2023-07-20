
use colored::*;
use core::mem::size_of;
use crossterm::{execute, style::{Print, SetForegroundColor, ResetColor, Color}};
use crypto_hash::{Algorithm, Hasher};
use hex;
use log::LevelFilter;
use simplelog::*;
use std::borrow::Cow;
use std::collections::HashSet;
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
fn trim_trailing_null_bytes(data: &[u8]) -> &[u8] {
    let trimmed_length = data.iter().rposition(|&x| x != 0).map_or(0, |pos| pos + 1);
    let original_size = data.len();
    let trimmed_size = original_size - trimmed_length;

    if trimmed_size > 0 {
        let trimmed_mb = trimmed_size as f64 / 1_000_000.0;
        log::warn!("Trimmed {:.2} MB of trailing null bytes", trimmed_mb);
        let message = format!("Trimmed {:.2} MB of trailing null bytes", trimmed_mb);
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(message),
            ResetColor,
            Print("\n")
        );
    }

    &data[..trimmed_length]
}

fn extract_executables(input_path: &str, output_path: &str) {
    let mut file = File::open(input_path).expect("Failed to open file");
    let mut offset: usize = 0;
    let mut overlap = vec![0; 0];
    let mut buffer = vec![0; CHUNK_SIZE + overlap.len()];
    let mut bytes_read = file
    .read(&mut buffer[overlap.len()..])
    .expect("Failed to read data");
    while bytes_read > 0 || !overlap.is_empty() {
        


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

            let (dos_header, valid) =
                safe_read::<IMAGE_DOS_HEADER>(&buffer[pos..pos + size_of::<IMAGE_DOS_HEADER>()]);
            if !valid {
                log::warn!("Warning: Failed to read IMAGE_DOS_HEADER at position {} (absolute position {}). It may be corrupted, processing.", pos, offset + pos);
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
                    let metadata = file.metadata().expect("Failed to retrieve file metadata");
                    let file_size = metadata.len() as usize;
                    if needed_size > file_size {
                        log::warn!("Warning: Attempt to read beyond file size at absolute offset 0x{:x}. The file metadata may be corrupted or incorrectly formatted. Analyzing...", offset + nt_header_pos);
                        eprintln!("{}", format!("Warning: Attempt to read beyond file size at absolute offset 0x{:x}. The file metadata may be corrupted or incorrectly formatted. Analyzing...", offset + nt_header_pos).red());
                        continue;
                    }
                    if needed_size > 650 * 1024 * 1024 {
                        // 650 MB
                        let needed_size_mb = needed_size as f64 / 1024.0 / 1024.0;
                        let mz_positions = find_mz_headers(&buffer[..effective_len]);
                        for pos in mz_positions {
                            let abs_offset = offset + pos;
                            let message = if needed_size_mb >= 1024.0 {
                                let needed_size_gb = needed_size_mb / 1024.0;
                                format!(
                                    "[x] NT Header from executable file reported size of {:.2} GB at offset 0x{:x} in input file. Processing possibly corrupted ELF file or 16-bit binary...",
                                    needed_size_gb,
                                    abs_offset
                                )
                            } else {
                                format!(
                                    "[x]  NT Header from executable file reported size of {:.2} MB at offset 0x{:x} in input file. Processing corrupted file...",
                                    needed_size_mb,
                                    abs_offset
                                )
                            };
                            log::warn!("{}", message);
                            let _ = crossterm::execute!(
                                std::io::stdout(),
                                SetForegroundColor(Color::Red),
                                Print(message),
                                ResetColor,
                                Print("\n")
                            );
                        
                            // Calculate relative position of the MZ header in the buffer
                            let mz_relative_pos = abs_offset - offset;
                        
                            // Get size of image from PE Optional Header
                            if mz_relative_pos + 0x3F >= buffer.len() {
                                log::error!("PE header offset exceeds buffer size");
                                continue;
                            }
                        
                            let pe_header_offset = u32::from_le_bytes([buffer[mz_relative_pos+0x3C], buffer[mz_relative_pos+0x3D], buffer[mz_relative_pos+0x3E], buffer[mz_relative_pos+0x3F]]) as usize;
                            let optional_header_offset = pe_header_offset + 4 + 20;
                        
                            // Check if accessing image size exceeds buffer size
                            if mz_relative_pos + optional_header_offset + 59 >= buffer.len() {
                                log::error!("PE image size offset exceeds buffer size");
                                continue;
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
                                continue;
                            }
                        
                            // This will start from the MZ header and span the entire image size
                            let corrupted_data = &buffer[mz_relative_pos..mz_relative_pos+image_size];
                        
                            // Verify MZ header
                            let mz_header = [0x4D, 0x5A]; // MZ header in bytes
                            if corrupted_data.get(0..2) != Some(&mz_header[..]) {
                                log::debug!("Data at offset: {:?}", corrupted_data.get(0..2));
                                log::warn!("MZ header not found at offset 0x{:x}. Skipping extraction of the corrupted file.", abs_offset);
                                continue;
                            }
                        
                            // Get a vector of bytes from the buffer to write
                            let trimmed_data = trim_trailing_null_bytes(corrupted_data);
                        
                            // Convert this byte slice to Vec<u8>
                            let mut trimmed_data_vec = trimmed_data.to_vec();
                        
                            // Construct header string
                            let header_str = format!("MZ at offset 0x{:x}", abs_offset);
                        
                            // header_bytes: size of the header
                            let header_bytes = trimmed_data_vec.len(); // since it is trimmed data, assuming it is all header
                        
                            // file_alignment: This might be fetched from IMAGE_NT_HEADERS32 or IMAGE_NT_HEADERS64 
                            let file_alignment = 4096; // adjust this as per your requirements
                        
                            // valid: validity of the file
                            let valid = true; // assuming the file is valid, adjust this as per your requirements
                        
                            // pos: position in buffer
                            let pos = 0; // As trimmed_data is independent of the buffer, position is 0
                        
                            write_file(
                                &mut trimmed_data_vec,
                                Cow::Borrowed(&header_str),
                                header_bytes,
                                file_alignment,
                                valid,
                                pos,
                                abs_offset,
                                output_path,
                                &mut count,
                                &mut headers,
                            );
                            
                        }
                    }
                    
else {
    log::error!("PE image size exceeds the limit or original buffer length");
                    
                    
                    
                        continue;
                    }

                    let mut new_buffer = vec![0; needed_size];
                    new_buffer[..current_size].copy_from_slice(&buffer[..current_size]);
                    let read_bytes = file
                        .read(&mut new_buffer[current_size..])
                        .expect("Failed to read data");
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

           // At the end of your loop...
    if bytes_read > 0 {
        if bytes_read >= overlap.len() {
            file.seek(SeekFrom::Current(-(overlap.len() as i64)))
                .unwrap();
            offset += bytes_read - overlap.len();
        } else {
            // Handle the special case here. For example:
            file.seek(SeekFrom::Current(-(bytes_read as i64)))
                .unwrap();
            offset += bytes_read;
        }
    } else {
        offset += bytes_read;
    }
    
    // Add this at the end of your loop to read in the next chunk of data:
    bytes_read = file
        .read(&mut buffer[overlap.len()..])
        .unwrap_or(0);
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