extern crate winapi;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::fs;
use std::io::SeekFrom;
use std::io::Seek;
use core::mem::size_of;
extern crate crypto_hash;
use crypto_hash::{Algorithm, Hasher};
use hex;
use std::borrow::Cow;
const CHUNK_SIZE: usize = 1024 * 1024 * 1024; // 1GB

fn find_mz_headers(buffer: &[u8]) -> Vec<usize> {
    let dos_magic = b"MZ";
    let mut mz_positions = Vec::new();

    for pos in 0..buffer.len()-dos_magic.len() {
        if buffer[pos..pos+dos_magic.len()] == *dos_magic {
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
        // Read data in chunks
        let mut buffer = vec![0; CHUNK_SIZE + 0x200]; // Plus maximum possible header size

        // Keep track of how much data we actually read
        let bytes_read = file
            .read(&mut buffer[overlap.len()..])
            .expect("Failed to read data");
        if bytes_read == 0 {
            break;
        }

        // Prepend any overlapping data from the previous chunk
        buffer.splice(..overlap.len(), overlap.iter().cloned());
        buffer.truncate(bytes_read + overlap.len());

        let mz_offsets = find_mz_headers(&buffer);

        let mut count = 0;
        let mut headers = std::collections::HashSet::new();

        for pos in mz_offsets {
            if pos + size_of::<IMAGE_DOS_HEADER>() > buffer.len() {
                continue;
            }

            // Read IMAGE_DOS_HEADER from buffer[pos..]
            let dos_header: IMAGE_DOS_HEADER =
                unsafe { std::ptr::read(buffer[pos..].as_ptr() as *const _) };

            if dos_header.e_magic != 0x5a4d {
                // "MZ"
                continue;
            }

            let nt_header_pos = pos + dos_header.e_lfanew as usize;
            if nt_header_pos + size_of::<IMAGE_NT_HEADERS32>() > buffer.len()
                || nt_header_pos + size_of::<IMAGE_NT_HEADERS64>() > buffer.len()
            {
                continue;
            }

            // Determine architecture
            if buffer[nt_header_pos..nt_header_pos + 4] == [0x50, 0x45, 0x00, 0x00] {
                // "PE\0\0"
                let magic: u16 =
                    unsafe { std::ptr::read(buffer[nt_header_pos + 0x18..].as_ptr() as *const _) };
                if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
                    let nt_headers: IMAGE_NT_HEADERS32 =
                        unsafe { std::ptr::read(buffer[nt_header_pos..].as_ptr() as *const _) };

                    let header_end = pos + nt_headers.OptionalHeader.SizeOfHeaders as usize;
                    if header_end > buffer.len() {
                        // Header size exceeds buffer length, create a new buffer for this executable
                        let mut new_buffer = buffer[pos..header_end].to_vec();
                        new_buffer.resize(
                            nt_headers.OptionalHeader.SizeOfImage as usize,
                            0,
                        );

                        let remaining_data = &buffer[header_end..];
                        new_buffer.extend_from_slice(remaining_data);

                        buffer = new_buffer;
                    }

                    let header_str = std::string::String::from_utf8_lossy(&buffer[pos..header_end]);

                    let header_str_owned = header_str.to_string();
                    write_file(
                        &mut buffer,
                        Cow::Borrowed(&header_str_owned),
                        nt_headers.OptionalHeader.SizeOfImage as usize,
                        nt_headers.OptionalHeader.FileAlignment as usize,
                        pos,
                        offset + pos,
                        output_path,
                        &mut count,
                        &mut headers,
                    );
                } else if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                    let nt_headers: IMAGE_NT_HEADERS64 =
                        unsafe { std::ptr::read(buffer[nt_header_pos..].as_ptr() as *const _) };

                    let header_end = pos + nt_headers.OptionalHeader.SizeOfHeaders as usize;
                    if header_end > buffer.len() {
                        // Header size exceeds buffer length, create a new buffer for this executable
                        let mut new_buffer = buffer[pos..pos + header_end - pos].to_vec();

                        new_buffer.resize(
                            nt_headers.OptionalHeader.SizeOfImage as usize,
                            0,
                        );

                        let remaining_data = &buffer[header_end..];
                        new_buffer.extend_from_slice(remaining_data);

                        buffer = new_buffer;
                    }

                    let header_str = std::string::String::from_utf8_lossy(&buffer[pos..header_end]);

                    let header_str_owned = header_str.to_string();
                    write_file(
                        &mut buffer,
                        Cow::Borrowed(&header_str_owned),
                        nt_headers.OptionalHeader.SizeOfImage as usize,
                        nt_headers.OptionalHeader.FileAlignment as usize,
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

        // Remember part of the chunk to handle executables spread over two chunks
        let overlap_size = buffer.len().saturating_sub(CHUNK_SIZE);
        if overlap_size > 0 {
            overlap = buffer[CHUNK_SIZE..].to_vec();

            // Seek backwards the size of the overlap so the next chunk will start at the right position
            file.seek(SeekFrom::Current(-(overlap.len() as i64))).unwrap();
        } else {
            overlap.clear();
        }
    }
}






fn write_file(
    data: &mut Vec<u8>,
    header_str: Cow<str>,
    header_bytes: usize,
    file_alignment: usize,
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
            println!("File at offset {} is too large or corrupted. Skipping...", offset);
            return;
        }

        let mut file = File::create(&filename).expect("Failed to create file");
        file.write_all(&data[pos..end]).expect("Failed to write data");

        println!("Extracted file: {}", filename);
    } else {
        println!("Duplicate executable with header hash {} skipped", header_hash);
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

    extract_executables(input_path, output_path);
}
