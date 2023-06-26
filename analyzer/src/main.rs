use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Write};
use std::path::Path;
use std::str;
use byteorder::{ByteOrder, LittleEndian};
use std::borrow::Borrow;
use std::ffi::CStr;
use std::borrow::Cow;
struct MZHeader {
    Signature: u16,
    LastPageSize: u16,
    Pages: u16,
    Relocations: u16,
    HeaderSize: u16,
    MinAlloc: u16,
    MaxAlloc: u16,
    InitialSS: u16,
    InitialSP: u16,
    Checksum: u16,
    InitialIP: u16,
    InitialCS: u16,
    RelocAddr: u16,
    OverlayNum: u16,
    Reserved: [u16; 8],
    OEMID: u16,
    OEMInfo: u16,
    Reserved2: [u16; 20],
    PEHeaderAddr: u32,
}

struct PEHeader {
    Signature: u32,
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

struct PESectionHeader {
    Name: [u8; 8],
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
}

fn find_pe_offset(data: &[u8], pos: usize) -> Option<usize> {
    let min_pe_offset = 0x40;
    let max_pe_offset = 0x200;

    for offset in min_pe_offset..=max_pe_offset {
        if pos + offset + 4 > data.len() {
            break;
        }
        if data[pos + offset..pos + offset + 4] == [0x50, 0x45, 0x00, 0x00] {
            return Some(offset);
        }
    }

    None
}
fn extract_executables(input_path: &str, output_path: &str) {
    let data = match std::fs::read(input_path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Failed to read input file: {}", err);
            return;
        }
    };

    let mz_offsets = find_mz_headers(&data);
    let mut count = 0;
    let mut headers = HashMap::<Cow<str>, bool>::new();

    for pos in mz_offsets {
        let pe_header_addr = match read_u32_from_slice(&data[pos + 0x3C..pos + 0x3C + 4]) {
            Some(addr) => addr as usize,
            None => continue,
        };
        let pe_header_pos = pos + pe_header_addr;

        if pe_header_addr <= 0 || pe_header_pos >= data.len() || pe_header_pos + 4 > data.len() {
            continue;
        }

        if &data[pe_header_pos..pe_header_pos + 4] != b"PE\0\0" {
            continue;
        }

        let pe_machine = match read_u16_from_slice(&data[pe_header_pos + 4..pe_header_pos + 4 + 2]) {
            Some(machine) => machine,
            None => continue,
        };

        if pe_machine != 0x14c && pe_machine != 0x8664 {
            continue;
        }

        let pe_size = match read_u32_from_slice(&data[pe_header_pos + 0x50..pe_header_pos + 0x50 + 4]) {
            Some(size) => size as usize,
            None => continue,
        };
        let file_alignment = match read_u32_from_slice(&data[pe_header_pos + 0x3C..pe_header_pos + 0x3C + 4]) {
            Some(alignment) => alignment as usize,
            None => continue,
        };

        if pe_size == 0 || pe_header_pos + pe_size > data.len() || pe_size > 100_000_000 {
            continue;
        }

        let header_bytes = &data[pe_header_pos..pe_header_pos + pe_size];
        let header_str = String::from_utf8_lossy(header_bytes);

        if headers.contains_key::<Cow<str>>(header_str.borrow()) {
            continue;
        }

        headers.insert(header_str.into_owned().into(), true);

        let padding = if file_alignment != 0 && pe_size % file_alignment != 0 {
            file_alignment - (pe_size % file_alignment)
        } else {
            0
        };

        let extracted_size = pe_size + padding;
        if pe_header_pos + extracted_size <= data.len() {
            let filename = format!("{}{}.exe", output_path, count);
            count += 1;

            match std::fs::write(&filename, &data[pos..pos + extracted_size]) {
                Ok(_) => println!("Extracted file: {}", filename),
                Err(err) => eprintln!("Failed to write output file: {}", err),
            }
        }
    }

    if count == 0 {
        println!("No executables found in input file.");
    } else {
        println!("Extracted {} executables to output path: {}", count, output_path);
    }
}

fn read_u16_from_slice(slice: &[u8]) -> Option<u16> {
    if slice.len() >= 2 {
        Some(u16::from_le_bytes([slice[0], slice[1]]))
    } else {
        None
    }
}

fn read_u32_from_slice(slice: &[u8]) -> Option<u32> {
    if slice.len() >= 4 {
        Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    } else {
        None
    }
}

fn find_mz_headers(buffer: &[u8]) -> Vec<usize> {
    let dos_magic = [b'M', b'Z'];
    let mut mz_positions = Vec::new();

    for pos in 0..buffer.len() - dos_magic.len() {
        if buffer[pos..pos + dos_magic.len()] == dos_magic {
            mz_positions.push(pos);
        }
    }

    mz_positions
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input_file> <output_dir>", args[0]);
        return;
    }

    let input_path = &args[1];
    let output_path = &args[2];

    if !std::path::Path::new(input_path).exists() {
        eprintln!("Input file does not exist: {}", input_path);
        return;
    }

    if !std::path::Path::new(output_path).exists() {
        match std::fs::create_dir(output_path) {
            Ok(_) => (),
            Err(err) => {
                eprintln!("Failed to create output directory: {}", err);
                return;
            }
        }
    } else if !std::path::Path::new(output_path).is_dir() {
        eprintln!("Output path is not a directory: {}", output_path);
        return;
    }

    extract_executables(input_path, output_path);
}
