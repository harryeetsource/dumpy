use std::env;
use std::fs::File;
use std::path::Path;
use byteorder::{ByteOrder, LittleEndian};
use core::cmp::min;
use std::io::{self, Read, Write};
use std::collections::{HashSet, VecDeque, HashMap};

fn calculate_entropy(data: &[u8]) -> f64 {
    let length = data.len() as f64;
    if length == 0.0 {
        return 0.0;
    }

    let mut occurrence: [u32; 256] = [0; 256];
    for &value in data {
        occurrence[value as usize] += 1;
    }

    let mut entropy = 0.0;
    for &value in occurrence.iter() {
        let p_x = f64::from(value) / length;
        if p_x > 0.0 {
            entropy -= p_x * p_x.log2();
        }
    }

    entropy
}

fn find_mz_headers(data: &[u8]) -> Vec<usize> {
    let mut mz_offsets = Vec::new();
    for i in 0..data.len() - 1 {
        if data[i..i+2] == [0x4D, 0x5A] {
            mz_offsets.push(i);
        }
    }
    mz_offsets
}

fn extract_executables(input_path: &str, output_path: &str) -> io::Result<()> {
    let mut data = Vec::new();
    File::open(input_path)?.read_to_end(&mut data)?;

    let mut count = 0;
    let mut headers = HashSet::new();
    let mut extraction_queue = VecDeque::new();

    let mz_offsets = find_mz_headers(&data);

    for pos in mz_offsets {
        let pe_header_addr = LittleEndian::read_u32(&data[pos + 0x3C..pos + 0x3C + 4]) as usize;
        let pe_header_pos = pos + pe_header_addr;

        if pe_header_addr <= 0 || pe_header_pos >= data.len() || pe_header_pos + 4 > data.len() {
            continue;
        }

        if data[pe_header_pos..pe_header_pos + 4] == [0x50, 0x45, 0x00, 0x00] {
            let pe_machine = LittleEndian::read_u16(&data[pe_header_pos + 4..pe_header_pos + 4 + 2]);
            let number_of_sections = LittleEndian::read_u16(&data[pe_header_pos + 6..pe_header_pos + 6 + 2]);

            if pe_machine == 0x14c || pe_machine == 0x8664 {
                let magic = LittleEndian::read_u16(&data[pe_header_pos + 0x18..pe_header_pos + 0x18 + 2]);
                let size_of_image_offset;
                let size_of_initialized_data_offset;
                let size_of_uninitialized_data_offset;

                if magic == 0x20b {
                    size_of_image_offset = 0x18;
                    size_of_initialized_data_offset = 0x20;
                    size_of_uninitialized_data_offset = 0x24;
                } else {
                    size_of_image_offset = 0x1C;
                    size_of_initialized_data_offset = 0x28;
                    size_of_uninitialized_data_offset = 0x2C;
                }

                let pe_size = LittleEndian::read_u32(&data[pe_header_pos + size_of_image_offset..pe_header_pos + size_of_image_offset + 4]) as usize;
                let file_alignment = LittleEndian::read_u32(&data[pe_header_pos + size_of_initialized_data_offset..pe_header_pos + size_of_initialized_data_offset + 4]) as usize;
                let size_of_image = LittleEndian::read_u32(&data[pe_header_pos + size_of_uninitialized_data_offset..pe_header_pos + size_of_uninitialized_data_offset + 4]) as usize;

                let rounded_up_size_of_image = if file_alignment > 0 {
                    ((size_of_image + file_alignment - 1) / file_alignment) * file_alignment
                } else {
                    size_of_image
                };

                if rounded_up_size_of_image != 0 && pe_header_pos + rounded_up_size_of_image <= data.len() && rounded_up_size_of_image <= 100000000 {
                    let header_str = String::from_utf8_lossy(&data[pe_header_pos..pe_header_pos + min(1024, pe_size)]);

                    if !headers.contains(&header_str) {
                        headers.insert(header_str.to_owned());

                        let extracted_filename = format!("{}/{}.exe", output_path, count);
                        let exe_data = &data[pos..pos + rounded_up_size_of_image];
                        File::create(&extracted_filename)?.write_all(exe_data)?;
                        println!("Extracted file: {}", extracted_filename);
                        count += 1;

                        extraction_queue.push_back((pe_header_pos, pe_size));
                    }
                }
            }
        }
    }

    let mut extracted_files = HashSet::new();

    while let Some((start_pos, pe_size)) = extraction_queue.pop_front() {
        if pe_size <= 0 || start_pos + pe_size > data.len() {
            continue;
        }

        let embedded_data_slice = &data[start_pos..start_pos + pe_size];
        let mut nested_extraction_queue = VecDeque::new();
        nested_extraction_queue.push_back((start_pos, pe_size));

        while let Some((nested_start_pos, nested_pe_size)) = nested_extraction_queue.pop_front() {
            let nested_mz_offsets = find_mz_headers(&embedded_data_slice);

            for nested_pos in nested_mz_offsets {
                let pe_header_addr = if nested_start_pos + nested_pos + 0x3C + 4 <= embedded_data_slice.len() {
                    LittleEndian::read_u32(&embedded_data_slice[nested_start_pos + nested_pos + 0x3C..nested_start_pos + nested_pos + 0x3C + 4]) as usize
                } else {
                    continue;
                };
                
                let pe_header_pos = nested_start_pos + nested_pos + pe_header_addr - 0x3C;

                if pe_header_addr <= 0 || pe_header_pos >= nested_start_pos + nested_pe_size || pe_header_pos + 4 > nested_start_pos + nested_pe_size {
                    continue;
                }

                if pe_header_pos + 4 <= embedded_data_slice.len() && embedded_data_slice[pe_header_pos..pe_header_pos + 4] == [0x50, 0x45, 0x00, 0x00] {
                    let pe_machine = LittleEndian::read_u16(&embedded_data_slice[pe_header_pos + 4..pe_header_pos + 4 + 2]);
                    let number_of_sections = LittleEndian::read_u16(&embedded_data_slice[pe_header_pos + 6..pe_header_pos + 6 + 2]);

                    if pe_machine == 0x14c || pe_machine == 0x8664 {
                        let magic = LittleEndian::read_u16(&embedded_data_slice[pe_header_pos + 0x18..pe_header_pos + 0x18 + 2]);
                        let size_of_image_offset;
                        let size_of_initialized_data_offset;
                        let size_of_uninitialized_data_offset;

                        if magic == 0x20b {
                            size_of_image_offset = 0x18;
                            size_of_initialized_data_offset = 0x20;
                            size_of_uninitialized_data_offset = 0x24;
                        } else {
                            size_of_image_offset = 0x1C;
                            size_of_initialized_data_offset = 0x28;
                            size_of_uninitialized_data_offset = 0x2C;
                        }

                        let pe_size = LittleEndian::read_u32(&embedded_data_slice[pe_header_pos + size_of_image_offset..pe_header_pos + size_of_image_offset + 4]) as usize;
                        let file_alignment = LittleEndian::read_u32(&embedded_data_slice[pe_header_pos + size_of_initialized_data_offset..pe_header_pos + size_of_initialized_data_offset + 4]) as usize;
                        let size_of_image = LittleEndian::read_u32(&embedded_data_slice[pe_header_pos + size_of_uninitialized_data_offset..pe_header_pos + size_of_uninitialized_data_offset + 4]) as usize;

                        let rounded_up_size_of_image = if file_alignment > 0 {
                            ((size_of_image + file_alignment - 1) / file_alignment) * file_alignment
                        } else {
                            size_of_image
                        };

                        if rounded_up_size_of_image != 0 && pe_header_pos + rounded_up_size_of_image <= nested_start_pos + nested_pe_size && rounded_up_size_of_image <= 100000000 {
                            let header_str = String::from_utf8_lossy(&embedded_data_slice[pe_header_pos..pe_header_pos + min(1024, pe_size)]);

                            if !headers.contains(&header_str) {
                                headers.insert(header_str.to_owned());

                                let extracted_filename = format!("{}/{}.exe", output_path, count);
                                let exe_data = &embedded_data_slice[nested_pos..nested_pos + rounded_up_size_of_image];
                                File::create(&extracted_filename)?.write_all(exe_data)?;
                                println!("Extracted file: {}", extracted_filename);
                                count += 1;

                                nested_extraction_queue.push_back((start_pos + nested_pos, pe_size));
                            }
                        }
                    }
                }
            }
        }

        // Mark the current extracted file as complete
        extracted_files.insert((start_pos, pe_size));
    }

    if count == 0 {
        println!("No executables found in the input file.");
    } else {
        println!("Extracted {} executables to the output path: {}", count, output_path);
    }

    Ok(())
}




fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input_file> <output_dir>", args[0]);
        return Ok(());
    }

    let input_path = &args[1];
    let output_path = &args[2];

    if !Path::new(input_path).exists() {
        println!("Input file does not exist: {}", input_path);
        return Ok(());
    }

    if !Path::new(output_path).exists() {
        std::fs::create_dir(output_path)?;
    } else if !Path::new(output_path).is_dir() {
        println!("Output path is not a directory: {}", output_path);
        return Ok(());
    }

    extract_executables(input_path, output_path)
}
