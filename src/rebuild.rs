use crate::*;
use std::error::Error;
use std::mem::size_of;
use std::path::Path;
use std::cmp;

/// Rebuilds (unmaps) a PE image from its in‑memory (virtual) layout into its static (raw) layout.
/// It returns a new Vec<u8> containing the PE as it should appear on disk.
/// Works for both 32‑bit and 64‑bit images.
pub fn rebuild_static_pe(buffer: &[u8], required_header_bytes: usize) -> Option<Vec<u8>> {
    // Check DOS header.
    if buffer.len() < size_of::<IMAGE_DOS_HEADER>() {
        log::error!("Buffer length {} less than size of IMAGE_DOS_HEADER", buffer.len());
        return None;
    }
    let dos_header = unsafe { &*(buffer.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != 0x5A4D {
        log::error!("Invalid DOS header magic: 0x{:x}", dos_header.e_magic);
        return None;
    }
    let nt_offset = dos_header.e_lfanew as usize;
    if buffer.len() < nt_offset + 4 {
        log::error!("Buffer length {} less than nt_offset + 4 ({})", buffer.len(), nt_offset+4);
        return None;
    }
    if &buffer[nt_offset..nt_offset + 4] != b"PE\0\0" {
        log::error!("PE signature not found at nt_offset {}", nt_offset);
        return None;
    }

    // Determine if 32-bit or 64-bit.
    let magic_offset = nt_offset + 4 + size_of::<IMAGE_FILE_HEADER>();
    if buffer.len() < magic_offset + 2 {
        log::error!("Buffer too small to read Optional Header magic");
        return None;
    }
    let magic = u16::from_le_bytes([buffer[magic_offset], buffer[magic_offset + 1]]);
    
    let (headers_size, num_sections, section_table_offset): (usize, usize, usize);
    let mut sections = Vec::new();
    if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC.0 {
        if buffer.len() < nt_offset + size_of::<IMAGE_NT_HEADERS32>() {
            log::error!("Buffer too small for IMAGE_NT_HEADERS32");
            return None;
        }
        let nt_headers = unsafe { &*(buffer[nt_offset..].as_ptr() as *const IMAGE_NT_HEADERS32) };
        headers_size = nt_headers.OptionalHeader.SizeOfHeaders as usize;
        num_sections = nt_headers.FileHeader.NumberOfSections as usize;
        section_table_offset = nt_offset + size_of::<IMAGE_NT_HEADERS32>();
    } else if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC.0 {
        if buffer.len() < nt_offset + size_of::<IMAGE_NT_HEADERS64>() {
            log::error!("Buffer too small for IMAGE_NT_HEADERS64");
            return None;
        }
        let nt_headers = unsafe { &*(buffer[nt_offset..].as_ptr() as *const IMAGE_NT_HEADERS64) };
        headers_size = nt_headers.OptionalHeader.SizeOfHeaders as usize;
        num_sections = nt_headers.FileHeader.NumberOfSections as usize;
        section_table_offset = nt_offset + size_of::<IMAGE_NT_HEADERS64>();
    } else {
        log::error!("Unknown Optional Header magic: 0x{:x}", magic);
        return None;
    }

    // Compute file size from header and section raw offsets.
    let mut file_size = headers_size;
    for i in 0..num_sections {
        let sec_offset = section_table_offset + i * size_of::<IMAGE_SECTION_HEADER>();
        if buffer.len() < sec_offset + size_of::<IMAGE_SECTION_HEADER>() {
            log::error!("Buffer too small for section header {} at offset {}", i, sec_offset);
            return None;
        }
        let section = unsafe { &*(buffer[sec_offset..].as_ptr() as *const IMAGE_SECTION_HEADER) };
        sections.push(*section);
        let sec_end = section.PointerToRawData as usize + section.SizeOfRawData as usize;
        file_size = cmp::max(file_size, sec_end);
    }
    let new_file_size = cmp::max(file_size, required_header_bytes);
    log::debug!("Rebuild static PE: headers_size: {}, file_size from sections: {}, required_header_bytes: {}, new_file_size: {}",
        headers_size, file_size, required_header_bytes, new_file_size);

    let mut new_buffer = vec![0u8; new_file_size];

    // Copy header region.
    if buffer.len() < headers_size {
        log::error!("Buffer too small for headers: {} vs {}", buffer.len(), headers_size);
        return None;
    }
    new_buffer[..headers_size].copy_from_slice(&buffer[..headers_size]);

    // Copy each section's raw data.
    for section in &sections {
        unsafe {
            let raw_offset = section.PointerToRawData as usize;
            let raw_size = section.SizeOfRawData as usize;
            let virt_addr = section.VirtualAddress as usize;
            // Use the larger of VirtualSize and SizeOfRawData.
            let virt_size = cmp::max(section.Misc.VirtualSize as usize, raw_size);
            let copy_size = cmp::min(raw_size, virt_size);
            if virt_addr + copy_size <= buffer.len() && raw_offset + copy_size <= new_buffer.len() {
                new_buffer[raw_offset..raw_offset + copy_size]
                    .copy_from_slice(&buffer[virt_addr..virt_addr + copy_size]);
            } else {
                log::warn!("Section copy skipped: virt_addr {} + copy_size {} exceeds buffer length {} or raw_offset {} + copy_size {} exceeds new_buffer length {}",
                    virt_addr, copy_size, buffer.len(), raw_offset, copy_size, new_buffer.len());
            }
        }
    }

    // Rebuild the Import Directory.
    let import_dir = if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC.0 {
        let nt_headers = unsafe { &*(buffer[nt_offset..].as_ptr() as *const IMAGE_NT_HEADERS32) };
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
    } else {
        let nt_headers = unsafe { &*(buffer[nt_offset..].as_ptr() as *const IMAGE_NT_HEADERS64) };
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
    };

    if import_dir.VirtualAddress != 0 && import_dir.Size != 0 {
        if let Some(import_raw_offset) = rva_to_raw(import_dir.VirtualAddress, &sections) {
            let mut descriptor_offset = import_raw_offset as usize;
            while descriptor_offset + size_of::<IMAGE_IMPORT_DESCRIPTOR>() <= new_buffer.len() {
                let descriptor: &mut IMAGE_IMPORT_DESCRIPTOR = unsafe {
                    &mut *(new_buffer[descriptor_offset..].as_mut_ptr() as *mut IMAGE_IMPORT_DESCRIPTOR)
                };
                if descriptor.Name == 0 &&
                   unsafe {descriptor.Anonymous.OriginalFirstThunk} == 0 &&
                   descriptor.FirstThunk == 0 {
                    break;
                }
                if descriptor.Name != 0 {
                    if let Some(name_raw) = rva_to_raw(descriptor.Name, &sections) {
                        descriptor.Name = name_raw;
                    } else {
                        log::error!("Failed to remap DLL name RVA at descriptor offset 0x{:x}", descriptor_offset);
                        break;
                    }
                }
                if unsafe{descriptor.Anonymous.OriginalFirstThunk} != 0 {
                    if let Some(ofthunk_raw) = rva_to_raw(unsafe{descriptor.Anonymous.OriginalFirstThunk}, &sections) {
                        descriptor.Anonymous.OriginalFirstThunk = ofthunk_raw;
                    } else {
                        log::error!("Failed to remap OriginalFirstThunk RVA at descriptor offset 0x{:x}", descriptor_offset);
                    }
                }
                if descriptor.FirstThunk != 0 {
                    if let Some(thunk_raw) = rva_to_raw(descriptor.FirstThunk, &sections) {
                        descriptor.FirstThunk = thunk_raw;
                    } else {
                        log::error!("Failed to remap FirstThunk RVA at descriptor offset 0x{:x}", descriptor_offset);
                    }
                }
                descriptor_offset += size_of::<IMAGE_IMPORT_DESCRIPTOR>();
            }
        } else {
            log::error!("Failed to map import directory RVA to raw offset");
        }
    }

    // Rebuild the Export Directory, if present.
    let export_dir = if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC.0 {
        let nt_headers = unsafe { &*(buffer[nt_offset..].as_ptr() as *const IMAGE_NT_HEADERS32) };
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
    } else {
        let nt_headers = unsafe { &*(buffer[nt_offset..].as_ptr() as *const IMAGE_NT_HEADERS64) };
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
    };

    if export_dir.VirtualAddress != 0 && export_dir.Size != 0 {
        if let Some(export_raw_offset) = rva_to_raw(export_dir.VirtualAddress, &sections) {
            if export_raw_offset as usize + size_of::<IMAGE_EXPORT_DIRECTORY>() <= new_buffer.len() {
                let export_dir_struct = unsafe {
                    &mut *(new_buffer[export_raw_offset as usize..].as_mut_ptr() as *mut IMAGE_EXPORT_DIRECTORY)
                };
                if export_dir_struct.Name != 0 {
                    if let Some(name_raw) = rva_to_raw(export_dir_struct.Name, &sections) {
                        export_dir_struct.Name = name_raw;
                    } else {
                        log::error!("Failed to remap export directory Name RVA");
                    }
                }
                if export_dir_struct.AddressOfFunctions != 0 {
                    if let Some(func_raw) = rva_to_raw(export_dir_struct.AddressOfFunctions, &sections) {
                        export_dir_struct.AddressOfFunctions = func_raw;
                    } else {
                        log::error!("Failed to remap AddressOfFunctions RVA");
                    }
                }
                if export_dir_struct.AddressOfNames != 0 {
                    if let Some(names_raw) = rva_to_raw(export_dir_struct.AddressOfNames, &sections) {
                        export_dir_struct.AddressOfNames = names_raw;
                    } else {
                        log::error!("Failed to remap AddressOfNames RVA");
                    }
                }
                if export_dir_struct.AddressOfNameOrdinals != 0 {
                    if let Some(ordinals_raw) = rva_to_raw(export_dir_struct.AddressOfNameOrdinals, &sections) {
                        export_dir_struct.AddressOfNameOrdinals = ordinals_raw;
                    } else {
                        log::error!("Failed to remap AddressOfNameOrdinals RVA");
                    }
                }
            } else {
                log::error!("Export directory structure exceeds new buffer length");
            }
        } else {
            log::error!("Failed to map export directory RVA to raw offset");
        }
    }

    Some(new_buffer)
}

/// Converts an RVA to a raw offset using section headers.
fn rva_to_raw(rva: u32, sections: &[IMAGE_SECTION_HEADER]) -> Option<u32> {
    unsafe {
        for section in sections {
            let start = section.VirtualAddress;
            // Use the larger of VirtualSize and SizeOfRawData.
            let size = cmp::max(section.Misc.VirtualSize as u32, section.SizeOfRawData);
            if rva >= start && rva < start + size {
                return Some(rva - start + section.PointerToRawData);
            }
        }
    }
    None
}

/// Processes the extracted PE by writing the rebuilt static image to disk.
/// output_path is now the full file path, e.g. "C:/Users/kernel/Desktop/e/extracted_static_1.exe"
pub fn process_extracted_pe(
    image_buffer: Vec<u8>,
    output_path: &str,
    header_bytes: usize,
    file_alignment: usize,
    valid: bool,
    pos: usize,
    offset: usize,
    count: &mut u32,
    headers: &mut HashSet<String>,
) -> Result<(), String> {
    if let Some(mut static_image) = rebuild_static_pe(&image_buffer, header_bytes) {
        log::debug!("Static image rebuilt; length: {}", static_image.len());
        let header_slice = static_image
            .get(0..header_bytes)
            .ok_or(format!(
                "Buffer too small for header extraction: requested {}, but static image length is {}",
                header_bytes,
                static_image.len()
            ))?
            .to_vec();
        let header_str = String::from_utf8_lossy(&header_slice).to_string();

        // Ensure the parent directory exists.
        let out_path = Path::new(output_path);
        if let Some(parent) = out_path.parent() {
            log::debug!("Output file parent directory: {}", parent.display());
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create output directory {}: {}", parent.display(), e))?;
        } else {
            return Err(format!("Failed to determine parent directory of output file: {}", output_path));
        }
        log::debug!("Writing static PE to output file: {}", output_path);
        write_file(
            &mut static_image,
            Cow::Borrowed(&header_str),
            header_bytes,
            file_alignment,
            valid,
            pos,
            offset,
            output_path,
            count,
            headers,
        )
        .map_err(|e| format!("Failed to write static PE file ({}): {}", output_path, e))?;

        println!("Successfully rebuilt static PE: {}", output_path);
        Ok(())
    } else {
        Err("Failed to rebuild static PE from the extracted image.".into())
    }
}
