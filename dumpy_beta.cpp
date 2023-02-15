#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <algorithm>

#include <cstdint>
#include <cstdio>

const uint16_t IMAGE_FILE_MACHINE_I386 = 0x014c;     // Intel x86 machine
const uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;    // x64 machine

// Structure to hold information about an executable section
struct section_info_t {
    uint32_t section_offset;
    uint32_t section_size;
};

// Find the offsets of all valid PE headers in the given buffer
void find_pe_offsets(const std::vector<char>& buffer, size_t buffer_size, std::vector<uint32_t>& pe_offsets) {
    const char* buffer_start = buffer.data();
    const char* buffer_end = buffer_start + buffer_size - 4;
    for (const char* p = buffer_start; p < buffer_end; p++) {
        if (memcmp(p, "MZ\0\0", 4) == 0) {
            const char* pe_offset_ptr = p + *(uint32_t*)&p[0x3c];
            if (pe_offset_ptr < buffer_end && memcmp(pe_offset_ptr, "PE\0\0", 4) == 0) {
                uint32_t pe_offset = static_cast<uint32_t>(pe_offset_ptr - buffer_start);
                pe_offsets.push_back(pe_offset);
            }
        }
    }
}

// Extract an executable section from the given buffer and write it to the given file
void extract(const std::vector<char>& buffer, uint32_t pe_offset, const std::string& output_path) {
    const char* dos_header = &buffer[0];
    const char* pe_header = &buffer[pe_offset];

    // Check for valid DOS header
    if (memcmp(dos_header, "MZ\0\0", 4) != 0) {
        std::cerr << "Invalid DOS header\n";
        return;
    }

    // Check for valid Win32 or Win64 PE format
    const char* pe_magic = &pe_header[0x18];
    if (memcmp(pe_magic, "PE\0\0", 4) != 0) {
        std::cerr << "Invalid PE header\n";
        return;
    }

    uint16_t machine_type = *(uint16_t*)&pe_header[0x4];
    uint32_t image_base = *(uint32_t*)&pe_header[0x34];

    // Check for valid machine type
    if (machine_type != IMAGE_FILE_MACHINE_I386 && machine_type != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "Invalid machine type\n";
        return;
    }

    uint32_t header_size = *(uint16_t*)&pe_header[0x14];
    uint16_t num_sections = *(uint16_t*)&pe_header[0x6];
    uint32_t section_table_offset = pe_offset + 4 + 2 + *(uint32_t*)&pe_header[0x78];

    // Find the code section and its properties
    uint32_t code_base = image_base;
    uint32_t code_size = 0;
    uint32_t code_offset = 0;
    for (uint16_t i = 0; i < num_sections; i++) {
        uint32_t section_base = *(uint32_t*)&buffer[section_table_offset + 8*i];
        uint32_t section_size = *(uint32_t*)&buffer[section_table_offset + 
