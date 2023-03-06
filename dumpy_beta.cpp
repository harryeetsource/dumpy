#include <iostream>

#include <fstream>

#include <vector>

#include <string>

#include <experimental/filesystem>

#include <cstring>

#include <windows.h>

namespace fs = std::experimental::filesystem;

void extract_executables(const std::string & input_path,
  const std::string & output_path) {
  std::ifstream input_file(input_path, std::ios::binary);
  if (!input_file) {
    std::cerr << "Failed to open input file: " << input_path << std::endl;
    return;
  }

  std::vector < char > buffer(std::istreambuf_iterator < char > (input_file), {});
  input_file.close();

  const char * data = buffer.data();
  const size_t size = buffer.size();

  size_t pos = 0;
  int count = 0;
  while (pos < size) {
    // Search for DOS header.
    const char * dos_header = & data[pos];
    const char * dos_magic = "MZ";
    const size_t dos_magic_size = 2; // DOS header is always 2 bytes long.
    if (memcmp(dos_header, dos_magic, dos_magic_size) == 0) {
      // Check for valid DOS executable format.
      const char * pe_header = & data[pos + 0x3C];
      const uint32_t pe_offset = * reinterpret_cast <
        const uint32_t * > (pe_header);
      const char * pe_signature = & data[pos + pe_offset];
      const char * pe_magic = "PE\0\0";
      const size_t pe_magic_size = 4; // PE signature is always 4 bytes long.
      if (pe_offset != 0 && pos + pe_offset + pe_magic_size <= size &&
        memcmp(pe_signature, pe_magic, pe_magic_size) == 0) {
        // Check for Win32 or Win64 PE format.
        const uint16_t pe_machine = * reinterpret_cast <
          const uint16_t * > ( & data[pos + pe_offset + 0x4]);
        if (pe_machine == 0x14c) { // Win32
          uint32_t pe_size = * reinterpret_cast <
            const uint32_t * > ( & data[pos + pe_offset + 0x50]);
          if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
            // Extract Win32 PE file data.
            const char * file_data = & data[pos];
            std::string filename = output_path + std::to_string(count) + ".exe";
            std::ofstream output_file(filename, std::ios::binary);
            if (output_file) {
              output_file.write(file_data, pe_size + pe_offset);

              // Verify that the file has a valid ending and no MZ header is appended to the end.
              uint16_t last_two_bytes = * reinterpret_cast <
                const uint16_t * > ( & data[pos + pe_offset + pe_size - 2]);
              if (last_two_bytes != 0 || memcmp( & data[pos + pe_offset + pe_size - dos_magic_size], dos_magic, dos_magic_size) == 0) {
                std::cerr << "Invalid ending or MZ header appended to the end of the file: " << filename << std::endl;
                output_file.close();
                std::remove(filename.c_str());
                pos += pe_offset + 1; // skip to next possible DOS header
                continue;
              }

              output_file.close();
              std::cout << "Extracted file: " << filename << std::endl;
            } else {
              std::cerr << "Failed to open output file: " << filename << std::endl;
            }
            count++;
            pos += pe_size + pe_offset;
          } else {
            std::cerr << "Invalid size or size too large: " << pe_size << std::endl;
            pos += pe_offset + 1; // skip to next possible DOS header
            continue;
          }
        } else if (pe_machine == 0x8664) { // Win64
         uint32_t pe_size = *reinterpret_cast<const uint32_t*>(&data[pos + pe_offset + 0x50]);

          if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
            // Extract Win64 PE file data.
            const char * file_data = & data[pos];
            std::string filename = output_path + std::to_string(count) + ".exe";
            std::ofstream output_file(filename, std::ios::binary);
            if (output_file) {
              output_file.write(file_data, pe_size + pe_offset);
              // Verify that the file has a valid ending and no MZ header is appended to the end.
              uint16_t last_two_bytes = * reinterpret_cast <
                const uint16_t * > ( & data[pos + pe_offset + pe_size - 2]);
              if (last_two_bytes != 0 || memcmp( & data[pos + pe_offset + pe_size - dos_magic_size], dos_magic, dos_magic_size) == 0) {
                std::cerr << "Invalid ending or MZ header appended to the end of the file: " << filename << std::endl;
                output_file.close();
                std::remove(filename.c_str());
                pos += pe_offset + 1; // skip to next possible DOS header
                continue;
              }

              output_file.close();
              std::cout << "Extracted file: " << filename << std::endl;
            } else {
              std::cerr << "Failed to open output file: " << filename << std::endl;
            }
            count++;
            pos += pe_size + pe_offset;
          } else {
            std::cerr << "Invalid size or size too large: " << pe_size << std::endl;
            pos += pe_offset + 1; // skip to next possible DOS header
            continue;
          }
        } else {
          std::cerr << "Invalid machine type: " << pe_machine << std::endl;
          pos += pe_offset + 1; // skip to next possible DOS header
          continue;
        }
      } else {
        std::cerr << "Invalid offset or PE signature not found" << std::endl;
        pos += dos_magic_size; // skip past the DOS header
        continue;
      }
    } else {
      pos += 1; // move to next byte
    }
  }
}
int main(int argc, char ** argv) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " input_file output_dir" << std::endl;
    return 1;
  }

  const std::string input_path = argv[1];
  const std::string output_path = argv[2];
  if (!fs::exists(output_path)) {
    fs::create_directory(output_path);
  }

  extract_executables(input_path, output_path);

  return 0;
}
