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
      const uint16_t e_lfanew = * reinterpret_cast <
        const uint16_t * > ( & data[pos + 0x3C]);
      if (e_lfanew >= dos_magic_size && e_lfanew < size) {
        const char * pe_header = & data[pos + e_lfanew];
        const char * pe_magic = "PE\0\0";
        const size_t pe_magic_size = 4; // PE signature is always 4 bytes long.
        if (memcmp(pe_header, pe_magic, pe_magic_size) == 0) {
          // Check for Win32 or Win64 PE format.
          const uint16_t pe_machine = * reinterpret_cast <
            const uint16_t * > ( & pe_header[4]);
          if (pe_machine == IMAGE_FILE_MACHINE_I386 || pe_machine == IMAGE_FILE_MACHINE_AMD64) {
            const uint32_t pe_sections_count = * reinterpret_cast <
              const uint16_t * > ( & pe_header[6]);
            const uint16_t pe_size_of_optional_header = * reinterpret_cast <
              const uint16_t * > ( & pe_header[20]);
            const uint32_t pe_image_size = * reinterpret_cast <
              const uint32_t * > ( & pe_header[80]);
            const uint32_t pe_header_size = e_lfanew + pe_size_of_optional_header + 24 + (40 * pe_sections_count);
            if (pos + pe_header_size + pe_image_size <= size) {
              // Extract PE file data.
              const char * file_data = & data[pos];
              std::string filename = output_path + std::to_string(count) + ".exe";
              std::ofstream output_file(filename, std::ios::binary);
              if (output_file) {
                output_file.write(file_data, pe_header_size + pe_image_size);

                // Verify that the file has a valid ending and no MZ header is appended to the end.
                uint16_t last_two_bytes = * reinterpret_cast <
                  const uint16_t * > ( & data[pos + pe_header_size + pe_image_size - 2]);
                if (last_two_bytes != 0 || memcmp( & data[pos + pe_header_size + pe_image_size - dos_magic_size], dos_magic, dos_magic_size) == 0) {
                  std::cerr << "Invalid ending or MZ header appended to the end of the file: " << filename << std::endl;
                  output_file.close();
                  std::remove(filename.c_str());
                  pos += pe_header_size + 1; // skip to next possible DOS header
                  continue;
                }
                output_file.close();
                std::cout << "Extracted file: " << filename << std::endl;
              } else {
                std::cerr << "Failed to open output file: " << filename << std::endl;
              }
              count++;
              pos += pe_header_size + pe_image_size;
            } else {
              std::cerr << "Invalid size or size too large: " << pe_image_size << std::endl;
              pos += pe_header_size + 1; // skip to next possible DOS header
              continue;
            }
          } else {
            std::cerr << "Invalid machine type: " << pe_machine << std::endl;
            pos += e_lfanew + 1; // skip to next possible DOS header
            continue;
          }
        }
      }
    }
    pos++;
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
