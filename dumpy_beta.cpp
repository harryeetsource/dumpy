#include <iostream>

#include <fstream>

#include <vector>

#include <string>

#include <experimental/filesystem>

#include <cstring>

#include <windows.h>

#include <thread>

#include <mutex>

#include <condition_variable>

namespace fs = std::experimental::filesystem;

void extract_executables(const std::string & input_path,
    const std::string & output_path, size_t start_pos, size_t end_pos) {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
      std::cerr << "Failed to open input file: " << input_path << std::endl;
      return;
    }
    int count = 0;

    // Set input file position to start of chunk.
    input_file.seekg(start_pos);

    std::vector < char > buffer(end_pos - start_pos);
    input_file.read(buffer.data(), buffer.size());
    input_file.close();

    const char * data = buffer.data();
    const size_t size = buffer.size();

    size_t pos = 0;

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
                output_file.close();
                std::cout << "Extracted file: " << filename << std::endl;
              } else {
                std::cerr << "Failed to open output file: " << filename << std::endl;
              }
              count++;
              pos += pe_size + pe_offset;
              continue;
            }
          } else if (pe_machine == 0x8664) { // Win64
            uint32_t pe_size = * reinterpret_cast <
              const uint32_t * > ( & data[pos + pe_offset + 0x50]);
            if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
              // Extract Win64 PE file data.
              const char * file_data = & data[pos];
              std::string filename = output_path + std::to_string(count) + ".exe";
              std::ofstream output_file(filename, std::ios::binary);
              if (output_file) {
                output_file.write(file_data, pe_size + pe_offset);
                output_file.close();
                std::cout << "Extracted file: " << filename << std::endl;
              } else {
                std::cerr << "Failed to open output file: " << filename << std::endl;
              }
              count++;
              pos += pe_size + pe_offset;
              continue;
            }
          }
        }
        // Check for 32-bit executable.
        const uint16_t magic = * reinterpret_cast <
          const uint16_t * > ( & data[pos]);
        if (magic == 0x5a4d) { // "MZ"
          const uint32_t pe_offset = * reinterpret_cast <
            const uint32_t * > ( & data[pos + 0x3c]);
          const char * pe_signature = & data[pos + pe_offset];
          const char * pe_magic = "PE\0\0";
          const size_t pe_magic_size = 4; // PE signature is always 4 bytes long.
          if (pe_offset != 0 && pos + pe_offset + pe_magic_size <= size &&
            memcmp(pe_signature, pe_magic, pe_magic_size) == 0) {
            const uint16_t pe_machine = * reinterpret_cast <
              const uint16_t * > ( & data[pos + pe_offset + 0x4]);
            if (pe_machine == 0x14c) { // Win32
              uint32_t pe_size = * reinterpret_cast <
                const uint32_t * > ( & data[pos + pe_offset + 0x50]);
              if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
                // Extract 32-bit PE file data.
                const char * file_data = & data[pos];
                std::string filename = output_path + std::to_string(count) + ".exe";
                std::ofstream output_file(filename, std::ios::binary);
                if (output_file) {
                  output_file.write(file_data, pe_size + pe_offset);
                  output_file.close();
                  std::cout << "Extracted file: " << filename << std::endl;
                } else {
                  std::cerr << "Failed to open output file: " << filename << std::endl;
                }
                count++;
                pos += pe_size + pe_offset;
                continue;
              }
            } else if (pe_machine == 0x8664) { // Win64
              uint32_t pe_size = * reinterpret_cast <
                const uint32_t * > ( & data[pos + pe_offset + 0x50]);
              if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
                // Extract 64-bit PE file data.
                const char * file_data = & data[pos];
                std::string filename = output_path + std::to_string(count) + ".exe";
                std::ofstream output_file(filename, std::ios::binary);
                if (output_file) {
                  output_file.write(file_data, pe_size + pe_offset);
                  output_file.close();
                  std::cout << "Extracted file: " << filename << std::endl;
                } else {
                  std::cerr << "Failed to open output file: " << filename << std::endl;
                }
                count++;
                pos += pe_size + pe_offset;
                continue;
              }
            }
          }
        }
        std::cout << "Processed chunk from " << "[" << start_pos << ", " << end_pos << ")" << std::endl;
      }
    }
    }
    int main(int argc, char * argv[]) {
      if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " input_file output_dir" << std::endl;
        return 1;
      }

      const std::string input_path = argv[1];
      const std::string output_path = argv[2];

      if (!fs::exists(input_path)) {
        std::cerr << "Input file does not exist: " << input_path << std::endl;
        return 1;
      }

      if (!fs::is_regular_file(input_path)) {
        std::cerr << "Input path is not a regular file: " << input_path << std::endl;
        return 1;
      }

      if (!fs::exists(output_path)) {
        if (!fs::create_directory(output_path)) {
          std::cerr << "Failed to create output directory: " << output_path << std::endl;
          return 1;
        }
      }

      if (!fs::is_directory(output_path)) {
        std::cerr << "Output path is not a directory: " << output_path << std::endl;
        return 1;
      }

      const size_t num_threads = std::thread::hardware_concurrency();
      const size_t chunk_size = fs::file_size(input_path) / num_threads;
      std::vector<std::thread> threads(num_threads);
      std::vector < size_t > start_positions(num_threads);
      std::vector < size_t > end_positions(num_threads);

      for (size_t i = 0; i < num_threads; ++i) {
    start_positions[i] = i * chunk_size;
    end_positions[i] = (i == num_threads - 1) ? fs::file_size(input_path) : start_positions[i] + chunk_size;
    threads[i] = std::thread(extract_executables, input_path, output_path, start_positions[i], end_positions[i]);
}
for (auto & t: threads) {
    t.join();
}






      return 0;
    }
