#include <iostream>

#include <fstream>

#include <vector>

#include <string>

#include <experimental/filesystem>

#include <cstring>

#include <windows.h>

#include <thread>

#include <unordered_set>

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
    size_t last_mz_pos = 0; // initialize last MZ header position to 0

    std::vector < std::thread > threads;

    std::unordered_set < std::string > headers;

    while (pos < size) {
      const char * dos_header = & data[pos];
      const char * dos_magic = "MZ";
      const size_t dos_magic_size = 2;
      if (memcmp(dos_header, dos_magic, dos_magic_size) == 0) {
        if (pos != last_mz_pos) { // check if this is a new file
          last_mz_pos = pos; // update last MZ header position
          const char * pe_header = & data[pos + 0x3C];
          const uint32_t pe_offset = * reinterpret_cast <
            const uint32_t * > ( & data[pos + reinterpret_cast <
              const uint32_t * > (pe_header)]);
          const char * pe_signature = & data[pos + pe_offset];
          const char * pe_magic = "PE\0\0";
          const size_t pe_magic_size = 4;
          if (pe_offset != 0 && pos + pe_offset + pe_magic_size <= size &&
            memcmp(pe_signature, pe_magic, pe_magic_size) == 0) {
            const uint16_t pe_machine = * reinterpret_cast <
              const uint16_t * > ( & data[pos + pe_offset + 0x4]);
            if (pe_machine == 0x14c) {
              uint32_t pe_size = * reinterpret_cast <
                const uint32_t * > ( & data[pos + pe_offset + 0x50]);
              if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
                const char * file_data = & data[pos];
                const std::string header_str(file_data + pos + pe_offset, pe_size > 1024 ? 1024 : pe_size);
                if (headers.find(header_str) == headers.end()) {
                  headers.insert(header_str);

                  // Look for a second MZ header near the end of the file
                  const size_t check_size = std::min < size_t > (pe_size, 0x10000);
                  const char * check_data = file_data + pe_offset + pe_size - check_size;
                  const char * check_magic = "MZ";
                  const size_t check_magic_size = 2;
                  const char * check_result = std::search(check_data, check_data + check_size - check_magic_size, check_magic, check_magic + check_magic_size);
                  if (check_result != check_data + check_size - check_magic_size) {
                    size_t second_mz_pos = pos + pe_offset + pe_size - check_size + std::distance(check_data, check_result);
                    if (second_mz_pos - pos > 0x200) { // Treat as separate file if the two MZ headers are far apart
                      std::string filename = output_path + std::to_string(count) + ".exe";
                     threads.emplace_back([file_data, pe_offset, second_mz_pos, filename]() {
  std::ofstream output_file(filename, std::ios::binary);
  if (output_file) {
    output_file.write(file_data + pos, second_mz_pos - pos);
    output_file.close();
    std::cout << "Extracted file: " << filename << std::endl;
  } else {
    std::cerr << "Failed to open output file: " << filename << std::endl;
  }
});
                      count++;
                    } else { // Otherwise, skip this file
                      std::cout << "Skipped file with duplicate MZ header: " << input_path << std::endl;
                    }
                  } else { // Only one MZ header, extract the whole file
                    std::string filename = output_path + std::to_string(count) + ".exe";
                    threads.emplace_back(file_data, pe_offset, pe_size, filename {
                      std::ofstream output_file(filename, std::ios::binary);
                      if (output_file) {
                        output_file.write(file_data + pos, pe_offset + pe_size);
                        output_file.close();
                        std::cout << "Extracted file: " << filename << std::endl;
                      } else {
                        std::cerr << "Failed to open output file: " << filename << std::endl;
                      }
                    });
                    count++;
                  }
                }
                pos += pe_size + pe_offset;
                continue;
              }
            } else if (pe_machine == 0x8664) {
              uint32_t pe_size = reinterpret_cast <
                const uint32_t > ( & data[pos + pe_offset + 0x50]);
              if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
                const char * file_data = & data[pos];
                const std::string header_str(file_data + pos + pe_offset, pe_size > 1024 ? 1024 : pe_size);
                if (headers.find(header_str) == headers.end()) {
                  headers.insert(header_str);
                  // Look for a second MZ header near the end of the file
                  const size_t check_size = std::min < size_t > (pe_size, 0x10000);
                  const char * check_data = file_data + pe_offset + pe_size - check_size;
                  const char * check_magic = "MZ";
                  const size_t check_magic_size = 2;
                  const char * check_result = std::search(check_data, check_data + check_size - check_magic_size, check_magic, check_magic + check_magic_size);
                  if (check_result != check_data + check_size - check_magic_size) {
                    size_t second_mz_pos = pos + pe_offset + pe_size - check_size + std::distance(check_data, check_result);
                    if (second_mz_pos - pos > 0x200) { // Treat as separate file if the two MZ headers are far apart
                      std::string filename = output_path + std::to_string(count) + ".exe";
                      threads.emplace_back([file_data, pe_offset, pe_size, filename]() {
  std::ofstream output_file(filename, std::ios::binary);
  if (output_file) {
    output_file.write(file_data + pos, pe_offset + pe_size);
    output_file.close();
    std::cout << "Extracted file: " << filename << std::endl;
  } else {
    std::cerr << "Failed to open output file: " << filename << std::endl;
  }
});
                      count++;
                    } else { // Otherwise, skip this file
                      std::cout << "Skipped file with duplicate MZ header: " << input_path << std::endl;
                    }
                  } else { // Only one MZ header, extract the whole file
                    std::string filename = output_path + std::to_string(count) + ".exe";
                    threads.emplace_back(file_data, pe_offset, pe_size, filename {
                      std::ofstream output_file(filename, std::ios::binary);
                      if (output_file) {
                        output_file.write(file_data + pos, pe_offset + pe_size);
                        output_file.close();
                        std::cout << "Extracted file: " << filename << std::endl;
                      } else {
                        std::cerr << "Failed to open output file: " << filename << std::endl;
                      }
                    });
                    count++;
                  }
                }
                pos += pe_size + pe_offset;
                continue;
              }
            }
            pos++;
          }
        }
      }
    }
          for (auto & thread: threads) {
            thread.join();
          }
        }

        int main(int argc, char ** argv) {
          if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " <input_path> <output_path>" << std::endl;
            return 1;
          }
          const std::string input_path(argv[1]);
          const std::string output_path(argv[2]);

          if (!fs::exists(input_path)) {
            std::cerr << "Input file does not exist: " << input_path << std::endl;
            return 1;
          }

          if (!fs::is_regular_file(input_path)) {
            std::cerr << "Input path is not a file: " << input_path << std::endl;
            return 1;
          }

          if (!fs::exists(output_path)) {
            std::cerr << "Output directory does not exist: " << output_path << std::endl;
            return 1;
          }

          if (!fs::is_directory(output_path)) {
            std::cerr << "Output path is not a directory: " << output_path << std::endl;
            return 1;
          }

          extract_executables(input_path, output_path);

          return 0;
        }
