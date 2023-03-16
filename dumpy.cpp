#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <experimental/filesystem>
#include <cstring>
#include <windows.h>
#include <algorithm>
#include <unordered_set>

namespace fs = std::experimental::filesystem;

std::vector<size_t> find_mz_headers(const std::vector<char>& buffer) {
    const char* dos_magic = "MZ";
    const size_t dos_magic_size = 2;
    std::vector<size_t> mz_positions;

    for (size_t pos = 0; pos < buffer.size() - dos_magic_size; ++pos) {
        if (memcmp(&buffer[pos], dos_magic, dos_magic_size) == 0) {
            mz_positions.push_back(pos);
        }
    }

    return mz_positions;
}

void extract_executables(const std::string& input_path, const std::string& output_path) {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        std::cerr << "Failed to open input file: " << input_path << std::endl;
        return;
    }

    std::vector<char> buffer(std::istreambuf_iterator<char>(input_file), {});
    input_file.close();

    std::vector<size_t> mz_positions = find_mz_headers(buffer);

    int count = 0;
    std::unordered_set<std::string> headers;

    for (size_t pos : mz_positions) {
        const char* pe_header = &buffer[pos + 0x3C];
        const uint32_t pe_offset = *reinterpret_cast<const uint32_t*>(pe_header);
        const char* pe_signature = &buffer[pos + pe_offset];
        const char* pe_magic = "PE\0\0";
        const size_t pe_magic_size = 4;

        if (pe_offset != 0 && pos + pe_offset + pe_magic_size <= buffer.size() &&
            memcmp(pe_signature, pe_magic, pe_magic_size) == 0) {
            const uint16_t pe_machine = *reinterpret_cast<const uint16_t*>(&buffer[pos + pe_offset + 0x4]);
            if (pe_machine == 0x14c || pe_machine == 0x8664) {
                uint32_t pe_size = *reinterpret_cast<const uint32_t*>(&buffer[pos + pe_offset + 0x50]);

                if (pe_size != 0 && pos + pe_offset + pe_size <= buffer.size() && pe_size <= 100000000) {
                    const std::string header_str(buffer.data() + pos + pe_offset, pe_size > 1024 ? 1024 : pe_size);
                    if (headers.find(header_str) == headers.end()) {
                        headers.insert(header_str);
                        std::string filename = output_path + std::to_string(count++) + ".exe";

                        std::ofstream output_file(filename, std::ios::binary);
                        if (output_file) {
                            output_file.write(buffer.data() + pos, pe_size + pe_offset);
                            output_file.close();
                            std::cout << "Extracted file: " << filename << std::endl;
                        } else {
                            std::cerr << "Failed to open output file: " << filename << std::endl;
                        }
                    }
                }
            }
        }
    } // This closing brace was moved to the correct position.

if (count == 0) {
    std::cout << "No executables found in input file." << std::endl;
} else {
    std::cout << "Extracted " << count << " executables to output path: " << output_path << std::endl;
}
}

int main(int argc, char* argv[]) {
if (argc != 3) {
std::cerr << "Usage: " << argv[0] << " <input_file> <output_dir>" << std::endl;
return 1;
}
std::string input_path = argv[1];
std::string output_path = argv[2];
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
} else if (!fs::is_directory(output_path)) {
    std::cerr << "Output path is not a directory: " << output_path << std::endl;
    return 1;
}

extract_executables(input_path, output_path);

return 0;
}                  
