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

void extract_executables(const std::string& input_path, const std::string& output_path) {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        std::cerr << "Failed to open input file: " << input_path << std::endl;
        return;
    }

    std::vector<char> buffer(std::istreambuf_iterator<char>(input_file), {});
    input_file.close();

    const char* data = buffer.data();
    const size_t size = buffer.size();

    size_t pos = 0;
    int count = 0;
    size_t last_mz_pos = 0; // initialize last MZ header position to 0

    std::vector<std::thread> threads;

    std::unordered_set<std::string> headers;
    const char* dos_magic = "MZ";
    const size_t dos_magic_size = 2;
    while (pos < size - dos_magic_size) { // Change the condition to avoid reading past the buffer
    const char* dos_header = &data[pos];
    
    if (memcmp(dos_header, dos_magic, dos_magic_size) == 0) {
            if (pos != last_mz_pos) { // check if this is a new file
                last_mz_pos = pos; // update last MZ header position
                const char* pe_header = &data[pos + 0x3C];
                const uint32_t pe_offset = *reinterpret_cast<const uint32_t*>(pe_header);
                const char* pe_signature = &data[pos + pe_offset];
                const char* pe_magic = "PE\0\0";
                const size_t pe_magic_size = 4;
                if (pe_offset != 0 && pos + pe_offset + pe_magic_size <= size &&
                    memcmp(pe_signature, pe_magic, pe_magic_size) == 0) {
                    const uint16_t pe_machine = *reinterpret_cast<const uint16_t*>(&data[pos + pe_offset + 0x4]);
                    if (pe_machine == 0x14c) {
                        uint32_t pe_size = *reinterpret_cast<const uint32_t*>(&data[pos + pe_offset + 0x50]);
                        if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
                            const char* file_data = &data[pos];
                            const std::string header_str(file_data + pos + pe_offset, pe_size > 1024 ? 1024 : pe_size);
                            if (headers.find(header_str) == headers.end()) {
                                headers.insert(header_str);

                                std::string filename = output_path + std::to_string(count) + ".exe";

                                threads.emplace_back([file_data, pe_offset, pe_size, filename]() {
                                    std::ofstream output_file(filename, std::ios::binary);
if (output_file) {
output_file.write(file_data, pe_size + pe_offset);
output_file.close();
std::cout << "Extracted file: " << filename << std::endl;
}
else {
std::cerr << "Failed to open output file: " << filename << std::endl;
}
});
                            count++;
                        }
                        pos += pe_size + pe_offset;
                        continue;
                    }
                }
                else if (pe_machine == 0x8664) {
                    uint32_t pe_size = *reinterpret_cast<const uint32_t*>(&data[pos + pe_offset + 0x50]);
                    if (pe_size != 0 && pos + pe_offset + pe_size <= size && pe_size <= 100000000) {
                        const char* file_data = &data[pos];
                        const std::string header_str(file_data + pos + pe_offset, pe_size > 1024 ? 1024 : pe_size);
                        if (headers.find(header_str) == headers.end()) {
                            headers.insert(header_str);

                            std::string filename = output_path + std::to_string(count) + ".exe";

                            threads.emplace_back([file_data, pe_offset, pe_size, filename]() {
                                std::ofstream output_file(filename, std::ios::binary);
                                if (output_file) {
                                    output_file.write(file_data, pe_size + pe_offset);
                                    output_file.close();
                                    std::cout << "Extracted file: " << filename << std::endl;
                                }
                                else {
                                    std::cerr << "Failed to open output file: " << filename << std::endl;
                                }
                            });

                            count++;
                        }
                        pos += pe_size + pe_offset;
                        continue;
                    }
                }
            }
        }
    }
    pos++;
}

for (auto& thread : threads) {
    thread.join();
}

if (count == 0) {
    std::cout << "No executables found in input file." << std::endl;
}
else {
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
}
else if (!fs::is_directory(output_path)) {
std::cerr << "Output path is not a directory: " << output_path << std::endl;
return 1;
}

extract_executables(input_path, output_path);

return 0;
}