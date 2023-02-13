#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <experimental/filesystem>
#include <cstring>

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
    while (pos < size) {
        // Search for MZ header.
        const char* mz_header = &data[pos];
        const char* mz_magic = "MZ";
        const size_t mz_magic_size = 2; // MZ header is always 2 bytes long.
        if (memcmp(mz_header, mz_magic, mz_magic_size) != 0) {
            pos++;
            continue;
        }

        // Extract PE file size.
        const uint32_t pe_size = *reinterpret_cast<const uint32_t*>(&data[pos + 0x8]);
        if (pe_size == 0 || pos + pe_size > size || pe_size > 100000000) {
            pos++;
            continue;
        }
        const size_t file_size = pe_size + 0x200; // PE size + MZ header size.

        // Extract PE file data.
        const char* file_data = &data[pos];
        std::string filename = output_path + std::to_string(count) + ".exe";

        std::ofstream output_file(filename, std::ios::binary);
        if (output_file) {
            output_file.write(file_data, file_size);
            output_file.close();
            std::cout << "Extracted file: " << filename << std::endl;
        } else {
            std::cerr << "Failed to open output file: " << filename << std::endl;
        }

        count++;
        pos += file_size;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input path> <output path>" << std::endl;
        return 1;
    }
    const std::string input_path = argv[1];
    const std::string output_path = argv[2];
    extract_executables(input_path, output_path);
    return 0;
}
