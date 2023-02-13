#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;

bool is_pe_file(const char* buffer, const size_t size) {
    const char pe_magic[] = { 'M', 'Z' };
    const size_t pe_magic_size = sizeof(pe_magic);
    if (size < pe_magic_size) {
        return false;
    }
    return std::memcmp(buffer, pe_magic, pe_magic_size) == 0;
}

void extract_pe_files(const std::string& input_path, const std::string& output_path) {
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
    while (pos < size) {
        if (is_pe_file(&data[pos], size - pos)) {
            const std::string filename = (fs::path(output_path) / (std::to_string(pos) + ".exe")).generic_string();
            std::ofstream output_file(filename, std::ios::binary);
            if (output_file) {
                output_file.write(&data[pos], size - pos);
                output_file.close();
                std::cout << "Extracted PE file: " << filename << std::endl;
            } else {
                std::cerr << "Failed to open output file: " << filename << std::endl;
            }
        }
        pos++;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input path> <output path>" << std::endl;
        return 1;
    }
    const std::string input_path = argv[1];
    const std::string output_path = argv[2];
    extract_pe_files(input_path, output_path);
    return 0;
}
