#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;

const uint64_t MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

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
        const char* file_data = &data[pos];
        size_t file_size = size - pos;
        std::string filename = output_path + std::to_string(count) + ".exe";
        if (file_size > MAX_FILE_SIZE) {
            std::cerr << "Skipping file: " << filename << " (file too large)" << std::endl;
        } else {
            std::ofstream output_file(filename, std::ios::binary);
            if (output_file) {
                output_file.write(file_data, file_size);
                output_file.close();
                std::cout << "Extracted file: " << filename << std::endl;
            } else {
                std::cerr << "Failed to open output file: " << filename << std::endl;
            }
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
