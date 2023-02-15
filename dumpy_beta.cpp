#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <algorithm>
#include <functional>
#include <cstdint>
#include <cstring>

#include <windows.h>

// Threadpool implementation
class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads) {
        for (size_t i = 0; i < num_threads; ++i) {
            threads.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock{mutex};
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock{mutex};
            stop = true;
        }
        condition.notify_all();
        for (auto &thread : threads) {
            thread.join();
        }
    }

    template<typename F, typename... Args>
    void enqueue(F &&f, Args &&... args) {
        {
            std::unique_lock<std::mutex> lock{mutex};
            tasks.emplace([f = std::forward<F>(f), args = std::make_tuple(std::forward<Args>(args)...)]() {
                std::apply(f, args);
            });
        }
        condition.notify_one();
    }

private:
    std::vector<std::thread> threads;
    std::queue<std::function<void()>> tasks;
    std::mutex mutex;
    std::condition_variable condition;
    bool stop = false;
};

// Check for valid DOS header
bool validate_dos_header(const char *buffer) {
    // Check for valid MZ signature
    if (memcmp(buffer, "MZ", 2) != 0) {
        return false;
    }

    // Check for valid PE offset
    uint32_t pe_offset = *reinterpret_cast<const uint32_t *>(buffer + 0x3c);
    if (pe_offset >= 0x1000) {
        return false;
    }

    return true;
}

// Check for valid PE signature
bool validate_pe_signature(const char *buffer, uint32_t size) {
    if (size < 0x1000) {
        return false;
    }

    // Check for valid PE signature
    if (memcmp(buffer + *reinterpret_cast<const uint32_t *>(buffer + 0x3c), "PE\0\0", 4) != 0) {
        return false;
    }

    return true;
}

// Find the offsets of all PE files in the memory dump
void find_pe_offsets(const std::vector<char>& data, size_t size, std::vector<uint32_t>& pe_offsets) {
    const char* buffer = &data[0];
    size_t max_offset = size - 0x1000;
    for (size_t i = 0; i < max_offset; ++i) {
        if (validate_dos_header(buffer + i)) {
            uint32_t pe_offset = *reinterpret_cast<const uint32_t *>(buffer + i + 0x3c);
            if (i + pe_offset + 4 < size) {
                if (validate_pe_signature(buffer + i + pe_offset, size - i - pe_offset)) {
                    pe_offsets.push_back(i + pe_offset);
                }
            }
        }
    }
}

// Extract a single PE file from the memory dump
void extract_pe(const std::vector<char>& data, uint32_t offset, const std::string& output_dir) {
const char* buffer = &data[0];
// Get the size of the PE file
uint32_t size_of_image = *reinterpret_cast<const uint32_t *>(buffer + offset + 0x50);
 // Write the PE file to disk
std::string output_file = output_dir + "/pe_" + std::to_string(offset) + ".exe";
std::ofstream file(output_file, std::ios::binary);
file.write(buffer + offset, size_of_image);
}
// Extract all PE files from the memory dump using threadpooling
void extract_pe_files(const std::vector<char>& data, const std::vector<uint32_t>& pe_offsets, const std::string& output_dir, size_t num_threads) {
ThreadPool thread_pool(num_threads);
    for (auto offset : pe_offsets) {
    thread_pool.enqueue(extract_pe, data, offset, output_dir);
}
}
int main(int argc, char** argv) {
if (argc != 4) {
std::cerr << "Usage: " << argv[0] << " <input file> <output dir> <num threads>" << std::endl;
return 1;
}
    std::string input_file = argv[1];
std::string output_dir = argv[2];
size_t num_threads = std::stoi(argv[3]);

// Read the memory dump file into a vector
std::vector<char> data;
std::ifstream file(input_file, std::ios::binary | std::ios::ate);
if (file.is_open()) {
    size_t size = file.tellg();
    data.resize(size);
    file.seekg(0, std::ios::beg);
    file.read(data.data(), size);
    file.close();
} else {
    std::cerr << "Error: could not open file: " << input_file << std::endl;
    return 1;
}

// Find the offsets of all PE files in the memory dump
std::vector<uint32_t> pe_offsets;
find_pe_offsets(data, data.size(), pe_offsets);

// Extract all PE files from the memory dump
extract_pe_files(data, pe_offsets, output_dir, num_threads);

return 0;
}
