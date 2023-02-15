#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <algorithm>

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
void extract
