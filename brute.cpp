#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <cstdint>

struct Task {
    uint32_t start;
    uint32_t end;
    int offset;
    uint8_t code;
    std::atomic<bool>* found;
    float* result;

    void operator()() const {
        for (uint32_t u = start; u < end && !found->load(); ++u) {
            if ((u & 0xFF) != code)
                continue;

            float num;
            std::memcpy(&num, &u, 4);

            // 过滤 NaN/Inf
            if (!std::isfinite(num))
                continue;

            float product = num * 0x1f;
            if ((int)product == offset) {
                *result = num;
                found->store(true);
                break;
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <offset> <code>" << std::endl;
        return 1;
    }

    int offset = std::stoi(argv[1]);
    int code = std::stoi(argv[2]);

    if (code < 0 || code > 255) {
        std::cerr << "Code must be between 0 and 255." << std::endl;
        return 1;
    }

    int thread_count = std::thread::hardware_concurrency();
    if (thread_count == 0)
        thread_count = 4;

    std::atomic<bool> found{false};
    float result = 0.0f;
    std::vector<std::thread> threads;

    uint64_t total = 1ULL << 32;
    uint64_t chunk = total / thread_count;

    for (int i = 0; i < thread_count; ++i) {
        uint32_t start = static_cast<uint32_t>(i * chunk);
        uint32_t end = (i == thread_count - 1) ? 0xFFFFFFFF : static_cast<uint32_t>(start + chunk);

        threads.emplace_back(Task{
            start,
            end,
            offset,
            static_cast<uint8_t>(code),
            &found,
            &result
        });
    }

    for (auto& t : threads)
        t.join();

    if (found) {
        std::cout << std::fixed << std::setprecision(10)
                << result << std::endl;
    } else {
        std::cout << "Error: not found." << std::endl;
    }

    return 0;
}
