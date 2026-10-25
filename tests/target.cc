#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#include "tests/invoke_target.h"

int main() {
  auto* code = static_cast<unsigned char*>(VirtualAlloc(
      nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
  auto* memory = static_cast<unsigned char*>(
      VirtualAlloc(nullptr, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (code == nullptr || memory == nullptr) return 1;
  const unsigned char basic[] = {0x48, 0x8b, 0xc1, 0x48,
                                 0x83, 0xc0, 0x07, 0xc3};
  const unsigned char rip[] = {0x48, 0x8b, 0x05, 0x01, 0, 0, 0, 0xc3,
                               0x2a, 0,    0,    0,    0, 0, 0, 0};
  const unsigned char branch[] = {0xe9, 0x01, 0, 0, 0, 0x90,
                                  0xb8, 0x2a, 0, 0, 0, 0xc3};
  const unsigned char conditional[] = {0x85, 0xc9, 0x74, 0x06, 0xb8, 0x01,
                                       0,    0,    0,    0xc3, 0xb8, 0x02,
                                       0,    0,    0,    0xc3};
  std::memcpy(code, basic, sizeof(basic));
  std::memcpy(code + 64, rip, sizeof(rip));
  std::memcpy(code + 128, branch, sizeof(branch));
  std::memcpy(code + 192, conditional, sizeof(conditional));
  DWORD old = 0;
  if (!VirtualProtect(memory + 4096, 4096, PAGE_NOACCESS, &old)) return 2;
  if (!VirtualProtect(memory + 8192, 4096, PAGE_READONLY, &old)) return 3;
  if (!VirtualProtect(memory + 12288, 4096, PAGE_READWRITE | PAGE_GUARD, &old))
    return 4;
  nlohmann::json info = {
      {"pid", GetCurrentProcessId()},
      {"entry", reinterpret_cast<std::uint64_t>(code)},
      {"rip", reinterpret_cast<std::uint64_t>(code + 64)},
      {"branch", reinterpret_cast<std::uint64_t>(code + 128)},
      {"conditional", reinterpret_cast<std::uint64_t>(code + 192)},
      {"memory", reinterpret_cast<std::uint64_t>(memory)},
      {"noaccess", reinterpret_cast<std::uint64_t>(memory + 4096)},
      {"readonly", reinterpret_cast<std::uint64_t>(memory + 8192)},
      {"guarded", reinterpret_cast<std::uint64_t>(memory + 12288)}};
  info["functions"] = InvocationTargets();
  std::cout << info.dump() << std::endl;
  std::string line;
  while (std::getline(std::cin, line)) {
    auto args = nlohmann::json::parse(line);
    if (args.value("exit", false)) break;
    auto address = args.at("address").get<std::uint64_t>();
    auto argument = args.value("argument", std::uint64_t{123});
    auto iterations = args.value("iterations", 1);
    auto threads = args.value("threads", 1);
    std::atomic<std::uint64_t> sum{0};
    std::vector<std::thread> workers;
    for (int thread = 0; thread < threads; ++thread) {
      workers.emplace_back([&] {
        auto function =
            reinterpret_cast<std::uint64_t (*)(std::uint64_t)>(address);
        for (int i = 0; i < iterations; ++i) sum.fetch_add(function(argument));
      });
    }
    for (auto& worker : workers) worker.join();
    std::cout << nlohmann::json({{"sum", sum.load()}}).dump() << std::endl;
  }
  return 0;
}
