#ifndef RRM_CLIENT_MEMORY_MEMORY_H_
#define RRM_CLIENT_MEMORY_MEMORY_H_

#include <windows.h>

#include <cstdint>
#include <map>
#include <vector>

namespace rrm {

constexpr std::size_t kMaxTransfer = 1024 * 1024;

void ValidateRange(std::uint64_t address, std::size_t size);
void CheckWindows(BOOL success, const char* operation);

class Memory {
 public:
  std::vector<std::uint8_t> Read(std::uint64_t address, std::size_t size) const;
  void Write(std::uint64_t address,
             const std::vector<std::uint8_t>& data) const;
  std::uint64_t Allocate(std::size_t size, bool executable);
  void Free(std::uint64_t address);
  std::size_t AllocationSize(std::uint64_t address) const;

 private:
  std::map<std::uint64_t, std::size_t> allocations_;
};

}

#endif
