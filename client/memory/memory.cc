#include "client/memory/memory.h"

#include <limits>
#include <stdexcept>
#include <system_error>

namespace rrm {
namespace {

void ValidatePages(std::uint64_t address, std::size_t size, bool writing) {
  ValidateRange(address, size);
  auto end = address + size;
  while (address < end) {
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<void*>(address),
                        &info, sizeof(info))) {
      CheckWindows(FALSE, "VirtualQueryEx");
    }
    DWORD protection = info.Protect & 0xff;
    bool readable =
        protection == PAGE_READONLY || protection == PAGE_READWRITE ||
        protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
        protection == PAGE_EXECUTE_READWRITE ||
        protection == PAGE_EXECUTE_WRITECOPY;
    bool writable = protection == PAGE_READWRITE ||
                    protection == PAGE_WRITECOPY ||
                    protection == PAGE_EXECUTE_READWRITE ||
                    protection == PAGE_EXECUTE_WRITECOPY;
    if (info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD) || !readable ||
        (writing && !writable)) {
      throw std::runtime_error(
          "Memory range is uncommitted, guarded, or lacks access");
    }
    auto next =
        reinterpret_cast<std::uint64_t>(info.BaseAddress) + info.RegionSize;
    if (next <= address) {
      throw std::runtime_error("Invalid memory region");
    }
    address = next;
  }
}

}

void ValidateRange(std::uint64_t address, std::size_t size) {
  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  auto maximum =
      reinterpret_cast<std::uint64_t>(info.lpMaximumApplicationAddress);
  if (address <
          reinterpret_cast<std::uint64_t>(info.lpMinimumApplicationAddress) ||
      size == 0 || size > kMaxTransfer || address > maximum ||
      size - 1 > maximum - address) {
    throw std::invalid_argument(
        "Invalid address or size; maximum transfer is 1 MiB");
  }
}

void CheckWindows(BOOL success, const char* operation) {
  if (!success) {
    throw std::system_error(static_cast<int>(GetLastError()),
                            std::system_category(), operation);
  }
}

std::vector<std::uint8_t> Memory::Read(std::uint64_t address,
                                       std::size_t size) const {
  ValidatePages(address, size, false);
  std::vector<std::uint8_t> data(size);
  SIZE_T transferred = 0;
  CheckWindows(
      ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
                        data.data(), size, &transferred),
      "ReadProcessMemory");
  if (transferred != size) {
    throw std::runtime_error("Partial memory read");
  }
  return data;
}

void Memory::Write(std::uint64_t address,
                   const std::vector<std::uint8_t>& data) const {
  ValidatePages(address, data.size(), true);
  SIZE_T transferred = 0;
  CheckWindows(
      WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
                         data.data(), data.size(), &transferred),
      "WriteProcessMemory");
  if (transferred != data.size()) {
    throw std::runtime_error("Partial memory write; memory may have changed");
  }
  CheckWindows(
      FlushInstructionCache(GetCurrentProcess(),
                            reinterpret_cast<void*>(address), data.size()),
      "FlushInstructionCache");
}

std::uint64_t Memory::Allocate(std::size_t size, bool executable) {
  if (size == 0 || size > kMaxTransfer) {
    throw std::invalid_argument(
        "Allocation size must be between 1 byte and 1 MiB");
  }
  void* address =
      VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE,
                   executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
  CheckWindows(address != nullptr, "VirtualAlloc");
  auto value = reinterpret_cast<std::uint64_t>(address);
  try {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    auto committed = (size + info.dwPageSize - 1) &
                     ~(static_cast<std::size_t>(info.dwPageSize) - 1);
    allocations_.emplace(value, committed);
  } catch (...) {
    VirtualFree(address, 0, MEM_RELEASE);
    throw;
  }
  return value;
}

void Memory::Free(std::uint64_t address) {
  AllocationSize(address);
  CheckWindows(VirtualFree(reinterpret_cast<void*>(address), 0, MEM_RELEASE),
               "VirtualFree");
  allocations_.erase(address);
}

std::size_t Memory::AllocationSize(std::uint64_t address) const {
  auto allocation = allocations_.find(address);
  if (allocation == allocations_.end()) {
    throw std::invalid_argument(
        "Address is not an allocation owned by this agent");
  }
  return allocation->second;
}

}
