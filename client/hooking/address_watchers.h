#ifndef RRM_CLIENT_HOOKING_ADDRESS_WATCHERS_H_
#define RRM_CLIENT_HOOKING_ADDRESS_WATCHERS_H_

#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>

namespace rrm {

class AddressWatchers {
 public:
  static AddressWatchers& Instance();
  static LONG WINAPI HandleException(EXCEPTION_POINTERS* info);
  nlohmann::json Add(std::uint64_t address, std::size_t size,
                     const std::string& access, std::size_t capacity);
  void Remove(std::uint64_t address);
  void RemoveAll();
  nlohmann::json GetHits(std::uint64_t address, std::uint64_t after,
                         std::size_t limit);
  bool Overlaps(std::uint64_t address, std::size_t size) const;

 private:
  struct Hit;
  struct Watcher;
  AddressWatchers();
  void Rearm(CONTEXT& context);
  static void Capture(Watcher& watcher, EXCEPTION_POINTERS* info);
  SRWLOCK state_lock_ = SRWLOCK_INIT;
  std::array<std::atomic<Watcher*>, 64> watchers_{};
  std::size_t count_ = 0;
  std::size_t page_size_ = 4096;
};

}

#endif
