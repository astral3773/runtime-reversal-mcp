#ifndef RRM_CLIENT_HOOKING_EXCEPTION_HOOKS_H_
#define RRM_CLIENT_HOOKING_EXCEPTION_HOOKS_H_

#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>

namespace rrm {

class ExceptionHooks {
 public:
  static ExceptionHooks& Instance();
  nlohmann::json Add(std::uint64_t address, std::size_t capacity,
                     std::size_t stack_size, bool logging = true);
  void AcquireInvocation(std::uint64_t address);
  void ReleaseInvocation(std::uint64_t address);
  void Remove(std::uint64_t address);
  void RemoveAll();
  nlohmann::json GetHits(std::uint64_t address, std::uint64_t after,
                         std::size_t limit) const;
  bool Overlaps(std::uint64_t address, std::size_t size) const;

 private:
  struct Hit;
  struct HitSlot;
  struct Hook;

  ExceptionHooks();
  static LONG WINAPI HandleException(EXCEPTION_POINTERS* info);
  static void Capture(Hook& hook, const CONTEXT& context);

  void* handler_ = nullptr;
  std::array<std::atomic<Hook*>, 128> hooks_{};
  std::size_t count_ = 0;
};

}

#endif
