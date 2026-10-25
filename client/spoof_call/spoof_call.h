#ifndef RRM_CLIENT_SPOOF_CALL_SPOOF_CALL_H_
#define RRM_CLIENT_SPOOF_CALL_SPOOF_CALL_H_

#include <windows.h>

#include <array>
#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>

namespace rrm {

struct alignas(16) SpoofFrame {
  std::uint64_t target = 0;
  std::array<std::uint64_t, 16> arguments{};
  std::uint64_t return_rsp = 0;
  std::uint64_t resume = 0;
  std::uint64_t rax = 0;
  std::array<std::uint8_t, 16> xmm0{};
  std::array<std::uint64_t, 8> nonvolatile{};
  std::array<M128A, 10> xmm_nonvolatile{};
  std::uint32_t mxcsr = 0;
  std::uint16_t control_word = 0;
  std::uint16_t padding = 0;
  std::uint32_t armed = 0;
  std::uint32_t exception_code = 0;
  std::uint64_t exception_address = 0;
};

class SpoofCall {
 public:
  SpoofCall();
  ~SpoofCall();
  SpoofCall(const SpoofCall&) = delete;
  SpoofCall& operator=(const SpoofCall&) = delete;

  nlohmann::json Invoke(const nlohmann::json& args);
  nlohmann::json GetResult(std::uint64_t id, DWORD timeout);
  void Refresh();
  static bool HandleException(EXCEPTION_POINTERS* info,
                              bool unhandled_breakpoint = false);

 private:
  struct Invocation;
  static unsigned __stdcall Run(void* parameter);
  nlohmann::json Collect(DWORD timeout);
  std::unique_ptr<Invocation> invocation_;
  std::uint64_t next_id_ = 1;
};

}

extern "C" void RrmSpoofStub(rrm::SpoofFrame* frame);

#endif
