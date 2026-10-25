#include "tests/invoke_target.h"

#include <intrin.h>
#include <immintrin.h>
#include <windows.h>

#include <cstdint>
#include <cstring>

namespace {

__declspec(noinline) std::uint64_t SelfReturn() {
  return reinterpret_cast<std::uint64_t>(_ReturnAddress());
}

__declspec(noinline) std::uint64_t Sum16(
    std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d,
    std::uint64_t e, std::uint64_t f, std::uint64_t g, std::uint64_t h,
    std::uint64_t i, std::uint64_t j, std::uint64_t k, std::uint64_t l,
    std::uint64_t m, std::uint64_t n, std::uint64_t o, std::uint64_t p) {
  return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7 + h * 8 + i * 9 +
         j * 10 + k * 11 + l * 12 + m * 13 + n * 14 + o * 15 + p * 16;
}

__declspec(noinline) double Mixed16(std::uint64_t a, double b, float c,
                                    std::int64_t d, double e, std::uint64_t f,
                                    float g, double h, std::int64_t i, double j,
                                    float k, std::uint64_t l, double m, float n,
                                    std::int64_t o, double p) {
  return static_cast<double>(a) + b * 2 + c * 3 + static_cast<double>(d) * 4 +
         e * 5 + static_cast<double>(f) * 6 + g * 7 + h * 8 +
         static_cast<double>(i) * 9 + j * 10 + k * 11 +
         static_cast<double>(l) * 12 + m * 13 + n * 14 +
         static_cast<double>(o) * 15 + p * 16;
}

__declspec(noinline) float Floats(float a, float b, float c, float d, float e,
                                  float f, float g, float h) {
  return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7 + h * 8;
}

__declspec(noinline) std::int64_t Signed(std::int8_t a, std::uint16_t b,
                                         std::int32_t c, std::uint64_t d,
                                         std::int64_t e, std::int16_t f) {
  return a + b + c + static_cast<std::int64_t>(d) + e + f;
}

__declspec(noinline) const char* Utf8(const char* value) { return value; }
__declspec(noinline) const wchar_t* Utf16(const wchar_t* value) {
  return value;
}

__declspec(noinline) unsigned char* Bytes(unsigned char* value,
                                          std::uint64_t size) {
  for (std::uint64_t i = 0; i < size; ++i) value[i] ^= 0x5a;
  return value;
}

__declspec(noinline) void Increment(std::uint64_t* value) { ++*value; }

__declspec(noinline) std::uint64_t ReadPointer(
    const volatile std::uint64_t* pointer) {
  return *pointer;
}

__declspec(noinline) std::uint64_t Divide(std::uint64_t value) {
  return 100 / value;
}

__declspec(noinline) std::uint64_t Delayed(std::uint32_t milliseconds) {
  Sleep(milliseconds);
  return 789;
}

__declspec(noinline) std::uint64_t ThreadId() { return GetCurrentThreadId(); }

__declspec(noinline) unsigned char* DelayedBytes(unsigned char* data,
                                                 std::uint32_t milliseconds) {
  Sleep(milliseconds);
  data[0] ^= 0x5a;
  return data;
}

__declspec(noinline) std::uint64_t Nested(std::uint64_t a) {
  volatile std::uint64_t value = SelfReturn();
  return value == reinterpret_cast<std::uint64_t>(&Nested) ? 0 : a + 17;
}

__declspec(noinline) void BufferFault(volatile unsigned char* data) {
  data[4096] = 1;
}

__declspec(noinline) void ThreadExit() { ExitThread(123); }

__declspec(noinline) void* VectorReturn(const float* object, float* output) {
  _mm_store_ps(output, _mm_load_ps(object));
  return output;
}

}

extern "C" std::uint64_t InvocationAlignment();
extern "C" std::uint64_t InvocationClobberFault();

nlohmann::json InvocationTargets() {
  auto* isolated = static_cast<unsigned char*>(VirtualAlloc(
      nullptr, 0x100000000ULL, MEM_RESERVE, PAGE_NOACCESS));
  if (isolated != nullptr) {
    isolated += 0x80000000ULL;
    if (VirtualAlloc(isolated, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
      const unsigned char code[] = {0x56, 0x48, 0x8b, 0xc1, 0x5e, 0xc3};
      std::memcpy(isolated, code, sizeof(code));
      FlushInstructionCache(GetCurrentProcess(), isolated, sizeof(code));
    } else isolated = nullptr;
  }
  return {{"self_return", reinterpret_cast<std::uint64_t>(&SelfReturn)},
          {"isolated", reinterpret_cast<std::uint64_t>(isolated)},
          {"vector_return", reinterpret_cast<std::uint64_t>(&VectorReturn)},
          {"sum16", reinterpret_cast<std::uint64_t>(&Sum16)},
          {"mixed16", reinterpret_cast<std::uint64_t>(&Mixed16)},
          {"floats", reinterpret_cast<std::uint64_t>(&Floats)},
          {"signed", reinterpret_cast<std::uint64_t>(&Signed)},
          {"utf8", reinterpret_cast<std::uint64_t>(&Utf8)},
          {"utf16", reinterpret_cast<std::uint64_t>(&Utf16)},
          {"bytes", reinterpret_cast<std::uint64_t>(&Bytes)},
          {"increment", reinterpret_cast<std::uint64_t>(&Increment)},
          {"read_pointer", reinterpret_cast<std::uint64_t>(&ReadPointer)},
          {"divide", reinterpret_cast<std::uint64_t>(&Divide)},
          {"delayed", reinterpret_cast<std::uint64_t>(&Delayed)},
          {"thread_id", reinterpret_cast<std::uint64_t>(&ThreadId)},
          {"delayed_bytes", reinterpret_cast<std::uint64_t>(&DelayedBytes)},
          {"nested", reinterpret_cast<std::uint64_t>(&Nested)},
          {"buffer_fault", reinterpret_cast<std::uint64_t>(&BufferFault)},
          {"thread_exit", reinterpret_cast<std::uint64_t>(&ThreadExit)},
          {"alignment", reinterpret_cast<std::uint64_t>(&InvocationAlignment)},
          {"clobber_fault",
           reinterpret_cast<std::uint64_t>(&InvocationClobberFault)}};
}
