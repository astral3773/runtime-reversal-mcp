#include "client/spoof_call/spoof_call.h"

#include <process.h>

#include <cmath>
#include <cstddef>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "client/hooking/exception_hooks.h"
#include "client/ipc/protocol.h"
#include "client/memory/memory.h"

namespace rrm {
namespace {

using Json = nlohmann::json;
thread_local SpoofFrame* active_frame = nullptr;

static_assert(offsetof(SpoofFrame, arguments) == 8);
static_assert(offsetof(SpoofFrame, return_rsp) == 0x88);
static_assert(offsetof(SpoofFrame, resume) == 0x90);
static_assert(offsetof(SpoofFrame, rax) == 0x98);
static_assert(offsetof(SpoofFrame, xmm0) == 0xa0);
static_assert(offsetof(SpoofFrame, nonvolatile) == 0xb0);
static_assert(offsetof(SpoofFrame, xmm_nonvolatile) == 0xf0);
static_assert(offsetof(SpoofFrame, mxcsr) == 0x190);
static_assert(offsetof(SpoofFrame, control_word) == 0x194);
static_assert(offsetof(SpoofFrame, armed) == 0x198);
static_assert(offsetof(SpoofFrame, exception_code) == 0x19c);
static_assert(offsetof(SpoofFrame, exception_address) == 0x1a0);

class Buffer {
 public:
  explicit Buffer(const std::vector<std::uint8_t>& data) : size_(data.size()) {
    if (size_ > kMaxTransfer)
      throw std::invalid_argument("Invalid argument buffer size");
    auto capacity = size_ == 0 ? std::size_t{1} : size_;
    auto payload = (capacity + 4095) & ~std::size_t{4095};
    base_ = VirtualAlloc(nullptr, payload + 8192, MEM_RESERVE, PAGE_NOACCESS);
    CheckWindows(base_ != nullptr, "VirtualAlloc(argument reserve)");
    auto* start = static_cast<std::uint8_t*>(base_) + 4096;
    if (!VirtualAlloc(start, payload, MEM_COMMIT, PAGE_READWRITE)) {
      DWORD error = GetLastError();
      VirtualFree(base_, 0, MEM_RELEASE);
      SetLastError(error);
      CheckWindows(FALSE, "VirtualAlloc(argument commit)");
    }
    data_ = start + payload - ((capacity + 15) & ~std::size_t{15});
    if (size_ != 0) std::memcpy(data_, data.data(), size_);
  }
  ~Buffer() { VirtualFree(base_, 0, MEM_RELEASE); }
  std::uint64_t address() const {
    return reinterpret_cast<std::uint64_t>(data_);
  }
  std::size_t size() const { return size_; }

 private:
  void* base_ = nullptr;
  void* data_ = nullptr;
  std::size_t size_ = 0;
};

void Keys(const Json& object, std::initializer_list<const char*> allowed) {
  if (!object.is_object())
    throw std::invalid_argument("Argument must be an object");
  for (const auto& item : object.items()) {
    bool found = false;
    for (const char* name : allowed)
      if (item.key() == name) found = true;
    if (!found)
      throw std::invalid_argument("Unexpected argument field: " + item.key());
  }
}

std::uint64_t Numeric(const Json& value, const std::string& format) {
  bool sign = format == "int8" || format == "int16" || format == "int32" ||
              format == "int64";
  unsigned bits = 0;
  if (format == "int8" || format == "uint8") bits = 8;
  if (format == "int16" || format == "uint16") bits = 16;
  if (format == "int32" || format == "uint32") bits = 32;
  if (format == "int64" || format == "uint64") bits = 64;
  if (bits == 0) throw std::invalid_argument("Unknown numeric format");
  std::string text;
  if (value.is_string())
    text = value.get<std::string>();
  else if (value.is_number_integer())
    text = value.dump();
  else
    throw std::invalid_argument(
        "Numeric values must be integers or integer strings");
  if (text.empty() || text.size() > 32 ||
      text.find_first_of(" \t\r\n+") != std::string::npos) {
    throw std::invalid_argument("Invalid integer representation");
  }
  bool negative = text[0] == '-';
  std::string magnitude = negative ? text.substr(1) : text;
  int base = 10;
  if (magnitude.rfind("0x", 0) == 0 || magnitude.rfind("0X", 0) == 0) {
    magnitude = magnitude.substr(2);
    base = 16;
  }
  if (magnitude.empty() ||
      magnitude.find_first_not_of(base == 16
                                      ? "0123456789abcdefABCDEF"
                                      : "0123456789") != std::string::npos) {
    throw std::invalid_argument("Invalid integer representation");
  }
  std::size_t used = 0;
  auto number = std::stoull(magnitude, &used, base);
  std::uint64_t maximum = sign         ? (std::uint64_t{1} << (bits - 1)) - 1
                          : bits == 64 ? UINT64_MAX
                                       : (std::uint64_t{1} << bits) - 1;
  if (negative) {
    if (!sign || number > maximum + 1)
      throw std::invalid_argument("Integer is out of range for its format");
    return std::uint64_t{0} - number;
  }
  if (number > maximum)
    throw std::invalid_argument("Integer is out of range for its format");
  return number;
}

std::vector<std::uint8_t> StringBytes(const std::string& text,
                                      const std::string& encoding) {
  if (text.size() > 65536 || text.find('\0') != std::string::npos) {
    throw std::invalid_argument(
        "String exceeds 65536 UTF-8 bytes or contains an embedded null");
  }
  int length = text.empty() ? 0
                            : MultiByteToWideChar(
                                  CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                  static_cast<int>(text.size()), nullptr, 0);
  if (!text.empty() && length == 0)
    throw std::invalid_argument("String is not valid UTF-8");
  if (encoding == "utf8") {
    std::vector<std::uint8_t> bytes(text.begin(), text.end());
    bytes.push_back(0);
    return bytes;
  }
  if (encoding != "utf16")
    throw std::invalid_argument("String format must be utf8 or utf16");
  std::wstring wide(length + 1, L'\0');
  if (length != 0)
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), wide.data(), length);
  std::vector<std::uint8_t> bytes(wide.size() * sizeof(wchar_t));
  std::memcpy(bytes.data(), wide.data(), bytes.size());
  return bytes;
}

std::string ReadString(std::uint64_t address, std::size_t maximum, bool wide) {
  std::vector<std::uint8_t> bytes;
  auto width = wide ? std::size_t{2} : std::size_t{1};
  if (wide && address % 2 != 0)
    throw std::invalid_argument("Returned UTF-16 pointer is not aligned");
  for (std::size_t offset = 0; offset + width <= maximum;) {
    auto size = (std::min)(
        {maximum - offset, std::size_t{256},
         4096 - static_cast<std::size_t>((address + offset) & 4095)});
    size -= size % width;
    if (size == 0) break;
    auto chunk = Memory().Read(address + offset, size);
    for (std::size_t i = 0; i < chunk.size(); i += width) {
      if (chunk[i] == 0 && (!wide || chunk[i + 1] == 0)) {
        if (!wide) {
          std::string result(bytes.begin(), bytes.end());
          if (!result.empty() &&
              !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, result.data(),
                                   static_cast<int>(result.size()), nullptr,
                                   0)) {
            throw std::runtime_error("Returned string is not valid UTF-8");
          }
          return result;
        }
        std::wstring text(bytes.size() / 2, L'\0');
        if (!bytes.empty())
          std::memcpy(text.data(), bytes.data(), bytes.size());
        if (text.empty()) return {};
        int encoded_size = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
            static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (!encoded_size)
          throw std::runtime_error("Returned string is not valid UTF-16");
        std::string result(encoded_size, '\0');
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), result.data(), encoded_size,
                            nullptr, nullptr);
        return result;
      }
      bytes.insert(bytes.end(), chunk.begin() + i, chunk.begin() + i + width);
    }
    offset += size;
  }
  throw std::runtime_error(
      "Returned string has no terminator within return_size");
}

Json ReturnValue(const SpoofFrame& frame, const std::string& type,
                 std::size_t size) {
  if (type == "void") return nullptr;
  if (type == "uint64") return frame.rax;
  if (type == "int64") {
    std::int64_t value = 0;
    std::memcpy(&value, &frame.rax, sizeof(value));
    return value;
  }
  if (type == "uint32") return static_cast<std::uint32_t>(frame.rax);
  if (type == "int32") return static_cast<std::int32_t>(frame.rax);
  if (type == "float") {
    float value = 0;
    std::memcpy(&value, frame.xmm0.data(), sizeof(value));
    if (!std::isfinite(value))
      throw std::runtime_error("Function returned a non-finite float");
    return value;
  }
  if (type == "double") {
    double value = 0;
    std::memcpy(&value, frame.xmm0.data(), sizeof(value));
    if (!std::isfinite(value))
      throw std::runtime_error("Function returned a non-finite double");
    return value;
  }
  if (type == "utf8" || type == "utf16") {
    if (frame.rax == 0) return nullptr;
    return ReadString(frame.rax, size, type == "utf16");
  }
  if (type == "bytes") {
    auto data = Memory().Read(frame.rax, size);
    return EncodeHex(data.data(), data.size());
  }
  throw std::invalid_argument("Unknown return_type");
}

}

struct SpoofCall::Invocation {
  SpoofFrame frame;
  std::uint64_t id = 0;
  HANDLE thread = nullptr;
  DWORD thread_id = 0;
  bool leased = false;
  std::string return_type;
  std::size_t return_size = 0;
  Json arguments;
  std::vector<std::unique_ptr<Buffer>> buffers;
  std::vector<std::size_t> buffer_indices;
  ~Invocation() {
    if (thread != nullptr) CloseHandle(thread);
  }
};

SpoofCall::SpoofCall() = default;

SpoofCall::~SpoofCall() {
  if (invocation_) {
    try {
      Refresh();
    } catch (...) {
    }
    if (invocation_->leased) invocation_.release();
  }
}

unsigned __stdcall SpoofCall::Run(void* parameter) {
  auto& invocation = *static_cast<Invocation*>(parameter);
  active_frame = &invocation.frame;
  RrmSpoofStub(active_frame);
  active_frame = nullptr;
  return 0;
}

bool SpoofCall::HandleException(EXCEPTION_POINTERS* info,
                                bool unhandled_breakpoint) {
  auto* frame = active_frame;
  if (frame == nullptr || frame->armed == 0) return false;
  auto address =
      reinterpret_cast<std::uint64_t>(info->ExceptionRecord->ExceptionAddress);
  bool breakpoint =
      info->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT;
  bool returning = breakpoint && address == frame->target &&
                   info->ContextRecord->Rsp == frame->return_rsp;
  if (breakpoint && !returning && !unhandled_breakpoint) return false;
  if (!returning) {
    frame->exception_code = info->ExceptionRecord->ExceptionCode;
    frame->exception_address = address;
    info->ContextRecord->Rax = 0;
    info->ContextRecord->Xmm0 = {};
  }
  frame->armed = 0;
  info->ContextRecord->Rbx = reinterpret_cast<std::uint64_t>(frame);
  info->ContextRecord->Rsp = frame->return_rsp;
  info->ContextRecord->Rip = frame->resume;
  info->ContextRecord->EFlags &= ~DWORD{0x400};
  return true;
}

void SpoofCall::Refresh() {
  if (!invocation_ || !invocation_->leased) return;
  DWORD state = WaitForSingleObject(invocation_->thread, 0);
  if (state == WAIT_TIMEOUT) return;
  CheckWindows(state == WAIT_OBJECT_0, "WaitForSingleObject(invocation)");
  ExceptionHooks::Instance().ReleaseInvocation(invocation_->frame.target);
  invocation_->leased = false;
  if (invocation_->frame.armed != 0) {
    invocation_->frame.exception_code = 0xe0000001;
    invocation_->frame.exception_address = invocation_->frame.target;
  }
}

Json SpoofCall::Invoke(const Json& args) {
  Refresh();
  if (invocation_ && invocation_->leased)
    throw std::runtime_error(
        "An invocation is already running; use get_invocation_result");
  if (invocation_)
    throw std::runtime_error(
        "Collect the previous invocation with get_invocation_result before "
        "starting another");
  Keys(args, {"address", "args", "return_type", "return_size", "timeout_ms"});
  auto job = std::make_unique<Invocation>();
  job->frame.target = UnsignedArgument(args, "address", 0x7fffffffffffULL);
  ValidateRange(job->frame.target, 1);
  job->return_type = args.at("return_type").get<std::string>();
  if (job->return_type != "uint64" && job->return_type != "int64" &&
      job->return_type != "uint32" && job->return_type != "int32" &&
      job->return_type != "float" && job->return_type != "double" &&
      job->return_type != "utf8" && job->return_type != "utf16" &&
      job->return_type != "bytes" && job->return_type != "void") {
    throw std::invalid_argument("Unknown return_type");
  }
  job->return_size = static_cast<std::size_t>(
      UnsignedArgument(args, "return_size", kMaxTransfer));
  if (job->return_size == 0)
    throw std::invalid_argument("return_size must be positive");
  auto timeout =
      static_cast<DWORD>(UnsignedArgument(args, "timeout_ms", 10000));
  const auto& arguments = args.at("args");
  if (!arguments.is_array() || arguments.size() > 16)
    throw std::invalid_argument("Provide at most 16 typed arguments");
  job->arguments = arguments;
  std::size_t total_size = 0;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const auto& argument = arguments[i];
    Keys(argument, {"type", "value", "format"});
    auto type = argument.at("type").get<std::string>();
    const auto& value = argument.at("value");
    if (type == "numeric") {
      job->frame.arguments[i] =
          Numeric(value, argument.value("format", std::string("uint64")));
    } else if (type == "decimal") {
      if (!value.is_number())
        throw std::invalid_argument("Decimal value must be a number");
      double number = value.get<double>();
      if (!std::isfinite(number))
        throw std::invalid_argument("Decimal value must be finite");
      auto format = argument.value("format", std::string("double"));
      if (format == "float") {
        float narrowed = static_cast<float>(number);
        if (!std::isfinite(narrowed))
          throw std::invalid_argument("Decimal exceeds float range");
        std::memcpy(&job->frame.arguments[i], &narrowed, sizeof(narrowed));
      } else if (format == "double") {
        std::memcpy(&job->frame.arguments[i], &number, sizeof(number));
      } else
        throw std::invalid_argument("Decimal format must be float or double");
    } else if (type == "string" || type == "bytes") {
      std::vector<std::uint8_t> data;
      if (type == "string")
        data = StringBytes(value.get<std::string>(),
                           argument.value("format", std::string("utf8")));
      else {
        if (argument.value("format", std::string("hex")) != "hex")
          throw std::invalid_argument("Byte format must be hex");
        auto text = value.get<std::string>();
        if (!text.empty()) data = DecodeHex(text);
        if (data.size() > 65536)
          throw std::invalid_argument("Byte argument exceeds 64 KiB");
      }
      total_size += data.size();
      if (total_size > kMaxTransfer)
        throw std::invalid_argument("Combined argument buffers exceed 1 MiB");
      auto buffer = std::make_unique<Buffer>(data);
      job->frame.arguments[i] = buffer->address();
      job->buffers.push_back(std::move(buffer));
      job->buffer_indices.push_back(i);
    } else
      throw std::invalid_argument(
          "Argument type must be numeric, decimal, string, or bytes");
  }
  PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy{};
  CheckWindows(GetProcessMitigationPolicy(GetCurrentProcess(),
                                          ProcessUserShadowStackPolicy, &policy,
                                          sizeof(policy)),
               "GetProcessMitigationPolicy(shadow stack)");
  if (policy.EnableUserShadowStack)
    throw std::runtime_error(
        "Self-address returns are incompatible with enabled hardware shadow "
        "stacks");
  ExceptionHooks::Instance().AcquireInvocation(job->frame.target);
  job->leased = true;
  job->id = next_id_++;
  unsigned thread_id = 0;
  job->thread = reinterpret_cast<HANDLE>(
      _beginthreadex(nullptr, 4 * 1024 * 1024, Run, job.get(), 0, &thread_id));
  job->thread_id = thread_id;
  if (job->thread == nullptr) {
    unsigned long error = 0;
    _get_doserrno(&error);
    if (error == 0) error = ERROR_NOT_ENOUGH_MEMORY;
    ExceptionHooks::Instance().ReleaseInvocation(job->frame.target);
    SetLastError(error);
    CheckWindows(FALSE, "_beginthreadex(invocation)");
  }
  invocation_ = std::move(job);
  return Collect(timeout);
}

Json SpoofCall::GetResult(std::uint64_t id, DWORD timeout) {
  if (!invocation_ || invocation_->id != id)
    throw std::invalid_argument("Invocation not found");
  return Collect(timeout);
}

Json SpoofCall::Collect(DWORD timeout) {
  DWORD state = WaitForSingleObject(invocation_->thread, timeout);
  if (state == WAIT_TIMEOUT)
    return {{"status", "running"}, {"invocation_id", invocation_->id}};
  CheckWindows(state == WAIT_OBJECT_0, "WaitForSingleObject(invocation)");
  Refresh();
  auto job = std::move(invocation_);
  if (job->frame.exception_code != 0) {
    throw std::runtime_error(
        "Native invocation fault: code " +
        std::to_string(job->frame.exception_code) + " at " +
        std::to_string(job->frame.exception_address) +
        "; native side effects and cleanup cannot be rolled back");
  }
  Json buffers = Json::array();
  for (std::size_t i = 0; i < job->buffers.size(); ++i) {
    auto data = job->buffers[i]->size() == 0
                    ? std::vector<std::uint8_t>{}
                    : Memory().Read(job->buffers[i]->address(),
                                    job->buffers[i]->size());
    buffers.push_back({{"index", job->buffer_indices[i]},
                       {"data", EncodeHex(data.data(), data.size())}});
  }
  return {
      {"status", "completed"},
      {"invocation_id", job->id},
      {"address", job->frame.target},
      {"return_address", job->frame.target},
      {"thread_id", job->thread_id},
      {"return_type", job->return_type},
      {"value", ReturnValue(job->frame, job->return_type, job->return_size)},
      {"rax", job->frame.rax},
      {"xmm0", EncodeHex(job->frame.xmm0.data(), 16)},
      {"buffers", buffers}};
}

}
