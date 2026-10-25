#include "client/ipc/protocol.h"

#include <algorithm>
#include <stdexcept>

#include "client/memory/memory.h"

namespace rrm {
namespace {

void Transfer(HANDLE pipe, void* data, DWORD size, bool writing,
              DWORD timeout = 10000) {
  auto* bytes = static_cast<char*>(data);
  while (size != 0) {
    DWORD transferred = 0;
    OVERLAPPED operation{};
    operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    CheckWindows(operation.hEvent != nullptr, "CreateEventW(pipe)");
    BOOL result = writing
                      ? WriteFile(pipe, bytes, size, &transferred, &operation)
                      : ReadFile(pipe, bytes, size, &transferred, &operation);
    DWORD error = result ? ERROR_SUCCESS : GetLastError();
    if (!result && error == ERROR_IO_PENDING) {
      DWORD wait = WaitForSingleObject(operation.hEvent, timeout);
      if (wait != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &operation);
        GetOverlappedResult(pipe, &operation, &transferred, TRUE);
        CloseHandle(operation.hEvent);
        throw std::runtime_error("Agent pipe operation timed out");
      }
      result = GetOverlappedResult(pipe, &operation, &transferred, FALSE);
      error = result ? ERROR_SUCCESS : GetLastError();
    }
    CloseHandle(operation.hEvent);
    SetLastError(error);
    CheckWindows(result, writing ? "WriteFile(pipe)" : "ReadFile(pipe)");
    if (transferred == 0) {
      throw std::runtime_error("Agent pipe disconnected");
    }
    size -= transferred;
    bytes += transferred;
  }
}

}

std::wstring PipeName(DWORD pid) {
  HMODULE module = nullptr;
  CheckWindows(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   reinterpret_cast<LPCWSTR>(&PipeName), &module),
               "GetModuleHandleExW(pipe namespace)");
  wchar_t path[32768]{};
  CheckWindows(GetModuleFileNameW(module, path, 32768) != 0,
               "GetModuleFileNameW(pipe namespace)");
  std::wstring name(path);
  name = name.substr(name.find_last_of(L"\\/") + 1);
  return L"\\\\.\\pipe\\rrm-" + name + L"-" + std::to_wstring(pid);
}

void SendMessage(HANDLE pipe, const nlohmann::json& message) {
  auto data =
      message.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  if (data.empty() || data.size() > kMaxMessage) {
    throw std::runtime_error(
        "Agent response exceeds message limit; request fewer hits");
  }
  DWORD size = static_cast<DWORD>(data.size());
  Transfer(pipe, &size, sizeof(size), true);
  Transfer(pipe, data.data(), size, true);
}

nlohmann::json ReceiveMessage(HANDLE pipe, DWORD timeout) {
  DWORD size = 0;
  Transfer(pipe, &size, sizeof(size), false, timeout);
  if (size == 0 || size > kMaxMessage) {
    throw std::runtime_error("Invalid agent message length");
  }
  std::string data(size, '\0');
  Transfer(pipe, data.data(), size, false);
  return nlohmann::json::parse(data);
}

std::uint64_t UnsignedArgument(const nlohmann::json& args, const char* name,
                               std::uint64_t maximum) {
  const auto& value = args.at(name);
  if (!value.is_number_integer() ||
      (value.is_number_integer() && !value.is_number_unsigned() &&
       value.get<std::int64_t>() < 0) ||
      value.get<std::uint64_t>() > maximum) {
    throw std::invalid_argument(std::string(name) +
                                " must be an unsigned integer within range");
  }
  return value.get<std::uint64_t>();
}

std::string EncodeHex(const void* data, std::size_t size) {
  constexpr char digits[] = "0123456789abcdef";
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::string text(size * 2, '\0');
  for (std::size_t i = 0; i < size; ++i) {
    text[i * 2] = digits[bytes[i] >> 4];
    text[i * 2 + 1] = digits[bytes[i] & 15];
  }
  return text;
}

std::vector<std::uint8_t> DecodeHex(const std::string& text) {
  if (text.empty() || text.size() % 2 != 0 || text.size() / 2 > kMaxTransfer) {
    throw std::invalid_argument(
        "Data must be an even-length hex string of 1 byte to 1 MiB");
  }
  auto digit = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    throw std::invalid_argument("Data contains a non-hex character");
  };
  std::vector<std::uint8_t> bytes(text.size() / 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>((digit(text[i * 2]) << 4) |
                                         digit(text[i * 2 + 1]));
  }
  return bytes;
}

}
