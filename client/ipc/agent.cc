#include "client/ipc/agent.h"

#include <sddl.h>

#include <atomic>
#include <limits>
#include <stdexcept>

#include "client/hooking/address_watchers.h"
#include "client/hooking/exception_hooks.h"
#include "client/ipc/protocol.h"
#include "client/memory/memory.h"
#include "client/spoof_call/spoof_call.h"

namespace rrm {
namespace {

std::atomic<bool> started{false};

nlohmann::json Execute(Memory& memory, SpoofCall& invoker,
                       const nlohmann::json& request) {
  const auto command = request.at("command").get<std::string>();
  const auto& args = request.at("arguments");
  invoker.Refresh();
  if (command == "invoke_function") return invoker.Invoke(args);
  if (command == "get_invocation_result") {
    return invoker.GetResult(
        UnsignedArgument(args, "invocation_id", UINT64_MAX),
        static_cast<DWORD>(UnsignedArgument(args, "timeout_ms", 10000)));
  }
  auto& watchers = AddressWatchers::Instance();
  if (command == "add_watcher") {
    return watchers.Add(
        UnsignedArgument(args, "address", UINT64_MAX),
        static_cast<std::size_t>(UnsignedArgument(args, "size", 4096)),
        args.at("access_type").get<std::string>(),
        static_cast<std::size_t>(UnsignedArgument(args, "capacity", 4096)));
  }
  if (command == "remove_watcher") {
    auto address = UnsignedArgument(args, "address", UINT64_MAX);
    watchers.Remove(address);
    return {{"address", address}, {"removed", true}};
  }
  if (command == "get_watcher_hits") {
    return watchers.GetHits(
        UnsignedArgument(args, "address", UINT64_MAX),
        UnsignedArgument(args, "after", UINT64_MAX),
        static_cast<std::size_t>(UnsignedArgument(args, "limit", 1024)));
  }
  auto& hooks = ExceptionHooks::Instance();
  if (command == "add_hook") {
    return hooks.Add(
        UnsignedArgument(args, "address", UINT64_MAX),
        static_cast<std::size_t>(UnsignedArgument(args, "capacity", 4096)),
        static_cast<std::size_t>(UnsignedArgument(args, "stack_size", 1024)));
  }
  if (command == "remove_hook") {
    auto address = UnsignedArgument(args, "address", UINT64_MAX);
    hooks.Remove(address);
    return {{"address", address}, {"removed", true}};
  }
  if (command == "get_hook_hits") {
    return hooks.GetHits(
        UnsignedArgument(args, "address", UINT64_MAX),
        UnsignedArgument(args, "after", UINT64_MAX),
        static_cast<std::size_t>(UnsignedArgument(args, "limit", 1024)));
  }
  if (command == "allocate_memory") {
    auto size =
        static_cast<std::size_t>(UnsignedArgument(args, "size", kMaxTransfer));
    auto protection = args.at("protection").get<std::string>();
    if (protection != "rw" && protection != "rwx") {
      throw std::invalid_argument("Protection must be rw or rwx");
    }
    return {{"address", memory.Allocate(size, protection == "rwx")},
            {"size", size},
            {"protection", protection}};
  }
  auto address = UnsignedArgument(args, "address", UINT64_MAX);
  if (command == "read_memory") {
    auto size =
        static_cast<std::size_t>(UnsignedArgument(args, "size", kMaxTransfer));
    auto data = memory.Read(address, size);
    return {{"address", address},
            {"size", data.size()},
            {"data", EncodeHex(data.data(), data.size())}};
  }
  if (command == "write_memory") {
    auto bytes = DecodeHex(args.at("data").get<std::string>());
    ValidateRange(address, bytes.size());
    if (watchers.Overlaps(address, bytes.size()))
      throw std::invalid_argument("Write overlaps a watched page");
    if (hooks.Overlaps(address, bytes.size())) {
      throw std::invalid_argument(
          "Write overlaps a hook or retained trampoline");
    }
    memory.Write(address, bytes);
    return {{"address", address}, {"written", bytes.size()}};
  }
  if (command == "free_memory") {
    if (watchers.Overlaps(address, memory.AllocationSize(address)))
      throw std::invalid_argument("Allocation contains a watched page");
    if (hooks.Overlaps(address, memory.AllocationSize(address))) {
      throw std::invalid_argument(
          "Allocation contains an active hook or retained trampoline");
    }
    memory.Free(address);
    return {{"address", address}, {"freed", true}};
  }
  throw std::invalid_argument("Unknown agent command");
}

DWORD WINAPI AgentThread(void* parameter) {
  HANDLE pipe = static_cast<HANDLE>(parameter);
  Memory memory;
  SpoofCall invoker;
  for (;;) {
    OVERLAPPED connection{};
    connection.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (connection.hEvent == nullptr) break;
    BOOL connected = ConnectNamedPipe(pipe, &connection);
    DWORD error = connected ? ERROR_SUCCESS : GetLastError();
    if (error == ERROR_IO_PENDING) {
      WaitForSingleObject(connection.hEvent, INFINITE);
      DWORD transferred = 0;
      connected = GetOverlappedResult(pipe, &connection, &transferred, FALSE);
    } else {
      connected = connected || error == ERROR_PIPE_CONNECTED;
    }
    CloseHandle(connection.hEvent);
    if (!connected) break;
    try {
      for (;;) {
        auto request = ReceiveMessage(pipe, INFINITE);
        nlohmann::json response;
        try {
          response = {{"result", Execute(memory, invoker, request)}};
        } catch (const std::exception& error_message) {
          response = {{"error", error_message.what()}};
        }
        SendMessage(pipe, response);
      }
    } catch (...) {
    }
    try {
      AddressWatchers::Instance().RemoveAll();
      ExceptionHooks::Instance().RemoveAll();
    } catch (...) {
    }
    DisconnectNamedPipe(pipe);
  }
  CloseHandle(pipe);
  started.store(false);
  return 0;
}

HANDLE CreateAgentPipe() {
  HANDLE token = nullptr;
  CheckWindows(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token),
               "OpenProcessToken");
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<std::uint8_t> buffer(size);
  BOOL result =
      GetTokenInformation(token, TokenUser, buffer.data(), size, &size);
  CloseHandle(token);
  CheckWindows(result, "GetTokenInformation");
  LPWSTR sid = nullptr;
  CheckWindows(
      ConvertSidToStringSidW(
          reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid),
      "ConvertSidToStringSidW");
  std::wstring sddl = L"D:P(A;;GA;;;" + std::wstring(sid) + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  CheckWindows(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                   sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr),
               "Create pipe security descriptor");
  SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  HANDLE pipe = CreateNamedPipeW(
      PipeName(GetCurrentProcessId()).c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      1, 65536, 65536, 0, &security);
  DWORD error = GetLastError();
  LocalFree(descriptor);
  SetLastError(error);
  CheckWindows(pipe != INVALID_HANDLE_VALUE, "CreateNamedPipeW");
  return pipe;
}

}
}

extern "C" DWORD WINAPI RrmStartAgent(void*) {
  bool expected = false;
  if (!rrm::started.compare_exchange_strong(expected, true))
    return ERROR_SUCCESS;
  HANDLE pipe = INVALID_HANDLE_VALUE;
  try {
    HMODULE pinned = nullptr;
    rrm::CheckWindows(
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(&RrmStartAgent), &pinned),
        "Pin agent DLL");
    pipe = rrm::CreateAgentPipe();
    HANDLE thread =
        CreateThread(nullptr, 0, rrm::AgentThread, pipe, 0, nullptr);
    rrm::CheckWindows(thread != nullptr, "CreateThread(agent)");
    CloseHandle(thread);
    return ERROR_SUCCESS;
  } catch (...) {
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    rrm::started.store(false);
    return ERROR_DLL_INIT_FAILED;
  }
}
