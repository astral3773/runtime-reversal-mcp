#include "client/client.h"

#include <tlhelp32.h>

#include <memory>
#include <stdexcept>
#include <system_error>

#include "client/ipc/agent.h"
#include "client/ipc/protocol.h"
#include "client/memory/memory.h"
#include "client/memory/module_exports.h"
#include "client/memory/scanner.h"

namespace rrm {
namespace {

struct HandleCloser {
  void operator()(void* handle) const {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
      CloseHandle(handle);
    }
  }
};

using UniqueHandle = std::unique_ptr<void, HandleCloser>;

[[noreturn]] void ThrowWindowsError(const char* operation) {
  throw std::system_error(static_cast<int>(GetLastError()),
                          std::system_category(), operation);
}

bool EqualName(const std::wstring& left, const std::wstring& right) {
  return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) ==
         CSTR_EQUAL;
}

UniqueHandle TakeSnapshot(DWORD flags, DWORD pid) {
  for (int attempt = 0; attempt < 8; ++attempt) {
    HANDLE handle = CreateToolhelp32Snapshot(flags, pid);
    if (handle != INVALID_HANDLE_VALUE) {
      return UniqueHandle(handle);
    }
    if (GetLastError() != ERROR_BAD_LENGTH) {
      ThrowWindowsError("CreateToolhelp32Snapshot");
    }
  }
  ThrowWindowsError("CreateToolhelp32Snapshot");
}

}

Client::~Client() {
  if (pipe_ != INVALID_HANDLE_VALUE) CloseHandle(pipe_);
  if (process_ != nullptr) {
    CloseHandle(process_);
  }
}

ProcessInfo Client::AttachBinary(std::uint32_t pid) {
  if (pid == 0) {
    throw std::invalid_argument("PID must be greater than zero");
  }
  UniqueHandle process(
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
  if (!process) {
    ThrowWindowsError("OpenProcess");
  }
  std::wstring path(32768, L'\0');
  DWORD length = static_cast<DWORD>(path.size());
  if (!QueryFullProcessImageNameW(process.get(), 0, path.data(), &length)) {
    ThrowWindowsError("QueryFullProcessImageNameW");
  }
  path.resize(length);
  ProcessInfo info{pid, path.substr(path.find_last_of(L"\\/") + 1), path};
  if (WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT) {
    throw std::runtime_error("Process has exited");
  }
  if (pipe_ != INVALID_HANDLE_VALUE) {
    CloseHandle(pipe_);
    pipe_ = INVALID_HANDLE_VALUE;
  }
  if (process_ != nullptr) {
    CloseHandle(process_);
  }
  process_ = process.release();
  pid_ = pid;
  return info;
}

ProcessInfo Client::AttachBinary(const std::wstring& name) {
  if (name.empty()) {
    throw std::invalid_argument("Process name must not be empty");
  }
  auto snapshot = TakeSnapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (!Process32FirstW(snapshot.get(), &entry)) {
    ThrowWindowsError("Process32FirstW");
  }
  DWORD pid = 0;
  do {
    if (EqualName(entry.szExeFile, name)) {
      if (pid != 0) {
        throw std::runtime_error("Multiple processes match; attach by PID");
      }
      pid = entry.th32ProcessID;
    }
  } while (Process32NextW(snapshot.get(), &entry));
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    ThrowWindowsError("Process32NextW");
  }
  if (pid == 0) {
    throw std::runtime_error("Process not found");
  }
  return AttachBinary(pid);
}

std::vector<ModuleInfo> Client::GetAllModules() const {
  if (process_ == nullptr) {
    throw std::runtime_error("Attach a process first");
  }
  DWORD state = WaitForSingleObject(process_, 0);
  if (state == WAIT_FAILED) {
    ThrowWindowsError("WaitForSingleObject");
  }
  if (state != WAIT_TIMEOUT) {
    throw std::runtime_error("Attached process has exited");
  }
  auto snapshot = TakeSnapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (!Module32FirstW(snapshot.get(), &entry)) {
    ThrowWindowsError("Module32FirstW");
  }
  std::vector<ModuleInfo> modules;
  do {
    modules.push_back({entry.szModule, entry.szExePath,
                       reinterpret_cast<std::uint64_t>(entry.modBaseAddr),
                       entry.modBaseSize});
  } while (Module32NextW(snapshot.get(), &entry));
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    ThrowWindowsError("Module32NextW");
  }
  return modules;
}

ModuleInfo Client::GetModule(const std::wstring& name) const {
  if (name.empty()) {
    throw std::invalid_argument("Module name must not be empty");
  }
  for (const auto& module : GetAllModules()) {
    if (EqualName(module.name, name)) {
      return module;
    }
  }
  throw std::runtime_error("Module not found");
}

std::string Client::GetModuleExports(const std::wstring& name) const {
  const auto module = GetModule(name);
  UniqueHandle process(OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid_));
  if (!process) ThrowWindowsError("OpenProcess(exports)");
  FILETIME original{}, current{}, exit{}, kernel{}, user{};
  CheckWindows(GetProcessTimes(process_, &original, &exit, &kernel, &user),
               "GetProcessTimes(attached)");
  CheckWindows(GetProcessTimes(process.get(), &current, &exit, &kernel, &user),
               "GetProcessTimes(exports)");
  if (CompareFileTime(&original, &current) != 0)
    throw std::runtime_error("Attached process identity changed");
  return ReadModuleExports(process.get(), module).dump();
}

std::string Client::ScanForValue(const std::string& args) const {
  if (process_ == nullptr || WaitForSingleObject(process_, 0) != WAIT_TIMEOUT) {
    throw std::runtime_error("Attach a running process first");
  }
  UniqueHandle process(OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid_));
  if (!process) ThrowWindowsError("OpenProcess(scan)");
  FILETIME original{}, current{}, exit{}, kernel{}, user{};
  CheckWindows(GetProcessTimes(process_, &original, &exit, &kernel, &user),
               "GetProcessTimes(attached)");
  CheckWindows(GetProcessTimes(process.get(), &current, &exit, &kernel, &user),
               "GetProcessTimes(scan)");
  if (CompareFileTime(&original, &current) != 0)
    throw std::runtime_error("Attached process identity changed");
  return rrm::ScanForValue(process.get(), nlohmann::json::parse(args)).dump();
}

void Client::ConnectAgent() {
  if (process_ == nullptr || WaitForSingleObject(process_, 0) != WAIT_TIMEOUT) {
    throw std::runtime_error("Attach a running process first");
  }
  if (pipe_ != INVALID_HANDLE_VALUE) return;
  USHORT machine = 0;
  USHORT native = 0;
  CheckWindows(IsWow64Process2(process_, &machine, &native), "IsWow64Process2");
  if (machine != IMAGE_FILE_MACHINE_UNKNOWN ||
      native != IMAGE_FILE_MACHINE_AMD64) {
    throw std::runtime_error(
        "The in-process agent requires a native x64 target");
  }
  auto try_connect = [&]() -> bool {
    HANDLE pipe =
        CreateFileW(PipeName(pid_).c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                    nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      if (error == ERROR_FILE_NOT_FOUND) return false;
      if (error == ERROR_PIPE_BUSY)
        throw std::runtime_error("Target already has an agent connection");
      ThrowWindowsError("CreateFileW(agent pipe)");
    }
    ULONG server_pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &server_pid) || server_pid != pid_) {
      CloseHandle(pipe);
      throw std::runtime_error(
          "Agent pipe does not belong to the attached target");
    }
    pipe_ = pipe;
    return true;
  };
  if (try_connect()) return;
  HMODULE module = nullptr;
  CheckWindows(
      GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCWSTR>(&RrmStartAgent), &module),
      "GetModuleHandleExW(client)");
  std::wstring dll_path(32768, L'\0');
  DWORD path_length = GetModuleFileNameW(module, dll_path.data(),
                                         static_cast<DWORD>(dll_path.size()));
  CheckWindows(path_length != 0 && path_length < dll_path.size(),
               "GetModuleFileNameW(client)");
  dll_path.resize(path_length);
  auto offset = reinterpret_cast<std::uint64_t>(&RrmStartAgent) -
                reinterpret_cast<std::uint64_t>(module);
  if (pid_ == GetCurrentProcessId()) {
    if (RrmStartAgent(nullptr) != ERROR_SUCCESS) {
      throw std::runtime_error("Cannot start the in-process agent");
    }
  } else {
    UniqueHandle target(
        OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                        PROCESS_VM_READ | SYNCHRONIZE,
                    FALSE, pid_));
    if (!target) ThrowWindowsError("OpenProcess(agent)");
    auto remote_thread = [&](std::uint64_t entry, void* argument) -> DWORD {
      UniqueHandle thread(
          CreateRemoteThread(target.get(), nullptr, 0,
                             reinterpret_cast<LPTHREAD_START_ROUTINE>(entry),
                             argument, 0, nullptr));
      if (!thread) ThrowWindowsError("CreateRemoteThread(agent)");
      DWORD wait = WaitForSingleObject(thread.get(), 10000);
      if (wait != WAIT_OBJECT_0) {
        throw std::runtime_error(
            "Agent initialization timed out; target thread was left running");
      }
      DWORD code = 0;
      CheckWindows(GetExitCodeThread(thread.get(), &code),
                   "GetExitCodeThread(agent)");
      return code;
    };
    auto find_dll = [&]() -> std::uint64_t {
      for (const auto& item : GetAllModules()) {
        if (EqualName(item.path, dll_path)) return item.base_address;
        if (EqualName(item.name,
                      dll_path.substr(dll_path.find_last_of(L"\\/") + 1))) {
          throw std::runtime_error(
              "A different client DLL is already loaded in the target");
        }
      }
      return 0;
    };
    auto remote_base = find_dll();
    if (remote_base == 0) {
      auto loader =
          GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
      CheckWindows(loader != nullptr, "GetProcAddress(LoadLibraryW)");
      HMODULE loader_module = nullptr;
      CheckWindows(
          GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                             reinterpret_cast<LPCWSTR>(loader), &loader_module),
          "GetModuleHandleExW(LoadLibraryW)");
      wchar_t loader_path[32768]{};
      CheckWindows(GetModuleFileNameW(loader_module, loader_path, 32768) != 0,
                   "GetModuleFileNameW(LoadLibraryW)");
      std::wstring loader_name(loader_path);
      loader_name = loader_name.substr(loader_name.find_last_of(L"\\/") + 1);
      auto remote_loader = GetModule(loader_name).base_address +
                           reinterpret_cast<std::uint64_t>(loader) -
                           reinterpret_cast<std::uint64_t>(loader_module);
      auto size = (dll_path.size() + 1) * sizeof(wchar_t);
      void* remote_path =
          VirtualAllocEx(target.get(), nullptr, size, MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE);
      CheckWindows(remote_path != nullptr, "VirtualAllocEx(DLL path)");
      SIZE_T written = 0;
      if (!WriteProcessMemory(target.get(), remote_path, dll_path.c_str(), size,
                              &written) ||
          written != size) {
        DWORD error = GetLastError();
        VirtualFreeEx(target.get(), remote_path, 0, MEM_RELEASE);
        SetLastError(error);
        ThrowWindowsError("WriteProcessMemory(DLL path)");
      }
      remote_thread(remote_loader, remote_path);
      CheckWindows(VirtualFreeEx(target.get(), remote_path, 0, MEM_RELEASE),
                   "VirtualFreeEx(DLL path)");
      remote_base = find_dll();
      if (remote_base == 0)
        throw std::runtime_error("Target could not load client.dll");
    }
    if (remote_thread(remote_base + offset, nullptr) != ERROR_SUCCESS) {
      throw std::runtime_error("Target could not start the agent");
    }
  }
  for (int attempt = 0; attempt < 100; ++attempt) {
    if (try_connect()) return;
    Sleep(20);
  }
  throw std::runtime_error("Agent pipe was not created");
}

std::string Client::Command(const std::string& request) {
  ConnectAgent();
  nlohmann::json response;
  try {
    SendMessage(pipe_, nlohmann::json::parse(request));
    response = ReceiveMessage(pipe_);
  } catch (...) {
    CloseHandle(pipe_);
    pipe_ = INVALID_HANDLE_VALUE;
    throw;
  }
  if (response.contains("error")) {
    throw std::runtime_error(response["error"].get<std::string>());
  }
  return response.at("result").dump();
}

}
