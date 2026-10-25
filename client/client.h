#ifndef RRM_CLIENT_CLIENT_H_
#define RRM_CLIENT_CLIENT_H_

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#ifdef RRM_CLIENT_EXPORTS
#define RRM_CLIENT_API __declspec(dllexport)
#else
#define RRM_CLIENT_API __declspec(dllimport)
#endif

namespace rrm {

struct ModuleInfo {
  std::wstring name;
  std::wstring path;
  std::uint64_t base_address;
  std::uint32_t size;
};

struct ProcessInfo {
  std::uint32_t pid;
  std::wstring name;
  std::wstring path;
};

class RRM_CLIENT_API Client {
 public:
  Client() = default;
  ~Client();
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  ProcessInfo AttachBinary(std::uint32_t pid);
  ProcessInfo AttachBinary(const std::wstring& name);
  std::vector<ModuleInfo> GetAllModules() const;
  ModuleInfo GetModule(const std::wstring& name) const;
  std::string Command(const std::string& request);
  std::string ScanForValue(const std::string& args) const;

 private:
  HANDLE process_ = nullptr;
  std::uint32_t pid_ = 0;
  HANDLE pipe_ = INVALID_HANDLE_VALUE;
  void ConnectAgent();
};

}

#endif
