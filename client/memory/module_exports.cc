#include "client/memory/module_exports.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace rrm {
namespace {

class ImageReader {
 public:
  ImageReader(HANDLE process, const ModuleInfo& module)
      : process_(process), module_(module) {}

  void Read(std::uint64_t rva, void* output, std::size_t size) const {
    if (rva > module_.size || size > module_.size - rva ||
        module_.base_address > UINT64_MAX - rva)
      throw std::runtime_error("Export data lies outside the module image");
    if (!size) return;
    std::uint64_t cursor = module_.base_address + rva;
    std::size_t remaining = size;
    while (remaining) {
      MEMORY_BASIC_INFORMATION region{};
      if (!VirtualQueryEx(process_, reinterpret_cast<void*>(cursor), &region,
                          sizeof(region)))
        Fail("VirtualQueryEx(exports)");
      const auto protection = region.Protect & 0xff;
      if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD) ||
          (protection != PAGE_READONLY && protection != PAGE_READWRITE &&
           protection != PAGE_WRITECOPY && protection != PAGE_EXECUTE_READ &&
           protection != PAGE_EXECUTE_READWRITE &&
           protection != PAGE_EXECUTE_WRITECOPY))
        throw std::runtime_error("Export data is not readable");
      const auto region_offset =
          cursor - reinterpret_cast<std::uint64_t>(region.BaseAddress);
      const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(
          remaining, region.RegionSize - region_offset));
      SIZE_T copied = 0;
      if (!ReadProcessMemory(process_, reinterpret_cast<void*>(cursor), output,
                             chunk, &copied) ||
          copied != chunk)
        Fail("ReadProcessMemory(exports)");
      cursor += chunk;
      remaining -= chunk;
      output = static_cast<unsigned char*>(output) + chunk;
    }
  }

  template <typename T>
  T Object(std::uint64_t rva) const {
    T value{};
    Read(rva, &value, sizeof(value));
    return value;
  }

  template <typename T>
  std::vector<T> Table(DWORD rva, DWORD count) const {
    if (count > 131072)
      throw std::runtime_error("Export table exceeds supported size");
    if (count && !rva) throw std::runtime_error("Missing export table RVA");
    std::vector<T> result(count);
    Read(rva, result.data(), result.size() * sizeof(T));
    return result;
  }

  std::string String(std::uint64_t rva, std::uint64_t end) {
    if (!rva || rva >= end || end > module_.size)
      throw std::runtime_error("Invalid export string RVA");
    std::string result;
    while (result.size() < 4096 && rva < end) {
      char buffer[64];
      const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
          {sizeof(buffer), end - rva, 4096 - result.size(),
           4096 - (module_.base_address + rva) % 4096}));
      Read(rva, buffer, count);
      const auto* zero =
          static_cast<const char*>(std::memchr(buffer, 0, count));
      result.append(buffer,
                    zero ? static_cast<std::size_t>(zero - buffer) : count);
      if (zero) {
        string_bytes_ += result.size();
        if (string_bytes_ > 16 * 1024 * 1024)
          throw std::runtime_error("Export strings exceed supported size");
        return result;
      }
      rva += count;
    }
    throw std::runtime_error("Unterminated or oversized export string");
  }

 private:
  [[noreturn]] static void Fail(const char* operation) {
    throw std::system_error(static_cast<int>(GetLastError()),
                            std::system_category(), operation);
  }
  HANDLE process_;
  const ModuleInfo& module_;
  std::size_t string_bytes_ = 0;
};

}

nlohmann::json ReadModuleExports(HANDLE process, const ModuleInfo& module) {
  using Json = nlohmann::json;
  if (module.base_address > UINT64_MAX - module.size)
    throw std::runtime_error("Invalid module image range");
  ImageReader reader(process, module);
  const auto dos = reader.Object<IMAGE_DOS_HEADER>(0);
  if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
    throw std::runtime_error("Invalid PE DOS header");
  const auto nt = static_cast<std::uint64_t>(dos.e_lfanew);
  if (reader.Object<DWORD>(nt) != IMAGE_NT_SIGNATURE)
    throw std::runtime_error("Invalid PE signature");
  const auto file = reader.Object<IMAGE_FILE_HEADER>(nt + sizeof(DWORD));
  const auto optional = nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
  const auto magic = reader.Object<WORD>(optional);
  IMAGE_DATA_DIRECTORY directory{};
  if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    if (file.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
      throw std::runtime_error("Truncated PE64 optional header");
    const auto header = reader.Object<IMAGE_OPTIONAL_HEADER64>(optional);
    if (header.NumberOfRvaAndSizes) directory = header.DataDirectory[0];
  } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    if (file.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
      throw std::runtime_error("Truncated PE32 optional header");
    const auto header = reader.Object<IMAGE_OPTIONAL_HEADER32>(optional);
    if (header.NumberOfRvaAndSizes) directory = header.DataDirectory[0];
  } else {
    throw std::runtime_error("Unknown PE optional header format");
  }
  Json exports = Json::array();
  if (!directory.VirtualAddress && !directory.Size)
    return {{"exports", exports}, {"count", 0}};
  const auto end = std::uint64_t{directory.VirtualAddress} + directory.Size;
  if (!directory.VirtualAddress ||
      directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY) || end > module.size)
    throw std::runtime_error("Invalid PE export directory range");
  const auto table =
      reader.Object<IMAGE_EXPORT_DIRECTORY>(directory.VirtualAddress);
  const auto functions =
      reader.Table<DWORD>(table.AddressOfFunctions, table.NumberOfFunctions);
  const auto names =
      reader.Table<DWORD>(table.AddressOfNames, table.NumberOfNames);
  const auto ordinals =
      reader.Table<WORD>(table.AddressOfNameOrdinals, table.NumberOfNames);
  std::vector<std::vector<std::string>> aliases(functions.size());
  for (std::size_t i = 0; i < names.size(); ++i) {
    if (ordinals[i] >= functions.size())
      throw std::runtime_error(
          "Export name ordinal lies outside function table");
    aliases[ordinals[i]].push_back(reader.String(names[i], module.size));
  }
  for (std::size_t i = 0; i < functions.size(); ++i) {
    const auto rva = functions[i];
    if (!rva) continue;
    if (rva >= module.size || i > UINT32_MAX - table.Base)
      throw std::runtime_error("Invalid export RVA or ordinal");
    const bool forwarded = rva >= directory.VirtualAddress && rva < end;
    Json forwarder = forwarded ? Json(reader.String(rva, end)) : Json(nullptr);
    const Json address =
        forwarded ? Json(nullptr) : Json(module.base_address + rva);
    auto append = [&](Json name) {
      exports.push_back({{"name", std::move(name)},
                         {"ordinal", table.Base + i},
                         {"rva", rva},
                         {"address", address},
                         {"forwarder", forwarder}});
    };
    if (aliases[i].empty()) append(nullptr);
    for (const auto& name : aliases[i]) append(name);
  }
  const auto count = exports.size();
  return {{"exports", std::move(exports)}, {"count", count}};
}

}
