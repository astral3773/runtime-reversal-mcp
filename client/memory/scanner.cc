#include "client/memory/scanner.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "client/ipc/protocol.h"
#include "client/memory/memory.h"

namespace rrm {
namespace {

using Json = nlohmann::json;
constexpr std::uint64_t kChunk = 1024 * 1024;

struct Interval {
  std::uint64_t start;
  std::uint64_t end;
};

struct Job {
  std::uint64_t start;
  std::uint64_t end;
  std::uint64_t read_end;
};

struct Scan {
  HANDLE process;
  std::vector<Job> jobs;
  std::array<std::uint8_t, 8> pattern{};
  std::size_t width;
  std::uint64_t alignment;
  std::vector<std::uint64_t> results;
  std::atomic<std::size_t> next{0};
  std::atomic<std::size_t> found{0};
  std::atomic<std::uint64_t> read_bytes{0};
  std::atomic<std::uint64_t> unreadable_bytes{0};
  std::atomic<bool> stopped{false};
  std::atomic<bool> limited{false};
  std::atomic<bool> timed_out{false};
  std::atomic<bool> worker_failed{false};
  LONGLONG deadline;
};

bool Stop(Scan& scan) {
  if (scan.stopped.load(std::memory_order_relaxed)) return true;
  LARGE_INTEGER now{};
  QueryPerformanceCounter(&now);
  if (now.QuadPart >= scan.deadline) {
    scan.timed_out.store(true);
    scan.stopped.store(true);
    return true;
  }
  return false;
}

void Match(Scan& scan, const Job& job, const std::uint8_t* data,
           std::size_t size, std::uint64_t address) {
  if (size < scan.width) return;
  std::size_t offset = 0;
  std::size_t candidates = 0;
  while (offset + scan.width <= size) {
    const auto* candidate = static_cast<const std::uint8_t*>(std::memchr(
        data + offset, scan.pattern[0], size - scan.width + 1 - offset));
    if (candidate == nullptr) return;
    offset = static_cast<std::size_t>(candidate - data);
    auto match = address + offset;
    if (match >= job.end) return;
    if (match >= job.start && match % scan.alignment == 0 &&
        std::memcmp(candidate, scan.pattern.data(), scan.width) == 0) {
      auto index = scan.found.fetch_add(1, std::memory_order_relaxed);
      if (index >= scan.results.size()) {
        scan.limited.store(true);
        scan.stopped.store(true);
        return;
      }
      scan.results[index] = match;
    }
    ++offset;
    if ((++candidates & 4095) == 0 && Stop(scan)) return;
  }
}

void ScanJob(Scan& scan, const Job& job, std::vector<std::uint8_t>& buffer) {
  SIZE_T read = 0;
  auto size = static_cast<std::size_t>(job.read_end - job.start);
  if (ReadProcessMemory(scan.process, reinterpret_cast<void*>(job.start),
                        buffer.data(), size, &read) &&
      read == size) {
    scan.read_bytes.fetch_add(read, std::memory_order_relaxed);
    Match(scan, job, buffer.data(), read, job.start);
    return;
  }
  std::array<std::uint8_t, 4096 + 8> page{};
  std::size_t carry = 0;
  for (auto address = job.start; address < job.read_end && !Stop(scan);) {
    auto count = static_cast<std::size_t>((std::min)(
        job.read_end - address, std::uint64_t{4096} - (address & 4095)));
    read = 0;
    BOOL success =
        ReadProcessMemory(scan.process, reinterpret_cast<void*>(address),
                          page.data() + carry, count, &read);
    if (success && read == count) {
      scan.read_bytes.fetch_add(read, std::memory_order_relaxed);
      Match(scan, job, page.data(), carry + read, address - carry);
      auto retained = (std::min)(scan.width - 1, carry + read);
      std::memmove(page.data(), page.data() + carry + read - retained,
                   retained);
      carry = retained;
    } else {
      scan.unreadable_bytes.fetch_add(count, std::memory_order_relaxed);
      carry = 0;
    }
    address += count;
  }
}

DWORD WINAPI ScanThread(void* parameter) {
  auto& scan = *static_cast<Scan*>(parameter);
  try {
    std::vector<std::uint8_t> buffer(kChunk + 8);
    while (!Stop(scan)) {
      auto index = scan.next.fetch_add(1, std::memory_order_relaxed);
      if (index >= scan.jobs.size()) break;
      ScanJob(scan, scan.jobs[index], buffer);
    }
  } catch (...) {
    scan.worker_failed.store(true);
    scan.stopped.store(true);
  }
  return 0;
}

std::vector<DWORD> Flags(
    const Json& args, const char* key,
    std::initializer_list<std::pair<const char*, DWORD>> options) {
  const auto& values = args.at(key);
  if (!values.is_array() || values.empty() || values.size() > options.size()) {
    throw std::invalid_argument(std::string(key) +
                                " must be a nonempty filter array");
  }
  std::vector<DWORD> flags;
  for (const auto& value : values) {
    if (!value.is_string())
      throw std::invalid_argument(std::string(key) +
                                  " entries must be strings");
    bool found = false;
    for (const auto& option : options) {
      if (value == option.first) {
        if (std::find(flags.begin(), flags.end(), option.second) !=
            flags.end()) {
          throw std::invalid_argument(std::string(key) +
                                      " contains duplicates");
        }
        flags.push_back(option.second);
        found = true;
        break;
      }
    }
    if (!found)
      throw std::invalid_argument(std::string("Unknown ") + key + " filter");
  }
  return flags;
}

bool Contains(const std::vector<DWORD>& flags, DWORD value) {
  return std::find(flags.begin(), flags.end(), value) != flags.end();
}

std::uint64_t Value(const Json& value) {
  if (value.is_number_integer()) {
    if (!value.is_number_unsigned() && value.get<std::int64_t>() < 0) {
      throw std::invalid_argument("Scan value must be unsigned");
    }
    return value.get<std::uint64_t>();
  }
  if (!value.is_string())
    throw std::invalid_argument(
        "Scan value must be an integer or integer string");
  auto text = value.get<std::string>();
  bool hex = text.rfind("0x", 0) == 0 || text.rfind("0X", 0) == 0;
  auto digits = hex ? text.substr(2) : text;
  if (digits.empty() || digits.size() > 20 ||
      digits.find_first_not_of(hex ? "0123456789abcdefABCDEF" : "0123456789") !=
          std::string::npos) {
    throw std::invalid_argument(
        "Invalid scan value; prefix hexadecimal addresses with 0x");
  }
  return std::stoull(digits, nullptr, hex ? 16 : 10);
}

}

Json ScanForValue(HANDLE process, const Json& args) {
  LARGE_INTEGER began{}, frequency{};
  CheckWindows(QueryPerformanceFrequency(&frequency),
               "QueryPerformanceFrequency(scan)");
  CheckWindows(QueryPerformanceCounter(&began),
               "QueryPerformanceCounter(scan)");
  Scan scan{};
  scan.process = process;
  auto value = Value(args.at("value"));
  scan.width = static_cast<std::size_t>(UnsignedArgument(args, "width", 8));
  if (scan.width != 1 && scan.width != 2 && scan.width != 4 &&
      scan.width != 8) {
    throw std::invalid_argument("width must be 1, 2, 4, or 8 bytes");
  }
  if (scan.width < 8 && value >= (std::uint64_t{1} << (scan.width * 8))) {
    throw std::invalid_argument("Scan value does not fit width");
  }
  std::memcpy(scan.pattern.data(), &value, scan.width);
  scan.alignment = UnsignedArgument(args, "alignment", 4096);
  if (scan.alignment == 0)
    throw std::invalid_argument("alignment must be positive");
  auto capacity =
      static_cast<std::size_t>(UnsignedArgument(args, "max_results", 1000000));
  if (capacity == 0)
    throw std::invalid_argument("max_results must be positive");
  scan.results.resize(capacity);
  auto timeout = UnsignedArgument(args, "timeout_ms", 20000);
  if (timeout == 0) throw std::invalid_argument("timeout_ms must be positive");
  scan.deadline = began.QuadPart +
                  static_cast<LONGLONG>(timeout) * frequency.QuadPart / 1000;
  auto types = Flags(
      args, "mem_types",
      {{"private", MEM_PRIVATE}, {"mapped", MEM_MAPPED}, {"image", MEM_IMAGE}});
  auto states = Flags(args, "states",
                      {{"committed", MEM_COMMIT},
                       {"reserved", MEM_RESERVE},
                       {"free", MEM_FREE}});
  auto protections = Flags(args, "protections",
                           {{"readonly", PAGE_READONLY},
                            {"readwrite", PAGE_READWRITE},
                            {"writecopy", PAGE_WRITECOPY},
                            {"execute_read", PAGE_EXECUTE_READ},
                            {"execute_readwrite", PAGE_EXECUTE_READWRITE},
                            {"execute_writecopy", PAGE_EXECUTE_WRITECOPY},
                            {"execute", PAGE_EXECUTE},
                            {"noaccess", PAGE_NOACCESS}});
  SYSTEM_INFO system{};
  GetSystemInfo(&system);
  auto minimum =
      reinterpret_cast<std::uint64_t>(system.lpMinimumApplicationAddress);
  auto maximum =
      reinterpret_cast<std::uint64_t>(system.lpMaximumApplicationAddress) + 1;
  auto start = UnsignedArgument(args, "start", maximum);
  auto end = UnsignedArgument(args, "end", maximum);
  start = start == 0 ? minimum : start;
  end = end == 0 ? maximum : end;
  if (start < minimum || start >= end)
    throw std::invalid_argument("Invalid scan interval; end is exclusive");
  std::vector<Interval> intervals;
  std::uint64_t eligible_bytes = 0;
  std::size_t regions = 0;
  for (auto address = start; address < end && !Stop(scan);) {
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQueryEx(process, reinterpret_cast<void*>(address), &info,
                        sizeof(info))) {
      CheckWindows(FALSE, "VirtualQueryEx(scan)");
    }
    auto region_end =
        reinterpret_cast<std::uint64_t>(info.BaseAddress) + info.RegionSize;
    if (region_end <= address)
      throw std::runtime_error("VirtualQueryEx returned an invalid region");
    region_end = (std::min)(region_end, end);
    auto protection = info.Protect & 0xff;
    bool readable =
        protection == PAGE_READONLY || protection == PAGE_READWRITE ||
        protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
        protection == PAGE_EXECUTE_READWRITE ||
        protection == PAGE_EXECUTE_WRITECOPY;
    if (Contains(types, info.Type) && Contains(states, info.State) &&
        Contains(protections, protection) && info.State == MEM_COMMIT &&
        readable && !(info.Protect & PAGE_GUARD)) {
      ++regions;
      eligible_bytes += region_end - address;
      if (!intervals.empty() && intervals.back().end == address)
        intervals.back().end = region_end;
      else
        intervals.push_back({address, region_end});
    }
    address = region_end;
  }
  for (const auto& interval : intervals) {
    for (auto address = interval.start; address < interval.end;
         address += kChunk) {
      if (Stop(scan)) break;
      if (scan.jobs.size() >= 1000000)
        throw std::runtime_error(
            "Scan exceeds one million chunks; narrow the interval");
      auto job_end = (std::min)(address + kChunk, interval.end);
      scan.jobs.push_back({address, job_end,
                           (std::min)(job_end + scan.width - 1, interval.end)});
    }
  }
  auto workers =
      static_cast<std::size_t>(UnsignedArgument(args, "threads", 64));
  if (workers == 0)
    workers = (std::min)(static_cast<std::size_t>(system.dwNumberOfProcessors),
                         std::size_t{16});
  workers = (std::min)(workers, scan.jobs.size());
  std::vector<HANDLE> threads;
  threads.reserve(workers);
  DWORD create_error = ERROR_SUCCESS;
  for (std::size_t i = 0; i < workers && !Stop(scan); ++i) {
    HANDLE thread = CreateThread(nullptr, 0, ScanThread, &scan, 0, nullptr);
    if (thread == nullptr) {
      create_error = GetLastError();
      scan.stopped.store(true);
      break;
    }
    threads.push_back(thread);
  }
  for (HANDLE thread : threads) {
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
  }
  if (create_error != ERROR_SUCCESS) {
    SetLastError(create_error);
    CheckWindows(FALSE, "CreateThread(scan)");
  }
  if (scan.worker_failed.load()) throw std::runtime_error("Scan worker failed");
  scan.results.resize((std::min)(scan.found.load(), capacity));
  std::sort(scan.results.begin(), scan.results.end());
  bool alive = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
  LARGE_INTEGER finished{};
  QueryPerformanceCounter(&finished);
  auto elapsed_us =
      (finished.QuadPart - began.QuadPart) * 1000000 / frequency.QuadPart;
  return {{"addresses", scan.results},
          {"count", scan.results.size()},
          {"complete",
           !scan.stopped.load() && scan.unreadable_bytes.load() == 0 && alive},
          {"limit_reached", scan.limited.load()},
          {"timed_out", scan.timed_out.load()},
          {"target_exited", !alive},
          {"eligible_regions", regions},
          {"eligible_bytes", eligible_bytes},
          {"bytes_read", scan.read_bytes.load()},
          {"unreadable_bytes", scan.unreadable_bytes.load()},
          {"threads", threads.size()},
          {"elapsed_ms", static_cast<double>(elapsed_us) / 1000.0}};
}

}
