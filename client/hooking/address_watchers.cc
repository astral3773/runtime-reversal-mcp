#include "client/hooking/address_watchers.h"

#include <Zydis/Zydis.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cstring>
#include <new>
#include <stdexcept>
#include <vector>

#include "client/ipc/protocol.h"
#include "client/memory/memory.h"

namespace rrm {
namespace {

std::atomic<AddressWatchers*> instance{nullptr};
thread_local std::uint64_t pending_pages = 0;
thread_local bool owned_trap = false;

std::size_t CopyInstruction(std::uint64_t address, unsigned char* bytes) {
  std::size_t copied = 0;
  __try {
    for (; copied < ZYDIS_MAX_INSTRUCTION_LENGTH; ++copied) {
      bytes[copied] =
          reinterpret_cast<volatile unsigned char*>(address)[copied];
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
  return copied;
}

const char* AccessName(std::uint64_t access) {
  return access == 1 ? "write" : access == 8 ? "execute" : "read";
}

bool IsThreadStack(void* allocation_base) {
  struct ThreadInfo {
    LONG status;
    void* teb;
    CLIENT_ID id;
    ULONG_PTR affinity;
    LONG priority;
    LONG base_priority;
  };
  using QueryThread =
      LONG(NTAPI*)(HANDLE, THREADINFOCLASS, void*, ULONG, ULONG*);
  auto query = reinterpret_cast<QueryThread>(GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
  if (!query) throw std::runtime_error("Cannot validate thread stack ranges");
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  CheckWindows(snapshot != INVALID_HANDLE_VALUE, "Thread snapshot(watcher)");
  THREADENTRY32 entry{sizeof(THREADENTRY32)};
  bool stack = false;
  for (BOOL more = Thread32First(snapshot, &entry); more;
       more = Thread32Next(snapshot, &entry)) {
    if (entry.th32OwnerProcessID != GetCurrentProcessId()) continue;
    HANDLE thread =
        OpenThread(THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
    if (!thread) continue;
    ThreadInfo info{};
    const LONG status = query(thread, static_cast<THREADINFOCLASS>(0), &info,
                              sizeof(info), nullptr);
    CloseHandle(thread);
    NT_TIB tib{};
    SIZE_T copied = 0;
    if (status < 0 ||
        !ReadProcessMemory(GetCurrentProcess(), info.teb, &tib, sizeof(tib),
                           &copied) ||
        copied != sizeof(tib) || !tib.StackBase)
      continue;
    MEMORY_BASIC_INFORMATION region{};
    if (VirtualQuery(static_cast<unsigned char*>(tib.StackBase) - 1, &region,
                     sizeof(region)) &&
        region.AllocationBase == allocation_base) {
      stack = true;
      break;
    }
  }
  CloseHandle(snapshot);
  return stack;
}

}

struct AddressWatchers::Hit {
  std::uint64_t sequence = 0;
  std::uint64_t timestamp_us = 0;
  std::uint64_t address = 0;
  std::uint64_t instruction_address = 0;
  std::uint64_t access = 0;
  DWORD thread_id = 0;
  std::size_t byte_count = 0;
  unsigned char bytes[ZYDIS_MAX_INSTRUCTION_LENGTH]{};
};

struct AddressWatchers::Watcher {
  std::uint64_t address = 0;
  std::size_t size = 0;
  std::uint64_t page = 0;
  DWORD protection = 0;
  std::uint32_t access_mask = 0;
  std::size_t capacity = 0;
  Hit* hits = nullptr;
  std::atomic<bool> enabled{false};
  std::atomic<bool> armed{false};
  std::atomic<std::uint64_t> total{0};
  std::atomic<std::uint64_t> contention{0};
  std::atomic<std::uint64_t> overwritten{0};
  std::atomic<std::uint64_t> rearm_failures{0};
  std::atomic_flag busy = ATOMIC_FLAG_INIT;
};

AddressWatchers& AddressWatchers::Instance() {
  static AddressWatchers watchers;
  return watchers;
}

AddressWatchers::AddressWatchers() {
  SYSTEM_INFO system{};
  GetSystemInfo(&system);
  page_size_ = system.dwPageSize;
  instance.store(this);
  CheckWindows(AddVectoredExceptionHandler(1, HandleException) != nullptr,
               "AddVectoredExceptionHandler(watchers)");
}

nlohmann::json AddressWatchers::Add(std::uint64_t address, std::size_t size,
                                    const std::string& access,
                                    std::size_t capacity) {
  ValidateRange(address, size);
  if (capacity == 0 || capacity > 4096)
    throw std::invalid_argument("Capacity must be between 1 and 4096");
  std::uint32_t mask = access == "read"        ? 1
                       : access == "write"     ? 2
                       : access == "readwrite" ? 3
                                               : 0;
  if (mask == 0) throw std::invalid_argument("Unknown watcher access type");
  const auto page = address - address % page_size_;
  if (size > page_size_ || address + size > page + page_size_)
    throw std::invalid_argument("Watcher range must fit within one page");
  MEMORY_BASIC_INFORMATION region{};
  CheckWindows(VirtualQuery(reinterpret_cast<void*>(address), &region,
                            sizeof(region)) != 0,
               "VirtualQuery(watcher)");
  const DWORD base = region.Protect & 0xff;
  if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD) ||
      (base != PAGE_READONLY && base != PAGE_READWRITE &&
       base != PAGE_WRITECOPY))
    throw std::invalid_argument(
        "Watchers require committed readable non-executable non-guard pages");
  HMODULE module = nullptr;
  CheckWindows(
      GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCWSTR>(&Instance), &module),
      "Locate watcher module");
  if (region.AllocationBase == module || IsThreadStack(region.AllocationBase))
    throw std::invalid_argument("Cannot watch agent memory or thread stacks");
  for (const auto& entry : watchers_) {
    auto* existing = entry.load();
    if (existing == region.AllocationBase)
      throw std::invalid_argument("Cannot watch internal watcher storage");
    if (existing && existing->enabled.load() && existing->page == page)
      throw std::invalid_argument("A watcher already owns this page");
  }
  if (count_ == watchers_.size())
    throw std::runtime_error("Watcher installation lifetime limit reached");
  const std::size_t allocation_size = sizeof(Watcher) + capacity * sizeof(Hit);
  void* allocation = VirtualAlloc(nullptr, allocation_size,
                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  CheckWindows(allocation != nullptr, "VirtualAlloc(watcher)");
  auto* watcher = new (allocation) Watcher;
  watcher->address = address;
  watcher->size = size;
  watcher->page = page;
  watcher->protection = region.Protect;
  watcher->access_mask = mask;
  watcher->capacity = capacity;
  watcher->hits = reinterpret_cast<Hit*>(watcher + 1);
  for (std::size_t i = 0; i < capacity; ++i) new (watcher->hits + i) Hit;
  watchers_[count_++].store(watcher);
  AcquireSRWLockExclusive(&state_lock_);
  watcher->enabled.store(true);
  DWORD old = 0;
  BOOL result = VirtualProtect(reinterpret_cast<void*>(page), page_size_,
                               region.Protect | PAGE_GUARD, &old);
  const DWORD error = GetLastError();
  watcher->armed.store(result != FALSE);
  if (!result) watcher->enabled.store(false);
  ReleaseSRWLockExclusive(&state_lock_);
  SetLastError(error);
  CheckWindows(result, "VirtualProtect(add watcher)");
  return {{"address", address},    {"size", size},
          {"access_type", access}, {"capacity", capacity},
          {"page_address", page},  {"mode", "page_guard"},
          {"best_effort", true}};
}

void AddressWatchers::Capture(Watcher& watcher, EXCEPTION_POINTERS* info) {
  const auto access = info->ExceptionRecord->ExceptionInformation[0];
  const auto address = info->ExceptionRecord->ExceptionInformation[1];
  const auto mask = access == 0 ? 1u : access == 1 ? 2u : 0u;
  if (!(watcher.access_mask & mask) || address < watcher.address ||
      address - watcher.address >= watcher.size)
    return;
  if (watcher.busy.test_and_set(std::memory_order_acquire)) {
    watcher.contention.fetch_add(1);
    return;
  }
  if (!watcher.enabled.load()) {
    watcher.busy.clear(std::memory_order_release);
    return;
  }
  const auto sequence = watcher.total.fetch_add(1) + 1;
  auto& hit = watcher.hits[(sequence - 1) % watcher.capacity];
  if (hit.sequence) watcher.overwritten.fetch_add(1);
  hit = {};
  hit.sequence = sequence;
  FILETIME time{};
  GetSystemTimePreciseAsFileTime(&time);
  ULARGE_INTEGER ticks{};
  ticks.LowPart = time.dwLowDateTime;
  ticks.HighPart = time.dwHighDateTime;
  hit.timestamp_us = (ticks.QuadPart - 116444736000000000ULL) / 10;
  hit.thread_id = GetCurrentThreadId();
  hit.address = address;
  hit.access = access;
  hit.instruction_address = info->ContextRecord->Rip;
  hit.byte_count = CopyInstruction(hit.instruction_address, hit.bytes);
  watcher.busy.clear(std::memory_order_release);
}

void AddressWatchers::Rearm(CONTEXT& context) {
  const auto pages = pending_pages;
  pending_pages = 0;
  for (std::size_t i = 0; i < watchers_.size(); ++i) {
    if (!(pages & (std::uint64_t{1} << i))) continue;
    auto* watcher = watchers_[i].load();
    AcquireSRWLockExclusive(&state_lock_);
    if (watcher->enabled.load()) {
      MEMORY_BASIC_INFORMATION region{};
      DWORD old = 0;
      const bool valid = VirtualQuery(reinterpret_cast<void*>(watcher->page),
                                      &region, sizeof(region)) &&
                         region.State == MEM_COMMIT &&
                         (region.Protect & ~PAGE_GUARD) == watcher->protection;
      const BOOL result =
          valid &&
          VirtualProtect(reinterpret_cast<void*>(watcher->page), page_size_,
                         watcher->protection | PAGE_GUARD, &old);
      watcher->armed.store(result != FALSE);
      if (!result) {
        watcher->rearm_failures.fetch_add(1);
      }
    }
    ReleaseSRWLockExclusive(&state_lock_);
  }
  if (owned_trap) context.EFlags &= ~DWORD{0x100};
  owned_trap = false;
}

LONG WINAPI AddressWatchers::HandleException(EXCEPTION_POINTERS* info) {
  auto* owner = instance.load();
  if (!owner) return EXCEPTION_CONTINUE_SEARCH;
  const auto code = info->ExceptionRecord->ExceptionCode;
  if (code == EXCEPTION_GUARD_PAGE &&
      info->ExceptionRecord->NumberParameters >= 2) {
    const auto address = info->ExceptionRecord->ExceptionInformation[1];
    for (std::size_t i = owner->watchers_.size(); i > 0; --i) {
      auto* watcher = owner->watchers_[i - 1].load();
      if (!watcher || address < watcher->page ||
          address - watcher->page >= owner->page_size_)
        continue;
      watcher->armed.store(false);
      if (!watcher->enabled.load()) return EXCEPTION_CONTINUE_EXECUTION;
      Capture(*watcher, info);
      if (!pending_pages) owned_trap = !(info->ContextRecord->EFlags & 0x100);
      pending_pages |= std::uint64_t{1} << (i - 1);
      info->ContextRecord->EFlags |= 0x100;
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }
  if (pending_pages) {
    const bool ours = owned_trap;
    owner->Rearm(*info->ContextRecord);
    if (code == EXCEPTION_SINGLE_STEP && ours &&
        !(info->ContextRecord->Dr6 & 0xf)) {
      info->ContextRecord->Dr6 &= ~DWORD64{0x4000};
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

void AddressWatchers::Remove(std::uint64_t address) {
  Watcher* found = nullptr;
  for (auto& entry : watchers_) {
    auto* watcher = entry.load();
    if (watcher && watcher->address == address && watcher->enabled.load())
      found = watcher;
  }
  if (!found) throw std::invalid_argument("No active watcher at this address");
  AcquireSRWLockExclusive(&state_lock_);
  MEMORY_BASIC_INFORMATION region{};
  DWORD old = 0;
  BOOL result = TRUE;
  if (VirtualQuery(reinterpret_cast<void*>(found->page), &region,
                   sizeof(region)) &&
      region.State == MEM_COMMIT && (region.Protect & PAGE_GUARD) &&
      (region.Protect & ~PAGE_GUARD) == found->protection) {
    result = VirtualProtect(reinterpret_cast<void*>(found->page), page_size_,
                            found->protection, &old);
  }
  const DWORD error = GetLastError();
  if (result) {
    found->enabled.store(false);
    found->armed.store(false);
  }
  ReleaseSRWLockExclusive(&state_lock_);
  SetLastError(error);
  CheckWindows(result, "VirtualProtect(remove watcher)");
  while (found->busy.test_and_set(std::memory_order_acquire)) SwitchToThread();
  std::fill_n(found->hits, found->capacity, Hit{});
  found->busy.clear(std::memory_order_release);
}

void AddressWatchers::RemoveAll() {
  for (auto& entry : watchers_) {
    auto* watcher = entry.load();
    if (watcher && watcher->enabled.load()) Remove(watcher->address);
  }
}

bool AddressWatchers::Overlaps(std::uint64_t address, std::size_t size) const {
  for (const auto& entry : watchers_) {
    auto* watcher = entry.load();
    if (watcher && watcher->enabled.load() &&
        address < watcher->page + page_size_ && watcher->page < address + size)
      return true;
  }
  return false;
}

nlohmann::json AddressWatchers::GetHits(std::uint64_t address,
                                        std::uint64_t after,
                                        std::size_t limit) {
  if (!limit || limit > 1024) throw std::invalid_argument("Invalid hit limit");
  nlohmann::json hits = nlohmann::json::array();
  nlohmann::json summaries = nlohmann::json::array();
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
  for (auto& entry : watchers_) {
    auto* watcher = entry.load();
    if (!watcher || !watcher->enabled.load() ||
        (address && watcher->address != address))
      continue;
    std::vector<Hit> snapshot(watcher->capacity);
    while (watcher->busy.test_and_set(std::memory_order_acquire))
      SwitchToThread();
    std::copy_n(watcher->hits, watcher->capacity, snapshot.begin());
    const auto total = watcher->total.load();
    watcher->busy.clear(std::memory_order_release);
    std::sort(snapshot.begin(), snapshot.end(), [](const Hit& a, const Hit& b) {
      return a.sequence < b.sequence;
    });
    auto next = after;
    bool more = false;
    for (const auto& hit : snapshot) {
      if (!hit.sequence || hit.sequence <= after) continue;
      if (hits.size() >= limit) {
        more = true;
        break;
      }
      char text[256]{};
      ZydisDecodedInstruction instruction{};
      ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
      const bool decoded = ZYAN_SUCCESS(ZydisDecoderDecodeFull(
          &decoder, hit.bytes, hit.byte_count, &instruction, operands));
      if (decoded)
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                        instruction.operand_count_visible, text,
                                        sizeof(text), hit.instruction_address,
                                        nullptr);
      hits.push_back({{"watcher_address", watcher->address},
                      {"sequence", hit.sequence},
                      {"timestamp_us", hit.timestamp_us},
                      {"thread_id", hit.thread_id},
                      {"access_type", AccessName(hit.access)},
                      {"address", hit.address},
                      {"instruction_address", hit.instruction_address},
                      {"instruction", decoded ? text : "unavailable"},
                      {"instruction_bytes",
                       EncodeHex(hit.bytes, decoded ? instruction.length
                                                    : hit.byte_count)}});
      next = hit.sequence;
    }
    summaries.push_back({{"address", watcher->address},
                         {"size", watcher->size},
                         {"total_hits", total},
                         {"next_after", next},
                         {"has_more", more},
                         {"armed", watcher->armed.load()},
                         {"overwritten_hits", watcher->overwritten.load()},
                         {"contention_drops", watcher->contention.load()},
                         {"rearm_failures", watcher->rearm_failures.load()}});
  }
  if (address && summaries.empty())
    throw std::invalid_argument("No active watcher at this address");
  return {{"watchers", summaries}, {"hits", hits}, {"best_effort", true}};
}

}
