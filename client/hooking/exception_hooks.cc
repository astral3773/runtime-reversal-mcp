#include "client/hooking/exception_hooks.h"

#include <Zydis/Zydis.h>
#include <intrin.h>

#include <algorithm>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <vector>

#include "client/ipc/protocol.h"
#include "client/memory/memory.h"
#include "client/spoof_call/spoof_call.h"

namespace rrm {
namespace {

thread_local bool capturing = false;
ExceptionHooks* instance = nullptr;

std::size_t CopyStack(void* output, const void* input, std::size_t size) {
  std::size_t copied = 0;
  __try {
    auto* destination = static_cast<volatile unsigned char*>(output);
    auto* source = static_cast<const volatile unsigned char*>(input);
    for (; copied < size; ++copied) {
      destination[copied] = source[copied];
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
  return copied;
}

void PatchByte(std::uint64_t address, std::uint8_t value) {
  auto* pointer = reinterpret_cast<void*>(address);
  DWORD protection = 0;
  CheckWindows(VirtualProtect(pointer, 1, PAGE_EXECUTE_READWRITE, &protection),
               "VirtualProtect(hook)");
  SIZE_T written = 0;
  BOOL patched =
      WriteProcessMemory(GetCurrentProcess(), pointer, &value, 1, &written);
  DWORD patch_error = patched ? ERROR_SUCCESS : GetLastError();
  DWORD unused = 0;
  BOOL restored = VirtualProtect(pointer, 1, protection, &unused);
  DWORD restore_error = restored ? ERROR_SUCCESS : GetLastError();
  BOOL flushed = FlushInstructionCache(GetCurrentProcess(), pointer, 1);
  if (!patched || written != 1) {
    SetLastError(patch_error ? patch_error : ERROR_PARTIAL_COPY);
    CheckWindows(FALSE, "WriteProcessMemory(hook)");
  }
  if (!restored) {
    SetLastError(restore_error);
    CheckWindows(FALSE, "VirtualProtect(restore hook protection)");
  }
  CheckWindows(flushed, "FlushInstructionCache(hook)");
}

void* AllocateNear(std::uint64_t address) {
  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  auto granularity = static_cast<std::uint64_t>(info.dwAllocationGranularity);
  auto aligned = address & ~(granularity - 1);
  auto maximum =
      reinterpret_cast<std::uint64_t>(info.lpMaximumApplicationAddress);
  for (std::uint64_t distance = granularity; distance < 0x70000000;
       distance += granularity) {
    for (int direction : {-1, 1}) {
      std::uint64_t candidate =
          direction < 0 ? aligned - distance : aligned + distance;
      if ((direction < 0 && aligned < distance) || candidate < granularity ||
          candidate > maximum - granularity) {
        continue;
      }
      MEMORY_BASIC_INFORMATION region{};
      if (VirtualQuery(reinterpret_cast<void*>(candidate), &region,
                       sizeof(region)) &&
          region.State == MEM_FREE) {
        if (void* page =
                VirtualAlloc(reinterpret_cast<void*>(candidate), 4096,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
          return page;
        }
      }
    }
  }
  throw std::runtime_error("Cannot allocate a nearby instruction trampoline");
}

std::vector<std::uint8_t> InstructionBytes(std::uint64_t address) {
  MEMORY_BASIC_INFORMATION region{};
  CheckWindows(VirtualQuery(reinterpret_cast<void*>(address), &region,
                            sizeof(region)) != 0,
               "VirtualQuery(hook)");
  HMODULE own_module = nullptr;
  CheckWindows(GetModuleHandleExW(
                   GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                   reinterpret_cast<LPCWSTR>(&InstructionBytes), &own_module),
               "GetModuleHandleExW(hook)");
  if (region.AllocationBase == own_module ||
      region.AllocationBase == GetModuleHandleW(L"ntdll.dll")) {
    throw std::invalid_argument(
        "Cannot hook the agent or ntdll exception-dispatch machinery");
  }
  auto protection = region.Protect & 0xff;
  if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD) ||
      (protection != PAGE_EXECUTE_READ &&
       protection != PAGE_EXECUTE_READWRITE &&
       protection != PAGE_EXECUTE_WRITECOPY)) {
    throw std::invalid_argument(
        "Hook address must be readable executable memory");
  }
  auto end =
      reinterpret_cast<std::uint64_t>(region.BaseAddress) + region.RegionSize;
  return Memory().Read(
      address,
      static_cast<std::size_t>(std::min<std::uint64_t>(15, end - address)));
}

void* MakeTrampoline(std::uint64_t address,
                     const std::vector<std::uint8_t>& bytes,
                     std::size_t* original_length) {
  ZydisDecoder decoder{};
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisDecodedInstruction instruction{};
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
  if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes.data(), bytes.size(),
                                           &instruction, operands))) {
    throw std::invalid_argument(
        "Cannot decode the instruction at the hook address");
  }
  if (instruction.mnemonic == ZYDIS_MNEMONIC_INT3 ||
      instruction.meta.category == ZYDIS_CATEGORY_CALL ||
      instruction.meta.category == ZYDIS_CATEGORY_INTERRUPT ||
      instruction.meta.category == ZYDIS_CATEGORY_SYSCALL ||
      instruction.meta.category == ZYDIS_CATEGORY_SYSRET) {
    throw std::invalid_argument(
        "Instruction cannot be transparently relocated; hook its entry or next "
        "instruction");
  }
  ZydisEncoderRequest request{};
  if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
          &instruction, operands, instruction.operand_count_visible,
          &request))) {
    throw std::invalid_argument(
        "Instruction is unsupported by the relocation encoder");
  }
  for (std::size_t i = 0; i < instruction.operand_count_visible; ++i) {
    const auto& operand = operands[i];
    bool relative_memory = operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                           (operand.mem.base == ZYDIS_REGISTER_RIP ||
                            operand.mem.base == ZYDIS_REGISTER_EIP);
    bool relative_immediate =
        operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative;
    if (relative_memory || relative_immediate) {
      ZyanU64 target = 0;
      if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operand,
                                                 address, &target))) {
        throw std::invalid_argument(
            "Cannot calculate the instruction operand address");
      }
      if (relative_memory)
        request.operands[i].mem.displacement = static_cast<ZyanI64>(target);
      if (relative_immediate) {
        request.operands[i].imm.u = target;
        request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
        request.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
      }
    }
  }
  void* page = AllocateNear(address);
  try {
    std::uint8_t encoded[64]{};
    ZyanUSize length = 32;
    if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstructionAbsolute(
            &request, encoded, &length, reinterpret_cast<ZyanU64>(page)))) {
      throw std::invalid_argument(
          "Instruction cannot be relocated to the nearby trampoline");
    }
    encoded[length] = 0xff;
    encoded[length + 1] = 0x25;
    auto continuation = address + instruction.length;
    std::memcpy(encoded + length + 6, &continuation, sizeof(continuation));
    std::memcpy(page, encoded, length + 14);
    DWORD previous = 0;
    CheckWindows(VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &previous),
                 "VirtualProtect(trampoline)");
    CheckWindows(FlushInstructionCache(GetCurrentProcess(), page, length + 14),
                 "FlushInstructionCache(trampoline)");
    *original_length = instruction.length;
    return page;
  } catch (...) {
    VirtualFree(page, 0, MEM_RELEASE);
    throw;
  }
}

nlohmann::json Registers(const CONTEXT& c) {
  return {{"rax", c.Rax},     {"rbx", c.Rbx},
          {"rcx", c.Rcx},     {"rdx", c.Rdx},
          {"rsi", c.Rsi},     {"rdi", c.Rdi},
          {"rbp", c.Rbp},     {"rsp", c.Rsp},
          {"r8", c.R8},       {"r9", c.R9},
          {"r10", c.R10},     {"r11", c.R11},
          {"r12", c.R12},     {"r13", c.R13},
          {"r14", c.R14},     {"r15", c.R15},
          {"rip", c.Rip},     {"rflags", c.EFlags},
          {"mxcsr", c.MxCsr}, {"cs", c.SegCs},
          {"ds", c.SegDs},    {"es", c.SegEs},
          {"fs", c.SegFs},    {"gs", c.SegGs},
          {"ss", c.SegSs},    {"dr0", c.Dr0},
          {"dr1", c.Dr1},     {"dr2", c.Dr2},
          {"dr3", c.Dr3},     {"dr6", c.Dr6},
          {"dr7", c.Dr7},     {"context_flags", c.ContextFlags}};
}

}

struct ExceptionHooks::Hit {
  std::uint64_t sequence = 0;
  std::uint64_t timestamp_us = 0;
  DWORD thread_id = 0;
  CONTEXT context{};
  std::uint64_t stack_base = 0;
  std::uint64_t stack_limit = 0;
  std::size_t stack_size = 0;
  std::array<std::uint8_t, 1024> stack{};
};

struct ExceptionHooks::HitSlot {
  std::atomic_flag busy = ATOMIC_FLAG_INIT;
  Hit hit;
};

struct ExceptionHooks::Hook {
  std::uint64_t address = 0;
  std::uint8_t original = 0;
  std::size_t length = 0;
  void* trampoline = nullptr;
  std::size_t capacity = 0;
  std::size_t stack_size = 0;
  bool logging = true;
  unsigned invocation_users = 0;
  std::array<std::uint8_t, 15> instruction{};
  std::unique_ptr<HitSlot[]> hits;
  std::atomic<bool> enabled{false};
  std::atomic<std::uint64_t> next{0};
  std::atomic<std::uint64_t> dropped{0};
  std::atomic<unsigned> readers{0};
};

ExceptionHooks& ExceptionHooks::Instance() {
  static auto* hooks = new ExceptionHooks;
  return *hooks;
}

ExceptionHooks::ExceptionHooks() {
  instance = this;
  handler_ = AddVectoredExceptionHandler(1, HandleException);
  CheckWindows(handler_ != nullptr, "AddVectoredExceptionHandler");
}

nlohmann::json ExceptionHooks::Add(std::uint64_t address, std::size_t capacity,
                                   std::size_t stack_size, bool logging) {
  ValidateRange(address, 1);
  if (capacity == 0 || capacity > 4096 || stack_size > 1024) {
    throw std::invalid_argument(
        "Capacity must be 1..4096 and stack_size 0..1024");
  }
  if (count_ == hooks_.size()) {
    throw std::runtime_error(
        "Agent lifetime hook limit reached (128); retired trampolines remain "
        "valid for in-flight threads");
  }
  auto bytes = InstructionBytes(address);
  if (bytes[0] == 0xcc) {
    throw std::invalid_argument("Address already contains a breakpoint");
  }
  auto hook = std::make_unique<Hook>();
  hook->address = address;
  hook->original = bytes[0];
  hook->capacity = capacity;
  hook->stack_size = stack_size;
  hook->logging = logging;
  hook->hits = std::make_unique<HitSlot[]>(capacity);
  hook->trampoline = MakeTrampoline(address, bytes, &hook->length);
  std::copy_n(bytes.begin(), hook->length, hook->instruction.begin());
  if (Overlaps(address, hook->length)) {
    VirtualFree(hook->trampoline, 0, MEM_RELEASE);
    throw std::invalid_argument("Hook overlaps an existing hook or trampoline");
  }
  Hook* published = hook.release();
  hooks_[count_++].store(published, std::memory_order_release);
  published->enabled.store(true);
  try {
    PatchByte(address, 0xcc);
  } catch (...) {
    published->enabled.store(false);
    try {
      PatchByte(address, published->original);
    } catch (...) {
    }
    while (published->readers.load() != 0) Sleep(0);
    published->hits.reset();
    throw;
  }
  return {{"address", address},
          {"capacity", capacity},
          {"stack_size", stack_size},
          {"instruction_size", published->length}};
}

void ExceptionHooks::Capture(Hook& hook, const CONTEXT& context) {
  hook.readers.fetch_add(1);
  if (!hook.enabled.load()) {
    hook.readers.fetch_sub(1);
    return;
  }
  auto sequence = hook.next.fetch_add(1) + 1;
  if (capturing) {
    hook.dropped.fetch_add(1);
    hook.readers.fetch_sub(1);
    return;
  }
  capturing = true;
  auto& slot = hook.hits[(sequence - 1) % hook.capacity];
  if (slot.busy.test_and_set(std::memory_order_acquire)) {
    hook.dropped.fetch_add(1);
  } else if (slot.hit.sequence >= sequence) {
    hook.dropped.fetch_add(1);
    slot.busy.clear(std::memory_order_release);
  } else {
    if (slot.hit.sequence != 0) hook.dropped.fetch_add(1);
    auto& hit = slot.hit;
    hit.sequence = sequence;
    FILETIME time{};
    GetSystemTimePreciseAsFileTime(&time);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = time.dwLowDateTime;
    ticks.HighPart = time.dwHighDateTime;
    hit.timestamp_us = ticks.QuadPart / 10 - 11644473600000000ULL;
    hit.thread_id = static_cast<DWORD>(__readgsqword(0x48));
    hit.context = context;
    hit.context.Rip = hook.address;
    hit.stack_base = __readgsqword(0x08);
    hit.stack_limit = __readgsqword(0x10);
    hit.stack_size = 0;
    if (context.Rsp >= hit.stack_limit && context.Rsp < hit.stack_base) {
      auto size = static_cast<std::size_t>(std::min<std::uint64_t>(
          hook.stack_size, hit.stack_base - context.Rsp));
      hit.stack_size = CopyStack(hit.stack.data(),
                                 reinterpret_cast<void*>(context.Rsp), size);
    }
    slot.busy.clear(std::memory_order_release);
  }
  capturing = false;
  hook.readers.fetch_sub(1);
}

LONG WINAPI ExceptionHooks::HandleException(EXCEPTION_POINTERS* info) {
  if (!capturing && SpoofCall::HandleException(info)) {
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  if (info->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  auto address =
      reinterpret_cast<std::uint64_t>(info->ExceptionRecord->ExceptionAddress);
  Hook* retired = nullptr;
  for (std::size_t i = instance->hooks_.size(); i > 0; --i) {
    Hook* hook = instance->hooks_[i - 1].load(std::memory_order_acquire);
    if (hook != nullptr && hook->address == address) {
      if (!hook->enabled.load()) {
        if (retired == nullptr) retired = hook;
        continue;
      }
      if (hook->logging) Capture(*hook, *info->ContextRecord);
      info->ContextRecord->Rip = reinterpret_cast<DWORD64>(hook->trampoline);
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }
  if (retired != nullptr) {
    info->ContextRecord->Rip = reinterpret_cast<DWORD64>(retired->trampoline);
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  if (!capturing && SpoofCall::HandleException(info, true)) {
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

void ExceptionHooks::AcquireInvocation(std::uint64_t address) {
  ValidateRange(address, 1);
  for (auto& entry : hooks_) {
    Hook* hook = entry.load();
    if (hook != nullptr && hook->address == address && hook->enabled.load()) {
      ++hook->invocation_users;
      return;
    }
  }
  auto bytes = InstructionBytes(address);
  for (auto& entry : hooks_) {
    Hook* hook = entry.load();
    if (hook != nullptr && hook->address == address && !hook->logging &&
        !hook->enabled.load() && bytes.size() >= hook->length &&
        std::equal(hook->instruction.begin(),
                   hook->instruction.begin() + hook->length, bytes.begin())) {
      hook->enabled.store(true);
      try {
        PatchByte(address, 0xcc);
      } catch (...) {
        hook->enabled.store(false);
        try {
          PatchByte(address, hook->original);
        } catch (...) {
        }
        throw;
      }
      hook->invocation_users = 1;
      return;
    }
  }
  Add(address, 1, 0, false);
  for (auto& entry : hooks_) {
    Hook* hook = entry.load();
    if (hook != nullptr && hook->address == address && hook->enabled.load()) {
      hook->invocation_users = 1;
      return;
    }
  }
}

void ExceptionHooks::ReleaseInvocation(std::uint64_t address) {
  for (auto& entry : hooks_) {
    Hook* hook = entry.load();
    if (hook != nullptr && hook->address == address && hook->enabled.load() &&
        hook->invocation_users != 0) {
      --hook->invocation_users;
      if (hook->invocation_users == 0 && !hook->logging) Remove(address);
      return;
    }
  }
  throw std::runtime_error("Invocation hook lease was lost");
}

void ExceptionHooks::Remove(std::uint64_t address) {
  for (auto& entry : hooks_) {
    Hook* hook = entry.load();
    if (hook != nullptr && hook->address == address && hook->enabled.load()) {
      if (hook->invocation_users != 0)
        throw std::runtime_error("Hook is reserved by a running invocation");
      PatchByte(address, hook->original);
      hook->enabled.store(false);
      while (hook->readers.load() != 0) Sleep(0);
      hook->hits.reset();
      hook->next.store(0);
      hook->dropped.store(0);
      return;
    }
  }
  throw std::invalid_argument("Hook not found");
}

void ExceptionHooks::RemoveAll() {
  std::exception_ptr failure;
  for (auto& entry : hooks_) {
    Hook* hook = entry.load();
    if (hook != nullptr && hook->enabled.load() &&
        hook->invocation_users == 0) {
      try {
        Remove(hook->address);
      } catch (...) {
        if (!failure) failure = std::current_exception();
      }
    }
  }
  if (failure) std::rethrow_exception(failure);
}

bool ExceptionHooks::Overlaps(std::uint64_t address, std::size_t size) const {
  for (const auto& entry : hooks_) {
    Hook* hook = entry.load();
    if (hook == nullptr) continue;
    auto trampoline = reinterpret_cast<std::uint64_t>(hook->trampoline);
    if ((address < trampoline + 4096 && trampoline < address + size) ||
        (hook->enabled.load() && address < hook->address + hook->length &&
         hook->address < address + size))
      return true;
  }
  return false;
}

nlohmann::json ExceptionHooks::GetHits(std::uint64_t address,
                                       std::uint64_t after,
                                       std::size_t limit) const {
  nlohmann::json hits = nlohmann::json::array();
  nlohmann::json summaries = nlohmann::json::array();
  bool found = address == 0;
  for (const auto& entry : hooks_) {
    Hook* hook = entry.load();
    if (hook == nullptr || !hook->enabled.load() || !hook->logging ||
        (address != 0 && hook->address != address))
      continue;
    found = true;
    std::vector<Hit> retained;
    retained.reserve(hook->capacity);
    for (std::size_t i = 0; i < hook->capacity; ++i) {
      auto& slot = hook->hits[i];
      while (slot.busy.test_and_set(std::memory_order_acquire)) Sleep(0);
      if (slot.hit.sequence > after) retained.push_back(slot.hit);
      slot.busy.clear(std::memory_order_release);
    }
    std::sort(retained.begin(), retained.end(), [](const Hit& a, const Hit& b) {
      return a.sequence < b.sequence;
    });
    std::uint64_t cursor = after;
    std::size_t returned = 0;
    for (const auto& hit : retained) {
      if (hits.size() == limit) break;
      nlohmann::json xmm = nlohmann::json::object();
      for (int i = 0; i < 16; ++i) {
        xmm["xmm" + std::to_string(i)] =
            EncodeHex(&hit.context.FltSave.XmmRegisters[i], 16);
      }
      hits.push_back(
          {{"address", hook->address},
           {"sequence", hit.sequence},
           {"timestamp_us", hit.timestamp_us},
           {"thread_id", hit.thread_id},
           {"registers", Registers(hit.context)},
           {"xmm", xmm},
           {"context_hex", EncodeHex(&hit.context, sizeof(hit.context))},
           {"stack",
            {{"address", hit.context.Rsp},
             {"base", hit.stack_base},
             {"limit", hit.stack_limit},
             {"size", hit.stack_size},
             {"requested_size", hook->stack_size},
             {"data", EncodeHex(hit.stack.data(), hit.stack_size)}}}});
      cursor = hit.sequence;
      ++returned;
    }
    summaries.push_back({{"address", hook->address},
                         {"total_hits", hook->next.load()},
                         {"dropped_hits", hook->dropped.load()},
                         {"capacity", hook->capacity},
                         {"next_after", cursor},
                         {"has_more", retained.size() > returned}});
  }
  if (!found) throw std::invalid_argument("Hook not found");
  return {{"hits", hits},
          {"hooks", summaries},
          {"timestamp_unit", "unix_microseconds"}};
}

}
