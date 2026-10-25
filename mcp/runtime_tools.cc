#include "mcp/runtime_tools.h"

#include <cstdint>
#include <stdexcept>

namespace rrm {
namespace {

using Json = nlohmann::json;

Json Integer(std::uint64_t minimum, std::uint64_t maximum) {
  return {{"type", "integer"}, {"minimum", minimum}, {"maximum", maximum}};
}

Json Tool(const char* name, const char* description, Json properties,
          Json required) {
  return {{"name", name},
          {"description", description},
          {"inputSchema",
           {{"type", "object"},
            {"properties", properties},
            {"required", required},
            {"additionalProperties", false}}}};
}

}

Json RuntimeTools() {
  auto address = Integer(65536, 0x7fffffffffffull);
  auto size = Integer(1, 1024 * 1024);
  auto capacity = Integer(1, 4096);
  capacity["default"] = 1024;
  auto stack = Integer(0, 1024);
  stack["default"] = 256;
  auto optional_address = Integer(0, 0x7fffffffffffull);
  optional_address["default"] = 0;
  auto after = Integer(0, UINT64_MAX);
  after["default"] = 0;
  auto limit = Integer(1, 1024);
  limit["default"] = 128;
  Json argument = {
      {"type", "object"},
      {"properties",
       {{"type",
         {{"type", "string"},
          {"enum", {"numeric", "decimal", "string", "bytes"}}}},
        {"value",
         {{"anyOf",
           Json::array({{{"type", "integer"}},
                        {{"type", "number"}},
                        {{"type", "string"}, {"maxLength", 131072}}})}}},
        {"format",
         {{"type", "string"},
          {"enum",
           {"uint8", "int8", "uint16", "int16", "uint32", "int32", "uint64",
            "int64", "float", "double", "utf8", "utf16", "hex"}}}}}},
      {"required", {"type", "value"}},
      {"additionalProperties", false}};
  Json arguments = {{"type", "array"},
                    {"items", argument},
                    {"maxItems", 16},
                    {"default", Json::array()}};
  Json return_type = {{"type", "string"},
                      {"enum",
                       {"uint64", "int64", "uint32", "int32", "float", "double",
                        "utf8", "utf16", "bytes", "void"}},
                      {"default", "uint64"}};
  auto return_size = size;
  return_size["default"] = 4096;
  auto timeout = Integer(0, 10000);
  timeout["default"] = 5000;
  auto poll_timeout = timeout;
  poll_timeout["default"] = 0;
  return Json::array(
      {Tool(
           "invoke_function",
           "Invoke a standard Windows x64 function on a new thread inside the "
           "attached process. "
           "The callee sees its own entry address as the return address; VEH "
           "handles continuation without single-stepping. "
           "args contains up to 16 typed values: numeric (default uint64; "
           "integer or decimal/0x string), "
           "decimal (default double, optional float), string (default utf8, "
           "optional utf16), bytes (hex). "
           "String/byte buffers are local to the target and valid only during "
           "the call; mutated bytes are returned in buffers. "
           "Use exact argument/return types; no structs by value, vectorcall, "
           "thread-affine functions or cross-thread C++ exception unwinding. "
           "return_size is the byte count for bytes or the maximum string read "
           "including its null terminator. "
           "Timeout returns status running and invocation_id; use "
           "get_invocation_result. Never forcibly terminates the native "
           "thread. "
           "Fault recovery cannot undo native side effects; fail-fast, process "
           "termination, and memory corruption can still kill the target. "
           "Enabled hardware shadow stacks are rejected.",
           {{"address", address},
            {"args", arguments},
            {"return_type", return_type},
            {"return_size", return_size},
            {"timeout_ms", timeout}},
           {"address"}),
       Tool("get_invocation_result",
            "Poll a pending native invocation. Returns running or the "
            "completed typed result and mutated argument buffers. "
            "Completed results are consumed once. Only one native invocation "
            "may be active per target.",
            {{"invocation_id", Integer(1, UINT64_MAX)},
             {"timeout_ms", poll_timeout}},
            {"invocation_id"}),
       Tool("add_hook",
            "Log execution at an x64 instruction address using VEH, without "
            "single-stepping or callbacks. "
            "Loads client.dll into the attached process. Captures Windows "
            "CONTEXT, XMM0..15 and a bounded stack snapshot. "
            "Buffer overwrites/contention are reported as dropped hits. "
            "Unsupported relocation returns an error. "
            "Maximum 128 installations per target lifetime. Exception delivery "
            "still has execution overhead.",
            {{"address", address},
             {"capacity", capacity},
             {"stack_size", stack}},
            {"address"}),
       Tool("remove_hook",
            "Restore the hooked byte and delete all captured hits for this "
            "hook. "
            "Small continuation trampolines remain allocated for in-flight "
            "threads until target exit.",
            {{"address", address}}, {"address"}),
       Tool("get_hook_hits",
            "Get retained hits for all active hooks or one address. Timestamps "
            "are Unix microseconds; "
            "XMM and stack data are raw little-endian hex. Includes registers "
            "and raw Windows CONTEXT, not AVX upper lanes. "
            "Use each hook's next_after cursor with its address for "
            "pagination; retrieval does not clear hits.",
            {{"address", optional_address}, {"after", after}, {"limit", limit}},
            Json::array()),
       Tool(
           "allocate_memory",
           "Allocate 1 byte to 1 MiB in the attached process. Defaults to "
           "read/write. "
           "Allocation persists until free_memory or process exit.",
           {{"size", size},
            {"protection",
             {{"type", "string"}, {"enum", {"rw", "rwx"}}, {"default", "rw"}}}},
           {"size"}),
       Tool("read_memory",
            "Read 1 byte to 1 MiB from the attached process as hex. Invalid, "
            "null, guarded and unreadable ranges return errors.",
            {{"address", address}, {"size", size}}, {"address", "size"}),
       Tool("write_memory",
            "Write hex bytes to committed writable target memory. Does not "
            "change page protections. "
            "Rejects null/invalid addresses and writes overlapping hooks. "
            "Concurrent target changes can cause partial writes, reported as "
            "errors.",
            {{"address", address},
             {"data",
              {{"type", "string"},
               {"minLength", 2},
               {"maxLength", 2097152},
               {"pattern", "^([0-9a-fA-F]{2})+$"}}}},
            {"address", "data"}),
       Tool("free_memory",
            "Release an allocation created by allocate_memory at its exact "
            "base address. "
            "Rejects allocations containing active hooks. Caller must ensure "
            "target threads no longer use the allocation.",
            {{"address", address}}, {"address"})});
}

bool IsRuntimeTool(const std::string& name) {
  for (const auto& tool : RuntimeTools()) {
    if (tool["name"] == name) return true;
  }
  return false;
}

Json CallRuntimeTool(Client& client, const std::string& name, Json args) {
  for (const auto& tool : RuntimeTools()) {
    if (tool["name"] != name) continue;
    const auto& schema = tool["inputSchema"];
    const auto& properties = schema["properties"];
    for (const auto& item : args.items()) {
      if (!properties.contains(item.key()))
        throw std::invalid_argument("Unknown argument: " + item.key());
    }
    for (const auto& item : properties.items()) {
      if (!args.contains(item.key()) && item.value().contains("default")) {
        args[item.key()] = item.value()["default"];
      }
    }
    for (const auto& required : schema["required"]) {
      if (!args.contains(required.get<std::string>()))
        throw std::invalid_argument("Missing required argument: " +
                                    required.get<std::string>());
    }
    for (const auto& item : args.items()) {
      const auto& rule = properties[item.key()];
      const auto& value = item.value();
      bool valid = true;
      if (rule["type"] == "integer") {
        valid = value.is_number_integer() &&
                (value.is_number_unsigned() || value.get<std::int64_t>() >= 0);
        if (valid) {
          auto number = value.get<std::uint64_t>();
          valid = number >= rule["minimum"].get<std::uint64_t>() &&
                  number <= rule["maximum"].get<std::uint64_t>();
        }
      } else if (rule["type"] == "array") {
        valid = value.is_array() &&
                value.size() <= rule["maxItems"].get<std::size_t>();
      } else {
        valid = value.is_string();
        if (valid && rule.contains("enum")) {
          valid = false;
          for (const auto& choice : rule["enum"])
            if (choice == value) valid = true;
        }
        if (valid && rule.contains("maxLength")) {
          auto length = value.get_ref<const std::string&>().size();
          valid = length >= rule["minLength"].get<std::size_t>() &&
                  length <= rule["maxLength"].get<std::size_t>();
          if (valid) {
            const auto& text = value.get_ref<const std::string&>();
            valid = text.size() % 2 == 0 &&
                    text.find_first_not_of("0123456789abcdefABCDEF") ==
                        std::string::npos;
          }
        }
      }
      if (!valid)
        throw std::invalid_argument("Invalid argument: " + item.key());
    }
    return Json::parse(
        client.Command(Json({{"command", name}, {"arguments", args}}).dump()));
  }
  throw std::invalid_argument("Unknown runtime tool");
}

}
