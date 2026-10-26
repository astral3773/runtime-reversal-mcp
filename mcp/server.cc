#include "mcp/server.h"

#include <fcntl.h>
#include <io.h>

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

#include "mcp/runtime_tools.h"

namespace rrm {
namespace {

using Json = nlohmann::json;

class RpcError : public std::runtime_error {
 public:
  RpcError(int code, const std::string& message)
      : std::runtime_error(message), code_(code) {}
  int code() const { return code_; }

 private:
  int code_;
};

std::wstring ToWide(const std::string& text) {
  if (text.empty() || text.find('\0') != std::string::npos) {
    throw std::invalid_argument("Name must be nonempty and contain no nulls");
  }
  int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                   static_cast<int>(text.size()), nullptr, 0);
  if (length == 0) {
    throw std::invalid_argument("Name must be valid UTF-8");
  }
  std::wstring result(length, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                      static_cast<int>(text.size()), result.data(), length);
  return result;
}

std::string ToUtf8(const std::wstring& text) {
  if (text.empty()) {
    return {};
  }
  int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                   static_cast<int>(text.size()), nullptr, 0,
                                   nullptr, nullptr);
  if (length == 0) {
    throw std::runtime_error("Cannot encode process information as UTF-8");
  }
  std::string result(length, '\0');
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                      static_cast<int>(text.size()), result.data(), length,
                      nullptr, nullptr);
  return result;
}

Json Serialize(const ModuleInfo& module) {
  return {{"name", ToUtf8(module.name)},
          {"path", ToUtf8(module.path)},
          {"base_address", module.base_address},
          {"size", module.size}};
}

Json ToolResult(const Json& value, bool error = false) {
  Json result = {
      {"content", Json::array({{{"type", "text"}, {"text", value.dump()}}})},
      {"isError", error}};
  if (!error) {
    result["structuredContent"] = value;
  }
  return result;
}

Json Tools() {
  Json name_schema = {{"type", "string"}, {"minLength", 1}};
  return Json::array(
      {{{"name", "attach_binary"},
        {"description",
         "Attach to a running process by executable name or PID. "
         "Provide exactly one. Duplicate names require a PID."},
        {"inputSchema",
         {{"type", "object"},
          {"properties",
           {{"name", name_schema},
            {"pid",
             {{"type", "integer"},
              {"minimum", 1},
              {"maximum", 4294967295ULL}}}}},
          {"oneOf",
           Json::array({{{"required", {"name"}}}, {{"required", {"pid"}}}})},
          {"additionalProperties", false}}}},
       {{"name", "get_all_modules"},
        {"description",
         "Get all modules in the attached process, including "
         "name, path, base address, and image size in bytes."},
        {"inputSchema",
         {{"type", "object"},
          {"properties", Json::object()},
          {"additionalProperties", false}}}},
       {{"name", "get_module_exports"},
        {"description",
         "List every export of a loaded module by case-insensitive filename. "
         "Returns exports with name (null for ordinal-only), ordinal, RVA, "
         "address and forwarder. Forwarded exports have a null address and "
         "a forwarder string; destinations are not resolved. Aliases are "
         "separate entries. Reads target memory without loading an agent."},
        {"inputSchema",
         {{"type", "object"},
          {"properties", {{"name", name_schema}}},
          {"required", {"name"}},
          {"additionalProperties", false}}}},
       {{"name", "get_module"},
        {"description",
         "Get an attached process module by case-insensitive "
         "filename, including its extension."},
        {"inputSchema",
         {{"type", "object"},
          {"properties", {{"name", name_schema}}},
          {"required", {"name"}},
          {"additionalProperties", false}}}}});
}

}

Json Server::CallTool(const Json& params) {
  if (!params.contains("name") || !params["name"].is_string()) {
    throw RpcError(-32602, "Tool name must be a string");
  }
  const auto name = params["name"].get<std::string>();
  if (name != "attach_binary" && name != "get_all_modules" &&
      name != "get_module" && name != "get_module_exports" &&
      !IsRuntimeTool(name)) {
    throw RpcError(-32602, "Unknown tool: " + name);
  }
  Json args = params.value("arguments", Json::object());
  if (!args.is_object()) {
    throw RpcError(-32602, "Tool arguments must be an object");
  }
  try {
    if (IsRuntimeTool(name))
      return ToolResult(CallRuntimeTool(client_, name, args));
    if (name == "attach_binary") {
      if (args.size() != 1 ||
          (!args.contains("name") && !args.contains("pid"))) {
        throw std::invalid_argument("Provide exactly one of name or pid");
      }
      ProcessInfo process;
      if (args.contains("pid")) {
        const auto& value = args["pid"];
        if (!value.is_number_integer() || value < 1 ||
            value > std::numeric_limits<std::uint32_t>::max()) {
          throw std::invalid_argument("PID must be a positive 32-bit integer");
        }
        process = client_.AttachBinary(value.get<std::uint32_t>());
      } else {
        process =
            client_.AttachBinary(ToWide(args.at("name").get<std::string>()));
      }
      return ToolResult({{"pid", process.pid},
                         {"name", ToUtf8(process.name)},
                         {"path", ToUtf8(process.path)}});
    }
    if (name == "get_module" || name == "get_module_exports") {
      if (args.size() != 1 || !args.contains("name")) {
        throw std::invalid_argument("Provide a module name");
      }
      if (name == "get_module_exports") {
        auto module_name = ToWide(args.at("name").get<std::string>());
        auto result = Json::parse(client_.GetModuleExports(module_name));
        result["module"] = Serialize(client_.GetModule(module_name));
        return ToolResult(result);
      }
      return ToolResult(Serialize(
          client_.GetModule(ToWide(args.at("name").get<std::string>()))));
    }
    if (!args.empty()) {
      throw std::invalid_argument("get_all_modules takes no arguments");
    }
    Json modules = Json::array();
    for (const auto& module : client_.GetAllModules()) {
      modules.push_back(Serialize(module));
    }
    return ToolResult({{"modules", modules}});
  } catch (const std::exception& error) {
    return ToolResult({{"error", error.what()}}, true);
  }
}

Json Server::Dispatch(const Json& request) {
  const auto method = request["method"].get<std::string>();
  Json params = request.value("params", Json::object());
  if (!params.is_object()) {
    throw RpcError(-32602, "Params must be an object");
  }
  if (method == "initialize") {
    if (!params.contains("protocolVersion") ||
        !params["protocolVersion"].is_string() ||
        !params.contains("capabilities") ||
        !params["capabilities"].is_object() || !params.contains("clientInfo") ||
        !params["clientInfo"].is_object()) {
      throw RpcError(-32602, "Invalid initialization parameters");
    }
    std::string version = params["protocolVersion"].get<std::string>();
    if (version != "2024-11-05" && version != "2025-03-26" &&
        version != "2025-06-18" && version != "2025-11-25") {
      version = "2025-11-25";
    }
    initialized_ = true;
    return {{"protocolVersion", version},
            {"capabilities", {{"tools", Json::object()}}},
            {"serverInfo", {{"name", "rrm"}, {"version", "0.1.0"}}}};
  }
  if (method == "ping") {
    return Json::object();
  }
  if (!initialized_) {
    throw RpcError(-32000, "Initialize the server first");
  }
  if (method == "tools/list") {
    auto tools = Tools();
    for (const auto& tool : RuntimeTools()) tools.push_back(tool);
    return {{"tools", tools}};
  }
  if (method == "tools/call") {
    return CallTool(params);
  }
  throw RpcError(-32601, "Method not found");
}

int Server::Run() {
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
  std::string line;
  while (std::getline(std::cin, line)) {
    Json id = nullptr;
    Json response;
    try {
      Json request = Json::parse(line);
      if (!request.is_object() || request.value("jsonrpc", Json()) != "2.0" ||
          !request.contains("method") || !request["method"].is_string() ||
          (request.contains("id") && !request["id"].is_string() &&
           !request["id"].is_number_integer())) {
        throw RpcError(-32600, "Invalid request");
      }
      if (!request.contains("id")) {
        continue;
      }
      id = request["id"];
      response = {
          {"jsonrpc", "2.0"}, {"id", id}, {"result", Dispatch(request)}};
    } catch (const Json::parse_error&) {
      response = {{"jsonrpc", "2.0"},
                  {"id", nullptr},
                  {"error", {{"code", -32700}, {"message", "Parse error"}}}};
    } catch (const RpcError& error) {
      response = {
          {"jsonrpc", "2.0"},
          {"id", id},
          {"error", {{"code", error.code()}, {"message", error.what()}}}};
    } catch (const std::exception& error) {
      response = {{"jsonrpc", "2.0"},
                  {"id", id},
                  {"error", {{"code", -32603}, {"message", error.what()}}}};
    }
    std::cout << response.dump(-1, ' ', false, Json::error_handler_t::replace)
              << '\n'
              << std::flush;
    if (!std::cout) {
      return 1;
    }
  }
  return std::cin.bad() ? 1 : 0;
}

}
