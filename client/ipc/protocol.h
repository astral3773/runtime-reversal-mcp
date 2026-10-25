#ifndef RRM_CLIENT_IPC_PROTOCOL_H_
#define RRM_CLIENT_IPC_PROTOCOL_H_

#include <windows.h>

#include <nlohmann/json.hpp>
#include <string>

namespace rrm {

constexpr DWORD kMaxMessage = 32 * 1024 * 1024;

std::wstring PipeName(DWORD pid);
void SendMessage(HANDLE pipe, const nlohmann::json& message);
nlohmann::json ReceiveMessage(HANDLE pipe, DWORD timeout = 30000);
std::uint64_t UnsignedArgument(const nlohmann::json& args, const char* name,
                               std::uint64_t maximum);
std::vector<std::uint8_t> DecodeHex(const std::string& text);
std::string EncodeHex(const void* data, std::size_t size);

}

#endif
