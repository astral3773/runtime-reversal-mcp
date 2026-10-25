#ifndef RRM_MCP_RUNTIME_TOOLS_H_
#define RRM_MCP_RUNTIME_TOOLS_H_

#include <nlohmann/json.hpp>

#include "client/client.h"

namespace rrm {

nlohmann::json RuntimeTools();
bool IsRuntimeTool(const std::string& name);
nlohmann::json CallRuntimeTool(Client& client, const std::string& name,
                               nlohmann::json args);

}

#endif
