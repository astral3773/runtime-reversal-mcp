#ifndef RRM_CLIENT_MEMORY_MODULE_EXPORTS_H_
#define RRM_CLIENT_MEMORY_MODULE_EXPORTS_H_

#include <nlohmann/json.hpp>

#include "client/client.h"

namespace rrm {

nlohmann::json ReadModuleExports(HANDLE process, const ModuleInfo& module);

}

#endif
