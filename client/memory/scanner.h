#ifndef RRM_CLIENT_MEMORY_SCANNER_H_
#define RRM_CLIENT_MEMORY_SCANNER_H_

#include <windows.h>

#include <nlohmann/json.hpp>

namespace rrm {

nlohmann::json ScanForValue(HANDLE process, const nlohmann::json& args);

}

#endif
