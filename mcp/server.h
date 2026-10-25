#ifndef RRM_MCP_SERVER_H_
#define RRM_MCP_SERVER_H_

#include <nlohmann/json.hpp>

#include "client/client.h"

namespace rrm {

class Server {
 public:
  int Run();

 private:
  nlohmann::json Dispatch(const nlohmann::json& request);
  nlohmann::json CallTool(const nlohmann::json& params);

  Client client_;
  bool initialized_ = false;
};

}

#endif
