@ -0,0 +1,55 @@
# runtime-reversal-mcp

A Windows x64 MCP server that lets your LLM agent inspect and interact with a running process.

## Features

- Attach by process name or PID.
- List modules and get their base addresses and sizes.
- Read, write, allocate, and free memory, with errors for invalid addresses.
- Multithreaded value scanning with memory type, protection, and address range filters.
- Log execution hits with registers, XMM values, stack snapshots, and timestamps.
- Watch data addresses for reads and writes, including the instruction responsible.
- Invoke functions with return address and stack pass-through, allows arguments (numeric, decimal, string, or byte-buffer), and returns the result (rax).

Address watchers use page guards and briefly single-step to re-arm them, so concurrent accesses can be missed. Native function calls can still crash the target if the address or calling signature is wrong.

## Usage

Initialize the submodules:

```sh
git submodule update --init --recursive
```

Open `rrm.sln` in Visual Studio 2022 with the C++ workload and Windows SDK installed, select `Release | x64`, and build the solution.

Keep `mcp.exe` and `client.dll` together in `build/x64/Release`. The server uses stdio, and the client is loaded into the target automatically when needed.

For Codex, register the server using its full path:

```sh
codex mcp add rrm -- "C:\path\to\runtime-reversal-mcp\build\x64\Release\mcp.exe"
```

For Claude Desktop, add this to your MCP configuration:

```json
{
  "mcpServers": {
    "rrm": {
      "command": "C:\\path\\to\\runtime-reversal-mcp\\build\\x64\\Release\\mcp.exe"
    }
  }
}
```

Reconnect your MCP client, start the target application, then ask the agent what you want to inspect:

```text
Attach to example.exe and list its modules.
Read 64 bytes at 0x12340000.
Scan private committed memory for the 8-byte value 0x12340000.
Watch 8 bytes at 0x12340000 for reads and writes, then show the hits.
Remove the watcher at 0x12340000.
```
