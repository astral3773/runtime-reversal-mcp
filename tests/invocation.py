import asyncio
import json
import math
import random
import subprocess
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def numeric(value, format="uint64"):
    return dict(type="numeric", value=value, format=format)


def decimal(value, format="double"):
    return dict(type="decimal", value=value, format=format)


async def run(configuration):
    binaries = Path(__file__).resolve().parents[1] / "build" / "x64" / configuration
    target = subprocess.Popen([str(binaries / "target.exe")], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    calls = 0
    try:
        info = json.loads(await asyncio.to_thread(target.stdout.readline))
        functions = info["functions"]
        rng = random.Random(734612)
        pending = None
        async with stdio_client(StdioServerParameters(command=str(binaries / "mcp.exe"))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                async def call(name, args=None, error=False):
                    nonlocal calls
                    calls += 1
                    result = await session.call_tool(name, args or {})
                    assert bool(result.isError) == error, (name, args, result)
                    return json.loads(result.content[0].text)

                async def invoke(name, args=None, return_type="uint64", error=False, **extra):
                    return await call("invoke_function", dict(address=functions[name], args=args or [],
                                                              return_type=return_type, **extra), error)

                await call("attach_binary", {"pid": info["pid"]})
                for _ in range(160):
                    result = await invoke("self_return")
                    assert result["value"] == functions["self_return"], result
                    assert result["return_address"] == functions["self_return"]
                assert (await invoke("alignment"))["value"] == 8
                for count in range(17):
                    result = await invoke("sum16", [numeric(i) for i in range(1, count + 1)])
                    assert result["value"] == sum(i * i for i in range(1, count + 1))
                for _ in range(120):
                    values = [rng.randrange(0, 1 << 64) for _ in range(16)]
                    arguments = [numeric(str(value) if i % 2 else hex(value)) for i, value in enumerate(values)]
                    expected = sum((i + 1) * value for i, value in enumerate(values)) % (1 << 64)
                    assert (await invoke("sum16", arguments))["value"] == expected
                assert (await invoke("signed", [numeric(-128, "int8"), numeric(65535, "uint16"),
                                                numeric(-2147483648, "int32"), numeric(987, "uint64"),
                                                numeric(-10000000000, "int64"), numeric(-32768, "int16")],
                                     "int64"))["value"] == -128 + 65535 - 2147483648 + 987 - 10000000000 - 32768
                for value in [-9223372036854775808, -1, 0, 9223372036854775807]:
                    result = await call("invoke_function", dict(address=info["entry"],
                                                                args=[numeric(str(value), "int64")],
                                                                return_type="int64"))
                    expected = ((value + 7 + (1 << 63)) % (1 << 64)) - (1 << 63)
                    assert result["value"] == expected
                for _ in range(100):
                    values = [rng.randrange(-40, 40) / 4 for _ in range(16)]
                    arguments = []
                    for i, value in enumerate(values):
                        if i in [0, 5, 11]:
                            values[i] = abs(int(value))
                            arguments.append(numeric(values[i]))
                        elif i in [3, 8, 14]:
                            values[i] = int(value)
                            arguments.append(numeric(values[i], "int64"))
                        else:
                            arguments.append(decimal(value, "float" if i in [2, 6, 10, 13] else "double"))
                    result = await invoke("mixed16", arguments, "double")
                    assert result["value"] == sum((i + 1) * value for i, value in enumerate(values))
                assert (await invoke("floats", [decimal(i / 4, "float") for i in range(1, 9)], "float"))["value"] == 51.0
                for type, name in [("utf8", "utf8"), ("utf16", "utf16")]:
                    for text in ["", "hello", "caf\u00e9 \u4e16\u754c \U0001f680", "x" * 4095]:
                        result = await invoke(name, [dict(type="string", value=text, format=type)], type,
                                              return_size=max(4096, len(text) * 4 + 2))
                        assert result["value"] == text
                        assert result["buffers"][0]["index"] == 0
                data = bytes(range(256))
                result = await invoke("bytes", [dict(type="bytes", value=data.hex()), numeric(len(data))],
                                      "bytes", return_size=len(data))
                expected = bytes(value ^ 0x5a for value in data).hex()
                assert result["value"] == expected
                assert result["buffers"][0]["data"] == expected
                result = await invoke("bytes", [dict(type="bytes", value=""), numeric(0)])
                assert result["buffers"][0]["data"] == ""
                assert (await invoke("utf8", [numeric("0xffffffffffffffff")]))["value"] == 18446744073709551615
                assert (await invoke("utf8", [numeric("0xffffffff")], "uint32"))["value"] == 4294967295
                assert (await invoke("utf8", [numeric("0xffffffff")], "int32"))["value"] == -1
                assert (await invoke("nested", [numeric(44)]))["value"] == 61
                result = await invoke("thread_id")
                assert result["value"] == result["thread_id"]
                allocation = (await call("allocate_memory", {"size": 4096}))["address"]
                await call("write_memory", {"address": allocation, "data": "0100000000000000"})
                assert (await invoke("increment", [numeric(allocation)], "void"))["value"] is None
                assert (await call("read_memory", {"address": allocation, "size": 8}))["data"] == "0200000000000000"
                print(f"{configuration}: exact callee-observed return address, 16-slot ABI, signed boundaries, mixed floats, strings and buffers passed", flush=True)
                invalid_arguments = [
                    [dict(type="numeric", value=True)],
                    [dict(type="numeric", value=1.5)],
                    [numeric(-1)],
                    [numeric(256, "uint8")],
                    [numeric(-129, "int8")],
                    [numeric("18446744073709551616")],
                    [numeric("9223372036854775808", "int64")],
                    [numeric("0x")],
                    [numeric("1x")],
                    [numeric(" 1")],
                    [numeric(1, "float")],
                    [dict(type="decimal", value="1.0")],
                    [decimal(1e100, "float")],
                    [decimal(1.0, "int64")],
                    [dict(type="string", value="a\u0000b")],
                    [dict(type="string", value=123)],
                    [dict(type="string", value="a", format="double")],
                    [dict(type="bytes", value="g0")],
                    [dict(type="bytes", value="f")],
                    [dict(type="bytes", value="00", format="utf8")],
                    [dict(type="nope", value=0)],
                    [dict(type="numeric")],
                    [dict(type="numeric", value=1, extra=True)],
                    [1],
                    [numeric(1)] * 17,
                ]
                for arguments in invalid_arguments:
                    await invoke("self_return", arguments, error=True)
                for extra in [dict(address=0), dict(address=info["noaccess"]), dict(address=allocation),
                              dict(return_type="bad"), dict(return_size=0), dict(return_size=1048577),
                              dict(timeout_ms=-1), dict(timeout_ms=10001), dict(unknown=True), dict(args="bad")]:
                    args = dict(address=functions["self_return"])
                    args.update(extra)
                    await call("invoke_function", args, error=True)
                for name, args in [("read_pointer", [numeric(0)]),
                                   ("read_pointer", [numeric(info["noaccess"])]),
                                   ("divide", [numeric(0)]),
                                   ("clobber_fault", []),
                                   ("buffer_fault", [dict(type="bytes", value="00")]),
                                   ("thread_exit", [])]:
                    result = await invoke(name, args, error=True)
                    assert "fault" in result["error"].lower(), result
                    assert (await invoke("self_return"))["value"] == functions["self_return"]
                    assert target.poll() is None
                await invoke("utf8", [numeric(1)], "utf8", error=True)
                await invoke("utf16", [numeric(1)], "utf16", error=True)
                await invoke("utf8", [dict(type="string", value="abc")], "utf8", return_size=2, error=True)
                await call("add_hook", {"address": functions["self_return"], "capacity": 32})
                assert (await invoke("self_return"))["value"] == functions["self_return"]
                hits = (await call("get_hook_hits", {"address": functions["self_return"]}))["hits"]
                assert len(hits) == 1, hits
                assert int.from_bytes(bytes.fromhex(hits[0]["stack"]["data"][:16]), "little") == functions["self_return"]
                await call("remove_hook", {"address": functions["self_return"]})
                result = await invoke("delayed", [numeric(300)], timeout_ms=1)
                assert result["status"] == "running", result
                await invoke("self_return", error=True)
                await call("remove_hook", {"address": functions["delayed"]}, error=True)
                await call("get_invocation_result", {"invocation_id": result["invocation_id"] + 1}, error=True)
                assert (await call("read_memory", {"address": allocation, "size": 1}))["data"] == "02"
                result = await call("get_invocation_result", {"invocation_id": result["invocation_id"], "timeout_ms": 1000})
                assert result["status"] == "completed" and result["value"] == 789
                await call("get_invocation_result", {"invocation_id": result["invocation_id"]}, error=True)
                await call("free_memory", {"address": allocation})
                pending = await invoke("delayed_bytes", [dict(type="bytes", value="00"), numeric(350)],
                                       "bytes", return_size=1, timeout_ms=1)
                assert pending["status"] == "running"
                print(f"{configuration}: invalid arguments, synchronous fault recovery, nonvolatile restoration, hooks and pending-call isolation passed", flush=True)
        await asyncio.sleep(0.6)
        async with stdio_client(StdioServerParameters(command=str(binaries / "mcp.exe"))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("attach_binary", {"pid": info["pid"]})
                result = await session.call_tool("get_invocation_result", {"invocation_id": pending["invocation_id"]})
                assert not result.isError, result
                completed = json.loads(result.content[0].text)
                assert completed["value"] == "5a"
                assert completed["buffers"][0]["data"] == "5a"
        print(f"{configuration}: {calls} MCP checks passed; timeout buffers survived disconnect and reconnect", flush=True)
    finally:
        if target.poll() is None:
            target.stdin.write('{"exit":true}\n')
            target.stdin.flush()
            target.wait(timeout=10)
        assert target.returncode == 0, (target.returncode, target.stderr.read())


asyncio.run(run(sys.argv[1] if len(sys.argv) > 1 else "Debug"))
