import asyncio
import json
import subprocess
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run(configuration):
    root = Path(__file__).resolve().parents[1]
    binaries = root / "build" / "x64" / configuration
    target = subprocess.Popen(
        [str(binaries / "target.exe")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        info = json.loads(await asyncio.to_thread(target.stdout.readline))

        async def execute(address, argument=123, iterations=1, threads=1):
            target.stdin.write(json.dumps(dict(address=address, argument=argument,
                                              iterations=iterations, threads=threads)) + "\n")
            target.stdin.flush()
            line = await asyncio.wait_for(asyncio.to_thread(target.stdout.readline), 20)
            assert line, (target.poll(), target.stderr.read() if target.poll() is not None else "")
            return json.loads(line)["sum"]

        async with stdio_client(StdioServerParameters(command=str(binaries / "mcp.exe"))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                async def call(name, args=None, error=False):
                    result = await session.call_tool(name, args or {})
                    assert bool(result.isError) == error, (name, args, result)
                    return json.loads(result.content[0].text)

                names = {tool.name for tool in (await session.list_tools()).tools}
                assert names == {"attach_binary", "get_all_modules", "get_module", "add_hook",
                                 "remove_hook", "get_hook_hits", "allocate_memory", "free_memory",
                                 "read_memory", "write_memory", "invoke_function", "get_invocation_result", "scan_for_value", "add_watcher", "remove_watcher", "get_watcher_hits"}
                await call("attach_binary", {"pid": info["pid"]})
                await call("read_memory", {"address": 0, "size": 1}, error=True)
                await call("write_memory", {"address": 0, "data": "ff"}, error=True)
                allocation = await call("allocate_memory", {"size": 4096})
                address = allocation["address"]
                await call("write_memory", {"address": address, "data": "1234abcd"})
                assert (await call("read_memory", {"address": address, "size": 4}))["data"] == "1234abcd"
                for tool, args in [
                    ("read_memory", {"address": info["noaccess"], "size": 1}),
                    ("read_memory", {"address": info["guarded"], "size": 1}),
                    ("read_memory", {"address": address, "size": 0}),
                    ("read_memory", {"address": address, "size": 1048577}),
                    ("read_memory", {"address": -1, "size": 1}),
                    ("read_memory", {"address": True, "size": 1}),
                    ("read_memory", {"address": 0x7fffffffffff, "size": 16}),
                    ("read_memory", {"address": address, "size": 1, "extra": 2}),
                    ("write_memory", {"address": address, "data": "not hex"}),
                    ("write_memory", {"address": info["noaccess"], "data": "aa"}),
                    ("write_memory", {"address": info["guarded"], "data": "aa"}),
                    ("write_memory", {"address": info["readonly"], "data": "aa"}),
                    ("write_memory", {"address": info["noaccess"] - 1, "data": "aabb"}),
                    ("allocate_memory", {"size": 0}),
                    ("allocate_memory", {"size": 1048577}),
                    ("allocate_memory", {"size": 1, "protection": "bad"}),
                    ("free_memory", {"address": info["memory"]}),
                    ("add_hook", {"address": address}),
                    ("add_hook", {"address": info["noaccess"]}),
                ]:
                    await call(tool, args, error=True)
                assert (await call("read_memory", {"address": info["noaccess"] - 1, "size": 1}))["data"] == "00"
                await call("free_memory", {"address": address})
                await call("free_memory", {"address": address}, error=True)
                executable = (await call("allocate_memory", {"size": 4096, "protection": "rwx"}))["address"]
                await call("write_memory", {"address": executable, "data": "488bc1c3"})
                await call("add_hook", {"address": executable})
                await call("free_memory", {"address": executable}, error=True)
                assert await execute(executable, argument=456) == 456
                await call("remove_hook", {"address": executable})
                await call("free_memory", {"address": executable})
                await call("add_hook", {"address": info["entry"], "capacity": 4096, "stack_size": 256})
                await call("add_hook", {"address": info["entry"]}, error=True)
                assert await execute(info["entry"], iterations=500, threads=4) == 2000 * 130
                hits = []
                after = 0
                while True:
                    page = await call("get_hook_hits", {"address": info["entry"], "after": after, "limit": 256})
                    hits.extend(page["hits"])
                    summary = page["hooks"][0]
                    after = summary["next_after"]
                    if not summary["has_more"]:
                        break
                assert summary["total_hits"] == 2000, summary
                assert summary["dropped_hits"] == 0, summary
                assert len(hits) == 2000
                assert len({hit["thread_id"] for hit in hits}) == 4
                for hit in hits:
                    assert hit["registers"]["rip"] == info["entry"]
                    assert hit["registers"]["rcx"] == 123
                    assert hit["timestamp_us"] > 1700000000000000
                    assert len(hit["xmm"]) == 16
                    assert all(len(value) == 32 for value in hit["xmm"].values())
                    assert hit["stack"]["size"] > 0
                    assert len(hit["stack"]["data"]) == hit["stack"]["size"] * 2
                    assert len(hit["context_hex"]) == 2464
                    assert not hit["registers"]["rflags"] & 0x100
                await call("write_memory", {"address": info["entry"], "data": "90"}, error=True)
                assert (await call("get_hook_hits", {"address": info["entry"], "limit": 1}))["hooks"][0]["total_hits"] == 2000
                await call("remove_hook", {"address": info["entry"]})
                assert (await call("get_hook_hits"))["hits"] == []
                await call("get_hook_hits", {"address": info["entry"]}, error=True)
                assert (await call("read_memory", {"address": info["entry"], "size": 1}))["data"] == "48"
                assert await execute(info["entry"]) == 130
                for key, hook_offset, argument, expected in [
                    ("rip", 0, 123, 42),
                    ("branch", 0, 123, 42),
                    ("conditional", 2, 0, 2),
                    ("conditional", 2, 1, 1),
                    ("entry", 7, 123, 130),
                    ("entry", 3, 123, 130),
                ]:
                    hook_address = info[key] + hook_offset
                    await call("add_hook", {"address": hook_address, "capacity": 8})
                    assert await execute(info[key], argument=argument) == expected
                    assert len((await call("get_hook_hits"))["hits"]) == 1
                    await call("remove_hook", {"address": hook_address})
                await call("add_hook", {"address": info["entry"], "capacity": 8})
                assert await execute(info["entry"], iterations=32) == 32 * 130
                page = await call("get_hook_hits")
                assert len(page["hits"]) == 8
                assert page["hooks"][0]["total_hits"] == 32
                assert page["hooks"][0]["dropped_hits"] == 24
                await call("remove_hook", {"address": info["entry"]})
                await call("add_hook", {"address": info["entry"]})
                running = asyncio.create_task(execute(info["entry"], iterations=10000, threads=4))
                await asyncio.sleep(0.03)
                await call("remove_hook", {"address": info["entry"]})
                assert await running == 40000 * 130
                await call("add_hook", {"address": info["entry"]})
        await asyncio.sleep(0.2)
        assert await execute(info["entry"], iterations=20) == 20 * 130
        assert target.poll() is None
        print(f"{configuration}: remote agent, concurrent VEH capture, context/XMM/stack, relocation, removal, overflow, memory errors and disconnect cleanup passed")
    finally:
        if target.poll() is None:
            target.stdin.write('{"exit":true}\n')
            target.stdin.flush()
            target.wait(timeout=10)
        assert target.returncode == 0, target.returncode


asyncio.run(run(sys.argv[1] if len(sys.argv) > 1 else "Debug"))
