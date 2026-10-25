import asyncio, ctypes, json, os, struct, sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main(configuration):
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    k.VirtualAlloc.restype = ctypes.c_void_p
    k.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    k.CreateFileMappingW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_wchar_p]
    k.CreateFileMappingW.restype = ctypes.c_void_p
    k.MapViewOfFile.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_size_t]
    k.MapViewOfFile.restype = ctypes.c_void_p
    k.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    k.GetModuleHandleW.restype = ctypes.c_void_p
    size = 8 * 1024 * 1024
    base = k.VirtualAlloc(None, size, 12288, 4)
    assert base
    value = 11785757608062936247
    offsets = [0, 19, 4093, 1048573, 2097152, 4194300, 4194432, size - 8]
    for offset in offsets:
        ctypes.memmove(base + offset, struct.pack('<Q', value), 8)
    old = ctypes.c_ulong()
    assert k.VirtualProtect(base + 4194304, 1048576, 2, ctypes.byref(old))
    assert k.VirtualProtect(base + 6291456, 4096, 260, ctypes.byref(old))
    assert k.VirtualProtect(base + 6295552, 4096, 1, ctypes.byref(old))
    mapping = k.CreateFileMappingW(ctypes.c_void_p(-1), None, 4, 0, 8192, None)
    assert mapping
    mapped = k.MapViewOfFile(mapping, 983071, 0, 0, 8192)
    assert mapped
    ctypes.memmove(mapped + 57, struct.pack('<Q', value), 8)
    exe = Path('build/x64') / configuration / 'mcp.exe'
    try:
        async with stdio_client(StdioServerParameters(command=str(exe.resolve()))) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                a = await s.call_tool('attach_binary', {'pid': os.getpid()})
                assert not a.isError

                async def scan(error=False, **args):
                    p = dict(value=hex(value), start=base, end=base + size)
                    p.update(args)
                    result = await s.call_tool('scan_for_value', p)
                    assert bool(result.isError) == error, (p, result)
                    return json.loads(result.content[0].text)
                one = await scan(threads=1)
                many = await scan(threads=8)
                assert one['addresses'] == many['addresses'] == [base + x for x in offsets], (one, many)
                assert one['complete'] and many['complete']
                assert many['threads'] == 8
                rw = await scan(protections=['readwrite'])
                assert rw['addresses'] == [base + x for x in offsets if x not in [4194300, 4194432]], rw
                aligned = await scan(alignment=8)
                assert aligned['addresses'] == [base + x for x in offsets if (base + x) % 8 == 0]
                assert (await scan(mem_types=['mapped']))['addresses'] == []
                assert (await scan(states=['reserved']))['addresses'] == []
                assert (await scan(protections=['noaccess']))['addresses'] == []
                capped = await scan(max_results=2)
                assert capped['count'] == 2 and capped['limit_reached'] and (not capped['complete']), capped
                m = await scan(start=mapped, end=mapped + 8192, mem_types=['mapped'])
                assert m['addresses'] == [mapped + 57] and m['complete'], m
                image = k.GetModuleHandleW('kernel32.dll')
                pe = await scan(start=image, end=image + 2, value=23117, width=2, mem_types=['image'])
                assert pe['addresses'] == [image], pe
                for width in [1, 2, 4, 8]:
                    v = (1 << width * 8) - 37
                    ctypes.memmove(base + 128, v.to_bytes(width, 'little'), width)
                    found = await scan(start=base + 128, end=base + 128 + width, width=width, value=str(v))
                    assert found['addresses'] == [base + 128], found
                for params in [dict(value=-1), dict(value=True), dict(value='0x'), dict(value='1z'), dict(value='18446744073709551616'), dict(width=3), dict(width=1, value=256), dict(threads=65), dict(alignment=0), dict(max_results=0), dict(timeout_ms=0), dict(start=base + 8, end=base), dict(mem_types=[]), dict(mem_types=['bad']), dict(mem_types=['private', 'private']), dict(states=['bad']), dict(protections=['bad'])]:
                    await scan(error=True, **params)
                large = k.VirtualAlloc(None, 128 * 1024 * 1024, 12288, 4)
                assert large
                try:
                    timed = await scan(start=large, end=large + 128 * 1024 * 1024, timeout_ms=1, threads=8)
                    assert timed['timed_out'] and (not timed['complete']), timed
                finally:
                    k.VirtualFree(large, 0, 32768)
                print(configuration + ': scanner passed: 1/8 worker equality, unaligned/chunk/page/region boundaries, protection/type/state filters, image/mapped memory, guard pages, width, limits and validation')
                print(json.dumps({'bytes': many['eligible_bytes'], 'workers': many['threads'], 'elapsed_ms': many['elapsed_ms']}))
    finally:
        k.UnmapViewOfFile(mapped)
        k.CloseHandle(mapping)
        k.VirtualFree(base, 0, 32768)
asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else 'Release-Scan'))
