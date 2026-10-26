import asyncio
import ctypes
import json
import shutil
import struct
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(configuration):
    root = Path(__file__).resolve().parents[1]
    binaries = root / 'build' / 'x64' / configuration
    fixture_path = binaries / 'export_fixture.dll'
    shutil.copyfile(binaries / {'Release-Watchers': 'client_watchers.dll', 'Release-Exports': 'client_exports.dll'}.get(configuration, 'client.dll'), fixture_path)
    fixture = ctypes.WinDLL(str(fixture_path))
    d3d11 = ctypes.WinDLL('d3d11.dll')
    kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
    kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.GetCurrentProcessId.restype = ctypes.c_ulong
    base = fixture._handle
    nt = struct.unpack('<I', ctypes.string_at(base + 0x3c,4))[0]
    optional = base + nt + 24
    directory = optional + 112
    original_directory = ctypes.string_at(directory, 8)
    export_rva, export_size = struct.unpack('<II', original_directory)
    assert export_size >= 256
    original_data = ctypes.string_at(base + export_rva, 256)

    def write(address, data):
        old = ctypes.c_ulong()
        assert kernel32.VirtualProtect(address,len(data),4,ctypes.byref(old))
        try:ctypes.memmove(address,bytes(data),len(data))
        finally:assert kernel32.VirtualProtect(address,len(data),old.value,ctypes.byref(old))

    def fixture_data():
        data = bytearray(256)
        struct.pack_into('<IIIIIIIIII',data,0,0,0,0,0,7,4,2,export_rva+64,export_rva+80,export_rva+88)
        struct.pack_into('<IIII',data,64,0x1000,0,0x1010,export_rva+160)
        struct.pack_into('<II',data,80,export_rva+100,export_rva+112)
        struct.pack_into('<HH',data,88,0,0)
        data[100:106] = b'Named\0'
        data[112:118] = b'Alias\0'
        data[160:175] = b'KERNEL32.Sleep\0'
        return data

    async with stdio_client(StdioServerParameters(command=str(binaries / 'mcp.exe'))) as (r,w):
        async with ClientSession(r,w) as session:
            await session.initialize()

            async def call(args, error=False):
                result = await session.call_tool('get_module_exports', args)
                data = json.loads(result.content[0].text)
                assert bool(result.isError) == error, (args,data)
                return data

            await call(dict(name='d3d11.dll'),error=True)
            await session.call_tool('attach_binary',dict(pid=kernel32.GetCurrentProcessId()))
            result = await call(dict(name='D3D11.DLL'))
            exports = result['exports']
            assert result['count'] == len(exports) > 0
            create = next(e for e in exports if e['name']=='D3D11CreateDevice')
            assert create['address'] == kernel32.GetProcAddress(d3d11._handle,b'D3D11CreateDevice')
            for e in exports:
                assert e['ordinal'] >= 0
                if e['forwarder'] is None:assert e['address'] == d3d11._handle + e['rva']
                else:assert e['address'] is None
            kernel_exports = await call(dict(name='kernel32.dll'))
            assert any(e['forwarder'] and e['address'] is None for e in kernel_exports['exports'])
            for args in [{},dict(name=''),dict(name='missing.dll'),dict(name=17),dict(name=True),dict(name='d3d11.dll',extra=1),dict(name='d3d11.dll\0')]:
                await call(args,error=True)
            try:
                write(directory,struct.pack('<II',export_rva,256))
                write(base+export_rva,fixture_data())
                result = await call(dict(name='export_fixture.dll'))
                exports = result['exports']
                assert len(exports)==4, result
                assert [e['ordinal'] for e in exports]==[7,7,9,10]
                assert [e['name'] for e in exports]==['Named','Alias',None,None]
                assert exports[-1]['forwarder']=='KERNEL32.Sleep' and exports[-1]['address'] is None
                assert exports[2]['address']==base+0x1010
                write(directory,bytes(8))
                assert (await call(dict(name='export_fixture.dll')))['exports']==[]
                write(directory,struct.pack('<II',export_rva,256))
                for offset,value in [(20,0xffffffff),(28,0xffffffff),(32,0),(36,0xffffffff)]:
                    data=fixture_data();struct.pack_into('<I',data,offset,value)
                    write(base+export_rva,data)
                    await call(dict(name='export_fixture.dll'),error=True)
                data=fixture_data();struct.pack_into('<H',data,88,4)
                write(base+export_rva,data)
                await call(dict(name='export_fixture.dll'),error=True)
                data=fixture_data();data[160:]=b'x'*96
                write(base+export_rva,data)
                await call(dict(name='export_fixture.dll'),error=True)
                data=fixture_data();struct.pack_into('<I',data,64,0xffffffff)
                write(base+export_rva,data)
                await call(dict(name='export_fixture.dll'),error=True)
                write(directory,bytes(8))
                header64 = ctypes.string_at(optional,240)
                header32=bytearray(240)
                struct.pack_into('<H',header32,0,0x10b)
                struct.pack_into('<I',header32,92,16)
                struct.pack_into('<II',header32,96,export_rva,256)
                try:
                    write(optional,header32)
                    write(base+export_rva,fixture_data())
                    assert (await call(dict(name='export_fixture.dll')))['count']==4
                finally:write(optional,header64)
            finally:
                write(base+export_rva,original_data)
                write(directory,original_directory)
    print('Module exports passed:',configuration,'D3D11, forwarders, aliases, ordinal-only, holes, PE32, malformed tables and validation')


asyncio.run(main(sys.argv[1] if len(sys.argv)>1 else 'Release'))
