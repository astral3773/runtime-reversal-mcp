import asyncio
import json
import struct
import subprocess
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(configuration):
    binaries = Path(__file__).resolve().parents[1] / 'build' / 'x64' / configuration
    target = subprocess.Popen([str(binaries / 'target.exe')], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        info = json.loads(await asyncio.to_thread(target.stdout.readline))
        address = info['memory']

        async def execute(entry, pointer=address, iterations=1, threads=1):
            target.stdin.write(json.dumps(dict(address=entry, argument=pointer,
                                              iterations=iterations, threads=threads)) + '\n')
            target.stdin.flush()
            line = await asyncio.wait_for(asyncio.to_thread(target.stdout.readline), 15)
            assert line, (target.poll(), target.stderr.read())
            return json.loads(line)['sum']

        async with stdio_client(StdioServerParameters(command=str(binaries / 'mcp.exe'))) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()

                async def call(name, args=None, error=False):
                    result = await session.call_tool(name, args or {})
                    data = json.loads(result.content[0].text)
                    assert bool(result.isError) == error, (name, data)
                    return data

                await call('attach_binary', {'pid': info['pid']})
                await call('write_memory', {'address': address, 'data': struct.pack('<Q', 17).hex()})
                for args in [dict(address=0), dict(address=info['noaccess']),
                             dict(address=info['guarded']), dict(address=info['entry']),
                             dict(address=info['stack']),
                             dict(address=address+4095, size=8), dict(address=address, size=0),
                             dict(address=address, access_type='bad'),
                             dict(address=address, capacity=0)]:
                    await call('add_watcher', args, error=True)
                agent_name = 'client_watchers.dll' if configuration == 'Release-Watchers' else 'client.dll'
                agent = await call('get_module', dict(name=agent_name))
                await call('add_watcher', dict(address=agent['base_address']), error=True)
                result = await call('add_watcher', dict(address=address, size=8, capacity=64))
                assert result['mode'] == 'page_guard' and result['best_effort']
                await call('add_watcher', dict(address=address+16), error=True)
                await call('read_memory', dict(address=address, size=8), error=True)
                await call('write_memory', dict(address=address, data='00'), error=True)
                assert await execute(info['watch_read'], iterations=12) == 204
                assert await execute(info['watch_write'], iterations=7) == 294
                hits = await call('get_watcher_hits', dict(address=address))
                assert len(hits['hits']) == 19, hits
                assert hits['watchers'][0]['armed'], hits
                assert [h['access_type'] for h in hits['hits']] == ['read']*12 + ['write']*7
                for hit in hits['hits']:
                    assert hit['address'] == address and hit['timestamp_us'] > 0
                    assert hit['instruction'].startswith('mov '), hit
                    assert hit['instruction_address'] in [info['watch_read'], info['watch_write']]
                assert await execute(info['watch_read'], address+128) == 0
                assert len((await call('get_watcher_hits'))['hits']) == 19
                page = await call('get_watcher_hits', dict(address=address, limit=3))
                assert len(page['hits']) == 3 and page['watchers'][0]['has_more']
                next_page = await call('get_watcher_hits', dict(address=address,
                    after=page['watchers'][0]['next_after'], limit=3))
                assert next_page['hits'][0]['sequence'] == 4
                await call('add_hook', dict(address=info['watch_read']))
                assert await execute(info['watch_read'], iterations=3) == 126
                assert len((await call('get_hook_hits'))['hits']) == 3
                invocation = await call('invoke_function', dict(address=info['watch_write'],
                    args=[dict(type='numeric', value=address)], return_type='uint64'))
                assert invocation['status'] == 'completed' and invocation['value'] == 42
                await call('remove_hook', dict(address=info['watch_read']))
                await call('remove_watcher', dict(address=address))
                assert (await call('read_memory', dict(address=address, size=8)))['data'] == struct.pack('<Q',42).hex()
                assert (await call('get_watcher_hits'))['hits'] == []
                await call('remove_watcher', dict(address=address), error=True)
                await call('get_watcher_hits', dict(address=address), error=True)
                for access, entry, other in [('read', info['watch_read'], info['watch_write']),
                                             ('write', info['watch_write'], info['watch_read'])]:
                    await call('add_watcher', dict(address=address, size=8, access_type=access, capacity=4))
                    await execute(other, iterations=3)
                    assert not (await call('get_watcher_hits'))['hits']
                    await execute(entry, iterations=11)
                    result = await call('get_watcher_hits')
                    assert len(result['hits']) == 4 and result['watchers'][0]['overwritten_hits'] == 7, result
                    assert all(h['access_type'] == access for h in result['hits'])
                    await call('remove_watcher', dict(address=address))
                await call('add_watcher', dict(address=address, size=8, capacity=512))
                assert await execute(info['watch_read'], iterations=100, threads=4) == 16800
                result = await call('get_watcher_hits', dict(limit=512))
                assert result['hits'] and result['watchers'][0]['rearm_failures'] == 0, result
                await call('remove_watcher', dict(address=address))
                await call('add_watcher', dict(address=info['readonly'], access_type='read'))
                assert await execute(info['watch_read'], info['readonly']) == 0
                await call('remove_watcher', dict(address=info['readonly']))
                await call('add_watcher', dict(address=address))
        await asyncio.sleep(.2)
        assert await execute(info['watch_read']) == 42
        async with stdio_client(StdioServerParameters(command=str(binaries / 'mcp.exe'))) as (r, w):
            async with ClientSession(r,w) as session:
                await session.initialize()
                await session.call_tool('attach_binary', {'pid':info['pid']})
                result = await session.call_tool('read_memory',dict(address=address,size=8))
                assert not result.isError, result
        print('Watcher integration passed:', configuration)
    finally:
        if target.poll() is None:
            target.stdin.write('{"exit":true}\n');target.stdin.flush()
            try:target.wait(timeout=5)
            except subprocess.TimeoutExpired:target.kill();target.wait()


asyncio.run(main(sys.argv[1] if len(sys.argv)>1 else 'Release'))
